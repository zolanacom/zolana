#!/usr/bin/env python3
"""Assemble the scratch workspace of the program-level differential run.

The candidate patch series in node/candidate carries its own text of the
native program and of the protocol library. This tool puts that text beside
the workspace's in one Cargo workspace, so that harness/tests/differential.rs
can run both programs on the same inputs. It writes, under --out:

  candidate-protocol/   zolana-native/protocol/src of the candidate, verbatim,
                        taken from the pinned patch chain with `git apply`,
                        the way tools/protocol_copy_guard.py takes it.
  candidate-program/    zolana-native/adapter/src of the candidate, verbatim
                        except the call sites listed in SUBSTITUTIONS, which
                        name an interface of the Agave 4.3.2 runtime that the
                        vendored 3.0.14 runtime spells differently.
  workspace-program/    node/adapter/src of this repository, verbatim except
                        one function body of processor/runtime_features.rs:
                        `slot_anchors` reads the harness's switch. The other
                        functions of that file, through which the program
                        reaches the compute meter, the sysvar cache and the
                        System program, are compiled as they are.
  gate/                 the switch both of those builds read.
  harness/              the test crate (from the folder beside this file).
  Cargo.toml, Cargo.lock
                        the workspace manifest, with the profiles and the
                        `[patch.crates-io]` section of the repository's, and a
                        copy of the repository's lock file.
  MANIFEST.json         SHA-256 of every input and output, and the count of
                        every substitution.

Nothing is built here, nothing is downloaded and nothing outside --out is
written except a temporary directory that is removed again. Every substitution
must match exactly the number of times recorded below, or the assembly stops.
The generated manifests name absolute paths of this checkout, which is why
--out belongs under the ignored target/ directory and not in the tree.

Standard library only; needs Git for `git apply`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COPY_ROOTS = ("zolana-native/protocol", "zolana-native/adapter")
HARDENING_DRAFT = "node/candidate/drafts/pool-state-hardening/agave-4.3.2-pool-state-hardening.patch"

# (label, text in the candidate's processor.rs, replacement, expected count)
SUBSTITUTIONS = (
    ("compute meter",
     "    context\n        .compute_meter\n        .consume_checked(",
     "    context\n        .consume_checked(", 1),
    ("sysvar cache, one line",
     "context.environment_config.sysvar_cache()",
     "context.get_sysvar_cache()", 1),
    ("sysvar cache, rent of the recipient",
     "context\n                        .environment_config\n                        .sysvar_cache()",
     "context\n                        .get_sysvar_cache()", 1),
    ("sysvar cache, rent of a marker",
     "context\n            .environment_config\n            .sysvar_cache()",
     "context\n            .get_sysvar_cache()", 1),
    ("native invoke, name",
     "context.native_invoke_signed(",
     "context.native_invoke(", 4),
    # The 4.3.2 call takes seeds and derives the signer from them. The 3.0.14
    # call takes the signer. Derive it here from the candidate's own seeds, so
    # that its seed computation stays the thing that decides the address.
    ("native invoke, signer derived from the candidate's seeds",
     "            &[signer_seeds],",
     "            &[solana_pubkey::Pubkey::create_program_address(signer_seeds, &id())\n"
     "                .map_err(|_| Error::InvalidSeeds)?],", 2),
    ("slot-anchor switch",
     "context.get_feature_set().native_slot_anchors",
     "differential_gate::slot_anchors()", 1),
)

# The test and development profiles of the repository's Cargo.toml end where
# this comment begins; the release profile after it is not used here.
PROFILES_END = "# Separate, bounded release candidate"

WORKSPACE_GATE_FILE = "processor/runtime_features.rs"
# (label, text in the repository's runtime_features.rs, replacement, expected count)
WORKSPACE_SUBSTITUTIONS = (
    ("slot-anchor switch",
     "pub(super) fn slot_anchors(_context: &InvokeContext) -> bool {\n    false\n}\n",
     "pub(super) fn slot_anchors(_context: &InvokeContext) -> bool {\n"
     "    differential_gate::slot_anchors()\n}\n", 1),
)
# Every function of the binding file must reach the build unchanged.
WORKSPACE_BINDING_FUNCTIONS = (
    "pub(super) fn consume_compute_units(",
    "pub(super) fn sysvars<",
    "pub(super) fn invoke(",
    "pub(super) fn invoke_as_marker(",
    "pub(super) fn slot_anchors(",
)

GATE_LIB = '''//! The slot-anchor switch of one differential case, per thread.
use std::cell::Cell;

thread_local! {
    static SLOT_ANCHORS: Cell<bool> = const { Cell::new(false) };
}

pub fn set(active: bool) {
    SLOT_ANCHORS.with(|cell| cell.set(active));
}

pub fn slot_anchors() -> bool {
    SLOT_ANCHORS.with(Cell::get)
}
'''


def require(condition, message):
    if not condition:
        raise SystemExit("assemble: " + message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def git_apply(directory, patch, includes):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment["GIT_CEILING_DIRECTORIES"] = str(directory.parent.resolve(strict=True))
    result = subprocess.run(
        ["git", "apply", "--no-index", "--whitespace=nowarn",
         *(f"--include={pattern}" for pattern in includes), str(patch)],
        cwd=directory, env=environment, capture_output=True, text=True, check=False)
    require(result.returncode == 0, "git apply failed: " + result.stderr.strip()[:400])


def touches_copies(patch_bytes):
    return any(line.startswith(b"diff --git a/" + root.encode() + b"/")
               for line in patch_bytes.splitlines() for root in COPY_ROOTS)


def candidate_tree(root, temporary, hardened, record):
    """The candidate's two source directories after the pinned patch chain, under `temporary`."""
    plan_path = root / "node/candidate/reconstruction-plan.json"
    plan = json.loads(plan_path.read_bytes())
    record["plan_sha256"] = digest(plan_path.read_bytes())
    base = root / plan["base_patch"]["path"]
    require(digest(base.read_bytes()) == plan["base_patch"]["sha256"], "base patch is not the pinned one")
    record["base_patch_sha256"] = plan["base_patch"]["sha256"]
    tree = temporary / "tree"
    tree.mkdir()
    includes = [copy_root + "/*" for copy_root in COPY_ROOTS]
    git_apply(tree, base, includes)
    record["plan_steps_touching_the_copies"] = []
    for step in plan["steps"]:
        patch = root / step["patch"]["path"]
        raw = patch.read_bytes()
        require(digest(raw) == step["patch"]["sha256"], f"{step['revision']} is not the pinned patch")
        if touches_copies(raw):
            git_apply(tree, patch, includes)
            record["plan_steps_touching_the_copies"].append(step["revision"])
    record["plan_steps"] = [step["revision"] for step in plan["steps"]]
    record["hardening_draft_applied"] = bool(hardened)
    if hardened:
        draft = root / HARDENING_DRAFT
        record["hardening_draft_sha256"] = digest(draft.read_bytes())
        git_apply(tree, draft, includes)
    return tree


def in_toml(path):
    """The path as the inside of a TOML basic string."""
    return json.dumps(str(path))[1:-1]


def copy_tree(source, target, record, prefix):
    for path in sorted(source.rglob("*")):
        if path.is_file():
            relative = path.relative_to(source).as_posix()
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            raw = path.read_bytes()
            destination.write_bytes(raw)
            record[f"{prefix}/{relative}"] = {"sha256": digest(raw), "verbatim": True}


def main():
    parser = argparse.ArgumentParser(
        description="Assemble the scratch workspace of the program-level differential run.")
    parser.add_argument("--out", required=True, type=Path,
                        help="directory to write; use one under the ignored target/ directory")
    parser.add_argument("--hardened", action="store_true",
                        help="apply the pool-state-hardening draft to the candidate protocol copy")
    parser.add_argument("--candidate-on-workspace-protocol", action="store_true",
                        help="link the candidate program to the workspace protocol crate instead of its own copy")
    arguments = parser.parse_args()
    out = arguments.out.resolve()
    for name in ("candidate-protocol", "candidate-program", "workspace-program", "gate", "harness"):
        shutil.rmtree(out / name, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    shared = arguments.candidate_on_workspace_protocol
    require(not (shared and arguments.hardened), "the two variants exclude each other")
    manifest = {"format": "zolana-program-differential-assembly-v1", "candidate": {}, "files": {},
                "substitutions": [],
                "candidate_program_links": "workspace protocol crate" if shared else "candidate protocol copy"}

    files = manifest["files"]
    with tempfile.TemporaryDirectory(prefix="zolana-differential-") as temporary:
        tree = candidate_tree(ROOT, Path(temporary), arguments.hardened, manifest["candidate"])
        if not shared:
            copy_tree(tree / "zolana-native/protocol/src", out / "candidate-protocol/src", files,
                      "candidate-protocol/src")
        copy_tree(tree / "zolana-native/adapter/src", out / "candidate-program/src", files,
                  "candidate-program/src")

    processor = out / "candidate-program/src/processor.rs"
    text = processor.read_text()
    before = text
    for label, old, new, expected in SUBSTITUTIONS:
        found = text.count(old)
        require(found == expected, f"substitution '{label}': {found} matches, expected {expected}")
        text = text.replace(old, new)
        manifest["substitutions"].append({"label": label, "count": found, "from": old, "to": new})
    for leftover in ("compute_meter", "environment_config", "native_invoke_signed", "native_slot_anchors"):
        require(leftover not in text, f"'{leftover}' is still in the candidate processor")
    processor.write_text(text)
    files["candidate-program/src/processor.rs"] = {
        "sha256_verbatim": digest(before.encode()), "sha256": digest(text.encode()),
        "verbatim": False, "lines_before": before.count("\n"), "lines_after": text.count("\n")}

    adapter = ROOT / "node/adapter/src"
    copy_tree(adapter, out / "workspace-program/src", files, "workspace-program/src")
    gate_file = out / "workspace-program/src" / WORKSPACE_GATE_FILE
    require(gate_file.is_file(), "node/adapter/src has no " + WORKSPACE_GATE_FILE)
    original = gate_file.read_bytes()
    binding = original.decode()
    manifest["workspace_substitutions"] = []
    for label, old, new, expected in WORKSPACE_SUBSTITUTIONS:
        found = binding.count(old)
        require(found == expected, f"workspace substitution '{label}': {found} matches, expected {expected}")
        binding = binding.replace(old, new)
        manifest["workspace_substitutions"].append({"label": label, "count": found, "from": old, "to": new})
    for name in WORKSPACE_BINDING_FUNCTIONS:
        require(binding.count(name) == 1, f"the binding file does not define '{name}' exactly once")
    require(binding.count("\n") == original.count(b"\n"), "the binding file changed its number of lines")
    gate_file.write_text(binding)
    files["workspace-program/src/" + WORKSPACE_GATE_FILE] = {
        "sha256_verbatim": digest(original), "sha256": digest(binding.encode()),
        "verbatim": False, "lines": binding.count("\n"),
        "lines_changed": sum(a != b for a, b in zip(original.decode().splitlines(), binding.splitlines()))}
    # The rule text of the workspace program must not name the runtime's own
    # interfaces any more: only the binding file may.
    for path in sorted((out / "workspace-program/src").rglob("*.rs")):
        if path == gate_file or path.name.endswith("_tests.rs"):
            continue
        text_of = path.read_text()
        for name in ("consume_checked", "get_sysvar_cache", "native_invoke"):
            require(name not in text_of, f"'{name}' is named outside the binding file, in {path.name}")
    # The in-crate tests of node/adapter call the gated entry point directly
    # and need that crate's development dependencies. They are copied with the
    # rest of the directory but are not built here: this workspace runs only
    # the harness's test, and the workspace's own checks run them.

    (out / "gate/src").mkdir(parents=True)
    (out / "gate/src/lib.rs").write_text(GATE_LIB)
    (out / "gate/Cargo.toml").write_text(
        '[package]\nname = "differential-gate"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n')

    root_text, agave_text = in_toml(ROOT), in_toml(ROOT / "node/agave")
    solana = '''solana-program-runtime = {{ path = "{agave}/program-runtime" }}
solana-pubkey = {{ version = "=3.0.0", features = ["curve25519", "sha2"] }}
solana-instruction = "=3.0.0"
solana-instruction-error = "=2.0.0"
solana-sdk-ids = "=3.0.0"
solana-system-interface = {{ version = "=2.0.0", features = ["bincode"] }}
differential-gate = {{ path = "../gate" }}
'''.format(agave=agave_text)
    orchard = 'orchard = { version = "=0.16.0", default-features = false, features = ["circuit", "std", "zeroize", "multicore"] }\n'
    workspace_protocol = f'{{ path = "{root_text}/protocol/payments" }}'
    if shared:
        # Cargo refuses one crate under two names in one package, so the
        # harness reaches the workspace crate through a crate that only
        # re-exports it.
        (out / "candidate-protocol/src").mkdir(parents=True)
        (out / "candidate-protocol/src/lib.rs").write_text("pub use native_payments::*;\n")
        (out / "candidate-protocol/Cargo.toml").write_text(
            '[package]\nname = "candidate-native-payments"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
            '[dependencies]\nnative-payments = ' + workspace_protocol + '\n')
    if not shared:
        (out / "candidate-protocol/Cargo.toml").write_text(
            '[package]\nname = "candidate-native-payments"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n'
            '[lib]\nname = "native_payments"\n\n[dependencies]\n' + orchard +
            'blake2b_simd = "1"\nnonempty = "0.11"\nincrementalmerkletree = "0.9"\n\n'
            '[dev-dependencies]\nrand = { version = "0.10", features = ["sys_rng"] }\n')
    candidate_protocol = (workspace_protocol if shared else
                          '{ package = "candidate-native-payments", path = "../candidate-protocol" }')
    (out / "candidate-program/Cargo.toml").write_text(
        '[package]\nname = "candidate-native-payment-program"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n'
        '[lib]\nname = "candidate_program"\n\n[dependencies]\n'
        'native-payments = ' + candidate_protocol + '\n'
        + orchard + solana)
    (out / "workspace-program/Cargo.toml").write_text(
        '[package]\nname = "workspace-copy-native-payment-program"\nversion = "0.0.0"\nedition = "2021"\npublish = false\n\n'
        '[lib]\nname = "workspace_program"\n\n[dependencies]\n'
        'native-payments = ' + workspace_protocol + '\n' + orchard + solana)

    (out / "harness/src").mkdir(parents=True)
    (out / "harness/tests").mkdir()
    (out / "harness/src/lib.rs").write_text("//! Test-only crate; see tests/differential.rs.\n")
    shutil.copyfile(HERE / "harness/tests/differential.rs", out / "harness/tests/differential.rs")
    harness_manifest = (HERE / "harness/Cargo.toml.in").read_text()
    require(harness_manifest.count("@ROOT@") == 3 and harness_manifest.count("@AGAVE@") == 7,
            "harness/Cargo.toml.in does not have the expected placeholders")
    (out / "harness/Cargo.toml").write_text(
        harness_manifest.replace("@ROOT@", root_text).replace("@AGAVE@", agave_text))
    for path in sorted((out / "harness").rglob("*")):
        if path.is_file():
            files["harness/" + path.relative_to(out / "harness").as_posix()] = {
                "sha256": digest(path.read_bytes())}

    root = (ROOT / "Cargo.toml").read_text()
    for marker in ("[profile.test]", PROFILES_END, "[patch.crates-io]"):
        require(root.count(marker) == 1, f"the repository's Cargo.toml does not have '{marker}' exactly once")
    patch_section = root[root.index("[patch.crates-io]"):]
    profiles = root[root.index("[profile.test]"):root.index(PROFILES_END)]
    (out / "Cargo.toml").write_text(
        '[workspace]\nmembers = ["candidate-protocol", "candidate-program", "workspace-program", '
        '"gate", "harness"]\n'
        'resolver = "2"\n\n' + profiles + "\n" + patch_section)
    shutil.copyfile(ROOT / "Cargo.lock", out / "Cargo.lock")
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"assembled {arguments.out.name}: {len(files)} files, "
          f"{sum(item['count'] for item in manifest['substitutions'])} substituted call sites "
          f"in {len(manifest['substitutions'])} kinds in the candidate program, "
          f"{sum(item['count'] for item in manifest['workspace_substitutions'])} substituted function body "
          f"in the workspace program")


if __name__ == "__main__":
    sys.exit(main())
