#!/usr/bin/env python3
"""Fail when the two copies of the payment protocol and native program drift.

The candidate patch series in node/candidate carries its own copy of the
protocol library and of the native program: the files it adds under
zolana-native/protocol/src and zolana-native/adapter/src of the patched tree.
The workspace builds and tests protocol/payments and node/adapter. A change
made to one copy only is a difference between tested and deployed rules.

`check` takes the candidate copies from the pinned patch chain with Git patch
application alone, compares them file by file with the workspace, and accepts
exactly the differences recorded in tools/protocol_copy_allowlist.json. Each
record pins both files by SHA-256, so any later edit to either side of a
recorded difference fails until the difference is reviewed again. A file that
is identical today must stay identical. A record whose files have become
identical must be deleted. The check builds nothing and reads no archive.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import tomllib

import prepare_native_candidate as source_tools
import reconstruct_native_candidate as candidate

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = ROOT / "tools/protocol_copy_allowlist.json"
FORMAT = "zolana-protocol-copy-allowlist-v1"
RESULT_FORMAT = "zolana-protocol-copy-check-v1"
# Candidate directory in the patched tree, then the workspace directory.
PAIRS = (
    ("zolana-native/protocol/src", "protocol/payments/src"),
    ("zolana-native/adapter/src", "node/adapter/src"),
)
# The proof system must be the same exact release wherever a copy is built.
PINNED_DEPENDENCY = "orchard"
CANDIDATE_MANIFESTS = ("zolana-native/protocol/Cargo.toml", "zolana-native/adapter/Cargo.toml")
CLASSES = ("formatting", "refactor", "behaviour")
HEX = re.compile(r"[a-f0-9]{64}\Z")
MAX_SOURCE_BYTES = 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unmatched_lines(candidate_raw, workspace_raw):
    """Lines on each side with no equal line left on the other side.

    Order is ignored on purpose: a function moved unchanged counts as zero,
    and the figure does not depend on any diff algorithm.
    """
    ours = Counter(candidate_raw.splitlines())
    theirs = Counter(workspace_raw.splitlines())
    return {"candidate": sum((ours - theirs).values()),
            "workspace": sum((theirs - ours).values())}


def candidate_root_of(name):
    for candidate_root, _ in PAIRS:
        if name == candidate_root or name.startswith(candidate_root + "/"):
            return candidate_root
    return None


def git_apply(directory, patch, includes):
    """Apply only the named paths of one patch inside a scratch tree."""
    environment = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        environment.pop(name, None)
    environment["GIT_CEILING_DIRECTORIES"] = str(directory.parent.resolve(strict=True))
    result = subprocess.run(
        ["git", "apply", "--no-index", "--whitespace=nowarn",
         *(f"--include={pattern}" for pattern in includes), str(patch)],
        cwd=directory, env=environment, capture_output=True, text=True, check=False)
    require(result.returncode == 0,
            "Git could not apply the candidate copy: " + result.stderr.strip()[:400])


def scratch_files(scratch):
    files = {}
    for path in sorted(scratch.rglob("*")):
        require(not path.is_symlink(), "candidate copy contains a symlink")
        if path.is_file():
            require(path.stat().st_size <= MAX_SOURCE_BYTES, "candidate copy exceeds size limit")
            files[path.relative_to(scratch).as_posix()] = path.read_bytes()
    return files


def candidate_copies(plan):
    """Return {patched-tree path: bytes} for both copy directories after the chain."""
    with tempfile.TemporaryDirectory(prefix="zolana-copy-guard-") as temporary:
        scratch = Path(temporary) / "tree"
        scratch.mkdir()
        patch = Path(temporary) / "step.patch"
        for raw in (plan.base_patch, *(step.patch for step in plan.transitions)):
            patch.write_bytes(raw)
            if any(candidate_root_of(name) for name in source_tools.patch_paths(patch)):
                git_apply(scratch, patch, [candidate_root + "/*" for candidate_root, _ in PAIRS])
        copies = scratch_files(scratch)
    require(all(candidate_root_of(name) for name in copies), "Git applied a path outside the copies")
    return copies


def candidate_manifests(plan):
    """Cargo manifests of the two candidate crates, as the base patch adds them."""
    with tempfile.TemporaryDirectory(prefix="zolana-copy-guard-") as temporary:
        scratch = Path(temporary) / "tree"
        scratch.mkdir()
        patch = Path(temporary) / "base.patch"
        patch.write_bytes(plan.base_patch)
        if set(CANDIDATE_MANIFESTS) & source_tools.patch_paths(patch):
            git_apply(scratch, patch, CANDIDATE_MANIFESTS)
        return scratch_files(scratch)


def workspace_copies():
    """Return {repository path: bytes} for both workspace directories."""
    copies = {}
    for _, workspace_root in PAIRS:
        directory = ROOT.joinpath(*PurePosixPath(workspace_root).parts)
        require(directory.is_dir() and not directory.is_symlink(),
                f"workspace directory missing: {workspace_root}")
        for path in sorted(directory.rglob("*")):
            require(not path.is_symlink(), "workspace copy contains a symlink")
            if path.is_file():
                require(path.stat().st_size <= MAX_SOURCE_BYTES, "workspace copy exceeds size limit")
                copies[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    return copies


def workspace_name(candidate_name):
    for candidate_root, workspace_root in PAIRS:
        if candidate_name.startswith(candidate_root + "/"):
            return workspace_root + candidate_name[len(candidate_root):]
    raise ValueError("path outside the copy directories")


def unplanned_patches(plan):
    """Patch files in node/candidate, outside the plan, that touch a copy."""
    planned = {digest(plan.base_patch), *(digest(step.patch) for step in plan.transitions)}
    found = []
    directory = ROOT / "node/candidate"
    for path in sorted(directory.rglob("*.patch")):
        if path.is_symlink() or not path.is_file():
            continue
        if digest(path.read_bytes()) in planned:
            continue
        if any(candidate_root_of(name) for name in source_tools.patch_paths(path)):
            found.append(path.relative_to(ROOT).as_posix())
    return found


def pinned_requirement(dependencies):
    """The version requirement a Cargo dependency table places on the proof system."""
    value = dependencies.get(PINNED_DEPENDENCY) if isinstance(dependencies, dict) else None
    if isinstance(value, dict):
        value = value.get("version")
    return value if isinstance(value, str) else None


def dependency_problems(plan):
    problems = []
    root_manifest = tomllib.loads((ROOT / "Cargo.toml").read_bytes().decode())
    workspace = pinned_requirement(root_manifest.get("workspace", {}).get("dependencies"))
    if not (workspace or "").startswith("="):
        problems.append(f"Cargo.toml: the workspace does not pin {PINNED_DEPENDENCY} to one exact release.")
    manifests = candidate_manifests(plan)
    for name in CANDIDATE_MANIFESTS:
        if name not in manifests:
            problems.append(f"{name}: the candidate series no longer adds this manifest.")
            continue
        found = pinned_requirement(tomllib.loads(manifests[name].decode()).get("dependencies"))
        if found != workspace:
            problems.append(f"{name}: requires {PINNED_DEPENDENCY} {found!r}; "
                            f"the workspace requires {workspace!r}.")
    return problems


def load_allowlist(path):
    raw = candidate.bounded_file(path, 1024 * 1024)
    value = candidate.decode(raw)
    require(isinstance(value, dict) and set(value) == {
        "format", "plan_sha256", "differences", "workspace_only", "candidate_only"
    } and value["format"] == FORMAT, "invalid protocol copy allow-list")
    require(isinstance(value["plan_sha256"], str) and HEX.fullmatch(value["plan_sha256"]),
            "allow-list must pin the reconstruction plan")
    shapes = {
        "differences": {"candidate_sha256", "workspace_sha256", "unmatched_lines", "class", "review"},
        "workspace_only": {"workspace_sha256", "class", "review"},
        "candidate_only": {"candidate_sha256", "class", "review"},
    }
    for section, fields in shapes.items():
        entries = value[section]
        require(isinstance(entries, dict), f"allow-list section {section} must be an object")
        for name, entry in entries.items():
            candidate.relative_name(name)
            require(isinstance(entry, dict) and set(entry) == fields,
                    f"allow-list entry {name} must have exactly: {', '.join(sorted(fields))}")
            require(entry["class"] in CLASSES, f"allow-list entry {name} has an unknown class")
            require(isinstance(entry["review"], str) and len(entry["review"].strip()) >= 20,
                    f"allow-list entry {name} needs a written review")
            for field in fields & {"candidate_sha256", "workspace_sha256"}:
                require(isinstance(entry[field], str) and HEX.fullmatch(entry[field]),
                        f"allow-list entry {name} has an invalid hash")
            if "unmatched_lines" in fields:
                counts = entry["unmatched_lines"]
                require(isinstance(counts, dict) and set(counts) == {"candidate", "workspace"}
                        and all(type(count) is int and count >= 0 for count in counts.values()),
                        f"allow-list entry {name} has invalid line counts")
    return value


def compare(allowlist, candidate_files, workspace_files):
    """Return (result, problems) for one candidate tree against one workspace."""
    problems = []
    identical, known = [], []
    differences = allowlist["differences"]
    workspace_only = allowlist["workspace_only"]
    candidate_only = allowlist["candidate_only"]
    mapped = {workspace_name(name): raw for name, raw in candidate_files.items()}
    for name in sorted(set(mapped) | set(workspace_files)):
        ours, theirs = mapped.get(name), workspace_files.get(name)
        if ours is None:
            entry = workspace_only.get(name)
            if entry is None:
                problems.append(f"{name}: exists only in the workspace and is not recorded. "
                                "Add it to the candidate series or record why it has no counterpart.")
            elif entry["workspace_sha256"] != digest(theirs):
                problems.append(f"{name}: workspace-only file changed since it was reviewed.")
            else:
                known.append(name)
            continue
        if theirs is None:
            entry = candidate_only.get(name)
            if entry is None:
                problems.append(f"{name}: exists only in the candidate series and is not recorded.")
            elif entry["candidate_sha256"] != digest(ours):
                problems.append(f"{name}: candidate-only file changed since it was reviewed.")
            else:
                known.append(name)
            continue
        if ours == theirs:
            identical.append(name)
            if name in differences:
                problems.append(f"{name}: the copies are identical now. Delete its allow-list entry.")
            continue
        entry = differences.get(name)
        if entry is None:
            problems.append(f"{name}: the workspace and the candidate series differ and no reviewed "
                            "difference is recorded. Make the same change on both sides.")
            continue
        if entry["candidate_sha256"] != digest(ours):
            problems.append(f"{name}: the candidate copy changed since the difference was reviewed.")
        if entry["workspace_sha256"] != digest(theirs):
            problems.append(f"{name}: the workspace copy changed since the difference was reviewed. "
                            "Make the same change in the candidate series, or review the difference "
                            "again and update the allow-list.")
        if entry["unmatched_lines"] != unmatched_lines(ours, theirs):
            problems.append(f"{name}: recorded line counts do not describe the files.")
        known.append(name)
    present = set(mapped) | set(workspace_files)
    for section in (differences, workspace_only, candidate_only):
        for name in sorted(set(section) - present):
            problems.append(f"{name}: allow-list entry for a file that no longer exists. Delete it.")
    for name in sorted(set(workspace_only) & set(mapped)):
        problems.append(f"{name}: recorded as workspace-only but the candidate series has it now.")
    for name in sorted(set(candidate_only) & set(workspace_files)):
        problems.append(f"{name}: recorded as candidate-only but the workspace has it now.")
    result = {
        "format": RESULT_FORMAT,
        "identical": identical,
        "recorded_differences": sorted(set(known) & set(differences)),
        "recorded_workspace_only": sorted(set(known) & set(workspace_only)),
        "recorded_candidate_only": sorted(set(known) & set(candidate_only)),
        "behaviour_differences": sorted(
            name for section in (differences, workspace_only, candidate_only)
            for name, entry in section.items() if entry["class"] == "behaviour"),
    }
    return result, problems


def check(allowlist_path=None, plan_path=None):
    allowlist = load_allowlist(allowlist_path or DEFAULT_ALLOWLIST)
    plan = candidate.load_plan(plan_path or candidate.DEFAULT_PLAN, allowlist["plan_sha256"])
    result, problems = compare(allowlist, candidate_copies(plan), workspace_copies())
    for name in unplanned_patches(plan):
        problems.append(f"{name}: a patch outside the reconstruction plan changes a protocol copy.")
    problems.extend(dependency_problems(plan))
    result["plan_sha256"] = plan.sha256
    result["revisions"] = [step.revision for step in plan.transitions]
    return result, problems


def describe(allowlist_path=None, plan_path=None):
    """Hashes and counts of every pair as they are now, for a reviewer's update."""
    allowlist = load_allowlist(allowlist_path or DEFAULT_ALLOWLIST)
    plan = candidate.load_plan(plan_path or candidate.DEFAULT_PLAN, allowlist["plan_sha256"])
    mapped = {workspace_name(name): raw for name, raw in candidate_copies(plan).items()}
    workspace = workspace_copies()
    rows = {}
    for name in sorted(set(mapped) | set(workspace)):
        ours, theirs = mapped.get(name), workspace.get(name)
        row = {"candidate_sha256": digest(ours) if ours is not None else None,
               "workspace_sha256": digest(theirs) if theirs is not None else None}
        if ours is not None and theirs is not None:
            row["identical"] = ours == theirs
            row["unmatched_lines"] = unmatched_lines(ours, theirs)
        rows[name] = row
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "describe"))
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--plan", type=Path, default=candidate.DEFAULT_PLAN)
    args = parser.parse_args()
    if args.command == "describe":
        print(json.dumps(describe(args.allowlist, args.plan), indent=2, sort_keys=True))
        return
    result, problems = check(args.allowlist, args.plan)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        raise SystemExit(f"{len(problems)} protocol copy problem(s)")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
