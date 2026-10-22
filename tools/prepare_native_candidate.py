#!/usr/bin/env python3
"""Reproduce the isolated native-payment candidate from an already local archive.

This prepares source only. It never downloads, builds, starts validators, changes
an existing directory, or opens wallet keys. See node/candidate/README.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import subprocess
import sys
import tarfile

UPSTREAM_COMMIT = "a203300045b405f86c9c84308b2eae76af69ac3b"
UPSTREAM_VERSION = "4.3.2"
ARCHIVE_ROOT = f"agave-{UPSTREAM_COMMIT}"
ARCHIVE_SHA256 = "917912ac67fc0b6ffec94e33e1ce113db581e1f1706aa1ecbe4224b967b15f30"
DEFAULT_PATCH = Path(__file__).resolve().parents[1] / "node/candidate/agave-4.3.2.patch"
REVISION_057_SPEC = DEFAULT_PATCH.parent / "LOCAL-057-source.json"
REVISION_057_SPEC_SHA256 = "8ee2c21f73527f49dec403eb9e64cca412b230a5fde50b6bdf3000534e06dfe6"
REVISION_057_FILES = frozenset(['Cargo.lock', 'rpc/Cargo.toml', 'rpc/src/rpc.rs', 'rpc/src/rpc/native_private_fee.rs'])
REVISION_058_SPEC = DEFAULT_PATCH.parent / "LOCAL-058-source.json"
REVISION_058_SPEC_SHA256 = "727c5dc94fb20cb5f3cd512360ea4f7492664b9ee9101afa59772fed00e24a2c"
REVISION_058_FILES = frozenset(['Cargo.lock', 'zolana-fast-check/Cargo.toml',
                              'zolana-fast-check/src/main.rs', 'zolana-fast-check/src/service.rs'])
REVISION_059_SPEC = DEFAULT_PATCH.parent / "LOCAL-059-source.json"
REVISION_059_SPEC_SHA256 = "d11952a9f613a7dcfc679f4eff9dd5de6081d47740688d1863226db7b113ec19"
REVISION_059_FILES = frozenset(['zolana-fast-check/src/ancestry.rs',
                              'zolana-fast-check/src/ancestry_tests.rs',
                              'zolana-fast-check/src/main.rs',
                              'zolana-fast-check/src/resume.rs',
                              'zolana-fast-check/src/service.rs'])


REVISION_072_SPEC = DEFAULT_PATCH.parent / "LOCAL-072-source.json"
REVISION_072_SPEC_SHA256 = "57a947addd2dff75665241af64a40be3ed9d07b9bd64e3e57cc94e2c37bb10d2"
REVISION_072_FILES = frozenset([
    'Cargo.lock', 'dev-bins/Cargo.toml', 'dev-bins/Cargo.lock',
    'ledger-tool/src/main.rs', 'ledger-tool/src/ledger_utils.rs',
    'zolana-fast-check/Cargo.toml', 'zolana-fast-check/src/main.rs',
    'zolana-fast-check/src/resume.rs', 'zolana-fast-check/src/service.rs',
    'zolana-fast-check/src/restart_snapshots.rs',
    'zolana-fast-check/src/bin/snapshot-provenance.rs',
])


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def checked_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    seen: set[str] = set()
    for member in members:
        path = PurePosixPath(member.name)
        if (
            path.is_absolute()
            or ".." in path.parts
            or not path.parts
            or path.parts[0] != ARCHIVE_ROOT
            or member.name in seen
        ):
            raise ValueError(f"unexpected pinned archive path: {member.name!r}")
        seen.add(member.name)
        if not (member.isdir() or member.isfile() or member.issym()):
            raise ValueError(f"unsupported archive entry: {member.name!r}")
        if member.issym():
            target = PurePosixPath(member.linkname)
            resolved = PurePosixPath(posixpath.normpath(str(path.parent / target)))
            if target.is_absolute() or not resolved.parts or resolved.parts[0] != ARCHIVE_ROOT:
                raise ValueError(f"archive symlink leaves pinned source: {member.name!r}")
    if not members or ARCHIVE_ROOT not in seen:
        raise ValueError("archive does not contain the exact full-commit root directory")
    return members


def extract(archive: tarfile.TarFile, members: list[tarfile.TarInfo], output: Path) -> None:
    for member in members:
        parts = PurePosixPath(member.name).parts[1:]
        if not parts:
            continue
        path = output.joinpath(*parts)
        # Never follow an archive-created symlink while creating another entry.
        if any(parent.is_symlink() for parent in path.parents if parent != output.parent):
            raise ValueError(f"archive path traverses a symlink: {member.name!r}")
        if member.isdir():
            path.mkdir(parents=True, exist_ok=True)
        elif member.issym():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(member.linkname)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise ValueError(f"missing archive file data: {member.name!r}")
            with source, path.open("xb") as destination:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    destination.write(block)
            path.chmod(member.mode & 0o777)


def revision_057_spec(patch: Path) -> dict:
    if sha256(REVISION_057_SPEC) != REVISION_057_SPEC_SHA256:
        raise ValueError("LOCAL-057 transition manifest checksum mismatch")
    spec = json.loads(REVISION_057_SPEC.read_bytes())
    if (spec.get("format") != "zolana-native-sdk4-delta-v1"
            or spec.get("revision") != "LOCAL-057"
            or spec.get("upstream_commit") != UPSTREAM_COMMIT
            or spec.get("archive_sha256") != ARCHIVE_SHA256
            or set(spec.get("files", {})) != REVISION_057_FILES
            or patch.name != spec["baseline_patch"]
            or sha256(patch) != spec["baseline_patch_sha256"]):
        raise ValueError("LOCAL-057 requires the exact frozen LOCAL-056 baseline patch")
    delta = REVISION_057_SPEC.parent / spec["delta_patch"]
    if delta.is_symlink() or not delta.is_file() or sha256(delta) != spec["delta_patch_sha256"]:
        raise ValueError("LOCAL-057 delta patch checksum mismatch")
    return spec


def verify_transition(root: Path, files: dict, side: str) -> None:
    for relative, identity in files.items():
        parts = PurePosixPath(relative)
        if parts.is_absolute() or ".." in parts.parts or not parts.parts:
            raise ValueError("unsafe transition file path")
        path = root.joinpath(*parts.parts)
        if any(root.joinpath(*parts.parts[:index]).is_symlink()
               for index in range(1, len(parts.parts) + 1)):
            raise ValueError(f"transition path traverses a symlink: {relative}")
        expected = identity[f"{side}_sha256"]
        if expected is None:
            if os.path.lexists(path):
                raise ValueError(f"transition requires an absent file: {relative}")
        elif (not path.is_file() or path.stat().st_size != identity[f"{side}_bytes"]
                or sha256(path) != expected):
            raise ValueError(f"transition {side} file checksum mismatch: {relative}")


def revision_058_spec(parent: dict) -> dict:
    if sha256(REVISION_058_SPEC) != REVISION_058_SPEC_SHA256:
        raise ValueError("LOCAL-058 transition manifest checksum mismatch")
    spec = json.loads(REVISION_058_SPEC.read_bytes())
    if (spec.get("format") != "zolana-native-sdk4-delta-v1"
            or spec.get("revision") != "LOCAL-058"
            or spec.get("upstream_commit") != UPSTREAM_COMMIT
            or spec.get("archive_sha256") != ARCHIVE_SHA256
            or set(spec.get("files", {})) != REVISION_058_FILES
            or spec.get("baseline_revision") != "LOCAL-057"
            or spec.get("baseline_delta_manifest") != REVISION_057_SPEC.name
            or spec.get("baseline_delta_manifest_sha256") != REVISION_057_SPEC_SHA256
            or spec.get("baseline_delta_patch") != parent["delta_patch"]
            or spec.get("baseline_delta_patch_sha256") != parent["delta_patch_sha256"]):
        raise ValueError("LOCAL-058 requires the exact frozen LOCAL-057 transition")
    delta = REVISION_058_SPEC.parent / spec["delta_patch"]
    if delta.is_symlink() or not delta.is_file() or sha256(delta) != spec["delta_patch_sha256"]:
        raise ValueError("LOCAL-058 delta patch checksum mismatch")
    return spec


def patch_paths(patch: Path) -> set[str]:
    paths = set()
    for line in patch.read_text().splitlines():
        if not line.startswith("diff --git "):
            continue
        parts = line.split(" ")
        if len(parts) != 4 or not parts[2].startswith("a/") or parts[3] != "b/" + parts[2][2:]:
            raise ValueError("candidate patches must use explicit unchanged relative file paths")
        relative = parts[2][2:]
        path = PurePosixPath(relative)
        if path.is_absolute() or any(part in ("", ".", "..") for part in relative.split("/")):
            raise ValueError("unsafe candidate patch path")
        paths.add(relative)
    if not paths:
        raise ValueError("candidate patch contains no file paths")
    return paths


def revision_059_spec(parent: dict) -> dict:
    if sha256(REVISION_059_SPEC) != REVISION_059_SPEC_SHA256:
        raise ValueError("LOCAL-059 transition manifest checksum mismatch")
    spec = json.loads(REVISION_059_SPEC.read_bytes())
    if (spec.get("format") != "zolana-native-sdk4-delta-v1"
            or spec.get("revision") != "LOCAL-059"
            or spec.get("upstream_commit") != UPSTREAM_COMMIT
            or spec.get("archive_sha256") != ARCHIVE_SHA256
            or set(spec.get("files", {})) != REVISION_059_FILES
            or spec.get("baseline_revision") != "LOCAL-058"
            or spec.get("baseline_delta_manifest") != REVISION_058_SPEC.name
            or spec.get("baseline_delta_manifest_sha256") != REVISION_058_SPEC_SHA256
            or spec.get("baseline_delta_patch") != parent["delta_patch"]
            or spec.get("baseline_delta_patch_sha256") != parent["delta_patch_sha256"]):
        raise ValueError("LOCAL-059 requires the exact frozen LOCAL-058 transition")
    delta = REVISION_059_SPEC.parent / spec["delta_patch"]
    if delta.is_symlink() or not delta.is_file() or sha256(delta) != spec["delta_patch_sha256"]:
        raise ValueError("LOCAL-059 delta patch checksum mismatch")
    expected = patch_paths(DEFAULT_PATCH) | REVISION_057_FILES | REVISION_058_FILES | REVISION_059_FILES
    if set(spec.get("final_files", {})) != expected or patch_paths(delta) != REVISION_059_FILES:
        raise ValueError("LOCAL-059 complete final changed-file inventory mismatch")
    return spec


def revision_072_spec(parent: dict) -> dict:
    if (REVISION_072_SPEC.is_symlink() or not REVISION_072_SPEC.is_file()
            or sha256(REVISION_072_SPEC) != REVISION_072_SPEC_SHA256):
        raise ValueError("LOCAL-072 transition manifest checksum mismatch")
    spec = json.loads(REVISION_072_SPEC.read_bytes())
    if (spec.get("format") != "zolana-native-sdk4-delta-v1"
            or spec.get("revision") != "LOCAL-072"
            or spec.get("upstream_commit") != UPSTREAM_COMMIT
            or spec.get("archive_sha256") != ARCHIVE_SHA256
            or set(spec.get("files", {})) != REVISION_072_FILES
            or spec.get("baseline_revision") != "LOCAL-059"
            or spec.get("baseline_delta_manifest") != REVISION_059_SPEC.name
            or spec.get("baseline_delta_manifest_sha256") != REVISION_059_SPEC_SHA256
            or spec.get("baseline_delta_patch") != parent["delta_patch"]
            or spec.get("baseline_delta_patch_sha256") != parent["delta_patch_sha256"]
            or spec.get("delta_patch") != "agave-4.3.2-LOCAL-072.patch"):
        raise ValueError("LOCAL-072 requires the exact frozen LOCAL-059 transition")
    delta = REVISION_072_SPEC.parent / spec["delta_patch"]
    if delta.is_symlink() or not delta.is_file() or sha256(delta) != spec["delta_patch_sha256"]:
        raise ValueError("LOCAL-072 delta patch checksum mismatch")
    expected = dict(parent["final_files"])
    for name, identity in spec["files"].items():
        expected[name] = {"sha256": identity["after_sha256"], "bytes": identity["after_bytes"]}
    if (spec.get("final_files") != expected
            or patch_paths(delta) != REVISION_072_FILES):
        raise ValueError("LOCAL-072 complete final changed-file inventory mismatch")
    return spec


def verify_final_files(root: Path, files: dict) -> None:
    verify_transition(root, {name: {"after_sha256": identity["sha256"], "after_bytes": identity["bytes"]}
                             for name, identity in files.items()}, "after")


def apply_patch(output: Path, patch: Path) -> None:
    # This fresh source may be inside an ignored subdirectory of another Git
    # worktree. Even --no-index otherwise discovers that worktree and silently
    # skips every patch outside its cwd prefix while returning success.
    environment = os.environ.copy()
    for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR",
                 "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"):
        environment.pop(name, None)
    environment["GIT_CEILING_DIRECTORIES"] = str(output.parent.resolve(strict=True))
    for arguments in (
        ["git", "apply", "--no-index", "--verbose", "--check", str(patch)],
        ["git", "apply", "--no-index", "--verbose", "--whitespace=nowarn", str(patch)],
    ):
        result = subprocess.run(arguments, cwd=output, env=environment, check=True,
                                capture_output=True, text=True)
        if "Skipped patch " in result.stderr or "Skipped patch " in result.stdout:
            raise ValueError("Git skipped a source patch; refusing an unpatched output")


def prepare(archive_path: Path, output: Path, patch: Path, manifest: bool,
            native_fee_057: bool = False, native_service_058: bool = False,
            native_restart_059: bool = False, native_restart_snapshot_072: bool = False) -> dict:
    if sum((native_fee_057, native_service_058, native_restart_059, native_restart_snapshot_072)) > 1:
        raise ValueError("choose exactly one opt-in candidate revision")
    archive_path = archive_path.resolve(strict=True)
    patch = patch.resolve(strict=True)
    if not archive_path.is_file() or not patch.is_file():
        raise ValueError("archive and patch must be regular local files")
    revision = revision_057_spec(patch) if any((native_fee_057, native_service_058, native_restart_059, native_restart_snapshot_072)) else None
    service_revision = revision_058_spec(revision) if native_service_058 or native_restart_059 or native_restart_snapshot_072 else None
    restart_revision = revision_059_spec(service_revision) if native_restart_059 or native_restart_snapshot_072 else None
    snapshot_revision = revision_072_spec(restart_revision) if native_restart_snapshot_072 else None
    actual = sha256(archive_path)
    if actual != ARCHIVE_SHA256:
        raise ValueError(f"pinned archive checksum mismatch: expected {ARCHIVE_SHA256}, got {actual}")
    # Normalize only the existing parent; the fresh leaf must not be a symlink or
    # an existing file/directory, including a dangling symlink.
    output = output.expanduser().absolute()
    if output.name in ("", ".", ".."):
        raise ValueError("output must name a fresh source directory")
    parent = output.parent.resolve(strict=True)
    output = parent / output.name
    if os.path.lexists(output):
        raise ValueError(f"refusing existing output: {output}")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = checked_members(archive)
        output.mkdir(mode=0o700)
        extract(archive, members, output)
    apply_patch(output, patch)
    if revision is not None:
        verify_transition(output, revision["files"], "before")
        apply_patch(output, REVISION_057_SPEC.parent / revision["delta_patch"])
        verify_transition(output, revision["files"], "after")
    if service_revision is not None:
        verify_transition(output, service_revision["files"], "before")
        apply_patch(output, REVISION_058_SPEC.parent / service_revision["delta_patch"])
        verify_transition(output, service_revision["files"], "after")
    if restart_revision is not None:
        verify_transition(output, restart_revision["files"], "before")
        apply_patch(output, REVISION_059_SPEC.parent / restart_revision["delta_patch"])
        verify_transition(output, restart_revision["files"], "after")
        verify_final_files(output, restart_revision["final_files"])
    if snapshot_revision is not None:
        verify_transition(output, snapshot_revision["files"], "before")
        apply_patch(output, REVISION_072_SPEC.parent / snapshot_revision["delta_patch"])
        verify_transition(output, snapshot_revision["files"], "after")
        verify_final_files(output, snapshot_revision["final_files"])
    result = {
        "format": "zolana-native-source-candidate-v1",
        "upstream_commit": UPSTREAM_COMMIT,
        "upstream_version": UPSTREAM_VERSION,
        "archive_sha256": actual,
        "patch_sha256": sha256(patch),
        "scope": "source preparation only; no build or validator execution",
    }
    if revision is not None:
        result.update(revision="LOCAL-057", baseline_patch_sha256=revision["baseline_patch_sha256"],
                      delta_patch_sha256=revision["delta_patch_sha256"],
                      delta_manifest_sha256=REVISION_057_SPEC_SHA256,
                      cargo_lock_sha256=revision["files"]["Cargo.lock"]["after_sha256"])
    if service_revision is not None:
        result.update(revision="LOCAL-058", baseline_revision="LOCAL-057",
                      baseline_delta_patch_sha256=revision["delta_patch_sha256"],
                      baseline_delta_manifest_sha256=REVISION_057_SPEC_SHA256,
                      delta_patch_sha256=service_revision["delta_patch_sha256"],
                      delta_manifest_sha256=REVISION_058_SPEC_SHA256,
                      cargo_lock_sha256=service_revision["files"]["Cargo.lock"]["after_sha256"])
    if restart_revision is not None:
        result.update(revision="LOCAL-059", baseline_revision="LOCAL-058",
                      baseline_delta_patch_sha256=service_revision["delta_patch_sha256"],
                      baseline_delta_manifest_sha256=REVISION_058_SPEC_SHA256,
                      delta_patch_sha256=restart_revision["delta_patch_sha256"],
                      delta_manifest_sha256=REVISION_059_SPEC_SHA256,
                      changed_files=restart_revision["final_files"],
                      source_chain=[dict(revision="LOCAL-056", patch_sha256=revision["baseline_patch_sha256"]),
                                    dict(revision="LOCAL-057", patch_sha256=revision["delta_patch_sha256"],
                                         manifest_sha256=REVISION_057_SPEC_SHA256),
                                    dict(revision="LOCAL-058", patch_sha256=service_revision["delta_patch_sha256"],
                                         manifest_sha256=REVISION_058_SPEC_SHA256),
                                    dict(revision="LOCAL-059", patch_sha256=restart_revision["delta_patch_sha256"],
                                         manifest_sha256=REVISION_059_SPEC_SHA256)])
    if snapshot_revision is not None:
        result.update(revision="LOCAL-072", baseline_revision="LOCAL-059",
                      baseline_delta_patch_sha256=restart_revision["delta_patch_sha256"],
                      baseline_delta_manifest_sha256=REVISION_059_SPEC_SHA256,
                      delta_patch_sha256=snapshot_revision["delta_patch_sha256"],
                      delta_manifest_sha256=REVISION_072_SPEC_SHA256,
                      cargo_lock_sha256=snapshot_revision["files"]["Cargo.lock"]["after_sha256"],
                      dev_bins_cargo_lock_sha256=snapshot_revision["files"]["dev-bins/Cargo.lock"]["after_sha256"],
                      changed_files=snapshot_revision["final_files"])
        result["source_chain"].append(dict(revision="LOCAL-072",
            patch_sha256=snapshot_revision["delta_patch_sha256"], manifest_sha256=REVISION_072_SPEC_SHA256))
    if manifest:
        with (output / "zolana-candidate.json").open("x") as target:
            json.dump(result, target, indent=2, sort_keys=True)
            target.write("\n")
    return {**result, "output": str(output)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path, help="already local exact pinned GitHub source tar.gz")
    parser.add_argument("--output", required=True, type=Path, help="new source directory; parent must already exist")
    parser.add_argument("--patch", type=Path, default=DEFAULT_PATCH, help="auditable local candidate patch")
    parser.add_argument("--manifest", action="store_true", help="write source checksums inside the new output")
    revisions = parser.add_mutually_exclusive_group()
    revisions.add_argument("--native-fee-057", action="store_true",
                        help="explicit LOCAL-057 private fee RPC delta on the exact frozen LOCAL-056 baseline")
    revisions.add_argument("--native-service-058", action="store_true",
                        help="explicit LOCAL-058 resume-only service delta on the exact frozen LOCAL-057 chain")
    revisions.add_argument("--native-restart-059", action="store_true",
                        help="explicit LOCAL-059 original-checkpoint ancestry delta on the exact frozen LOCAL-058 chain")
    revisions.add_argument("--native-restart-snapshot-072", action="store_true",
                        help="explicit LOCAL-072 verified full-snapshot restart delta on the exact frozen LOCAL-059 chain")
    args = parser.parse_args()
    try:
        result = prepare(args.archive, args.output, args.patch, args.manifest,
                         args.native_fee_057, args.native_service_058, args.native_restart_059,
                         args.native_restart_snapshot_072)
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", None) or str(error)
        print(f"source preparation failed: {detail}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
