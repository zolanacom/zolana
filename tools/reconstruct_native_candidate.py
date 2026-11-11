#!/usr/bin/env python3
"""Reconstruct a reviewed native candidate from local pinned source inputs.

The plan names the complete patch chain. Verification reads only repository
artifacts. Preparation applies it to a fresh extraction of the supplied local
archive and records the resulting source hashes. Neither command builds or
starts the candidate.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import tarfile
import tempfile

import prepare_native_candidate as source_tools

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = ROOT / "node/candidate/reconstruction-plan.json"
FORMAT = "zolana-native-reconstruction-plan-v1"
HEX = re.compile(r"[a-f0-9]{64}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def decode(raw):
    def unique(pairs):
        value = {}
        for name, item in pairs:
            require(name not in value, "duplicate JSON field")
            value[name] = item
        return value

    return json.loads(raw, object_pairs_hook=unique)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bounded_file(path, maximum):
    require(not path.is_symlink() and path.is_file(), "regular source artifact required")
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, "source artifact exceeds size limit")
    return raw


def relative_name(value):
    require(isinstance(value, str) and value != "", "relative source path required")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ("", ".", "..")
            for part in value.split("/")), "unsafe source path")
    return path


def artifact(reference, maximum):
    require(isinstance(reference, dict) and set(reference) == {"path", "sha256"},
            "source reference requires path and hash")
    relative = relative_name(reference["path"])
    require(relative.parts[:2] == ("node", "candidate"), "artifact outside candidate directory")
    expected = reference["sha256"]
    require(isinstance(expected, str) and HEX.fullmatch(expected), "invalid artifact hash")
    path = ROOT.joinpath(*relative.parts)
    for parent in (path, *path.parents):
        require(not parent.is_symlink(), "source artifact traverses a symlink")
        if parent == ROOT:
            break
    raw = bounded_file(path, maximum)
    require(digest(raw) == expected, "source artifact hash mismatch")
    return raw


def file_states(manifest):
    """Normalize the two retained transition-manifest representations."""
    files = manifest.get("files")
    require(isinstance(files, dict) and files, "transition file inventory required")
    normalized = {}
    for name, value in files.items():
        relative_name(name)
        require(isinstance(value, dict), "invalid transition file state")
        entry = {}
        for phase in ("before", "after"):
            state = value.get(phase)
            if phase in value:
                require(state is None or isinstance(state, dict), "invalid file state")
                size = state.get("bytes") if state is not None else None
                checksum = state.get("sha256") if state is not None else None
            else:
                require(phase + "_bytes" in value and phase + "_sha256" in value,
                        "missing transition phase")
                size, checksum = value[phase + "_bytes"], value[phase + "_sha256"]
            require((size is None and checksum is None) or (
                type(size) is int and size >= 0 and isinstance(checksum, str)
                and HEX.fullmatch(checksum)), "invalid transition file identity")
            entry[phase + "_bytes"] = size
            entry[phase + "_sha256"] = checksum
        normalized[name] = entry
    return normalized


@dataclass
class Transition:
    revision: str
    patch: bytes
    files: dict
    manifest_sha256: str


@dataclass
class Plan:
    sha256: str
    archive_sha256: str
    base_patch: bytes
    base_files: set[str]
    transitions: list[Transition]


def load_plan(path, expected):
    require(isinstance(expected, str) and HEX.fullmatch(expected), "pinned plan hash required")
    raw = bounded_file(path, 2 * 1024 * 1024)
    require(digest(raw) == expected, "reconstruction plan hash mismatch")
    value = decode(raw)
    require(isinstance(value, dict) and set(value) == {
        "format", "upstream_commit", "archive_sha256", "base_patch", "steps"
    } and value["format"] == FORMAT, "invalid reconstruction plan")
    require(value["upstream_commit"] == source_tools.UPSTREAM_COMMIT,
            "unsupported upstream source root")
    require(isinstance(value["archive_sha256"], str) and HEX.fullmatch(value["archive_sha256"]),
            "invalid upstream archive hash")
    base_patch = artifact(value["base_patch"], 16 * 1024 * 1024)
    steps = value["steps"]
    require(isinstance(steps, list) and 1 <= len(steps) <= 32, "bounded patch chain required")
    transitions, known, revisions = [], {}, set()
    with tempfile.TemporaryDirectory(prefix="zolana-patch-check-") as temporary:
        check_patch = Path(temporary) / "candidate.patch"
        check_patch.write_bytes(base_patch)
        base_files = source_tools.patch_paths(check_patch)
        for step in steps:
            require(isinstance(step, dict) and set(step) == {"revision", "manifest", "patch"},
                    "invalid reconstruction step")
            revision = step["revision"]
            require(isinstance(revision, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", revision)
                    and revision not in revisions, "invalid or duplicate revision")
            revisions.add(revision)
            manifest = decode(artifact(step["manifest"], 2 * 1024 * 1024))
            require(isinstance(manifest, dict), "transition manifest must be an object")
            patch = artifact(step["patch"], 16 * 1024 * 1024)
            files = file_states(manifest)
            check_patch.write_bytes(patch)
            require(source_tools.patch_paths(check_patch) == set(files),
                    "patch paths differ from transition inventory")
            for name, identity in files.items():
                before = identity["before_sha256"], identity["before_bytes"]
                require(name not in known or known[name] == before,
                        "patch chain has incompatible before and after states")
                known[name] = identity["after_sha256"], identity["after_bytes"]
            transitions.append(Transition(revision, patch, files, step["manifest"]["sha256"]))
    return Plan(expected, value["archive_sha256"], base_patch, base_files, transitions)


def summary(plan):
    return {
        "format": "zolana-native-reconstruction-result-v1",
        "plan_sha256": plan.sha256,
        "upstream_commit": source_tools.UPSTREAM_COMMIT,
        "archive_sha256": plan.archive_sha256,
        "base_patch_sha256": digest(plan.base_patch),
        "revisions": [step.revision for step in plan.transitions],
        "transition_manifests": {step.revision: step.manifest_sha256 for step in plan.transitions},
        "transition_files": len({name for step in plan.transitions for name in step.files}),
        "build_performed": False,
        "runtime_started": False,
    }


def prepare(plan, archive_path, output):
    parent = output.absolute().parent.resolve(strict=True)
    output = parent / output.name
    require(output.name not in ("", ".", "..") and not os.path.lexists(output),
            "fresh output directory required")
    require(archive_path.is_file(), "local upstream archive required")
    # Keep one descriptor across hash verification and extraction.
    with archive_path.open("rb") as source:
        before = os.fstat(source.fileno())
        require(hashlib.file_digest(source, "sha256").hexdigest() == plan.archive_sha256,
                "upstream archive hash mismatch")
        source.seek(0)
        with tarfile.open(fileobj=source, mode="r:gz") as archive:
            members = source_tools.checked_members(archive)
            output.mkdir(mode=0o700)
            source_tools.extract(archive, members, output)
        after = os.fstat(source.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                "upstream archive changed during extraction")
    with tempfile.TemporaryDirectory(prefix="zolana-patch-apply-") as temporary:
        patch = Path(temporary) / "candidate.patch"
        patch.write_bytes(plan.base_patch)
        source_tools.apply_patch(output, patch)
        final_files = {}
        for step in plan.transitions:
            source_tools.verify_transition(output, step.files, "before")
            patch.write_bytes(step.patch)
            source_tools.apply_patch(output, patch)
            source_tools.verify_transition(output, step.files, "after")
            final_files.update(step.files)
        source_tools.verify_transition(output, final_files, "after")
    result = summary(plan)
    result["prepared"] = True
    result["files"] = {}
    for name in sorted(plan.base_files | set(final_files)):
        path = output.joinpath(*PurePosixPath(name).parts)
        require(not path.is_symlink(), "final source file is a symlink")
        require(not os.path.lexists(path) or path.is_file(), "final source is not a regular file")
        result["files"][name] = ({"bytes": path.stat().st_size, "sha256": source_tools.sha256(path)}
                                  if path.is_file() else None)
    with (output / "zolana-reconstruction.json").open("x") as receipt:
        json.dump(result, receipt, indent=2, sort_keys=True)
        receipt.write("\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("verify-plan", "prepare"))
    parser.add_argument("--plan", type=Path, default=DEFAULT_PLAN)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    plan = load_plan(args.plan, args.plan_sha256)
    if args.command == "verify-plan":
        require(args.archive is None and args.output is None,
                "verify-plan takes no archive or output")
        result = summary(plan)
        result["prepared"] = False
    else:
        require(args.archive is not None and args.output is not None,
                "prepare requires a local archive and fresh output")
        result = prepare(plan, args.archive, args.output)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
