"""Source-only reconstruction checks with disposable archives and real Git apply."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import reconstruct_native_candidate as candidate


def checksum(raw):
    return hashlib.sha256(raw).hexdigest()


def state(raw):
    return None if raw is None else {"bytes": len(raw), "sha256": checksum(raw)}


class ReconstructionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repository = self.root / "repository"
        self.artifacts = self.repository / "node/candidate"
        self.artifacts.mkdir(parents=True)
        replacement = patch.object(candidate, "ROOT", self.repository)
        replacement.start()
        self.addCleanup(replacement.stop)
        self.archive = self.root / "source.tar.gz"
        self.write_archive()
        self.base = self.write("base.patch", b"diff --git a/base.txt b/base.txt\n--- a/base.txt\n+++ b/base.txt\n@@ -1 +1 @@\n-upstream\n+base\n"
                               b"diff --git a/base-only.txt b/base-only.txt\n--- a/base-only.txt\n+++ b/base-only.txt\n@@ -1 +1 @@\n-original\n+retained\n")
        self.first_patch = self.write("first.patch", b"diff --git a/base.txt b/base.txt\n--- a/base.txt\n+++ b/base.txt\n@@ -1 +1 @@\n-base\n+first\n"
                                      b"diff --git a/added.rs b/added.rs\nnew file mode 100644\n--- /dev/null\n+++ b/added.rs\n@@ -0,0 +1 @@\n+first\n")
        self.second_patch = self.write("second.patch", b"diff --git a/added.rs b/added.rs\n--- a/added.rs\n+++ b/added.rs\n@@ -1 +1 @@\n-first\n+second\n")
        self.first_manifest = self.write_json("first.json", {"files": {
            "base.txt": {"before": state(b"base\n"), "after": state(b"first\n")},
            "added.rs": {"before": None, "after": state(b"first\n")}}})
        self.second_manifest = self.write_json("second.json", {"files": {"added.rs": {
            "before_bytes": 6, "before_sha256": checksum(b"first\n"),
            "after_bytes": 7, "after_sha256": checksum(b"second\n")}}})
        self.plan_path = self.artifacts / "plan.json"
        self.output = self.root / "output"
        self.plan = {
            "format": candidate.FORMAT,
            "upstream_commit": candidate.source_tools.UPSTREAM_COMMIT,
            "archive_sha256": checksum(self.archive.read_bytes()),
            "base_patch": self.reference(self.base),
            "steps": [
                {"revision": "first", "manifest": self.reference(self.first_manifest), "patch": self.reference(self.first_patch)},
                {"revision": "second", "manifest": self.reference(self.second_manifest), "patch": self.reference(self.second_patch)}]}

    def write(self, name, raw):
        path = self.artifacts / name
        path.write_bytes(raw)
        return path

    def write_json(self, name, value):
        return self.write(name, json.dumps(value).encode())

    def reference(self, path):
        return {"path": path.relative_to(self.repository).as_posix(), "sha256": checksum(path.read_bytes())}

    def write_archive(self, extra=None):
        entries = {"base.txt": b"upstream\n", "base-only.txt": b"original\n", **(extra or {})}
        with tarfile.open(self.archive, "w:gz") as archive:
            info = tarfile.TarInfo(candidate.source_tools.ARCHIVE_ROOT)
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
            for name, raw in entries.items():
                info = tarfile.TarInfo(candidate.source_tools.ARCHIVE_ROOT + "/" + name)
                info.size = len(raw)
                archive.addfile(info, io.BytesIO(raw))

    def load(self):
        raw = json.dumps(self.plan).encode()
        self.plan_path.write_bytes(raw)
        return candidate.load_plan(self.plan_path, checksum(raw))

    def test_cli_prepares_complete_chain_from_local_archive(self):
        plan = self.load()
        arguments = ["reconstruct_native_candidate.py", "prepare", "--plan", str(self.plan_path),
                     "--plan-sha256", plan.sha256, "--archive", str(self.archive), "--output", str(self.output)]
        with patch.object(sys, "argv", arguments), contextlib.redirect_stdout(io.StringIO()) as output:
            candidate.main()
        result = json.loads(output.getvalue())
        self.assertTrue(result["prepared"])
        self.assertEqual((self.output / "base.txt").read_bytes(), b"first\n")
        self.assertEqual((self.output / "added.rs").read_bytes(), b"second\n")
        self.assertEqual(json.loads((self.output / "zolana-reconstruction.json").read_text()), result)
        self.assertEqual(result["revisions"], ["first", "second"])
        self.assertEqual(result["files"]["base-only.txt"], state(b"retained\n"))
        self.assertEqual(result["files"]["added.rs"], state(b"second\n"))
        self.assertFalse(result["build_performed"])
        self.assertFalse(result["runtime_started"])

    def test_mutated_manifest_or_patch_is_rejected_before_creation(self):
        for path in [self.first_manifest, self.first_patch]:
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            with self.assertRaisesRegex(ValueError, "artifact hash mismatch"):
                self.load()
            self.assertFalse(self.output.exists())
            path.write_bytes(original)

    def test_existing_output_and_wrong_archive_are_rejected(self):
        plan = self.load()
        self.output.mkdir()
        sentinel = self.output / "keep"
        sentinel.write_text("existing source")
        with self.assertRaisesRegex(ValueError, "fresh output"):
            candidate.prepare(plan, self.archive, self.output)
        self.assertEqual(sentinel.read_text(), "existing source")
        self.archive.write_bytes(self.archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "archive hash mismatch"):
            candidate.prepare(plan, self.archive, self.root / "fresh")
        self.assertFalse((self.root / "fresh").exists())

    def test_baseline_mismatch_retains_partial_source_without_applying_step(self):
        value = json.loads(self.first_manifest.read_text())
        value["files"]["base.txt"]["before"] = state(b"other\n")
        self.first_manifest.write_text(json.dumps(value))
        self.plan["steps"][0]["manifest"] = self.reference(self.first_manifest)
        plan = self.load()
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            candidate.prepare(plan, self.archive, self.output)
        self.assertEqual((self.output / "base.txt").read_bytes(), b"base\n")
        self.assertFalse((self.output / "added.rs").exists())
        self.assertFalse((self.output / "zolana-reconstruction.json").exists())

    def test_deletion_transition_and_receipt_retain_absence(self):
        deleted_patch = self.write("delete.patch", b"diff --git a/added.rs b/added.rs\ndeleted file mode 100644\n--- a/added.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-second\n")
        deleted_manifest = self.write_json("delete.json", {"files": {"added.rs": {
            "before": state(b"second\n"), "after": None}}})
        self.plan["steps"].append({"revision": "delete", "manifest": self.reference(deleted_manifest),
                                   "patch": self.reference(deleted_patch)})
        result = candidate.prepare(self.load(), self.archive, self.output)
        self.assertFalse((self.output / "added.rs").exists())
        self.assertIsNone(result["files"]["added.rs"])

    def test_output_symlink_is_refused_without_touching_its_target(self):
        target = self.root / "existing"
        target.mkdir()
        sentinel = target / "keep"
        sentinel.write_text("existing source")
        self.output.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "fresh output"):
            candidate.prepare(self.load(), self.archive, self.output)
        self.assertEqual(sentinel.read_text(), "existing source")

    def test_missing_or_reordered_transition_is_refused(self):
        self.plan["steps"].reverse()
        with self.assertRaisesRegex(ValueError, "incompatible"):
            self.load()
        self.plan["steps"] = self.plan["steps"][:1]
        plan = self.load()
        with self.assertRaisesRegex(ValueError, "missing|checksum"):
            candidate.prepare(plan, self.archive, self.output)
        self.assertFalse((self.output / "zolana-reconstruction.json").exists())

    def test_patch_extra_paths_and_unsafe_manifest_paths_are_rejected(self):
        self.second_patch.write_bytes(self.second_patch.read_bytes() +
            b"diff --git a/extra.rs b/extra.rs\nnew file mode 100644\n--- /dev/null\n+++ b/extra.rs\n@@ -0,0 +1 @@\n+extra\n")
        self.plan["steps"][1]["patch"] = self.reference(self.second_patch)
        with self.assertRaisesRegex(ValueError, "patch paths"):
            self.load()
        value = json.loads(self.first_manifest.read_text())
        value["files"]["../escape.rs"] = value["files"].pop("added.rs")
        self.first_manifest.write_text(json.dumps(value))
        self.plan["steps"][0]["manifest"] = self.reference(self.first_manifest)
        with self.assertRaisesRegex(ValueError, "unsafe source path"):
            self.load()

    def test_external_or_symlink_artifact_is_rejected(self):
        original = dict(self.plan["steps"][0]["manifest"])
        for name in ["../first.json", "/first.json", "tools/first.json"]:
            self.plan["steps"][0]["manifest"] = {**original, "path": name}
            with self.assertRaisesRegex(ValueError, "source path|candidate directory"):
                self.load()
        self.plan["steps"][0]["manifest"] = original
        moved = self.root / "original.json"
        self.first_manifest.rename(moved)
        self.first_manifest.symlink_to(moved)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.load()

    def test_archive_traversal_is_rejected_before_output_exists(self):
        self.write_archive({"../escape": b"escaped"})
        self.plan["archive_sha256"] = checksum(self.archive.read_bytes())
        plan = self.load()
        with self.assertRaisesRegex(ValueError, "archive path"):
            candidate.prepare(plan, self.archive, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse((self.root / "escape").exists())

    def test_duplicate_plan_fields_or_revisions_are_rejected(self):
        raw = b'{"format":"a","format":"b"}'
        self.plan_path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            candidate.load_plan(self.plan_path, checksum(raw))
        self.plan["steps"][1]["revision"] = "first"
        with self.assertRaisesRegex(ValueError, "duplicate revision"):
            self.load()

    def test_reviewed_repository_plan_verifies_all_historical_steps(self):
        with patch.object(candidate, "ROOT", Path(candidate.__file__).resolve().parents[1]):
            path = candidate.ROOT / "node/candidate/reconstruction-plan.json"
            plan = candidate.load_plan(path, "f7e49b5c08901b0c868b826f8f828215f025cf4b42499a7707b1d3763b8075b0")
        self.assertEqual(len(plan.transitions), 10)
        self.assertEqual(plan.transitions[-1].revision, "LOCAL-098-r3")
        self.assertEqual(candidate.summary(plan)["transition_files"], 53)


if __name__ == "__main__":
    unittest.main()
