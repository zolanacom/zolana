"""Source-only checks; these tests never download, build or start validators."""
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import prepare_native_candidate as candidate


class SourcePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self):
        self.temp.cleanup()

    def test_patch_is_applied_inside_another_worktree_with_inherited_git_environment(self):
        repository = self.root / "parent"
        repository.mkdir()
        subprocess.run(["git", "init", "--quiet", str(repository)], check=True)
        (repository / "Cargo.lock").write_text("parent must remain unchanged\n")
        output = repository / ".local" / "new-source"
        output.mkdir(parents=True)
        (output / "Cargo.lock").write_text("upstream\n")
        source_patch = self.root / "source.patch"
        source_patch.write_text(
            "diff --git a/Cargo.lock b/Cargo.lock\n"
            "--- a/Cargo.lock\n+++ b/Cargo.lock\n"
            "@@ -1 +1 @@\n-upstream\n+candidate\n"
            "diff --git a/added.rs b/added.rs\n"
            "new file mode 100644\n--- /dev/null\n+++ b/added.rs\n"
            "@@ -0,0 +1 @@\n+native\n"
        )
        with patch.dict(os.environ, {
            "GIT_DIR": str(repository / ".git"),
            "GIT_WORK_TREE": str(repository),
            "GIT_INDEX_FILE": str(repository / ".git/index"),
        }):
            candidate.apply_patch(output, source_patch)
        self.assertEqual((output / "Cargo.lock").read_text(), "candidate\n")
        self.assertEqual((output / "added.rs").read_text(), "native\n")
        self.assertEqual((repository / "Cargo.lock").read_text(), "parent must remain unchanged\n")
        self.assertFalse((output / ".git").exists())

    def test_even_a_successful_git_exit_cannot_hide_a_skipped_patch(self):
        output = self.root / "source"
        output.mkdir()
        completed = subprocess.CompletedProcess([], 0, "", "Skipped patch 'Cargo.lock'.\n")
        with patch.object(candidate.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(ValueError, "skipped"):
                candidate.apply_patch(output, self.root / "source.patch")

    def test_frozen_manifest_and_delta_match_and_wrong_baseline_is_rejected(self):
        spec = candidate.revision_057_spec(candidate.DEFAULT_PATCH)
        self.assertEqual(set(spec["files"]), candidate.REVISION_057_FILES)
        altered = self.root / candidate.DEFAULT_PATCH.name
        altered.write_bytes(candidate.DEFAULT_PATCH.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "exact frozen"):
            candidate.revision_057_spec(altered)

    def test_changed_manifest_or_delta_is_rejected_before_source_creation(self):
        spec_path = self.root / "LOCAL-057-source.json"
        spec_path.write_bytes(candidate.REVISION_057_SPEC.read_bytes() + b"\n")
        with patch.object(candidate, "REVISION_057_SPEC", spec_path):
            with self.assertRaisesRegex(ValueError, "manifest checksum"):
                candidate.revision_057_spec(candidate.DEFAULT_PATCH)
        spec_path.write_bytes(candidate.REVISION_057_SPEC.read_bytes())
        spec = json.loads(spec_path.read_bytes())
        (self.root / spec["delta_patch"]).write_bytes(b"different delta")
        with patch.object(candidate, "REVISION_057_SPEC", spec_path):
            with self.assertRaisesRegex(ValueError, "delta patch checksum"):
                candidate.revision_057_spec(candidate.DEFAULT_PATCH)

    def test_transition_checks_bytes_absence_and_symlink_components(self):
        source = self.root / "source"
        source.mkdir()
        content = b"baseline\n"
        (source / "Cargo.lock").write_bytes(content)
        files = {
            "Cargo.lock": {"before_sha256": hashlib.sha256(content).hexdigest(), "before_bytes": len(content)},
            "rpc/new.rs": {"before_sha256": None, "before_bytes": None},
        }
        candidate.verify_transition(source, files, "before")
        (source / "Cargo.lock").write_bytes(b"modified\n")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            candidate.verify_transition(source, files, "before")
        (source / "Cargo.lock").write_bytes(content)
        (source / "rpc").mkdir()
        (source / "rpc/new.rs").write_bytes(b"unexpected existing source")
        with self.assertRaisesRegex(ValueError, "absent"):
            candidate.verify_transition(source, files, "before")
        (source / "rpc/new.rs").unlink()
        (source / "rpc").rmdir()
        (source / "rpc").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            candidate.verify_transition(source, files, "before")

    def test_service_transition_requires_exact_parent_and_its_own_delta(self):
        parent = candidate.revision_057_spec(candidate.DEFAULT_PATCH)
        spec = candidate.revision_058_spec(parent)
        self.assertEqual(set(spec["files"]), candidate.REVISION_058_FILES)
        self.assertEqual(spec["files"]["Cargo.lock"]["before_sha256"],
                         parent["files"]["Cargo.lock"]["after_sha256"])
        changed = dict(parent, delta_patch_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "exact frozen LOCAL-057"):
            candidate.revision_058_spec(changed)
        copied = self.root / candidate.REVISION_058_SPEC.name
        copied.write_bytes(candidate.REVISION_058_SPEC.read_bytes())
        (self.root / spec["delta_patch"]).write_bytes(b"changed service delta")
        with patch.object(candidate, "REVISION_058_SPEC", copied):
            with self.assertRaisesRegex(ValueError, "LOCAL-058 delta patch checksum"):
                candidate.revision_058_spec(parent)

    def test_candidate_revision_flags_are_mutually_exclusive_before_any_io(self):
        for flags in (flags for flags in itertools.product((False, True), repeat=4) if sum(flags) > 1):
            with self.subTest(flags=flags), self.assertRaisesRegex(ValueError, "exactly one"):
                candidate.prepare(self.root / "missing.tar.gz", self.root / "untouched",
                                  candidate.DEFAULT_PATCH, False, *flags)
        self.assertFalse((self.root / "untouched").exists())

    def test_patch_inventory_rejects_renames_absolute_and_parent_paths(self):
        path=self.root/'candidate.patch'
        for header in ('diff --git a/old.rs b/new.rs','diff --git a/../old.rs b/../old.rs',
                       'diff --git a//absolute.rs b//absolute.rs'):
            path.write_text(header+'\n')
            with self.subTest(header=header),self.assertRaises(ValueError):candidate.patch_paths(path)
        self.assertEqual(len(candidate.patch_paths(candidate.DEFAULT_PATCH)),78)

    def test_final_changed_files_check_all_content_and_refuse_symlink_replacement(self):
        source=self.root/'final';source.mkdir();content=b'original retained safety checks\n'
        (source/'resume.rs').write_bytes(content)
        (source/'tests.rs').write_bytes(b'new ancestry guards\n')
        files={name:dict(sha256=hashlib.sha256((source/name).read_bytes()).hexdigest(),bytes=(source/name).stat().st_size)
               for name in ('resume.rs','tests.rs')}
        candidate.verify_final_files(source,files)
        (source/'tests.rs').write_bytes(b'tampered tests\n')
        with self.assertRaisesRegex(ValueError,'checksum mismatch'):candidate.verify_final_files(source,files)
        (source/'tests.rs').unlink();(source/'tests.rs').symlink_to(source/'resume.rs')
        with self.assertRaisesRegex(ValueError,'symlink'):candidate.verify_final_files(source,files)

    def test_restart_transition_pins_parent_new_tests_and_complete_final_inventory(self):
        parent=candidate.revision_058_spec(candidate.revision_057_spec(candidate.DEFAULT_PATCH))
        spec=candidate.revision_059_spec(parent)
        self.assertEqual(set(spec['files']),candidate.REVISION_059_FILES)
        for name in ('zolana-fast-check/src/ancestry.rs','zolana-fast-check/src/ancestry_tests.rs'):
            self.assertIsNone(spec['files'][name]['before_sha256'])
            self.assertIsNone(spec['files'][name]['before_bytes'])
            self.assertGreater(spec['files'][name]['after_bytes'],0)
        self.assertEqual(spec['final_files']['Cargo.lock']['sha256'],parent['files']['Cargo.lock']['after_sha256'])
        self.assertEqual(set(spec['final_files']),candidate.patch_paths(candidate.DEFAULT_PATCH)|
                         candidate.REVISION_057_FILES|candidate.REVISION_058_FILES|candidate.REVISION_059_FILES)
        changed=dict(parent,delta_patch_sha256='0'*64)
        with self.assertRaisesRegex(ValueError,'exact frozen LOCAL-058'):candidate.revision_059_spec(changed)

    def test_restart_manifest_delta_and_inventory_tampering_is_rejected(self):
        parent=candidate.revision_058_spec(candidate.revision_057_spec(candidate.DEFAULT_PATCH))
        copied=self.root/candidate.REVISION_059_SPEC.name
        copied.write_bytes(candidate.REVISION_059_SPEC.read_bytes()+b'\n')
        with patch.object(candidate,'REVISION_059_SPEC',copied):
            with self.assertRaisesRegex(ValueError,'manifest checksum'):candidate.revision_059_spec(parent)
        copied.write_bytes(candidate.REVISION_059_SPEC.read_bytes());spec=json.loads(copied.read_bytes())
        delta=self.root/spec['delta_patch'];delta.write_bytes(b'changed ancestry delta')
        with patch.object(candidate,'REVISION_059_SPEC',copied):
            with self.assertRaisesRegex(ValueError,'delta patch checksum'):candidate.revision_059_spec(parent)
        delta.write_bytes((candidate.REVISION_059_SPEC.parent/spec['delta_patch']).read_bytes())
        del spec['final_files']['zolana-fast-check/src/ancestry_tests.rs']
        copied.write_text(json.dumps(spec))
        with patch.object(candidate,'REVISION_059_SPEC',copied),\
             patch.object(candidate,'REVISION_059_SPEC_SHA256',candidate.sha256(copied)):
            with self.assertRaisesRegex(ValueError,'inventory mismatch'):candidate.revision_059_spec(parent)


    def snapshot_parent(self):
        return candidate.revision_059_spec(candidate.revision_058_spec(
            candidate.revision_057_spec(candidate.DEFAULT_PATCH)))

    def test_snapshot_transition_pins_exact_parent_both_locks_and_provenance(self):
        parent = self.snapshot_parent()
        spec = candidate.revision_072_spec(parent)
        self.assertEqual(set(spec['files']), candidate.REVISION_072_FILES)
        self.assertEqual(len(spec['final_files']), 90)
        self.assertEqual(spec['files']['Cargo.lock']['before_sha256'],
                         parent['final_files']['Cargo.lock']['sha256'])
        for name in ('zolana-fast-check/src/restart_snapshots.rs',
                     'zolana-fast-check/src/bin/snapshot-provenance.rs'):
            self.assertIsNone(spec['files'][name]['before_sha256'])
            self.assertGreater(spec['files'][name]['after_bytes'], 0)
        self.assertEqual(spec['dev_bins_lock']['resolved_sha256'],
                         spec['files']['dev-bins/Cargo.lock']['after_sha256'])
        self.assertEqual(candidate.patch_paths(candidate.REVISION_072_SPEC.parent / spec['delta_patch']),
                         candidate.REVISION_072_FILES)
        with self.assertRaisesRegex(ValueError, 'exact frozen LOCAL-059'):
            candidate.revision_072_spec(dict(parent, delta_patch_sha256='0' * 64))

    def test_snapshot_manifest_delta_and_complete_inventory_fail_closed(self):
        parent = self.snapshot_parent()
        copied = self.root / candidate.REVISION_072_SPEC.name
        copied.write_bytes(candidate.REVISION_072_SPEC.read_bytes() + b'\n')
        with patch.object(candidate, 'REVISION_072_SPEC', copied):
            with self.assertRaisesRegex(ValueError, 'manifest checksum'):
                candidate.revision_072_spec(parent)
        copied.write_bytes(candidate.REVISION_072_SPEC.read_bytes())
        spec = json.loads(copied.read_bytes())
        delta = self.root / spec['delta_patch']
        delta.write_bytes(b'changed snapshot delta')
        with patch.object(candidate, 'REVISION_072_SPEC', copied):
            with self.assertRaisesRegex(ValueError, 'delta patch checksum'):
                candidate.revision_072_spec(parent)
        delta.write_bytes((candidate.REVISION_072_SPEC.parent / spec['delta_patch']).read_bytes())
        # A complete set of names alone is insufficient: unchanged parent file
        # identities must also remain exact in the final ninety-file inventory.
        spec['final_files']['zolana-fast-check/src/ancestry.rs']['sha256'] = '0' * 64
        copied.write_text(json.dumps(spec))
        with patch.object(candidate, 'REVISION_072_SPEC', copied), \
             patch.object(candidate, 'REVISION_072_SPEC_SHA256', candidate.sha256(copied)):
            with self.assertRaisesRegex(ValueError, 'inventory mismatch'):
                candidate.revision_072_spec(parent)

    def test_snapshot_new_helpers_and_nested_lock_refuse_existing_or_aliased_input(self):
        spec = candidate.revision_072_spec(self.snapshot_parent())
        source = self.root / 'source'; source.mkdir()
        helper = 'zolana-fast-check/src/bin/snapshot-provenance.rs'
        candidate.verify_transition(source, {helper: spec['files'][helper]}, 'before')
        path = source / helper; path.parent.mkdir(parents=True)
        path.write_bytes(b'existing helper cannot be overwritten')
        with self.assertRaisesRegex(ValueError, 'absent'):
            candidate.verify_transition(source, {helper: spec['files'][helper]}, 'before')
        path.unlink(); path.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            candidate.verify_transition(source, {helper: spec['files'][helper]}, 'before')
        (source / 'dev-bins').mkdir()
        (source / 'dev-bins/Cargo.lock').write_bytes(b'incorrect nested workspace resolution')
        with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            candidate.verify_transition(source, {'dev-bins/Cargo.lock': spec['files']['dev-bins/Cargo.lock']}, 'before')

    def test_snapshot_manifest_symlink_is_rejected_even_with_identical_bytes(self):
        alias = self.root / 'LOCAL-072-source.json'
        alias.symlink_to(candidate.REVISION_072_SPEC)
        with patch.object(candidate, 'REVISION_072_SPEC', alias):
            with self.assertRaisesRegex(ValueError, 'manifest checksum'):
                candidate.revision_072_spec(self.snapshot_parent())


if __name__ == "__main__":
    unittest.main()
