import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from localnet import digest, prepare_snapshot_recovery
from offline_localnet import OfflineExperiment, offline_target, resumable_offline


class OfflineIntervalTests(unittest.TestCase):
    def test_requires_both_epoch_advancement_and_expired_authorization(self):
        self.assertEqual(offline_target(100, 2, 128), 768)
        self.assertEqual(offline_target(1000, 2, 128), 1008)

    def test_continuation_cannot_repeat_a_later_or_completed_payment_sequence(self):
        events = [{"kind": "payment_finalized", "action": action, "who": who, "amount": amount}
                  for action, who, amount in [("deposit", "alice", 100), ("send", "alice", 20), ("send", "alice", 5), ("withdraw", "bob", 2)]]
        stopped = {"kind": "minority_offline"}
        result = {"status": "failed", "checks": [], "error": "cluster did not regain fresh finalization and exact native state", "events": events + [stopped]}
        self.assertEqual(resumable_offline(result), stopped)
        for key, value in [("status", "passed"), ("checks", ["offline_catchup_passed"]), ("error", "different failure")]:
            modified = dict(result, **{key: value})
            with self.assertRaisesRegex(RuntimeError, "refusing to repeat payments"):
                resumable_offline(modified)
        later = dict(result, events=result["events"] + [{"kind": "payment_finalized", "action": "deposit", "who": "alice", "amount": 1}])
        with self.assertRaisesRegex(RuntimeError, "refusing to repeat payments"):
            resumable_offline(later)


class OfflineFallbackTests(unittest.TestCase):
    def test_only_bounded_liveness_failure_enters_snapshot_recovery(self):
        trial = OfflineExperiment(Path("unused-test-root"))
        trial.launch = Mock()
        trial.converge = Mock(side_effect=RuntimeError("cluster did not regain fresh finalization and exact native state"))
        trial.slots = Mock(return_value=[800, 200])
        trial.event = Mock()
        trial.offline_snapshot = Mock(return_value=[820, 819])
        context = {"target": 700, "expected_native": {}}
        self.assertEqual(trial.catch_up_offline(context), ([820, 819], True))
        trial.offline_snapshot.assert_called_once_with(context)
        trial.offline_snapshot.reset_mock()
        trial.converge.side_effect = RuntimeError("unexpected validator identity")
        with self.assertRaisesRegex(RuntimeError, "unexpected validator identity"):
            trial.catch_up_offline(context)
        trial.offline_snapshot.assert_not_called()


class SnapshotTransferTests(unittest.TestCase):
    def fixture(self, root):
        (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True}))
        (root / "ledger-0").mkdir()
        archive = root / "ledger-0" / ("snapshot-80-" + "1" * 32 + ".tar.zst")
        archive.write_bytes(b"immutable snapshot source")
        (root / "active-ledger-1.json").write_text(json.dumps("ledger-original"))
        return archive

    def test_stale_snapshot_cannot_create_or_select_a_replacement_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            with patch("localnet.subprocess.run") as prepare:
                with self.assertRaisesRegex(RuntimeError, "beyond the shutdown tip"):
                    prepare_snapshot_recovery(root, "ledger-recovered-test", 80)
                prepare.assert_not_called()
            self.assertEqual(json.loads((root / "active-ledger-1.json").read_text()), "ledger-original")

    def test_changed_transfer_never_selects_a_bad_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.fixture(root)
            with patch("localnet.subprocess.run", side_effect=lambda *a, **k: (root / "ledger-recovered-test").mkdir()), patch("localnet.shutil.copy2", side_effect=lambda src, dst: dst.write_bytes(b"damaged in transfer")):
                with self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                    prepare_snapshot_recovery(root, "ledger-recovered-test", 70)
            self.assertEqual(archive.read_bytes(), b"immutable snapshot source")
            self.assertEqual(json.loads((root / "active-ledger-1.json").read_text()), "ledger-original")

    def test_overlong_recovery_path_is_rejected_before_creating_a_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            with patch("localnet.subprocess.run") as prepare:
                with self.assertRaisesRegex(RuntimeError, "admin socket limit"):
                    prepare_snapshot_recovery(root, "ledger-recovered-" + "a" * 150, 70)
                prepare.assert_not_called()

    def test_verified_copy_retains_source_and_does_not_change_active_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = self.fixture(root)
            with patch("localnet.subprocess.run", side_effect=lambda *a, **k: (root / "ledger-recovered-test").mkdir()):
                result = prepare_snapshot_recovery(root, "ledger-recovered-test", 70)
            copied = root / result["fresh_ledger"] / result["archive"]
            self.assertEqual(copied.read_bytes(), archive.read_bytes())
            self.assertEqual(result["archive_sha256"], digest(archive))
            self.assertEqual(json.loads((root / "active-ledger-1.json").read_text()), "ledger-original")
