import tempfile
import json
from unittest.mock import patch
from pathlib import Path
import unittest
from localnet import newer_full_snapshot, start


class SnapshotSelectionTests(unittest.TestCase):
    def test_recovery_requires_a_full_archive_newer_than_payments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in [
                "snapshot-40-" + "1" * 32 + ".tar.zst",
                "incremental-snapshot-40-100-" + "1" * 32 + ".tar.zst",
                "snapshot-120-invalid.tar.zst",
                "snapshot-140-" + "1" * 32 + ".tar.zst.partial",
            ]:
                (root / name).touch()
            self.assertIsNone(newer_full_snapshot(root, 40))
            newest = root / ("snapshot-80-" + "1" * 32 + ".tar.zst")
            newest.touch()
            self.assertEqual(newer_full_snapshot(root, 40), (80, newest))

    def test_archive_slot_sorting_is_numeric(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for slot in [80, 120]:
                (root / (f"snapshot-{slot}-" + "1" * 32 + ".tar.zst")).touch()
            self.assertEqual(newer_full_snapshot(root, 50)[0], 120)


class ConsensusStorageTests(unittest.TestCase):
    def test_replacing_snapshot_ledger_preserves_tower_and_requires_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True, "genesis_hash": "fixture"}))
            (root / "ledger-1").mkdir()
            with patch("localnet.socket.socket"), patch("localnet.subprocess.Popen") as launch:
                launch.return_value.pid = 1234
                start(root, 1)
                first = launch.call_args.args[0]
                tower = Path(first[first.index("--tower") + 1])
                self.assertEqual(tower, root / "consensus-1")
                (tower / "tower-fixture.bin").touch()
                (root / "ledger-recovered").mkdir()
                (root / "active-ledger-1.json").write_text(json.dumps("ledger-recovered"))
                start(root, 1, archive=True)
                recovered = launch.call_args.args[0]
                self.assertEqual(recovered[recovered.index("--tower") + 1], str(tower))
                self.assertIn("--require-tower", recovered)
                self.assertNotIn("--no-wait-for-vote-to-start-leader", recovered)
                self.assertIn("--use-snapshot-archives-at-startup", recovered)


if __name__ == "__main__":
    unittest.main()
