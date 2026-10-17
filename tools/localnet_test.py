import tempfile
import json
from unittest.mock import patch
from pathlib import Path
import unittest
from localnet import newer_full_snapshot, restart_state, start, wait_finalized_progress


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
    def test_fault_control_cannot_leak_into_ordinary_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ledger-0").mkdir()
            (root / "consensus-0").mkdir()
            (root / "consensus-0/tower-fixture.bin").touch()
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True, "pool_format": "NPOOL002", "genesis_hash": "genesis"}))
            with patch("localnet.socket.socket"), patch("localnet.subprocess.Popen") as launch, patch.dict("localnet.os.environ", {"NATIVE_LOCAL_SHRED_FAULT": "unexpected"}):
                launch.return_value.pid = 123
                start(root, 0)
                self.assertNotIn("NATIVE_LOCAL_SHRED_FAULT", launch.call_args.kwargs["env"])
                self.assertNotIn("--tpu-enable-udp", launch.call_args.args[0])
                start(root, 0, faults=True)
                self.assertEqual(launch.call_args.kwargs["env"]["NATIVE_LOCAL_SHRED_FAULT"], str(root / "fault-0.json"))
                self.assertIn("--tpu-enable-udp", launch.call_args.args[0])

    def test_coordinated_start_uses_checkpoint_gate_and_keeps_tower_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ledger-0").mkdir()
            (root / "consensus-0").mkdir()
            (root / "consensus-0/tower-fixture.bin").write_bytes(b"signed fixture")
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True, "pool_format": "NPOOL002", "genesis_hash": "genesis"}))
            state = {"slot": 100, "bank_hash": "checkpoint", "shred_version": 123}
            with patch("localnet.socket.socket"), patch("localnet.subprocess.Popen") as launch, patch("localnet.restart_state", return_value=state):
                launch.return_value.pid = 123
                start(root, 0, coordinated=True)
                args = launch.call_args.args[0]
                for flag, value in [("--wait-for-supermajority", "100"), ("--expected-bank-hash", "checkpoint"), ("--expected-shred-version", "123")]:
                    self.assertEqual(args[args.index(flag) + 1], value)
                self.assertIn("--require-tower", args)
                self.assertNotIn("--no-wait-for-vote-to-start-leader", args)

    def test_startup_requires_new_finalization_from_both_peers(self):
        with patch("localnet.rpc", side_effect=[100, 101, 110, 111]) as query, patch("localnet.time.sleep"):
            self.assertEqual(wait_finalized_progress(None, [0, 1], 100), [110, 111])
            self.assertEqual(query.call_count, 4)

    def test_missing_tower_never_reenables_bootstrap_after_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ledger-0").mkdir()
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True, "pool_format": "NPOOL002"}))
            (root / "validator-0.pid").write_text("123")
            with patch("localnet.socket.socket"), patch("localnet.subprocess.Popen") as launch:
                with self.assertRaisesRegex(RuntimeError, "no saved tower"):
                    start(root, 0)
                launch.assert_not_called()

    def test_checkpoint_authenticates_identity_and_genesis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ledger-0").mkdir()
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True, "genesis_hash": "genesis", "identities": ["node"]}))
            for state in [{"genesis_hash": "other", "identity": "node"}, {"genesis_hash": "genesis", "identity": "other"}]:
                with patch("localnet.subprocess.run") as inspect:
                    inspect.return_value.stdout = json.dumps(state)
                    with self.assertRaisesRegex(RuntimeError, "identity/genesis mismatch"):
                        restart_state(root, 0)

    def test_snapshot_root_cannot_trigger_tower_discard(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ledger-0/snapshots/100").mkdir(parents=True)
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True, "genesis_hash": "genesis", "identities": ["node"]}))
            with patch("localnet.subprocess.run") as inspect:
                inspect.return_value.stdout = json.dumps({"genesis_hash": "genesis", "identity": "node", "slot": 100})
                with self.assertRaisesRegex(RuntimeError, "tower-discard"):
                    restart_state(root, 0)

    def test_old_development_state_cannot_start_with_the_new_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True, "pool_format": "NPOOL001"}))
            with patch("localnet.subprocess.Popen") as launch:
                with self.assertRaisesRegex(RuntimeError, "incompatible development pool format"):
                    start(root, 0)
                launch.assert_not_called()
            self.assertFalse((root / "consensus-0").exists())

    def test_replacing_snapshot_ledger_preserves_tower_and_requires_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True, "genesis_hash": "fixture", "pool_format": "NPOOL002"}))
            (root / "ledger-1").mkdir()
            with patch("localnet.socket.socket"), patch("localnet.subprocess.Popen") as launch, patch("localnet.subprocess.run"):
                launch.return_value.pid = 1234
                start(root, 1)
                first = launch.call_args.args[0]
                self.assertIn("--enable-rpc-transaction-history", first)
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
