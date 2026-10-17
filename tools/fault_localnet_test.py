import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from fault_localnet import crash_owned, sealed_on_both
from localnet import PROJECT
from park_ledger import park, restore


class OwnedCrashTests(unittest.TestCase):
    def test_never_signals_an_exited_or_mismatched_pid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = Mock(pid=123)
            process.poll.return_value = 0
            with self.assertRaisesRegex(RuntimeError, "live validator child"):
                crash_owned(root, 0, process)
            process.kill.assert_not_called()
            process.poll.return_value = None
            (root / "validator-0.pid").write_text("456")
            with self.assertRaisesRegex(RuntimeError, "live validator child"):
                crash_owned(root, 0, process)
            process.kill.assert_not_called()

    def test_rpc_authentication_precedes_sigkill(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "validator-0.pid").write_text("123")
            process = Mock(pid=123)
            process.poll.return_value = None
            with patch("fault_localnet.wait_rpc", side_effect=RuntimeError("wrong network")):
                with self.assertRaisesRegex(RuntimeError, "wrong network"):
                    crash_owned(root, 0, process)
            process.kill.assert_not_called()


class FinalizedStagingTests(unittest.TestCase):
    def test_equal_writing_accounts_are_not_a_sealed_checkpoint(self):
        raw = bytearray(96)
        value = {"data": [base64.b64encode(raw).decode(), "base64"]}
        with patch("fault_localnet.account", return_value=value):
            self.assertFalse(sealed_on_both("buffer"))
        raw[88] = 1
        sealed = {"data": [base64.b64encode(raw).decode(), "base64"]}
        with patch("fault_localnet.account", return_value=sealed):
            self.assertTrue(sealed_on_both("buffer"))
        with patch("fault_localnet.account", side_effect=[value, sealed]):
            self.assertFalse(sealed_on_both("buffer"))


class LedgerArchiveTests(unittest.TestCase):
    def test_verified_archive_roundtrip_preserves_bytes(self):
        with tempfile.TemporaryDirectory(dir=PROJECT / ".data") as directory:
            root = Path(directory)
            (root / "network.json").write_text(json.dumps({"fixture_keys_are_public": True}))
            ledger = root / "ledger-test"
            (ledger / "rocksdb").mkdir(parents=True)
            (ledger / "rocksdb/LOCK").touch()
            (ledger / "ledger.lock").touch()
            data = b"recoverable ledger fixture\0" * 90000
            (ledger / "rocksdb/data.sst").write_bytes(data)
            (ledger / "genesis.bin").write_bytes(b"genesis")
            park(ledger)
            archived = ledger.with_name(ledger.name + ".parked")
            self.assertFalse(ledger.exists())
            self.assertTrue((archived / "rocksdb/data.sst.parked.zst").exists())
            restore(archived)
            self.assertEqual((ledger / "rocksdb/data.sst").read_bytes(), data)
            self.assertEqual((ledger / "genesis.bin").read_bytes(), b"genesis")
