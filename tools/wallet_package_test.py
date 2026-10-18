import hashlib
import json
from pathlib import Path
import platform
import tempfile
import unittest
from unittest.mock import patch

from package_wallet import archive, public_profile
from wallet_launch import verify
from wallet_ui import WalletApp


class TesterPackageTests(unittest.TestCase):
    def config(self):
        return {"format": "native-wallet-profile-v1", "label": "Test network", "key_mode": "user-wallet-v1",
                "network": [7] * 32, "genesis_hash": "1" * 32, "program": "public-program", "pool": "public-pool",
                "pool_format": "NPOOL003", "recipient_withdrawals": True,
                "rpc": {"transport": "loopback-http", "url": "http://127.0.0.1:18899"}}

    def validated(self, config=None):
        return type("Completed", (), {"returncode": 0, "stdout": json.dumps(config or self.config())})()

    def test_public_export_is_an_allowlist_and_never_exports_operator_fields(self):
        config = {**self.config(), "roles": {"treasury": "private-role"}, "secret": "secret-value", "fixture_keys_are_public": False}
        exported = public_profile(config, "Invite", "https://rpc.example.invalid", "https")
        self.assertNotIn("private-role", json.dumps(exported))
        self.assertNotIn("secret-value", json.dumps(exported))
        self.assertNotIn("fixture_keys_are_public", exported)

    def test_standalone_storage_is_private_and_bound_to_profile_without_overwrite(self):
        with tempfile.TemporaryDirectory() as name, patch("wallet_ui.subprocess.run", return_value=self.validated()):
            root = Path(name) / "state"
            app = WalletApp.from_profile(Path("profile.json"), root)
            pending = Path(str(app.wallet) + ".pending.json")
            pending.write_text("preserved journal")
            again = WalletApp.from_profile(Path("profile.json"), root)
            self.assertEqual(again.status()["network"], "Test network")
            self.assertFalse(again.status()["operator_sponsor_available"])
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(app.network_file.stat().st_mode & 0o777, 0o600)
            changed = self.config()
            changed["rpc"]["url"] = "http://127.0.0.1:19899"
            with patch("wallet_ui.subprocess.run", return_value=self.validated(changed)):
                with self.assertRaisesRegex(ValueError, "different profile"):
                    WalletApp.from_profile(Path("other.json"), root)
            self.assertEqual(pending.read_text(), "preserved journal")

    def test_standalone_refuses_symlinks_and_shared_storage(self):
        with tempfile.TemporaryDirectory() as name, patch("wallet_ui.subprocess.run", return_value=self.validated()):
            root = Path(name) / "state"
            root.mkdir(mode=0o755)
            with self.assertRaisesRegex(ValueError, "owner-only"):
                WalletApp.from_profile(Path("profile.json"), root)
            link = Path(name) / "link"
            link.symlink_to(root)
            with self.assertRaisesRegex(ValueError, "symlink"):
                WalletApp.from_profile(Path("profile.json"), link)
            root.chmod(0o700)
            (root / "network.json").symlink_to(Path(name) / "external")
            with self.assertRaises(OSError):
                WalletApp.from_profile(Path("profile.json"), root)

    def test_standalone_cannot_redirect_rpc_or_use_operator_sponsorship(self):
        with tempfile.TemporaryDirectory() as name, patch("wallet_ui.subprocess.run", return_value=self.validated()):
            app = WalletApp.from_profile(Path("profile.json"), Path(name) / "state")
            app.ack.touch()
            with self.assertRaisesRegex(ValueError, "Operator sponsorship"):
                app.action({"action": "fund"})
            self.assertTrue(app.status()["user_paid_sends"])
            with patch.object(app,"cli",return_value={}) as cli:
                app.action({"action":"send","password":"test-password-long","amount":1,"recipient":"npriv1example","fee_mode":"user","max_fee_debit":150000000})
                self.assertEqual(cli.call_args.args[0],"send")
                self.assertNotIn("--sponsor",cli.call_args.args[2])
            with patch("wallet_ui.subprocess.run", return_value=self.validated()) as run:
                app.cli("address", "test-password-long")
                self.assertNotIn("--rpc", run.call_args.args[0])
                self.assertEqual(run.call_args.kwargs["input"], "test-password-long")

    def bundle(self, root):
        (root / "asset").write_bytes(b"content")
        manifest = {"format": "native-wallet-bundle-v1", "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
                    "files": {"asset": {"size": 7, "sha256": hashlib.sha256(b"content").hexdigest()}}}
        (root / "MANIFEST.json").write_text(json.dumps(manifest))

    def test_integrity_rejects_modified_added_and_symlinked_files(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            self.bundle(root)
            verify(root)
            (root / "asset").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "integrity"):
                verify(root)
            (root / "asset").write_bytes(b"content")
            (root / "extra").touch()
            with self.assertRaisesRegex(ValueError, "inventory"):
                verify(root)
            (root / "extra").unlink()
            (root / "extra").symlink_to(root / "asset")
            with self.assertRaisesRegex(ValueError, "symlink"):
                verify(root)

    def test_archive_bytes_are_deterministic_regardless_of_input_order(self):
        self.assertEqual(archive({"a": b"one", "b": b"two"}, {}), archive({"b": b"two", "a": b"one"}, {}))


if __name__ == "__main__":
    unittest.main()
