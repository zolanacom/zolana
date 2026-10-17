import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wallet_ui import Handler, WalletApp


class WalletUiTests(unittest.TestCase):
    def app(self, root):
        root = root.resolve()
        with patch("wallet_ui.PROJECT", root), patch("wallet_ui.load", return_value={"pool_format": "NPOOL003", "fixture_keys_are_public": True}):
            fixture = root / ".data" / "fixture"
            fixture.mkdir(parents=True)
            return WalletApp(fixture)

    def test_host_origin_and_session_all_required_for_mutations(self):
        handler = object.__new__(Handler)
        handler.server = type("Server", (), {"authority": "127.0.0.1:8765", "app": type("App", (), {"token": "test-token"})()})()
        valid = {"Host": "127.0.0.1:8765", "Origin": "http://127.0.0.1:8765", "X-Wallet-Token": "test-token"}
        handler.headers = valid.copy()
        self.assertTrue(handler.allowed(mutation=True))
        for key in valid:
            handler.headers = {**valid, key: "untrusted"}
            self.assertFalse(handler.allowed(mutation=True))
        handler.headers = {"Host": "127.0.0.1:8765"}
        self.assertFalse(handler.allowed(mutation=True))

    def test_backup_required_and_amounts_cannot_be_coerced_or_redirect_rpc(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            with patch.object(app, "cli") as cli:
                with self.assertRaisesRegex(ValueError, "recovery file"):
                    app.action({"action": "fund", "password": "local-test-password"})
                cli.assert_not_called()
                app.ack.touch()
                for amount in [True, 0, -1, 1.5, "5", 10**20]:
                    with self.assertRaises(ValueError):
                        app.action({"action": "send", "amount": amount, "recipient": "npriv1test"})
                app.action({"action": "fund", "password": "local-test-password", "rpc": "https://external.invalid", "amount": 999})
                self.assertEqual(cli.call_args.args[0], "deposit")
                self.assertEqual(cli.call_args.args[2][-2:], ["--amount", "100"])

    def test_password_uses_stdin_and_never_a_named_file_even_on_failure(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            def fail(args, **options):
                self.assertEqual(args[args.index("--password-file") + 1], "-")
                self.assertEqual(options["input"], "local-test-password")
                self.assertNotIn("local-test-password", args)
                raise OSError("simulated child failure")
            with patch("wallet_ui.subprocess.run", side_effect=fail):
                with self.assertRaises(OSError):
                    app.cli("address", "local-test-password")
            self.assertEqual(list(app.directory.glob(".unlock-*")), [])

    def test_failed_partial_creation_can_resume_from_its_encrypted_backup(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            app.backup.write_text(json.dumps({"ciphertext": []}))
            self.assertTrue(app.status()["exists"])
            with patch.object(app, "cli", return_value={"address": "npriv1fixture"}) as cli:
                app.action({"action": "unlock", "password": "local-test-password"})
                self.assertEqual(cli.call_args_list[0].args[0], "restore")
