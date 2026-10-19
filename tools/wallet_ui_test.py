import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wallet_ui import Handler, WalletApp


class WalletUiTests(unittest.TestCase):
    def test_admission_transport_retry_preserves_exact_identity_and_password_pipe(self):
        with tempfile.TemporaryDirectory() as name:
            app=self.app(Path(name));app.tester=True;app.invite_required=True
            failed=type('Done',(),dict(returncode=1,stdout='',stderr='Wallet error: error sending request for url (https://127.0.0.1:13781/join)'))()
            ok=type('Done',(),dict(returncode=0,stdout='{"admitted":true}',stderr=''))()
            with patch('wallet_ui.subprocess.run',side_effect=[failed,failed,ok]) as run,patch('wallet_ui.time.sleep') as pause:
                value=app.cli('join','local-test-password',['--invitation-file','original-invite'])
            self.assertTrue(value['admitted']);self.assertEqual(run.call_count,3);self.assertEqual(pause.call_count,2)
            self.assertEqual(run.call_args_list[0],run.call_args_list[1]);self.assertEqual(run.call_args_list[1],run.call_args_list[2])
            self.assertEqual(run.call_args.kwargs['input'],'local-test-password');self.assertNotIn('local-test-password',run.call_args.args[0])
    def test_payment_authorization_and_quota_errors_never_auto_retry_and_transport_is_bounded(self):
        with tempfile.TemporaryDirectory() as name:
            app=self.app(Path(name));app.tester=True;app.invite_required=True
            transport='error sending request for url (https://127.0.0.1:13781/join)'
            cases=[('send',transport,1),('withdraw',transport,1),('resolve',transport,1),('join','Invitation invalid',1),
                   ('join','Testnet request limit reached. Wait before checking the same wallet again.',1),('access-status',transport,4),('test-coins',transport,4)]
            for command,error,calls in cases:
                failed=type('Done',(),dict(returncode=1,stdout='',stderr='Wallet error: '+error))()
                with patch('wallet_ui.subprocess.run',return_value=failed) as run,patch('wallet_ui.time.sleep'):
                    with self.assertRaisesRegex(ValueError,error.split(' ')[0]):app.cli(command,'local-test-password')
                    self.assertEqual(run.call_count,calls)
    def test_rehearsal_sponsor_is_operator_selected_and_requires_private_password_file(self):
        with tempfile.TemporaryDirectory() as name:
            project = Path(name).resolve()
            root = project / ".data" / "rehearsal"
            root.mkdir(parents=True, mode=0o700)
            secret = project / "operator.password"
            secret.write_bytes(b"separate operator password")
            secret.chmod(0o600)
            config = {"pool_format": "NPOOL003", "fixture_keys_are_public": False,
                      "key_mode": "local-testnet-rehearsal-v1"}
            with patch("wallet_ui.PROJECT", project), patch("wallet_ui.load", return_value=config):
                independent = WalletApp(root)
                self.assertFalse(independent.status()["operator_sponsor_available"])
                independent.ack.touch()
                with self.assertRaisesRegex(ValueError, "Operator sponsorship"):
                    independent.action({"action": "fund", "password": "local-test-password"})
                secret.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "owner-only"):
                    WalletApp(root, sponsor_password_file=secret)
                secret.chmod(0o600)
                app = WalletApp(root, sponsor_password_file=secret)
                app.ack.touch()
                with patch.object(app, "cli", return_value={}) as cli:
                    app.action({"action": "fund", "password": "local-test-password",
                                "sponsor_password_file": "attacker", "sponsor_request_id": "reuse-this-request"})
                    extra = cli.call_args.args[2]
                    self.assertNotIn("--sponsor", extra)
                    self.assertEqual(extra[extra.index("--sponsor-password-file") + 1], str(secret))
                    self.assertNotIn("reuse-this-request", extra)
                    app.action({"action": "reclaim", "password": "local-test-password"})
                    self.assertNotIn("--sponsor-request-id", cli.call_args.args[2])

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

    def test_withdrawals_require_feature_backup_and_strict_user_destination(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            request = {"action": "withdraw", "password": "local-test-password", "amount": 1_000_000}
            with patch.object(app, "cli", return_value={}) as cli:
                with self.assertRaisesRegex(ValueError, "recovery file"):
                    app.action(request)
                app.ack.touch()
                with self.assertRaisesRegex(ValueError, "preserved network"):
                    app.action(request)
                app.withdrawal_enabled = True
                for value in [True, 0, -1, 1.5, "1000000", 10**20]:
                    with self.assertRaises(ValueError):
                        app.action({**request, "amount": value})
                for value in ["npriv1test", "0" * 44, "1" * 45, [], 123]:
                    with self.assertRaises(ValueError):
                        app.action({**request, "recipient": value})
                cli.assert_not_called()
                app.action(request)
                self.assertEqual(cli.call_args.args[0], "withdraw")
                self.assertNotIn("--to", cli.call_args.args[2])
                destination = "1" * 32
                app.action({**request, "recipient": destination, "rpc": "https://untrusted.invalid"})
                extra = cli.call_args.args[2]
                self.assertEqual(extra[-2:], ["--to", destination])
                self.assertNotIn("untrusted.invalid", str(extra))

    def test_failed_partial_creation_can_resume_from_its_encrypted_backup(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            app.backup.write_text(json.dumps({"ciphertext": []}))
            self.assertTrue(app.status()["exists"])
            with patch.object(app, "cli", return_value={"address": "npriv1fixture"}) as cli:
                app.action({"action": "unlock", "password": "local-test-password"})
                self.assertEqual(cli.call_args_list[0].args[0], "restore")

    def test_retained_history_and_peer_are_server_selected_and_never_resolve_from_history(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            app.rpc_index = 1
            history = app.root / "recovery-history"
            history.mkdir()
            (history / "manifest.json").write_text("{}")
            completed = type("Completed", (), {"returncode": 0, "stdout": "{}"})()
            with patch("wallet_ui.subprocess.run", return_value=completed) as run:
                app.cli("balance", "local-test-password")
                args = run.call_args.args[0]
                self.assertEqual(args[args.index("--rpc") + 1], "http://127.0.0.1:19899")
                self.assertEqual(args[args.index("--history") + 1], str(history))
                for command in ["resolve", "reclaim", "address", "restore"]:
                    app.cli(command, "local-test-password")
                    self.assertNotIn("--history", run.call_args.args[0])

    def test_user_paid_withdrawal_and_recovery_never_load_operator_options(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            app.private_setup = True
            app.withdrawal_enabled = True
            app.ack.touch()
            request = {"action": "withdraw", "password": "local-test-password", "amount": 1000000, "fee_mode": "user", "max_fee_debit": 150000000}
            with patch.object(app, "cli", return_value={}) as cli:
                for cap in [True, 0, -1, "150000000", 1.5, 10**20]:
                    with self.assertRaises(ValueError):
                        app.action({**request, "max_fee_debit": cap})
                for mode in [[], {}, True, "external"]:
                    with self.assertRaises(ValueError):
                        app.action({**request, "fee_mode": mode})
                for action in ["fund", "reclaim"]:
                    with self.assertRaisesRegex(ValueError, "only supported for sends and withdrawals"):
                        app.action({**request, "action": action})
                cli.assert_not_called()
                app.action({**request, "sponsor_password_file": "attacker", "sponsor_request_id": "attacker"})
                extra = cli.call_args.args[2]
                self.assertEqual(extra[:4], ["--fee-payer", "user", "--max-fee-debit", "150000000"])
                self.assertNotIn("--sponsor-password-file", extra)
                self.assertNotIn("--sponsor-request-id", extra)
                Path(str(app.wallet) + ".staging.json").write_text(json.dumps({"user_fee": {"maximum": 150000000}}))
                app.action({"action": "reclaim", "password": "local-test-password"})
                self.assertEqual(cli.call_args.args, ("reclaim", "local-test-password"))
                app.action({"action": "fees", "password": "local-test-password"})
                self.assertEqual(cli.call_args.args, ("fees", "local-test-password"))

    def test_private_send_fee_quote_and_authorization_are_strict_without_operator(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            app.private_setup = True
            app.ack.touch()
            request = {"action":"send", "password":"local-test-password", "amount":10,
                       "recipient":"npriv1example", "fee_mode":"user", "max_fee_debit":150000000}
            with patch.object(app,"cli",return_value={}) as cli:
                app.action(request)
                self.assertEqual(cli.call_args.args[0],"send")
                extra = cli.call_args.args[2]
                self.assertEqual(extra[:4],["--fee-payer","user","--max-fee-debit","150000000"])
                self.assertNotIn("--sponsor-password-file",extra)
                for cap in [True,0,-1,1.5,"150000000",10**20]:
                    with self.assertRaises(ValueError): app.action({**request,"max_fee_debit":cap})
                for mode in [[],{},True,"external"]:
                    with self.assertRaises(ValueError): app.action({**request,"fee_mode":mode})
                with self.assertRaisesRegex(ValueError,"requires user-paid"):
                    app.action({**request,"fee_mode":"sponsor"})
                for value in [True,[],{},"deposit","send --rpc external"]:
                    with self.assertRaises(ValueError): app.action({"action":"fees","payment":value,"password":"local-test-password"})
                app.action({"action":"fees","payment":"send","password":"local-test-password"})
                self.assertEqual(cli.call_args.args,("fees","local-test-password",["--payment","send"]))
                with self.assertRaisesRegex(ValueError,"only supported for fees"):
                    app.action({**request,"payment":"send"})
