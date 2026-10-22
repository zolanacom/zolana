import json
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from wallet_ui import Handler, WalletApp, main, streaming_cli


class WalletUiTests(unittest.TestCase):
    def test_standalone_cli_uses_explicit_binary_and_never_starts_validators(self):
        app = object()
        with patch('wallet_ui.WalletApp.from_profile', return_value=app) as load, \
                patch('wallet_ui.serve') as serve:
            main(['--network-profile', 'native-profile.json', '--data-dir', 'new-test-data',
                  '--binary', 'pinned/native-wallet', '--port', '18765', '--duration', '60'])
        load.assert_called_once_with(Path('native-profile.json'), Path('new-test-data'), 'default', Path('pinned/native-wallet'))
        serve.assert_called_once_with(app, 18765, 60)

    def test_explicit_binary_cannot_change_fixture_validator_launch(self):
        with patch('wallet_ui.WalletApp') as app, self.assertRaises(SystemExit) as denied:
            main(['--root', '.data/preserved', '--binary', 'other-wallet', '--start-network'])
        self.assertEqual(denied.exception.code, 2)
        app.assert_not_called()

    def test_admitted_native_balance_reads_again_without_repeating_status_preflight(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            app.invite_required = True
            app.private_send_transport = 'native-inline-v1'
            app.admitted = True
            password = 'local-test-password\r\n'
            with patch.object(app, 'cli', side_effect=[{'balance': 7}, {'balance': 8}]) as cli:
                self.assertEqual(app.action(dict(action='balance', password=password)), {'balance': 7})
                self.assertEqual(app.action(dict(action='balance', password=password)), {'balance': 8})
            self.assertEqual([entry.args for entry in cli.call_args_list],
                             [('balance', password), ('balance', password)])

    def test_balance_preflight_remains_for_first_reads_and_other_transports(self):
        for transport, admitted in [('native-inline-v1', False), ('native-inline-v1', 1),
                                    ('native-inline-v1', 'yes'), (None, True), ('legacy', True)]:
            with self.subTest(transport=transport, admitted=admitted), tempfile.TemporaryDirectory() as name:
                app = self.app(Path(name))
                app.invite_required = True
                app.private_send_transport = transport
                app.admitted = admitted
                with patch.object(app, 'cli', side_effect=[{'admitted': True}, {'balance': 7}]) as cli:
                    self.assertEqual(app.action(dict(action='balance', password='local-test-password')), {'balance': 7})
                self.assertEqual([entry.args for entry in cli.call_args_list],
                                 [('access-status', 'local-test-password'), ('balance', 'local-test-password')])
                self.assertIs(app.admitted, True)

    def test_native_balance_rpc_revocation_propagates_without_reusing_previous_balance(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            app.invite_required = True
            app.private_send_transport = 'native-inline-v1'
            app.admitted = True
            app.wallet.write_bytes(b'preserved encrypted wallet')
            app.backup.write_bytes(b'preserved encrypted backup')
            before = (app.wallet.read_bytes(), app.backup.read_bytes())
            denied = ValueError('RPC invitation access revoked')
            with patch.object(app, 'cli', side_effect=[{'balance': 7}, denied]) as cli:
                self.assertEqual(app.action(dict(action='balance', password='local-test-password')), {'balance': 7})
                with self.assertRaisesRegex(ValueError, 'revoked') as failed:
                    app.action(dict(action='balance', password='local-test-password'))
                self.assertIs(failed.exception, denied)
            self.assertEqual([entry.args[0] for entry in cli.call_args_list], ['balance', 'balance'])
            self.assertEqual((app.wallet.read_bytes(), app.backup.read_bytes()), before)

    def test_native_fees_and_value_actions_still_check_admission_fresh(self):
        with tempfile.TemporaryDirectory() as name:
            app = self.app(Path(name))
            app.invite_required = True
            app.private_send_transport = 'native-inline-v1'
            for action in ('fees', 'send', 'withdraw', 'resolve', 'test-coins', 'reclaim'):
                with self.subTest(action=action):
                    app.admitted = True
                    with patch.object(app, 'cli', return_value={'admitted': False, 'state': 'revoked'}) as cli:
                        with self.assertRaisesRegex(ValueError, 'access is unavailable'):
                            app.action(dict(action=action, password='local-test-password'))
                        cli.assert_called_once_with('access-status', 'local-test-password')
                    self.assertIs(app.admitted, False)

    def test_progress_disconnect_does_not_interrupt_or_retry_the_original_cli(self):
        with tempfile.TemporaryDirectory() as name:
            marker = Path(name) / 'attempts'
            script = '''import json,sys
assert sys.stdin.read() == 'local-test-password'
with open(sys.argv[1],'a') as out: out.write('one attempt\\n')
for phase in ('key','sync','prove','upload','confirm','finalize'):
 print(json.dumps({'wallet_progress':phase}),flush=True)
print(json.dumps({'signature':'original-finalized-signature','staging_rent_reclaimed':True}))
'''
            phases = []
            def disconnected(phase):
                phases.append(phase)
                raise BrokenPipeError('simulated UI disconnect')
            args = [sys.executable, '-c', script, str(marker)]
            result = streaming_cli(args, 'local-test-password', disconnected, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['signature'], 'original-finalized-signature')
            self.assertEqual(phases, ['key','sync','prove','upload','confirm','finalize'])
            self.assertEqual(marker.read_text(), 'one attempt\n')
            self.assertNotIn('local-test-password', args)

    def test_streaming_cli_timeout_and_duplicate_receipts_fail_without_retry(self):
        with self.assertRaises(subprocess.TimeoutExpired):
            streaming_cli([sys.executable, '-c', 'import sys,time; sys.stdin.read(); time.sleep(10)'],
                          'local-test-password', lambda _: None, timeout=.1)
        with self.assertRaisesRegex(ValueError, 'Invalid wallet result'):
            streaming_cli([sys.executable, '-c', 'import sys; sys.stdin.read(); print("{}"); print("{}")'],
                          'local-test-password', lambda _: None, timeout=5)

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

    def test_native_send_uses_private_fee_cap_and_pending_journal_without_operator_options(self):
        with tempfile.TemporaryDirectory() as name:
            app=self.app(Path(name));app.private_send_transport='native-inline-v1';app.ack.touch()
            request=dict(action='send',password='local-test-password',amount=10,recipient='npriv1example',fee_mode='shielded',max_shielded_fee=3000000)
            with patch.object(app,'cli',return_value={}) as cli:
                app.action(request)
                self.assertEqual(cli.call_args.args,('send','local-test-password',['--fee-payer','shielded','--max-shielded-fee','3000000','--amount','10','--to','npriv1example']))
                for cap in [True,0,-1,1.5,'3000000',100000001]:
                    with self.assertRaises(ValueError):app.action({**request,'max_shielded_fee':cap})
                for extra in [dict(fee_mode='user'),dict(fee_mode='sponsor'),dict(max_fee_debit=100),dict(amount=True)]:
                    with self.assertRaises(ValueError):app.action({**request,**extra})
                app.action(dict(action='resolve',password='local-test-password'))
                self.assertEqual(cli.call_args.args,('resolve','local-test-password'))
            for suffix in ['.shielded.json','.native.json']:
                journal=Path(str(app.wallet)+suffix);journal.write_text('preserved')
                self.assertTrue(app.status()['pending']);journal.unlink()
            self.assertEqual(app.status()['private_send_transport'],'native-inline-v1')
            app.private_send_transport=None
            with self.assertRaises(ValueError):app.action(request)

    def test_native_durable_progress_is_observation_and_requires_one_final_result(self):
        phases=[]
        script='import sys,json;sys.stdin.read();print(json.dumps({"wallet_progress":"native_packet_durable"}));print(json.dumps({"accepted":True,"encrypted_checkpoint_durable":True}))'
        result=streaming_cli([sys.executable,'-c',script],'local-test-password',phases.append,timeout=5)
        self.assertEqual(phases,['native_packet_durable'])
        self.assertTrue(json.loads(result.stdout)['encrypted_checkpoint_durable'])
