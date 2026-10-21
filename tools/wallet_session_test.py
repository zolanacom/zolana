"""Owned fake workers only: no RPC, crypto, validator or real wallet files."""
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from wallet_session import CommandSession, SessionUnsupported, STDERR_LIMIT
from wallet_ui import WalletApp

PASSWORD = 'fake-local-test-password'
FAKE = r'''
import json,os,sys,time
assert sys.argv[1] == 'command-session'
assert sys.argv[2] == '--network' and sys.argv[4] == '--wallet'
assert os.environ['NATIVE_WALLET_PROGRESS'] == '1'
assert os.environ['RAYON_NUM_THREADS'] == '6'
mode = os.environ.get('WALLET_SESSION_TEST_MODE','good')
if mode in ('old','generic-startup','unknown-with-stdout','old-truncated'):
 if mode=='unknown-with-stdout':print('{}',flush=True)
 sys.stderr.write('Wallet error: '+('invalid fixed network profile' if mode=='generic-startup' else 'unknown wallet command; use --help')+'\n')
 if mode=='old-truncated':sys.stderr.write(' '*20000+'different failure')
 sys.stderr.flush();sys.exit(1)
if mode == 'ready-timeout': time.sleep(20)
if mode == 'stderr': sys.stderr.write('x'*30000); sys.stderr.flush()
print(json.dumps({'session_ready':mode!='bad-ready',
 'format':'native-wallet-command-session-v1','public_key_only':True,'proof_key_ms':12}),flush=True)
if mode == 'write-timeout': time.sleep(20)
count=0
for line in sys.stdin:
 request=json.loads(line);count+=1
 assert set(request)=={'args','password'}
 assert isinstance(request['password'],list)
 secret=bytes(request['password']).decode()
 assert len(secret)>=12
 assert secret not in str(sys.argv) and secret not in str(dict(os.environ))
 assert not any(x in request['args'] for x in ('--network','--wallet','--password-file'))
 command=request['args'][0]
 trace=os.environ.get('WALLET_SESSION_TEST_TRACE')
 if trace:
  with open(trace,'a') as target:target.write(json.dumps({'command':command,'pid':os.getpid()})+'\n')
 if mode=='timeout' and command=='send':time.sleep(20)
 if mode=='invalid' and command=='send':print('[]',flush=True);continue
 if mode=='oversize':print('x'*70000,flush=True);continue
 if mode=='bad-progress':print(json.dumps({'wallet_progress':[]}),flush=True);continue
 if mode=='error' and command=='fees':
  print(json.dumps({'session_error':True,'error':'fixture rejected'}),flush=True);continue
 if mode=='unknown-after-write':
  print(json.dumps({'session_error':True,'error':'unknown wallet command; use --help'}),flush=True);continue
 if mode=='serial':time.sleep(.1)
 print(json.dumps({'wallet_progress':'sync'}),flush=True)
 print(json.dumps({'command':command,'count':count,'pid':os.getpid(),'password_bytes':len(request['password'])}),flush=True)
 del secret,request
'''


class CommandSessionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.binary = self.root / 'fake-wallet'
        self.binary.write_text('#!' + sys.executable + '\n' + FAKE)
        self.binary.chmod(0o700)
        self.sessions = []

    def tearDown(self):
        for session in self.sessions:
            session.close()
        self.temporary.cleanup()

    def session(self, mode='good', **options):
        environment = {'WALLET_SESSION_TEST_MODE': mode,
                       'WALLET_SESSION_TEST_TRACE': str(self.root / 'trace')}
        value = CommandSession(self.binary, self.root / 'network.json', self.root / 'wallet.json',
                               env=environment, **options)
        self.sessions.append(value)
        return value

    def test_lazy_ready_progress_and_same_owned_worker_for_sequential_requests(self):
        session = self.session()
        self.assertIsNone(session.pid)
        phases = []
        first = json.loads(session.run('balance', [], PASSWORD, callback=phases.append).stdout)
        second = json.loads(session.run('fees', ['--payment','send'], PASSWORD).stdout)
        self.assertEqual(phases, ['sync'])
        self.assertEqual(first['pid'], second['pid'])
        self.assertEqual((first['count'], second['count']), (1, 2))
        self.assertEqual(session.ready['proof_key_ms'], 12)
        self.assertEqual(session.pid, first['pid'])
        self.assertNotIn(PASSWORD, str(session.__dict__))
        self.assertNotIn(PASSWORD, (self.root / 'trace').read_text())

    def test_error_does_not_resend_and_next_explicit_request_reuses_worker(self):
        session = self.session('error')
        failed = session.run('fees', [], PASSWORD)
        pid = session.pid
        self.assertEqual((failed.returncode, failed.stderr), (1, 'fixture rejected'))
        result = json.loads(session.run('balance', [], PASSWORD).stdout)
        self.assertEqual(result['pid'], pid)
        self.assertEqual(result['count'], 2)
        self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 2)

    def test_timeout_kills_only_owned_worker_without_resend_then_next_operation_restarts(self):
        session = self.session('timeout')
        with self.assertRaises(subprocess.TimeoutExpired):
            session.run('send', ['--amount','1'], PASSWORD, timeout=.15)
        self.assertIsNone(session.pid)
        attempts = [json.loads(line) for line in (self.root / 'trace').read_text().splitlines()]
        self.assertEqual([item['command'] for item in attempts], ['send'])
        result = json.loads(session.run('balance', [], PASSWORD).stdout)
        self.assertNotEqual(attempts[0]['pid'], result['pid'])
        self.assertEqual(result['count'], 1)
        attempts = [json.loads(line)['command'] for line in (self.root / 'trace').read_text().splitlines()]
        self.assertEqual(attempts, ['send', 'balance'])

    def test_invalid_protocol_kills_worker_without_resend_and_next_call_restarts(self):
        session = self.session('invalid')
        with self.assertRaisesRegex(ValueError, 'saved payment status'):
            session.run('send', [], PASSWORD)
        self.assertIsNone(session.pid)
        self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1)
        result = json.loads(session.run('resolve', [], PASSWORD).stdout)
        self.assertEqual(result['count'], 1)
        self.assertEqual(result['command'], 'resolve')

    def test_startup_timeout_and_invalid_handshake_send_no_request(self):
        for mode in ('ready-timeout', 'bad-ready'):
            with self.subTest(mode=mode):
                session = self.session(mode, ready_timeout=.15)
                with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                    session.run('balance', [], PASSWORD)
                self.assertIsNone(session.pid)
                self.assertFalse((self.root / 'trace').exists())

    def test_request_write_and_response_wait_share_the_same_bounded_deadline(self):
        session = self.session('write-timeout')
        with self.assertRaises(subprocess.TimeoutExpired):
            session.run('send', ['--to', 'x'*11000], 'p'*1024, timeout=.15)
        self.assertIsNone(session.pid)
        self.assertFalse((self.root / 'trace').exists())

    def test_output_and_progress_are_bounded_and_fail_closed(self):
        for mode in ('oversize', 'bad-progress'):
            with self.subTest(mode=mode):
                session = self.session(mode)
                with self.assertRaisesRegex(ValueError, 'saved payment status'):
                    session.run('balance', [], PASSWORD)
                self.assertIsNone(session.pid)

    def test_stderr_is_drained_with_bounded_memory(self):
        session = self.session('stderr')
        result = session.run('balance', [], PASSWORD)
        self.assertEqual(result.returncode, 0)
        self.assertLessEqual(len(session._child.errors), STDERR_LIMIT)
        self.assertLessEqual(len(result.stderr), STDERR_LIMIT)
        self.assertNotIn(PASSWORD, result.stderr)

    def test_callbacks_disconnecting_do_not_interrupt_or_retry_original_request(self):
        session = self.session()
        def disconnected(_):
            raise BrokenPipeError('fixture browser disconnect')
        result = session.run('send', [], PASSWORD, callback=disconnected)
        self.assertEqual(json.loads(result.stdout)['count'], 1)
        self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1)

    def test_concurrent_requests_are_serialized_on_one_owned_worker(self):
        session = self.session('serial')
        barrier = threading.Barrier(2)
        def request():
            barrier.wait(timeout=2)
            return json.loads(session.run('balance', [], PASSWORD).stdout)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result(timeout=5) for future in [pool.submit(request), pool.submit(request)]]
        self.assertEqual(sorted(item['count'] for item in results), [1, 2])
        self.assertEqual(len({item['pid'] for item in results}), 1)

    def test_fixed_bindings_request_limits_and_password_never_reach_command_or_environment(self):
        session = self.session()
        args = [str(self.binary), 'balance', '--network', session.network,
                '--wallet', session.wallet, '--password-file', '-']
        result = json.loads(session.run_cli(args, PASSWORD).stdout)
        self.assertEqual(result['password_bytes'], len(PASSWORD.encode()))
        for changed in (args[:-2], [*args, '--wallet', 'other'],
                        [args[0], 'balance', '--network', 'other', *args[4:]]):
            with self.assertRaises(ValueError): session.run_cli(changed, PASSWORD)
        for extra in (['--wallet','other'], ['--rpc','other'], ['x'*20000], ['x'*16350]):
            with self.assertRaises(ValueError): session.run('send', extra, PASSWORD)
        for password in ('short', 'x'*1025):
            with self.assertRaises(ValueError): session.run('balance', [], password)
        self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1)

    def test_ui_routes_only_native_selected_commands_and_closes_worker(self):
        app = WalletApp.__new__(WalletApp)
        app.binary, app.network_file, app.wallet = self.binary, self.root/'network.json', self.root/'wallet.json'
        app.root, app.tester = self.root, True
        app.private_send_transport, app.invite_required = 'native-inline-v1', False
        app._command_session = self.session()
        first = app.cli('balance', PASSWORD)
        second = app.cli('fees', PASSWORD, ['--payment', 'send'])
        self.assertEqual(first['pid'], second['pid'])
        done = subprocess.CompletedProcess([],0,'{}','')
        with patch('wallet_ui.subprocess.run', return_value=done) as old:
            app.cli('address', PASSWORD)
            app.private_send_transport = None
            app.cli('balance', PASSWORD)
            self.assertEqual(old.call_count, 2)
        app.close()
        self.assertIsNone(app._command_session.pid)

    def test_native_withdrawal_and_default_fee_quotes_use_original_read_only_cli(self):
        app = self.app(self.session())
        send_quote = app.cli('fees', PASSWORD, ['--payment', 'send'])
        done = subprocess.CompletedProcess([],0,'{"payment":"withdraw"}','')
        with patch('wallet_ui.subprocess.run', return_value=done) as legacy:
            self.assertEqual(app.cli('fees', PASSWORD, ['--payment', 'withdraw'])['payment'], 'withdraw')
            self.assertEqual(app.cli('fees', PASSWORD)['payment'], 'withdraw')
            self.assertEqual(legacy.call_count, 2)
            self.assertEqual(legacy.call_args_list[0].args[0][-2:], ['--payment', 'withdraw'])
        balance = app.cli('balance', PASSWORD)
        self.assertEqual(balance['pid'], send_quote['pid'])
        self.assertEqual(balance['count'], 2)

    def test_retained_history_balance_and_send_validation_keep_original_cli(self):
        app = self.app(self.session())
        history = self.root/'recovery-history'
        history.mkdir()
        manifest = history/'manifest.json'
        manifest.write_text('{}')
        done = subprocess.CompletedProcess([],0,'{"balance":7,"retained_history":true}','')
        with patch('wallet_ui.subprocess.run', return_value=done) as legacy:
            self.assertTrue(app.cli('balance', PASSWORD)['retained_history'])
            self.assertEqual(legacy.call_count, 1)
            self.assertEqual(legacy.call_args.args[0][-2:], ['--history', str(history)])
        self.assertIsNone(app._command_session.pid)
        failed = subprocess.CompletedProcess([],1,'',
            'Wallet error: native send recovery uses canonical gateway history; --history is unsupported')
        with patch('wallet_ui.subprocess.run', return_value=failed) as legacy:
            with self.assertRaisesRegex(ValueError, 'canonical gateway history'):
                app.cli('send', PASSWORD)
            self.assertEqual(legacy.call_count, 1)
            self.assertEqual(legacy.call_args.args[0][-2:], ['--history', str(history)])
        self.assertIsNone(app._command_session.pid)
        self.assertFalse((self.root/'trace').exists())
        manifest.unlink()
        self.assertEqual(app.cli('balance', PASSWORD)['count'], 1)

    def app(self, session):
        app = WalletApp.__new__(WalletApp)
        app.binary, app.network_file, app.wallet = self.binary, self.root/'network.json', self.root/'wallet.json'
        app.root, app.tester = self.root, True
        app.private_send_transport, app.invite_required = 'native-inline-v1', False
        app._command_session, app._command_session_unsupported = session, False
        return app

    def test_exact_old_binary_rejection_precedes_every_request_or_password_write(self):
        session = self.session('old')
        with patch.object(session, '_write') as write:
            with self.assertRaises(SessionUnsupported):
                session.run('send', [], PASSWORD)
            write.assert_not_called()
        self.assertIsNone(session.pid)
        self.assertFalse((self.root/'trace').exists())

    def test_ui_old_binary_fallback_runs_once_then_memoizes_single_command_interface(self):
        app = self.app(self.session('old'))
        done = subprocess.CompletedProcess([],0,'{"legacy":true}','')
        with patch('wallet_ui.subprocess.run', return_value=done) as legacy:
            self.assertTrue(app.cli('send', PASSWORD)['legacy'])
            self.assertTrue(app.cli('balance', PASSWORD)['legacy'])
            self.assertEqual(legacy.call_count, 2)
        self.assertTrue(app._command_session_unsupported)
        self.assertIsNone(app._command_session)
        self.assertFalse((self.root/'trace').exists())

    def test_arbitrary_startup_error_or_output_never_authorizes_legacy_fallback(self):
        for mode in ('generic-startup', 'unknown-with-stdout', 'old-truncated'):
            with self.subTest(mode=mode):
                app = self.app(self.session(mode))
                with patch('wallet_ui.subprocess.run') as legacy:
                    with self.assertRaisesRegex(ValueError, 'saved payment status'):
                        app.cli('send', PASSWORD)
                    legacy.assert_not_called()
                self.assertFalse(app._command_session_unsupported)
                self.assertIsNone(app._command_session.pid)

    def test_identical_unknown_command_text_after_write_never_falls_back_or_resends(self):
        app = self.app(self.session('unknown-after-write'))
        with patch('wallet_ui.subprocess.run') as legacy:
            with self.assertRaisesRegex(ValueError, 'unknown wallet command'):
                app.cli('send', PASSWORD)
            legacy.assert_not_called()
        self.assertFalse(app._command_session_unsupported)
        self.assertEqual([json.loads(line)['command'] for line in (self.root/'trace').read_text().splitlines()], ['send'])

    def test_ui_old_binary_streaming_fallback_preserves_callback_and_one_attempt(self):
        app = self.app(self.session('old'))
        app.progress_callback = lambda _: None
        done = subprocess.CompletedProcess([],0,'{"legacy":true}','')
        with patch('wallet_ui.streaming_cli', return_value=done) as legacy:
            self.assertTrue(app.cli('send', PASSWORD)['legacy'])
            self.assertEqual(legacy.call_count, 1)
            self.assertIs(legacy.call_args.args[2], app.progress_callback)
        self.assertTrue(app._command_session_unsupported)
        self.assertFalse((self.root/'trace').exists())


if __name__ == '__main__':
    unittest.main()
