import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_faucet import BoundedServer, Faucet
from wallet_ui import WalletApp


class DistributionTests(unittest.TestCase):
    def test_password_stays_in_worker_stdin_and_claim_schema_is_fixed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); root.chmod(0o700)
            password=root/'password'; password.write_text('dedicated-faucet-password'); password.chmod(0o600)
            app=Faucet(root,password)
            for request in [{}, {'amount':100}, {'password':'do-not-upload'}]:
                with self.assertRaises(ValueError): app.accept(request)
            data=dict(format='native-test-grant-v1',network={},private_address='test',fee_address='test',signature='signed')
            with patch('test_faucet.subprocess.run',return_value=type('Result',(),dict(returncode=0,stdout='{"state":"queued"}'))()) as run:
                self.assertEqual(app.accept(data)['state'],'queued')
                self.assertNotIn('dedicated-faucet-password',str(run.call_args))
                with self.assertRaisesRegex(ValueError,'moment'): app.accept(data)
            app.close()
            self.assertEqual(app.password,'')

    def test_standalone_grant_uses_only_own_seed_addresses_and_needs_backup(self):
        config=dict(label='Distribution',genesis_hash='11111111111111111111111111111111',faucet={'transport':'loopback-http','url':'http://127.0.0.1:8780'})
        result=type('Result',(),dict(returncode=0,stdout=json.dumps(config)))()
        with tempfile.TemporaryDirectory() as directory, patch('wallet_ui.subprocess.run',return_value=result):
            app=WalletApp.from_profile(Path('profile.json'),Path(directory)/'client')
            self.assertTrue(app.status()['test_faucet_available'])
            with self.assertRaisesRegex(ValueError,'recovery'): app.action({'action':'test-coins','password':'local-password-long'})
            app.ack.touch()
            with patch.object(app,'cli',return_value={'state':'queued'}) as cli:
                app.action({'action':'test-coins','password':'local-password-long','recipient':'redirect','amount':999,'rpc':'bad','faucet':'bad'})
                self.assertEqual(cli.call_args.args,('test-coins','local-password-long'))
                Path(str(app.wallet)+'.pending.json').write_text('preserved')
                with self.assertRaisesRegex(ValueError,'previous payment'): app.action({'action':'test-coins','password':'local-password-long'})


    def test_worker_password_uses_stdin_and_http_concurrency_is_bounded(self):
        import threading
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); root.chmod(0o700)
            password=root/'password'; password.write_text('dedicated-faucet-password'); password.chmod(0o600)
            app=Faucet(root,password)
            class Child:
                returncode=0
                def communicate(self,**kwargs):
                    self_input=kwargs.get('input')
                    if self_input!='dedicated-faucet-password': raise AssertionError('password was not piped')
                    app.stop.set()
                    return '{}',''
            with patch('test_faucet.subprocess.Popen',return_value=Child()) as run:
                app.work()
                args=run.call_args.args[0]
                self.assertEqual(args[-2:],['--password-file','-'])
                self.assertNotIn('dedicated-faucet-password',str(run.call_args))
            server=object.__new__(BoundedServer); server.slots=threading.BoundedSemaphore(4)
            with patch('http.server.ThreadingHTTPServer.process_request'), patch.object(server,'shutdown_request') as reject:
                for _ in range(5): server.process_request(object(),('127.0.0.1',123))
                self.assertEqual(reject.call_count,1)
            with patch('http.server.ThreadingHTTPServer.process_request_thread'):
                server.process_request_thread(object(),('127.0.0.1',123))
            self.assertTrue(server.slots.acquire(blocking=False))


if __name__=='__main__': unittest.main()
