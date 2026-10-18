import base64
from email.message import Message
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from testnet_gateway import Handler
from wallet_ui import WalletApp


class GatewayTests(unittest.TestCase):
    def request(self, body, access=None, headers=None, limit=False):
        calls=[]
        class Faucet:
            def ingress(self, channel, peer):
                calls.append(('ingress',channel,peer))
                if limit: raise ValueError('request quota exhausted')
            def command(self, command, data):
                calls.append((command,data))
                if data!={'signature':'valid'}: raise ValueError('invalid proof')
        class App:
            faucet=Faucet()
            def forward(self, raw):
                calls.append(('forward',json.loads(raw)))
                return b'{"jsonrpc":"2.0","id":1,"result":"genuine-upstream"}'
        handler=object.__new__(Handler)
        handler.server=type('Server',(),dict(authority='127.0.0.1:18898',app=App()))()
        handler.client_address=('127.0.0.1',3456); handler.path='/'
        raw=json.dumps(body).encode(); handler.rfile=io.BytesIO(raw); handler.wfile=io.BytesIO()
        handler.headers=Message()
        for key,value in {'Host':'127.0.0.1:18898','Content-Type':'application/json','Content-Length':str(len(raw)), **(headers or {})}.items(): handler.headers[key]=value
        if access is not None: handler.headers['X-Testnet-Access']=access
        response=[]
        handler.send_response=lambda code:response.append(code)
        handler.send_header=lambda *_:None; handler.end_headers=lambda:None
        handler.do_POST()
        return response[0],json.loads(handler.wfile.getvalue()),calls

    def test_public_genesis_and_member_rpc_are_charged_before_forwarding(self):
        genesis=dict(jsonrpc='2.0',id=1,method='getGenesisHash')
        code,_,calls=self.request(genesis,headers={'X-Forwarded-For':'attacker-controlled'})
        self.assertEqual(code,200); self.assertEqual(calls[0],('ingress','rpc','127.0.0.1'))
        self.assertEqual(self.request(dict(genesis, params=None))[0],200)
        request=dict(jsonrpc='2.0',id=1,method='sendTransaction',params=['signed-native-transaction'])
        code,_,calls=self.request(request)
        self.assertEqual(code,403); self.assertFalse(any(c[0]=='forward' for c in calls))
        header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        code,_,calls=self.request(request,header)
        self.assertEqual(code,200); self.assertEqual([c[0] for c in calls],['ingress','authorize','forward'])
        code,_,calls=self.request(request,header,limit=True)
        self.assertEqual(code,429); self.assertEqual(len(calls),1)

    def test_malformed_envelopes_methods_headers_and_batches_never_reach_upstream(self):
        genesis=dict(jsonrpc='2.0',id=1,method='getGenesisHash')
        for request in [[], {}, dict(genesis,method={}), dict(genesis,method=[]), dict(genesis,id=True), dict(genesis,params={}), dict(genesis,method='getIdentity'),dict(genesis,extra='unbounded'),dict(genesis,id='x'*65)]:
            with self.subTest(request=request):
                code,_,calls=self.request(request)
                self.assertEqual(code,403); self.assertFalse(any(c[0]=='forward' for c in calls))
        for headers in [{'Host':'evil.invalid'},{'Origin':'http://evil.invalid'},{'Content-Length':'32769'},{'Transfer-Encoding':'chunked'},{'Content-Type':'text/plain'}]:
            code,_,calls=self.request(genesis,headers=headers)
            self.assertEqual(code,403); self.assertFalse(any(c[0]=='forward' for c in calls))
        for header in ['?', 'x'*3073, base64.urlsafe_b64encode(b'{}').decode()]:
            code,_,calls=self.request(dict(genesis,method='getBalance'),header)
            self.assertEqual(code,403); self.assertFalse(any(c[0]=='forward' for c in calls))


class InvitedWalletTests(unittest.TestCase):
    def app(self, directory):
        profile=dict(label='Invited testnet',invite_required=True,faucet={'transport':'loopback-http','url':'http://127.0.0.1:8780'})
        result=type('Result',(),dict(returncode=0,stdout=json.dumps(profile)))()
        with patch('wallet_ui.subprocess.run',return_value=result):
            return WalletApp.from_profile(Path('profile.json'),Path(directory)/'client')
    def test_invite_is_private_temporary_input_and_backup_precedes_redemption(self):
        with tempfile.TemporaryDirectory() as directory:
            app=self.app(directory); code='invite1_'+'A'*43; seen=[]
            self.assertTrue(app.status()['invite_required'])
            with self.assertRaisesRegex(ValueError,'recovery'): app.action(dict(action='join',password='local-password-long',invitation=code))
            app.ack.touch()
            def cli(command,password,extra):
                self.assertEqual(command,'join'); self.assertEqual(password,'local-password-long')
                self.assertEqual(extra[0],'--invitation-file')
                path=Path(extra[1]); self.assertEqual(path.stat().st_mode&0o777,0o600)
                self.assertEqual(path.read_text(),code); seen.append(path)
                self.assertNotIn(code,extra)
                return {'admitted':True,'state':'queued'}
            with patch.object(app,'cli',side_effect=cli):
                app.action(dict(action='join',password='local-password-long',invitation=code,rpc='attacker-url',amount=9999))
            self.assertTrue(app.admitted); self.assertFalse(seen[0].exists())
            with patch.object(app,'cli',side_effect=ValueError('expired')):
                with self.assertRaisesRegex(ValueError,'expired'): app.action(dict(action='join',password='local-password-long',invitation=code))
            self.assertEqual(list(app.directory.glob('.invite-*')),[])
    def test_revoked_access_blocks_value_actions_but_preserves_wallet_and_recovery(self):
        with tempfile.TemporaryDirectory() as directory:
            app=self.app(directory); app.ack.touch()
            app.wallet.write_text('encrypted-wallet-preserved')
            for action in ['balance','fees','test-coins','send','withdraw','resolve','reclaim']:
                with patch.object(app,'cli',return_value={'admitted':False,'state':'revoked'}) as cli:
                    with self.assertRaisesRegex(ValueError,'access is unavailable'): app.action(dict(action=action,password='local-password-long'))
                    self.assertEqual(cli.call_args.args,('access-status','local-password-long'))
            self.assertEqual(app.wallet.read_text(),'encrypted-wallet-preserved')
            with patch.object(app,'cli',return_value={'address':'npriv1-same-wallet'}):
                self.assertEqual(app.action(dict(action='ack-backup',password='local-password-long'))['address'],'npriv1-same-wallet')


class InviteCheckpointTests(unittest.TestCase):
    def test_resume_refuses_completed_running_and_unrelated_evidence_before_mutation(self):
        from invite_localnet import gas_checkpoint, compat_checkpoint
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/'invite-result.json'
            for status in ['passed','running','failed']:
                path.write_text(json.dumps(dict(status=status,error='unrelated failure',events=[])))
                original=path.read_bytes()
                with self.assertRaisesRegex(ValueError,'exact failed'): gas_checkpoint(root)
                with self.assertRaisesRegex(ValueError,'exact failed'): compat_checkpoint(root,root)
                self.assertEqual(path.read_bytes(),original)


if __name__=='__main__': unittest.main()
