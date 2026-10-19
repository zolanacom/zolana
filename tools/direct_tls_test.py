"""Direct TLS authority/binding, native admission and crash recovery; no validators."""
from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import direct_tls
import pilot_cohort as pilot
import pilot_cohort_test as fixtures
from local_test_tls import create as create_tls
from service_tls import listener
from testnet_gateway import Handler as GatewayHandler
from wallet_release import create,decode,encode,read,sha


def config(endpoint,port,cert,key,bind='127.0.0.1'):
    return dict(format='zolana-direct-tls-v1',audience=endpoint,bind_ip=bind,port=port,
                certificate_sha256=sha(cert.read_bytes()),key_sha256=sha(key.read_bytes()))


def dns_certificate(tls):
    ext=tls/'dns.cnf'
    ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:rpc.pilot.invalid,DNS:faucet.pilot.invalid,IP:127.0.0.1\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
    subprocess.run(['openssl','x509','-req','-in',str(tls/'server.csr'),'-CA',str(tls/'ca.crt'),'-CAkey',str(tls/'ca.key'),
                    '-set_serial','99','-out',str(tls/'dns.crt'),'-days','2','-sha256','-extfile',str(ext)],
                   check=True,capture_output=True,timeout=20)


def request(port,ca,host,headers=(),body=None,name='127.0.0.1',verify=True):
    raw=json.dumps(body or dict(jsonrpc='2.0',id=1,method='getGenesisHash')).encode()
    context=ssl.create_default_context(cafile=str(ca) if ca is not None else None) if verify else ssl._create_unverified_context()
    with socket.create_connection(('127.0.0.1',port),timeout=4) as sock:
        with context.wrap_socket(sock,server_hostname=name) as stream:
            stream.sendall(('POST / HTTP/1.1\r\nHost: '+host+'\r\nContent-Type: application/json\r\nContent-Length: '+str(len(raw))+'\r\n'+
                            ''.join(k+': '+v+'\r\n' for k,v in headers)+'Connection: close\r\n\r\n').encode()+raw)
            reply=http.client.HTTPResponse(stream);reply.begin()
            return reply.status,reply.read()


@contextmanager
def running(server):
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:yield server
    finally:server.shutdown();server.server_close();thread.join(timeout=5)


class DirectPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.base=Path(cls.tmp.name);cls.base.chmod(0o700)
        cls.tls=cls.base/'tls';create_tls(cls.tls);dns_certificate(cls.tls)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def setUp(self):
        self.port=fixtures.unused_port();self.endpoint=f'https://rpc.pilot.invalid:{self.port}'
        self.cert,self.key=self.tls/'dns.crt',self.tls/'server.key'
        self.path=self.base/'binding.json'
        self.value=config(self.endpoint,self.port,self.cert,self.key)
        self.write(self.value)
    def write(self,value):
        self.path.write_bytes(encode(value));self.path.chmod(0o600);self.digest=sha(self.path.read_bytes())
    def server(self,app):return listener(self.endpoint,self.port,GatewayHandler,app,self.cert,self.key,self.path,self.digest)
    def test_schema_digest_bind_and_profile_changes_fail_before_bind(self):
        bad_values=[dict(self.value,extra=True),dict(self.value,format='proxy'),dict(self.value,port=True),
                    dict(self.value,bind_ip='localhost'),dict(self.value,bind_ip='224.0.0.1'),dict(self.value,bind_ip='::'),
                    dict(self.value,audience='https://other.invalid:'+str(self.port)),dict(self.value,key_sha256='0'*64)]
        with patch('service_tls.TLSServer') as bind:
            for value in bad_values:
                self.write(value)
                with self.assertRaises((ValueError,OSError)):self.server(object())
            self.write(self.value);self.digest='0'*64
            with self.assertRaises(ValueError):self.server(object())
            bind.assert_not_called()
        self.write(self.value);self.path.chmod(0o644)
        with self.assertRaises(ValueError):self.server(object())
        self.path.chmod(0o600)
        link=self.base/'binding-link.json'
        link.unlink(missing_ok=True);link.symlink_to(self.path)
        with self.assertRaises(OSError):direct_tls.policy(link,self.digest,self.endpoint,self.port,self.cert,self.key)
    def test_noncanonical_and_non_https_audiences_are_refused(self):
        for endpoint in [f'http://rpc.pilot.invalid:{self.port}',self.endpoint+'/',self.endpoint+'?x',self.endpoint+'#x',
                         f'https://RPC.pilot.invalid:{self.port}',f'https://user{chr(64)}rpc.pilot.invalid:{self.port}',
                         f'https://0.0.0.0:{self.port}',f'https://224.0.0.1:{self.port}',f'https://127.1:{self.port}',
                         f'https://[::1]:{self.port}',f'https://rpc..invalid:{self.port}',f'https://rpc.pilot.invalid:{self.port+1}']:
            self.write(dict(self.value,audience=endpoint))
            with self.assertRaises(ValueError):direct_tls.policy(self.path,self.digest,endpoint,self.port,self.cert,self.key)
        endpoint='https://rpc.pilot.invalid:0';self.write(config(endpoint,443,self.cert,self.key))
        with self.assertRaises(ValueError):direct_tls.policy(self.path,self.digest,endpoint,443,self.cert,self.key)
        endpoint='https://rpc.pilot.invalid:1';self.write(config(endpoint,1,self.cert,self.key))
        with self.assertRaises(ValueError):direct_tls.policy(self.path,self.digest,endpoint,True,self.cert,self.key)

    def test_bind_is_separate_and_all_interfaces_require_explicit_review(self):
        self.write(dict(self.value,bind_ip='0.0.0.0'))
        with patch('service_tls.TLSServer') as bind:
            self.server(object());self.assertEqual(bind.call_args.args[0],('0.0.0.0',self.port))
        # The old API still cannot expose an external audience without an opt-in.
        with self.assertRaises(ValueError):listener(self.endpoint,self.port,GatewayHandler,object(),self.cert,self.key)
        for path,digest in [(self.path,None),(None,self.digest)]:
            with self.assertRaises(ValueError):listener(self.endpoint,self.port,GatewayHandler,object(),self.cert,self.key,path,digest)
    def test_invalid_or_changed_certificate_key_never_binds(self):
        with patch('service_tls.TLSServer') as bind,self.assertRaises(ssl.SSLError):
            key=self.tls/'rotated.key';self.write(config(self.endpoint,self.port,self.cert,key))
            listener(self.endpoint,self.port,GatewayHandler,object(),self.cert,key,self.path,self.digest)
        bind.assert_not_called()
        self.write(self.value)
        with self.assertRaises(ValueError):listener(self.endpoint,self.port,GatewayHandler,object(),self.tls/'server.crt',self.key,self.path,self.digest)
    def test_real_dns_sni_host_and_forwarded_headers_fail_before_native_work(self):
        calls=[]
        class Faucet:
            def ingress(self,channel,peer):calls.append((channel,peer))
        class App:
            faucet=Faucet()
            def forward(self,raw):calls.append('upstream');return b'{"result":"genuine"}'
        with running(self.server(App())):
            ca=self.tls/'ca.crt';host=f'rpc.pilot.invalid:{self.port}'
            with socket.create_connection(('127.0.0.1',self.port),timeout=4) as plain:
                plain.sendall(b'POST / HTTP/1.1\r\nHost: attacker\r\n\r\n')
                try:self.assertEqual(plain.recv(1024),b'')
                except ConnectionResetError:pass
            self.assertEqual(calls,[])
            self.assertEqual(request(self.port,ca,host,name='rpc.pilot.invalid')[0],200)
            self.assertEqual(calls,[('rpc','127.0.0.1'),'upstream']);calls.clear()
            for headers in [[('Host',host)],[('Content-Length','2')],[('Content-Type','text/plain')],
                            [('X-Testnet-Access','a'),('X-Testnet-Access','b')],[('Origin','https://evil.invalid')],
                            [('X-Forwarded-For','198.51.100.7')],[('Forwarded','for=198.51.100.7')],
                            [('X-Forwarded-Host',host)],[('X-Real-IP','198.51.100.7')],
                            [('CF-Connecting-IP','198.51.100.7')],[('Transfer-Encoding','chunked')]]:
                self.assertEqual(request(self.port,ca,host,headers,name='rpc.pilot.invalid')[0],403)
            self.assertEqual(request(self.port,ca,'wrong.invalid',name='rpc.pilot.invalid')[0],403)
            self.assertEqual(calls,[])
            for name in ['faucet.pilot.invalid','127.0.0.1']:
                with self.assertRaises(ssl.SSLError):request(self.port,ca,host,name=name)
            # No-SNI clients are refused even when they disable client verification.
            with self.assertRaises(ssl.SSLError):request(self.port,ca,host,name=None,verify=False)
    def test_expired_and_untrusted_tls_never_reach_application(self):
        class App:
            def forward(self,raw):raise AssertionError('invalid TLS reached app')
        for cert in [self.tls/'expired.crt',self.tls/'wrong-host.crt']:
            endpoint=f'https://127.0.0.1:{self.port}';self.write(config(endpoint,self.port,cert,self.tls/(('wrong-host' if cert.name=='wrong-host.crt' else 'server')+'.key')))
            with running(listener(endpoint,self.port,GatewayHandler,App(),cert,self.tls/(('wrong-host' if cert.name=='wrong-host.crt' else 'server')+'.key'),self.path,self.digest)):
                with self.assertRaises(ssl.SSLCertVerificationError):request(self.port,self.tls/'ca.crt',f'127.0.0.1:{self.port}')
        self.write(self.value)
        with running(self.server(App())):
            with self.assertRaises(ssl.SSLCertVerificationError):
                request(self.port,None,f'rpc.pilot.invalid:{self.port}',name='rpc.pilot.invalid')


class NativeDirectTests(unittest.TestCase):
    prepare=fixtures.PilotTests.prepare
    wallet=fixtures.PilotTests.wallet
    command=fixtures.PilotTests.command
    def setUp(self):
        fixtures.PilotTests.setUp(self)
        self.tls=self.base/'tls';create_tls(self.tls)
        tester=self.value['tester_profile'];tester['rpc']=dict(transport='https',url='https://127.0.0.1:'+str(fixtures.unused_port()))
        tester['faucet']=dict(transport='https',url='https://127.0.0.1:'+str(self.port))
        tester['local_tls_ca_pem']=(self.tls/'ca.crt').read_text()
        self.value=pilot.validate(self.value);self.digest=sha(encode(self.value));self.prepare()
        self.path=self.base/'listener.json';self.cert=self.tls/'server.crt';self.key=self.tls/'server.key'
        create(self.path,encode(config(tester['faucet']['url'],self.port,self.cert,self.key)))
        self.listener_digest=sha(self.path.read_bytes())
    @contextmanager
    def server(self):
        # Native admission is real; no grant worker or validator is needed here.
        script='''import sys
from pathlib import Path
from service_tls import listener
from test_faucet import Faucet,Handler
app=Faucet(Path(sys.argv[1]),Path(sys.argv[2]))
info=app.command('access-info')
server=listener(info['faucet_audience'],int(sys.argv[3]),Handler,app,Path(sys.argv[4]),Path(sys.argv[5]),Path(sys.argv[6]),sys.argv[7])
server.serve_forever()
'''
        child=subprocess.Popen([sys.executable,'-B','-c',script,str(self.root/'faucet'),str(self.password),str(self.port),
                                str(self.cert),str(self.key),str(self.path),self.listener_digest],
                               cwd=pilot.PROJECT/'tools',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                if child.poll() is not None:raise RuntimeError('direct native server exited')
                try:
                    with socket.create_connection(('127.0.0.1',self.port),timeout=.2):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('direct native server unavailable')
            yield child
        finally:
            if child.poll() is None:child.kill()
            child.wait(timeout=10)
    def test_real_tls_join_sigkill_seed_restore_and_revocation_keep_original_claim(self):
        alice,backup,keys=self.wallet('alice')
        issued=pilot.issue(self.root,self.digest,'tester-01',bind_fee=keys['fee_address'])
        invitation=self.root/'invitations/tester-01.json';original=read(self.root/'faucet/wallet.enc.json',16384,secret=True)
        with self.server() as child:
            first=self.command('join',alice,invitation_file=invitation)
            self.assertTrue(first['admitted']);self.assertEqual(first['state'],'queued')
            child.kill();child.wait(timeout=10)
        claims=read(self.root/'faucet/claims.json',1024*1024,secret=True)
        restored=self.base/'restored.wallet';self.command('restore',restored,backup=backup)
        with self.server():
            self.assertTrue(self.command('access-status',restored)['admitted'])
            self.assertEqual(self.command('join',restored,invitation_file=invitation)['claim_id'],first['claim_id'])
            self.assertEqual(self.command('test-coins',restored)['claim_id'],first['claim_id'])
            pilot.native(pilot.FAUCET,'invite-revoke',self.root/'faucet',['--invite-id',issued['invite_id']])
            self.assertFalse(self.command('access-status',restored)['admitted'])
        self.assertEqual(original,read(self.root/'faucet/wallet.enc.json',16384,secret=True))
        self.assertEqual(claims,read(self.root/'faucet/claims.json',1024*1024,secret=True))
        self.assertEqual(pilot.audit(self.root,self.digest)['reserved_claims'],1)
    def test_spoofed_peers_never_mutate_native_edge_quota_and_exhaustion_survives_restart(self):
        from wallet_release import atomic
        admission=self.root/'faucet/admission.json'
        # Leave enough of the real native minute for both process restarts.
        remaining=60-time.time()%60
        if remaining<5:time.sleep(remaining+.05)
        # Native edge invocation sets its own real-clock bucket and peer hash.
        pilot.native(pilot.FAUCET,'edge',self.root/'faucet',['--channel','faucet','--peer','127.0.0.1'])
        value=decode(read(admission,1024*1024,secret=True))
        for edge in value['edge']:
            if edge['peer']!='global':edge['bucket']['count']=240
        atomic(admission,value);before=admission.read_bytes()
        with self.server() as child:
            for name in ['X-Forwarded-For','Forwarded','X-Real-IP']:
                self.assertEqual(request(self.port,self.tls/'ca.crt',f'127.0.0.1:{self.port}',[(name,'198.51.100.9')])[0],403)
            self.assertEqual(admission.read_bytes(),before)
            # A normal /join envelope is rate limited before proof parsing.
            self.assertEqual(self.join_raw()[0],429)
            child.kill();child.wait(timeout=10)
        with self.server():self.assertEqual(self.join_raw()[0],429)
        self.assertEqual(pilot.audit(self.root,self.digest)['reserved_claims'],0)
    def join_raw(self):
        ctx=ssl.create_default_context(cafile=str(self.tls/'ca.crt'))
        conn=http.client.HTTPSConnection('127.0.0.1',self.port,context=ctx,timeout=5)
        try:
            conn.request('POST','/join',b'{}',{'Content-Type':'application/json'})
            reply=conn.getresponse();return reply.status,reply.read()
        finally:conn.close()


if __name__=='__main__':unittest.main()
