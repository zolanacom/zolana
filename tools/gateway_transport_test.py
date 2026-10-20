"""Real bounded TLS connection reuse, reauthorization and rejected-body isolation."""
import base64
from contextlib import closing
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

from direct_tls_test import config, running
from local_test_tls import create as create_tls
from service_tls import listener
from testnet_gateway import Handler
from wallet_release import encode, sha


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.base = Path(cls.temp.name); cls.base.chmod(0o700)
        cls.tls = cls.base/'tls'; create_tls(cls.tls)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def server(self):
        calls = []; owner = self
        class Faucet:
            def ingress(self, channel, peer): calls.append(('edge', peer))
            def command(self, command, proof):
                calls.append(('authorize', proof))
                if proof != {'signature':'valid'} or getattr(owner, 'revoked', False):
                    raise ValueError('access denied')
        class App:
            faucet = Faucet()
            def forward(self, raw):
                query = json.loads(raw); calls.append(('forward', query['method']))
                return json.dumps(dict(jsonrpc='2.0', id=query['id'], result='ok')).encode()
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
        endpoint = 'https://127.0.0.1:' + str(port)
        cert, key = self.tls/'server.crt', self.tls/'server.key'
        path = self.base/'listener.json'; path.write_bytes(encode(config(endpoint,port,cert,key))); path.chmod(0o600)
        return listener(endpoint,port,Handler,App(),cert,key,path,sha(path.read_bytes())), port, calls

    def client(self, port):
        return http.client.HTTPSConnection('127.0.0.1',port,context=ssl.create_default_context(cafile=str(self.tls/'ca.crt')),timeout=3)

    def post(self, client, method='getGenesisHash', access=None):
        headers={'Content-Type':'application/json'}
        if access is not None: headers['X-Testnet-Access']=access
        client.request('POST','/',json.dumps(dict(jsonrpc='2.0',id=1,method=method)),headers)
        reply=client.getresponse(); body=reply.read()
        return reply, body

    def test_reuses_same_tls_socket_and_reauthorizes_every_request_including_revocation(self):
        self.revoked=False
        server,port,calls=self.server()
        with running(server), closing(self.client(port)) as client:
            reply,_=self.post(client); sock=client.sock
            self.assertEqual(reply.version,11); self.assertFalse(reply.will_close)
            header=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
            reply,_=self.post(client,'getBalance',header)
            self.assertEqual(reply.status,200); self.assertIs(client.sock,sock)
            self.revoked=True
            reply,_=self.post(client,'getBalance',header)
            self.assertEqual(reply.status,403);self.assertTrue(reply.will_close)
            self.assertEqual(len([c for c in calls if c[0]=='authorize']),2)
            self.assertEqual(len([c for c in calls if c[0]=='forward']),2)

    def test_connection_request_budget_closes_after_complete_response(self):
        server,port,_=self.server(); server.RequestHandlerClass.max_connection_requests=2
        with running(server), closing(self.client(port)) as client:
            self.assertFalse(self.post(client)[0].will_close)
            reply,body=self.post(client)
            self.assertEqual(reply.status,200); self.assertEqual(json.loads(body)['result'],'ok')
            self.assertTrue(reply.will_close)

    def test_idle_and_lifetime_limits_close_reusable_connections(self):
        server,port,_=self.server()
        with running(server), closing(self.client(port)) as client:
            self.assertFalse(self.post(client)[0].will_close)
            client.sock.settimeout(7)
            self.assertEqual(client.sock.recv(1),b'')
        server,port,_=self.server();server.RequestHandlerClass.max_connection_seconds=0
        with running(server), closing(self.client(port)) as client:
            reply,body=self.post(client)
            self.assertEqual(reply.status,200);self.assertTrue(reply.will_close)
            self.assertEqual(json.loads(body)['result'],'ok')

    def test_rejected_framing_closes_before_pipelined_body_can_become_rpc(self):
        for bad_header in ['Content-Length: 2\r\nContent-Length: 2', 'Transfer-Encoding: chunked',
                           'X-Forwarded-For: 198.51.100.4', 'Content-Length: +2']:
            server,port,calls=self.server()
            with running(server):
                context=ssl.create_default_context(cafile=str(self.tls/'ca.crt'))
                with socket.create_connection(('127.0.0.1',port),timeout=3) as tcp, context.wrap_socket(tcp,server_hostname='127.0.0.1') as secure:
                    follow=json.dumps(dict(jsonrpc='2.0',id=1,method='getGenesisHash')).encode()
                    second=(f'POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {len(follow)}\r\n\r\n').encode()+follow
                    first=(f'POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\n{bad_header}\r\n\r\n').encode()+b'{}'
                    secure.sendall(first+second)
                    reply=http.client.HTTPResponse(secure);reply.begin();reply.read()
                    self.assertEqual(reply.status,403);self.assertTrue(reply.will_close)
                    self.assertFalse(any(c[0]=='forward' for c in calls))


if __name__ == '__main__': unittest.main()
