import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from operator_transport import Operator, credential, check_socket, private_parent
from rpc_isolation import validate


class HostIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='rpc-',dir='/private/tmp');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.key=self.root/'rpc-access.key';self.path=self.root/'rpc-18899.sock'
        self.doc={'format':'native-rpc-unix-v1','token':'a'*64,'sockets':{str(p):str(self.root/f'rpc-{p}.sock') for p in [18899,19899,28899,29899]}}
        self.write(self.key,self.doc)
    def write(self,path,data):
        path.write_text(json.dumps(data));path.chmod(0o600)
    def test_hardened_policy_cannot_downgrade_on_restart(self):
        marker=self.root/'raw-rpc-required.json'
        self.write(marker,{'format':'native-raw-rpc-unix-v1','credential_sha256':hashlib.sha256(self.key.read_bytes()).hexdigest()})
        policy={'raw_rpc_isolation':True,'raw_rpc_host_isolation':True}
        self.assertEqual(validate(self.root,policy),self.key)
        for config in [{},{'raw_rpc_isolation':True},{**policy,'raw_rpc_host_isolation':False}]:
            with self.assertRaises(ValueError):validate(self.root,config)
        marker.unlink()
        with self.assertRaises((ValueError,OSError)):validate(self.root,policy)
        with self.assertRaises((ValueError,OSError)):validate(self.root,{})
    def test_missing_private_socket_never_contacts_a_tcp_impostor(self):
        with socket.socket() as impostor:
            impostor.bind(('127.0.0.1',0));impostor.listen();impostor.settimeout(.1)
            port=impostor.getsockname()[1];self.doc['sockets'][str(port)]=str(self.path);self.write(self.key,self.doc)
            client=Operator(f'http://127.0.0.1:{port}',self.key)
            with self.assertRaises((ValueError,OSError)):client.forward(b'{}',timeout=.2)
            with self.assertRaises((TimeoutError,socket.timeout)):impostor.accept()
            with self.assertRaises(ValueError):Operator('http://127.0.0.1:1',self.key)
    def test_real_unix_http_forwarding_refuses_redirect_and_unsafe_socket(self):
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(self.path));self.path.chmod(0o600);server.listen()
            replies=[200,302];seen=[]
            def serve():
                for code in replies:
                    conn,_=server.accept()
                    with conn:
                        data=b''
                        while b'\r\n\r\n' not in data:data+=conn.recv(4096)
                        head,body=data.split(b'\r\n\r\n',1)
                        while len(body)<2:body+=conn.recv(2-len(body))
                        seen.append(head+b'\r\n\r\n'+body)
                        conn.sendall(f'HTTP/1.1 {code} test\r\nContent-Length: 2\r\nLocation: http://127.0.0.1:1\r\nConnection: close\r\n\r\n{{}}'.encode())
            thread=threading.Thread(target=serve,daemon=True);thread.start()
            client=Operator('http://127.0.0.1:18899',self.key)
            self.assertEqual(client.forward(b'{}'),b'{}')
            with self.assertRaises(ValueError):client.forward(b'{}')
            thread.join(timeout=2);self.assertFalse(thread.is_alive());self.assertEqual(len(seen),2)
            self.path.chmod(0o666)
            with self.assertRaises(ValueError):client.forward(b'{}')
        self.path.unlink();self.path.symlink_to(self.root/'absent')
        with self.assertRaises(ValueError):check_socket(self.path)
    def test_shared_writable_ancestor_is_refused_without_sticky_rename_protection(self):
        shared=self.root/'shared';inner=shared/'inner';inner.mkdir(parents=True,mode=0o700)
        shared.chmod(0o777)
        with self.assertRaises(ValueError):private_parent(inner/'rpc.sock')
        shared.chmod(0o1777);private_parent(inner/'rpc.sock')
    def test_public_export_excludes_private_transport_and_operator_material(self):
        from package_wallet import public_profile
        network={key:'public' for key in ['network','genesis_hash','program','pool','pool_format','recipient_withdrawals']}
        network.update(raw_rpc_isolation=True,raw_rpc_host_isolation=True,credential=self.doc,sockets=self.doc['sockets'])
        exported=public_profile(network,'Test','https://127.0.0.1:18898','https')
        self.assertTrue(set(exported).isdisjoint({'raw_rpc_isolation','raw_rpc_host_isolation','credential','sockets'}))
        self.assertNotIn(self.doc['token'],json.dumps(exported))
        self.assertNotIn(str(self.root),json.dumps(exported))
    def test_private_material_permissions_and_malformed_routes(self):
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):credential(self.key)
        self.key.chmod(0o600);self.root.chmod(0o755)
        with self.assertRaises(ValueError):credential(self.key)
        self.root.chmod(0o700)
        for routes in [{},{'0':str(self.path)},{'18899':'relative.sock'}]:
            self.doc['sockets']=routes;self.write(self.key,self.doc)
            with self.assertRaises(ValueError):credential(self.key)


if __name__=='__main__':unittest.main()
