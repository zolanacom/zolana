import copy
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error

from history_retention import atomic, manifest, MAX_SEGMENT
from history_retention_test import NETWORK, archive, block, segment, write
from history_replica import Client, Receiver, credential, fetch, initialize, replicate, server
from local_test_tls import create


class ReplicaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cert_temp=tempfile.TemporaryDirectory()
        cls.certs=Path(cls.cert_temp.name).resolve()/'tls'
        create(cls.certs)
        (cls.certs/'ca.crt').chmod(0o600)
    @classmethod
    def tearDownClass(cls):cls.cert_temp.cleanup()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.source=self.root/'source';archive(self.source)
        self.replica=self.root/'replica';self.key=self.root/'source.key'
        initialize(self.replica,NETWORK,self.key)
        self.listener=server(self.replica,0,self.certs/'server.crt',self.certs/'server.key')
        self.thread=threading.Thread(target=self.listener.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.shutdown)
        self.options=dict(network=NETWORK,url='https://'+self.listener.authority,credential_file=self.key,ca_file=self.certs/'ca.crt')
    def shutdown(self):
        self.listener.shutdown();self.listener.server_close();self.thread.join(5);self.listener.app.close()
    def push(self):return replicate(self.source,**self.options)
    def extend(self):
        data=json.loads((self.source/'manifest.json').read_bytes());data['segments'].append(segment(self.source,[block(2)],1));archive(self.source,data['segments'])
    def test_tls_transfer_retry_omits_secrets_and_download_reconstructs_exact_history(self):
        write(self.source/'wallet.password',b'should never cross the transport')
        write(self.source/'validator.key',b'should never cross the transport')
        first=self.push();self.assertTrue(first['durable']);self.assertEqual(first['finalized_slot'],1)
        self.assertEqual(self.push()['uploaded_bytes'],0)
        self.assertFalse((self.replica/'committed/wallet.password').exists())
        self.assertFalse((self.replica/'incoming/validator.key').exists())
        self.extend();self.assertEqual(self.push()['finalized_slot'],2)
        destination=self.root/'recovered';result=fetch(destination,**self.options)
        self.assertEqual(result['finalized_slot'],2)
        raw,files,_=manifest(self.source,NETWORK)
        self.assertEqual((destination/'manifest.json').read_bytes(),raw)
        for name,_ in files:self.assertEqual((destination/name).read_bytes(),(self.source/name).read_bytes())
    def test_rollback_prefix_replacement_and_wrong_network_leave_commit_intact(self):
        self.push();original=(self.replica/'committed/manifest.json').read_bytes()
        for mode in ['rollback','changed','network']:
            with self.subTest(mode=mode):
                if mode=='rollback':archive(self.source,[])
                if mode=='changed':archive(self.source,[segment(self.source,[dict(block(1),transactions=[{'changed':True}])])])
                if mode=='network':
                    data=json.loads(original);data['network']['network'][0]=99;write(self.source/'manifest.json',json.dumps(data).encode())
                with self.assertRaises(ValueError):self.push()
                self.assertEqual((self.replica/'committed/manifest.json').read_bytes(),original)
    def test_corrupt_missing_and_rehashed_gap_cannot_publish_new_manifest(self):
        self.push();original=(self.replica/'committed/manifest.json').read_bytes();self.extend()
        _,files,_=manifest(self.source,NETWORK);name=files[-1][0];data=(self.source/name).read_bytes()
        write(self.source/name,b'corrupt')
        with self.assertRaisesRegex(ValueError,'checksum'):self.push()
        (self.source/name).unlink()
        with self.assertRaises(FileNotFoundError):self.push()
        write(self.source/name,data)
        descriptors=json.loads(original)['segments'];descriptors.append(segment(self.source,[block(2,parent=99)],1));archive(self.source,descriptors)
        with self.assertRaises(ValueError):self.push()
        self.assertEqual((self.replica/'committed/manifest.json').read_bytes(),original)
    def test_auth_paths_and_raw_rpc_credentials_cannot_access_replica(self):
        self.push();client=Client(**self.options);client.token='0'*64
        with self.assertRaises(ValueError):client.request('GET','manifest.json')
        client=Client(**self.options)
        for path in ['../replica.key','replica.key','../network.json','manifest.json?secret=1']:
            with self.assertRaises(ValueError):client.request('GET',path)
        write(self.root/'rpc.key',b'{"format":"native-rpc-unix-v1","token":"unrelated"}')
        with self.assertRaises(ValueError):credential(self.root/'rpc.key',NETWORK)
        wrong=copy.deepcopy(NETWORK);wrong['network'][0]=99
        with self.assertRaises(ValueError):credential(self.key,wrong)
    def test_http_redirect_and_ca_pin_downgrade_are_rejected(self):
        with self.assertRaises(ValueError):Client(**dict(self.options,url=self.options['url'].replace('https:','http:')))
        with self.assertRaises(ValueError):Client(**self.options,ca_sha256='0'*64)
        import socket
        from http.server import BaseHTTPRequestHandler
        with socket.socket() as trap:
            trap.bind(('127.0.0.1',0));trap.listen();trap.settimeout(.2)
            location='http://127.0.0.1:'+str(trap.getsockname()[1])+'/credential-trap'
            class Redirect(BaseHTTPRequestHandler):
                def log_message(self,*_):pass
                def do_GET(self):
                    self.send_response(302);self.send_header('Location',location)
                    self.send_header('Content-Length','0');self.end_headers()
            original=self.listener.RequestHandlerClass;self.listener.RequestHandlerClass=Redirect
            try:
                with self.assertRaises(ValueError):Client(**self.options).request('GET','manifest.json')
                with self.assertRaises(socket.timeout):trap.accept()
            finally:self.listener.RequestHandlerClass=original
        # Correct CA, wrong IP SAN: the real TLS client must reject this listener.
        other_root=self.root/'other-replica';other_key=self.root/'other.key'
        initialize(other_root,NETWORK,other_key)
        other=server(other_root,0,self.certs/'wrong-host.crt',self.certs/'wrong-host.key')
        thread=threading.Thread(target=other.serve_forever,daemon=True);thread.start()
        try:
            options=dict(self.options,url='https://'+other.authority,credential_file=other_key)
            with self.assertRaises(urllib.error.URLError):Client(**options).request('GET','manifest.json')
        finally:other.shutdown();other.server_close();thread.join(5);other.app.close()
    def test_incomplete_upload_and_failed_publication_preserve_commit(self):
        self.push();original=(self.replica/'committed/manifest.json').read_bytes();self.extend()
        raw,files,_=manifest(self.source,NETWORK);client=Client(**self.options)
        prepared=json.loads(client.request('POST','prepare',raw));checkpoint=prepared['checkpoint']
        with self.assertRaises(ValueError):client.request('POST',checkpoint+'/commit',b'{}')
        self.assertEqual((self.replica/'committed/manifest.json').read_bytes(),original)
        name,_=files[-1];client.request('PUT',checkpoint+'/'+name,(self.source/name).read_bytes())
        with patch('history_retention.atomic',side_effect=OSError('simulated manifest publication interruption')):
            with self.assertRaises(ValueError):client.request('POST',checkpoint+'/commit',b'{}')
        self.assertEqual((self.replica/'committed/manifest.json').read_bytes(),original)
        self.assertEqual(self.push()['finalized_slot'],2)
    def test_capacity_low_space_process_lock_and_symlink_fail_closed(self):
        self.push();original=(self.replica/'committed/manifest.json').read_bytes();self.extend()
        from types import SimpleNamespace
        with patch('history_replica.shutil.disk_usage',return_value=SimpleNamespace(free=1)):
            with self.assertRaises(ValueError):self.push()
        with self.assertRaises(BlockingIOError):Receiver(self.replica)
        with self.assertRaises(ValueError):initialize(self.replica,NETWORK,self.root/'new.key')
        name=manifest(self.source,NETWORK)[1][-1][0];(self.source/name).unlink();(self.source/name).symlink_to(self.key)
        with self.assertRaises((OSError,ValueError)):self.push()
        self.assertEqual((self.replica/'committed/manifest.json').read_bytes(),original)
    def test_cancellation_and_receiver_outage_never_acknowledge_success(self):
        stop=threading.Event();stop.set()
        with self.assertRaises(ValueError):replicate(self.source,**self.options,stop=stop)
        with self.assertRaises((urllib.error.URLError,OSError)):
            replicate(self.source,**dict(self.options,url='https://127.0.0.1:1'))
        self.assertFalse((self.replica/'committed/manifest.json').exists())

    def test_system_python_receiver_exits_when_launcher_inherits_blocked_sigterm(self):
        root=self.root/'masked-receiver';initialize(root,NETWORK,self.root/'masked.key')
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        def blocked():signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM})
        executable='/usr/bin/python3' if sys.platform=='darwin' else sys.executable
        output=self.root/'masked.stdout';error=self.root/'masked.stderr'
        with output.open('wb') as stdout,error.open('wb') as stderr:
            child=subprocess.Popen([executable,'-B',str(Path(__file__).with_name('history_replica.py')),'serve',
                '--root',str(root),'--port',str(port),'--cert',str(self.certs/'server.crt'),
                '--key',str(self.certs/'server.key'),'--duration','30'],preexec_fn=blocked,stdout=stdout,stderr=stderr)
        try:
            end=time.monotonic()+10
            while not output.stat().st_size:
                if child.poll() is not None or time.monotonic()>end:raise AssertionError(error.read_text())
                time.sleep(.05)
            child.terminate();self.assertEqual(child.wait(timeout=5),0,error.read_text())
            with socket.socket() as probe:
                probe.settimeout(.2);self.assertNotEqual(probe.connect_ex(('127.0.0.1',port)),0)
        finally:
            if child.poll() is None:child.kill();child.wait(timeout=5)


if __name__=='__main__':unittest.main()
