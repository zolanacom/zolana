import copy
import hashlib
from http.server import BaseHTTPRequestHandler
import io
import json
import os
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

from local_test_tls import create
import monitor_transport as transport
from monitor_transport import Client, Exporter, Inbox, Server, encode, digest, observation
from monitor_package import prepare
from offhost_monitor import Watch, clients, load_config
from operator_health import Publisher, atomic
from operator_monitor import Journal

DEPLOYMENT='a'*32
BINDING={'format':'native-monitor-route-v1','deployment':DEPLOYMENT,'source_origin':'https://127.0.0.1:1',
         'source_ca':'b'*64,'alert_origin':'https://127.0.0.1:2','alert_ca':'b'*64}


def write(path,value):
    path.write_bytes(value if isinstance(value,bytes) else encode(value));path.chmod(0o600)


def event(sequence=1):return {'id':'c'*32+':'+str(sequence),'sequence':sequence,'kind':'incident','code':'remote_unavailable','at':100.}


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs=tempfile.TemporaryDirectory();cls.tls=Path(cls.certs.name)/'tls';create(cls.tls)
        for path in cls.tls.iterdir():
            if path.is_file():path.chmod(0o600)
    @classmethod
    def tearDownClass(cls):cls.certs.cleanup()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.servers=[]
        self.addCleanup(self.temp.cleanup);self.addCleanup(self.shutdown)
        (self.root/'health').mkdir(mode=0o755)
        self.publisher=Publisher(self.root/'health/heartbeat.json',interval=100).start();self.addCleanup(self.publisher.close)
        self.publisher.observe(9,validator_count=2,ingress_ready=True);self.publisher.update('ready')
        self.job={'loaded':True,'pid':os.getpid()}
        self.exporter=Exporter(self.root/'health/heartbeat.json',os.getuid(),DEPLOYMENT,probe=lambda:self.job)
        self.inbox=Inbox(self.root/'inbox',DEPLOYMENT);self.addCleanup(lambda:self.inbox.close())
        self.keys={}
        for role,token in [('health-read','1'*64),('alert-write','2'*64)]:
            p=self.root/(role+'.json');write(p,dict(format='native-monitor-capability-v1',deployment=DEPLOYMENT,role=role,token=token));self.keys[role]=p
        self.health_server=self.listen(self.exporter,'health-read');self.alert_server=self.listen(self.inbox,'alert-write')
        self.source=self.client(self.health_server,'health-read');self.alerts=self.client(self.alert_server,'alert-write')
        self.journal=Journal(self.root/'journal',binding=BINDING);self.addCleanup(lambda:self.journal.close())
        self.watch=Watch(self.journal,self.source,self.alerts)

    def listen(self,app,role,cert='server.crt'):
        server=Server(('127.0.0.1',0),app,'','1'*64 if role=='health-read' else '2'*64,role,self.tls/cert,self.tls/'server.key' if cert=='expired.crt' else self.tls/(cert.replace('.crt','.key')))
        server.authority='127.0.0.1:'+str(server.server_port)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
        self.servers.append((server,thread));return server

    def client(self,server,role,**changes):
        options=dict(url='https://'+server.authority,ca_file=self.tls/'ca.crt',ca_sha256=hashlib.sha256((self.tls/'ca.crt').read_bytes()).hexdigest(),key_file=self.keys[role],deployment=DEPLOYMENT,role=role)
        options.update(changes);return Client(**options)

    def shutdown(self):
        for server,thread in self.servers:
            server.shutdown();server.server_close();thread.join(3)

    def stop(self,server):
        index=next(i for i,(s,_) in enumerate(self.servers) if s is server)
        s,t=self.servers.pop(index);s.shutdown();s.server_close();t.join(3)

    def test_challenged_tls_health_is_sanitized_and_replays_fail(self):
        result=self.source.health();self.assertEqual(result['health']['phase'],'ready')
        self.assertEqual(set(result['health']),set(self.publisher.data))
        for change in ({'deployment':'b'*32},{'challenge':'f'*64},{'observed_at':time.time()-11},{'extra':'CANARY_SECRET'}):
            bad=dict(result,**change)
            with self.assertRaises(ValueError):observation(bad,DEPLOYMENT,result['challenge'])
        self.assertNotIn('token',encode(result).decode());self.assertNotIn('wallet',encode(result).decode())

    def test_role_deployment_rpc_and_bad_credentials_are_rejected(self):
        for changes in [dict(key_file=self.keys['alert-write']),dict(deployment='b'*32)]:
            with self.assertRaises(ValueError):self.client(self.health_server,'health-read',**changes)
        rpc=self.root/'rpc.json';write(rpc,{'format':'native-rpc-unix-v1','token':'1'*64})
        with self.assertRaises(ValueError):self.client(self.health_server,'health-read',key_file=rpc)
        self.source.token='2'*64
        with self.assertRaises(ValueError):self.source.health()
        with self.assertRaises(ValueError):self.alerts.request('/v1/health',{})

    def test_endpoint_tls_pin_hostname_expiry_and_private_modes(self):
        for url in ['http://127.0.0.1:9','https://user:password@127.0.0.1:9','https://127.0.0.1:9/path','https://127.0.0.1:9?x=1','https://elsewhere.invalid','https://127.0.0.1:9?','https://127.0.0.1:\n9']:
            with self.assertRaises(ValueError):self.client(self.health_server,'health-read',url=url)
        with self.assertRaises(ValueError):self.client(self.health_server,'health-read',ca_sha256='0'*64)
        for cert in ('wrong-host.crt','expired.crt'):
            server=self.listen(self.exporter,'health-read',cert)
            with self.assertRaises(ssl.SSLError):self.client(server,'health-read').health()
        self.keys['health-read'].chmod(0o644)
        with self.assertRaises(ValueError):self.client(self.health_server,'health-read')

    def test_redirect_is_not_followed_or_sent_credentials(self):
        with socket.socket() as trap:
            trap.bind(('127.0.0.1',0));trap.listen();trap.settimeout(.1)
            target='https://127.0.0.1:'+str(trap.getsockname()[1])
            class Redirect(BaseHTTPRequestHandler):
                def log_message(self,*_):pass
                def do_POST(self):
                    self.send_response(307);self.send_header('Location',target);self.send_header('Content-Length','0');self.end_headers()
            self.health_server.RequestHandlerClass=Redirect
            with self.assertRaises(ValueError):self.source.health()
            with self.assertRaises(socket.timeout):trap.accept()

    def test_host_loss_after_intentional_pause_still_alerts(self):
        self.job={'loaded':False,'pid':None};self.assertEqual(self.watch.sample()['state'],'paused')
        self.stop(self.health_server)
        self.assertEqual(self.watch.sample()['code'],'remote_unavailable');self.watch.deliver(0)
        self.assertEqual(len(self.inbox.state['events']),1)
        self.health_server=self.listen(self.exporter,'health-read');self.watch.source=self.client(self.health_server,'health-read')
        self.assertEqual(self.watch.sample()['state'],'paused');self.watch.deliver(10)
        self.assertEqual([e['kind'] for e in self.inbox.state['events']],['incident','operator_paused'])

    def test_expected_running_deployment_does_not_silence_unloaded_service(self):
        self.watch.expect_running=True;self.job={'loaded':False,'pid':None}
        self.assertEqual(self.watch.sample()['code'],'service_paused')
        self.watch.deliver(0);self.assertEqual(self.inbox.state['events'][0]['code'],'service_paused')

    def test_fresh_tls_heartbeat_cannot_hide_stalled_finality(self):
        self.watch.monitor.finality=.1;self.assertEqual(self.watch.sample()['state'],'healthy')
        time.sleep(.12);self.publisher.observe(9)
        self.assertEqual(self.watch.sample()['code'],'finality_stalled')

    def test_delivery_outage_keeps_sampling_and_recovery_queued_in_order(self):
        self.stop(self.alert_server);self.stop(self.health_server)
        self.watch.sample();self.watch.deliver(0);self.assertEqual(self.watch.delivery,'retrying')
        self.health_server=self.listen(self.exporter,'health-read');self.watch.source=self.client(self.health_server,'health-read')
        self.assertEqual(self.watch.sample()['state'],'healthy');self.watch.deliver(1)
        self.assertEqual([e['kind'] for e in self.journal.state['events']],['incident','recovered'])
        self.assertTrue(all(not e['delivered'] for e in self.journal.state['events']))
        self.alert_server=self.listen(self.inbox,'alert-write');self.watch.alerts=self.client(self.alert_server,'alert-write')
        self.watch.deliver(40);self.watch.deliver(41)
        self.assertEqual([e['kind'] for e in self.inbox.state['events']],['incident','recovered'])
        self.assertTrue(all(e['delivered'] for e in self.journal.state['events']))

    def test_lost_ack_retry_has_same_id_and_one_durable_record(self):
        def hook(phase,_):
            if phase=='after_commit':raise OSError('lost acknowledgement')
        self.inbox.hook=hook
        self.journal.event('incident','remote_unavailable',time.time());self.journal.save()
        self.watch.deliver(0);self.assertEqual(self.watch.delivery,'retrying')
        self.assertFalse(self.journal.state['events'][0]['delivered']);self.assertEqual(len(self.inbox.state['events']),1)
        self.watch.deliver(3);self.assertTrue(self.journal.state['events'][0]['delivered'])
        self.assertEqual(len(self.inbox.state['events']),1)

    def test_changed_retry_and_unverified_receipts_cannot_ack_pending(self):
        original=event();self.alerts.alert(original)
        with self.assertRaises(ValueError):self.alerts.alert(dict(original,code='remote_invalid'))
        # Python equates 100 with 100.0, but their canonical event hashes differ.
        with self.assertRaises(ValueError):self.alerts.alert(dict(original,at=100))
        self.assertEqual(self.inbox.state['events'],[original])
        self.journal.event('incident','remote_unavailable',100);self.journal.save()
        for receipt in ({'id':'wrong','sha256':'0'*64,'durable':True},{'id':event()['id'],'sha256':digest(event()),'durable':False},
                        {'id':self.journal.state['events'][0]['id'],'sha256':digest({k:v for k,v in self.journal.state['events'][0].items() if k!='delivered'}),'durable':1}):
            with self.assertRaises(ValueError):self.journal.deliver_remote(lambda _:receipt)
            self.assertFalse(self.journal.state['events'][0]['delivered'])

    def test_remote_route_persists_and_stdout_cannot_ack_it(self):
        self.journal.event('incident','remote_unavailable',100);self.journal.save()
        with self.assertRaises(ValueError):self.journal.deliver(io.StringIO())
        self.journal.close()
        for route in (None,dict(BINDING,alert_origin='https://changed.invalid')):
            with self.assertRaises(ValueError):Journal(self.root/'journal',binding=route)
        self.journal=Journal(self.root/'journal',binding=BINDING)
        self.assertFalse(self.journal.state['events'][0]['delivered'])

    def test_inbox_restart_deduplicates_and_corruption_or_missing_state_never_reset(self):
        self.alerts.alert(event());self.stop(self.alert_server);self.inbox.close()
        self.inbox=Inbox(self.root/'inbox',DEPLOYMENT)
        self.assertEqual(self.inbox.handle({'format':'native-monitor-alert-v1','deployment':DEPLOYMENT,'event':event()})['id'],event()['id'])
        self.assertEqual(len(self.inbox.state['events']),1);self.inbox.close()
        path=self.root/'inbox/inbox.json';raw=path.read_bytes();write(path,b'{corrupt')
        with self.assertRaises(ValueError):Inbox(self.root/'inbox',DEPLOYMENT)
        self.assertEqual(path.read_bytes(),b'{corrupt');path.unlink()
        with self.assertRaises(FileNotFoundError):Inbox(self.root/'inbox',DEPLOYMENT)
        write(path,raw);self.inbox=Inbox(self.root/'inbox',DEPLOYMENT)

    def test_uncertain_directory_fsync_poisoned_receiver_preserves_commit_on_restart(self):
        original=transport.atomic
        def uncertain(path,data,mode):original(path,data,mode);raise OSError('dirsync failed after replace')
        with patch.object(transport,'atomic',side_effect=uncertain):
            with self.assertRaises(OSError):self.inbox.handle({'format':'native-monitor-alert-v1','deployment':DEPLOYMENT,'event':event()})
        with self.assertRaises(RuntimeError):self.inbox.handle({'format':'native-monitor-alert-v1','deployment':DEPLOYMENT,'event':event(2)})
        self.stop(self.alert_server);self.inbox.close();self.inbox=Inbox(self.root/'inbox',DEPLOYMENT)
        self.assertEqual(self.inbox.state['events'],[event()])

    def test_inbox_lock_capacity_and_changed_deployment(self):
        with self.assertRaises(BlockingIOError):Inbox(self.root/'inbox',DEPLOYMENT)
        self.inbox.state['events']=[event(i) for i in range(1,1025)]
        with self.assertRaises(ValueError):self.inbox.handle({'format':'native-monitor-alert-v1','deployment':DEPLOYMENT,'event':event(1025)})
        self.assertEqual(self.inbox.handle({'format':'native-monitor-alert-v1','deployment':DEPLOYMENT,'event':event()})['id'],event()['id'])

    def test_payload_privacy_bounds_and_invalid_source_are_static(self):
        bad=dict(event(),wallet='CANARY_SECRET')
        with self.assertRaises(ValueError):self.alerts.alert(bad)
        self.exporter.probe=lambda:(_ for _ in ()).throw(OSError('CANARY_SECRET'))
        value=self.source.health();self.assertEqual(value['error'],'monitor_probe_failed');self.assertNotIn('CANARY',encode(value).decode())
        self.assertEqual(self.watch.sample()['code'],'monitor_probe_failed')

    def test_missing_and_corrupt_loaded_heartbeat_do_not_become_intentional_pause(self):
        self.watch.monitor.grace=0
        self.publisher.path.unlink();self.assertEqual(self.watch.sample()['code'],'heartbeat_missing')
        write(self.publisher.path,b'{CANARY_SECRET');self.publisher.path.chmod(0o644)
        self.assertEqual(self.watch.sample()['code'],'heartbeat_invalid')
        self.assertNotIn('CANARY',(self.root/'journal/state.json').read_text())

    def test_duplicate_json_and_wrong_deployment_are_rejected_without_storage(self):
        with self.assertRaises(ValueError):transport.decode(b'{"event":1,"event":2}')
        with self.assertRaises(ValueError):self.alerts.request('/v1/alerts',{'format':'native-monitor-alert-v1','deployment':'b'*32,'event':event()})
        self.assertEqual(self.inbox.state['events'],[])

    def test_explicit_running_policy_private_config_and_separate_tokens(self):
        peer=lambda server,role:dict(origin='https://'+server.authority,capability_file=str(self.keys[role]),ca_file=str(self.tls/'ca.crt'),ca_sha256=hashlib.sha256((self.tls/'ca.crt').read_bytes()).hexdigest())
        config=dict(format='native-offhost-monitor-v1',deployment=DEPLOYMENT,source=peer(self.health_server,'health-read'),alerts=peer(self.alert_server,'alert-write'),journal='new-journal',interval_seconds=1,expect_running=True)
        path=self.root/'watch.json';write(path,config)
        loaded=load_config(path,False);self.assertTrue(loaded['expect_running']);self.assertEqual(len(clients(loaded,False)),2)
        config['expect_running']=1;write(path,config)
        with self.assertRaises(ValueError):load_config(path,False)
        config['expect_running']=True;write(path,config);path.chmod(0o644)
        with self.assertRaises(ValueError):load_config(path,False)
        key=transport.decode(self.keys['alert-write'].read_bytes());key['token']='1'*64;write(self.keys['alert-write'],key)
        with self.assertRaises(ValueError):clients(loaded,False)

    def test_slow_trickle_cannot_extend_absolute_socket_deadline(self):
        class Trickle(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                self.send_response(200);self.send_header('Content-Length','100');self.send_header('Content-Type','application/json');self.end_headers()
                try:
                    for _ in range(100):self.wfile.write(b' ');self.wfile.flush();time.sleep(.04)
                except OSError:pass
        self.health_server.RequestHandlerClass=Trickle;self.source.timeout=.2
        start=time.monotonic()
        with self.assertRaises((OSError,ValueError)):self.source.health()
        self.assertLess(time.monotonic()-start,1)


class PackageTests(unittest.TestCase):
    def test_reproducible_secret_free_package_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'a').mkdir();(root/'b').mkdir()
            a=prepare(root/'a/monitor');b=prepare(root/'b/monitor')
            self.assertEqual(a['manifest_sha256'],b['manifest_sha256']);self.assertEqual(a['archive_sha256'],b['archive_sha256'])
            package=Path(a['bundle']);self.assertFalse(any(p.suffix=='.key' for p in package.iterdir()))
            self.assertEqual((package/'LICENSE').read_bytes(),Path(__file__).parents[1].joinpath('LICENSE').read_bytes())
            key=root/'scoped.json'
            command=[sys.executable,'-I',str(package/'run.py'),'keygen','--deployment',DEPLOYMENT,'--role','health-read','--output',str(key)]
            self.assertEqual(subprocess.run(command,capture_output=True,timeout=5).returncode,0)
            token=json.loads(key.read_bytes())['token'];self.assertNotIn(token,Path(a['archive']).read_bytes().decode('latin1'))
            self.assertNotEqual(subprocess.run(command,capture_output=True,timeout=5).returncode,0)
            code=package/'offhost_monitor.py';code.chmod(0o644);code.write_text('raise Exception("UNVERIFIED_CODE_EXECUTED")')
            result=subprocess.run(command,capture_output=True,text=True,timeout=5)
            self.assertNotEqual(result.returncode,0);self.assertNotIn('UNVERIFIED_CODE_EXECUTED',result.stderr)
            with self.assertRaises(ValueError):prepare(package)


if __name__=='__main__':unittest.main()
