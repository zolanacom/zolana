import copy
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import human_paging as paging
from human_paging import PageFailure, Provider, Relay, retry_after
from local_test_tls import create
from monitor_transport import Inbox, Server, decode, encode
from operator_health import atomic

DEPLOYMENT='a'*32
ROUTING='f'*32


def event(seq=1,kind='incident',code='remote_unavailable',stream='c'*32):
    return {'id':stream+':'+str(seq),'sequence':seq,'kind':kind,'code':code,'at':100.}


class MockPager:
    """Test-only provider model. Never shipped in the standalone bundle."""
    def __init__(self,root,routing=ROUTING):
        self.root=Path(root);self.routing=routing;self.lock=threading.Lock()
        self.root.mkdir(mode=0o700,exist_ok=True)
        self.policy=self.root/'policy.json';self.path=self.root/'provider.json'
        if not self.policy.exists():atomic(self.policy,{'status':202},0o600)
        if not self.path.exists():atomic(self.path,{'requests':0,'records':[],'active':{},'pages_created':0,'resolutions':0},0o600)

    def handle(self,payload):
        with self.lock:
            policy=json.loads(self.policy.read_text());state=json.loads(self.path.read_text())
            state['requests']+=1;atomic(self.path,state,0o600)
            if payload.get('routing_key')!=self.routing:return 403,{'error':'wrong-key'},policy
            status=policy['status']
            if status!=202:return status,{'error':'CANARY_PROVIDER_BODY'},policy
            if policy.get('crash')=='before_accept':os.kill(os.getpid(),9)
            action=payload['event_action'];key=payload['dedup_key']
            if action=='trigger':
                if key not in state['active']:state['pages_created']+=1
                state['active'][key]=payload['payload']['summary']
            elif action=='resolve':
                if key in state['active']:state['resolutions']+=1;state['active'].pop(key)
            else:raise ValueError('adapter must not acknowledge as a human')
            record={k:v for k,v in payload.items() if k!='routing_key'}
            state['records'].append(record);atomic(self.path,state,0o600)
            if policy.get('crash')=='after_accept':os.kill(os.getpid(),9)
            if policy.get('disconnect'):raise OSError('test lost acknowledgement')
            body={'status':'success','message':'Event processed','dedup_key':key}
            if policy.get('bad_ack'):body['dedup_key']='wrong'
            return 202,body,policy


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_POST(self):
        if self.path!='/v2/enqueue' or self.headers.get('Host')!=self.server.authority:return
        length=int(self.headers.get('Content-Length','0'))
        if not 0<length<=8192:return
        try:status,body,policy=self.server.app.handle(decode(self.rfile.read(length)))
        except OSError:return
        raw=encode(body);self.send_response(status);self.send_header('Content-Type','application/json')
        if 'retry_after' in policy:self.send_header('Retry-After',policy['retry_after'])
        if policy.get('redirect'):self.send_header('Location',policy['redirect'])
        if policy.get('chunked'):
            self.send_header('Transfer-Encoding','chunked');self.end_headers();self.wfile.write(('%x\r\n'%len(raw)).encode()+raw+b'\r\n0\r\n\r\n')
        else:self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)


class PagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs=tempfile.TemporaryDirectory();cls.tls=Path(cls.certs.name)/'tls';create(cls.tls)
        for path in cls.tls.iterdir():
            if path.is_file():path.chmod(0o600)
    @classmethod
    def tearDownClass(cls):cls.certs.cleanup()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.addCleanup(self.temp.cleanup)
        self.inbox=Inbox(self.root/'inbox',DEPLOYMENT);self.addCleanup(self.inbox.close)
        self.mock=MockPager(self.root/'mock');self.server=self.listen()
        self.key=self.root/'pager-key.json';atomic(self.key,{'format':'native-pagerduty-key-v1','deployment':DEPLOYMENT,'routing_key':ROUTING},0o600)
        self.pin=hashlib.sha256((self.tls/'ca.crt').read_bytes()).hexdigest()
        self.url='https://'+self.server.authority+'/v2/enqueue'
        self.provider=self.client();self.route={'provider':self.url,'key_sha256':hashlib.sha256(ROUTING.encode()).hexdigest()}
        self.relay=Relay(self.root/'relay',self.root/'inbox',DEPLOYMENT,self.route,self.provider)
        self.addCleanup(lambda:self.relay.close())
    def listen(self,cert='server.crt',key='server.key'):
        server=Server(('127.0.0.1',0),self.mock,'','unused','mock-pager',self.tls/cert,self.tls/key)
        server.authority='127.0.0.1:'+str(server.server_port);server.RequestHandlerClass=MockHandler
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
        def close():server.shutdown();server.server_close();thread.join(3)
        self.addCleanup(close);return server
    def client(self,**changes):
        args=dict(url=self.url,ca_file=self.tls/'ca.crt',ca_sha256=self.pin,key_file=self.key,deployment=DEPLOYMENT)
        args.update(changes);return Provider(**args)
    def add(self,e):self.inbox.handle({'format':'native-monitor-alert-v1','deployment':DEPLOYMENT,'event':e})
    def policy(self,**kwargs):atomic(self.mock.policy,dict(status=202,**kwargs),0o600)
    def model(self):return json.loads(self.mock.path.read_text())
    def restart(self):
        self.relay.close();self.relay=Relay(self.root/'relay',self.root/'inbox',DEPLOYMENT,self.route,self.provider)

    def test_fault_updates_share_key_recovery_resolves_and_new_cycle_has_new_key(self):
        for e in (event(),event(2,code='heartbeat_stale'),event(3,'recovered'),event(4)):
            self.add(e);self.assertEqual(self.relay.step(100+e['sequence'])['phase'],'accepted')
        records=self.model()['records'];self.assertEqual([r['event_action'] for r in records],['trigger','trigger','resolve','trigger'])
        self.assertEqual(len({r['dedup_key'] for r in records[:3]}),1);self.assertNotEqual(records[0]['dedup_key'],records[3]['dedup_key'])
        self.assertEqual(self.model()['pages_created'],2);self.assertEqual(self.model()['resolutions'],1)

    def test_separate_observer_streams_do_not_resolve_each_other(self):
        for e in (event(),event(stream='d'*32),event(2,'operator_paused')):self.add(e);self.relay.step(100)
        self.assertEqual(len(self.model()['active']),1);self.assertEqual(len(self.relay.state['active']),1)

    def test_outage_backoff_and_pending_id_survive_restart(self):
        atomic(self.mock.policy,{'status':503},0o600);self.add(event())
        self.assertEqual(self.relay.step(100)['phase'],'retrying');pending=copy.deepcopy(self.relay.state['pending']);self.restart()
        self.assertEqual(self.relay.step(101)['phase'],'waiting');self.assertEqual(self.model()['requests'],1)
        self.policy();self.assertEqual(self.relay.step(102)['phase'],'accepted')
        self.assertEqual(self.model()['records'][0]['dedup_key'],pending['plan']['dedup_key'])

    def test_lost_acceptance_retry_has_one_open_page_after_restart(self):
        self.policy(disconnect=True);self.add(event())
        self.assertEqual(self.relay.step(100)['phase'],'retrying');self.assertEqual(self.model()['pages_created'],1)
        self.restart();self.policy();self.relay.step(102)
        self.assertEqual(self.model()['pages_created'],1);self.assertEqual(len(self.model()['records']),2)
        self.assertEqual(self.relay.state['cursor'],1)

    def test_rate_limit_not_before_is_persisted_and_retry_after_dates_work(self):
        atomic(self.mock.policy,{'status':429,'retry_after':'60'},0o600);self.add(event());self.relay.step(100);self.restart()
        self.assertEqual(self.relay.step(159)['phase'],'waiting');self.assertEqual(self.model()['requests'],1)
        self.policy();self.relay.step(160);self.assertEqual(self.relay.state['cursor'],1)
        self.assertEqual(retry_after('Thu, 01 Jan 1970 00:03:00 GMT',100),180)
        self.assertIsNone(retry_after('not-a-date',100));self.assertEqual(retry_after('999999999',100),86500)

    def test_rejected_key_blocks_without_dropping_or_stopping_inbox_ingestion(self):
        atomic(self.mock.policy,{'status':403},0o600);self.add(event());self.assertEqual(self.relay.step(100)['phase'],'blocked')
        self.add(event(2,code='remote_invalid'));self.restart();self.policy()
        self.assertEqual(self.relay.step(500)['phase'],'blocked');self.assertEqual(self.model()['requests'],1)
        self.assertEqual(len(self.inbox.state['events']),2);self.assertEqual(self.relay.state['cursor'],0)
        original=self.relay.state['pending']['plan'].copy();self.assertEqual(self.relay.retry_blocked(501)['phase'],'retry_armed')
        self.assertEqual(self.model()['requests'],1);self.restart();self.relay.step(501)
        self.assertEqual(self.relay.state['receipts'][0]['plan'],original);self.assertEqual(self.relay.state['cursor'],1)

    def test_invalid_provider_acceptance_never_advances_local_cursor(self):
        self.policy(bad_ack=True);self.add(event());self.relay.step(100)
        self.assertEqual(self.relay.state['cursor'],0);self.assertEqual(self.relay.state['pending']['failure'],'provider_response_invalid')
        self.policy();self.relay.step(102);self.assertEqual(self.model()['pages_created'],1)

    def test_chunked_acceptance_supported_and_no_secret_in_state_or_payload_details(self):
        self.policy(chunked=True);self.add(event());status=self.relay.step(100)
        self.assertEqual(status['phase'],'accepted');self.assertFalse(status['human_receipt_verified'])
        self.assertNotIn(ROUTING,(self.root/'relay/state.json').read_text());self.assertNotIn(ROUTING,self.mock.path.read_text())
        self.assertEqual(set(self.model()['records'][0]['payload']['custom_details']),{'event_id','code','kind'})

    def test_orphan_resolution_is_recorded_without_creating_a_page(self):
        self.add(event(2,'operator_paused'));self.assertEqual(self.relay.step(100)['phase'],'no_active_page')
        self.assertEqual(self.model()['requests'],0);self.assertEqual(self.relay.state['receipts'][0]['outcome'],'no_active_page')

    def test_source_canonical_prefix_change_or_reorder_stops_before_next_send(self):
        self.add(event());self.relay.step(100)
        value=json.loads((self.root/'inbox/inbox.json').read_text());value['events'][0]['at']=100
        atomic(self.root/'inbox/inbox.json',value,0o600)
        with self.assertRaises(ValueError):self.relay.step(101)
        self.assertEqual(self.model()['requests'],1)

    def test_corrupt_deleted_initialized_state_and_changed_route_cannot_reset(self):
        self.add(event());self.relay.step(100);self.relay.close();path=self.root/'relay/state.json';raw=path.read_bytes()
        atomic(path,{'corrupt':True},0o600)
        with self.assertRaises(ValueError):Relay(self.root/'relay',self.root/'inbox',DEPLOYMENT,self.route,self.provider)
        path.unlink()
        with self.assertRaises(FileNotFoundError):Relay(self.root/'relay',self.root/'inbox',DEPLOYMENT,self.route,self.provider)
        path.write_bytes(raw);path.chmod(0o600)
        with self.assertRaises(ValueError):Relay(self.root/'relay',self.root/'inbox',DEPLOYMENT,dict(self.route,provider='changed'),self.provider)
        self.relay=Relay(self.root/'relay',self.root/'inbox',DEPLOYMENT,self.route,self.provider)

    def test_uncertain_state_commit_poisoned_relay_requires_restart(self):
        self.add(event());original=paging.atomic
        def uncertain(path,data,mode):original(path,data,mode);raise OSError('uncertain dirsync')
        with patch.object(paging,'atomic',side_effect=uncertain):
            with self.assertRaises(OSError):self.relay.step(100)
        with self.assertRaises(ValueError):self.relay.step(101)
        self.restart();self.assertEqual(self.relay.step(102)['phase'],'accepted')

    def uncertain_acceptance(self,committed):
        self.add(event());original=paging.atomic;count=[0]
        def fault(path,data,mode):
            count[0]+=1
            if count[0]==3:
                if committed:original(path,data,mode)
                raise OSError('acceptance persistence uncertain')
            return original(path,data,mode)
        with patch.object(paging,'atomic',side_effect=fault):
            with self.assertRaises(OSError):self.relay.step(100)
        self.assertEqual(self.model()['pages_created'],1)
        with self.assertRaises(ValueError):self.relay.step(101)
        self.restart();self.relay.step(102)
        self.assertEqual(self.relay.state['cursor'],1);self.assertEqual(self.model()['pages_created'],1)
        self.assertEqual(self.model()['requests'],1 if committed else 2)

    def test_uncertain_acceptance_with_old_cursor_retries_original_key(self):
        self.uncertain_acceptance(False)

    def test_uncertain_acceptance_with_new_cursor_does_not_resend(self):
        self.uncertain_acceptance(True)

    def test_active_incident_capacity_fails_before_sending_extra_page(self):
        from types import SimpleNamespace
        sent=[]
        def send(event,action,key,now):sent.append(key);return {'accepted':True,'dedup_key':key}
        self.relay.provider=SimpleNamespace(send=send)
        for number in range(128):
            self.add(event(stream='%032x'%number));self.relay.step(100)
        self.add(event(stream='%032x'%128))
        with self.assertRaisesRegex(ValueError,'capacity'):self.relay.step(101)
        self.assertEqual(len(sent),128);self.assertEqual(self.relay.state['cursor'],128)

    def test_process_lock_overlap_and_clock_rollback_fail_visibly(self):
        with self.assertRaises(BlockingIOError):Relay(self.root/'relay',self.root/'inbox',DEPLOYMENT,self.route,self.provider)
        self.add(event());self.relay.step(100);self.restart()
        with self.assertRaises(ValueError):self.relay.step(90)
        with self.assertRaises(ValueError):Relay(self.root/'inbox'/'nested',self.root/'inbox',DEPLOYMENT,self.route,self.provider)

    def test_wrong_role_credentials_origin_downgrade_and_ca_pin_fail(self):
        for changes in (dict(url='http://127.0.0.1/v2/enqueue'),dict(url='https://127.0.0.1/v2/enqueue?x'),dict(url='https://events.pagerduty.com/v2/enqueue'),dict(url='https://evil.invalid/v2/enqueue',allow_network=True),dict(ca_sha256='0'*64)):
            with self.assertRaises(ValueError):self.client(**changes)
        atomic(self.key,{'format':'native-monitor-capability-v1','deployment':DEPLOYMENT,'role':'alert-write','token':'b'*64},0o600)
        with self.assertRaises(ValueError):self.client()

    def test_wrong_hostname_and_expired_tls_never_send_routing_key(self):
        for cert,key in (('wrong-host.crt','wrong-host.key'),('expired.crt','server.key')):
            server=self.listen(cert,key);client=self.client(url='https://'+server.authority+'/v2/enqueue')
            with self.assertRaises(PageFailure):client.send(event(),'trigger','nativepay:'+'a'*64,100)
        self.assertEqual(self.model()['requests'],0)

    def test_redirect_is_never_followed(self):
        with socket.socket() as trap:
            trap.bind(('127.0.0.1',0));trap.listen();trap.settimeout(.1)
            atomic(self.mock.policy,{'status':302,'redirect':'https://127.0.0.1:'+str(trap.getsockname()[1])+'/secret-trap'},0o600)
            self.add(event());self.assertEqual(self.relay.step(100)['phase'],'retrying')
            with self.assertRaises(socket.timeout):trap.accept()


if __name__=='__main__':unittest.main()
