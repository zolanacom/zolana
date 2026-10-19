import copy
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from human_paging import PageFailure
from local_test_tls import create
from monitor_transport import Server,encode
from operator_health import atomic
from operator_monitor import Journal
from watchdog_monitor import Agent,AgentClient,Context,Detector,observation
from watchdog_notify import Telegram
from watchdog_progress import Progress

DEPLOYMENT='a'*32
PRIMARY='b'*64
BOT='123456:'+'d'*32
CHAT=-123456789


class MockTelegram:
    """Test-only Telegram API model, deliberately without send idempotency."""
    def __init__(self,root,token=BOT,chat=CHAT):
        self.root=Path(root);self.root.mkdir(mode=0o700,exist_ok=True);self.token=token;self.chat=chat;self.lock=threading.Lock()
        self.policy=self.root/'policy.json';self.path=self.root/'messages.json'
        if not self.policy.exists():atomic(self.policy,{'status':200},0o600)
        if not self.path.exists():atomic(self.path,{'requests':0,'messages':[]},0o600)
    def handle(self,path,payload):
        with self.lock:
            policy=json.loads(self.policy.read_text());state=json.loads(self.path.read_text());state['requests']+=1;atomic(self.path,state,0o600)
            if path!='/bot'+self.token+'/sendMessage' or payload['chat_id']!=self.chat:return 403,{'ok':False},policy
            if policy['status']==429:return 429,{'ok':False,'parameters':{'retry_after':policy.get('retry_after',2)}},policy
            if policy['status']!=200:return policy['status'],{'ok':False,'description':'CANARY_PRIVATE_ERROR'},policy
            if policy.get('crash')=='before_accept':os.kill(os.getpid(),9)
            state['messages'].append({'text':payload['text']});atomic(self.path,state,0o600)
            if policy.get('crash')=='after_accept':os.kill(os.getpid(),9)
            if policy.get('disconnect'):raise OSError('mock lost acknowledgement')
            result={'message_id':len(state['messages']),'chat':{'id':self.chat if not policy.get('wrong_chat') else 9876},'text':payload['text']}
            return 200,{'ok':True if not policy.get('bad_ok') else 1,'result':result},policy


class TelegramHandler(BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_POST(self):
        if self.headers.get('Host')!=self.server.authority:return
        length=int(self.headers.get('Content-Length','0'))
        if not 0<length<=8192:return
        try:status,value,policy=self.server.app.handle(self.path,json.loads(self.rfile.read(length)))
        except OSError:return
        raw=encode(value);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)))
        if policy.get('redirect'):self.send_header('Location',policy['redirect'])
        self.end_headers();self.wfile.write(raw)


class WatchdogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_certs=tempfile.TemporaryDirectory();cls.tls=Path(cls.temp_certs.name)/'tls';create(cls.tls)
        for p in cls.tls.iterdir():
            if p.is_file():p.chmod(0o600)
    @classmethod
    def tearDownClass(cls):cls.temp_certs.cleanup()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.addCleanup(self.temp.cleanup);self.servers=[];self.addCleanup(self.shutdown)
        self.now=100.
        for role in ('monitor','pager'):(self.root/role).mkdir(mode=0o700)
        self.monitor=Progress(self.root/'monitor',DEPLOYMENT,'monitor',clock=lambda:self.now)
        self.pager=Progress(self.root/'pager',DEPLOYMENT,'pager',PRIMARY,clock=lambda:self.now)
        self.monitor.complete();self.pager.complete()
        self.targets={role:{'pulse_file':str(self.root/role/'watchdog.json'),'owner':os.getuid()} for role in ('monitor','pager')}
        self.agent=Agent(DEPLOYMENT,self.targets);self.agent_server=self.listen(self.agent,'watchdog-read','1'*64)
        self.key=self.root/'watchdog-key.json';atomic(self.key,dict(format='native-monitor-capability-v1',deployment=DEPLOYMENT,role='watchdog-read',token='1'*64),0o600)
        self.pin=hashlib.sha256((self.tls/'ca.crt').read_bytes()).hexdigest()
        self.client=AgentClient('https://'+self.agent_server.authority,self.tls/'ca.crt',self.pin,self.key,DEPLOYMENT,'watchdog-read')
        self.journal=Journal(self.root/'journal',binding={'purpose':'watchdog-test'});self.addCleanup(lambda:self.journal.close())
        self.detector=Detector(self.journal,self.client,PRIMARY)
        self.telegram_key=self.root/'telegram.json';atomic(self.telegram_key,dict(format='native-watchdog-telegram-key-v1',deployment=DEPLOYMENT,bot_token=BOT,chat_id=CHAT),0o600)
        self.mock=MockTelegram(self.root/'telegram-mock');self.telegram_server=self.listen(self.mock,'mock','unused',TelegramHandler)
        self.telegram=Telegram('https://'+self.telegram_server.authority,self.tls/'ca.crt',self.pin,self.telegram_key,DEPLOYMENT)
    def listen(self,app,role,token,handler=None):
        server=Server(('127.0.0.1',0),app,'',token,role,self.tls/'server.crt',self.tls/'server.key');server.authority='127.0.0.1:'+str(server.server_port)
        if handler:server.RequestHandlerClass=handler
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start();self.servers.append((server,thread));return server
    def stop(self,server):
        index=next(i for i,(s,_) in enumerate(self.servers) if s is server);s,t=self.servers.pop(index);s.shutdown();s.server_close();t.join(3)
    def shutdown(self):
        for server,thread in self.servers:server.shutdown();server.server_close();thread.join(3)
    def sample(self):return self.detector.sample(self.now)
    def policy(self,**items):atomic(self.mock.policy,items,0o600)
    def event(self):return {'id':'c'*32+':1','sequence':1,'kind':'incident','code':'watchdog_unavailable','at':100}
    def context(self):
        self.now=time.time();self.monitor.complete();self.pager.complete()
        c=dict(format='native-independent-watchdog-v1',deployment=DEPLOYMENT,root=str(self.root/'independent'),primary_integration_sha256=PRIMARY,
            agent=dict(origin='https://'+self.agent_server.authority,ca_file=str(self.tls/'ca.crt'),ca_sha256=self.pin,capability_file=str(self.key)),
            provider=dict(origin='https://'+self.telegram_server.authority,ca_file=str(self.tls/'ca.crt'),ca_sha256=self.pin,key_file=str(self.telegram_key)),
            interval_seconds=1,stale_seconds=3,backlog_seconds=3,startup_seconds=3)
        return Context(c)

    def test_completed_cycles_are_sanitized_and_separate_from_process_liveness(self):
        data=self.client.observe();self.assertEqual(data['targets']['monitor']['progress']['phase'],'running');self.assertEqual(self.sample()['state'],'healthy')
        self.now=116;self.pager.complete()
        self.assertEqual(self.sample()['code'],'monitor_stale')
        self.assertNotIn(BOT,encode(data).decode());self.assertNotIn('pulse_file',encode(data).decode())

    def test_cli_all_notification_roles_enforce_local_limits_before_config_or_dispatch(self):
        from offhost_monitor import main
        for role in ('page','page-retry','watchdog-agent','watchdog','watchdog-retry'):
            for duration in ('0','601','-1'):
                with self.subTest(role=role,duration=duration),patch('sys.argv',['monitor',role,'--config','nonexistent.json','--duration',duration]):
                    with self.assertRaisesRegex(ValueError,'finite 1–600'):main()
            with self.subTest(role=role,external_bind=True),patch('sys.argv',['monitor',role,'--config','nonexistent.json','--bind','0.0.0.0']):
                with self.assertRaisesRegex(ValueError,'external bind'):main()

    def test_new_starting_instance_does_not_resolve_incident_until_completed_work(self):
        self.sample();self.now=116;self.pager.complete();self.sample()
        self.monitor=Progress(self.root/'monitor',DEPLOYMENT,'monitor',clock=lambda:self.now)
        self.assertEqual(self.sample()['state'],'starting');self.assertIsNotNone(self.journal.state['incident'])
        self.monitor.complete();self.assertEqual(self.sample()['state'],'healthy');self.assertIsNone(self.journal.state['incident'])

    def test_repeated_restarts_do_not_extend_startup_grace(self):
        self.monitor=Progress(self.root/'monitor',DEPLOYMENT,'monitor',clock=lambda:self.now);self.sample()
        self.now=130;self.pager.complete();self.monitor=Progress(self.root/'monitor',DEPLOYMENT,'monitor',clock=lambda:self.now);self.sample()
        self.now=161;self.pager.complete();self.monitor=Progress(self.root/'monitor',DEPLOYMENT,'monitor',clock=lambda:self.now)
        self.assertEqual(self.sample()['code'],'monitor_startup_stalled')

    def test_fresh_role_loop_with_blocked_or_old_delivery_still_alerts(self):
        self.pager.complete(1,100,'delivery_blocked');self.assertEqual(self.sample()['code'],'pager_blocked')
        self.now=161;self.monitor.complete();self.pager.complete(1,100,'delivery_retrying')
        self.assertEqual(self.sample()['code'],'pager_backlog')
        self.pager.complete();self.monitor.complete(1,100,'delivery_retrying');self.assertEqual(self.sample()['code'],'monitor_backlog')

    def test_sequence_replay_or_rollback_cannot_fake_progress(self):
        self.sample();pulse=copy.deepcopy(self.monitor.value);self.now=116;self.pager.complete()
        pulse['completed_at']=self.now;atomic(self.monitor.path,pulse,0o600)
        self.assertEqual(self.sample()['code'],'monitor_stale')
        pulse['sequence']=1;atomic(self.monitor.path,pulse,0o600)
        self.assertEqual(self.sample()['code'],'monitor_invalid')

    def test_missing_invalid_private_status_and_integration_mismatch_are_visible(self):
        self.monitor.path.unlink();self.assertEqual(self.sample()['code'],'monitor_missing')
        self.monitor.write();self.monitor.path.chmod(0o644);self.assertEqual(self.sample()['code'],'monitor_invalid')
        self.monitor.path.chmod(0o600);self.pager.value['integration_sha256']='f'*64;self.pager.write()
        self.assertEqual(self.sample()['code'],'pager_invalid')

    def test_stopped_role_is_an_incident_and_clock_rollback_is_not_recovery(self):
        self.monitor.close();self.assertEqual(self.sample()['code'],'monitor_stopped')
        self.now=90;self.assertEqual(self.sample()['code'],'watchdog_invalid')

    def test_watchdog_restart_keeps_progress_deadline_and_incident(self):
        self.sample();self.now=116;self.pager.complete();self.sample();identifier=self.journal.state['incident']['id']
        self.journal.close();self.journal=Journal(self.root/'journal',binding={'purpose':'watchdog-test'});self.detector=Detector(self.journal,self.client,PRIMARY)
        self.assertEqual(self.sample()['code'],'monitor_stale');self.assertEqual(self.journal.state['incident']['id'],identifier)
        self.detector.path.unlink()
        with self.assertRaises(ValueError):Detector(self.journal,self.client,PRIMARY)

    def test_challenge_and_role_auth_reject_replays_or_wrong_capabilities(self):
        value=self.client.observe()
        with self.assertRaises(ValueError):observation(value,DEPLOYMENT,'0'*64)
        self.client.token='2'*64
        with self.assertRaises(ValueError):self.client.observe()
        with self.assertRaises(ValueError):self.client.request('/v1/alerts',{})

    def test_agent_loss_uses_own_queue_and_telegram_without_primary_pipeline(self):
        context=self.context();self.addCleanup(context.close);self.assertEqual(context.step()['state'],'healthy')
        # There is deliberately no primary monitor inbox or provider journal here.
        self.assertFalse((self.root/'pager/inbox.json').exists());self.stop(self.agent_server)
        status=context.step();self.assertEqual(status['code'],'watchdog_unavailable');self.assertEqual(status['delivery'],'accepted')
        messages=json.loads(self.mock.path.read_text())['messages'];self.assertEqual(len(messages),1)
        self.assertIn('watchdog_unavailable',messages[0]['text']);self.assertFalse(status['human_receipt_verified'])

    def test_telegram_retry_ambiguity_can_duplicate_same_incident_message(self):
        self.policy(status=200,disconnect=True)
        with self.assertRaises(PageFailure):self.telegram.send(self.event(),'trigger','nativepay:'+'a'*64,100)
        self.policy(status=200);self.telegram.send(self.event(),'trigger','nativepay:'+'a'*64,102)
        messages=json.loads(self.mock.path.read_text())['messages'];self.assertEqual(len(messages),2)
        self.assertEqual(messages[0]['text'],messages[1]['text'])

    def test_telegram_rate_limit_rejections_wrong_chat_and_fake_success(self):
        self.policy(status=429,retry_after=8)
        with self.assertRaises(PageFailure) as error:self.telegram.send(self.event(),'trigger','nativepay:'+'a'*64,100)
        self.assertEqual(error.exception.retry_at,108)
        self.policy(status=403)
        with self.assertRaises(PageFailure) as error:self.telegram.send(self.event(),'trigger','nativepay:'+'a'*64,100)
        self.assertTrue(error.exception.blocked)
        for option in ('wrong_chat','bad_ok'):
            self.policy(status=200,**{option:True})
            with self.assertRaises(PageFailure):self.telegram.send(self.event(),'trigger','nativepay:'+'a'*64,100)

    def test_telegram_redirect_never_forwards_bot_token(self):
        with socket.socket() as trap:
            trap.bind(('127.0.0.1',0));trap.listen();trap.settimeout(.1)
            self.policy(status=302,redirect='https://127.0.0.1:'+str(trap.getsockname()[1])+'/secret-trap')
            with self.assertRaises(PageFailure):self.telegram.send(self.event(),'trigger','nativepay:'+'a'*64,100)
            with self.assertRaises(socket.timeout):trap.accept()

    def test_changed_watchdog_route_or_corrupt_progress_history_cannot_reset(self):
        context=self.context();self.addCleanup(context.close);context.step();c=copy.deepcopy(context.c);context.close()
        c['stale_seconds']=30
        with self.assertRaises(ValueError):Context(c)
        atomic(self.detector.path,{'corrupt':'CANARY'},0o600)
        with self.assertRaises(ValueError):Detector(self.journal,self.client,PRIMARY)

    def test_notification_credentials_cannot_be_primary_pager_or_monitor_keys(self):
        atomic(self.telegram_key,{'format':'native-pagerduty-key-v1','deployment':DEPLOYMENT,'routing_key':'a'*32},0o600)
        with self.assertRaises(ValueError):Telegram('https://'+self.telegram_server.authority,self.tls/'ca.crt',self.pin,self.telegram_key,DEPLOYMENT)
        with self.assertRaises(ValueError):Telegram('https://api.telegram.org',self.tls/'ca.crt',self.pin,self.telegram_key,DEPLOYMENT)

    def test_telegram_wrong_tls_or_ca_never_transmits_bot_secret(self):
        for cert,key in (('wrong-host.crt','wrong-host.key'),('expired.crt','server.key')):
            server=Server(('127.0.0.1',0),self.mock,'','unused','mock',self.tls/cert,self.tls/key)
            server.authority='127.0.0.1:'+str(server.server_port);server.RequestHandlerClass=TelegramHandler
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start();self.servers.append((server,thread))
            client=Telegram('https://'+server.authority,self.tls/'ca.crt',self.pin,self.telegram_key,DEPLOYMENT)
            with self.assertRaises(PageFailure):client.send(self.event(),'trigger','nativepay:'+'a'*64,100)
        self.assertEqual(json.loads(self.mock.path.read_text())['requests'],0)
        with self.assertRaises(ValueError):Telegram('https://'+self.telegram_server.authority,self.tls/'ca.crt','0'*64,self.telegram_key,DEPLOYMENT)

    def test_unknown_private_fields_never_leave_agent_and_future_progress_fails(self):
        value=copy.deepcopy(self.monitor.value);value['bot_token']='CANARY_PRIVATE';atomic(self.monitor.path,value,0o600)
        data=self.client.observe();self.assertEqual(data['targets']['monitor']['error'],'invalid');self.assertNotIn('CANARY',encode(data).decode())
        self.monitor.write();value=copy.deepcopy(self.monitor.value);value['completed_at']=self.now+3;atomic(self.monitor.path,value,0o600)
        self.assertEqual(self.sample()['code'],'monitor_invalid')
