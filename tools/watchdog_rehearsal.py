"""Finite independent-watchdog crash rehearsal using loopback TLS only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def telegram_worker(stage,bundle):
    sys.path.insert(0,str(bundle))
    from watchdog_test import MockTelegram,TelegramHandler
    from watchdog_notify import credential
    from monitor_transport import Server
    meta=json.loads((stage/'telegram-mock.json').read_text());key=credential(stage/'telegram-key.json',meta['deployment'])
    model=MockTelegram(stage/'telegram',key['bot_token'],key['chat_id'])
    server=Server(('127.0.0.1',meta['port']),model,'127.0.0.1:'+str(meta['port']),'unused','mock',stage/'tls/server.crt',stage/'tls/server.key')
    server.RequestHandlerClass=TelegramHandler;server.timeout=.2;stopping=threading.Event()
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,lambda *_:stopping.set())
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    print(json.dumps({'listening':True,'telegram_mock_only':True}),flush=True);deadline=time.monotonic()+240
    try:
        while not stopping.is_set() and time.monotonic()<deadline:server.handle_request()
    finally:server.server_close()


def rehearse():
    from local_test_tls import create
    from monitor_package import prepare
    from monitor_transport import Client
    from operator_health import atomic
    repo=Path(__file__).resolve().parents[1];base=Path('/Library/NativePayLocal');plist=Path('/Library/LaunchDaemons/local.nativepay.validator.plist')
    def paused():return subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1
    def unloaded():return subprocess.run(['/bin/launchctl','print','system/local.nativepay.validator'],capture_output=True).returncode==113
    if not paused() or not unloaded():raise ValueError('keep validators paused')
    original_manifest=sha(base/'MANIFEST.json');original_plist=sha(plist)
    stage=Path(tempfile.mkdtemp(prefix='native-independent-watchdog-034-',dir='/private/tmp'));stage.chmod(0o700)
    (stage/'a').mkdir();(stage/'b').mkdir();package=prepare(stage/'a/monitor');repeat=prepare(stage/'b/monitor')
    if package['archive_sha256']!=repeat['archive_sha256']:raise ValueError('non-reproducible monitoring package')
    (stage/'extracted').mkdir(mode=0o700)
    with zipfile.ZipFile(package['archive']) as archive:archive.extractall(stage/'extracted')
    bundle=stage/'extracted/monitor';runner=bundle/'run.py';create(stage/'tls')
    for path in (stage/'tls').iterdir():
        if path.is_file():path.chmod(0o600)
    deployment=os.urandom(16).hex();numbers=[]
    for _ in range(6):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0));number=probe.getsockname()[1]
        if number in numbers:raise ValueError('ephemeral port collision; preserve stage')
        numbers.append(number)
    ports=dict(zip(('source','receiver','primary','agent','telegram','unused'),numbers))
    origin=lambda role:'https://127.0.0.1:'+str(ports[role]);pin=sha(stage/'tls/ca.crt')
    for role in ('health-read','alert-write','watchdog-read'):
        subprocess.run(['/usr/bin/python3','-I',str(runner),'keygen','--deployment',deployment,'--role',role,'--output',str(stage/(role+'.json'))],check=True,capture_output=True,timeout=10)
    primary_key=os.urandom(16).hex();primary_sha=hashlib.sha256(primary_key.encode()).hexdigest()
    atomic(stage/'provider-key.json',dict(format='native-pagerduty-key-v1',deployment=deployment,routing_key=primary_key),0o600)
    atomic(stage/'telegram-key.json',dict(format='native-watchdog-telegram-key-v1',deployment=deployment,bot_token='123456:'+os.urandom(16).hex(),chat_id=-123456789),0o600)
    peer=lambda role,cap:dict(origin=origin(role),ca_file='tls/ca.crt',ca_sha256=pin,capability_file=cap+'.json')
    tls=dict(deployment=deployment,certificate_file='tls/server.crt',key_file='tls/server.key')
    configs={
        'source':dict(tls,format='native-health-exporter-v1',origin=origin('source'),capability_file='health-read.json',heartbeat_file=str(base/'health/heartbeat.json'),heartbeat_owner=450),
        'receiver':dict(tls,format='native-alert-receiver-v1',origin=origin('receiver'),capability_file='alert-write.json',root='primary-inbox'),
        'monitor':dict(format='native-offhost-monitor-v1',deployment=deployment,journal='monitor-state',interval_seconds=1,expect_running=False,source=peer('source','health-read'),alerts=peer('receiver','alert-write')),
        'pager':dict(format='native-human-pager-config-v1',deployment=deployment,inbox='primary-inbox',state='pager-state',interval_seconds=1,
            provider=dict(endpoint=origin('primary')+'/v2/enqueue',ca_file='tls/ca.crt',ca_sha256=pin,routing_key_file='provider-key.json')),
        'agent':dict(tls,format='native-watchdog-agent-v1',origin=origin('agent'),capability_file='watchdog-read.json',targets={role:dict(pulse_file=role+'-state/watchdog.json',owner=os.getuid()) for role in ('monitor','pager')}),
        'watchdog':dict(format='native-independent-watchdog-v1',deployment=deployment,root='watchdog-state',interval_seconds=1,stale_seconds=5,backlog_seconds=5,startup_seconds=10,
            primary_integration_sha256=primary_sha,agent=peer('agent','watchdog-read'),provider=dict(origin=origin('telegram'),ca_file='tls/ca.crt',ca_sha256=pin,key_file='telegram-key.json')),
    }
    for name,value in configs.items():atomic(stage/(name+'.json'),value,0o600)
    atomic(stage/'telegram-mock.json',{'deployment':deployment,'port':ports['telegram']},0o600)
    atomic(stage/'mock.json',{'deployment':deployment,'port':ports['primary']},0o600)
    (stage/'mock').mkdir(mode=0o700);atomic(stage/'mock/policy.json',{'status':202},0o600)
    (stage/'telegram').mkdir(mode=0o700);atomic(stage/'telegram/policy.json',{'status':200},0o600)
    atomic(repo/'.local/watchdog-034-stage.json',{'stage':str(stage),'bundle':str(bundle),'package':package},0o600)
    children=[];starts={};result={'status':'failed','stage':str(stage)}
    def progress(phase):atomic(stage/'progress.json',{'phase':phase},0o600)
    def wait(predicate,seconds,message):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.1)
        raise TimeoutError(message)
    def start(role):
        starts[role]=starts.get(role,0)+1;name=role+'-'+str(starts[role]);out=stage/(name+'.stdout');err=stage/(name+'.stderr')
        if role=='telegram':command=[sys.executable,'-B',str(Path(__file__).resolve()),'--telegram-worker','--stage',str(stage),'--bundle',str(bundle)]
        elif role=='primary':command=[sys.executable,'-B',str(repo/'tools/paging_rehearsal.py'),'--worker','provider','--stage',str(stage),'--bundle',str(bundle)]
        else:
            action={'source':'export','receiver':'receive','monitor':'watch','pager':'page','agent':'watchdog-agent','watchdog':'watchdog'}[role]
            command=['/usr/bin/python3','-I',str(runner),action,'--config',str(stage/(role+'.json')),'--duration','240']
        with out.open('xb') as stdout,err.open('xb') as stderr:child=subprocess.Popen(command,cwd=stage,stdout=stdout,stderr=stderr,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
        children.append(child)
        def ready():
            if child.poll() is not None:raise RuntimeError(role+' startup failed; stage evidence retained')
            return out.stat().st_size>0
        wait(ready,12,role+' startup deadline');return child
    def stop(child,crash=False):
        if child.poll() is None:
            child.kill() if crash else child.terminate()
            try:code=child.wait(timeout=6)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3);raise RuntimeError('owned process failed graceful shutdown')
            if code!=(-9 if crash else 0):raise ValueError('unexpected child exit')
    def state():return json.loads((stage/'watchdog-state/observations/state.json').read_text())
    def delivery():return json.loads((stage/'watchdog-state/delivery/state.json').read_text())
    def messages():return json.loads((stage/'telegram/messages.json').read_text())['messages']
    def fault(code):
        value=state()['incident'];return value is not None and value['code']==code
    def recovered(count):return state()['incident'] is None and delivery()['pending'] is None and len(messages())>=count
    def unchanged():return paused() and unloaded() and sha(base/'MANIFEST.json')==original_manifest and sha(plist)==original_plist
    def alarm(*_):raise TimeoutError('finite independent watchdog rehearsal')
    signal.signal(signal.SIGALRM,alarm);signal.alarm(210)
    try:
        progress('actual_monitor_and_pager_completed_cycles')
        receiver=start('receiver');source=start('source');monitor=start('monitor');pager=start('pager');telegram=start('telegram');agent=start('agent');watchdog=start('watchdog')
        wait(lambda:state()['last_wall'] is not None and state()['incident'] is None,8,'watchdog healthy startup')
        progress('monitor_sigstop_and_watchdog_crash_recovery')
        monitor.send_signal(signal.SIGSTOP)
        wait(lambda:fault('monitor_stale') and len(messages())>=1 and delivery()['pending'] is None,12,'hung monitor not detected')
        incident=state()['incident'];stop(watchdog,True);watchdog=start('watchdog');time.sleep(2)
        if state()['incident']!=incident or len(messages())!=1:raise ValueError('watchdog restart changed accepted incident')
        stop(monitor,True);monitor=start('monitor');wait(lambda:recovered(2),10,'monitor fresh-cycle recovery')
        progress('pager_sigstop_sigkill_and_fresh_cycle_recovery')
        pager.send_signal(signal.SIGSTOP)
        wait(lambda:fault('pager_stale') and len(messages())>=3 and delivery()['pending'] is None,12,'hung pager not detected')
        stop(pager,True);pager=start('pager');wait(lambda:recovered(4),10,'pager restart recovery')
        progress('independent_lane_reports_primary_provider_outage')
        client=Client(origin('receiver'),stage/'tls/ca.crt',pin,stage/'alert-write.json',deployment,'alert-write')
        client.alert({'id':'e'*32+':1','sequence':1,'kind':'incident','code':'remote_unavailable','at':time.time()})
        wait(lambda:fault('pager_backlog') and len(messages())>=5 and delivery()['pending'] is None,15,'live pager backlog did not reach independent lane')
        if (stage/'mock/provider.json').exists():raise ValueError('watchdog depended on an active primary provider')
        primary=start('primary');wait(lambda:recovered(6),20,'primary delivery recovery')
        progress('agent_loss_and_watchdog_pending_restart')
        stop(telegram);stop(agent,True)
        wait(lambda:fault('watchdog_unavailable') and delivery()['pending'] is not None and delivery()['pending']['failure'] is not None,10,'agent loss not durably queued')
        plan=delivery()['pending']['plan'];stop(watchdog,True);watchdog=start('watchdog')
        if delivery()['pending']['plan']!=plan:raise ValueError('pending watchdog notification changed after restart')
        progress('telegram_sigkill_after_acceptance_and_duplicate_safe_retry')
        atomic(stage/'telegram/policy.json',{'status':200,'crash':'after_accept'},0o600);telegram=start('telegram')
        wait(lambda:telegram.poll() is not None,15,'mock Telegram did not crash after acceptance')
        if telegram.returncode!=-9 or delivery()['pending'] is None:raise ValueError('ambiguous Telegram acceptance incorrectly cleared')
        accepted=messages()[-1]['text'];atomic(stage/'telegram/policy.json',{'status':200},0o600);telegram=start('telegram')
        wait(lambda:delivery()['pending'] is None and len(messages())>=8,20,'Telegram same-key retry recovery')
        if messages()[-1]['text']!=accepted or messages()[-2]['text']!=accepted:raise ValueError('ambiguous retry lost stable incident text')
        agent=start('agent');wait(lambda:recovered(9),10,'fresh role/agent recovery')
        count=len(messages());stop(watchdog,True);watchdog=start('watchdog');time.sleep(2)
        if len(messages())!=count or state()['incident'] is not None:raise ValueError('accepted watchdog restart resent notifications')
        for child in (watchdog,agent,monitor,pager,receiver,source,primary,telegram):stop(child)
        if not unchanged():raise ValueError('original installed service changed')
        result.update(status='passed',manifest_sha256=package['manifest_sha256'],archive_sha256=package['archive_sha256'],
            standalone_v3_system_python=True,byte_identical_repeat_build=True,actual_monitor_sigstop_sigkill_recovery=True,
            actual_pager_sigstop_sigkill_recovery=True,watchdog_restart_preserved_incident=True,
            live_pager_backlog_alerted_without_primary_provider=True,agent_sigkill_alerted=True,
            watchdog_pending_restart_preserved_action=True,telegram_sigkill_after_acceptance=True,
            ambiguous_telegram_retry_visible_duplicate_same_incident=True,accepted_watchdog_restart_sent_zero_messages=True,
            mock_telegram_messages=len(messages()),human_receipt_verified=False,external_messages_sent=0,
            validators_started=0,payment_broadcast_commands=0,private_service_files_accessed=0,
            installed_manifest_unchanged=original_manifest,normal_plist_unchanged=True,network_scope='loopback TLS mocks only')
    except BaseException as error:result['error']=type(error).__name__+': '+str(error)[:240];raise
    finally:
        signal.alarm(0);errors=[]
        for child in reversed(children):
            if child.poll() is None:
                # An interrupted SIGSTOP test must be unparked before SIGTERM.
                try:child.send_signal(signal.SIGCONT)
                except ProcessLookupError:pass
                try:stop(child)
                except Exception:errors.append('owned_child_shutdown_failed')
        closed=[]
        for number in numbers:
            with socket.socket() as probe:probe.settimeout(.2);closed.append(probe.connect_ex(('127.0.0.1',number))!=0)
        result.update(all_test_children_stopped=all(c.poll() is not None for c in children),test_ports_closed=all(closed),
            validators_paused_and_original_service_unchanged=unchanged(),cleanup_errors=errors)
        if errors or not all(result[k] for k in ('all_test_children_stopped','test_ports_closed','validators_paused_and_original_service_unchanged')):result['status']='failed'
        atomic(stage/'result.json',result,0o600);atomic(repo/'.local/watchdog-034-result.json',result,0o600)
    if result['status']!='passed':raise ValueError('watchdog rehearsal cleanup failed')
    print(json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--telegram-worker',action='store_true');parser.add_argument('--stage',type=Path);parser.add_argument('--bundle',type=Path)
    args=parser.parse_args()
    if args.telegram_worker:telegram_worker(args.stage,args.bundle)
    else:rehearse()
