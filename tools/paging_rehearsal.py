"""Finite loopback human-paging crash rehearsal; no real provider or validators."""
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


def worker(stage,bundle,role,crash):
    sys.path.insert(0,str(bundle))
    from operator_health import atomic
    from human_paging import Relay,configuration,routing_key
    stopping=threading.Event()
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,lambda *_:stopping.set())
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    deadline=time.monotonic()+240
    if role=='pager':
        config,route,provider=configuration(stage/'pager.json')
        def hook(phase):
            if phase==crash:
                atomic(stage/('relay-crashed-'+phase+'.json'),{'checkpoint':phase},0o600);os.kill(os.getpid(),9)
        relay=Relay(config['state'],config['inbox'],config['deployment'],route,provider,hook=hook)
        try:
            while not stopping.is_set() and time.monotonic()<deadline:
                print(json.dumps(relay.step(),sort_keys=True),flush=True);stopping.wait(1)
        finally:relay.close()
    else:
        # Test-only provider/fault injector is excluded from the shipped bundle.
        from human_paging_test import MockPager,MockHandler
        from monitor_transport import Server
        config=json.loads((stage/'mock.json').read_text())
        mock=MockPager(stage/'mock',routing_key(stage/'provider-key.json',config['deployment']))
        server=Server(('127.0.0.1',config['port']),mock,'127.0.0.1:'+str(config['port']),'unused','mock',stage/'tls/server.crt',stage/'tls/server.key')
        server.RequestHandlerClass=MockHandler;server.timeout=.2
        print(json.dumps({'listening':True,'mock_only':True}),flush=True)
        try:
            while not stopping.is_set() and time.monotonic()<deadline:server.handle_request()
        finally:server.server_close()


def rehearse():
    from local_test_tls import create
    from monitor_package import prepare
    from monitor_transport import Client
    from operator_health import atomic
    repo=Path(__file__).resolve().parents[1]
    stage=Path(tempfile.mkdtemp(prefix='native-human-paging-033-',dir='/private/tmp'));stage.chmod(0o700)
    base=Path('/Library/NativePayLocal');plist=Path('/Library/LaunchDaemons/local.nativepay.validator.plist')
    def unloaded():return subprocess.run(['/bin/launchctl','print','system/local.nativepay.validator'],capture_output=True).returncode==113
    def paused():return subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1
    if not unloaded() or not paused():raise ValueError('keep the original validator service paused')
    original_manifest=sha(base/'MANIFEST.json');original_plist=sha(plist)
    (stage/'a').mkdir();(stage/'b').mkdir();package=prepare(stage/'a/monitor');repeat=prepare(stage/'b/monitor')
    if package['archive_sha256']!=repeat['archive_sha256']:raise ValueError('monitor package is not reproducible')
    (stage/'extracted').mkdir(mode=0o700)
    with zipfile.ZipFile(package['archive']) as archive:archive.extractall(stage/'extracted')
    bundle=stage/'extracted/monitor';runner=bundle/'run.py'
    create(stage/'tls')
    for path in (stage/'tls').iterdir():
        if path.is_file():path.chmod(0o600)
    deployment=os.urandom(16).hex()
    subprocess.run(['/usr/bin/python3','-I',str(runner),'keygen','--deployment',deployment,'--role','alert-write','--output',str(stage/'alert-write.json')],check=True,capture_output=True,timeout=10)
    atomic(stage/'provider-key.json',{'format':'native-pagerduty-key-v1','deployment':deployment,'routing_key':os.urandom(16).hex()},0o600)
    def port():
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));return probe.getsockname()[1]
    receiver_port=port();provider_port=port()
    if receiver_port==provider_port:provider_port=port()
    receiver_origin='https://127.0.0.1:'+str(receiver_port);provider_origin='https://127.0.0.1:'+str(provider_port)
    atomic(stage/'receiver.json',dict(format='native-alert-receiver-v1',deployment=deployment,origin=receiver_origin,
        capability_file='alert-write.json',certificate_file='tls/server.crt',key_file='tls/server.key',root='inbox'),0o600)
    atomic(stage/'pager.json',dict(format='native-human-pager-config-v1',deployment=deployment,inbox='inbox',state='paging-state',interval_seconds=1,
        provider=dict(endpoint=provider_origin+'/v2/enqueue',ca_file='tls/ca.crt',ca_sha256=sha(stage/'tls/ca.crt'),routing_key_file='provider-key.json')),0o600)
    atomic(stage/'mock.json',{'deployment':deployment,'port':provider_port},0o600)
    (stage/'mock').mkdir(mode=0o700)
    atomic(stage/'mock/policy.json',{'status':503},0o600)
    atomic(repo/'.local/paging-033-stage.json',{'stage':str(stage),'bundle':str(bundle),'package':package},0o600)
    client=Client(receiver_origin,stage/'tls/ca.crt',sha(stage/'tls/ca.crt'),stage/'alert-write.json',deployment,'alert-write')
    children=[];starts={};result={'status':'failed','stage':str(stage)}
    def progress(phase):atomic(stage/'progress.json',{'phase':phase},0o600)
    def wait(predicate,seconds,message):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.1)
        raise TimeoutError(message)
    def start(role,crash=None):
        starts[role]=starts.get(role,0)+1;name=role+'-'+str(starts[role]);out=stage/(name+'.stdout');err=stage/(name+'.stderr')
        if role=='provider' or crash:
            command=[sys.executable,'-B',str(Path(__file__).resolve()),'--worker',role,'--stage',str(stage),'--bundle',str(bundle)]
            if crash:command+=['--crash',crash]
        else:
            command=['/usr/bin/python3','-I',str(runner),'receive' if role=='receiver' else 'page','--config',str(stage/('receiver.json' if role=='receiver' else 'pager.json')),'--duration','240']
        with out.open('xb') as stdout,err.open('xb') as stderr:child=subprocess.Popen(command,cwd=stage,stdout=stdout,stderr=stderr,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
        children.append(child)
        def ready():
            if child.poll() is not None:raise RuntimeError(role+' startup failed; stage evidence retained')
            return out.stat().st_size>0
        wait(ready,10,role+' startup deadline');return child
    def stop(child,crash=False):
        if child.poll() is None:
            child.kill() if crash else child.terminate()
            try:code=child.wait(timeout=6)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3);raise RuntimeError('owned process graceful stop failed')
            if code!=(-9 if crash else 0):raise ValueError('unexpected child exit')
    def state():return json.loads((stage/'paging-state/state.json').read_text())
    def model():return json.loads((stage/'mock/provider.json').read_text())
    def policy(**kwargs):atomic(stage/'mock/policy.json',kwargs,0o600)
    def enqueue(seq,kind='incident',code='remote_unavailable'):
        client.alert({'id':'d'*32+':'+str(seq),'sequence':seq,'kind':kind,'code':code,'at':time.time()})
    def untouched():return unloaded() and paused() and sha(base/'MANIFEST.json')==original_manifest and sha(plist)==original_plist
    def deadline(*_):raise TimeoutError('finite human paging rehearsal deadline')
    signal.signal(signal.SIGALRM,deadline);signal.alarm(210)
    try:
        progress('relay_sigkill_after_durable_plan_before_send')
        receiver=start('receiver');provider=start('provider');pager=start('pager',crash='planned')
        enqueue(1);wait(lambda:pager.poll() is not None,8,'planned relay crash deadline')
        if pager.returncode!=-9 or model()['requests']!=0 or state()['cursor']!=0:raise ValueError('planned crash sent or acknowledged early')
        pending=state()['pending']['plan'];pager=start('pager')
        wait(lambda:state()['pending']['failure']=='provider_unavailable',8,'unavailable delivery was not persisted')
        stop(pager,crash=True)
        progress('persisted_rate_limit_across_relay_restart')
        policy(status=429,retry_after='5');pager=start('pager')
        wait(lambda:state()['pending']['failure']=='rate_limited',8,'rate limit not observed')
        next_at=state()['pending']['next_at'];stop(pager,crash=True)
        calls=model()['requests'];policy(status=202,crash='before_accept');pager=start('pager')
        if time.time()<next_at-.5:
            time.sleep(.3)
            if model()['requests']!=calls:raise ValueError('restart ignored persisted retry-after')
        progress('provider_sigkill_before_acceptance')
        wait(lambda:provider.poll() is not None,12,'preaccept provider crash deadline')
        if provider.returncode!=-9 or model()['pages_created']!=0 or state()['cursor']!=0:raise ValueError('provider preaccept crash lost pending action')
        progress('provider_sigkill_after_acceptance_before_response')
        policy(status=202,crash='after_accept');provider=start('provider')
        wait(lambda:provider.poll() is not None,20,'postaccept provider crash deadline')
        if provider.returncode!=-9 or model()['pages_created']!=1 or state()['cursor']!=0:raise ValueError('provider lost-ack evidence differs')
        stop(pager,crash=True);policy(status=202);provider=start('provider')
        progress('relay_sigkill_after_202_before_local_acceptance')
        pager=start('pager',crash='provider_accepted')
        wait(lambda:pager.poll() is not None,25,'relay postaccept crash deadline')
        if pager.returncode!=-9 or model()['pages_created']!=1 or state()['cursor']!=0 or state()['pending']['plan']!=pending:
            raise ValueError('relay postaccept crash changed key or cursor')
        progress('same_key_retry_and_ordered_fault_update_resolution')
        pager=start('pager');wait(lambda:state()['cursor']==1,40,'postaccept relay recovery deadline')
        enqueue(2,code='heartbeat_stale');enqueue(3,kind='recovered',code='heartbeat_stale')
        wait(lambda:state()['cursor']==3,8,'fault update/recovery delivery deadline')
        if model()['pages_created']!=1 or model()['resolutions']!=1 or model()['active']:raise ValueError('fault update created an orphan or duplicate page')
        progress('permanent_rejection_keeps_ingestion_and_requires_explicit_retry')
        policy(status=403);enqueue(4)
        wait(lambda:state()['pending'] is not None and state()['pending']['blocked'],8,'rejected delivery did not block')
        enqueue(5,kind='operator_paused');stop(pager);pager=start('pager');time.sleep(2)
        if state()['cursor']!=3 or len(json.loads((stage/'inbox/inbox.json').read_text())['events'])!=5:raise ValueError('blocked provider stopped ingestion or dropped action')
        stop(pager);calls=model()['requests']
        armed=subprocess.run(['/usr/bin/python3','-I',str(runner),'page-retry','--config',str(stage/'pager.json')],capture_output=True,text=True,timeout=10)
        if armed.returncode or json.loads(armed.stdout)['phase']!='retry_armed' or model()['requests']!=calls:raise ValueError('explicit retry sent or failed to preserve pending')
        policy(status=202);pager=start('pager');wait(lambda:state()['cursor']==5,8,'reviewed retry did not recover')
        if model()['pages_created']!=2 or model()['resolutions']!=2 or model()['active']:raise ValueError('new incident cycle failed to use a fresh key')
        stop(pager,crash=True);before=model()['requests'];pager=start('pager');time.sleep(2)
        if state()['cursor']!=5 or model()['requests']!=before:raise ValueError('accepted cursor restart resent completed pages')
        for child in (pager,receiver,provider):stop(child)
        if not untouched():raise ValueError('original installed service changed')
        records=model()['records'];keys={r['dedup_key'] for r in records}
        if len(keys)!=2 or any(r['event_action']=='acknowledge' for r in records):raise ValueError('unexpected provider action')
        result.update(status='passed',manifest_sha256=package['manifest_sha256'],archive_sha256=package['archive_sha256'],
            standalone_v2_system_python=True,byte_identical_repeat_build=True,relay_sigkill_before_send=True,
            provider_sigkill_before_acceptance=True,provider_sigkill_after_acceptance_before_ack=True,
            relay_sigkill_after_202_before_local_commit=True,stable_pending_action_and_incident_key=True,
            retry_after_persisted_across_restart=True,provider_503_retried=True,provider_403_block_survived_restart=True,
            explicit_retry_preserved_action_without_sending=True,inbox_ingestion_continued_while_blocked=True,
            accepted_cursor_restart_sent_zero_requests=True,processed_inbox_events=state()['cursor'],
            mock_pages_created=model()['pages_created'],mock_incidents_resolved=model()['resolutions'],
            fault_updates_did_not_create_extra_pages=True,human_receipt_verified=False,
            external_messages_sent=0,validators_started=0,payment_broadcast_commands=0,private_service_files_accessed=0,
            installed_manifest_unchanged=original_manifest,normal_plist_unchanged=True,network_scope='loopback HTTPS mocks only')
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)[:240];raise
    finally:
        signal.alarm(0);errors=[]
        for child in reversed(children):
            if child.poll() is None:
                try:stop(child)
                except Exception:errors.append('owned_child_shutdown_failed')
        closed=[]
        for number in (receiver_port,provider_port):
            with socket.socket() as probe:probe.settimeout(.2);closed.append(probe.connect_ex(('127.0.0.1',number))!=0)
        result.update(all_test_children_stopped=all(c.poll() is not None for c in children),test_ports_closed=all(closed),
            validators_paused_and_original_service_unchanged=untouched(),cleanup_errors=errors)
        if errors or not all(result[k] for k in ('all_test_children_stopped','test_ports_closed','validators_paused_and_original_service_unchanged')):result['status']='failed'
        atomic(stage/'result.json',result,0o600);atomic(repo/'.local/paging-033-result.json',result,0o600)
    if result['status']!='passed':raise ValueError('paging rehearsal cleanup failed')
    print(json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--worker',choices=('pager','provider'))
    parser.add_argument('--stage',type=Path);parser.add_argument('--bundle',type=Path);parser.add_argument('--crash',choices=('planned','provider_accepted'))
    args=parser.parse_args()
    if args.worker:worker(args.stage,args.bundle,args.worker,args.crash)
    else:rehearse()
