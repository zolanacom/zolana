"""Finite loopback process-crash rehearsal; validators are never started."""
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


def worker(stage,bundle,phase):
    # Test-only receiver fault injection is outside the shipped runtime/CLI.
    sys.path.insert(0,str(bundle))
    from offhost_monitor import load_config
    from monitor_transport import Inbox,Server,capability,endpoint
    config=load_config(stage/'receiver.json',False)
    def crash(at,_):
        if at==phase:os.kill(os.getpid(),signal.SIGKILL)
    inbox=Inbox(config['root'],config['deployment'],hook=crash)
    origin=endpoint(config['origin']);server=None;stopping=threading.Event()
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,lambda *_:stopping.set())
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    try:
        server=Server(('127.0.0.1',origin.port),inbox,origin.netloc,capability(config['capability_file'],config['deployment'],'alert-write'),
                      'alert-write',config['certificate_file'],config['key_file'])
        server.timeout=.2;print(json.dumps({'listening':True,'test_only':True}),flush=True)
        end=time.monotonic()+120
        while not stopping.is_set() and time.monotonic()<end:server.handle_request()
    finally:
        if server is not None:server.server_close()
        inbox.close()


def rehearse():
    from monitor_package import prepare
    from local_test_tls import create
    from operator_health import atomic
    stage=Path(tempfile.mkdtemp(prefix='native-offhost-monitor-032-',dir='/private/tmp'));stage.chmod(0o700)
    base=Path('/Library/NativePayLocal');plist=Path('/Library/LaunchDaemons/local.nativepay.validator.plist')
    if subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode!=1:raise ValueError('keep original validators paused')
    if subprocess.run(['/bin/launchctl','print','system/local.nativepay.validator'],capture_output=True).returncode!=113:raise ValueError('original service must be unloaded')
    original_manifest=sha(base/'MANIFEST.json');original_plist=sha(plist)
    (stage/'a').mkdir();(stage/'b').mkdir()
    package=prepare(stage/'a/monitor');repeat=prepare(stage/'b/monitor')
    if package['archive_sha256']!=repeat['archive_sha256']:raise ValueError('standalone build is not reproducible')
    extracted=stage/'extracted';extracted.mkdir(mode=0o700)
    with zipfile.ZipFile(package['archive']) as zipped:zipped.extractall(extracted)
    bundle=extracted/'monitor';runner=bundle/'run.py'
    tls=stage/'tls';create(tls)
    for path in tls.iterdir():
        if path.is_file():path.chmod(0o600)
    deployment=os.urandom(16).hex()
    for role in ('health-read','alert-write'):
        subprocess.run(['/usr/bin/python3','-I',str(runner),'keygen','--deployment',deployment,'--role',role,'--output',str(stage/(role+'.json'))],
                       check=True,capture_output=True,timeout=10)
    def port():
        with socket.socket() as listener:listener.bind(('127.0.0.1',0));return listener.getsockname()[1]
    source_port=port();alert_port=port()
    if source_port==alert_port:alert_port=port()
    source_origin='https://127.0.0.1:'+str(source_port);alert_origin='https://127.0.0.1:'+str(alert_port)
    common=dict(deployment=deployment,certificate_file='tls/server.crt',key_file='tls/server.key')
    configs={
        'exporter':dict(common,format='native-health-exporter-v1',origin=source_origin,capability_file='health-read.json',
                        heartbeat_file=str(base/'health/heartbeat.json'),heartbeat_owner=450),
        'receiver':dict(common,format='native-alert-receiver-v1',origin=alert_origin,capability_file='alert-write.json',root='inbox'),
        'observer':dict(format='native-offhost-monitor-v1',deployment=deployment,journal='journal',interval_seconds=1,expect_running=False,
            source=dict(origin=source_origin,capability_file='health-read.json',ca_file='tls/ca.crt',ca_sha256=sha(tls/'ca.crt')),
            alerts=dict(origin=alert_origin,capability_file='alert-write.json',ca_file='tls/ca.crt',ca_sha256=sha(tls/'ca.crt'))),
    }
    for name,config in configs.items():atomic(stage/(name+'.json'),config,0o600)
    atomic(Path.cwd()/'.local/offhost-032-stage.json',{'stage':str(stage),'bundle':str(bundle),'package':package},0o600)
    children=[];starts={};result={'status':'failed','stage':str(stage)}
    def progress(phase):atomic(stage/'progress.json',{'phase':phase},0o600)
    def wait(predicate,seconds,message):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.1)
        raise TimeoutError(message)
    def start(role,crash=None):
        starts[role]=starts.get(role,0)+1;name=role+'-'+str(starts[role])
        stdout=stage/(name+'.stdout');stderr=stage/(name+'.stderr')
        command=([sys.executable,'-B',str(Path(__file__).resolve()),'--worker',crash,'--stage',str(stage),'--bundle',str(bundle)] if crash else
                 ['/usr/bin/python3','-I',str(runner),{'exporter':'export','receiver':'receive','observer':'watch'}[role],
                  '--config',str(stage/(role+'.json')),'--duration','240'])
        with stdout.open('xb') as out,stderr.open('xb') as err:
            child=subprocess.Popen(command,stdout=out,stderr=err,cwd=stage,env={'PATH':'/usr/bin:/bin','PYTHONDONTWRITEBYTECODE':'1'})
        children.append(child)
        def ready():
            if child.poll() is not None:raise RuntimeError(role+' startup failed; private stage logs retained')
            return stdout.stat().st_size>0
        wait(ready,10,role+' startup deadline');return child
    def stop(child,crash=False):
        if child.poll() is None:
            child.kill() if crash else child.terminate()
            try:code=child.wait(timeout=6)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3);raise RuntimeError('graceful role shutdown failed')
            if code!=(-9 if crash else 0):raise ValueError('unexpected role exit')
    def state():
        return json.loads((stage/'journal/state.json').read_text())
    def inbox():return json.loads((stage/'inbox/inbox.json').read_text())['events']
    def original_paused():
        return (sha(base/'MANIFEST.json')==original_manifest and sha(plist)==original_plist and
            subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1 and
            subprocess.run(['/bin/launchctl','print','system/local.nativepay.validator'],capture_output=True).returncode==113)
    try:
        progress('real_installed_source_paused_unprivileged_export')
        receiver=start('receiver');exporter=start('exporter');observer=start('observer')
        wait(lambda:(stage/'journal/state.json').exists(),5,'observer journal creation')
        time.sleep(2)
        if state()['events'] or state()['incident'] is not None:raise ValueError('healthy paused source created noise')
        progress('source_and_delivery_outage_then_observer_sigkill')
        stop(receiver);stop(exporter,crash=True)
        wait(lambda:state()['incident'] is not None and state()['incident']['code']=='remote_unavailable' and any(not e['delivered'] for e in state()['events']),8,'missing host-loss event after pause')
        incident=state()['incident'];stop(observer,crash=True)
        observer=start('observer')
        if state()['incident']!=incident or len(state()['events'])!=1:raise ValueError('observer crash changed pending incident')
        progress('receiver_sigkill_before_durable_commit')
        receiver=start('receiver',crash='before_commit')
        wait(lambda:receiver.poll() is not None,15,'receiver did not crash before commit')
        if receiver.returncode!=-9 or inbox() or state()['events'][0]['delivered']:raise ValueError('precommit crash incorrectly acknowledged')
        progress('receiver_sigkill_after_commit_before_ack')
        receiver=start('receiver',crash='after_commit')
        wait(lambda:receiver.poll() is not None,20,'receiver did not crash after commit')
        if receiver.returncode!=-9 or len(inbox())!=1 or inbox()[0]['id']!=incident['id'] or state()['events'][0]['delivered']:
            raise ValueError('postcommit crash lost durable event or acknowledged early')
        progress('same_id_retry_after_receiver_restart')
        receiver=start('receiver')
        wait(lambda:state()['events'][0]['delivered'],40,'ambiguous delivery did not retry')
        if len(inbox())!=1 or inbox()[0]['id']!=incident['id']:raise ValueError('lost-ack retry duplicated alert')
        progress('source_restart_and_fresh_operator_pause_resolution')
        exporter=start('exporter')
        wait(lambda:state()['incident'] is None and len(inbox())==2 and all(e['delivered'] for e in state()['events']),15,'fresh paused source did not resolve outage')
        if [e['kind'] for e in inbox()]!=['incident','operator_paused']:raise ValueError('pause misreported as ready recovery')
        snapshot=state()['events'];stop(observer,crash=True);observer=start('observer');time.sleep(3)
        if state()['events']!=snapshot or len(inbox())!=2:raise ValueError('acknowledged event replayed as a new incident')
        stop(observer);stop(exporter);stop(receiver)
        if not original_paused():raise ValueError('installed runtime/plist/pause changed')
        sys.path.insert(0,str(bundle))
        from monitor_transport import Client
        alert=Client(alert_origin,tls/'ca.crt',sha(tls/'ca.crt'),stage/'alert-write.json',deployment,'alert-write')
        receiver=start('receiver');alert.alert(inbox()[0]);stop(receiver)
        if len(inbox())!=2:raise ValueError('inbox restart did not retain deduplication')
        result.update(status='passed',manifest_sha256=package['manifest_sha256'],archive_sha256=package['archive_sha256'],
            independent_system_python_bundle=True,byte_identical_repeat_build=True,
            actual_installed_paused_source_exported_without_admin=True,host_loss_after_pause_alerted=True,
            exporter_sigkill=True,observer_sigkill_pending_and_acknowledged=True,
            receiver_sigkill_before_commit=True,receiver_sigkill_after_commit_before_ack=True,
            same_event_id_retried_without_duplicate_receipt=True,pending_journal_recovered=True,
            fresh_pause_resolution_not_false_ready_recovery=True,receiver_restart_deduplication=True,
            durable_remote_events=len(inbox()),validators_started=0,payment_broadcast_commands=0,
            private_service_files_accessed=0,external_messages_sent=0,network_scope='loopback TLS only',
            installed_manifest_unchanged=original_manifest,normal_plist_unchanged=True)
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)[:240];raise
    finally:
        errors=[]
        for child in reversed(children):
            if child.poll() is None:
                try:stop(child)
                except Exception:errors.append('owned_child_shutdown_failed')
        closed=[]
        for number in (source_port,alert_port):
            with socket.socket() as probe:probe.settimeout(.2);closed.append(probe.connect_ex(('127.0.0.1',number))!=0)
        result.update(all_test_children_stopped=all(c.poll() is not None for c in children),test_ports_closed=all(closed),
            validators_still_paused_and_original_service_unchanged=original_paused(),cleanup_errors=errors)
        if errors or not all(result[k] for k in ('all_test_children_stopped','test_ports_closed','validators_still_paused_and_original_service_unchanged')):result['status']='failed'
        atomic(stage/'result.json',result,0o600);atomic(Path.cwd()/'.local/offhost-032-result.json',result,0o600)
    if result['status']!='passed':raise ValueError('rehearsal cleanup failed')
    print(json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--worker',choices=('before_commit','after_commit'))
    parser.add_argument('--stage',type=Path);parser.add_argument('--bundle',type=Path);args=parser.parse_args()
    if args.worker:worker(args.stage,args.bundle,args.worker)
    else:rehearse()
