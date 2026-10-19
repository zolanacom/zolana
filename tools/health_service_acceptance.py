"""Finite installed heartbeat/observer crash acceptance; never initialize state."""
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import signal
import socket
import subprocess
import sys
import time

BASE=Path('/Library/NativePayLocal')
if __name__=='__main__':sys.path.insert(0,str(BASE/'tools'))
import service_account as service
from operator_health import read


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path,value,mode=0o600,owner=None):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),mode)
        if owner is not None:os.fchown(stream.fileno(),*owner)


def main(stage,expected_manifest,resume=False):
    service.require_root();config=service.verify_install();os.nice(15)
    stage=Path(stage);root=BASE/'.data/s20';owner=(config['uid'],config['gid'])
    desktop=config['desktop_uid'];desktop_group=pwd.getpwuid(desktop).pw_gid
    if stage.parent!=Path('/private/tmp') or stage.resolve()!=stage or stage.lstat().st_uid!=desktop or stage.lstat().st_mode&0o077:
        raise ValueError('expected reviewed private stage')
    if digest(BASE/'MANIFEST.json')!=expected_manifest:raise ValueError('reviewed sealed runtime differs')
    suffix='-RECHECK1' if resume else ''
    report=BASE/('OPERATOR-HEALTH-031'+suffix+'.json');marker=BASE/('OPERATOR-HEALTH-031'+suffix+'.started.json')
    if report.exists() or marker.exists():raise ValueError('preserve existing health acceptance evidence')
    normal=service.PLIST.read_bytes();plist=plistlib.loads(normal)
    baseline=json.loads((BASE/'HISTORY-REPLICA-030.started.json').read_text())
    original=json.loads((root/'replica-evidence-030/initial-live.json').read_text())['native_state']
    def unloaded():return subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode==113
    def stopped():return subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1
    def fixed():return {name:digest(root/name) for name in baseline['private_file_digests']}
    if not unloaded() or not stopped() or plist['ProgramArguments'][-1]!='run' or digest(service.PLIST)!=baseline['normal_plist_sha256'] or fixed()!=baseline['private_file_digests']:
        raise ValueError('original paused service or private state differs')
    write(marker,{'private_file_digests':fixed(),'normal_plist_sha256':digest(service.PLIST)},mode=0o400)
    session=root/'operator-health-session-031.json'
    if resume:
        prior=json.loads((BASE/'OPERATOR-HEALTH-031.json').read_text())
        if (prior.get('status')!='failed' or prior.get('error')!='TimeoutError: stale publisher not detected' or prior.get('cleanup_errors')!=[] or
                not all(prior.get(k) is True for k in ('job_unloaded','normal_plist_restored','observer_stopped','validators_paused'))):
            raise ValueError('guarded resume requires the preserved paused stale-detection failure')
    elif os.path.lexists(session):raise ValueError('preserve existing finite health session')
    observer=None;observer_starts=0;source_stopped=False;result={'status':'failed'}
    journal=stage/'monitor';heartbeat=BASE/'health/heartbeat.json';loaded=False
    def progress(phase,**fields):
        target=BASE/('OPERATOR-HEALTH-031'+suffix+'.progress.json');temporary=target.with_suffix('.tmp')
        write(temporary,dict(phase=phase,**fields),mode=0o444);os.replace(temporary,target)
    def drop():os.setgroups([]);os.setgid(desktop_group);os.setuid(desktop);os.umask(0o077)
    def observer_start():
        nonlocal observer,observer_starts
        observer_starts+=1
        out=stage/('monitor-'+str(observer_starts)+'.stdout');err=stage/('monitor-'+str(observer_starts)+'.stderr')
        for path in (out,err):
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.fchown(fd,desktop,desktop_group);os.close(fd)
        code='import sys;sys.path.insert(0,"/Library/NativePayLocal/tools");from operator_monitor import main;main()'
        with out.open('wb') as stdout,err.open('wb') as stderr:
            observer=subprocess.Popen(['/usr/bin/python3','-I','-c',code,'watch','--journal',str(journal)],
                preexec_fn=drop,cwd=stage,env={'PATH':'/usr/bin:/bin'},stdout=stdout,stderr=stderr)
    def state():
        if observer.poll() is not None:raise ValueError('independent observer exited')
        try:return json.loads((journal/'state.json').read_text())
        except FileNotFoundError:return None
    def wait_for(predicate,seconds,message):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            value=predicate()
            if value:return value
            time.sleep(.25)
        raise TimeoutError(message)
    def ready_after(instance=None):
        try:
            h=read(heartbeat,config['uid'])
            if h['phase'] in ('failed','blocked'):raise RuntimeError('installed health failed: '+str(h['reason']))
            if h['phase']=='ready' and h['ingress_ready'] and h['validator_count']==2 and h['sampled_at'] and h['published_at']>time.time()-10 and h['instance']!=instance:
                return h
        except FileNotFoundError:pass
        return None
    def native():
        value=json.loads(service.as_service('status',config).stdout)
        if value['native_state']!=original or fixed()!=baseline['private_file_digests']:
            raise ValueError('original wallet/key/payment state changed')
        count=sum(base64.b64decode(a['data'][0])[:8]==b'NSPENT01' for a in value['native_state'].values())
        if count!=20 or len(value['native_state'])!=21:raise ValueError('original nullifier inventory differs')
        return value['slots']
    def stop_observer(crash=False):
        if observer is not None and observer.poll() is None:
            observer.kill() if crash else observer.terminate()
            try:code=observer.wait(timeout=5)
            except subprocess.TimeoutExpired:
                observer.kill();observer.wait(timeout=5);raise RuntimeError('observer graceful shutdown failed')
            if code!=(-9 if crash else 0):raise ValueError('unexpected observer exit')
    def timeout(*_):raise TimeoutError('finite health service acceptance deadline')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(600)
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGALRM})
    try:
        observer_start();wait_for(lambda:state(),15,'observer initialization deadline')
        time.sleep(2)
        if state()['events'] or state()['incident'] is not None:raise ValueError('intentional pause alerted')
        new_session={'format':'local-operator-health-test-v1','expires_at':time.time()+560}
        if resume:
            write(BASE/'OPERATOR-HEALTH-031.previous-session.json',json.loads(session.read_text()),mode=0o400)
            temporary=session.with_suffix('.recheck1.json');write(temporary,new_session,owner=owner);os.replace(temporary,session)
        else:write(session,new_session,owner=owner)
        plist['ProgramArguments'][-1]='run-health-test';service.PLIST.write_bytes(plistlib.dumps(plist))
        progress('starting_original_service')
        service.command(['/bin/launchctl','bootstrap','system',str(service.PLIST)],timeout=60);loaded=True
        first=wait_for(ready_after,210,'original service ready deadline');first_slots=native()
        wait_for(lambda:state()['ready_pid']==first['pid'] and state()['incident'] is None,10,'observer ready deadline')
        # Stop the actual supervisor/heartbeat, leaving its children running for
        # only the short stale-heartbeat detection window. Then crash that exact
        # supervised process; launchd owns coordinated child cleanup/restart.
        progress('stopping_supervisor_for_stale_detection',slots=first_slots)
        service.command(['/bin/launchctl','kill','SIGSTOP','system/'+service.LABEL],timeout=10);source_stopped=True
        incident=wait_for(lambda:(state()['incident'] if state()['incident'] and state()['incident']['code']=='heartbeat_stale' else None),25,'stale publisher not detected')
        wait_for(lambda:all(e['delivered'] for e in state()['events']),5,'local incident not delivered')
        initial_sequence=state()['next_sequence'];stop_observer(crash=True)
        observer_start();wait_for(lambda:state()['last_wall']>time.time()-4,15,'observer restart deadline')
        time.sleep(2)
        if state()['incident']!=incident or state()['next_sequence']!=initial_sequence:raise ValueError('observer restart duplicated or lost incident')
        progress('crashing_supervisor_and_recovering_original_cluster')
        service.command(['/bin/launchctl','kill','SIGKILL','system/'+service.LABEL],timeout=10);source_stopped=False
        second=wait_for(lambda:ready_after(first['instance']),210,'crash recovery readiness deadline');second_slots=native()
        wait_for(lambda:state()['incident'] is None and any(e['kind']=='recovered' for e in state()['events']),15,'observer recovery deadline')
        if min(second_slots)<=min(first_slots) or first['pid']==second['pid']:raise ValueError('restart failed to make fresh progress')
        progress('unloading_original_service_after_recovery',slots=second_slots)
        service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=110);loaded=False
        wait_for(stopped,15,'validator shutdown deadline')
        wait_for(lambda:state()['pid'] is None and state()['incident'] is None,10,'intentional pause state deadline')
        quiet_sequence=state()['next_sequence'];time.sleep(3)
        if state()['next_sequence']!=quiet_sequence:raise ValueError('paused service produced alert noise')
        stop_observer();service.PLIST.write_bytes(normal)
        if digest(service.PLIST)!=baseline['normal_plist_sha256'] or fixed()!=baseline['private_file_digests']:raise ValueError('original state changed after cleanup')
        denied=service.probe_identity(config,desktop,desktop_group)
        public=read(heartbeat,config['uid'])
        events=json.loads((journal/'state.json').read_text())['events']
        ports=[18899,19899,18898,8780,23899,24899,23898,13780,33899,34899]
        for port in ports:
            with socket.socket() as probe:
                probe.settimeout(.2)
                if probe.connect_ex(('127.0.0.1',port))==0:raise ValueError('test port remains open')
        result.update(status='passed',initial_slots=first_slots,recovered_slots=second_slots,
            actual_supervisor_sigstop_stale_detection=True,actual_supervisor_sigkill=True,
            monitor_sigkill_and_restart_preserved_incident_id=True,ready_recovery_observed=True,
            intentionally_unloaded_service_quiet=True,original_private_files_unchanged=len(baseline['private_file_digests']),
            original_native_accounts=21,permanent_nullifiers=20,payment_broadcast_commands=0,
            desktop_private_keys_raw_rpc_and_code_writes_denied=all(denied.values()),
            public_heartbeat_fields=sorted(public),monitor_events=[{k:e[k] for k in ('id','kind','code')} for e in events],
            local_delivery_only=True,observer_starts=observer_starts,sealed_runtime_manifest_sha256=expected_manifest,closed_ports=ports)
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)[:300];raise
    finally:
        signal.alarm(0)
        if source_stopped:
            subprocess.run(['/bin/launchctl','kill','SIGCONT','system/'+service.LABEL],capture_output=True,timeout=10)
        cleanup_errors=[]
        if loaded or not unloaded():
            try:service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=110)
            except Exception:cleanup_errors.append('service_unload_failed')
        try:stop_observer()
        except Exception:cleanup_errors.append('observer_shutdown_failed')
        service.PLIST.write_bytes(normal)
        result.update(validators_paused=stopped(),job_unloaded=unloaded(),normal_plist_restored=service.PLIST.read_bytes()==normal,
            observer_stopped=observer is None or observer.poll() is not None,cleanup_errors=cleanup_errors)
        if cleanup_errors or not all(result[k] for k in ('validators_paused','job_unloaded','normal_plist_restored','observer_stopped')):
            result['status']='failed'
        write(report,result,mode=0o444)
    if result['status']!='passed':raise ValueError('installed health acceptance cleanup failed')
    print(json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':main(sys.argv[1],sys.argv[2],resume=len(sys.argv)==4 and sys.argv[3]=='--resume')
