"""Finite installed public explorer acceptance. Never initializes wallet/chain state."""
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import signal
import socket
import stat
import subprocess
import sys
import time

BASE=Path('/Library/NativePayLocal')
if __name__=='__main__':sys.path.insert(0,str(BASE/'tools'))
import service_account as service
from explorer_feed import read as read_feed
from operator_health import read as read_health


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path,value,mode=0o444,owner=None):
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
    report=BASE/('EXPLORER-LIVE-039'+suffix+'.json');marker=BASE/('EXPLORER-LIVE-039'+suffix+'.started.json')
    if report.exists() or marker.exists():raise ValueError('preserve existing explorer acceptance evidence')
    normal=service.PLIST.read_bytes();plist=plistlib.loads(normal)
    baseline=json.loads((BASE/'HISTORY-REPLICA-030.started.json').read_text())
    original=json.loads((root/'replica-evidence-030/initial-live.json').read_text())['native_state']
    public=json.loads((root/'network.json').read_text());network={k:public[k] for k in ('network','genesis_hash')}
    def unloaded():return subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode==113
    def stopped():return subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1
    def fixed():return {name:digest(root/name) for name in baseline['private_file_digests']}
    if not unloaded() or not stopped() or plist['ProgramArguments'][-1]!='run' or digest(service.PLIST)!=baseline['normal_plist_sha256'] or fixed()!=baseline['private_file_digests']:
        raise ValueError('original paused service or private state differs')
    write(marker,{'private_file_digests':fixed(),'normal_plist_sha256':digest(service.PLIST)},mode=0o400)
    session=root/'explorer-live-session-039.json'
    if resume:
        prior=json.loads((BASE/'EXPLORER-LIVE-039.json').read_text())
        if (prior.get('status')!='failed' or prior.get('error')!='TimeoutError: desktop browser observation deadline' or prior.get('cleanup_errors')!=[] or
                not all(prior.get(k) is True for k in ('job_unloaded','normal_plist_restored','validators_paused'))):
            raise ValueError('guarded resume requires the preserved paused observation timeout')
    elif os.path.lexists(session):raise ValueError('preserve existing finite explorer session')
    result={'status':'failed'};loaded=False;first=None
    def progress(phase,**fields):
        target=BASE/('EXPLORER-LIVE-039'+suffix+'.progress.json');temporary=target.with_suffix('.tmp')
        write(temporary,dict(phase=phase,**fields));os.replace(temporary,target)
    def wait_for(predicate,seconds,message):
        deadline=time.monotonic()+seconds
        while time.monotonic()<deadline:
            value=predicate()
            if value:return value
            time.sleep(.25)
        raise TimeoutError(message)
    def ready_after(instance=None):
        try:
            h=read_health(BASE/'health/heartbeat.json',config['uid'])
            if h['phase'] in ('failed','blocked'):raise RuntimeError('installed service failed: '+str(h['reason']))
            if h['phase']!='ready' or not h['ingress_ready'] or h['validator_count']!=2 or h['published_at']<time.time()-10 or h['instance']==instance:return None
            f=read_feed(BASE/'health/explorer.json',config['uid'],network)
            if f['phase']=='live' and time.time()-10<=f['sampled_at']<=time.time() and (first is None or f['instance']!=first['instance']):return h,f
        except FileNotFoundError:pass
        return None
    def native():
        value=json.loads(service.as_service('status',config).stdout)
        if value['native_state']!=original or fixed()!=baseline['private_file_digests']:raise ValueError('original wallet/key/payment state changed')
        count=sum(base64.b64decode(a['data'][0])[:8]==b'NSPENT01' for a in value['native_state'].values())
        if count!=20 or len(value['native_state'])!=21:raise ValueError('original nullifier inventory differs')
        return value['slots']
    def desktop_ack(name,tip):
        # Desktop acknowledgement can only shorten a fixed observation window;
        # it supplies no paths, commands, private data or service configuration.
        def found():
            path=stage/name
            try:
                with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
                    m=os.fstat(stream.fileno())
                    if not stat.S_ISREG(m.st_mode) or m.st_uid!=desktop or not 0<m.st_size<=1024:raise ValueError('invalid desktop observation')
                    value=json.loads(stream.read(1025))
                return value=={'observed':True,'genesis_hash':network['genesis_hash'],'minimum_slot':tip}
            except FileNotFoundError:return False
        return wait_for(found,90,'desktop portal observation deadline')
    def timeout(*_):raise TimeoutError('finite explorer service acceptance deadline')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(560)
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGALRM})
    try:
        new_session={'format':'local-explorer-live-test-v1','expires_at':time.time()+550}
        if resume:
            write(BASE/'EXPLORER-LIVE-039.previous-session.json',json.loads(session.read_text()),mode=0o400)
            temporary=session.with_suffix('.recheck1.json');write(temporary,new_session,mode=0o600,owner=owner);os.replace(temporary,session)
        else:write(session,new_session,mode=0o600,owner=owner)
        plist['ProgramArguments'][-1]='run-explorer-test';service.PLIST.write_bytes(plistlib.dumps(plist))
        progress('starting_original_service')
        service.command(['/bin/launchctl','bootstrap','system',str(service.PLIST)],timeout=60);loaded=True
        h,first=wait_for(ready_after,190,'original live explorer deadline');first_slots=native()
        write(stage/'first-feed.json',first)
        tip=first['blocks'][-1]['slot'];progress('awaiting_first_portal',tip=tip,instance=first['instance'])
        desktop_ack('desktop-first.json',tip)
        progress('crashing_supervisor_and_recovering')
        service.command(['/bin/launchctl','kill','SIGKILL','system/'+service.LABEL],timeout=10)
        recovered,second=wait_for(lambda:ready_after(h['instance']),190,'explorer crash recovery deadline');second_slots=native()
        old={b['slot']:b for b in first['blocks']};new={b['slot']:b for b in second['blocks']}
        if any(new[s]!=b for s,b in old.items() if s in new) or tip not in new or second['sequence']<=first['sequence'] or second['blocks'][-1]['slot']<=tip or h['pid']==recovered['pid']:
            raise ValueError('finalized explorer checkpoint changed or did not advance')
        write(stage/'recovered-feed.json',second)
        tip2=second['blocks'][-1]['slot'];progress('awaiting_recovered_portal',tip=tip2,instance=second['instance'])
        desktop_ack('desktop-recovered.json',tip2)
        progress('pausing_original_service')
        service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=110);loaded=False
        wait_for(stopped,15,'validator shutdown deadline');service.PLIST.write_bytes(normal)
        if fixed()!=baseline['private_file_digests'] or digest(service.PLIST)!=baseline['normal_plist_sha256']:raise ValueError('original private state changed after cleanup')
        denied=service.probe_identity(config,desktop,desktop_group)
        final=read_feed(BASE/'health/explorer.json',config['uid'],network)
        if final['phase']!='paused':raise ValueError('public explorer pause was not published')
        ports=[23899,24899,23898,13780]
        for port in ports:
            with socket.socket() as probe:
                probe.settimeout(.2)
                if probe.connect_ex(('127.0.0.1',port))==0:raise ValueError('service port remains open')
        result.update(status='passed',genesis_hash=network['genesis_hash'],initial_slots=first_slots,recovered_slots=second_slots,
            first_explorer_tip=first['blocks'][-1]['slot'],recovered_explorer_tip=second['blocks'][-1]['slot'],
            actual_supervisor_sigkill=True,canonical_checkpoint_rechecked=True,public_feed_restart_continuity=True,
            original_private_files_unchanged=len(baseline['private_file_digests']),original_native_accounts=21,permanent_nullifiers=20,
            payment_broadcast_commands=0,desktop_private_keys_raw_rpc_and_code_writes_denied=all(denied.values()),
            final_feed_phase=final['phase'],sealed_runtime_manifest_sha256=expected_manifest,closed_service_ports=ports)
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)[:300];raise
    finally:
        signal.alarm(0);cleanup_errors=[]
        if loaded or not unloaded():
            try:service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=110)
            except Exception:cleanup_errors.append('service_unload_failed')
        service.PLIST.write_bytes(normal)
        result.update(validators_paused=stopped(),job_unloaded=unloaded(),normal_plist_restored=service.PLIST.read_bytes()==normal,cleanup_errors=cleanup_errors)
        if cleanup_errors or not all(result[k] for k in ('validators_paused','job_unloaded','normal_plist_restored')):result['status']='failed'
        write(report,result)
        progress('complete' if result['status']=='passed' else 'failed')
    if result['status']!='passed':raise ValueError('installed explorer acceptance cleanup failed')
    print(json.dumps(result,sort_keys=True),flush=True)


if __name__=='__main__':main(sys.argv[1],sys.argv[2],resume=len(sys.argv)==4 and sys.argv[3]=='--resume')
