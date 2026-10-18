#!/usr/bin/env python3
"""Bounded, two-UID acknowledgement-loss acceptance on existing funded wallets."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import signal
import stat
import subprocess
import sys
import time


def fingerprint(raw):return hashlib.sha256(raw).hexdigest()


def atomic(path,data,owner=None,mode=0o600):
    temporary=path.with_name(path.name+'.new')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(json.dumps(data,sort_keys=True).encode());stream.flush();os.fsync(stream.fileno())
        if owner is not None:os.fchown(stream.fileno(),*owner)
    os.replace(temporary,path)
    directory=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(directory)
    finally:os.close(directory)


def read(path,uid):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        meta=os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=uid or meta.st_mode&0o077 or meta.st_size>16384:
            raise ValueError('unsafe bounded test coordination record')
        return json.loads(stream.read(16385))


class Channel:
    def __init__(self,path,uid):
        meta=path.lstat()
        if path.parent.resolve()!=Path('/private/tmp') or not path.name.startswith('native-ack-loss-022-') or not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=uid or meta.st_mode&0o077:
            raise ValueError('private desktop-owned temporary coordination directory required')
        self.path=path;self.uid=uid;self.nonce=path.name.removeprefix('native-ack-loss-022-')
        if len(self.nonce)!=32 or any(c not in '0123456789abcdef' for c in self.nonce):raise ValueError('invalid experiment nonce')

    def send(self,name,phase,**data):
        owner=(self.uid,pwd.getpwuid(self.uid).pw_gid) if os.geteuid()==0 else None
        atomic(self.path/(name+'.json'),dict(nonce=self.nonce,phase=phase,**data),owner)

    def wait(self,name,phase,timeout=180):
        end=time.monotonic()+timeout;path=self.path/(name+'.json')
        while time.monotonic()<end:
            if path.exists():
                data=read(path,self.uid)
                if data.get('nonce')!=self.nonce:raise ValueError('experiment nonce changed')
                if data.get('phase')=='error':raise RuntimeError('other test participant stopped: '+str(data.get('reason')))
                if data.get('phase')==phase:return data
            time.sleep(.05)
        raise TimeoutError('test coordination timed out waiting for '+phase)


def desktop(ipc,evidence,resume_waiting=False,recover_held=False):
    lock=evidence/'ack-loss-022.lock'
    fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    with os.fdopen(fd,'r+b') as owned:
        meta=os.fstat(owned.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077 or meta.st_size:
            raise ValueError('unsafe desktop participant lock')
        fcntl.flock(owned,fcntl.LOCK_EX|fcntl.LOCK_NB)
        return desktop_owned(ipc,evidence,resume_waiting,recover_held)


def desktop_owned(ipc,evidence,resume_waiting,recover_held=False):
    from service_wallet_acceptance import Acceptance
    from wallet_localnet import private_new
    from wallet_ui import WALLET
    if os.getuid()==0:raise PermissionError('desktop acceptance must not run as administrator')
    channel=Channel(ipc,os.getuid());app=Acceptance(evidence,None)
    record=evidence/'ack-loss-022.json'
    if record.exists() and not resume_waiting and not recover_held:raise ValueError('experiment already started; recover original pending identity, never resend')
    previous=read(record,os.getuid()) if record.exists() else None
    if recover_held:return desktop_recover_held(channel,app,record,previous,evidence)
    if resume_waiting and (previous is None or previous.get('phase')!='waiting'):
        raise ValueError('only an unchanged pre-send authentication wait can resume; no payment retry permitted')
    child=None;pending=Path(str(app.clients['alice'].wallet)+'.pending.json');stage=Path(str(app.clients['alice'].wallet)+'.staging.json')
    if record.exists():
        state=previous
        if (state.get('phase')!='waiting' or pending.exists() or stage.exists() or
            state.get('fingerprints')!=app.fingerprints() or (ipc/'response.json').exists()):
            raise ValueError('only an unchanged pre-send authentication wait can resume; no payment retry permitted')
        channel.send('request','waiting')
    else:
        if resume_waiting:raise ValueError('no original authentication wait exists')
        state={'phase':'waiting','fingerprints':app.fingerprints()};atomic(record,state)
    try:
        channel.wait('response','ready',600)
        end=time.monotonic()+120
        while True:
            check=subprocess.run([str(WALLET),'check','--network',str(evidence/'profile.json')],capture_output=True,text=True,timeout=20)
            if check.returncode==0:break
            if time.monotonic()>end:raise TimeoutError('original pinned HTTPS gateway did not become ready')
            time.sleep(.5)
        if pending.exists() or stage.exists():raise ValueError('existing original journal requires recovery before another experiment')
        if app.balances()!={'alice':950_000,'bob':1_050_000}:raise ValueError('funded baseline differs; no new payment submitted')
        quote=app.user('alice','fees',payment='send');recipient=app.user('bob','unlock')['address']
        state.update(phase='send_started',maximum_fee_debit=quote['maximum_gross_debit']);atomic(record,state)
        args=[str(WALLET),'send','--network',str(evidence/'profile.json'),'--wallet',str(app.clients['alice'].wallet),
            '--password-file',str(evidence/'password'),'--amount','10000','--to',recipient,'--fee-payer','user','--max-fee-debit',str(quote['maximum_gross_debit'])]
        child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,preexec_fn=lambda:os.nice(10))
        end=time.monotonic()+240
        while True:
            if pending.exists():
                try:
                    value=json.loads(pending.read_bytes())
                    if isinstance(value.get('signature'),str) and value.get('staging_account'):break
                except (OSError,ValueError):pass
            if child.poll() is not None:
                _,error=child.communicate();raise RuntimeError('send exited before pending boundary: '+error[-800:])
            if time.monotonic()>end:raise TimeoutError('original send has not reached pending boundary; do not repeat')
            time.sleep(.01)
        child.send_signal(signal.SIGSTOP)
        original=pending.read_bytes();original_stage=stage.read_bytes();target=json.loads(original)['signature']
        private_new(evidence/'ack-loss-022.pending.original.json',original)
        private_new(evidence/'ack-loss-022.staging.original.json',original_stage)
        state.update(phase='client_stopped',signature=target,pending_sha256=fingerprint(original),staging_sha256=fingerprint(original_stage));atomic(record,state)
        channel.send('request','pending',signature=target,pending_sha256=state['pending_sha256'],staging_sha256=state['staging_sha256'],client_pid=child.pid)
        armed=channel.wait('response','armed')
        if armed['signature']!=target:raise ValueError('armed gate changed original signature')
        child.send_signal(signal.SIGCONT)
        channel.send('request','resumed',signature=target)
        held=channel.wait('response','held',180)
        if held['signature']!=target or fingerprint(pending.read_bytes())!=state['pending_sha256']:raise ValueError('original pending identity changed before kill')
        child.kill();child.communicate(timeout=15)
        if child.returncode!=-9:raise ValueError('signing client was not SIGKILLed before acknowledgement')
        state['phase']='client_killed';atomic(record,state)
        channel.send('request','killed',signature=target,pending_sha256=state['pending_sha256'],staging_sha256=state['staging_sha256'],returncode=child.returncode)
        finish_desktop(channel,app,record,state,evidence,pending,stage,target,original)
    except BaseException as error:
        channel.send('request','error',reason=type(error).__name__+': '+str(error)[:700]);raise
    finally:
        if child is not None and child.poll() is None:child.kill();child.communicate(timeout=15)


def desktop_recover_held(channel,app,record,state,evidence):
    from wallet_localnet import private_new
    if not state or state.get('phase')!='client_stopped':
        raise ValueError('only the original held acknowledgement checkpoint may recover; never resend')
    pending=Path(str(app.clients['alice'].wallet)+'.pending.json');stage=Path(str(app.clients['alice'].wallet)+'.staging.json')
    original=(evidence/'ack-loss-022.pending.original.json').read_bytes()
    original_stage=(evidence/'ack-loss-022.staging.original.json').read_bytes()
    if (fingerprint(original)!=state['pending_sha256'] or pending.read_bytes()!=original or
        fingerprint(original_stage)!=state['staging_sha256'] or stage.read_bytes()!=original_stage or
        json.loads(original)['signature']!=state['signature'] or app.fingerprints()!=state['fingerprints']):
        raise ValueError('original interrupted wallet or journal changed; preserve evidence')
    # Preserve the failed participant's exact record before any recovery writes.
    private_new(evidence/'ack-loss-022.interrupted.original.json',record.read_bytes())
    target=state['signature']
    try:
        channel.wait('response','ready',600)
        channel.send('request','pending',signature=target,pending_sha256=state['pending_sha256'],staging_sha256=state['staging_sha256'],recover_held=True)
        held=channel.wait('response','held',180)
        if held['signature']!=target:raise ValueError('held original signature changed')
        channel.send('request','killed',signature=target,pending_sha256=state['pending_sha256'],staging_sha256=state['staging_sha256'],previous_client_terminated=True)
        finish_desktop(channel,app,record,state,evidence,pending,stage,target,original)
    except BaseException as error:
        channel.send('request','error',reason=type(error).__name__+': '+str(error)[:700]);raise


def finish_desktop(channel,app,record,state,evidence,pending,stage,target,original):
    from wallet_localnet import private_new
    recovered=channel.wait('response','recovered',300)
    if recovered['signature']!=target or fingerprint(pending.read_bytes())!=state['pending_sha256'] or fingerprint(stage.read_bytes())!=state['staging_sha256']:
        raise ValueError('original pending/staging journal changed across validator crash')
    state['phase']='resolving_original';atomic(record,state)
    resolution=app.user('alice','resolve')
    if resolution.get('signature')!=target or resolution.get('accepted') is not True or not resolution.get('pending_cleared'):raise ValueError('original send did not resolve as accepted')
    if resolution.get('sync',{}).get('cache_used') is not True:raise ValueError('private-send recovery did not use its authenticated checkpoint')
    reclaim=app.user('alice','reclaim') if stage.exists() else None
    if pending.exists() or stage.exists():raise ValueError('original recovery journals not cleared')
    expected={'alice':940_000,'bob':1_060_000}
    if app.balances()!=expected or app.fingerprints()!=state['fingerprints']:raise ValueError('original private balances or wallet files differ')
    # Simulate a crash after resolution writes its outcome but before its
    # journal removal persists: replay the exact saved identity, never send.
    state['phase']='replaying_original_resolution';atomic(record,state)
    private_new(pending,original)
    repeated=app.user('alice','resolve')
    if repeated.get('accepted') is not True or repeated.get('signature')!=target or pending.exists() or app.balances()!=expected:
        raise ValueError('repeated original resolution changed the payment outcome')
    for who in app.clients:
        if not app.user(who,'access-status').get('admitted') or app.user(who,'test-coins')['state']!='ready':raise ValueError('original admission/grant lost')
    security=app.security()
    state.update(phase='verified',private_balances=expected,original_signature_resolved=True,repeated_resolution_without_resubmission=True,
        pending_and_staging_recovered_unchanged=True,recovery_scan=resolution['sync'],repeated_scan=repeated.get('sync'),reclaim=reclaim,security=security)
    atomic(record,state)
    channel.send('request','verified',signature=target,private_balances=expected,repeated_resolution_without_resubmission=True,recovery_scan=state['recovery_scan'],repeated_scan=state['repeated_scan'],reclaim_close_signature=None if reclaim is None else reclaim.get('close_signature'))
    channel.wait('response','passed',180)
    state['phase']='passed';atomic(record,state)
    print(json.dumps({k:state[k] for k in ('phase','signature','private_balances','original_signature_resolved','repeated_resolution_without_resubmission','pending_and_staging_recovered_unchanged')},sort_keys=True))

def admission_identity(path):
    state=json.loads(path.read_text());invitations=json.loads(json.dumps(state['invitations']))
    for invitation in invitations:
        member=invitation.get('member')
        if member:member.pop('rpc',None);member.pop('faucet',None)
    return {'policy':state['policy'],'invitations':invitations}


def administrator(ipc,recover_held=False):
    base=Path('/Library/NativePayLocal');sys.path.insert(0,str(base/'tools'))
    import service_account as service
    service.require_root();config=service.verify_install();channel=Channel(ipc,config['desktop_uid']);root=base/'.data/s20'
    started=base/'ACK-LOSS-022.started.json';report=base/'ACK-LOSS-022.json'
    if report.exists() or (started.exists() and not recover_held):raise ValueError('test already started; retain original crash/payment checkpoint')
    interrupted=json.loads(started.read_text()) if recover_held else None
    if recover_held and (interrupted.get('phase')!='starting' or (base/'ACK-LOSS-022.resume.started.json').exists()):
        raise ValueError('only the original pre-crash held-checkpoint failure may resume once')
    service.trusted(service.PLIST);original_plist=service.PLIST.read_bytes();plist=plistlib.loads(original_plist)
    if plist['ProgramArguments'][-1]!='run':raise ValueError('original normal service configuration required')
    active=subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True,text=True)
    if active.returncode!=113:raise ValueError('validators must be paused before this bounded experiment')
    if not recover_held and (root/'gateway-ack-test-022.json').exists():raise ValueError('original gate already exists; never rearm another payment')
    if not recover_held and (root/'gateway-ack-broadcasts-022.json').exists():raise ValueError('original broadcast evidence already exists; preserve it')
    def status():return json.loads(service.as_service('status',config).stdout)
    def canonical_hash(state):return fingerprint(json.dumps(state,sort_keys=True).encode())
    def files(include_admission=False):
        names=['rpc-access.key','client-profile.json','faucet/claims.json','faucet/wallet.enc.json','sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json']
        if include_admission:names+=['faucet/admission.json','gateway-ack-broadcasts-022.json']
        names+=[p.name for p in root.glob('*.keypair.json')]
        return {name:fingerprint((root/name).read_bytes()) for name in names}
    def wait_status(predicate,timeout=240):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            try:data=status()
            except subprocess.CalledProcessError:time.sleep(1);continue
            if predicate(data):return data
            time.sleep(.5)
        raise TimeoutError('original service did not reach required canonical checkpoint')
    def restore_plist():
        fd=os.open(service.PLIST,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
        with os.fdopen(fd,'wb') as stream:stream.write(original_plist);stream.flush();os.fsync(stream.fileno())
    checkpoint={'phase':'starting','original_plist_sha256':fingerprint(original_plist),'files':files()}
    if recover_held:
        if interrupted['files']!=checkpoint['files'] or interrupted['original_plist_sha256']!=checkpoint['original_plist_sha256']:
            raise ValueError('original keys, claims, budget or service configuration changed')
        gate=json.loads((root/'gateway-ack-test-022.json').read_text())
        if gate.get('phase')!='held':raise ValueError('original authentic finalized acknowledgement was not held')
        commands=service.command(['/bin/ps','-U',str(config['desktop_uid']),'-o','comm=']).stdout.splitlines()
        if any(Path(command.strip()).name=='native-wallet' for command in commands):
            raise ValueError('original desktop signing process must have terminated before held recovery')
        started=base/'ACK-LOSS-022.resume.started.json'
        checkpoint['prior_interruption']='checkpoint RPC routes were not initialized; original client killed and service stopped by cleanup'
    atomic(started,checkpoint,mode=0o400)
    before_identity=admission_identity(root/'faucet/admission.json');result=None
    try:
        atomic(root/'gateway-ack-session-022.json',{'format':'local-gateway-ack-test-v1','expires_at':time.time()+600},owner=(config['uid'],config['gid']))
        plist['ProgramArguments'][-1]='run-ack-test'
        fd=os.open(service.PLIST,os.O_WRONLY|os.O_TRUNC|os.O_NOFOLLOW)
        with os.fdopen(fd,'wb') as stream:stream.write(plistlib.dumps(plist));stream.flush();os.fsync(stream.fileno())
        service.command(['/bin/launchctl','bootstrap','system',str(service.PLIST)],timeout=60)
        baseline=wait_status(lambda s:min(s['slots'])>0)
        if len(baseline['native_state'])!=(15 if recover_held else 13):raise ValueError('expected original twelve-nullifier baseline')
        denied_before=service.probe_identity(config,config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid)
        channel.send('response','ready')
        pending=channel.wait('request','pending',300);target=pending['signature']
        if recover_held:
            if not pending.get('recover_held') or pending['signature']!=gate['signature']:
                raise ValueError('recovery changed the original held identity')
        else:
            arm=json.loads(service.as_service('ack-arm',config,(target,)).stdout)
            if arm['signature']!=target:raise ValueError('service armed different transaction')
            channel.send('response','armed',signature=target)
            resumed=channel.wait('request','resumed',45)
            if resumed['signature']!=target:raise ValueError('resumed client identity changed')
        end=time.monotonic()+180
        while True:
            gate=json.loads((root/'gateway-ack-test-022.json').read_text())
            if gate.get('phase')=='held':break
            if time.monotonic()>end:raise TimeoutError('real finalized acknowledgement never reached test gate')
            request=read(ipc/'request.json',config['desktop_uid'])
            if request.get('phase')=='error':raise RuntimeError('desktop stopped before finalized acknowledgement')
            time.sleep(.05)
        end=time.monotonic()+20
        while True:
            try:accepted=json.loads(service.as_service('ack-checkpoint',config).stdout);break
            except subprocess.CalledProcessError:
                if time.monotonic()>end:raise
                time.sleep(.2)
        if accepted['signature']!=target or len(accepted['native_state'])!=15:raise ValueError('expected exact finalized send and fourteen nullifiers')
        old_markers={k:v for k,v in baseline['native_state'].items() if base64.b64decode(v['data'][0])[:8]==b'NSPENT01'}
        if any(accepted['native_state'].get(k)!=v for k,v in old_markers.items()):raise ValueError('original permanent nullifier changed')
        if files()!=checkpoint['files']:raise ValueError('service keys, claims or sponsor budget changed while desktop paid fees')
        crash_files=files(True);instance=json.loads((root/'service-instance.json').read_text())
        original_attempts=json.loads((root/'gateway-ack-broadcasts-022.json').read_text())['attempts']
        if not original_attempts or any(a.get('signature') is None for a in original_attempts):raise ValueError('incomplete original broadcast attempt evidence')
        checkpoint.update(phase='held',signature=target,pending_sha256=pending['pending_sha256'],staging_sha256=pending['staging_sha256'],
            native_state_sha256=canonical_hash(accepted['native_state']),slots=accepted['slots'],instance=instance,crash_files=crash_files,gate=accepted['gate'])
        atomic(started,checkpoint,mode=0o400)
        channel.send('response','held',signature=target)
        killed=channel.wait('request','killed',45)
        client_terminated=killed.get('previous_client_terminated') is True if recover_held else killed.get('returncode')==-9
        if killed.get('signature')!=target or not client_terminated or killed.get('pending_sha256')!=pending['pending_sha256'] or killed.get('staging_sha256')!=pending['staging_sha256']:
            raise ValueError('original signing-client crash evidence differs')
        service.command(['/bin/launchctl','kill','SIGKILL','system/'+service.LABEL],timeout=30)
        def replaced(data):
            current=json.loads((root/'service-instance.json').read_text())
            return current['supervisor']!=instance['supervisor'] and not (set(current['validators'])&set(instance['validators'])) and min(data['slots'])>max(accepted['slots'])+8
        recovered=wait_status(replaced)
        current=json.loads((root/'service-instance.json').read_text())
        if set(current['process_groups'])!={os.getpgid(current['supervisor'])}:raise ValueError('validator escaped owned process group')
        if canonical_hash(recovered['native_state'])!=checkpoint['native_state_sha256'] or files(True)!=crash_files:
            raise ValueError('original native state, keys, admission quota or claims changed during restart')
        denied_after=service.probe_identity(config,config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid)
        channel.send('response','recovered',signature=target)
        verified=channel.wait('request','verified',240)
        if verified.get('signature')!=target or verified.get('private_balances')!={'alice':940_000,'bob':1_060_000} or verified.get('repeated_resolution_without_resubmission') is not True or verified.get('recovery_scan',{}).get('cache_used') is not True:
            raise ValueError('original client resolution evidence differs')
        final=status()
        if canonical_hash(final['native_state'])!=checkpoint['native_state_sha256'] or files()!=checkpoint['files'] or admission_identity(root/'faucet/admission.json')!=before_identity:
            raise ValueError('resolution, reclaim or journal replay changed native effects, grants or service budget')
        attempts=json.loads((root/'gateway-ack-broadcasts-022.json').read_text())['attempts']
        subsequent=attempts[len(original_attempts):];close=verified.get('reclaim_close_signature')
        if attempts[:len(original_attempts)]!=original_attempts or len(subsequent)!=(0 if close is None else 1) or (close is not None and subsequent[0].get('signature')!=close):
            raise ValueError('recovery broadcast a replacement/repeated payment instead of only original staging cleanup')
        result={'status':'passed','original_signature':target,'private_balances':verified['private_balances'],'permanent_nullifiers':14,
            'real_finalized_acknowledgement_withheld':True,'signing_client_sigkill':not recover_held,'interrupted_client_terminated_by_prior_failure_cleanup':recover_held,
            'orderly_cleanup_before_crash_test':recover_held,'supervisor_and_both_validators_replaced':True,
            'original_pending_and_staging_hashes':{'pending':pending['pending_sha256'],'staging':pending['staging_sha256']},
            'pool_nullifiers_keys_claims_sponsor_and_admission_preserved':True,'repeated_original_resolution_without_resubmission':True,
            'recovery_scan':verified['recovery_scan'],'repeated_scan':verified.get('repeated_scan'),
            'recovery_broadcasts':len(subsequent),'only_original_staging_cleanup_broadcast':close is not None,'replacement_or_repeated_send_broadcast':False,
            'desktop_denied_before':denied_before,'desktop_denied_after':denied_after,'new_finalized_slots':recovered['slots']}
    except BaseException as error:
        channel.send('response','error',reason=type(error).__name__+': '+str(error)[:700]);raise
    finally:
        try:
            loaded=subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True,text=True)
            if loaded.returncode==0:service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=120)
        finally:restore_plist()
    if result is None:raise ValueError('no completed acceptance')
    result.update(validators_paused_after_test=True,normal_service_plist_restored=service.PLIST.read_bytes()==original_plist)
    atomic(report,result,mode=0o444);channel.send('response','passed')
    print(json.dumps(result,sort_keys=True))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('role',choices=['desktop','administrator'])
    parser.add_argument('--ipc',type=Path,required=True);parser.add_argument('--evidence',type=Path)
    parser.add_argument('--resume-waiting',action='store_true',help='resume only an unchanged wait before the first signing process exists')
    parser.add_argument('--recover-held',action='store_true',help='recover the exact original held payment after checkpoint-command failure; never starts send')
    args=parser.parse_args()
    if args.recover_held and args.resume_waiting:parser.error('recovery modes are mutually exclusive')
    if args.role=='desktop':
        if args.evidence is None:parser.error('desktop role requires original funded wallet evidence')
        desktop(args.ipc,args.evidence.resolve(),args.resume_waiting,args.recover_held)
    else:administrator(args.ipc,args.recover_held)


if __name__=='__main__':main()
