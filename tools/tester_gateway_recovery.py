#!/usr/bin/env python3
"""Extracted-package update and original-journal recovery; never submits a payment."""
import argparse
import json
import os
from pathlib import Path
import plistlib
import pwd
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from gateway_ack_loss import Channel,atomic,fingerprint,admission_identity

# This worker imports only the extracted, integrity-verified runtime. Passwords
# arrive on stdin and never appear in argv, environment, or the result record.
WORKER='''import sys,json
from pathlib import Path
sys.dont_write_bytecode=True
bundle=Path(sys.argv[1]);sys.path.insert(0,str(bundle/'runtime'))
import wallet_launch,wallet_ui
manifest=wallet_launch.verify(bundle)
request=json.load(sys.stdin)
app=wallet_ui.WalletApp.from_profile(bundle/'wallet-profile.json',Path(sys.argv[2]),binary=bundle/'bin/native-wallet')
try:
 result=app.status() if request.get('action')=='status' else app.action(request)
 output={'ok':True,'result':result}
except (ValueError,OSError) as error:output={'ok':False,'error':str(error)[:800]}
output.update(runtime=str(Path(wallet_ui.__file__).resolve()),binary=str(app.binary),source_commit=manifest['source_commit'])
print(json.dumps(output))
'''


def packaged(bundle,state,request):
    if request.get('action') not in ('status','resolve','reclaim','balance','access-status','test-coins'):
        raise ValueError('package acceptance cannot submit a new payment or invitation')
    command=[sys.executable,'-I','-B','-c',WORKER,str(bundle),str(state)]
    result=subprocess.run(command,input=json.dumps(request),capture_output=True,text=True,timeout=240,cwd='/private/tmp')
    if result.returncode:raise RuntimeError('extracted runtime failed: '+result.stderr[-1000:])
    value=json.loads(result.stdout)
    if value['runtime']!=str(bundle/'runtime/wallet_ui.py') or value['binary']!=str(bundle/'bin/native-wallet'):
        raise ValueError('acceptance did not use the extracted runtime and binary')
    return value


def files(root):
    return {p.relative_to(root).as_posix():fingerprint(p.read_bytes()) for p in root.rglob('*') if p.is_file()}


def extract(archive,destination):
    destination.mkdir(mode=0o700,exist_ok=True)
    with tarfile.open(archive) as tar:tar.extractall(destination,filter='data')
    bundle=destination/'native-wallet'
    subprocess.run(['sh',str(bundle/'start-wallet.command'),'--verify'],check=True,capture_output=True,text=True,timeout=30)
    return bundle


def stage_journals(client,source,evidence):
    # Copy only encrypted client state; original funded wallets remain untouched.
    from wallet_localnet import private_new
    if any((client/'wallet-ui'/('wallet.json.'+name+'.json')).exists() for name in ('pending','staging')):
        raise ValueError('copied client already has an unknown payment; never replace its journals')
    names={'pending':'ack-loss-022.pending.original.json','staging':'ack-loss-022.staging.original.json'}
    expected=json.loads((source/'ack-loss-022.json').read_text())
    if expected['phase']!='passed':raise ValueError('original gateway recovery must already have passed')
    originals={name:(source/path).read_bytes() for name,path in names.items()}
    for name,raw in originals.items():
        if fingerprint(raw)!=expected[name+'_sha256']:raise ValueError('saved original journal differs from accepted evidence')
    if json.loads(originals['pending'])['signature']!=expected['signature']:raise ValueError('original signature differs')
    for name,raw in originals.items():private_new(client/'wallet-ui'/('wallet.json.'+name+'.json'),raw)
    atomic(evidence/'journal-injection.json',{'signature':expected['signature'],'hashes':{name:fingerprint(raw) for name,raw in originals.items()},'fault_injection_only':True})
    return expected['signature']


def desktop(ipc,evidence,archive,baseline,source):
    if os.getuid()==0:raise PermissionError('desktop participant requires the desktop UID')
    if evidence.exists():raise ValueError('use a new evidence directory; recover existing journals explicitly')
    evidence.mkdir(mode=0o700);channel=Channel(ipc,os.getuid())
    original_files=files(source);password=(source/'password').read_text()
    try:
        profile=json.loads((source/'profile.json').read_text())
        current=extract(archive,evidence/'updated')
        if json.loads((current/'wallet-profile.json').read_text())!=profile:raise ValueError('updated bundle changed the existing pinned profile')
        asset=current/'assets/app.js';original_asset=asset.read_bytes();asset.write_bytes(original_asset+b'\nmodified')
        try:
            if subprocess.run(['sh',str(current/'start-wallet.command'),'--verify'],capture_output=True,timeout=30).returncode==0:
                raise ValueError('extracted launcher accepted modified package contents')
        finally:asset.write_bytes(original_asset)
        for extra in (['--rpc','http://127.0.0.1:24899'],['--sponsor','missing-operator-key']):
            rejected=subprocess.run([str(current/'bin/native-wallet'),'check','--network',str(current/'wallet-profile.json'),*extra],capture_output=True,text=True,timeout=30)
            if rejected.returncode==0 or not any(word in rejected.stderr for word in ('forbidden','no operator sponsorship')):
                raise ValueError('extracted binary did not reject operator or RPC overrides before network access')
        # Rebind the old local package's PUBLIC profile for this update fixture.
        # Its old executable/runtime/assets remain unchanged; no release claim.
        old=extract(baseline,evidence/'previous')
        manifest_path=old/'MANIFEST.json';manifest=json.loads(manifest_path.read_text())
        raw=(current/'wallet-profile.json').read_bytes();(old/'wallet-profile.json').write_bytes(raw)
        manifest['files']['wallet-profile.json']={'size':len(raw),'sha256':fingerprint(raw)}
        manifest['local_update_fixture_profile_rebound']=True;manifest_path.write_text(json.dumps(manifest))
        subprocess.run(['sh',str(old/'start-wallet.command'),'--verify'],check=True,capture_output=True,timeout=30)
        for who in ('alice','bob'):
            shutil.copytree(source/(who+'-client'),evidence/(who+'-client'))
        client=evidence/'alice-client';target=stage_journals(client,source,evidence)
        before=files(client)
        previous=packaged(old,client,{'action':'status'})
        if not previous.get('ok') or not previous['result']['pending'] or not previous['result']['staging']:
            raise ValueError('previous standalone bundle did not recognize original pending journals')
        updated=packaged(current,client,{'action':'status'})
        if not updated.get('ok') or updated['result']!=previous['result'] or files(client)!=before:
            raise ValueError('package update changed the original wallet or recovery journals')
        offline=packaged(current,client,{'action':'resolve','password':password})
        if offline.get('ok') or files(client)!=before:raise ValueError('offline resolution must fail with the exact original state retained')
        # Actually replace the package directory and restart its own launcher.
        shutil.rmtree(old)
        replacement=extract(archive,evidence/'previous')
        with socket.socket() as probe:probe.bind(('127.0.0.1',8773))
        launcher=subprocess.Popen(['sh',str(replacement/'start-wallet.command'),'--no-browser','--data-dir',str(client),'--port','8773','--duration','60'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True,cwd='/private/tmp')
        try:
            end=time.monotonic()+10
            while True:
                if launcher.poll() is not None:raise ValueError('replaced package launcher did not stay running')
                try:
                    with socket.create_connection(('127.0.0.1',8773),timeout=.2):break
                except OSError:
                    if time.monotonic()>end:raise ValueError('replaced package did not open its local listener')
                    time.sleep(.1)
            if files(client)!=before:raise ValueError('launcher restart changed encrypted state or journals')
        finally:
            if launcher.poll() is None:launcher.terminate()
            launcher.communicate(timeout=15)
        if files(source)!=original_files:raise ValueError('original client evidence changed during package preparation')
        atomic(evidence/'state.json',{'phase':'offline_passed','signature':target,'archive_sha256':fingerprint(archive.read_bytes()),'original_files':original_files,'client_before':before})
        channel.send('request','package_ready',signature=target,journal_hashes=json.loads((evidence/'journal-injection.json').read_text())['hashes'])
        channel.wait('response','recovered',600)
        health=subprocess.run(['sh',str(replacement/'start-wallet.command'),'--check'],check=True,capture_output=True,text=True,timeout=30)
        results={}
        for action in ('resolve','reclaim'):
            value=packaged(replacement,client,{'action':action,'password':password})
            if not value.get('ok'):raise ValueError('packaged '+action+' failed: '+value.get('error',''))
            results[action]=value['result']
        resolved=results['resolve']
        if resolved.get('signature')!=target or resolved.get('accepted') is not True or not resolved.get('pending_cleared') or resolved.get('sync',{}).get('cache_used') is not True:
            raise ValueError('extracted package did not resolve original identity with verified cache')
        if results['reclaim'].get('close_signature'):raise ValueError('already-closed original staging account broadcast another cleanup')
        balances={};gas={}
        for who in ('alice','bob'):
            state=evidence/(who+'-client')
            result=packaged(replacement,state,{'action':'balance','password':password})
            if not result.get('ok'):raise ValueError('packaged balance failed')
            balances[who]=result['result']['balance'];gas[who]=result['result']['public_balance']
            for action in ('access-status','test-coins'):
                value=packaged(replacement,state,{'action':action,'password':password})
                if not value.get('ok') or (action=='access-status' and not value['result'].get('admitted')) or (action=='test-coins' and value['result'].get('state')!='ready'):
                    raise ValueError('existing invitation or grant not recovered by extracted runtime')
        if balances!={'alice':940000,'bob':1060000}:raise ValueError('packaged recovery changed private payment effects')
        for who in ('alice','bob'):
            for name in ('wallet.json','recovery.json','backup-confirmed'):
                if (source/(who+'-client')/'wallet-ui'/name).read_bytes()!=(evidence/(who+'-client')/'wallet-ui'/name).read_bytes():raise ValueError('packaged recovery changed encrypted wallet or backup')
        for name in ('pending','staging'):
            if (client/'wallet-ui'/('wallet.json.'+name+'.json')).exists():raise ValueError('original journal not cleared')
        if files(source)!=original_files:raise ValueError('original funded desktop state changed')
        result={'phase':'verified','signature':target,'private_balances':balances,'public_gas':gas,'resolution':resolved,'reclaim':results['reclaim'],'offline_failure_preserved_state':True,'update_preserved_pending_wallet_and_backups':True,'original_desktop_state_unchanged':True,'package_check':json.loads(health.stdout),'runtime':str(replacement/'runtime/wallet_ui.py'),'binary':str(replacement/'bin/native-wallet')}
        atomic(evidence/'result.json',result)
        channel.send('request','verified',signature=target,private_balances=balances,recovery_scan=resolved['sync'])
        channel.wait('response','passed',180)
        result['phase']='passed';atomic(evidence/'result.json',result)
        print(json.dumps({k:result[k] for k in ('phase','private_balances','offline_failure_preserved_state','update_preserved_pending_wallet_and_backups','original_desktop_state_unchanged')}))
    except BaseException as error:
        channel.send('request','error',reason=type(error).__name__+': '+str(error)[:700]);raise


def administrator(ipc):
    base=Path('/Library/NativePayLocal');sys.path.insert(0,str(base/'tools'))
    import service_account as service
    service.require_root();config=service.verify_install();root=base/'.data/s20';channel=Channel(ipc,config['desktop_uid'])
    started=base/'PACKAGE-RECOVERY-023.started.json';report=base/'PACKAGE-RECOVERY-023.json'
    if started.exists() or report.exists():raise ValueError('package recovery already started; retain its original record')
    attempted=root/'package-recovery-broadcast-attempt-023.json'
    if os.path.lexists(attempted):raise ValueError('preserve original package broadcast-attempt evidence')
    original=service.PLIST.read_bytes();plist=plistlib.loads(original)
    if plist['ProgramArguments'][-1]!='run' or subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode!=113:
        raise ValueError('original normal service must be paused before package test')
    historical=(base/'ACK-LOSS-022.json').read_bytes();accepted=json.loads(historical)
    ready=channel.wait('request','package_ready',600)
    if ready['signature']!=accepted['original_signature'] or ready['journal_hashes']!=accepted['original_pending_and_staging_hashes']:
        raise ValueError('package must recover the exact originally accepted journal identity')
    def state():return json.loads(service.as_service('status',config).stdout)
    def pinned(include_usage=True):
        paths=['rpc-access.key','client-profile.json','faucet/claims.json','faucet/wallet.enc.json','sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json','gateway-ack-test-022.json','gateway-ack-broadcasts-022.json']
        paths+=[p.name for p in root.glob('*.keypair.json')]
        if include_usage:paths+=['faucet/admission.json']
        return {n:fingerprint((root/n).read_bytes()) for n in paths}
    def wait(predicate):
        end=time.monotonic()+240
        while time.monotonic()<end:
            try:value=state()
            except subprocess.CalledProcessError:time.sleep(.5);continue
            if predicate(value):return value
            time.sleep(.5)
        raise TimeoutError('original service did not reach package recovery checkpoint')
    before=pinned();identity=admission_identity(root/'faucet/admission.json');result=None
    atomic(started,{'phase':'starting','files':before,'original_plist_sha256':fingerprint(original)},mode=0o400)
    try:
        atomic(root/'package-recovery-session-023.json',{'format':'local-package-recovery-test-v1','expires_at':time.time()+600},owner=(config['uid'],config['gid']))
        plist['ProgramArguments'][-1]='run-package-test';service.PLIST.write_bytes(plistlib.dumps(plist))
        service.command(['/bin/launchctl','bootstrap','system',str(service.PLIST)],timeout=60)
        baseline=wait(lambda s:min(s['slots'])>0)
        if len(baseline['native_state'])!=15:raise ValueError('expected original fourteen-nullifier state')
        instance=json.loads((root/'service-instance.json').read_text())
        denied_before=service.probe_identity(config,config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid)
        atomic(started,{'phase':'crashing','files':before,'original_plist_sha256':fingerprint(original),'native_state':baseline['native_state'],'instance':instance,'slots':baseline['slots']},mode=0o400)
        service.command(['/bin/launchctl','kill','SIGKILL','system/'+service.LABEL],timeout=30)
        def replaced(value):
            new=json.loads((root/'service-instance.json').read_text())
            return new['supervisor']!=instance['supervisor'] and not(set(new['validators'])&set(instance['validators'])) and min(value['slots'])>max(baseline['slots'])+8
        recovered=wait(replaced);new=json.loads((root/'service-instance.json').read_text())
        if recovered['native_state']!=baseline['native_state'] or pinned()!=before or set(new['process_groups'])!={os.getpgid(new['supervisor'])}:
            raise ValueError('package-test restart changed original native state or private files')
        denied_after=service.probe_identity(config,config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid)
        channel.send('response','recovered')
        verified=channel.wait('request','verified',300)
        final=state()
        if verified['signature']!=ready['signature'] or verified['private_balances']!={'alice':940000,'bob':1060000} or not verified['recovery_scan']['cache_used']:
            raise ValueError('extracted package recovery evidence differs')
        expected={n:v for n,v in before.items() if n!='faucet/admission.json'}
        if os.path.lexists(attempted) or pinned(False)!=expected or final['native_state']!=baseline['native_state'] or admission_identity(root/'faucet/admission.json')!=identity or (base/'ACK-LOSS-022.json').read_bytes()!=historical:
            raise ValueError('packaged recovery changed native effects, keys, grants, historical evidence or budgets')
        result={'status':'passed','private_balances':verified['private_balances'],'permanent_nullifiers':14,'broadcast_attempts':0,'journal_replay_only_no_new_send':True,'supervisor_and_both_validators_replaced':True,'original_keys_claims_budgets_and_native_state_unchanged':True,'desktop_denied_before':denied_before,'desktop_denied_after':denied_after,'recovery_scan':verified['recovery_scan'],'new_finalized_slots':recovered['slots']}
    except BaseException as error:
        channel.send('response','error',reason=type(error).__name__+': '+str(error)[:700]);raise
    finally:
        try:
            if subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode==0:
                service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=120)
        finally:service.PLIST.write_bytes(original)
    result.update(validators_paused_after_test=True,normal_service_plist_restored=service.PLIST.read_bytes()==original)
    atomic(report,result,mode=0o444);channel.send('response','passed');print(json.dumps(result,sort_keys=True))


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('role',choices=['desktop','administrator']);p.add_argument('--ipc',type=Path,required=True)
    for name in ('evidence','archive','baseline','source'):p.add_argument('--'+name,type=Path)
    args=p.parse_args()
    if args.role=='administrator':administrator(args.ipc)
    else:
        if any(getattr(args,n) is None for n in ('evidence','archive','baseline','source')):p.error('desktop requires evidence/archive/baseline/source')
        desktop(args.ipc,args.evidence.resolve(),args.archive.resolve(),args.baseline.resolve(),args.source.resolve())


if __name__=='__main__':main()
