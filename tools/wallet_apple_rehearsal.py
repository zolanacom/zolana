"""Finite local Apple preparation crash acceptance; no Apple service calls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def worker(stage,point):
    sys.path.insert(0,str(stage/'verifier'))
    import wallet_apple as apple
    from wallet_release import create,encode
    def checkpoint(current):
        if current==point:
            create(stage/('checkpoint-'+point+'.json'),encode({'point':point,'pid':os.getpid()}))
            os.kill(os.getpid(),signal.SIGSTOP)
    source=json.loads((stage/'input.json').read_text());root=stage/'preparation'
    if point=='mounted':
        with apple.mounted_payload(root,checkpoint):pass
    elif point=='submission_unknown':
        from apple_notary_handoff import Handoff
        _,receipt=apple.verify(root);handoff=Handoff(stage/'notary-fixture',receipt['image_sha256'])
        try:handoff.begin_submission();checkpoint(point)
        finally:handoff.close()
    else:apple.prepare(Path(source['archive']),Path(source['release']),Path(source['trust']),root,root.exists(),checkpoint)


def rehearse(source):
    repo=Path(__file__).resolve().parents[1];sys.path.insert(0,str(repo/'tools'))
    from wallet_release import atomic,create,encode
    import wallet_apple as apple
    from apple_notary_handoff import Handoff
    from wallet_ui import WalletApp
    base=Path('/Library/NativePayLocal');plist=Path('/Library/LaunchDaemons/local.nativepay.validator.plist')
    def paused():return subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1
    def unloaded():return subprocess.run(['/bin/launchctl','print','system/local.nativepay.validator'],capture_output=True).returncode==113
    if not paused() or not unloaded():raise ValueError('original validators must remain paused')
    original_manifest=digest(base/'MANIFEST.json');original_plist=digest(plist);original_debug=digest(repo/'target/debug/native-wallet')
    stage=Path(tempfile.mkdtemp(prefix='native-apple-wallet-037-',dir='/private/tmp'));stage.chmod(0o700)
    atomic(repo/'.local/apple-037-stage.json',{'stage':str(stage)})
    source=Path(source).absolute();inputs={'archive':str(source/'wallet-5.tar.gz'),'release':str(source/'release-5.json'),'trust':str(source/'installation')}
    create(stage/'input.json',encode(inputs));(stage/'verifier').mkdir(mode=0o700)
    for name in ('wallet_release.py','wallet_apple.py','apple_notary_handoff.py'):create(stage/'verifier'/name,(repo/'tools'/name).read_bytes())
    root=stage/'preparation';children=[];errors=[];result={'stage':str(stage),'status':'running'}
    def command(argv,**kwargs):
        p=subprocess.run(argv,capture_output=True,timeout=45,**kwargs)
        if p.returncode:raise ValueError('local rehearsal child failed')
        return p.stdout
    def crash(point):
        with open(stage/('crash-'+point+'.log'),'wb') as log:
            child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--worker','--stage',str(stage),'--point',point],stdout=log,stderr=log)
        children.append(child);end=time.monotonic()+45
        while not (stage/('checkpoint-'+point+'.json')).exists():
            if child.poll() is not None or time.monotonic()>end:raise ValueError('bounded crash checkpoint not reached')
            time.sleep(.05)
        child.kill();child.wait(timeout=5)
        if child.returncode!=-signal.SIGKILL:raise ValueError('actual SIGKILL not observed')
    def interrupted(*_):raise TimeoutError('bounded Apple rehearsal interrupted')
    signal.signal(signal.SIGALRM,interrupted);signal.signal(signal.SIGTERM,interrupted);signal.alarm(240)
    try:
        crash('payload_signed');first=json.loads((root/'state.json').read_text())
        if first['phase']!='payload_signed':raise ValueError('wrong durable crash phase')
        crash('image_signed');second=json.loads((root/'state.json').read_text())
        if second['phase']!='image_signed' or first['attempt']==second['attempt']:raise ValueError('interrupted attempt overwritten')
        work,receipt=apple.prepare(Path(inputs['archive']),Path(inputs['release']),Path(inputs['trust']),root,True)
        if len(list((root/'attempts').iterdir()))!=3:raise ValueError('partial attempts were not retained')
        repeated,_=apple.prepare(Path(inputs['archive']),Path(inputs['release']),Path(inputs['trust']),root,True)
        if repeated!=work:raise ValueError('completed resume repeated signing')
        result['preparation_sigkill_phases']=['payload_signed','image_signed'];result['partial_attempts_retained']=True;result['completed_resume_idempotent']=True
        crash('mounted')
        if not apple.image_mounts(work/'wallet-rehearsal.dmg'):raise ValueError('crashed worker did not leave actual attachment')
        apple.recover_mount(root)
        if apple.image_mounts(work/'wallet-rehearsal.dmg'):raise ValueError('owned disk image was not recovered')
        result['actual_mount_sigkill_and_detach_recovery']=True
        with apple.mounted_payload(root) as bundle:
            command([sys.executable,'-I','-B',str(bundle/'runtime/wallet_launch.py'),'--verify'])
            app=WalletApp.from_profile(bundle/'wallet-profile.json',stage/'fresh-wallet',binary=bundle/'bin/native-wallet')
            password='Apple-local-rehearsal-'+os.urandom(16).hex();address=app.cli('init',password,['--backup',str(app.backup)])['address']
            create(Path(str(app.wallet)+'.pending.json'),encode({'synthetic_preservation_sentinel':True,'do_not_send':True}))
            create(Path(str(app.wallet)+'.staging.json'),encode({'synthetic_preservation_sentinel':True,'do_not_reclaim':True}))
            baseline={str(p.relative_to(app.wallet.parent)):digest(p) for p in app.wallet.parent.rglob('*') if p.is_file()}
            if app.cli('address',password)['address']!=address:raise ValueError('signed wallet identity mismatch')
            restored=stage/'restored';restored.mkdir(mode=0o700)
            response=json.loads(command([str(bundle/'bin/native-wallet'),'restore','--network',str(bundle/'wallet-profile.json'),'--wallet',str(restored/'wallet.json'),'--backup',str(app.backup),'--password-file','-'],input=password.encode()))
            if response['address']!=address:raise ValueError('signed wallet restore identity changed')
            after={str(p.relative_to(app.wallet.parent)):digest(p) for p in app.wallet.parent.rglob('*') if p.is_file()}
            if after!=baseline:raise ValueError('new wallet/recovery/sentinel bytes changed')
        result.update(mounted_isolated_launcher_verified=True,actual_hardened_wallet_offline_init_address_restore=True,fresh_encrypted_wallet_and_synthetic_pending_unchanged=True)
        crash('submission_unknown');handoff=Handoff(stage/'notary-fixture',receipt['image_sha256'])
        try:
            if handoff.state['phase']!='submission_unknown':raise ValueError('ambiguous fixture submission lost')
            try:handoff.begin_submission()
            except ValueError:pass
            else:raise ValueError('fixture silently repeated ambiguous submission')
            identifier='11111111-1111-4111-8111-111111111111';handoff.attach_submission(identifier,receipt['image_sha256']);handoff.result(identifier,receipt['image_sha256'],'Accepted');handoff.staple(identifier,receipt['image_sha256'],False)
        finally:handoff.close()
        handoff=Handoff(stage/'notary-fixture',receipt['image_sha256'])
        try:
            if handoff.state['phase']!='staple_failed':raise ValueError('failed ticket fixture lost on restart')
            handoff.staple(identifier,receipt['image_sha256'],True,'a'*64);handoff.assess('a'*64,False)
        finally:handoff.close()
        handoff=Handoff(stage/'notary-fixture',receipt['image_sha256'])
        try:
            if handoff.state['phase']!='assessment_failed':raise ValueError('failed assessment fixture lost on restart')
            handoff.assess('a'*64,True)
            if handoff.state['notarized'] is not False or handoff.state['release_ready'] is not False:raise ValueError('fixture claimed actual Apple approval')
        finally:handoff.close()
        result.update(status='passed',fixture_submission_sigkill_no_automatic_resubmit=True,fixture_ticket_and_assessment_failure_restart=True,
            image_sha256=receipt['image_sha256'],original_binary_sha256=receipt['transformation']['original_binary_sha256'],signed_binary_sha256=receipt['transformation']['signed_binary_sha256'],
            code_identity=receipt['transformation']['code_identity'],rehearsal_work=str(work),notarized=False,release_ready=False,developer_id_used=False,credentials_accessed=False,
            validators_started=0,payment_broadcast_commands=0,private_service_files_accessed=0,network_commands_executed=False)
    except BaseException as error:
        result.update(status='failed',failure_type=type(error).__name__);raise
    finally:
        signal.alarm(0)
        for child in children:
            if child.poll() is None:
                try:child.kill();child.wait(timeout=5)
                except OSError:errors.append('child_cleanup_failed')
        if (root/'state.json').exists() and json.loads((root/'state.json').read_text()).get('phase')=='complete':
            try:apple.recover_mount(root)
            except Exception:errors.append('owned_mount_recovery_failed')
        result.update(cleanup_errors=errors,all_owned_direct_children_stopped=all(c.poll() is not None for c in children),
            installed_manifest_unchanged=digest(base/'MANIFEST.json')==original_manifest,normal_plist_unchanged=digest(plist)==original_plist,
            original_debug_wallet_unchanged=digest(repo/'target/debug/native-wallet')==original_debug,validators_paused_and_job_unloaded=paused() and unloaded())
        atomic(stage/'result.json',result);atomic(repo/'.local/apple-037-result.json',result)
    if errors or any(result[k] is not True for k in ('all_owned_direct_children_stopped','installed_manifest_unchanged','normal_plist_unchanged','original_debug_wallet_unchanged','validators_paused_and_job_unloaded')):raise ValueError('Apple rehearsal preservation audit failed')
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path);parser.add_argument('--worker',action='store_true');parser.add_argument('--stage',type=Path);parser.add_argument('--point',choices=('payload_signed','image_signed','mounted','submission_unknown'));args=parser.parse_args()
    if args.worker:worker(args.stage,args.point)
    elif args.source:rehearse(args.source)
    else:parser.error('--source is required')
