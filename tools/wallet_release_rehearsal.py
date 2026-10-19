"""Finite offline release/update crash acceptance; never starts validators."""
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
import time
import urllib.request


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def worker(stage,number,point):
    sys.path.insert(0,str(stage/'verifier'))
    from wallet_release import Installation,create,encode
    signal.alarm(90)
    def checkpoint(current):
        if current==point:
            create(stage/('checkpoint-'+str(number)+'.json'),encode({'point':point,'pid':os.getpid()}))
            os.kill(os.getpid(),signal.SIGSTOP)
    installation=Installation(stage/'installation',checkpoint)
    try:installation.install(stage/('wallet-'+str(number)+'.tar.gz'),stage/('release-'+str(number)+'.json'))
    finally:installation.close()


def rehearse(build_root=None):
    from wallet_release import create,encode,public_der,crypto
    repo=Path(__file__).resolve().parents[1];base=Path('/Library/NativePayLocal');plist=Path('/Library/LaunchDaemons/local.nativepay.validator.plist')
    def paused():return subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1
    def unloaded():return subprocess.run(['/bin/launchctl','print','system/local.nativepay.validator'],capture_output=True).returncode==113
    if not paused() or not unloaded():raise ValueError('keep original validators paused')
    original_manifest=sha(base/'MANIFEST.json');original_plist=sha(plist)
    case='remap-036' if build_root is not None else 'release-035'
    stage=Path(tempfile.mkdtemp(prefix='native-remapped-wallet-036-' if build_root is not None else 'native-wallet-release-035-',dir='/private/tmp'));stage.chmod(0o700)
    children=[];owned_groups=[];cleanup=[];results={'stage':str(stage),'status':'running'}
    def write(path,value):
        from wallet_release import atomic
        atomic(path,value)
    write(repo/('.local/'+case+'-stage.json'),{'stage':str(stage)})
    def command(args,**kwargs):
        result=subprocess.run(args,capture_output=True,timeout=45,**kwargs)
        if result.returncode:raise RuntimeError('local command failed: '+str(args[1] if len(args)>1 else 'command'))
        return result.stdout
    def wait_until(predicate,seconds=15):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.05)
        raise RuntimeError('bounded rehearsal condition timed out')
    def tool(*args,system=False,success=True):
        result=subprocess.run([('/usr/bin/python3' if system else sys.executable),'-I','-B',str(stage/'verifier/wallet_release.py'),*map(str,args)],capture_output=True,timeout=30)
        if (result.returncode==0)!=success:raise RuntimeError('release tool acceptance mismatch')
        return result
    def installed():
        value=json.loads((stage/'installation/state.json').read_text());v=value['active']['release']
        return stage/'installation/releases'/(str(v['sequence']).zfill(10)+'-'+v['archive_sha256'][:24])/'bundle'
    def closed(port):
        with socket.socket() as probe:return probe.connect_ex(('127.0.0.1',port))!=0
    def stop_group(group):
        try:os.killpg(group,signal.SIGTERM)
        except ProcessLookupError:return
    def interrupted(*_):raise TimeoutError('bounded rehearsal interrupted')
    signal.signal(signal.SIGALRM,interrupted);signal.signal(signal.SIGTERM,interrupted);signal.alarm(180)
    try:
        (stage/'verifier').mkdir(mode=0o700)
        create(stage/'verifier/wallet_release.py',(repo/'tools/wallet_release.py').read_bytes())
        # Use an already-built wallet. This rehearsal performs no Rust build,
        # dependency download, validator startup or chain operation.
        binary=Path(build_root)/'native-wallet' if build_root is not None else repo/'target/debug/native-wallet'
        create(stage/'native-wallet',binary.read_bytes(),0o700)
        profile_path=repo/'.local/service-wallet-acceptance-021/refreshed-profile.json';profile=json.loads(profile_path.read_text())
        ca=stage/'public-ca.crt';create(ca,profile['local_tls_ca_pem'].encode())
        args=[sys.executable,'-B',str(repo/'tools/package_wallet.py'),'--network',str(profile_path),'--label',profile['label'],'--rpc',profile['rpc']['url'],
            '--transport','https','--faucet',profile['faucet']['url'],'--invite-only','--local-tls-ca',str(ca),'--binary',str(stage/'native-wallet')]
        if build_root is not None:args+=['--build-receipt',str(Path(build_root)/'BUILD.json')]
        package=json.loads(command([*args,'--output',str(stage/'wallet.tar.gz')],cwd=repo))
        repeat=json.loads(command([*args,'--output',str(stage/'repeat.tar.gz')],cwd=repo))
        if package['sha256']!=repeat['sha256']:raise ValueError('package not reproducible')
        from wallet_release import unpack
        from package_wallet import archive
        files,_=unpack((stage/'wallet.tar.gz').read_bytes());profile_sha=hashlib.sha256(files['wallet-profile.json']).hexdigest()
        if build_root is not None:
            from wallet_build import path_audit
            for raw in files.values():path_audit(raw,{'checkout':repo.resolve(),'home':Path.home().resolve(),'build':Path(build_root).resolve()})
            if files['BUILD.json']!=(Path(build_root)/'BUILD.json').read_bytes():raise ValueError('build receipt not preserved in package')
        key=crypto(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-pkeyopt','ec_param_enc:named_curve'],b'');create(stage/'rehearsal-key.pem',key)
        pub=crypto(['pkey','-pubout'],key);create(stage/'rehearsal-key.pub',pub);pin=hashlib.sha256(public_der(pub)).hexdigest()
        tool('init','--root',stage/'installation','--public-key',stage/'rehearsal-key.pub','--key-sha256',pin,'--profile-sha256',profile_sha,'--channel','local-invited-rehearsal','--minimum-sequence',1)
        archives={1:stage/'wallet.tar.gz'}
        for number in range(1,6):
            if number>1:
                changed=dict(files);changed['README.txt']=files['README.txt']+('\nLocal signed-update rehearsal version '+str(number)+'\n').encode()
                manifest=json.loads(files['MANIFEST.json']);manifest['files']['README.txt']={'size':len(changed['README.txt']),'sha256':hashlib.sha256(changed['README.txt']).hexdigest()}
                changed['MANIFEST.json']=encode(manifest);archives[number]=stage/('wallet-'+str(number)+'.tar.gz')
                create(archives[number],archive(changed,{'bin/native-wallet':0o755,'start-wallet.command':0o755}))
            tool('sign','--archive',archives[number],'--private-key',stage/'rehearsal-key.pem','--channel','local-invited-rehearsal','--sequence',number,'--output',stage/('release-'+str(number)+'.json'))
        tool('verify','--root',stage/'installation','--archive',stage/'wallet.tar.gz','--release',stage/'release-1.json',system=True)
        tool('install','--root',stage/'installation','--archive',stage/'wallet.tar.gz','--release',stage/'release-1.json')
        tool('run','--root',stage/'installation','--','--verify')
        # Create a completely new encrypted wallet offline. Original tester
        # wallets and protected service data are never read.
        sys.path.insert(0,str(repo/'tools'));from wallet_ui import WalletApp
        app=WalletApp.from_profile(installed()/'wallet-profile.json',stage/'wallet-state',binary=installed()/'bin/native-wallet')
        password='Local-release-rehearsal-'+os.urandom(16).hex()
        address=app.cli('init',password,['--backup',str(app.backup)])['address']
        app.ack.touch(mode=0o600)
        create(Path(str(app.wallet)+'.pending.json'),encode({'synthetic_preservation_sentinel':True,'do_not_send':True}))
        create(Path(str(app.wallet)+'.staging.json'),encode({'synthetic_preservation_sentinel':True,'do_not_reclaim':True}))
        baseline={str(p.relative_to(stage/'wallet-state')):sha(p) for p in (stage/'wallet-state').rglob('*') if p.is_file()}
        # Actual standalone server inherits the installation lock even after
        # killing its trusted parent runner.
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));port=probe.getsockname()[1]
        log=open(stage/'wallet-runner.log','wb')
        runner=subprocess.Popen([sys.executable,'-I','-B',str(stage/'verifier/wallet_release.py'),'run','--root',str(stage/'installation'),'--','--no-browser','--duration','60','--port',str(port),'--data-dir',str(stage/'wallet-state')],stdout=log,stderr=log,start_new_session=True)
        log.close();children.append(runner);owned_groups.append(runner.pid)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def ready():
            try:
                with opener.open('http://127.0.0.1:'+str(port)+'/',timeout=.5) as response:return response.status==200 and len(response.read(512000))>100
            except OSError:return False
        wait_until(ready)
        runner.kill();runner.wait(timeout=5)
        tool('install','--root',stage/'installation','--archive',archives[2],'--release',stage/'release-2.json',success=False)
        results['wallet_inherited_lock_survived_runner_sigkill']=True
        stop_group(runner.pid);wait_until(lambda:closed(port));owned_groups.remove(runner.pid)
        outcomes=[]
        for number,point in enumerate(('planned','extracting','published','activated'),2):
            log=open(stage/('crash-'+str(number)+'.log'),'wb')
            child=subprocess.Popen([sys.executable,'-B',str(Path(__file__).resolve()),'--worker','--stage',str(stage),'--number',str(number),'--point',point],stdout=log,stderr=log)
            log.close();children.append(child)
            wait_until(lambda:(stage/('checkpoint-'+str(number)+'.json')).exists())
            child.kill();child.wait(timeout=5)
            state=json.loads((stage/'installation/state.json').read_text());expected=number if point=='activated' else number-1
            if state['sequence']!=expected:raise ValueError('unexpected active commit after SIGKILL')
            if point!='activated':tool('run','--root',stage/'installation','--','--verify',success=False)
            tool('install','--root',stage/'installation','--archive',archives[number],'--release',stage/('release-'+str(number)+'.json'))
            tool('run','--root',stage/'installation','--','--verify')
            if ('Local signed-update rehearsal version '+str(number)).encode() not in (installed()/'README.txt').read_bytes():raise ValueError('new signed contents not activated')
            app=WalletApp.from_profile(installed()/'wallet-profile.json',stage/'wallet-state',binary=installed()/'bin/native-wallet')
            if app.cli('address',password)['address']!=address:raise ValueError('wallet identity changed')
            after={str(p.relative_to(stage/'wallet-state')):sha(p) for p in (stage/'wallet-state').rglob('*') if p.is_file()}
            if after!=baseline:raise ValueError('wallet/recovery/synthetic payment records changed')
            outcomes.append({'point':point,'actual_sigkill':True,'recovered_sequence':number,'wallet_files_unchanged':True})
            print(json.dumps({'checkpoint_passed':point}),flush=True)
        tool('install','--root',stage/'installation','--archive',stage/'wallet.tar.gz','--release',stage/'release-1.json',success=False)
        # Seed-only encrypted restore remains usable with the activated binary.
        (stage/'restored').mkdir(mode=0o700)
        restored=json.loads(command([str(installed()/'bin/native-wallet'),'restore','--network',str(installed()/'wallet-profile.json'),'--wallet',str(stage/'restored/wallet.json'),'--backup',str(app.backup),'--password-file','-'],input=password.encode()))
        if restored['address']!=address:raise ValueError('encrypted restore identity changed')
        tool('status','--root',stage/'installation',system=True)
        results.update(status='passed',crash_checkpoints=outcomes,byte_identical_repeat_archive=True,archive_sha256=package['sha256'],
            changed_signed_contents_activated=True,final_update_archive_sha256=sha(archives[5]),
            verifier_sha256=sha(stage/'verifier/wallet_release.py'),all_wallet_and_recovery_files_unchanged=True,synthetic_pending_and_staging_unchanged=True,
            offline_encrypted_restore_same_address=True,system_python_offline_verify_and_status=True,old_signed_release_rejected=True,standalone_isolated_launcher_served=True,
            wallet_port_closed=closed(port),validators_started=0,payment_broadcast_commands=0,external_messages_sent=0,private_service_files_accessed=0,
            network_scope='one loopback wallet HTTP check only; no RPC requests',production_key_created=False,apple_signing_or_notarization=False)
        if build_root is not None:results.update(path_remapped_build=True,build_receipt_in_signed_inventory=True,all_package_files_path_audited=True,binary_sha256=sha(binary))
    except BaseException as error:
        results.update(status='failed',failure_type=type(error).__name__)
        raise
    finally:
        signal.alarm(0)
        for group in owned_groups:
            try:stop_group(group)
            except OSError:cleanup.append('wallet_group_cleanup_failed')
        for child in children:
            if child.poll() is None:
                try:child.kill();child.wait(timeout=5)
                except OSError:cleanup.append('worker_cleanup_failed')
        results.update(all_owned_direct_children_stopped=all(c.poll() is not None for c in children),cleanup_errors=cleanup,
            installed_manifest_unchanged=sha(base/'MANIFEST.json')==original_manifest,normal_plist_unchanged=sha(plist)==original_plist,validators_paused_and_job_unloaded=paused() and unloaded())
        write(stage/'result.json',results);write(repo/('.local/'+case+'-result.json'),results)
    if cleanup or not results['validators_paused_and_job_unloaded'] or not results['installed_manifest_unchanged'] or not results['normal_plist_unchanged']:raise ValueError('final preservation audit failed')
    print(json.dumps(results,sort_keys=True))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--worker',action='store_true');parser.add_argument('--stage',type=Path);parser.add_argument('--number',type=int);parser.add_argument('--point');parser.add_argument('--build-root',type=Path);args=parser.parse_args()
    if args.worker:worker(args.stage,args.number,args.point)
    else:rehearse(args.build_root)
