"""Pinned finite installed-service replication rehearsal; preserve original private state."""
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


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path,value,owner=None,mode=0o600,raw=False):
    data=value if raw else (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as output:
        output.write(data);output.flush();os.fsync(output.fileno())
        if owner is not None:os.fchown(output.fileno(),*owner)


def main(stage,resume=False):
    service.require_root();config=service.verify_install();os.nice(15)
    stage=Path(stage).absolute()
    if stage.parent!=Path('/private/tmp') or stage.resolve()!=stage or stage.lstat().st_uid!=config['desktop_uid'] or stage.lstat().st_mode&0o077:
        raise ValueError('expected owner-only reviewed local replica stage')
    meta=json.loads((stage/'acceptance.json').read_text());root=BASE/'.data/s20';owner=(config['uid'],config['gid'])
    from history_replica import KEY_FORMAT, DIGEST
    network=json.loads((root/'network.json').read_text());network={k:network[k] for k in ['network','genesis_hash']}
    key_path=stage/'sender.key';key_info=key_path.lstat()
    if (not stat.S_ISREG(key_info.st_mode) or key_info.st_uid!=config['desktop_uid']
            or key_info.st_mode&0o077 or not 0<key_info.st_size<=2048):
        raise ValueError('expected separately owned reviewed history credential')
    key=json.loads(key_path.read_bytes())
    if (set(key)!={'format','network','token'} or key['format']!=KEY_FORMAT or key['network']!=network
            or not isinstance(key['token'],str) or DIGEST.fullmatch(key['token']) is None):
        raise ValueError('reviewed credential is not for this history replica')
    if digest(stage/'sender.key')!=meta['credential_sha256'] or digest(stage/'tls/ca.crt')!=meta['ca_sha256']:
        raise ValueError('reviewed replica provision changed')
    suffix='-RECHECK1' if resume else ''
    report=BASE/('HISTORY-REPLICA-030'+suffix+'.json');marker=BASE/('HISTORY-REPLICA-030'+suffix+'.started.json')
    evidence=root/('replica-evidence-030'+suffix)
    if report.exists() or marker.exists() or evidence.exists():raise ValueError('preserve existing replica test evidence')
    normal=service.PLIST.read_bytes();plist=plistlib.loads(normal)
    def unloaded():return subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode==113
    def validators_stopped():return subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode==1
    if not unloaded() or not validators_stopped() or plist['ProgramArguments'][-1]!='run':raise ValueError('original service must be normally paused')
    names=set(json.loads((BASE/'CANONICAL-ARCHIVE-028.started.json').read_text())['private_file_digests'])
    names.update(['faucet/admission.json','raw-rpc-required.json'])
    names.update(str(p.relative_to(root)) for p in root.glob('*.wallet.json*') if p.is_file())
    def fixed():return {name:digest(root/name) for name in sorted(names)}
    before=fixed()
    temporary=['history-replica.json','history-replica.key','history-replica-ca.crt','history-replica-required.json']
    if any(os.path.lexists(root/name) for name in temporary):raise ValueError('never replace an existing operator replica policy')
    if (root/'history-replica-session-030.json').exists() and not resume:raise ValueError('existing replica session must remain preserved')
    previous=None
    if resume:
        previous=json.loads((BASE/'HISTORY-REPLICA-030.json').read_text())
        prior_marker=json.loads((BASE/'HISTORY-REPLICA-030.started.json').read_text())
        if (previous.get('status')!='failed' or previous.get('error')!='TimeoutError: required replica outage did not park validators'
                or previous.get('last_retention_health',{}).get('phase')!='paused'
                or previous['last_retention_health'].get('error')!='retention_replica_unavailable_or_unverified'
                or not all(previous.get(k) is True for k in ['validators_paused_after_test','normal_plist_restored','temporary_replica_policy_removed','independent_receiver_stopped'])
                or before!=prior_marker['private_file_digests']
                or hashlib.sha256(normal).hexdigest()!=prior_marker['normal_plist_sha256']):
            raise ValueError('paused-outage resume requires exact preserved failure/private-state evidence')
    write(marker,{'private_file_digests':before,'normal_plist_sha256':hashlib.sha256(normal).hexdigest()},mode=0o400)
    evidence.mkdir(mode=0o700);os.chown(evidence,*owner)
    receiver=None;receiver_starts=0;created=[];result={'status':'failed'};started_at=0
    def progress(phase,**fields):
        path=BASE/('HISTORY-REPLICA-030'+suffix+'.progress.json');new=path.with_suffix('.tmp')
        write(new,dict(phase=phase,**fields),mode=0o444);os.replace(new,path)
    def desktop_drop():
        os.setgroups([]);os.setgid(pwd.getpwuid(config['desktop_uid']).pw_gid);os.setuid(config['desktop_uid']);os.umask(0o077)
    def receiver_start():
        nonlocal receiver,receiver_starts
        receiver_starts+=1
        out=evidence/('receiver-'+str(receiver_starts)+'.stdout');err=evidence/('receiver-'+str(receiver_starts)+'.stderr')
        for p in [out,err]:write(p,b'',owner,raw=True)
        with out.open('wb') as stdout,err.open('wb') as stderr:
            receiver=subprocess.Popen(['/usr/bin/python3','-B',str(stage/'receiver-tools/history_replica.py'),'serve',
                '--root',str(stage/'receiver'),'--port',str(meta['port']),'--cert',str(stage/'tls/server.crt'),
                '--key',str(stage/'tls/server.key'),'--duration','540'],preexec_fn=desktop_drop,cwd=stage,
                env={'PATH':'/usr/bin:/bin','RAYON_NUM_THREADS':'2'},stdout=stdout,stderr=stderr)
        end=time.monotonic()+15
        while time.monotonic()<end:
            if receiver.poll() is not None:raise RuntimeError('independent receiver failed: '+err.read_text()[-1000:])
            if out.stat().st_size:return
            time.sleep(.1)
        raise TimeoutError('independent receiver startup deadline')
    def receiver_stop(crash=False):
        if receiver is not None and receiver.poll() is None:
            receiver.kill() if crash else receiver.terminate()
            try:receiver.wait(timeout=10)
            except subprocess.TimeoutExpired:
                receiver.kill();receiver.wait(timeout=10)
            if crash and receiver.returncode!=-9:raise RuntimeError('owned receiver did not SIGKILL')
    def start():
        nonlocal started_at
        started_at=time.time();service.command(['/bin/launchctl','bootstrap','system',str(service.PLIST)],timeout=60)
    def stop():
        if not unloaded():service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=100)
        end=time.monotonic()+15
        while not validators_stopped():
            if time.monotonic()>=end:raise TimeoutError('validators did not pause')
            time.sleep(.2)
    def wait_ready(after):
        end=time.monotonic()+220;last=0
        while time.monotonic()<end:
            path=root/'history-retention.json'
            info=json.loads(path.read_text()) if path.exists() else {}
            fresh=path.exists() and path.stat().st_mtime>=started_at
            if fresh and info.get('phase')=='blocked':raise RuntimeError('replica retention failed: '+str(info.get('error')))
            try:
                value=json.loads(service.as_service('status',config).stdout)
                info=value['history_retention'];receipt=info.get('replica')
                if time.monotonic()-last>15:
                    progress('waiting_for_replicated_finality',slots=value['slots'],retention_phase=info.get('phase'));last=time.monotonic()
                if (fresh and info.get('phase')=='ready' and receipt and receipt.get('durable') is True
                        and receipt['manifest_sha256']==info['manifest_sha256'] and min(value['slots'])>after
                        and max(value['slots'])-min(value['slots'])<=12):return value
            except (subprocess.CalledProcessError,ValueError,OSError):pass
            time.sleep(.5)
        raise TimeoutError('fresh replicated service checkpoint deadline')
    def archival():
        value=json.loads(service.as_service('archival-check',config).stdout)
        if not value['same_anchor'] or not value['private_unix_transport'] or value['blocks']!=16 or value['next_blocks']!=16:
            raise ValueError('canonical archival continuation changed')
        return {k:value[k] for k in ['blocks','next_blocks','same_anchor','private_unix_transport']}
    def timeout(*_):raise TimeoutError('bounded installed replica acceptance deadline')
    signal.signal(signal.SIGALRM,timeout);signal.alarm(700)
    try:
        receiver_start()
        for name,data in [('history-replica.key',(stage/'sender.key').read_bytes()),('history-replica-ca.crt',(stage/'tls/ca.crt').read_bytes()),
            ('history-replica.json',json.dumps({'format':'native-history-replication-v1','url':'https://127.0.0.1:'+str(meta['port']),
                'ca_sha256':meta['ca_sha256']}).encode())]:
            write(root/name,data,owner,raw=True);created.append(name)
        session=root/'history-replica-session-030.json'
        if resume:
            write(evidence/'prior-session.json',json.loads(session.read_text()),owner)
            replacement=root/'history-replica-session-030.recheck1.json'
            write(replacement,{'format':'local-history-replica-test-v1','expires_at':time.time()+585},owner);os.replace(replacement,session)
        else:write(session,{'format':'local-history-replica-test-v1','expires_at':time.time()+585},owner)
        plist['ProgramArguments'][-1]='run-replica-test';service.PLIST.write_bytes(plistlib.dumps(plist))
        if resume:
            baseline=json.loads((root/'replica-evidence-030/initial-live.json').read_text())
            if len(baseline['native_state'])!=21:raise ValueError('preserved baseline payment inventory differs')
            pages=[];write(evidence/'prior-paused-outage.json',previous,owner)
            progress('resuming_preserved_paused_outage',initial_slots=baseline['slots'])
        else:
            start();baseline=wait_ready(0)
            if len(baseline['native_state'])!=21 or fixed()!=before:raise ValueError('original payment/private state changed')
            first=baseline['history_retention']['replica'];pages=[archival()]
            write(evidence/'initial-live.json',baseline,owner)
            progress('original_service_replicated',slots=baseline['slots'],segments=first['segments'],native_accounts=21)
            receiver_stop(crash=True);progress('independent_receiver_sigkilled')
            end=time.monotonic()+110
            while time.monotonic()<end:
                info=json.loads((root/'history-retention.json').read_text())
                if info.get('phase') in ('blocked','paused') and info.get('error')=='retention_replica_unavailable_or_unverified' and validators_stopped():break
                time.sleep(.5)
            else:raise TimeoutError('required replica outage did not park validators')
            if fixed()!=before:raise ValueError('replica outage changed original private state')
            write(evidence/'outage-health.json',info,owner)
            stop();receiver_start()
        for port in [23898,13780]:
            with socket.socket() as probe:
                probe.settimeout(.2)
                if probe.connect_ex(('127.0.0.1',port))==0:raise ValueError('replica outage left tester ingress open')
        progress('replica_outage_paused_validators_and_ingress')
        start();recovered=wait_ready(max(baseline['slots'])+8)
        if recovered['native_state']!=baseline['native_state'] or fixed()!=before:raise ValueError('receiver/service restart changed payment state')
        pages.append(archival());write(evidence/'restarted-live.json',recovered,owner)
        stop();progress('source_service_paused_before_independent_download')
        # The desktop UID can access only the public-history receiver, not the
        # private source root or raw RPC credential. All source services are off.
        child=subprocess.run(['/usr/bin/python3','-B',str(stage/'receiver-tools/history_replica.py'),'fetch',
            '--network',str(stage/'network.json'),'--destination',str(stage/'downloaded-history'),
            '--url','https://127.0.0.1:'+str(meta['port']),'--credential-file',str(stage/'sender.key'),'--ca-file',str(stage/'tls/ca.crt')],
            preexec_fn=desktop_drop,cwd=stage,env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=90)
        if child.returncode:raise RuntimeError('independent download failed: '+child.stderr[-1000:])
        downloaded=json.loads(child.stdout)
        final_receipt=recovered['history_retention']['replica']
        # Background collection can extend the prefix between live sampling and
        # shutdown. The replica may be newer, but must retain that exact prefix.
        from history_retention import manifest
        _,accepted_files,_=manifest(root/'recovery-history-mirror',network,owner=config['uid'])
        _,downloaded_files,_=manifest(stage/'downloaded-history',network,owner=config['desktop_uid'])
        if downloaded_files!=accepted_files or downloaded['finalized_slot']<final_receipt['finalized_slot']:
            raise ValueError('independent download differs from latest durable source prefix')
        if fixed()!=before:raise ValueError('read-only replica acceptance changed original private files')
        result.update(status='passed',resumed_preserved_paused_outage=resume,initial_finalized_slots=baseline['slots'],post_receiver_and_service_restart_slots=recovered['slots'],
            original_native_accounts=21,permanent_nullifiers=20,original_private_file_count=len(before),
            original_keys_wallets_journals_admission_sponsor_and_claims_unchanged=True,
            independent_receiver_uid=config['desktop_uid'],source_service_uid=config['uid'],
            receiver_sigkill=True,required_replica_outage_paused_validators_and_ingress=True,
            replica_restart_preserved_committed_prefix=True,download_with_source_service_stopped=downloaded,
            receiver_contains_no_wallet_validator_sponsor_or_raw_rpc_keys=True,canonical_archival_pages=pages,payment_broadcast_commands=0)
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)[:500]
        p=root/'history-retention.json'
        if p.exists():result['last_retention_health']=json.loads(p.read_text())
        raise
    finally:
        signal.alarm(0)
        try:
            stop();receiver_stop()
        except BaseException as error:
            result.update(status='failed',cleanup_error=type(error).__name__+': '+str(error)[:300])
            raise
        finally:
            # Restore pre-test absence only for these newly provisioned rehearsal
            # files. Preserve their bytes in private evidence, never touch history.
            for name in created+['history-replica-required.json']:
                p=root/name
                if p.exists():
                    write(evidence/('test-'+name),p.read_bytes(),owner,raw=True);p.unlink()
            service.PLIST.write_bytes(normal)
            result.update(validators_paused_after_test=unloaded() and validators_stopped(),normal_plist_restored=service.PLIST.read_bytes()==normal,
                temporary_replica_policy_removed=not any(os.path.lexists(root/name) for name in temporary),
                independent_receiver_stopped=receiver is None or receiver.poll() is not None)
            write(report,result,mode=0o444)
    print(json.dumps(result),flush=True)


if __name__=='__main__':
    if sys.argv[2:] not in ([],['--resume-after-paused-outage']):raise ValueError('unexpected acceptance arguments')
    main(sys.argv[1],bool(sys.argv[2:]))
