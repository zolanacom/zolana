"""Finalize preserved replica recovery evidence and check receiver-only shutdown."""
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


def main(stage,expected_manifest):
    service.require_root();config=service.verify_install();os.nice(15);stage=Path(stage)
    def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    if digest(BASE/'MANIFEST.json')!=expected_manifest:raise ValueError('sealed final runtime differs')
    previous=BASE/'HISTORY-REPLICA-030-RECHECK1.json';prior=json.loads(previous.read_text())
    if (prior['status']!='passed' or prior['original_native_accounts']!=21 or prior['permanent_nullifiers']!=20
            or prior['independent_receiver_stopped'] is not False
            or not all(prior[k] for k in ['validators_paused_after_test','normal_plist_restored','temporary_replica_policy_removed',
                'original_keys_wallets_journals_admission_sponsor_and_claims_unchanged','required_replica_outage_paused_validators_and_ingress'])):
        raise ValueError('expected preserved recovery pass with recorded shutdown timeout')
    root=BASE/'.data/s20';baseline=json.loads((BASE/'HISTORY-REPLICA-030.started.json').read_text())
    def paused():
        if subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode!=113:raise ValueError('service is loaded')
        if subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode!=1:raise ValueError('validators running')
        if digest(service.PLIST)!=baseline['normal_plist_sha256'] or plistlib.loads(service.PLIST.read_bytes())['ProgramArguments'][-1]!='run':raise ValueError('normal plist differs')
        if any(digest(root/name)!=value for name,value in baseline['private_file_digests'].items()):raise ValueError('original private state changed')
        for name in ['history-replica.json','history-replica.key','history-replica-ca.crt','history-replica-required.json']:
            if os.path.lexists(root/name):raise ValueError('temporary operator policy remains')
    paused()
    if digest(stage/'receiver-tools/history_replica.py')!=digest(BASE/'tools/history_replica.py'):
        raise ValueError('receiver shutdown regression must use the exact installed helper')
    meta=json.loads((stage/'acceptance.json').read_text())
    def drop():
        os.setgroups([]);os.setgid(pwd.getpwuid(config['desktop_uid']).pw_gid);os.setuid(config['desktop_uid']);os.umask(0o077)
    report=BASE/'HISTORY-REPLICA-030-FINAL.json'
    if report.exists():raise ValueError('preserve final audit evidence')
    result={'status':'failed'};child=None
    def end(*_):raise TimeoutError('finite final replica-only audit')
    signal.signal(signal.SIGALRM,end);signal.alarm(60)
    try:
        out=stage/'final-receiver.stdout';err=stage/'final-receiver.stderr'
        for p in [out,err]:
            fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.fchown(fd,config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid);os.close(fd)
        with out.open('wb') as stdout,err.open('wb') as stderr:
            child=subprocess.Popen(['/usr/bin/python3','-B',str(stage/'receiver-tools/history_replica.py'),'serve',
                '--root',str(stage/'receiver'),'--port',str(meta['port']),'--cert',str(stage/'tls/server.crt'),
                '--key',str(stage/'tls/server.key'),'--duration','40'],preexec_fn=drop,cwd=stage,
                env={'PATH':'/usr/bin:/bin'},stdout=stdout,stderr=stderr)
        deadline=time.monotonic()+10
        while not out.stat().st_size:
            if child.poll() is not None or time.monotonic()>deadline:raise ValueError('final receiver startup failed: '+err.read_text()[-500:])
            time.sleep(.05)
        downloaded=subprocess.run(['/usr/bin/python3','-B',str(stage/'receiver-tools/history_replica.py'),'fetch',
            '--network',str(stage/'network.json'),'--destination',str(stage/'final-downloaded-history'),
            '--url','https://127.0.0.1:'+str(meta['port']),'--credential-file',str(stage/'sender.key'),'--ca-file',str(stage/'tls/ca.crt')],
            preexec_fn=drop,cwd=stage,env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=45)
        if downloaded.returncode:raise ValueError('final source-stopped download failed: '+downloaded.stderr[-500:])
        received=json.loads(downloaded.stdout)
        if received!=prior['download_with_source_service_stopped']:raise ValueError('replica changed the committed recovery point')
        begin=time.monotonic();child.terminate();code=child.wait(timeout=5)
        if code!=0:raise ValueError('receiver did not shut down gracefully')
        paused()
        ports=[18899,19899,18898,8780,23899,24899,23898,13780,33899,34899,meta['port']]
        for port in ports:
            with socket.socket() as probe:
                probe.settimeout(.2)
                if probe.connect_ex(('127.0.0.1',port))==0:raise ValueError('test port still listening: '+str(port))
        result.update(status='passed',functional_acceptance_sha256=digest(previous),prior_shutdown_timeout_retained=True,
            original_private_files_unchanged=len(baseline['private_file_digests']),original_pool_and_twenty_nullifiers_preserved=True,
            receiver_only_sigterm_under_administrator_launcher='graceful',shutdown_seconds=round(time.monotonic()-begin,3),
            independent_receiver_stopped=True,validators_paused=True,normal_plist_restored=True,temporary_operator_policy_removed=True,
            independent_source_stopped_download=received,closed_ports=ports,sealed_runtime_manifest_sha256=expected_manifest,
            validators_started_by_final_audit=0,payment_broadcast_commands=0)
    except BaseException as error:
        result['error']=type(error).__name__+': '+str(error)[:400];raise
    finally:
        signal.alarm(0)
        if child is not None and child.poll() is None:child.kill();child.wait(timeout=5)
        raw=(json.dumps(result,sort_keys=True,indent=2)+'\n').encode()
        fd=os.open(report,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    print(json.dumps(result),flush=True)


if __name__=='__main__':main(sys.argv[1],sys.argv[2])
