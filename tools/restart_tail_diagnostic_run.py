"""One bounded protected-service diagnosis; exports public consensus data only."""
import hashlib,json,os,plistlib,stat,subprocess,sys,time
from pathlib import Path
BASE=Path('/Library/NativePayLocal');ROOT=BASE/'.data/s20'
sys.path.insert(0,str(BASE/'tools'))
import service_account as service

def main(stage):
    service.require_root();config=service.verify_install();os.nice(15)
    original=service.PLIST.read_bytes();plist=plistlib.loads(original)
    def paused():return subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode==113
    if not paused() or plist['ProgramArguments'][-1]!='run':raise ValueError('original service must be paused')
    if stage.is_symlink() or stage.stat().st_uid!=config['desktop_uid'] or stage.stat().st_mode&0o077:raise ValueError('private desktop evidence directory required')
    stage_fd=os.open(stage,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    before=json.loads((BASE/'CANONICAL-ARCHIVE-028.started.json').read_text())['private_file_digests']
    if any(digest(ROOT/name)!=value for name,value in before.items()):raise ValueError('original private state changed')
    def write(path,value,owner,dir_fd=None):
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dir_fd)
        with os.fdopen(fd,'w') as output:
            json.dump(value,output);output.flush();os.fsync(output.fileno());os.fchown(output.fileno(),*owner)
    def publish(name,value):
        temporary=name+'.root.tmp'
        write(temporary,value,(config['desktop_uid'],os.getgid()),stage_fd)
        os.replace(temporary,name,src_dir_fd=stage_fd,dst_dir_fd=stage_fd)
    def stop_requested():
        try:meta=os.stat('stop-diagnostic',dir_fd=stage_fd,follow_symlinks=False)
        except FileNotFoundError:return False
        return stat.S_ISREG(meta.st_mode) and meta.st_uid==config['desktop_uid'] and meta.st_size==0
    def drop():os.setgroups([]);os.setgid(config['gid']);os.setuid(config['uid']);os.umask(0o077)
    def run(args,timeout=25):
        return subprocess.run([str(a) for a in args],preexec_fn=drop,cwd=BASE,env={'PATH':'/usr/bin:/bin','RAYON_NUM_THREADS':'2'},capture_output=True,text=True,timeout=timeout)
    def logs():
        result=[]
        for i in [0,1]:
            p=ROOT/('validator-'+str(i)+'.log')
            with p.open('rb') as stream:stream.seek(max(0,p.stat().st_size-32768));raw=stream.read()
            result.append(raw.decode(errors='replace').splitlines()[-90:])
        return result
    query="""import sys,json
from pathlib import Path
sys.path.insert(0,'/Library/NativePayLocal/tools');import localnet
r=Path('/Library/NativePayLocal/.data/s20');localnet.load(r);out=[]
for p in [23899,24899]:
 try:
  slots={c:localnet.rpc(p,'getSlot',[{'commitment':c}]) for c in ['processed','confirmed','finalized']}
  accounts=localnet.rpc(p,'getVoteAccounts',[])
  votes=[{k:v.get(k) for k in ['votePubkey','lastVote','rootSlot','activatedStake']} for v in accounts['current']+accounts['delinquent']]
  out.append({'slots':slots,'votes':votes})
 except Exception as error:out.append({'error':type(error).__name__})
print(json.dumps(out))
"""
    result={'status':'failed'}
    try:
        session=ROOT/'restart-tail-session-029.json';replacement=ROOT/'restart-tail-diagnostic-029.session.json'
        write(replacement,{'format':'local-restart-tail-test-v1','expires_at':time.time()+585},(config['uid'],config['gid']))
        publish('prior-session.json',json.loads(session.read_text()));os.replace(replacement,session)
        plist['ProgramArguments'][-1]='run-tail-test';service.PLIST.write_bytes(plistlib.dumps(plist))
        began=time.time();service.command(['/bin/launchctl','bootstrap','system',str(service.PLIST)],timeout=60)
        end=time.monotonic()+175;enabled=False
        while time.monotonic()<end and not stop_requested():
            sample=run(['/usr/bin/python3','-I','-c',query])
            try:state=json.loads(sample.stdout)
            except ValueError:state={'error':'status_unavailable'}
            instance=ROOT/'service-instance.json'
            if not enabled and instance.exists() and json.loads(instance.read_text()).get('started_at',0)>=began:
                code="""import subprocess
for i in [0,1]:subprocess.run(['/Library/NativePayLocal/target/debug/agave-validator','--ledger','/Library/NativePayLocal/.data/s20/ledger-'+str(i),'set-log-filter','warn,solana_core::replay_stage=info,solana_core::consensus=info'],check=True,capture_output=True,timeout=10)
"""
                enabled=run(['/usr/bin/python3','-I','-c',code]).returncode==0
            publish('progress.json',{'phase':'diagnosing','state':state,'replay_logging_enabled':enabled,'logs':logs()})
            time.sleep(2)
        result={'status':'diagnosed','logs':logs()}
    finally:
        try:
            if not paused():service.command(['/bin/launchctl','bootout','system',str(service.PLIST)],timeout=110)
        finally:
            service.PLIST.write_bytes(original)
            result.update(validators_paused=paused(),normal_plist_restored=service.PLIST.read_bytes()==original,
                original_private_files_unchanged=all(digest(ROOT/name)==value for name,value in before.items()))
            publish('finished.json',result)
    reports=[]
    for i in [0,1]:
        value=run([BASE/'target/debug/native-localnet','diagnose-restart',ROOT,i,'ledger-'+str(i)],40)
        reports.append(json.loads(value.stdout) if value.returncode==0 else {'error':value.stderr[-500:]})
    publish('stopped-ledgers.json',reports)
    os.close(stage_fd)

