"""Fixed local stopped-service diagnosis on private APFS ledger copies."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

BASE=Path('/Library/NativePayLocal')
sys.path.insert(0,str(BASE/'tools'))
import service_account as service

DIAGNOSTIC=BASE/'.diagnostics/LOCAL-029/native-localnet'
FIXED_LAB=BASE/'.diagnostics/LOCAL-029/native-localnet-fixed-v2'
FIXED_VALIDATOR=BASE/'.diagnostics/LOCAL-029/agave-validator-fixed-v2'
ROOT=BASE/'.data/s20'
COPY=ROOT/'restart-copy-029b'


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def private_json(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as output:
        json.dump(value,output,sort_keys=True,indent=2);output.write('\n');output.flush();os.fsync(output.fileno())


def stopped():
    if subprocess.run(['/bin/launchctl','print','system/'+service.LABEL],capture_output=True).returncode!=113:
        raise ValueError('normal service must remain unloaded')
    if subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode!=1:
        raise ValueError('all validators must be stopped before copying')


def copy_owned(source,destination):
    # APFS clone copies share extents, never inodes. Offline replay can change
    # its copy without editing the original. Reject escaping links/special files.
    paths=[source,*source.rglob('*')] if source.is_dir() else [source]
    links=[];stale_admin_socket=False
    for path in paths:
        meta=path.lstat()
        if stat.S_ISLNK(meta.st_mode):
            target=path.resolve()
            if not target.is_relative_to(source):raise ValueError('copy link escapes its ledger')
            links.append((path.relative_to(source),target.relative_to(source)))
        elif not (stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode)):
            if path==source/'admin.rpc' and stat.S_ISSOCK(meta.st_mode):
                # An abrupt crash leaves this runtime endpoint behind. Exclude
                # it only from the copy; never unlink the original endpoint.
                stale_admin_socket=True
            else:raise ValueError('copy source contains a link or special file: '+path.name)
        if meta.st_uid!=os.getuid():raise ValueError('copy source ownership differs')
    if stale_admin_socket:
        destination.mkdir(mode=0o700)
        for path in source.iterdir():
            if path.name!='admin.rpc':subprocess.run(['/bin/cp','-cRP',str(path),str(destination/path.name)],check=True,capture_output=True,timeout=120)
    else:subprocess.run(['/bin/cp','-cRP',str(source),str(destination)],check=True,capture_output=True,timeout=120)
    # Agave snapshots contain account_path_* symlinks. Map only validated
    # internal links into the copy, so replay cannot follow them to originals.
    for name,target in links:
        link=destination/name
        if not link.is_symlink():raise ValueError('copied snapshot link changed')
        link.unlink();link.symlink_to(destination/target)


def copy():
    service.require_root();config=service.verify_install();stopped()
    if COPY.exists():raise ValueError('diagnostic copy already exists; preserve it')
    marker=json.loads((BASE/'CANONICAL-ARCHIVE-028.started.json').read_text())
    for name,value in marker['private_file_digests'].items():
        if digest(ROOT/name)!=value:raise ValueError('original private file changed: '+name)
    if digest(service.PLIST)!=marker['original_plist_sha256']:raise ValueError('normal plist changed')
    # All keys and copies remain under the original dedicated UID's 0700 root.
    os.setgroups([]);os.setgid(config['gid']);os.setuid(config['uid']);os.umask(0o077)
    locks=[]
    try:
        for i in [0,1]:
            lock=(ROOT/('ledger-'+str(i))/'ledger.lock').open('a+')
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(lock)
        COPY.mkdir(mode=0o700)
        names=['network.json','rpc-access.key']
        names += [role+'-'+str(i)+'.keypair.json' for i in [0,1] for role in ['identity','voter']]
        names += [directory+'-'+str(i) for i in [0,1] for directory in ['consensus','ledger']]
        for name in names:copy_owned(ROOT/name,COPY/name)
        original_towers={str(p.relative_to(ROOT)):digest(p) for i in [0,1] for p in (ROOT/('consensus-'+str(i))).glob('tower-*.bin')}
        if not all(digest(COPY/name)==value for name,value in original_towers.items()):raise ValueError('copied tower bytes differ')
        private_json(COPY/'copy-evidence.json',{'format':'native-restart-copy-v1','original_towers':original_towers,
            'original_private_files':marker['private_file_digests']})
        print(json.dumps({'status':'private_copies_created','copies':str(COPY),'signed_towers_copied':len(original_towers)}),flush=True)
    finally:
        for lock in locks:lock.close()


def inspect():
    service.require_root();config=service.verify_install();stopped()
    service.trusted(DIAGNOSTIC)
    os.setgroups([]);os.setgid(config['gid']);os.setuid(config['uid']);os.umask(0o077)
    evidence=json.loads((COPY/'copy-evidence.json').read_text())
    for name,value in evidence['original_private_files'].items():
        if digest(ROOT/name)!=value:raise ValueError('original private file changed')
    independent=0
    for i in [0,1]:
        original=ROOT/('ledger-'+str(i));cloned=COPY/('ledger-'+str(i))
        for source in original.rglob('*'):
            target=cloned/source.relative_to(original);meta=source.lstat()
            if stat.S_ISLNK(meta.st_mode):
                if not target.is_symlink() or not target.resolve().is_relative_to(cloned):raise ValueError('snapshot link can reach original data')
            elif stat.S_ISREG(meta.st_mode):
                other=target.lstat()
                if not stat.S_ISREG(other.st_mode) or other.st_ino==meta.st_ino or other.st_size!=meta.st_size:raise ValueError('copy is not independent')
                independent+=1
    reports=[]
    for i in [0,1]:
        result=subprocess.run([str(DIAGNOSTIC),'diagnose-restart',str(COPY),str(i),'ledger-'+str(i)],capture_output=True,text=True,check=True,timeout=30)
        value=json.loads(result.stdout);private_json(COPY/('diagnostic-'+str(i)+'.json'),value);reports.append(value)
    print(json.dumps({'status':'diagnosed_on_private_copies','copies':str(COPY),'independent_files':independent,'reports':reports}),flush=True)


def validate_copy(future=False):
    service.require_root();config=service.verify_install();stopped()
    service.trusted(FIXED_LAB);service.trusted(FIXED_VALIDATOR)
    os.setgroups([]);os.setgid(config['gid']);os.setuid(config['uid']);os.umask(0o077);os.nice(15)
    os.environ['RAYON_NUM_THREADS']='2'
    evidence=json.loads((COPY/'copy-evidence.json').read_text())
    if (COPY/'validated-copy-029.json').exists():raise ValueError('copy validation already completed')
    for name,value in evidence['original_private_files'].items():
        if digest(ROOT/name)!=value:raise ValueError('original private file changed')
    # Translate only the disposable copy's private IPC routes. Keep its token
    # and chain identity; no original credential/policy is written or exported.
    from history_retention import atomic
    key=COPY/'rpc-access.key';credential=json.loads(key.read_text())
    credential['sockets']={port:str(COPY/Path(path).name) for port,path in credential['sockets'].items()}
    material=json.dumps(credential,sort_keys=True).encode()
    if key.read_bytes()!=material:atomic(key,material)
    policy=json.loads((ROOT/'raw-rpc-required.json').read_text());policy['credential_sha256']=digest(key)
    policy_path=COPY/'raw-rpc-required.json'
    if policy_path.exists():
        if json.loads(policy_path.read_text())!=policy:raise ValueError('copy policy changed')
    else:private_json(policy_path,policy)
    import localnet,replay_localnet
    localnet.LAB=FIXED_LAB;localnet.VALIDATOR=FIXED_VALIDATOR
    replay_localnet.LAB=FIXED_LAB;replay_localnet.VALIDATOR=FIXED_VALIDATOR
    before=[replay_localnet.plan(COPY,i) for i in [0,1]]
    checkpoint=6270 if future else 6174
    if before[0]['slot']!=checkpoint or before[1]['slot']!=checkpoint or before[0]['bank_hash']!=before[1]['bank_hash']:
        raise ValueError('copy checkpoint differs from original diagnosis')
    if future:
        if before[0]['last_vote']!=6271 or before[0]['retained_future_tower_vote']!=6271 or 6271 not in before[0]['retained_partial_slots']:
            raise ValueError('copy lost the crash-persisted future vote')
    else:
        if before[0]['retained_competing_slots']!=[6176] or before[0]['retained_partial_slots']!=[6175,6179]:
            raise ValueError('copy no longer reproduces original restart tail')
        if before[0]['retained_rejected_slots']!=[6156]:raise ValueError('copy lost its retained rejected fork')
    private_json(COPY/'before-validation.json',before)
    result=replay_localnet._replay(COPY,localnet.load(COPY),before,0,checkpoint,before[1]['bank_hash'])
    for name,value in evidence['original_towers'].items():
        if digest(ROOT/name)!=value or digest(COPY/name)!=value:raise ValueError('signed tower changed during no-voting validation')
    for name,value in evidence['original_private_files'].items():
        if digest(ROOT/name)!=value:raise ValueError('original private file changed during copy validation')
    private_json(COPY/'validated-copy-029.json',dict(result,original_private_files_unchanged=True,
        competing_fork_preserved=True,partial_children_preserved=True,checkpoint=checkpoint,retained_future_tower_vote=6271 if future else None))
    print(json.dumps({'status':'copy_checkpoint_verified_without_voting','checkpoint':checkpoint,
        'competing_fork_preserved':True,'partial_children_preserved':True,'original_private_files_unchanged':True,'future_vote_retained':future}))


if __name__=='__main__':
    if sys.argv[1:]==['--copy']:copy()
    elif sys.argv[1:]==['--inspect']:inspect()
    elif sys.argv[1:]==['--validate-copy']:validate_copy()
    elif sys.argv[1:]==['--validate-future-copy']:
        COPY=ROOT/'restart-copy-029d'
        FIXED_LAB=BASE/'.diagnostics/LOCAL-029/native-localnet-fixed-v3'
        # copy() deliberately drops privileges permanently. Keep validation's
        # root verifier in the parent; ledger work in both paths runs as UID450.
        pid=os.fork()
        if pid==0:
            try:copy()
            except BaseException:
                import traceback
                traceback.print_exc();os._exit(1)
            os._exit(0)
        _,status=os.waitpid(pid,0)
        if status:raise RuntimeError('preserve failed future-copy evidence')
        validate_copy(future=True)
    elif sys.argv[1:]==['--validate-existing-future-copy']:
        COPY=ROOT/'restart-copy-029d'
        FIXED_LAB=BASE/'.diagnostics/LOCAL-029/native-localnet-fixed-v3'
        validate_copy(future=True)
    else:raise ValueError('unexpected controller arguments')
