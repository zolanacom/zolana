#!/usr/bin/env python3
"""Prepare or administer the sealed, local macOS validator service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import grp
import shutil
import stat
import subprocess
import sys
import time

ACCOUNT='_nativepay'
LABEL='local.nativepay.validator'
INSTALL=Path('/Library/NativePayLocal')
PLIST=Path('/Library/LaunchDaemons')/(LABEL+'.plist')
LEGACY_RUNTIME_FILES=('service_account.py','service_runtime.py','localnet.py','replay_localnet.py','restart_localnet.py','wallet_localnet.py','rpc_isolation.py','operator_transport.py','service_tls.py','test_faucet.py')
LEGACY_BINARIES=('agave-validator','native-localnet','native-wallet')
LEGACY_FILES=tuple('tools/'+n for n in LEGACY_RUNTIME_FILES)+tuple('target/debug/'+n for n in LEGACY_BINARIES)+('LICENSE','THIRD_PARTY.md','node/agave/LICENSE')
V2_RUNTIME_FILES=LEGACY_RUNTIME_FILES+('service_ingress.py','testnet_gateway.py','local_test_tls.py')
V3_RUNTIME_FILES=V2_RUNTIME_FILES+('history_retention.py',)
RUNTIME_FILES=V3_RUNTIME_FILES+('gateway_history.py',)
BINARIES=LEGACY_BINARIES+('native-faucet',)
V2_FILES=tuple('tools/'+n for n in V2_RUNTIME_FILES)+tuple('target/debug/'+n for n in BINARIES)+('LICENSE','THIRD_PARTY.md','node/agave/LICENSE')
V3_FILES=tuple('tools/'+n for n in V3_RUNTIME_FILES)+tuple('target/debug/'+n for n in BINARIES)+('LICENSE','THIRD_PARTY.md','node/agave/LICENSE')
FILES=tuple('tools/'+n for n in RUNTIME_FILES)+tuple('target/debug/'+n for n in BINARIES)+('LICENSE','THIRD_PARTY.md','node/agave/LICENSE')


def digest(data):return hashlib.sha256(data).hexdigest()


def regular(path,maximum=256*1024*1024):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        meta=os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or not 0<meta.st_size<=maximum:raise ValueError('invalid bounded bundle input')
        raw=stream.read(maximum+1)
        if len(raw)>maximum:raise ValueError('bundle input exceeds bound')
        return raw


def verify_bundle(root,expected=None):
    raw=regular(root/'MANIFEST.json',32768)
    if expected is not None and digest(raw)!=expected:raise ValueError('administrator-approved manifest changed')
    manifest=json.loads(raw)
    inventory={'native-service-bundle-v1':LEGACY_FILES,'native-service-bundle-v2':V2_FILES,'native-service-bundle-v3':V3_FILES,'native-service-bundle-v4':FILES}.get(manifest.get('format'))
    if set(manifest)!={'format','files'} or inventory is None or set(manifest['files'])!=set(inventory):
        raise ValueError('unexpected bundle inventory')
    for name,value in manifest['files'].items():
        if set(value)!={'sha256','size'}:raise ValueError('invalid bundle digest record')
        data=regular(root/name)
        if len(data)!=value['size'] or digest(data)!=value['sha256']:raise ValueError('bundle content changed')
    return manifest


def trusted(path, directory=False):
    meta=path.lstat()
    if meta.st_uid!=0 or meta.st_mode&0o022 or (not stat.S_ISDIR(meta.st_mode) if directory else not stat.S_ISREG(meta.st_mode)):
        raise ValueError('service code/config must be root-owned and immutable to non-root users')
    for parent in path.parents:
        m=parent.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:raise ValueError('untrusted service code ancestor')


def verify_install(root=INSTALL):
    trusted(root,True)
    manifest=verify_bundle(root)
    trusted(root/'MANIFEST.json');trusted(root/'SERVICE.json')
    for name in manifest['files']:trusted(root/name)
    config=json.loads((root/'SERVICE.json').read_text())
    if config.get('format')!='native-service-install-v1' or config.get('account')!=ACCOUNT or config.get('label')!=LABEL:
        raise ValueError('service identity configuration changed')
    user=pwd.getpwnam(ACCOUNT);group=grp.getgrnam(ACCOUNT)
    if user.pw_uid!=config['uid'] or user.pw_gid!=config['gid'] or group.gr_gid!=config['gid'] or user.pw_uid==0 or user.pw_shell!='/usr/bin/false':
        raise ValueError('service OS identity differs from sealed installation')
    return config


def launch_config():
    return {'Label':LABEL,'UserName':ACCOUNT,'GroupName':ACCOUNT,
        'ProgramArguments':['/usr/bin/python3','-I',str(INSTALL/'tools/service_runtime.py'),'run'],
        'WorkingDirectory':str(INSTALL),'EnvironmentVariables':{'PATH':'/usr/bin:/bin','PYTHONNOUSERSITE':'1','SOLANA_METRICS_CONFIG':''},
        'Umask':63,'RunAtLoad':True,'KeepAlive':True,'ThrottleInterval':15,'ExitTimeOut':90,
        'AbandonProcessGroup':False,'ProcessType':'Interactive',
        'StandardOutPath':str(INSTALL/'.data/service.stdout.log'),'StandardErrorPath':str(INSTALL/'.data/service.stderr.log')}


def prepare(source,output):
    output=output.resolve()
    if output.exists():raise ValueError('use a new local service bundle directory')
    output.mkdir(mode=0o700,parents=True)
    records={}
    for name in FILES:
        data=regular(source/name);destination=output/name;destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open('xb') as stream:stream.write(data)
        destination.chmod(0o500 if name.startswith('target/') else 0o400)
        records[name]={'size':len(data),'sha256':digest(data)}
    raw=(json.dumps({'format':'native-service-bundle-v4','files':records},sort_keys=True,indent=2)+'\n').encode()
    (output/'MANIFEST.json').write_bytes(raw);(output/'MANIFEST.json').chmod(0o400)
    verify_bundle(output)
    return {'bundle':str(output),'manifest_sha256':digest(raw),'installer_sha256':records['tools/service_account.py']['sha256'],'keys_generated':False,'installed':False}


def command(args,**kwargs):
    return subprocess.run(args,check=True,capture_output=True,text=True,timeout=kwargs.pop('timeout',180),**kwargs)


def require_root():
    if sys.platform!='darwin' or os.geteuid()!=0:raise PermissionError('macOS administrator authentication required')


def as_service(action,config,extra=()):
    def drop():
        os.setgroups([]);os.setgid(config['gid']);os.setuid(config['uid']);os.umask(0o077)
    return command(['/usr/bin/python3','-I',str(INSTALL/'tools/service_runtime.py'),action,*extra],cwd=str(INSTALL),
        env={'PATH':'/usr/bin:/bin','PYTHONNOUSERSITE':'1','SOLANA_METRICS_CONFIG':''},preexec_fn=drop,timeout=600)


def install(bundle,expected,desktop_uid):
    require_root();verify_bundle(bundle,expected)
    if verify_bundle(bundle,expected)['format']!='native-service-bundle-v4':raise ValueError('new installation requires current bundle inventory')
    if INSTALL.exists() or PLIST.exists():raise ValueError('installation already exists; preserve original service keys/state')
    try:pwd.getpwnam(ACCOUNT)
    except KeyError:pass
    else:raise ValueError('service account already exists; refusing to adopt an unrelated identity')
    try:grp.getgrnam(ACCOUNT)
    except KeyError:pass
    else:raise ValueError('service group already exists')
    selected=None
    for number in range(450,500):
        try:pwd.getpwuid(number);continue
        except KeyError:pass
        try:grp.getgrgid(number);continue
        except KeyError:pass
        selected=number;break
    if selected is None:raise ValueError('no unused local service UID/GID available')
    # Fixed records only: no login password, administrator group or sudoers rule.
    for record,fields in [('/Groups/'+ACCOUNT,{'PrimaryGroupID':str(selected),'Password':'*'}),
        ('/'+'Users/'+ACCOUNT,{'UniqueID':str(selected),'PrimaryGroupID':str(selected),'UserShell':'/usr/bin/false','NFSHomeDirectory':'/var/empty','RealName':'Native Payments Local Service','Password':'*','IsHidden':'1'})]:
        command(['/usr/bin/dscl','.','-create',record])
        for field,value in fields.items():command(['/usr/bin/dscl','.','-create',record,field,value])
    INSTALL.mkdir(mode=0o755)
    manifest=verify_bundle(bundle,expected)
    for name in FILES:
        data=regular(bundle/name)
        if digest(data)!=manifest['files'][name]['sha256']:raise ValueError('bundle changed during installation')
        destination=INSTALL/name;destination.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        with destination.open('xb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        destination.chmod(0o555 if name.startswith('target/') else 0o444)
    (INSTALL/'MANIFEST.json').write_bytes(regular(bundle/'MANIFEST.json',32768));(INSTALL/'MANIFEST.json').chmod(0o444)
    config={'format':'native-service-install-v1','account':ACCOUNT,'label':LABEL,'uid':selected,'gid':selected,'desktop_uid':desktop_uid,'port_offset':5000}
    (INSTALL/'SERVICE.json').write_text(json.dumps(config,sort_keys=True));(INSTALL/'SERVICE.json').chmod(0o444)
    state=INSTALL/'.data';state.mkdir(mode=0o700);os.chown(state,selected,selected)
    verify_install();as_service('init',config)
    with PLIST.open('xb') as stream:plistlib.dump(launch_config(),stream)
    PLIST.chmod(0o644);trusted(PLIST)
    command(['/bin/launchctl','bootstrap','system',str(PLIST)],timeout=60)
    return {'installed':True,'account':ACCOUNT,'uid':selected,'private_root':str(INSTALL/'.data/s20'),'raw_tcp_disabled':True}


def update(bundle,expected):
    """Replace reviewed code only; keep the original account, keys and ledgers."""
    require_root();verify_install();trusted(PLIST)
    old=verify_bundle(INSTALL);new=verify_bundle(bundle,expected)
    if new['format']!='native-service-bundle-v4':raise ValueError('update requires current bundle inventory')
    changed={name:regular(bundle/name) for name in FILES if old['files'].get(name)!=new['files'][name]}
    for name,data in changed.items():
        if digest(data)!=new['files'][name]['sha256']:raise ValueError('reviewed update changed')
    manifest=regular(bundle/'MANIFEST.json',32768)
    if digest(manifest)!=expected:raise ValueError('reviewed update manifest changed')
    original={}
    for name in changed:
        if name in old['files']:original[name]=regular(INSTALL/name)
        elif os.path.lexists(INSTALL/name):raise ValueError('new sealed path already occupied')
        else:original[name]=None
    original['MANIFEST.json']=regular(INSTALL/'MANIFEST.json',32768)
    def replace(name,data):
        target=INSTALL/name;temporary=target.with_name(target.name+'.update')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        temporary.chmod(0o555 if name.startswith('target/') else 0o444)
        os.replace(temporary,target)
    # Updating an intentionally paused installation must not start validators.
    active=subprocess.run(['/bin/launchctl','print','system/'+LABEL],capture_output=True,text=True,timeout=15)
    if active.returncode not in (0,113):raise ValueError('cannot determine original service loaded state')
    was_loaded=active.returncode==0
    if was_loaded:command(['/bin/launchctl','bootout','system',str(PLIST)],timeout=120)
    try:
        for name,data in changed.items():replace(name,data)
        replace('MANIFEST.json',manifest);verify_install()
    except BaseException:
        for name,data in original.items():
            if data is None:(INSTALL/name).unlink(missing_ok=True)
            else:replace(name,data)
        raise
    finally:
        if was_loaded:command(['/bin/launchctl','bootstrap','system',str(PLIST)],timeout=60)
    return {'updated_files':sorted(changed),'original_service_identity_and_private_state_retained':True,'service_left_paused':not was_loaded}


def export_client(output,client):
    require_root();config=verify_install()
    if client not in ('alice','bob') or output.parent.resolve()!=Path('/private/tmp'):
        raise ValueError('client export requires a new private temporary file and a fixed test client')
    # Contains public profile + one invitation only, never service signing keys.
    result=as_service('client-export',config,(client,))
    raw=result.stdout.encode();data=json.loads(raw)
    if set(data)!={'profile','invitation','invite_id'} or len(raw)>16384:raise ValueError('unexpected client export')
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.fchown(stream.fileno(),config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid)
    return {'exported':True,'client':client,'output':str(output),'service_keys_exported':False}


def probe_identity(config,uid,gid):
    code='''import json,os,socket
from pathlib import Path
root=Path("/Library/NativePayLocal")
checks={}
for name in ["identity-0.keypair.json","voter-0.keypair.json","rpc-access.key"]:
 try:
  fd=os.open(str(root/".data/s20"/name),os.O_RDONLY);os.close(fd);checks[name]=False
 except PermissionError:checks[name]=True
for name in ["tools/service_runtime.py","target/debug/agave-validator","SERVICE.json"]:
 try:
  fd=os.open(str(root/name),os.O_WRONLY);os.close(fd);checks[name]=False
 except PermissionError:checks[name]=True
for p in [23899,24899]:
 s=socket.socket(socket.AF_UNIX)
 try:s.connect(str(root/".data/s20"/("rpc-%s.sock"%p)));checks[str(p)]=False
 except PermissionError:checks[str(p)]=True
 finally:s.close()
print(json.dumps(checks))
'''
    def drop():os.setgroups([]);os.setgid(gid);os.setuid(uid)
    result=command(['/usr/bin/python3','-I','-c',code],preexec_fn=drop,env={'PATH':'/usr/bin:/bin'},cwd='/private/tmp')
    checks=json.loads(result.stdout)
    if len(checks)!=8 or not all(checks.values()):raise ValueError('desktop user bypassed service isolation')
    return checks


def acceptance():
    require_root();config=verify_install()
    # The current service runtime owns all signing; administrator output contains no secret material.
    before=json.loads(as_service('test-begin',config).stdout)
    denied=probe_identity(config,config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid)
    command(['/bin/launchctl','kill','SIGKILL','system/'+LABEL],timeout=30)
    deadline=time.monotonic()+180;last=None
    while time.monotonic()<deadline:
        try:
            result=as_service('test-finish',config);after=json.loads(result.stdout);break
        except subprocess.CalledProcessError as error:last=error;time.sleep(2)
    else:raise RuntimeError('service did not recover its original payment after SIGKILL') from last
    # A missing original credential must stop the launchd restart, not initialize
    # a fresh capability or an open TCP listener. Restore the exact same inode.
    key=INSTALL/'.data/s20/rpc-access.key';retained=key.with_suffix('.key.retained');original=digest(regular(key,4096))
    command(['/bin/launchctl','bootout','system',str(PLIST)],timeout=120)
    key.rename(retained)
    try:
        command(['/bin/launchctl','bootstrap','system',str(PLIST)],timeout=60)
        time.sleep(3)
        try:as_service('status',config)
        except subprocess.CalledProcessError:pass
        else:raise ValueError('missing credential permitted service startup')
        if key.exists():raise ValueError('service regenerated its original capability')
    finally:
        retained.rename(key)
        command(['/bin/launchctl','kickstart','-k','system/'+LABEL],timeout=60)
    end=time.monotonic()+180
    while time.monotonic()<end:
        try:
            restored=json.loads(as_service('status',config).stdout)
            if restored['native_state']==json.loads((INSTALL/'.data/s20/service-acceptance.json').read_text())['native_state']:break
        except subprocess.CalledProcessError:pass
        time.sleep(1)
    else:raise ValueError('original service state did not recover after missing credential')
    if digest(regular(key,4096))!=original:raise ValueError('original service capability changed')
    denied_after=probe_identity(config,config['desktop_uid'],pwd.getpwuid(config['desktop_uid']).pw_gid)
    report={'status':'passed','before':before,'after':after,'desktop_denied_before':denied,'desktop_denied_after':denied_after,'wallet_port_untouched':8765,'missing_credential_restart_refused':True,'original_credential_restored_without_reset':True}
    path=INSTALL/'ACCEPTANCE.json';path.write_text(json.dumps(report,sort_keys=True,indent=2));path.chmod(0o444)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('prepare');p.add_argument('--output',type=Path,required=True)
    p=sub.add_parser('install');p.add_argument('--bundle',type=Path,required=True);p.add_argument('--manifest-sha256',required=True);p.add_argument('--desktop-uid',type=int,required=True)
    p=sub.add_parser('update');p.add_argument('--bundle',type=Path,required=True);p.add_argument('--manifest-sha256',required=True)
    p=sub.add_parser('client-export');p.add_argument('--client',choices=['alice','bob'],required=True);p.add_argument('--output',type=Path,required=True)
    sub.add_parser('ingress-init')
    sub.add_parser('test');sub.add_parser('verify')
    args=parser.parse_args()
    if args.action=='prepare':result=prepare(Path(__file__).resolve().parents[1],args.output)
    elif args.action=='install':result=install(args.bundle,args.manifest_sha256,args.desktop_uid)
    elif args.action=='update':result=update(args.bundle,args.manifest_sha256)
    elif args.action=='client-export':result=export_client(args.output,args.client)
    elif args.action=='ingress-init':require_root();result=json.loads(as_service('ingress-init',verify_install()).stdout)
    elif args.action=='test':result=acceptance()
    else:result=verify_install()
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
