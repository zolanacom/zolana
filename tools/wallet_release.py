#!/usr/bin/env python3
"""Offline release signing/verification and recoverable standalone installation.

Obtain this tool and the publisher pin independently of a downloaded wallet.
No downloaded Python or wallet executable is imported during verification.
"""
import argparse
import base64
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import tempfile

OPENSSL='/usr/bin/openssl'
ARCHIVE_LIMIT=64*1024*1024
CONTENT_LIMIT=128*1024*1024
FILE_LIMIT=64*1024*1024
HEX=re.compile('[0-9a-f]{64}')
P256=bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004')
DOMAIN=b'native-wallet-release-signature-v1\x00'
EXECUTABLES={'bin/native-wallet','start-wallet.command'}
REQUIRED=EXECUTABLES|{'runtime/wallet_launch.py','runtime/wallet_ui.py','wallet-profile.json','LICENSE','THIRD_PARTY.md','AGAVE-LICENSE','README.txt','assets/index.html','assets/style.css','assets/app.js','DEPENDENCIES.json'}
BUILD_KINDS=('local-development','path-remapped-development')


def generic_paths_absent(raw):
    prefixes=tuple('/'+part+'/' for part in ('Users','home','private/var/folders','var/folders','private/tmp','tmp'))
    if any(prefix.encode(codec) in raw for prefix in prefixes for codec in ('utf-8','utf-16-le','utf-16-be')):
        raise ValueError('artifact contains a personal or temporary path')


def build_metadata(value,binary):
    keys={'format','recipe','binary_sha256','binary_size','source_sha256','cargo_lock_sha256','source_commit','source_dirty','rustc_release','rustc_commit','target','profile','jobs','offline','path_audit','linkage','probes','canonical_prefixes'}
    if (not isinstance(value,dict) or set(value)!=keys or value['format']!='native-wallet-build-v1' or value['recipe']!='path-remapped-wallet-v1' or
            any(not hex64(value[k]) for k in ('binary_sha256','source_sha256','cargo_lock_sha256')) or type(value['binary_size']) is not int or value['binary_size']!=len(binary) or value['binary_sha256']!=sha(binary) or
            not isinstance(value['source_commit'],str) or re.fullmatch('[0-9a-f]{40}',value['source_commit']) is None or type(value['source_dirty']) is not bool or
            value['rustc_release']!='1.92.0' or not isinstance(value['rustc_commit'],str) or re.fullmatch('[0-9a-f]{40}',value['rustc_commit']) is None or value['target']!='aarch64-apple-darwin' or
            value['profile']!='wallet-release' or type(value['jobs']) is not int or value['jobs']!=1 or value['offline'] is not True or
            encode(value['path_audit'])!=encode({'format':'native-path-audit-v1','known_roots_absent':True,'generic_personal_paths_absent':True,'encodings':['utf-8','utf-16-le','utf-16-be']}) or
            encode(value['probes'])!=encode({'rust_file_macro':True,'rust_panic_location':True,'native_file_macro':True,'probe_binary_paths_clean':True}) or
            value['canonical_prefixes']!={'home':'/native/home','temporary':'/native/tmp','build':'/native/build','source':'/native/src','cargo':'/native/cargo','toolchain':'/native/toolchain'}):raise ValueError('invalid or mismatched wallet build receipt')
    item=value['linkage']
    if (not isinstance(item,dict) or set(item)!={'system_only','libraries','rpaths','debug_segments','uuid_commands','native_signature'} or item['system_only'] is not True or
            any(type(item[k]) is not int or item[k]!=0 for k in ('rpaths','debug_segments','uuid_commands')) or item['native_signature']!='toolchain-ad-hoc' or
            not isinstance(item['libraries'],list) or not 1<=len(item['libraries'])<=32 or any(not isinstance(p,str) or len(p)>512 or not p.startswith(('/usr/lib/','/System/Library/Frameworks/')) or '..' in PurePosixPath(p).parts for p in item['libraries'])):raise ValueError('invalid wallet build linkage receipt')
    generic_paths_absent(binary)
    return value


def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def host():return platform.system().lower()+'-'+platform.machine().lower()
def hex64(value):return isinstance(value,str) and HEX.fullmatch(value) is not None


def decode(raw):
    def unique(pairs):
        value={}
        for k,v in pairs:
            if k in value:raise ValueError('duplicate JSON field')
            value[k]=v
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def read(path,limit,secret=False,allow_empty=False):
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        meta=os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&(0o077 if secret else 0o022) or not (0 if allow_empty else 1)<=meta.st_size<=limit:
            raise ValueError('unsafe or oversized release input')
        data=stream.read(limit+1)
        if len(data)!=meta.st_size:raise ValueError('release input changed while reading')
        return data


def directory(path):
    meta=path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077:raise ValueError('release directory must be private and owned')


def parents(path):
    for parent in path.resolve().parents:
        meta=parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0,os.getuid()) or (meta.st_mode&0o022 and not (meta.st_uid==0 and meta.st_mode&stat.S_ISVTX)):
            raise ValueError('unsafe release parent directory')


def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def create(path,data,mode=0o600):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode),'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())


def atomic(path,value):
    temporary=path.with_name('.'+path.name+'-'+secrets.token_hex(8))
    create(temporary,encode(value));os.replace(temporary,path);fsync_dir(path.parent)


def crypto(args,data):
    result=subprocess.run([OPENSSL,*args],input=data,capture_output=True,timeout=15,
        env={'PATH':'/usr/bin:/bin','OPENSSL_CONF':'/dev/null'})
    if result.returncode:raise ValueError('release cryptographic check failed')
    return result.stdout


def public_der(pem):
    if b'PRIVATE' in pem:raise ValueError('publisher requires a public key')
    raw=crypto(['pkey','-pubin','-outform','DER'],pem)
    if len(raw)!=len(P256)+64 or not raw.startswith(P256):raise ValueError('publisher key must be named-curve P-256')
    return raw


def public_pem(der):
    if len(der)!=len(P256)+64 or not der.startswith(P256):raise ValueError('invalid publisher public key')
    text=base64.b64encode(der)
    return b'-----BEGIN PUBLIC KEY-----\n'+b'\n'.join(text[i:i+64] for i in range(0,len(text),64))+b'\n-----END PUBLIC KEY-----\n'


def sequence(value):return type(value) is int and 1<=value<=2**31-1


def descriptor(value):
    if (not isinstance(value,dict) or set(value)!={'format','channel','sequence','key_sha256','archive_sha256','archive_size','manifest_sha256','profile_sha256','platform','source_commit','binary_kind'} or
            value['format']!='native-wallet-release-v1' or not isinstance(value['channel'],str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,47}',value['channel']) is None or
            not sequence(value['sequence']) or any(not hex64(value[k]) for k in ('key_sha256','archive_sha256','manifest_sha256','profile_sha256')) or
            type(value['archive_size']) is not int or not 1<=value['archive_size']<=ARCHIVE_LIMIT or
            value['platform'] not in ('darwin-arm64','darwin-x86_64','linux-aarch64','linux-x86_64') or
            not isinstance(value['source_commit'],str) or re.fullmatch('[0-9a-f]{40}',value['source_commit']) is None or value['binary_kind'] not in BUILD_KINDS):
        raise ValueError('invalid local release descriptor')
    return value


def safe_name(name):
    if not isinstance(name,str):return False
    path=PurePosixPath(name)
    return isinstance(name,str) and 0<len(name)<=240 and re.fullmatch('[A-Za-z0-9_.+/-]+',name) is not None and not path.is_absolute() and str(path)==name and all(p not in ('.','..') for p in path.parts)


def inventory(files):
    if 'MANIFEST.json' not in files or not REQUIRED<=set(files):raise ValueError('wallet release missing required files')
    if any(name not in REQUIRED|{'MANIFEST.json','BUILD.json'} and not name.startswith('notices/') for name in files):raise ValueError('file outside wallet release allowlist')
    raw=files['MANIFEST.json']
    if len(raw)>1_000_000:raise ValueError('manifest exceeds limit')
    manifest=decode(raw)
    if (not isinstance(manifest,dict) or set(manifest)!={'format','platform','source_commit','source_dirty','binary_kind','files'} or
            manifest['format']!='native-wallet-bundle-v1' or type(manifest['source_dirty']) is not bool or manifest['binary_kind'] not in BUILD_KINDS or
            not isinstance(manifest['files'],dict) or set(manifest['files'])!=set(files)-{'MANIFEST.json'}):raise ValueError('invalid wallet manifest inventory')
    for name,item in manifest['files'].items():
        if (not safe_name(name) or not isinstance(item,dict) or set(item)!={'size','sha256'} or type(item['size']) is not int or
                item['size']!=len(files[name]) or item['sha256']!=sha(files[name])):raise ValueError('wallet file digest mismatch')
    profile=decode(files['wallet-profile.json'])
    if not isinstance(profile,dict) or profile.get('format')!='native-wallet-profile-v1':raise ValueError('invalid public wallet profile')
    if manifest['binary_kind']=='path-remapped-development':
        if 'BUILD.json' not in files or len(files['BUILD.json'])>16384 or manifest['platform']!='darwin-arm64':raise ValueError('missing or incompatible remapped build receipt')
        build_metadata(decode(files['BUILD.json']),files['bin/native-wallet'])
    elif 'BUILD.json' in files:raise ValueError('development build cannot claim a remapped receipt')
    return manifest


def unpack(data):
    files={};total=0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data),mode='rb') as compressed:
            expanded=compressed.read(CONTENT_LIMIT+2*1024*1024+1)
        if len(expanded)>CONTENT_LIMIT+2*1024*1024:raise ValueError('expanded archive exceeds limit')
        with tarfile.open(fileobj=io.BytesIO(expanded),mode='r:') as archive:
            for member in archive:
                if len(files)>=1024 or not member.name.startswith('native-wallet/'):raise ValueError('invalid release archive inventory')
                name=member.name[len('native-wallet/'):]
                if not safe_name(name) or name in files or member.type!=tarfile.REGTYPE or member.pax_headers or member.linkname or member.size<0 or member.size>FILE_LIMIT or member.mode!=(0o755 if name in EXECUTABLES else 0o644):
                    raise ValueError('unsafe wallet archive member')
                total+=member.size
                if total>CONTENT_LIMIT:raise ValueError('release contents exceed limit')
                files[name]=archive.extractfile(member).read(member.size+1)
                if len(files[name])!=member.size:raise ValueError('truncated wallet archive')
    except (tarfile.TarError,EOFError,gzip.BadGzipFile) as error:raise ValueError('invalid wallet archive') from error
    for name in files:
        if any(str(parent) in files for parent in PurePosixPath(name).parents):raise ValueError('archive file-directory conflict')
    return files,inventory(files)


def attest(archive_path,key_path,channel,number,output,password_file=None):
    data=read(archive_path,ARCHIVE_LIMIT);files,manifest=unpack(data)
    key=read(key_path,16384,True);password=read(password_file,1024,True) if password_file else b'\n'
    output=Path(output);signature_path=Path(str(output)+'.sig')
    if os.path.lexists(output) or os.path.lexists(signature_path):raise ValueError('use new release signature paths')
    with tempfile.TemporaryDirectory(prefix='wallet-release-sign-') as tmp:
        root=Path(tmp);private=root/'key.pem';passfile=root/'pass';create(private,key);create(passfile,password)
        der=crypto(['pkey','-in',str(private),'-passin','file:'+str(passfile),'-pubout','-outform','DER'],b'')
        public_pem(der)
        value=descriptor(dict(format='native-wallet-release-v1',channel=channel,sequence=number,key_sha256=sha(der),archive_sha256=sha(data),archive_size=len(data),
            manifest_sha256=sha(files['MANIFEST.json']),profile_sha256=sha(files['wallet-profile.json']),platform=manifest['platform'],source_commit=manifest['source_commit'],binary_kind=manifest['binary_kind']))
        raw=encode(value);signature=crypto(['dgst','-sha256','-sign',str(private),'-passin','file:'+str(passfile)],DOMAIN+raw)
    create(output,raw);create(signature_path,signature);fsync_dir(output.parent)
    return value


def authenticate(raw,signature,trust):
    value=descriptor(decode(raw))
    if raw!=encode(value) or not 8<=len(signature)<=80:raise ValueError('noncanonical release descriptor or signature')
    if any(value[k]!=trust[k] for k in ('channel','key_sha256','profile_sha256','platform')) or value['sequence']<trust['minimum_sequence']:
        raise ValueError('release differs from independently pinned policy')
    with tempfile.TemporaryDirectory(prefix='wallet-release-verify-') as tmp:
        root=Path(tmp);pub=root/'key.pem';sig=root/'signature';create(pub,public_pem(base64.b64decode(trust['public_key_der'],validate=True)));create(sig,signature)
        crypto(['dgst','-sha256','-verify',str(pub),'-signature',str(sig)],DOMAIN+raw)
    return value


def match(value,files,manifest):
    if (sha(files['MANIFEST.json'])!=value['manifest_sha256'] or sha(files['wallet-profile.json'])!=value['profile_sha256'] or
            any(manifest[k]!=value[k] for k in ('platform','source_commit','binary_kind'))):raise ValueError('signed release and bundle differ')


def initialize(root,public_key,key_sha256,channel,profile_sha256,minimum_sequence):
    der=public_der(read(public_key,4096))
    if not hex64(key_sha256) or sha(der)!=key_sha256:raise ValueError('publisher public key differs from independent pin')
    if not hex64(profile_sha256) or not sequence(minimum_sequence) or not isinstance(channel,str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,47}',channel) is None:raise ValueError('invalid independent release policy')
    root=Path(root).absolute()
    if os.path.lexists(root):raise ValueError('release initialization requires a new directory')
    parents(root)
    root.mkdir(mode=0o700);root=root.resolve()
    trust=dict(format='native-wallet-release-trust-v1',channel=channel,key_sha256=key_sha256,public_key_der=base64.b64encode(der).decode(),profile_sha256=profile_sha256,platform=host(),minimum_sequence=minimum_sequence)
    create(root/'trust.json',encode(trust));(root/'releases').mkdir(mode=0o700)
    atomic(root/'state.json',dict(format='native-wallet-install-v1',trust_sha256=sha(encode(trust)),sequence=0,active=None,pending=None))
    create(root/'initialized',encode({'format':'native-wallet-install-marker-v1','trust_sha256':sha(encode(trust))}));fsync_dir(root);fsync_dir(root.parent)
    return trust


def version(value):return str(value['sequence']).zfill(10)+'-'+value['archive_sha256'][:24]


class Installation:
    def __init__(self,root,hook=None):
        self.root=Path(root).absolute();directory(self.root);parents(self.root);self.root=self.root.resolve();self.hook=hook or (lambda _:None);self.failed=False
        self.lock=os.open(self.root/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            meta=os.fstat(self.lock)
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077:raise ValueError('unsafe installation lock')
            fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            raw=read(self.root/'trust.json',8192,True);self.trust=decode(raw);t=self.trust
            if (not isinstance(t,dict) or set(t)!={'format','channel','key_sha256','public_key_der','profile_sha256','platform','minimum_sequence'} or t['format']!='native-wallet-release-trust-v1' or
                    t['platform']!=host() or not sequence(t['minimum_sequence']) or not hex64(t['profile_sha256']) or not hex64(t['key_sha256']) or
                    not isinstance(t['channel'],str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,47}',t['channel']) is None or
                    not isinstance(t['public_key_der'],str) or sha(base64.b64decode(t['public_key_der'],validate=True))!=t['key_sha256']):raise ValueError('invalid release trust policy')
            public_pem(base64.b64decode(t['public_key_der'],validate=True))
            marker=decode(read(self.root/'initialized',8192,True))
            if marker!={'format':'native-wallet-install-marker-v1','trust_sha256':sha(raw)}:raise ValueError('release trust policy changed')
            self.state=decode(read(self.root/'state.json',16384,True));s=self.state
            if (not isinstance(s,dict) or set(s)!={'format','trust_sha256','sequence','active','pending'} or s['format']!='native-wallet-install-v1' or
                    s['trust_sha256']!=sha(raw) or type(s['sequence']) is not int or not 0<=s['sequence']<=2**31-1 or (s['sequence']==0)!=(s['active'] is None)):
                raise ValueError('invalid initialized installation state')
            directory(self.root/'releases')
            for item in (s['active'],s['pending']):
                if item is None:continue
                if not isinstance(item,dict) or set(item)!={'release','descriptor_sha256'} or not hex64(item['descriptor_sha256']):raise ValueError('invalid install action')
                descriptor(item['release'])
                if sha(encode(item['release']))!=item['descriptor_sha256']:raise ValueError('install action digest changed')
                for k in ('channel','key_sha256','profile_sha256','platform'):
                    if item['release'][k]!=self.trust[k]:raise ValueError('install action policy changed')
            if s['active'] and s['active']['release']['sequence']!=s['sequence']:raise ValueError('active sequence changed')
            if s['pending'] and s['pending']['release']['sequence']<=s['sequence']:raise ValueError('pending sequence rollback')
        except BaseException:self.close();raise
    def close(self):
        if self.lock is not None:os.close(self.lock);self.lock=None
    def ready(self):
        if self.failed or self.lock is None:raise ValueError('installation must reopen after interruption or uncertain storage')
    def save(self):
        self.ready()
        try:atomic(self.root/'state.json',self.state)
        except BaseException:self.failed=True;raise
    def current(self):
        self.ready()
        if self.state['active'] is None:raise ValueError('no authenticated wallet installed')
        return self.check_installed(self.state['active'])
    def check_installed(self,action):
        value=action['release'];root=self.root/'releases'/version(value);directory(root);bundle=root/'bundle';directory(bundle)
        if {p.name for p in root.iterdir()}!={'bundle','release.json','release.sig'}:raise ValueError('installed release metadata inventory changed')
        raw=read(root/'release.json',8192,True);signature=read(root/'release.sig',80,True)
        if sha(raw)!=action['descriptor_sha256'] or authenticate(raw,signature,self.trust)!=value:raise ValueError('installed release identity changed')
        files={};directories=set();total=0
        for path in bundle.rglob('*'):
            meta=path.lstat()
            if stat.S_ISDIR(meta.st_mode):
                directory(path);directories.add(path.relative_to(bundle).as_posix())
                if len(directories)>1024:raise ValueError('installed directory inventory exceeds limit')
                continue
            name=path.relative_to(bundle).as_posix()
            if not safe_name(name) or len(files)>=1024 or not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o777!=(0o500 if name in EXECUTABLES else 0o400):raise ValueError('unsafe installed release file')
            files[name]=read(path,FILE_LIMIT,allow_empty=True);total+=len(files[name])
            if total>CONTENT_LIMIT:raise ValueError('installed release exceeds limit')
        match(value,files,inventory(files))
        expected={str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent)!='.'}
        if directories!=expected:raise ValueError('installed directory inventory changed')
        return bundle
    def verify(self,archive_path,release_path):
        self.ready()
        raw=read(release_path,8192);signature=read(str(release_path)+'.sig',80)
        value=authenticate(raw,signature,self.trust)
        current=self.state['active'];pending=self.state['pending']
        if value['sequence']<self.state['sequence'] or (current and value['sequence']==self.state['sequence'] and sha(raw)!=current['descriptor_sha256']):raise ValueError('release rollback or sequence equivocation')
        action={'release':value,'descriptor_sha256':sha(raw)}
        if pending is not None and pending!=action:raise ValueError('another interrupted release must recover first')
        data=read(archive_path,ARCHIVE_LIMIT)
        if len(data)!=value['archive_size'] or sha(data)!=value['archive_sha256']:raise ValueError('download differs from signed release')
        files,manifest=unpack(data);match(value,files,manifest)
        return action,files,raw,signature
    def install(self,archive_path,release_path):
        self.ready()
        try:return self._install(archive_path,release_path)
        except BaseException:self.failed=True;raise
    def _install(self,archive_path,release_path):
        action,files,raw,signature=self.verify(archive_path,release_path)
        if self.state['active']:self.current()
        if self.state['active']==action:return self.current()
        if self.state['pending'] is None:
            self.state['pending']=action;self.save()
        self.hook('planned')
        final=self.root/'releases'/version(action['release'])
        if os.path.lexists(final):self.check_installed(action)
        else:
            stage=Path(tempfile.mkdtemp(prefix='.staging-',dir=self.root/'releases'));bundle=stage/'bundle';bundle.mkdir(mode=0o700)
            for index,(name,data) in enumerate(sorted(files.items())):
                path=bundle/name;parent=bundle
                # pathlib's parents=True applies mode only to the leaf; create
                # every intermediate notice directory explicitly and privately.
                for component in PurePosixPath(name).parts[:-1]:
                    parent=parent/component;parent.mkdir(mode=0o700,exist_ok=True);directory(parent)
                create(path,data,0o500 if name in EXECUTABLES else 0o400)
                if index==0:self.hook('extracting')
            create(stage/'release.json',raw);create(stage/'release.sig',signature)
            for path in sorted((p for p in stage.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):fsync_dir(path)
            fsync_dir(stage);os.rename(stage,final);fsync_dir(final.parent)
        self.hook('published')
        self.check_installed(action)
        self.state.update(sequence=action['release']['sequence'],active=action,pending=None);self.save();self.hook('activated')
        return self.current()


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    sign=sub.add_parser('sign');sign.add_argument('--archive',required=True,type=Path);sign.add_argument('--private-key',required=True,type=Path);sign.add_argument('--password-file',type=Path)
    sign.add_argument('--channel',required=True);sign.add_argument('--sequence',required=True,type=int);sign.add_argument('--output',required=True,type=Path)
    init=sub.add_parser('init');init.add_argument('--root',required=True,type=Path);init.add_argument('--public-key',required=True,type=Path);init.add_argument('--key-sha256',required=True)
    init.add_argument('--channel',required=True);init.add_argument('--profile-sha256',required=True);init.add_argument('--minimum-sequence',required=True,type=int)
    for name in ('verify','install','status','run'):
        cmd=sub.add_parser(name);cmd.add_argument('--root',required=True,type=Path)
        if name in ('verify','install'):cmd.add_argument('--archive',required=True,type=Path);cmd.add_argument('--release',required=True,type=Path)
        if name=='run':cmd.add_argument('wallet_arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args()
    if args.action=='sign':
        value=attest(args.archive,args.private_key,args.channel,args.sequence,args.output,args.password_file)
        print(json.dumps({'signed':True,'sequence':value['sequence'],'key_sha256':value['key_sha256'],'distributed':False}));return
    if args.action=='init':
        initialize(args.root,args.public_key,args.key_sha256,args.channel,args.profile_sha256,args.minimum_sequence)
        print(json.dumps({'initialized':True,'independent_pin_required':True}));return
    installation=Installation(args.root)
    try:
        if args.action=='verify':
            action,_,_,_=installation.verify(args.archive,args.release);print(json.dumps({'verified':True,'sequence':action['release']['sequence'],'executed_downloaded_code':False}))
        elif args.action=='install':
            installation.install(args.archive,args.release);print(json.dumps({'installed':True,'sequence':installation.state['sequence'],'wallet_state_accessed':False}))
        elif args.action=='status':
            if installation.state['active']:installation.current()
            print(json.dumps({'sequence':installation.state['sequence'],'pending_sequence':installation.state['pending']['release']['sequence'] if installation.state['pending'] else None,'wallet_state_accessed':False}))
        else:
            if installation.state['pending']:raise ValueError('recover interrupted installation before launching')
            bundle=installation.current();forwarded=args.wallet_arguments
            if forwarded[:1]==['--']:forwarded=forwarded[1:]
            selected=[]
            for index,arg in enumerate(forwarded):
                if arg=='--data-dir':
                    if index+1==len(forwarded):raise ValueError('missing wallet data path')
                    data=forwarded[index+1]
                elif arg.startswith('--data-dir='):data=arg.split('=',1)[1]
                else:continue
                selected.append(data)
            if not selected:
                profile=decode(read(bundle/'wallet-profile.json',1_000_000))
                base=Path.home()/('Library/Application Support' if platform.system()=='Darwin' else '.local/share')
                selected=[base/'Zolana Test Wallet'/profile['genesis_hash']]
            for data in selected:
                resolved=Path(data).resolve()
                # samefile also catches aliases on case-insensitive filesystems.
                nested=any(p.exists() and p.samefile(installation.root) for p in (resolved,*resolved.parents))
                contains=resolved.exists() and any(p.samefile(resolved) for p in (installation.root,*installation.root.parents))
                if nested or contains:raise ValueError('wallet data must be separate from release installation')
            # Keep the update lock in the wallet process too if this runner is
            # killed. A running wallet must finish before package activation.
            subprocess.run([sys.executable,'-I','-B',str(bundle/'runtime/wallet_launch.py'),*forwarded],check=True,pass_fds=(installation.lock,))
    finally:installation.close()


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        print('Release operation failed; retain the original download, trust policy and installation state.',file=sys.stderr);sys.exit(1)
