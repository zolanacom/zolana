#!/usr/bin/env python3
"""Exact-byte public-IP TLS verification and fixed root-only certificate deployment.

The endpoint address is operator configuration: pass --public-ip or set
ZOLANA_PUBLIC_IP. No address is built in.
"""
import argparse
import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile

PUBLIC_IP_SETTING='ZOLANA_PUBLIC_IP'
SERVICE_UID=994
TLS_ROOT=Path('/etc/zolana-native-074/tls')
LETSENCRYPT=Path('/etc/letsencrypt')
OPENSSL='/usr/bin/openssl'
GATEWAY='zolana-native-060-gateway.service'
FORMAT='zolana-public-tls-bundle-v1'
HEX=re.compile('[a-f0-9]{64}\\Z')
CERTIFICATE_LIMIT=65536
KEY_LIMIT=32768
CERTIFICATE=re.compile(br'-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?')


def require(value,message):
    if not value:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def _read(path,uid,maximum,mode=None,secret=False):
    path=Path(path)
    require(path.is_absolute() and path.resolve(strict=True)==path,'real absolute certificate path required')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid==uid and before.st_nlink==1
            and 0<before.st_size<=maximum and (mode is None or stat.S_IMODE(before.st_mode)==mode)
            and not before.st_mode&(0o077 if secret else 0o022),'bounded owned regular certificate input required')
        raw=stream.read(maximum+1);after=os.fstat(stream.fileno())
    final=path.lstat()
    identity=lambda m:(m.st_dev,m.st_ino,m.st_size,m.st_mtime_ns,m.st_uid,stat.S_IMODE(m.st_mode),m.st_nlink)
    require(len(raw)==before.st_size and identity(before)==identity(after)==identity(final),'certificate input changed while read')
    return raw


def _openssl(*args,input=None):
    result=subprocess.run([OPENSSL,*map(str,args)],input=input,capture_output=True,timeout=10,
        env=dict(PATH='/usr/bin:/bin',HOME='/nonexistent',LANG='C',LC_ALL='C'))
    require(result.returncode==0 and len(result.stdout)<=65536 and len(result.stderr)<=16384,'public TLS certificate validation failed')
    return result.stdout


def _public_ip(public_ip):
    require(isinstance(public_ip,str) and str(ipaddress.IPv4Address(public_ip))==public_ip
        and ipaddress.IPv4Address(public_ip).is_global and not ipaddress.IPv4Address(public_ip).is_multicast,
        'canonical public unicast IPv4 identity required')
    return public_ip


def _bytes_context(certificate,key,public_ip,minimum_validity,trust_directory):
    _public_ip(public_ip)
    require(type(minimum_validity) is int and 0<=minimum_validity<=2147483647,'bounded integral minimum validity required')
    require(Path(trust_directory).is_absolute() and Path(trust_directory).is_dir(),'explicit certificate trust directory required')
    blocks=CERTIFICATE.findall(certificate)
    require(1<=len(blocks)<=8 and not CERTIFICATE.sub(b'',certificate).strip(),'bounded PEM certificate chain required')
    require(0<len(certificate)<=CERTIFICATE_LIMIT and 0<len(key)<=KEY_LIMIT,'certificate/key bytes exceed limit')
    with tempfile.TemporaryDirectory(prefix='zolana-public-tls-') as directory:
        folder=Path(directory);os.chmod(folder,0o700)
        def private(name,raw):
            path=folder/name
            with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as stream:stream.write(raw)
            return path
        chain=private('server.crt',certificate);secret=private('server.key',key);leaf=private('leaf.pem',blocks[0])
        args=['verify','-no-CAfile','-no-CAstore','-CApath',str(trust_directory),'-verify_ip',public_ip,'-purpose','sslserver']
        if len(blocks)>1:args+=['-untrusted',private('intermediates.pem',b''.join(blocks[1:]))]
        _openssl(*args,leaf)
        _openssl('x509','-in',leaf,'-noout','-checkend',minimum_validity)
        public=_openssl('x509','-in',leaf,'-pubkey','-noout')
        cert_public=_openssl('pkey','-pubin','-pubout','-outform','DER',input=public)
        key_public=_openssl('pkey','-in',secret,'-passin','pass:','-pubout','-outform','DER')
        require(cert_public==key_public,'public certificate/private key mismatch')
        expiry=_openssl('x509','-in',leaf,'-noout','-enddate').decode('ascii').strip()
        require(expiry.startswith('notAfter='),'certificate expiry is unavailable')
        timestamp=int(ssl.cert_time_to_seconds(expiry[len('notAfter='):]))
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1']);context.load_cert_chain(chain,secret,password=lambda:'')
    metadata=dict(certificate_sha256=sha(certificate),key_sha256=sha(key),public_ip=public_ip,
        not_after=datetime.datetime.fromtimestamp(timestamp,datetime.timezone.utc).isoformat().replace('+00:00','Z'),
        not_after_unix=timestamp,minimum_validity=minimum_validity)
    return context,metadata


def verified_context(cert,key,public_ip,expected_uid,minimum_validity=3600,trust_directory='/etc/ssl/certs'):
    """Return (server SSLContext, public metadata), loading only captured exact bytes.

    The caller seals path ancestry and expected hashes. The pure trust_directory
    override supports isolated test CAs; production deployment always uses the
    normal fixed /etc/ssl/certs trust directory and a3600-second minimum.
    """
    require(type(expected_uid) is int and expected_uid>=0,'explicit certificate owner UID required')
    certificate=_read(Path(cert),expected_uid,CERTIFICATE_LIMIT,mode=0o600,secret=True)
    secret=_read(Path(key),expected_uid,KEY_LIMIT,mode=0o600,secret=True)
    return _bytes_context(certificate,secret,public_ip,minimum_validity,trust_directory)


def _root_directory(path):
    path=Path(path)
    require(path.is_absolute(),'fixed root directory required')
    for parent in (path,*path.parents):
        meta=parent.lstat()
        require(parent.resolve()==parent and stat.S_ISDIR(meta.st_mode) and meta.st_uid==0
            and not meta.st_mode&0o022,'immutable root-owned certificate ancestry required')


def _fsync(directory):
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def _mkdir(path):
    try:
        path.mkdir(mode=0o755);os.chmod(path,0o755)
    except FileExistsError:pass
    _root_directory(path)
    require(path.stat().st_mode&0o001,'certificate directory must be traversable by service UID')
    _fsync(path.parent)


def _decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            require(key not in value,'duplicate certificate manifest field');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite manifest')))


def manifest(raw):
    value=_decode(raw)
    require(isinstance(value,dict) and set(value)=={'format','sequence','certificate_sha256','key_sha256'}
        and value['format']==FORMAT and type(value['sequence']) is int and 1<=value['sequence']<2**63
        and all(isinstance(value[k],str) and HEX.fullmatch(value[k]) for k in ('certificate_sha256','key_sha256')),
        'exact versioned public TLS manifest required')
    return value


def _lineage_bytes(public_ip):
    LINEAGE=LETSENCRYPT/'live'/public_ip;ARCHIVE=LETSENCRYPT/'archive'/public_ip
    require(os.environ.get('RENEWED_LINEAGE',str(LINEAGE))==str(LINEAGE),'unexpected certificate renewal lineage')
    _root_directory(LINEAGE);_root_directory(ARCHIVE)
    captured=[];versions=[]
    for name,kind,limit,secret in (('fullchain.pem','fullchain',CERTIFICATE_LIMIT,False),('privkey.pem','privkey',KEY_LIMIT,True)):
        source=LINEAGE/name;before=source.lstat()
        require(stat.S_ISLNK(before.st_mode) and before.st_uid==0,'fixed Certbot leaf symlink required')
        link=os.readlink(source);target=source.resolve(strict=True)
        match=re.fullmatch(kind+r'([1-9][0-9]*)\.pem',target.name)
        require(target.parent==ARCHIVE and match is not None,'certificate symlink escaped fixed root archive')
        _root_directory(target.parent);raw=_read(target,0,limit,secret=secret)
        captured.append((source,link,before.st_ino,raw));versions.append(match[1])
    require(versions[0]==versions[1],'certificate renewal pair versions differ')
    for path,link,inode,_ in captured:
        after=path.lstat();require(after.st_ino==inode and after.st_uid==0 and stat.S_ISLNK(after.st_mode)
            and os.readlink(path)==link,'renewal links changed during capture')
    return captured[0][3],captured[1][3]


def _write_new(path,raw,mode,uid):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode),'wb') as stream:
        os.fchown(stream.fileno(),uid,-1);os.fchmod(stream.fileno(),mode)
        stream.write(raw);stream.flush();os.fsync(stream.fileno())


def _publish(certificate,key,metadata,expected_uid=SERVICE_UID):
    """Caller holds fixed deploy lock and has validated this exact byte pair."""
    require(all(metadata[k]==sha(raw) for k,raw in (('certificate_sha256',certificate),('key_sha256',key))),
        'validated certificate bytes differ from deployment metadata')
    bundles=TLS_ROOT/'bundles';_mkdir(bundles)
    current=TLS_ROOT/'current.json';old=None
    if os.path.lexists(current):
        old=manifest(_read(current,0,4096,mode=0o444))
        directory=bundles/str(old['sequence']);_root_directory(directory)
        for name,field,limit in (('server.crt','certificate_sha256',CERTIFICATE_LIMIT),('server.key','key_sha256',KEY_LIMIT)):
            require(sha(_read(directory/name,expected_uid,limit,mode=0o600,secret=True))==old[field],'current certificate bundle seal differs')
        if all(old[k]==metadata[k] for k in ('certificate_sha256','key_sha256')):return old,False
    sequences=[]
    for entry in bundles.iterdir():
        require(re.fullmatch('[1-9][0-9]*',entry.name) and int(entry.name)<2**63,'unexpected certificate bundle entry')
        _root_directory(entry);sequences.append(int(entry.name))
    sequence=max([old['sequence'] if old else 0,*sequences])+1;require(sequence<2**63,'certificate sequence exhausted')
    directory=bundles/str(sequence);directory.mkdir(mode=0o755);os.chmod(directory,0o755);_root_directory(directory);_fsync(bundles)
    _write_new(directory/'server.crt',certificate,0o600,expected_uid)
    _write_new(directory/'server.key',key,0o600,expected_uid);_fsync(directory)
    value=dict(format=FORMAT,sequence=sequence,**{k:metadata[k] for k in ('certificate_sha256','key_sha256')})
    temporary=TLS_ROOT/('.current-'+secrets.token_hex(16)+'.tmp')
    try:
        _write_new(temporary,(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode(),0o444,0)
        os.replace(temporary,current);_fsync(TLS_ROOT)
    finally:
        if os.path.lexists(temporary):temporary.unlink()
    return value,True


def _restart_active():
    command=['/usr/bin/systemctl','show',GATEWAY,'--property=ActiveState','--property=SubState',
        '--property=MainPID','--property=InvocationID']
    def state():
        result=subprocess.run(command,capture_output=True,text=True,check=True,timeout=10)
        value=dict(line.split('=',1) for line in result.stdout.splitlines())
        require(set(value)=={'ActiveState','SubState','MainPID','InvocationID'},'gateway service state unavailable')
        return value
    before=state()
    if before['ActiveState']=='inactive':return False
    require(before['ActiveState']=='active' and before['SubState']=='running' and before['MainPID'].isdecimal()
        and int(before['MainPID'])>1 and re.fullmatch('[a-f0-9]{32}',before['InvocationID']),
        'gateway must already be stably active for renewal restart')
    # try-restart cannot start an inactive unit if its bounded lifecycle stopped
    # between the read and this command; never explicitly target the validator.
    subprocess.run(['/usr/bin/systemctl','try-restart',GATEWAY],capture_output=True,check=True,timeout=90)
    after=state()
    if after['ActiveState']=='inactive':return False
    require(after['ActiveState']=='active' and after['SubState']=='running' and after['MainPID'].isdecimal()
        and int(after['MainPID'])>1 and re.fullmatch('[a-f0-9]{32}',after['InvocationID'])
        and after['InvocationID']!=before['InvocationID'],'gateway certificate reload did not reach a fresh active invocation')
    return True


def deploy(restart_active=False,public_ip=None):
    require(sys.platform=='linux' and os.getuid()==os.geteuid()==0,'fixed certificate deployment requires Linux root')
    require(type(restart_active) is bool,'explicit restart choice required')
    public_ip=_public_ip(os.environ.get(PUBLIC_IP_SETTING) if public_ip is None else public_ip)
    _root_directory(TLS_ROOT.parent.parent)
    _mkdir(TLS_ROOT.parent);_mkdir(TLS_ROOT)
    lock=TLS_ROOT/'deploy.lock';fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        m=os.fstat(fd);require(stat.S_ISREG(m.st_mode) and m.st_uid==0 and m.st_nlink==1
            and stat.S_IMODE(m.st_mode)==0o600,'fixed root600 deployment lock required')
        fcntl.flock(fd,fcntl.LOCK_EX)
        certificate,key=_lineage_bytes(public_ip)
        _,metadata=_bytes_context(certificate,key,public_ip,3600,'/etc/ssl/certs')
        value,changed=_publish(certificate,key,metadata)
        # Explicit reload is retryable even if a previous publication succeeded
        # but its service restart failed. Default unchanged deployment is a no-op.
        restarted=_restart_active() if restart_active else False
        return dict(status='passed',manifest=value,changed=changed,restarted_gateway=restarted,
            certificate=metadata,validator_restart_requested=False,authority_operations=0)
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('command',choices=('deploy',))
    parser.add_argument('--restart-active',action='store_true')
    parser.add_argument('--public-ip',help='canonical public IPv4 of this endpoint; defaults to '+PUBLIC_IP_SETTING)
    args=parser.parse_args()
    os.umask(0o077);print(json.dumps(deploy(args.restart_active,args.public_ip),sort_keys=True))


if __name__=='__main__':main()
