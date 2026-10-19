#!/usr/bin/env python3
"""Allowlisted host bundle and resumable inert installation. Never loads a service."""
import argparse
import os
from pathlib import Path
import platform
import plistlib
import pwd
import grp
import stat
import sys

import pilot_cohort as cohort
import pilot_runtime as runtime
from pilot_funding import native_lock
from wallet_release import create,decode,encode,fsync_dir,hex64,read,sha

PROJECT=Path(__file__).resolve().parents[1]
PREFIX=Path('/Library/ZolanaPilot')
ACCOUNT='_zolanapilot'
LABEL='local.zolana.pilot'
FILES=tuple('tools/'+n for n in runtime.CODE)+('tools/pilot_install.py','tools/pilot_provision.py')+tuple('target/debug/'+n for n in runtime.BINARIES)+('LICENSE','THIRD_PARTY.md','node/agave/LICENSE')
SETUP='''Zolana pilot installation — disabled until a separately reviewed activation

Target: macOS arm64; two validators on one host, a single consensus failure domain.
This bundle contains development binaries; no Apple signature/notarization or
portable Linux support is claimed. Transfer/review MANIFEST.json's SHA-256 by an
independent trusted channel. Hashes provide integrity, not publisher authenticity.

1. Provision a dedicated no-login _zolanapilot account/group on the intended host
   (matching UID/GID, home /var/empty, shell /usr/bin/false). Do not reuse _nativepay.
   Review the account, firewall, TLS, storage, independent backups and alert custody.
2. Place the reviewed bundle under an administrator-controlled real directory
   (for example /private/var/root/ZolanaPilotBundle), root:wheel, directories 0700
   and files 0600. Review the independent digest before using it. Source tools
   must also come from your trusted copy, rather than an unverified download.
   From independently trusted tools, run pilot_install.py install --bundle BUNDLE
   --manifest-sha256 REVIEWED_SHA as administrator. This writes only the separate
   /Library/ZolanaPilot prefix. It neither creates accounts nor loads launchd jobs.
   An interrupted copy resumes with the same digest; mismatched files are retained
   and refused. Never delete a funded state directory to reinstall.
3. As _zolanapilot, initialize a NEW private network under .data/pilot, enable
   hardened Unix RPC and prepare the reviewed ten-slot cohort at its FINAL paths.
   Existing bindings/ledgers cannot be moved or silently repinned. Keep cold key
   custody outside the running service after the explicit provisioning ceremony.
4. Review pilot_provision.py prepare's digest; run its exact finite ceremony with
   original cold/sponsor passwords locally on that host. Two 5m private deposits,
   one 6,000,300,000 public test-unit allocation, separate <=10,000 treasury fee.
   Retry original journals, not new IDs. Check pilot_funding.py verify immediately
   before pilot_runtime.py bind. Runtime code/binaries/TLS/state are pinned there.
5. From the same reviewed tool, render --binding-sha256 ORIGINAL_BINDING to obtain
   an inert local.zolana.pilot.plist. Have the administrator verify root-owned
   code/ancestors, UID-only .data, Python interpreter, exact identity and binding.
   Install the plist root:wheel 0644 in /Library/LaunchDaemons ONLY after a separate
   deployment review. It is Disabled=true; this tool never enables/bootstrap jobs.
   launchd must retain AbandonProcessGroup=false, so supervisor SIGKILL also removes
   owned validators/workers. Actual launchd, dedicated-UID denial and reboot tests
   remain deployment gates; local subprocess-group tests do not prove those gates.
6. Check trusted TLS/exact Host/SNI, raw TCP denial, independent canonical/archive
   recovery, authorized human alert receipt and an external supported device before
   inviting people. No real coin value, automatic refill or public readiness claimed.
'''


def file_bytes(path):return cohort.code_bytes(path,256*1024*1024)


def prepare(output):
    if platform.system()!='Darwin' or platform.machine()!='arm64':raise ValueError('build on reviewed Darwin arm64 host')
    output=Path(output).absolute();output.mkdir(mode=0o700)
    entries={}
    for name in FILES:
        raw=file_bytes(PROJECT/name);dest=output/name;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        create(dest,raw);entries[name]=dict(size=len(raw),sha256=sha(raw),mode=0o555 if name.startswith('target/') else 0o444)
    create(output/'HOST-SETUP.txt',SETUP.encode())
    entries['HOST-SETUP.txt']=dict(size=len(SETUP.encode()),sha256=sha(SETUP.encode()),mode=0o444)
    manifest=dict(format='zolana-pilot-install-v1',platform='darwin-arm64',prefix=str(PREFIX),account=ACCOUNT,
                  service_label=LABEL,activation_enabled=False,files=entries)
    create(output/'MANIFEST.json',encode(manifest));fsync_dir(output)
    return dict(manifest_sha256=sha(encode(manifest)),files=len(entries),activation_enabled=False,credentials_included=False)


def inventory(base,allowed,skip_state=False):
    # Never follow a link while walking this bounded, fixed inventory.
    expected_dirs={str(Path(name).parent) for name in allowed}
    for name in list(expected_dirs):expected_dirs.update(str(p) for p in Path(name).parents)
    for parent,dirs,files in os.walk(base,followlinks=False):
        if skip_state and Path(parent)==base and '.data' in dirs:
            if (base/'.data').is_symlink():raise ValueError('linked pilot state directory')
            dirs.remove('.data')
        for name in dirs+files:
            path=Path(parent)/name;relative=str(path.relative_to(base));meta=path.lstat()
            if stat.S_ISLNK(meta.st_mode) or (relative not in allowed and relative not in expected_dirs):raise ValueError('unexpected installation content')
            if not stat.S_ISREG(meta.st_mode) and not stat.S_ISDIR(meta.st_mode):raise ValueError('nonregular installation content')


def verify(bundle,expected):
    bundle=Path(bundle).absolute();cohort.directory(bundle)
    raw=read(bundle/'MANIFEST.json',32768,secret=True)
    if not hex64(expected) or sha(raw)!=expected:raise ValueError('reviewed installation digest changed')
    m=decode(raw)
    if (set(m)!={'format','platform','prefix','account','service_label','activation_enabled','files'} or
        m['format']!='zolana-pilot-install-v1' or m['platform']!='darwin-arm64' or m['prefix']!=str(PREFIX) or
        m['account']!=ACCOUNT or m['service_label']!=LABEL or m['activation_enabled'] is not False or set(m['files'])!={*FILES,'HOST-SETUP.txt'}):raise ValueError('invalid installation contract')
    inventory(bundle,{*m['files'],'MANIFEST.json'})
    for name,item in m['files'].items():
        raw=read(bundle/name,256*1024*1024,secret=True)
        if item!=dict(size=len(raw),sha256=sha(raw),mode=0o555 if name.startswith('target/') else 0o444):raise ValueError('installation input differs')
    if read(bundle/'HOST-SETUP.txt',16384,secret=True)!=SETUP.encode():raise ValueError('installation instructions differ')
    return m


def stage(bundle,expected,prefix,uid,gid,rehearsal=False,hook=lambda _:None):
    if not rehearsal:
        if os.getuid()!=0 or Path(prefix).absolute()!=PREFIX:raise ValueError('official installation requires administrator and fixed prefix')
        bundle=Path(bundle).absolute()
        for parent in (bundle,*bundle.parents):
            meta=parent.lstat()
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:raise ValueError('official input must be under root-controlled real directories')
    prefix=Path(prefix).absolute()
    with native_lock(prefix.with_name(prefix.name+'.install.lock')):
        return stage_locked(bundle,expected,prefix,uid,gid,rehearsal,hook)


def stage_locked(bundle,expected,prefix,uid,gid,rehearsal=False,hook=lambda _:None):
    bundle,prefix=Path(bundle).absolute(),Path(prefix).absolute();m=verify(bundle,expected)
    if not rehearsal:
        if os.getuid()!=0 or prefix!=PREFIX:raise ValueError('official installation requires administrator and separate fixed prefix')
        user=pwd.getpwnam(ACCOUNT);group=grp.getgrnam(ACCOUNT)
        if (uid!=user.pw_uid or gid!=user.pw_gid or gid!=group.gr_gid or uid<450 or gid<450 or user.pw_dir!='/var/empty' or user.pw_shell!='/usr/bin/false'):
            raise ValueError('dedicated no-login pilot identity required')
        for parent in prefix.parents:
            meta=parent.lstat()
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022:raise ValueError('installation ancestors must be root controlled')
    elif uid!=os.getuid() or gid!=os.getgid() or prefix==PREFIX:raise ValueError('rehearsal may only use current UID outside official prefix')
    if prefix.resolve()!=prefix or prefix==bundle or prefix in bundle.parents or bundle in prefix.parents:raise ValueError('installation paths must be separate and real')
    journal=dict(format='zolana-pilot-install-journal-v1',manifest_sha256=expected,prefix=str(prefix),uid=uid,gid=gid,rehearsal=rehearsal)
    if prefix.exists():
        if decode(read(prefix/'INSTALLING.json',4096))!=journal:raise ValueError('existing installation differs; preserve state')
    else:
        prefix.mkdir(mode=0o755);create(prefix/'INSTALLING.json',encode(journal));fsync_dir(prefix);fsync_dir(prefix.parent)
    inventory(prefix,{*m['files'],'INSTALLING.json','INSTALLED.json',*(name+'.installing' for name in m['files'])},skip_state=True)
    # Immutable inputs are copied under a private staging name and atomically renamed.
    # A lost temporary write is resumable only when its bytes match the reviewed input.
    for name,item in m['files'].items():
        target=prefix/name;raw=read(bundle/name,256*1024*1024,secret=True)
        for parent in reversed(target.relative_to(prefix).parents):
            if str(parent)=='.':continue
            directory=prefix/parent
            if not directory.exists():directory.mkdir(mode=0o755)
            meta=directory.lstat()
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o022:raise ValueError('unsafe installed code directory')
        if os.path.lexists(target):
            if file_bytes(target)!=raw:raise ValueError('installed code differs; preserve without overwrite')
        else:
            temporary=target.with_name(target.name+'.installing')
            if os.path.lexists(temporary):
                if read(temporary,256*1024*1024)!=raw:raise ValueError('partial copy requires review; never overwrite')
            else:create(temporary,raw)
            hook('copy-'+name)
            os.chmod(temporary,item['mode']);os.rename(temporary,target);fsync_dir(target.parent)
        meta=target.lstat()
        if meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=item['mode']:raise ValueError('installed code permissions differ')
    state=prefix/'.data'
    if not state.exists():state.mkdir(mode=0o700);os.chown(state,uid,gid);fsync_dir(prefix)
    meta=state.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=uid or meta.st_gid!=gid or meta.st_mode&0o077:raise ValueError('unsafe pilot state ownership')
    receipt=dict(**journal,phase='installed-disabled',services_started=0)
    path=prefix/'INSTALLED.json'
    if os.path.lexists(path):
        if read(path,4096)!=encode(receipt):raise ValueError('installation receipt changed')
    else:create(path,encode(receipt));fsync_dir(prefix)
    return receipt


def launchd(binding):
    if not hex64(binding):raise ValueError('reviewed runtime binding required')
    return plistlib.dumps(dict(Label=LABEL,UserName=ACCOUNT,GroupName=ACCOUNT,Disabled=True,RunAtLoad=False,
        KeepAlive=dict(UnsuccessfulExit=True),AbandonProcessGroup=False,ExitTimeOut=90,ThrottleInterval=30,
        ProcessType='Background',Nice=15,Umask=0o077,WorkingDirectory=str(PREFIX),
        ProgramArguments=['/usr/bin/python3','-B',str(PREFIX/'tools/pilot_runtime.py'),'run','--network-root',str(PREFIX/'.data/pilot'),'--binding-sha256',binding],
        EnvironmentVariables=dict(RAYON_NUM_THREADS='2',RUST_LOG='warn',PYTHONNOUSERSITE='1',PYTHONDONTWRITEBYTECODE='1'),
        StandardOutPath=str(PREFIX/'.data/host.stdout.log'),StandardErrorPath=str(PREFIX/'.data/host.stderr.log')),sort_keys=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('prepare','check','rehearse','install','render'))
    p.add_argument('--bundle',type=Path);p.add_argument('--manifest-sha256');p.add_argument('--prefix',type=Path);p.add_argument('--output',type=Path);p.add_argument('--binding-sha256')
    a=p.parse_args()
    if a.action=='prepare':result=prepare(a.bundle)
    elif a.action=='check':verify(a.bundle,a.manifest_sha256);result=dict(verified=True,services_started=0)
    elif a.action=='render':create(a.output,launchd(a.binding_sha256));result=dict(plist_written=True,enabled=False)
    else:
        rehearsal=a.action=='rehearse'
        user=None if rehearsal else pwd.getpwnam(ACCOUNT)
        result=stage(a.bundle,a.manifest_sha256,a.prefix if rehearsal else PREFIX,os.getuid() if rehearsal else user.pw_uid,os.getgid() if rehearsal else user.pw_gid,rehearsal)
    print(encode(result).decode(),end='')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError):raise SystemExit('Pilot installation stopped; preserve original bundle/state. No service was loaded.')
