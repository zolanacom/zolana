#!/usr/bin/env python3
"""Offline, isolated path-remapped wallet builds; no deployment or publication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import time

PROJECT=Path(__file__).resolve().parents[1]
RECIPE='path-remapped-wallet-v1'
CANONICAL={'home':'/native/home','temporary':'/native/tmp','build':'/native/build','source':'/native/src','cargo':'/native/cargo','toolchain':'/native/toolchain'}
SOURCE_ARGS=('Cargo.toml','Cargo.lock','rust-toolchain.toml','clients','protocol','node')


def encode(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(*args):return subprocess.check_output(['git',*args],cwd=PROJECT)


def sources():
    names=git('ls-files','--cached','--others','--exclude-standard','-z','--',*SOURCE_ARGS).decode().split('\0')
    records={}
    for name in sorted(set(n for n in names if n)):
        path=PROJECT/name;meta=path.lstat()
        if path.is_symlink():
            target=os.readlink(path)
            if os.path.isabs(target):raise ValueError('absolute source symlink is not portable')
            if not path.resolve().is_relative_to(PROJECT):raise ValueError('source symlink escapes the checkout')
            records[name]={'kind':'symlink','sha256':sha(target.encode()),'target':target}
        elif stat.S_ISREG(meta.st_mode):records[name]={'kind':'file','sha256':sha(path.read_bytes()),'executable':bool(meta.st_mode&0o111)}
        else:raise ValueError('unsupported source input')
    for name,item in records.items():
        if item['kind']=='symlink' and (PROJECT/name).exists() and (PROJECT/name).resolve().relative_to(PROJECT).as_posix() not in records:
            raise ValueError('source symlink points outside the source inventory')
    if not all(n in records for n in ('Cargo.toml','Cargo.lock','rust-toolchain.toml','clients/wallet/src/main.rs')):raise ValueError('incomplete wallet source')
    return records,sha(encode(records))


def snapshot(destination,records):
    destination.mkdir(mode=0o700)
    for name,item in records.items():
        source=PROJECT/name;target=destination/name;target.parent.mkdir(parents=True,exist_ok=True)
        if item['kind']=='symlink':target.symlink_to(item['target'])
        else:
            raw=source.read_bytes()
            if sha(raw)!=item['sha256']:raise ValueError('source changed while snapshotting')
            target.write_bytes(raw);target.chmod(0o755 if item['executable'] else 0o644)
    if sources()[1]!=sha(encode(records)):raise ValueError('source changed while snapshotting')


def toolchain():
    root=Path(subprocess.check_output(['rustc','--print','sysroot'],cwd=PROJECT,text=True).strip()).resolve()
    value=subprocess.check_output([str(root/'bin/rustc'),'-vV'],text=True)
    fields=dict(line.split(': ',1) for line in value.splitlines() if ': ' in line)
    if fields.get('release')!='1.92.0' or fields.get('host')!='aarch64-apple-darwin':raise ValueError('initial release recipe requires pinned Rust 1.92.0 on Apple arm64')
    return root,fields


def environment(output,source,cargo,compiler):
    import tempfile
    roots={'home':Path.home().resolve(),'temporary':Path(tempfile.gettempdir()).resolve(),'build':output.resolve(),
        'source':source.resolve(),'cargo':cargo.resolve(),'toolchain':compiler.resolve()}
    # Rust chooses the last matching prefix; order broad roots before specific
    # roots. Encoded flags preserve spaces in checkout/cache paths exactly.
    ordered=sorted(roots,key=lambda k:len(str(roots[k])))
    rust=['--remap-path-prefix='+str(roots[k])+'='+CANONICAL[k] for k in ordered]
    rust+=['-C','codegen-units=1','-C','link-arg=-Wl,-no_uuid']
    native=['-g0']+[flag+str(roots[k])+'='+CANONICAL[k] for k in ordered for flag in ('-ffile-prefix-map=','-fdebug-prefix-map=')]
    env={k:os.environ[k] for k in ('HOME','USER','LOGNAME','TMPDIR') if k in os.environ}
    env.update(PATH=str(compiler/'bin')+':/usr/bin:/bin:/usr/sbin:/sbin',RUSTC=str(compiler/'bin/rustc'),
        CARGO_HOME=str(cargo),CARGO_TARGET_DIR=str(output/'target'),CARGO_NET_OFFLINE='true',CARGO_BUILD_JOBS='1',CARGO_INCREMENTAL='0',
        CARGO_ENCODED_RUSTFLAGS='\x1f'.join(rust),CC='/usr/bin/clang',CXX='/usr/bin/clang++',
        CFLAGS=shlex.join(native),CXXFLAGS=shlex.join(native),CC_SHELL_ESCAPED_FLAGS='1',
        NUM_JOBS='1',MAKEFLAGS='-j1',CMAKE_BUILD_PARALLEL_LEVEL='1',RAYON_NUM_THREADS='1',SOURCE_DATE_EPOCH='1700000000')
    return env,roots,rust,native


def path_audit(raw,roots):
    from wallet_release import generic_paths_absent
    findings=[]
    for label,path in roots.items():
        value=str(path)
        if any(value.encode(codec) in raw for codec in ('utf-8','utf-16-le','utf-16-be')):findings.append(label)
    patterns=(rb'/(?:Users|home)/[^/\x00\s]+',rb'/(?:private/)?var/folders/',rb'/(?:private/)?tmp/')
    if any(re.search(p,raw) for p in patterns):findings.append('generic_personal_or_temporary_path')
    if findings:raise ValueError('artifact path audit failed: '+','.join(sorted(findings)))
    generic_paths_absent(raw)
    return {'format':'native-path-audit-v1','known_roots_absent':True,'generic_personal_paths_absent':True,'encodings':['utf-8','utf-16-le','utf-16-be']}


def linkage(binary):
    loaded=subprocess.check_output(['/usr/bin/otool','-L',str(binary)],text=True).splitlines()[1:]
    libraries=[line.strip().split(' (',1)[0] for line in loaded if line.strip()]
    if not libraries or any(not x.startswith(('/usr/lib/','/System/Library/Frameworks/')) or '..' in Path(x).parts for x in libraries):raise ValueError('wallet has a non-system dynamic dependency')
    commands=subprocess.check_output(['/usr/bin/otool','-l',str(binary)],text=True)
    if 'cmd LC_RPATH' in commands or 'segname __DWARF' in commands or 'cmd LC_UUID' in commands:raise ValueError('wallet contains an unreviewed rpath, debug segment or UUID')
    checked=subprocess.run(['/usr/bin/codesign','--verify','--strict',str(binary)],capture_output=True)
    info=subprocess.run(['/usr/bin/codesign','-d','--verbose=4',str(binary)],capture_output=True)
    if checked.returncode or b'Signature=adhoc' not in info.stderr or b'TeamIdentifier=not set' not in info.stderr:raise ValueError('unexpected toolchain code signature')
    return {'system_only':True,'libraries':libraries,'rpaths':0,'debug_segments':0,'uuid_commands':0,'native_signature':'toolchain-ad-hoc'}


def probes(output,env,roots,rust,native,compiler):
    probe=output/'probes';probe.mkdir(mode=0o700)
    rs=probe/'location.rs';rs.write_text('fn main() { println!("{}", file!()); panic!("local-remap-probe"); }\n')
    rb=probe/'rust-location'
    subprocess.run([str(compiler/'bin/rustc'),str(rs),'-C','debuginfo=0','-C','strip=symbols',*rust,'-o',str(rb)],env=env,check=True,capture_output=True)
    result=subprocess.run([str(rb)],capture_output=True,env=env)
    if result.returncode==0 or b'/native/build/probes/location.rs' not in result.stdout or b'/native/build/probes/location.rs' not in result.stderr:raise ValueError('Rust location remapping failed')
    path_audit(rb.read_bytes(),roots);path_audit(result.stdout+result.stderr,roots)
    c=probe/'location.c';c.write_text('#include <stdio.h>\nint main(void) { puts(__FILE__); return 0; }\n')
    cb=probe/'c-location';subprocess.run(['/usr/bin/clang',*native,str(c),'-o',str(cb)],env=env,check=True,capture_output=True)
    result=subprocess.run([str(cb)],capture_output=True,check=True,env=env)
    if b'/native/build/probes/location.c' not in result.stdout:raise ValueError('native macro remapping failed')
    path_audit(cb.read_bytes(),roots);path_audit(result.stdout,roots)
    return {'rust_file_macro':True,'rust_panic_location':True,'native_file_macro':True,'probe_binary_paths_clean':True}


def run_compiler(command,source,env,log_path,timeout):
    started=time.monotonic()
    with log_path.open('xb') as log:
        child=subprocess.Popen(['/usr/bin/nice','-n','15',*command],cwd=source,env=env,stdout=log,stderr=log,start_new_session=True)
        try:result=child.wait(timeout=timeout)
        except BaseException:
            try:os.killpg(child.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=5)
            raise
    if result:raise ValueError('offline compiler command failed; private log retained')
    return round(time.monotonic()-started,3)


def checks(output,timeout=3600):
    from wallet_release import atomic,build_metadata,create,decode,read
    output=Path(output).resolve();value=build_metadata(decode(read(output/'BUILD.json',16384)),read(output/'native-wallet',64*1024*1024))
    records,digest=sources()
    if digest!=value['source_sha256']:raise ValueError('native source changed since the build')
    source=output/'source'
    for name,item in records.items():
        path=source/name
        if item['kind']=='symlink':valid=path.is_symlink() and os.readlink(path)==item['target']
        else:valid=not path.is_symlink() and sha(path.read_bytes())==item['sha256']
        if not valid:raise ValueError('build snapshot changed before testing')
    compiler,version=toolchain();env,roots,_,_=environment(output,source,(PROJECT/'.tools/cargo').resolve(),compiler)
    path_audit(read(output/'native-wallet',64*1024*1024),roots);linkage(output/'native-wallet')
    command=[str(compiler/'bin/cargo'),'test','--offline','--locked','--profile','wallet-release','--target',version['host'],'-j','1',
        '-p','native-wallet','-p','native-payments','--features','native-wallet/apple-fast-field','--lib','--','--test-threads=1']
    atomic(output/'tests-state.json',{'status':'running','jobs':1,'validators_started':0})
    try:
        seconds=run_compiler(command,source,env,output/'tests.log',timeout)
        summaries=re.findall(r'test result: ok\. (\d+) passed; 0 failed;', (output/'tests.log').read_text())
        if len(summaries)!=2:raise ValueError('missing native test acceptance summaries')
        result={'format':'native-wallet-build-tests-v1','status':'passed','passed':sum(map(int,summaries)),'suites':2,'seconds':seconds,'jobs':1,
            'binary_sha256':value['binary_sha256'],'validators_started':0,'external_requests':0}
        create(output/'TESTS.json',encode(result),0o400);atomic(output/'tests-state.json',result);print(json.dumps(result),flush=True);return result
    except BaseException:
        atomic(output/'tests-state.json',{'status':'failed','original_evidence_retained':True,'validators_started':0});raise


def build(output,timeout=3600):
    from wallet_release import atomic,create
    output=Path(output).absolute()
    if os.path.lexists(output):raise ValueError('use a new private build output')
    output.mkdir(mode=0o700);output=output.resolve();records,source_sha=sources();source=output/'source';snapshot(source,records)
    compiler,version=toolchain();cargo=(PROJECT/'.tools/cargo').resolve()
    env,roots,rust,native=environment(output,source,cargo,compiler)
    marker={'format':'native-wallet-build-state-v1','status':'probing','validators_started':0,'published':False}
    atomic(output/'state.json',marker)
    try:
        probe_result=probes(output,env,roots,rust,native,compiler)
        command=[str(compiler/'bin/cargo'),'build','--offline','--locked','--profile','wallet-release','--target',version['host'],'-j','1','-p','native-wallet','--bin','native-wallet','--features','apple-fast-field']
        marker.update(status='building',jobs=1,priority='nice-15');atomic(output/'state.json',marker)
        print(json.dumps({'building':True,'jobs':1,'priority':'nice-15','offline':True,'separate_output':True}),flush=True)
        seconds=run_compiler(command,source,env,output/'build.log',timeout)
        binary=output/'target'/version['host']/'wallet-release/native-wallet';raw=binary.read_bytes();audit=path_audit(raw,roots);libraries=linkage(binary)
        receipt={'format':'native-wallet-build-v1','recipe':RECIPE,'binary_sha256':sha(raw),'binary_size':len(raw),'source_sha256':source_sha,
            'cargo_lock_sha256':records['Cargo.lock']['sha256'],'source_commit':git('rev-parse','HEAD').decode().strip(),
            'source_dirty':bool(git('status','--porcelain')),'rustc_release':version['release'],'rustc_commit':version['commit-hash'],'target':version['host'],
            'profile':'wallet-release','jobs':1,'offline':True,'path_audit':audit,'linkage':libraries,'probes':probe_result,'canonical_prefixes':CANONICAL}
        create(output/'native-wallet',raw,0o500);create(output/'BUILD.json',encode(receipt),0o400)
        marker.update(status='passed',seconds=seconds,binary_sha256=receipt['binary_sha256']);atomic(output/'state.json',marker)
        print(json.dumps({'status':'passed','binary_sha256':receipt['binary_sha256'],'binary_size':len(raw),'seconds':marker['seconds'],'published':False}),flush=True)
        return receipt
    except BaseException as error:
        marker.update(status='failed');atomic(output/'state.json',marker)
        if isinstance(error,subprocess.CalledProcessError):
            create(output/'probe-failure.log',(error.stderr or b'compiler probe failed'),0o600)
            raise ValueError('compiler probe failed; private evidence retained') from None
        raise


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=Path);parser.add_argument('--timeout',type=int,default=3600);parser.add_argument('--tests',action='store_true',help='test an existing verified build snapshot with the same optimized profile')
    args=parser.parse_args()
    if not 60<=args.timeout<=7200:raise ValueError('build timeout must be bounded')
    def interrupted(*_):raise InterruptedError('local build interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    if args.tests:checks(args.output,args.timeout)
    else:build(args.output,args.timeout)


if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):
        print('Local build failed; private build evidence retained. Use a new output for the next attempt.',file=__import__('sys').stderr)
        raise SystemExit(1)
