#!/usr/bin/env python3
"""Local-only Apple signing rehearsal and disabled notarization handoff.

Never selects a private signing identity, changes a keychain or calls the
notary service. Developer ID/timestamp/upload commands are reviewable plans.
"""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import signal
import stat
import struct
import subprocess
import tempfile

from wallet_release import Installation,REQUIRED,atomic,build_metadata,create,decode,directory,encode,fsync_dir,generic_paths_absent,hex64,parents,read,safe_name,sha

IDENTIFIER='dev.nativepay.wallet.rehearsal'
IMAGE_IDENTIFIER='dev.nativepay.wallet.rehearsal.image'
MODE='ad-hoc-rehearsal'


def command(argv,timeout=120):
    # No caller-controlled executable, shell, inherited Python path, identity
    # selector, timestamp server or notary command reaches this executor.
    if not argv or argv[0] not in ('/usr/bin/codesign','/usr/bin/hdiutil','/usr/bin/otool'):raise ValueError('unreviewed Apple rehearsal command')
    if argv[0]=='/usr/bin/codesign':
        if '--sign' in argv:
            expected=(['--force','--sign','-','--timestamp=none','--identifier',IMAGE_IDENTIFIER],
                ['--force','--sign','-','--options','runtime','--timestamp=none','--identifier',IDENTIFIER,'--entitlements'])
            if argv[1:-1]!=expected[0] and not (len(argv)==12 and argv[1:-2]==expected[1]):raise ValueError('rehearsal cannot use a private identity or timestamp service')
        elif argv[1:-1] not in (['--verify','--strict'],['--display','--verbose=4'],['--display','--entitlements','-','--xml']):raise ValueError('unreviewed codesign operation')
    result=subprocess.run(argv,capture_output=True,timeout=timeout,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
    if result.returncode:raise ValueError('local Apple tool validation failed')
    return result


def code_identity(raw):
    """Hash all Mach-O content except its signature and signature size fields.

    Existing/new signatures begin at the same offset. Every other load command
    and all pre-signature code/data remain covered, including linkedit content.
    """
    if len(raw)<32 or struct.unpack_from('<I',raw)[0]!=0xfeedfacf:raise ValueError('requires thin arm64 Mach-O')
    _,cpu,_,kind,count,size,_,_=struct.unpack_from('<8I',raw)
    if cpu!=0x100000c or kind!=2 or not 1<=count<=256 or size>1_000_000 or 32+size>len(raw):raise ValueError('invalid Mach-O header')
    normalized=bytearray(raw);cursor=32;signature=None;linkedit=None
    for _ in range(count):
        if cursor+8>32+size:raise ValueError('truncated Mach-O commands')
        tag,length=struct.unpack_from('<II',raw,cursor)
        if length<8 or length%8 or cursor+length>32+size:raise ValueError('invalid Mach-O command bounds')
        if tag==0x1d:
            if signature is not None or length!=16:raise ValueError('invalid signature command')
            signature=struct.unpack_from('<II',raw,cursor+8);normalized[cursor+8:cursor+16]=bytes(8)
        if tag==0x19:
            if length<72:raise ValueError('invalid segment command')
            if raw[cursor+8:cursor+24].rstrip(b'\0')==b'__LINKEDIT':
                if linkedit is not None:raise ValueError('duplicate linkedit segment')
                vmaddr,vmsize,offset,filesize=struct.unpack_from('<4Q',raw,cursor+24)
                if offset+filesize!=len(raw) or vmsize<filesize:raise ValueError('invalid linkedit extent')
                linkedit=(offset,filesize);normalized[cursor+32:cursor+40]=bytes(8);normalized[cursor+48:cursor+56]=bytes(8)
        cursor+=length
    if cursor!=32+size or signature is None or linkedit is None:raise ValueError('missing Mach-O signature layout')
    offset,length=signature
    if offset<max(cursor,linkedit[0]) or length<8 or offset+length!=len(raw):raise ValueError('signature is not a terminal blob')
    if raw[offset:offset+4]!=bytes.fromhex('fade0cc0'):raise ValueError('invalid embedded signature blob')
    return {'format':'native-mach-o-code-identity-v1','sha256':sha(normalized[:offset]),'signature_offset':offset}


def signature(path,identifier,runtime=False):
    command(['/usr/bin/codesign','--verify','--strict',str(path)])
    info=command(['/usr/bin/codesign','--display','--verbose=4',str(path)]).stderr.decode()
    fields=dict(line.split('=',1) for line in info.splitlines() if '=' in line)
    if fields.get('Identifier')!=identifier or fields.get('Signature')!='adhoc' or fields.get('TeamIdentifier')!='not set' or 'Timestamp' in fields or any(line.startswith('Authority=') for line in info.splitlines()):raise ValueError('unexpected rehearsal signature identity')
    if runtime:
        match=re.search(r'flags=0x([0-9a-fA-F]+)',info)
        if match is None or int(match[1],16)&0x10002!=0x10002:raise ValueError('missing ad-hoc/hardened runtime flags')
        entitlements=command(['/usr/bin/codesign','--display','--entitlements','-','--xml',str(path)]).stdout
        if plistlib.loads(entitlements)!={}:raise ValueError('unexpected wallet entitlements')
    return {'identifier':identifier,'signature':'ad-hoc','team_identifier':None,'secure_timestamp':False,'hardened_runtime':runtime,'entitlements':{} if runtime else None}


def notary_plan(image_sha256):
    # These are data, not executable commands. A new real Developer ID artifact
    # is required; the ad-hoc image cannot enter the production handoff.
    steps=[
        ('sign_native',['/usr/bin/codesign','--force','--sign','<DEVELOPER_ID_SHA1>','--options','runtime','--timestamp','--identifier','<REVIEWED_IDENTIFIER>','--entitlements','<EMPTY_ENTITLEMENTS_PLIST>','<NATIVE_WALLET>']),
        ('rebuild_inventory',['<REVIEWED_PACKAGER>','<SIGNED_PAYLOAD_AND_PROVENANCE>']),
        ('create_image',['/usr/bin/hdiutil','create','-srcfolder','<SIGNED_PAYLOAD>','-fs','HFS+','-format','UDZO','-nospotlight','<NEW_DMG>']),
        ('sign_image',['/usr/bin/codesign','--force','--sign','<DEVELOPER_ID_SHA1>','--timestamp','--identifier','<REVIEWED_IMAGE_IDENTIFIER>','<NEW_DMG>']),
        ('submit',['/usr/bin/xcrun','notarytool','submit','<DEVELOPER_ID_DMG>','--keychain-profile','<KEYCHAIN_PROFILE>','--output-format','json']),
        ('inspect',['/usr/bin/xcrun','notarytool','info','<SUBMISSION_UUID>','--keychain-profile','<KEYCHAIN_PROFILE>','--output-format','json']),
        ('log',['/usr/bin/xcrun','notarytool','log','<SUBMISSION_UUID>','--keychain-profile','<KEYCHAIN_PROFILE>','<PRIVATE_LOG_JSON>']),
        ('staple',['/usr/bin/xcrun','stapler','staple','<ACCEPTED_DMG>']),
        ('validate_ticket',['/usr/bin/xcrun','stapler','validate','<STAPLED_DMG>']),
        ('assess',['/usr/sbin/spctl','--assess','--type','open','--context','context:primary-signature','<STAPLED_DMG>'])]
    return {'format':'native-apple-notarization-plan-v1','input_rehearsal_image_sha256':image_sha256,'requires_new_developer_id_artifact':True,
        'credentials_configured':False,'network_commands_executed':False,'release_ready':False,
        'steps':[{'name':name,'argv':argv,'execution_enabled':False} for name,argv in steps],
        'submit_without_wait':True,'persist_submission_id_before_polling':True,'ambiguous_submit_requires_explicit_reconciliation':True,
        'rebuild_publisher_signature_after_stapling':True}


def bundle_files(bundle):
    directory(bundle)
    result={};total=0
    for path in bundle.rglob('*'):
        meta=path.lstat()
        if stat.S_ISDIR(meta.st_mode):continue
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o022 or len(result)>=1024:raise ValueError('unsafe Apple payload inventory')
        name=path.relative_to(bundle).as_posix()
        if not safe_name(name) or (name not in REQUIRED|{'MANIFEST.json','BUILD.json','APPLE.json'} and not name.startswith('notices/')):raise ValueError('file outside Apple payload inventory')
        result[name]=read(path,64*1024*1024,allow_empty=True)
        total+=len(result[name])
        if total>128*1024*1024:raise ValueError('Apple payload exceeds bounded inventory')
    if not REQUIRED|{'MANIFEST.json','BUILD.json','APPLE.json'}<=set(result):raise ValueError('incomplete Apple payload')
    return result


def state_value(state):
    keys={'format','mode','binding','phase','attempt','receipt_sha256'}
    if not isinstance(state,dict) or set(state)!=keys or state['format']!='native-apple-preparation-v1' or state['mode']!=MODE or state['phase'] not in ('planned','payload_signed','image_created','image_signed','complete'):raise ValueError('invalid Apple preparation state')
    if not isinstance(state['binding'],dict) or set(state['binding'])!={'archive_sha256','descriptor_sha256','trust_sha256','mode'} or state['binding']['mode']!=MODE or any(not hex64(state['binding'][k]) for k in ('archive_sha256','descriptor_sha256','trust_sha256')):raise ValueError('invalid Apple input binding')
    if state['attempt'] is not None and (not isinstance(state['attempt'],str) or re.fullmatch('[0-9a-f]{32}',state['attempt']) is None):raise ValueError('invalid Apple attempt identity')
    if (state['phase']=='complete' and (state['attempt'] is None or not hex64(state['receipt_sha256']))) or (state['phase']!='complete' and state['receipt_sha256'] is not None):raise ValueError('invalid Apple commit')
    return state


@contextmanager
def workspace(root):
    directory(root);fd=os.open(root/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077:raise ValueError('unsafe Apple preparation lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)


def _verify(root):
    root=Path(root).absolute();directory(root);state=decode(read(root/'state.json',16384,True));marker=decode(read(root/'initialized',16384,True))
    state_value(state)
    if marker!={'format':'native-apple-preparation-marker-v1','binding':state.get('binding')} or state.get('format')!='native-apple-preparation-v1' or state.get('mode')!=MODE or state.get('phase')!='complete':raise ValueError('Apple rehearsal is incomplete or changed')
    attempt=state['attempt']
    if not isinstance(attempt,str) or re.fullmatch('[0-9a-f]{32}',attempt) is None:raise ValueError('invalid Apple attempt')
    work=root/'attempts'/attempt;directory(work);receipt=decode(read(work/'REHEARSAL.json',16384,True));bundle=work/'payload/native-wallet'
    if (not isinstance(receipt,dict) or set(receipt)!={'format','mode','transformation','image_sha256','notarized','release_ready','developer_id_used','credentials_accessed','network_commands_executed','python_runtime_bundled','requires_python_3_10'} or
            sha(encode(receipt))!=state['receipt_sha256'] or receipt['format']!='native-apple-signing-rehearsal-v1' or receipt['mode']!=MODE or not hex64(receipt['image_sha256']) or
            any(receipt[k] is not False for k in ('notarized','release_ready','developer_id_used','credentials_accessed','network_commands_executed','python_runtime_bundled')) or receipt['requires_python_3_10'] is not True):raise ValueError('Apple evidence changed')
    files=bundle_files(bundle);manifest=decode(files['MANIFEST.json'])
    if manifest['format']!='native-wallet-bundle-v1' or manifest['binary_kind']!='apple-signing-rehearsal' or set(manifest['files'])!=set(files)-{'MANIFEST.json'}:raise ValueError('Apple manifest changed')
    for name,item in manifest['files'].items():
        if item!={'size':len(files[name]),'sha256':sha(files[name])}:raise ValueError('Apple payload changed')
        generic_paths_absent(files[name])
    apple=decode(files['APPLE.json']);binary=files['bin/native-wallet'];origin=read(work/'original-native-wallet',64*1024*1024)
    if apple!=receipt['transformation'] or apple['original_binary_sha256']!=sha(origin) or apple['signed_binary_sha256']!=sha(binary) or apple['pre_sign_build_sha256']!=sha(files['BUILD.json']):raise ValueError('Apple code provenance changed')
    build_metadata(decode(files['BUILD.json']),origin)
    if code_identity(origin)!=code_identity(binary) or apple['code_identity']!=code_identity(binary):raise ValueError('signing changed native code')
    if encode(signature(bundle/'bin/native-wallet',IDENTIFIER,True))!=encode(apple['signature']):raise ValueError('native signature evidence changed')
    image=work/'wallet-rehearsal.dmg'
    if sha(read(image,64*1024*1024))!=receipt['image_sha256']:raise ValueError('Apple image changed')
    signature(image,IMAGE_IDENTIFIER);command(['/usr/bin/hdiutil','verify',str(image)])
    if decode(read(work/'NOTARIZATION-PLAN.json',16384,True))!=notary_plan(receipt['image_sha256']):raise ValueError('notarization plan changed')
    return work,receipt


def prepare(archive,release,trust_root,root,resume=False,hook=None):
    root=Path(root).absolute()
    parents(root)
    if not resume:
        if os.path.lexists(root):raise ValueError('use a new Apple preparation root')
        root.mkdir(mode=0o700)
    with workspace(root):return _prepare(archive,release,trust_root,root,resume,hook)


def verify(root):
    root=Path(root).absolute()
    with workspace(root):return _verify(root)


def _prepare(archive,release,trust_root,root,resume=False,hook=None):
    hook=hook or (lambda _:None);root=Path(root).absolute()
    installation=Installation(trust_root)
    try:
        action,files,_,_=installation.verify(archive,release)
        binding={'archive_sha256':action['release']['archive_sha256'],'descriptor_sha256':action['descriptor_sha256'],'trust_sha256':sha(encode(installation.trust)),'mode':MODE}
    finally:installation.close()
    manifest=decode(files['MANIFEST.json'])
    if manifest['binary_kind']!='path-remapped-development':raise ValueError('Apple preparation requires a verified remapped build')
    build_metadata(decode(files['BUILD.json']),files['bin/native-wallet']);origin_identity=code_identity(files['bin/native-wallet'])
    if resume:
        directory(root);state=decode(read(root/'state.json',16384,True));marker=decode(read(root/'initialized',16384,True))
        state_value(state)
        if state.get('binding')!=binding or marker!={'format':'native-apple-preparation-marker-v1','binding':binding}:raise ValueError('Apple preparation route changed')
        if state.get('phase')=='complete':return _verify(root)
    else:
        if {p.name for p in root.iterdir()}!={'lock'}:raise ValueError('new Apple workspace contains unexpected files')
        (root/'attempts').mkdir(mode=0o700)
        state={'format':'native-apple-preparation-v1','mode':MODE,'binding':binding,'phase':'planned','attempt':None,'receipt_sha256':None}
        atomic(root/'state.json',state);create(root/'initialized',encode({'format':'native-apple-preparation-marker-v1','binding':binding}));fsync_dir(root)
    # Derived local artifacts can be regenerated. Retain every old attempt;
    # never repeat any network submission as part of preparation/recovery.
    attempt=secrets.token_hex(16);work=root/'attempts'/attempt;work.mkdir(mode=0o700);state.update(attempt=attempt,phase='planned');atomic(root/'state.json',state);hook('planned')
    payload=work/'payload';bundle=payload/'native-wallet';bundle.mkdir(mode=0o700,parents=True)
    for name,raw in files.items():
        path=bundle/name;path.parent.mkdir(parents=True,exist_ok=True);create(path,raw,0o700 if name in ('bin/native-wallet','start-wallet.command') else 0o600)
    create(work/'original-native-wallet',files['bin/native-wallet'],0o500)
    empty=work/'empty-entitlements.plist';create(empty,plistlib.dumps({},sort_keys=True))
    command(['/usr/bin/codesign','--force','--sign','-','--options','runtime','--timestamp=none','--identifier',IDENTIFIER,'--entitlements',str(empty),str(bundle/'bin/native-wallet')])
    signed=read(bundle/'bin/native-wallet',64*1024*1024);generic_paths_absent(signed)
    if code_identity(signed)!=origin_identity:raise ValueError('signing modified native code/data')
    transformation={'format':'native-apple-code-transformation-v1','mode':MODE,'original_binary_sha256':sha(files['bin/native-wallet']),
        'signed_binary_sha256':sha(signed),'pre_sign_build_sha256':sha(files['BUILD.json']),'code_identity':origin_identity,'signature':signature(bundle/'bin/native-wallet',IDENTIFIER,True)}
    create(bundle/'APPLE.json',encode(transformation))
    (bundle/'start-wallet.command').write_bytes(b'#!/bin/sh\nset -eu\nexec python3 -I -B "$(dirname -- "$0")/runtime/wallet_launch.py" "$@"\n')
    current=bundle_files(bundle);manifest['binary_kind']='apple-signing-rehearsal';manifest['files']={n:{'size':len(raw),'sha256':sha(raw)} for n,raw in sorted(current.items()) if n!='MANIFEST.json'}
    atomic(bundle/'MANIFEST.json',manifest);state['phase']='payload_signed';atomic(root/'state.json',state);hook('payload_signed')
    image=work/'wallet-rehearsal.dmg'
    command(['/usr/bin/hdiutil','create','-srcfolder',str(payload),'-volname','Native Wallet Rehearsal','-fs','HFS+','-format','UDZO','-nospotlight',str(image)])
    state['phase']='image_created';atomic(root/'state.json',state);hook('image_created')
    command(['/usr/bin/codesign','--force','--sign','-','--timestamp=none','--identifier',IMAGE_IDENTIFIER,str(image)])
    signature(image,IMAGE_IDENTIFIER);command(['/usr/bin/hdiutil','verify',str(image)])
    image_sha=sha(read(image,64*1024*1024));receipt={'format':'native-apple-signing-rehearsal-v1','mode':MODE,'transformation':transformation,
        'image_sha256':image_sha,'notarized':False,'release_ready':False,'developer_id_used':False,'credentials_accessed':False,'network_commands_executed':False,
        'python_runtime_bundled':False,'requires_python_3_10':True}
    create(work/'REHEARSAL.json',encode(receipt));create(work/'NOTARIZATION-PLAN.json',encode(notary_plan(image_sha)));fsync_dir(work)
    state['phase']='image_signed';atomic(root/'state.json',state);hook('image_signed')
    state.update(phase='complete',receipt_sha256=sha(encode(receipt)));atomic(root/'state.json',state);hook('complete')
    return _verify(root)


def image_mounts(image):
    value=plistlib.loads(command(['/usr/bin/hdiutil','info','-plist']).stdout)
    found=[]
    for item in value.get('images',[]):
        if Path(item.get('image-path','/nonexistent')).resolve()!=image.resolve():continue
        for entity in item.get('system-entities',[]):
            if 'mount-point' in entity:found.append((entity.get('dev-entry'),entity['mount-point']))
    return found


def _recover_mount(root,work):
    image=work/'wallet-rehearsal.dmg';mount=work/'readonly-mount';record=root/'mount-state.json'
    if record.exists():
        value=decode(read(record,8192,True))
        if not isinstance(value,dict) or set(value)!={'format','image_sha256','mountpoint','device','phase'} or value['format']!='native-apple-mount-v1' or value['image_sha256']!=sha(read(image,64*1024*1024)) or value['mountpoint']!=str(mount) or value['phase'] not in ('mounting','mounted','detached') or (value['device'] is not None and (not isinstance(value['device'],str) or re.fullmatch('/dev/disk[0-9]+s[0-9]+',value['device']) is None)):
            raise ValueError('invalid owned Apple mount state')
    else:value={'format':'native-apple-mount-v1','image_sha256':sha(read(image,64*1024*1024)),'mountpoint':str(mount),'device':None,'phase':'mounting'}
    # Reconcile a crash between hdiutil attachment and saving its device ID.
    # Detach only this exact verified image at our private reserved mountpoint.
    for device,where in image_mounts(image):
        if where!=str(mount) or re.fullmatch('/dev/disk[0-9]+s[0-9]+',device or '') is None:raise ValueError('image has an unexpected attachment; no device detached')
        if value['device'] is not None and value['device']!=device:raise ValueError('owned mount device changed; no device detached')
        command(['/usr/bin/hdiutil','detach',device]);value['device']=device
    value['phase']='detached';atomic(record,value)


def recover_mount(root):
    root=Path(root).absolute()
    with workspace(root):
        work,_=_verify(root);_recover_mount(root,work)


@contextmanager
def mounted_payload(root,hook=None):
    root=Path(root).absolute();hook=hook or (lambda _:None)
    with workspace(root):
        work,receipt=_verify(root);_recover_mount(root,work);mount=work/'readonly-mount'
        mount.mkdir(mode=0o700,exist_ok=True)
        value={'format':'native-apple-mount-v1','image_sha256':receipt['image_sha256'],'mountpoint':str(mount),'device':None,'phase':'mounting'}
        atomic(root/'mount-state.json',value)
        try:
            attached=plistlib.loads(command(['/usr/bin/hdiutil','attach','-readonly','-nobrowse','-noautoopen','-mountpoint',str(mount),'-plist',str(work/'wallet-rehearsal.dmg')]).stdout)
            entities=[e for e in attached.get('system-entities',[]) if e.get('mount-point')==str(mount)]
            if len(entities)!=1:raise ValueError('unexpected Apple image attachment')
            value.update(phase='mounted',device=entities[0].get('dev-entry'));atomic(root/'mount-state.json',value);hook('mounted')
            # Compare every mounted file to the sealed staging bytes before any
            # optional local test executes the wallet copy. No files are copied
            # into Applications or a user's existing wallet directory.
            expected=bundle_files(work/'payload/native-wallet');actual={}
            for path in (mount/'native-wallet').rglob('*'):
                meta=path.lstat()
                if stat.S_ISDIR(meta.st_mode):continue
                if not stat.S_ISREG(meta.st_mode) or len(actual)>=1024:raise ValueError('unexpected mounted payload object')
                name=path.relative_to(mount/'native-wallet').as_posix()
                if name not in expected or meta.st_size!=len(expected[name]):raise ValueError('mounted payload inventory changed')
                actual[name]=path.read_bytes()
            if actual!=expected:raise ValueError('mounted Apple payload differs')
            yield mount/'native-wallet'
        finally:_recover_mount(root,work)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('prepare');p.add_argument('--archive',required=True,type=Path);p.add_argument('--release',required=True,type=Path);p.add_argument('--trust-root',required=True,type=Path);p.add_argument('--root',required=True,type=Path);p.add_argument('--resume',action='store_true')
    v=sub.add_parser('verify');v.add_argument('--root',required=True,type=Path);args=parser.parse_args()
    if args.action=='prepare':_,receipt=prepare(args.archive,args.release,args.trust_root,args.root,args.resume)
    else:_,receipt=verify(args.root)
    print(json.dumps({'verified_rehearsal':True,'image_sha256':receipt['image_sha256'],'notarized':False,'release_ready':False,'network_commands_executed':False}))


if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):
        print('Apple preparation failed; retain original input and private attempt evidence.',file=__import__('sys').stderr);raise SystemExit(1)
