#!/usr/bin/env python3
"""Explicit Developer ID preparation, separate from the frozen ad-hoc rehearsal.

Only new copies are signed. This tool does not upload, notarize, staple, publish,
change a keychain, replace a wallet or claim a one-click application installer.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import subprocess
import tempfile

from wallet_release import (Installation, atomic, build_metadata, create, decode,
    directory, encode, fsync_dir, hex64, parents, read, safe_name, sha)
from wallet_apple import code_identity, workspace

FORMAT = 'zolana-apple-developer-id-preparation-v1'
MODE = 'developer-id'


def identifiers(certificate, team, bundle):
    if (not isinstance(certificate,str) or re.fullmatch('[A-Fa-f0-9]{40}',certificate) is None or
        not isinstance(team,str) or re.fullmatch('[A-Z0-9]{10}',team) is None or
        not isinstance(bundle,str) or len(bundle)>180 or re.fullmatch(r'[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z][A-Za-z0-9-]*){2,}',bundle) is None):
        raise ValueError('explicit certificate SHA1, ten-character Team ID and reverse-DNS identifier required')
    return certificate.upper(),team,bundle


def developer_id_requirement(identifier, team):
    identifiers('A'*40,team,identifier)
    return ('anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
            'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists '
            f'and certificate leaf[subject.OU] = "{team}" and identifier "{identifier}"')


def command(argv, timeout=180):
    if not isinstance(argv,list) or not argv or any(not isinstance(v,str) or '\0' in v for v in argv):
        raise ValueError('explicit bounded Apple argument vector required')
    exe=argv[0]
    if exe=='/usr/bin/security':
        valid=argv==['/usr/bin/security','find-identity','-v','-p','codesigning']
    elif exe=='/usr/bin/codesign':
        valid=argv[1:-1] in (['--verify','--strict'],['--display','--verbose=4'],['--display','--entitlements','-','--xml'])
        if len(argv)==5 and argv[1:3]==['--verify','--strict']:
            match=re.fullmatch(r'-R=.*certificate leaf\[subject\.OU\] = "([A-Z0-9]{10})" and identifier "([A-Za-z][A-Za-z0-9.-]*)"',argv[3])
            if match:
                try:valid=argv[3]=='-R='+developer_id_requirement(match[2],match[1])
                except ValueError:valid=False
        if len(argv)==5 and argv[1:3]==['--display','--extract-certificates'] and Path(argv[3]).is_absolute():
            directory(Path(argv[3]).parent);valid=True
        if argv[1:3]==['--force','--sign']:
            certificate=argv[3] if len(argv)>3 else ''
            identifier=argv[6] if len(argv)>6 else ''
            try:identifiers(certificate,'A'*10,identifier)
            except ValueError:valid=False
            else:
                prefix=['/usr/bin/codesign','--force','--sign',certificate,'--timestamp','--identifier',identifier]
                valid=argv[:-1]==prefix
                if len(argv)==12 and argv[:7]==prefix and argv[7:10]==['--options','runtime','--entitlements']:
                    valid=Path(argv[10]).is_absolute() and plistlib.loads(read(Path(argv[10]),8192,True))=={}
        valid=valid and Path(argv[-1]).is_absolute()
    elif exe=='/usr/bin/hdiutil':
        valid=(len(argv)==3 and argv[1]=='verify' and Path(argv[2]).is_absolute())
        if len(argv)==12 and argv[1:3]==['create','-srcfolder']:
            valid=(Path(argv[3]).is_absolute() and argv[4:11]==['-volname','Zolana Wallet Pilot','-fs','HFS+','-format','UDZO','-nospotlight'] and Path(argv[11]).is_absolute())
    else:valid=False
    if not valid:raise ValueError('unreviewed Apple preparation command')
    result=subprocess.run(argv,capture_output=True,timeout=timeout,env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})
    if result.returncode:raise ValueError('Apple signing/preparation command failed; preserve attempt evidence')
    return result


def preflight_identity(certificate):
    output=command(['/usr/bin/security','find-identity','-v','-p','codesigning'],30).stdout.decode()
    rows=re.findall(r'^\s*\d+\) ([0-9A-Fa-f]{40}) "(Developer ID Application:[^"\n]+)"',output,re.M)
    if sum(pin.upper()==certificate for pin,_ in rows)!=1:
        raise ValueError('the explicit usable Developer ID Application certificate is unavailable')


def signature(path, identifier, team, runtime, certificate=None):
    command(['/usr/bin/codesign','--verify','--strict','-R='+developer_id_requirement(identifier,team),str(path)])
    info=command(['/usr/bin/codesign','--display','--verbose=4',str(path)]).stderr.decode()
    fields=dict(line.split('=',1) for line in info.splitlines() if '=' in line)
    authorities=[line[10:] for line in info.splitlines() if line.startswith('Authority=')]
    if (fields.get('Identifier')!=identifier or fields.get('TeamIdentifier')!=team or
        fields.get('Signature')=='adhoc' or not fields.get('Timestamp') or not authorities or
        not authorities[0].startswith('Developer ID Application:')):
        raise ValueError('Developer ID, secure timestamp, Team ID or identifier differs')
    entitlements=None
    if runtime:
        match=re.search(r'flags=0x([0-9a-fA-F]+)',info)
        if match is None or not int(match[1],16)&0x10000:raise ValueError('hardened runtime required')
        entitlements=plistlib.loads(command(['/usr/bin/codesign','--display','--entitlements','-','--xml',str(path)]).stdout)
        if entitlements!={}:raise ValueError('only empty wallet entitlements are allowed')
    if certificate is None:raise ValueError('explicit leaf certificate fingerprint required')
    certificate,_,_=identifiers(certificate,team,identifier)
    # Extract only the public signing certificate, never a private key/keychain.
    with tempfile.TemporaryDirectory(prefix='zolana-leaf-cert-') as temporary:
        prefix=Path(temporary)/'cert'
        command(['/usr/bin/codesign','--display','--extract-certificates',str(prefix),str(path)])
        actual=hashlib.sha1(read(Path(str(prefix)+'0'),128*1024)).hexdigest().upper()
    if actual!=certificate:raise ValueError('actual Developer ID leaf certificate differs')
    return dict(identifier=identifier,team_identifier=team,certificate_sha1=actual,signature='Developer ID Application',secure_timestamp=True,hardened_runtime=runtime,entitlements=entitlements)


def tree_files(bundle):
    directory(bundle);result={};total=0
    for path in bundle.rglob('*'):
        if path.is_symlink():raise ValueError('Apple payload symlink refused')
        if path.is_dir():continue
        name=path.relative_to(bundle).as_posix()
        if not safe_name(name) or len(result)>=1024:raise ValueError('bounded safe Apple inventory required')
        result[name]=read(path,64*1024*1024,allow_empty=True);total+=len(result[name])
        if total>128*1024*1024:raise ValueError('Apple payload exceeds inventory bounds')
    return result


def sign_args(path, certificate, identifier, entitlements=None):
    args=['/usr/bin/codesign','--force','--sign',certificate,'--timestamp','--identifier',identifier]
    if entitlements is not None:args+=['--options','runtime','--entitlements',str(entitlements)]
    return args+[str(path)]


def state_value(state):
    if (not isinstance(state,dict) or set(state)!={'format','binding','phase','attempt','receipt_sha256'} or
        state['format']!='zolana-developer-id-workspace-v1' or state['phase'] not in ('planned','payload_signed','image_created','complete') or
        not isinstance(state['binding'],dict) or set(state['binding'])!={'archive_sha256','descriptor_sha256','trust_sha256','certificate_sha1','team_identifier','bundle_identifier'}):
        raise ValueError('invalid Developer ID preparation state')
    binding=state['binding'];identifiers(binding['certificate_sha1'],binding['team_identifier'],binding['bundle_identifier'])
    if not all(hex64(binding[k]) for k in ('archive_sha256','descriptor_sha256','trust_sha256')):
        raise ValueError('invalid authenticated source binding')
    if state['attempt'] is not None and re.fullmatch('[0-9a-f]{32}',state['attempt']) is None:raise ValueError('invalid attempt identity')
    if state['phase']=='complete' and (state['attempt'] is None or not hex64(state['receipt_sha256'])):raise ValueError('invalid completed preparation')
    if state['phase']!='complete' and state['receipt_sha256'] is not None:raise ValueError('unfinished preparation cannot carry a receipt')
    return state


def _verify_prepared(root, expected_receipt_sha256=None):
    state=state_value(decode(read(root/'state.json',16384,True)))
    if decode(read(root/'initialized',16384,True))!={'format':'zolana-developer-id-marker-v1','binding':state['binding']} or state['phase']!='complete':raise ValueError('Developer ID preparation is incomplete or rebound')
    work=root/'attempts'/state['attempt'];directory(work)
    raw=read(work/'SIGNED-PREPARATION.json',16384,True)
    if sha(raw)!=state['receipt_sha256'] or (expected_receipt_sha256 is not None and (not hex64(expected_receipt_sha256) or sha(raw)!=expected_receipt_sha256)):
        raise ValueError('explicit Developer ID receipt digest differs')
    receipt=decode(raw);required={'format','mode','input_binding','image_sha256','image_bytes','image_identifier','certificate_sha1','team_identifier','bundle_identifier','transformation','payload_manifest_sha256','source_manifest_sha256','notarized','release_ready','developer_id_used','python_runtime_bundled','requires_python_3_10'}
    binding=state['binding']
    if (not isinstance(receipt,dict) or set(receipt)!=required or receipt['format']!=FORMAT or receipt['mode']!=MODE or receipt['input_binding']!=binding or
        any(receipt[k] is not False for k in ('notarized','release_ready','python_runtime_bundled')) or receipt['developer_id_used'] is not True or receipt['requires_python_3_10'] is not True or
        any(receipt[k]!=binding[k] for k in ('certificate_sha1','team_identifier','bundle_identifier')) or receipt['image_identifier']!=binding['bundle_identifier']+'.image'):
        raise ValueError('invalid Developer ID preparation receipt')
    image=work/'Zolana-Wallet.dmg';image_raw=read(image,64*1024*1024)
    if not hex64(receipt['image_sha256']) or type(receipt['image_bytes']) is not int or len(image_raw)!=receipt['image_bytes'] or sha(image_raw)!=receipt['image_sha256']:raise ValueError('signed DMG bytes changed')
    original=read(work/'original-native-wallet',64*1024*1024)
    source_raw=read(work/'SOURCE-MANIFEST.json',1_000_000,True)
    if sha(source_raw)!=receipt['source_manifest_sha256']:raise ValueError('authenticated source inventory changed')
    source=decode(source_raw);bundle=work/'payload/native-wallet';files=tree_files(bundle)
    if set(files)!=set(source['files'])|{'MANIFEST.json','APPLE.json'}:raise ValueError('exact authenticated payload inventory required')
    manifest=decode(files['MANIFEST.json'])
    if (sha(files['MANIFEST.json'])!=receipt['payload_manifest_sha256'] or manifest!={**source,'binary_kind':'apple-developer-id','files':{n:dict(size=len(v),sha256=sha(v)) for n,v in sorted(files.items()) if n!='MANIFEST.json'}}):raise ValueError('Developer ID manifest changed')
    transform=receipt['transformation']
    if decode(files['APPLE.json'])!=transform or transform['format']!='zolana-apple-code-transformation-v1' or transform['mode']!=MODE or transform['original_binary_sha256']!=sha(original) or transform['signed_binary_sha256']!=sha(files['bin/native-wallet']) or transform['pre_sign_build_sha256']!=sha(files['BUILD.json']):raise ValueError('pre-sign build provenance changed')
    build_metadata(decode(files['BUILD.json']),original)
    if code_identity(original)!=code_identity(files['bin/native-wallet']) or transform['code_identity']!=code_identity(original):raise ValueError('signing modified executable code/data')
    if signature(bundle/'bin/native-wallet',binding['bundle_identifier'],binding['team_identifier'],True,binding['certificate_sha1'])!=transform['signature']:raise ValueError('native signature metadata changed')
    for name,item in source['files'].items():
        if name not in ('bin/native-wallet','start-wallet.command') and item!=dict(size=len(files[name]),sha256=sha(files[name])):raise ValueError('signing changed authenticated resource')
    if files['start-wallet.command']!=b'#!/bin/sh\nset -eu\nexec python3 -I -B "$(dirname -- "$0")/runtime/wallet_launch.py" "$@"\n':raise ValueError('isolated launcher changed')
    signature(image,receipt['image_identifier'],binding['team_identifier'],False,binding['certificate_sha1'])
    command(['/usr/bin/hdiutil','verify',str(image)])
    return image,receipt


def verify_prepared(root, expected_receipt_sha256=None):
    root=Path(root).absolute()
    with workspace(root):return _verify_prepared(root,expected_receipt_sha256)


def prepare(archive,release,trust_root,root,certificate,team,bundle_identifier,resume=False,hook=None):
    certificate,team,bundle_identifier=identifiers(certificate,team,bundle_identifier)
    root=Path(root).absolute();parents(root);hook=hook or (lambda _:None)
    installation=Installation(trust_root)
    try:
        action,files,_,_=installation.verify(archive,release)
        binding=dict(archive_sha256=action['release']['archive_sha256'],descriptor_sha256=action['descriptor_sha256'],trust_sha256=sha(encode(installation.trust)),certificate_sha1=certificate,team_identifier=team,bundle_identifier=bundle_identifier)
    finally:installation.close()
    source=decode(files['MANIFEST.json'])
    if source['binary_kind']!='path-remapped-development' or 'APPLE.json' in files:raise ValueError('original authenticated path-remapped source required')
    build_metadata(decode(files['BUILD.json']),files['bin/native-wallet']);origin=code_identity(files['bin/native-wallet'])
    # A missing or ambiguous identity stops before creating any new workspace.
    preflight_identity(certificate)
    if not resume:
        if os.path.lexists(root):raise ValueError('use a genuinely new Developer ID workspace')
        root.mkdir(mode=0o700)
    with workspace(root):
        if resume:
            state=state_value(decode(read(root/'state.json',16384,True)))
            if state['binding']!=binding or decode(read(root/'initialized',16384,True))!={'format':'zolana-developer-id-marker-v1','binding':binding}:raise ValueError('original preparation inputs or identity changed')
            if state['phase']=='complete':return _verify_prepared(root)
        else:
            if {p.name for p in root.iterdir()}!={'lock'}:raise ValueError('unexpected new workspace contents')
            (root/'attempts').mkdir(mode=0o700)
            state=dict(format='zolana-developer-id-workspace-v1',binding=binding,phase='planned',attempt=None,receipt_sha256=None)
            atomic(root/'state.json',state);create(root/'initialized',encode(dict(format='zolana-developer-id-marker-v1',binding=binding)))
        attempt=secrets.token_hex(16);work=root/'attempts'/attempt;work.mkdir(mode=0o700);state.update(attempt=attempt,phase='planned');atomic(root/'state.json',state);hook('planned')
        payload=work/'payload';native=payload/'native-wallet';native.mkdir(mode=0o700,parents=True)
        for name,raw in files.items():
            path=native/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);create(path,raw,0o700 if name in ('bin/native-wallet','start-wallet.command') else 0o600)
        create(work/'original-native-wallet',files['bin/native-wallet'],0o500);create(work/'SOURCE-MANIFEST.json',files['MANIFEST.json'])
        empty=work/'empty-entitlements.plist';create(empty,plistlib.dumps({},sort_keys=True))
        command(sign_args(native/'bin/native-wallet',certificate,bundle_identifier,empty))
        signed=read(native/'bin/native-wallet',64*1024*1024)
        if code_identity(signed)!=origin:raise ValueError('signing modified executable code/data')
        transform=dict(format='zolana-apple-code-transformation-v1',mode=MODE,original_binary_sha256=sha(files['bin/native-wallet']),signed_binary_sha256=sha(signed),pre_sign_build_sha256=sha(files['BUILD.json']),code_identity=origin,signature=signature(native/'bin/native-wallet',bundle_identifier,team,True,certificate))
        create(native/'APPLE.json',encode(transform))
        (native/'start-wallet.command').write_bytes(b'#!/bin/sh\nset -eu\nexec python3 -I -B "$(dirname -- "$0")/runtime/wallet_launch.py" "$@"\n')
        current=tree_files(native);manifest={**source,'binary_kind':'apple-developer-id','files':{n:dict(size=len(v),sha256=sha(v)) for n,v in sorted(current.items()) if n!='MANIFEST.json'}};atomic(native/'MANIFEST.json',manifest)
        state['phase']='payload_signed';atomic(root/'state.json',state);hook('payload_signed')
        image=work/'Zolana-Wallet.dmg';command(['/usr/bin/hdiutil','create','-srcfolder',str(payload),'-volname','Zolana Wallet Pilot','-fs','HFS+','-format','UDZO','-nospotlight',str(image)])
        state['phase']='image_created';atomic(root/'state.json',state);hook('image_created')
        image_identifier=bundle_identifier+'.image';command(sign_args(image,certificate,image_identifier));signature(image,image_identifier,team,False,certificate);command(['/usr/bin/hdiutil','verify',str(image)])
        raw=read(image,64*1024*1024);receipt=dict(format=FORMAT,mode=MODE,input_binding=binding,image_sha256=sha(raw),image_bytes=len(raw),image_identifier=image_identifier,certificate_sha1=certificate,team_identifier=team,bundle_identifier=bundle_identifier,transformation=transform,payload_manifest_sha256=sha((native/'MANIFEST.json').read_bytes()),source_manifest_sha256=sha(files['MANIFEST.json']),notarized=False,release_ready=False,developer_id_used=True,python_runtime_bundled=False,requires_python_3_10=True)
        create(work/'SIGNED-PREPARATION.json',encode(receipt));fsync_dir(work)
        state.update(phase='complete',receipt_sha256=sha(encode(receipt)));atomic(root/'state.json',state);hook('complete')
        return _verify_prepared(root)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='action',required=True)
    p=sub.add_parser('prepare')
    for name in ('archive','release','trust-root','root'):p.add_argument('--'+name,required=True,type=Path)
    for name in ('certificate-sha1','team-id','bundle-identifier'):p.add_argument('--'+name,required=True)
    p.add_argument('--resume',action='store_true')
    p=sub.add_parser('verify');p.add_argument('--root',required=True,type=Path);p.add_argument('--receipt-sha256')
    a=parser.parse_args()
    if a.action=='prepare':image,receipt=prepare(a.archive,a.release,a.trust_root,a.root,a.certificate_sha1,a.team_id,a.bundle_identifier,a.resume)
    else:image,receipt=verify_prepared(a.root,a.receipt_sha256)
    print(json.dumps(dict(verified_preparation=True,image=str(image),image_sha256=receipt['image_sha256'],notarized=False,release_ready=False,python_runtime_bundled=False)))


if __name__=='__main__':
    try:main()
    except (Exception,KeyboardInterrupt):
        print('Developer ID preparation failed; preserve original input and attempt evidence.',file=__import__('sys').stderr);raise SystemExit(1)
