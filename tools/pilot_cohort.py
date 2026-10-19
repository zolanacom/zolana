#!/usr/bin/env python3
"""Prepare a finite, separate local pilot faucet. Never funds, starts or publishes."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from wallet_release import atomic, create, decode, encode, fsync_dir, read, sha

PROJECT = Path(__file__).resolve().parents[1]
FAUCET = PROJECT / 'target/debug/native-faucet'
WALLET = PROJECT / 'target/debug/native-wallet'
PRIVATE_GRANT, GAS_GRANT, PAYMENT_CAP, ATTEMPTS, GAS_FEE_CAP = 1_000_000, 150_000_000, 150_000_000, 3, 10_000


def code_bytes(path, maximum):
    """Hash local developer code or immutable root-owned installed code only.

    Private wallets, policies and capabilities still use the UID-owned reader.
    A root-owned executable in a user-writable directory is not sealed code.
    """
    path=Path(path)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as source:
        meta=os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode&0o022 or not 1<=meta.st_size<=maximum:
            raise ValueError('unsafe or oversized runtime code input')
        if meta.st_uid!=os.getuid():
            if meta.st_uid!=0:raise ValueError('runtime code owner differs')
            if not path.is_absolute() or path.resolve()!=path:raise ValueError('installed code path must be real')
            for parent in path.parents:
                m=parent.lstat()
                if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:
                    raise ValueError('installed code ancestors must be immutable to service users')
        data=source.read(maximum+1)
        if len(data)!=meta.st_size:raise ValueError('runtime code changed during read')
        return data


def bounded(value, low, high):
    return type(value) is int and low <= value <= high


def budget(count):
    if not bounded(count, 1, 100):
        raise ValueError('cohort must contain 1..100 lifetime slots')
    return dict(private_grants=count*PRIVATE_GRANT, public_gas_grants=count*GAS_GRANT,
                initial_working_reserve=PAYMENT_CAP, gas_fee_reserve=count*ATTEMPTS*GAS_FEE_CAP,
                initial_public_units=count*GAS_GRANT+PAYMENT_CAP+count*ATTEMPTS*GAS_FEE_CAP,
                conservative_public_units=count*(GAS_GRANT+ATTEMPTS*(PAYMENT_CAP+GAS_FEE_CAP)))


def native(binary, command, root=None, extra=(), password=None):
    args=[str(Path(binary).resolve()), command]
    if root is not None: args += ['--root', str(root)]
    result=subprocess.run([*args, *map(str, extra)], input=password, capture_output=True, timeout=40)
    if result.returncode:
        # A failed child may contain a private request. Never echo its output.
        raise ValueError('native '+command+' failed; preserve the original pilot directory')
    return decode(result.stdout)


def profile(value, binary=WALLET):
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        path=Path(temporary)/'profile.json'; create(path, encode(value))
        return native(binary, 'profile', extra=['--network', path])


def validate(value, wallet=WALLET):
    keys={'format','phase','cohort_size','daily_admissions','rpc_per_minute','invitation_ttl_seconds',
          'membership_seconds','private_grant','gas_grant','budget','source_profile','tester_profile'}
    if (not isinstance(value,dict) or set(value)!=keys or value['format']!='zolana-pilot-plan-v1' or
            value['phase']!='local-rehearsal' or not bounded(value['cohort_size'],1,100) or
            not bounded(value['daily_admissions'],1,value['cohort_size']) or
            not bounded(value['rpc_per_minute'],1,10000) or not bounded(value['invitation_ttl_seconds'],1,604800) or
            value['membership_seconds']!=604800 or value['private_grant']!=PRIVATE_GRANT or value['gas_grant']!=GAS_GRANT or
            value['budget']!=budget(value['cohort_size'])):
        raise ValueError('invalid finite pilot plan or budget')
    source, tester = profile(value['source_profile'],wallet), profile(value['tester_profile'],wallet)
    identity=('network','genesis_hash','program','pool','pool_format','recipient_withdrawals')
    if (source!=value['source_profile'] or tester!=value['tester_profile'] or
            source.get('invite_required',False) or tester.get('invite_required') is not True or
            any(source[k]!=tester[k] for k in identity) or source['rpc']==tester['rpc'] or
            tester['rpc']['url']==tester['faucet']['url'] or source.get('faucet') is not None or
            source['rpc']['transport']!='loopback-http'):
        raise ValueError('pilot requires separate compatible operator/gateway/faucet profiles')
    # Native parsing validates endpoints and pins; retain exactly that public allowlist.
    return value


def plan(source, tester, count=10, daily=3, rpc_limit=2000, ttl=86400, wallet=WALLET):
    source,tester=profile(source,wallet),profile(tester,wallet)
    return validate(dict(format='zolana-pilot-plan-v1',phase='local-rehearsal',cohort_size=count,
                         daily_admissions=daily,rpc_per_minute=rpc_limit,invitation_ttl_seconds=ttl,
                         membership_seconds=604800,private_grant=PRIVATE_GRANT,gas_grant=GAS_GRANT,
                         budget=budget(count),source_profile=source,tester_profile=tester),wallet)


def directory(path):
    meta=path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077:
        raise ValueError('pilot directory must be owned, private and not a symlink')
    for parent in path.resolve().parents:
        m=parent.lstat()
        if not stat.S_ISDIR(m.st_mode) or (m.st_mode&0o022 and not (m.st_uid==0 and m.st_mode&stat.S_ISVTX)):
            raise ValueError('unsafe pilot ancestor')


@contextmanager
def locked(root):
    directory(root)
    fd=os.open(root/'pilot.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        m=os.fstat(fd)
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=os.getuid() or m.st_mode&0o077:
            raise ValueError('unsafe pilot lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
    finally: os.close(fd)


def private_json(path, limit=1024*1024):
    return decode(read(path,limit,secret=True))


def checked(root, expected, faucet=FAUCET, wallet=WALLET):
    value=validate(private_json(root/'plan.json',32768),wallet)
    if sha(encode(value))!=expected:
        raise ValueError('reviewed plan digest differs; original pilot is preserved')
    marker=private_json(root/'initialized.json')
    if (set(marker)!={'format','plan_sha256','faucet_sha256','wallet_sha256','rpc_access_sha256'} or
            marker['format']!='zolana-pilot-root-v1' or marker['plan_sha256']!=expected or
            marker['faucet_sha256']!=sha(code_bytes(faucet,64*1024*1024)) or marker['wallet_sha256']!=sha(code_bytes(wallet,64*1024*1024))):
        raise ValueError('pilot identity/binary changed')
    if read(root/'source-profile.json',8192)!=encode(value['source_profile']) or read(root/'tester-profile.json',8192)!=encode(value['tester_profile']):
        raise ValueError('pilot public profile changed')
    return value


def policy(root, value, faucet=FAUCET):
    data=root/'faucet'; directory(data)
    claims=private_json(data/'claims.json'); p=claims['policy']
    expected=dict(network=value['source_profile']['network'],genesis_hash=value['source_profile']['genesis_hash'])
    if (p['network']!=expected or p['max_claims']!=value['cohort_size'] or p['private_amount']!=PRIVATE_GRANT or
            p['gas_amount']!=GAS_GRANT or p['payment_cap']!=PAYMENT_CAP or p['max_attempts']!=ATTEMPTS or
            len(claims['claims'])>value['cohort_size'] or
            private_json(data/'profile.json',8192)!=value['source_profile']):
        raise ValueError('native faucet differs from reviewed cohort')
    info=native(faucet,'access-info',data)
    marker=private_json(root/'initialized.json')
    credential=marker['rpc_access_sha256']
    if bool(p.get('operator_rpc',False))!=(credential is not None) or (credential is not None and
            sha(read(data/'rpc-access.key',16384,secret=True))!=credential):
        raise ValueError('original operator RPC credential changed')
    if info.get('invite_required'):
        admission=private_json(data/'admission.json'); a=admission['policy']
        if (a['network']!=expected or a['max_invites']!=value['cohort_size'] or a['daily_admissions']!=value['daily_admissions'] or
                a['rpc_per_minute']!=value['rpc_per_minute'] or a['rpc_audience']!=value['tester_profile']['rpc']['url'] or
                a['faucet_audience']!=value['tester_profile']['faucet']['url']):
            raise ValueError('native admission differs from reviewed cohort')
    return claims, info


def prepare(value, root, expected, password_file, resume=False, faucet=FAUCET, wallet=WALLET, rpc_access_file=None):
    value=validate(value,wallet); root=Path(root).absolute()
    if sha(encode(value))!=expected: raise ValueError('explicit reviewed plan digest required')
    password=read(password_file,1024,secret=True)
    if len(password)<12: raise ValueError('faucet password must be 12..1024 bytes')
    if not resume:
        directory(root.parent)
        root.mkdir(mode=0o700); fsync_dir(root.parent)
        create(root/'initialized.json',encode(dict(format='zolana-pilot-root-v1',plan_sha256=expected,
               faucet_sha256=sha(code_bytes(faucet,64*1024*1024)),wallet_sha256=sha(code_bytes(wallet,64*1024*1024)),
               rpc_access_sha256=sha(read(rpc_access_file,16384,secret=True)) if rpc_access_file is not None else None)))
        for name,data in [('plan.json',value),('source-profile.json',value['source_profile']),('tester-profile.json',value['tester_profile'])]:
            create(root/name,encode(data))
        fsync_dir(root)
    with locked(root):
        checked(root,expected,faucet,wallet)
        if rpc_access_file is not None and sha(read(rpc_access_file,16384,secret=True))!=private_json(root/'initialized.json')['rpc_access_sha256']:
            raise ValueError('operator RPC credential does not match original setup')
        data=root/'faucet'
        if not os.path.lexists(data):
            extra=['--profile',root/'source-profile.json','--password-file','-','--max-claims',value['cohort_size']]
            if rpc_access_file is not None: extra+=['--rpc-access-file',rpc_access_file]
            native(faucet,'init',data,extra,password)
        # Existing partial native setup is never replaced or reinitialized.
        claims,info=policy(root,value,faucet)
        addresses=native(wallet,'address',extra=['--network',root/'source-profile.json','--wallet',data/'wallet.enc.json','--password-file','-'],password=password)
        if addresses['address']!=claims['policy']['source_private_address'] or addresses['fee_address']!=claims['policy']['source_fee_address']:
            raise ValueError('faucet key differs from original policy')
        if not info.get('invite_required'):
            native(faucet,'access-init',data,['--profile',root/'tester-profile.json','--daily-admissions',value['daily_admissions'],'--rpc-limit',value['rpc_per_minute']])
        _,info=policy(root,value,faucet)
        if not os.path.lexists(root/'issuance.json'):
            if (root/'prepared.json').exists() or info['issued']:
                raise ValueError('issuance journal missing; never recreate capacity')
            create(root/'issuance.json',encode(dict(format='zolana-pilot-issuance-v1',slots={})));fsync_dir(root)
        receipt=dict(format='zolana-pilot-prepared-v1',plan_sha256=expected,cohort_size=value['cohort_size'],
                     private_address=addresses['address'],fee_address=addresses['fee_address'],budget=value['budget'],
                     funded=False,installed=False,services_started=False,published=False)
        if (root/'prepared.json').exists():
            if private_json(root/'prepared.json')!=receipt: raise ValueError('prepared receipt changed')
        else: create(root/'prepared.json',encode(receipt)); fsync_dir(root)
        return receipt


def issuance(root,value):
    state=private_json(root/'issuance.json')
    if (set(state)!={'format','slots'} or state['format']!='zolana-pilot-issuance-v1' or
            not isinstance(state['slots'],dict) or len(state['slots'])>value['cohort_size'] or
            any(not isinstance(slot,str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,31}',slot) is None or
                not isinstance(record,dict) or set(record)!={'bind_fee'} or
                (record['bind_fee'] is not None and not isinstance(record['bind_fee'],str))
                for slot,record in state['slots'].items())):
        raise ValueError('invalid issuance journal; preserve original capacity')
    return state


def checked_exports(root,state):
    invitations=private_json(root/'faucet/admission.json')['invitations'];known={i['id']:i for i in invitations}
    tracked={}
    folder=root/'invitations'
    if os.path.lexists(folder):
        directory(folder)
        for path in folder.iterdir():
            if path.suffix!='.json' or path.stem not in state['slots']:raise ValueError('untracked invitation export')
            export=private_json(path,1024)
            if set(export)!={'invitation','invite_id','redeem_by'} or not isinstance(export['invitation'],str) or re.fullmatch('invite1_[A-Za-z0-9_-]{43}',export['invitation']) is None:
                raise ValueError('invalid invitation export')
            invitation=known.get(export['invite_id'])
            if (invitation is None or export['invite_id'] in tracked or
                    hashlib.blake2b(export['invitation'].encode(),digest_size=32).hexdigest()!=export['invite_id'] or
                    invitation['redeem_by']!=export['redeem_by'] or invitation['bound_fee']!=state['slots'][path.stem]['bind_fee']):
                raise ValueError('invitation export/ledger incomplete; never replace or reissue this slot')
            tracked[export['invite_id']]=(path.stem,invitation)
    if set(tracked)!=set(known):raise ValueError('native invitation export missing; preserve original state')
    return tracked


def issue(root, expected, slot, faucet=FAUCET, wallet=WALLET, bind_fee=None):
    root=Path(root).absolute()
    if not isinstance(slot,str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,31}',slot) is None:
        raise ValueError('invitation slot must be a short nonpersonal identifier')
    with locked(root):
        value=checked(root,expected,faucet,wallet)
        if private_json(root/'prepared.json')['plan_sha256']!=expected: raise ValueError('pilot setup not completed')
        policy(root,value,faucet)
        exports=root/'invitations'
        if not os.path.lexists(exports): exports.mkdir(mode=0o700); fsync_dir(root)
        directory(exports)
        state_path=root/'issuance.json'
        state=issuance(root,value)
        checked_exports(root,state)
        if slot not in state['slots']:
            if len(state['slots'])>=value['cohort_size']: raise ValueError('cohort lifetime capacity exhausted')
            state['slots'][slot]={'bind_fee':bind_fee}; atomic(state_path,state)
        if state['slots'][slot]!={'bind_fee':bind_fee}: raise ValueError('invitation binding changed')
        output=exports/(slot+'.json')
        if not os.path.lexists(output):
            # If the native ledger has a committed code without its export, never issue a replacement.
            extra=['--output',output,'--expires-in',value['invitation_ttl_seconds']]
            if bind_fee is not None: extra+=['--bind-fee',bind_fee]
            native(faucet,'invite-issue',root/'faucet',extra)
        # Verify both directions again after the native commit.
        tracked=checked_exports(root,state)
        export=private_json(output,1024);invitation=tracked[export['invite_id']][1]
        return dict(invite_id=export['invite_id'],redeem_by=export['redeem_by'],slot=slot,
                    revoked=invitation['revoked'],redeemed=invitation['member'] is not None,export_written=True,published=False)


def audit(root,expected,faucet=FAUCET,wallet=WALLET):
    root=Path(root).absolute()
    with locked(root):
        value=checked(root,expected,faucet,wallet); claims,info=policy(root,value,faucet)
        receipt=private_json(root/'prepared.json')
        if receipt['plan_sha256']!=expected: raise ValueError('prepared receipt mismatch')
        state=issuance(root,value);checked_exports(root,state)
        return dict(plan_sha256=expected,cohort_size=value['cohort_size'],issued=info.get('issued',0),
                    reserved_claims=len(claims['claims']),budget=value['budget'],
                    funding_verified=False,installed=False,services_started=False,published=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__); commands=parser.add_subparsers(dest='command',required=True)
    p=commands.add_parser('plan');p.add_argument('--source-profile',type=Path,required=True);p.add_argument('--tester-profile',type=Path,required=True)
    p.add_argument('--size',type=int,default=10);p.add_argument('--daily',type=int,default=3);p.add_argument('--rpc-limit',type=int,default=2000);p.add_argument('--ttl',type=int,default=86400);p.add_argument('--output',type=Path,required=True)
    p=commands.add_parser('prepare');p.add_argument('--plan',type=Path,required=True);p.add_argument('--password-file',type=Path,required=True);p.add_argument('--rpc-access-file',type=Path);p.add_argument('--resume',action='store_true')
    for name in ('issue','audit'):
        p=commands.add_parser(name)
        if name=='issue': p.add_argument('--slot',required=True);p.add_argument('--bind-fee')
    for name in ('prepare','issue','audit'):
        p=commands.choices[name];p.add_argument('--root',type=Path,required=True);p.add_argument('--plan-sha256',required=True)
    args=parser.parse_args()
    if args.command=='plan':
        value=plan(decode(read(args.source_profile,8192)),decode(read(args.tester_profile,8192)),args.size,args.daily,args.rpc_limit,args.ttl)
        create(args.output,encode(value));fsync_dir(args.output.parent)
        result=dict(plan_sha256=sha(encode(value)),budget=value['budget'],published=False)
    elif args.command=='prepare':result=prepare(decode(read(args.plan,32768)),args.root,args.plan_sha256,args.password_file,args.resume,rpc_access_file=args.rpc_access_file)
    elif args.command=='issue':result=issue(args.root,args.plan_sha256,args.slot,bind_fee=args.bind_fee)
    else:result=audit(args.root,args.plan_sha256)
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Pilot preparation failed closed. Preserve its plan, keys, invitations and original journals; no automatic reset.')
