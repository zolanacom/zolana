#!/usr/bin/env python3
"""Offline finite LOCAL-060 cohort planning, invitation issuance and audit.

Never initializes a faucet, sends funding, starts a worker, exports a seed or
contacts RPC. Native Rust admission remains authoritative for its ten slots.
"""
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

from explorer_model import public_key
from pilot_cohort import code_bytes
from wallet_release import atomic, create, decode, encode, fsync_dir, read

PREFIX=Path('/opt/zolana-native-058')
BASE_CONFIG=Path('/etc/zolana-native-058/config.json')
ROOT=Path('/var/lib/zolana-native-058/gateway/cohort-060')
ETC=Path('/etc/zolana-native-058/cohort-060')
FAUCET=PREFIX/'bin/native-faucet'
WALLET=PREFIX/'bin/native-wallet'
SLOTS=tuple(f'tester-{index:02}' for index in range(1,11))
MODES={'cohort-060':(39443,39444),'cohort-060-rehearsal':(40443,40444)}
HEX=re.compile('[a-f0-9]{64}')
PLAN_KEYS={'format','network','pool_format','cohort_size','private_grant','gas_grant','attempts','payment_cap',
    'private_budget','public_budget','source_private_address','source_fee_address','source_wallet_sha256',
    'password_sha256','source_profile_sha256','public_profile_sha256','relay_policy_sha256',
    'faucet_policy_sha256','admission_policy_sha256'}


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def hash_value(value):return hashlib.sha256(canonical(value)).hexdigest()
def raw_hash(value):return hashlib.sha256(value).hexdigest()
def bounded(value,low,high):return type(value) is int and low<=value<=high


def mode(root):
    if Path(root).name not in MODES:raise ValueError('only the named pilot or rehearsal cohort is supported')
    return MODES[Path(root).name]


def directory(path):
    path=Path(path);meta=path.lstat()
    if path.resolve()!=path or not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o700:
        raise ValueError('real current-owner mode700 cohort directory required')
    for parent in path.parents:
        item=parent.lstat()
        if (not stat.S_ISDIR(item.st_mode) or parent.resolve()!=parent or item.st_uid not in (0,os.getuid())
                or item.st_mode&0o022 and not (item.st_uid==0 and item.st_mode&stat.S_ISVTX)):
            raise ValueError('cohort ancestors are mutable or substituted')


def public_json(path,maximum=65536):
    path=Path(path)
    if path.resolve()!=path:raise ValueError('public template must be a real path')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as source:
        meta=os.fstat(source.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid not in (0,os.getuid()) or meta.st_mode&0o022
                or not 1<=meta.st_size<=maximum):raise ValueError('unsafe public template')
        raw=source.read(maximum+1)
        if len(raw)!=meta.st_size:raise ValueError('template changed during read')
    return decode(raw)


def private_json(path,maximum=1024*1024):return decode(read(Path(path),maximum,secret=True))


def loopback(value,http=False):
    prefix='http://127.0.0.1:' if http else '127.0.0.1:'
    if not isinstance(value,str) or not value.startswith(prefix):raise ValueError('literal private loopback endpoint required')
    tail=value[len(prefix):]
    if not tail.isascii() or not tail.isdecimal() or str(int(tail))!=tail or not 1<=int(tail)<=65535:
        raise ValueError('invalid private loopback endpoint')


def profile_matches(current,template,mutable=False):
    baseline=json.loads(canonical(current))
    if mutable:
        loopback(baseline['rpc']['url'],True)
        baseline['rpc']['url']=template['rpc']['url']
    if baseline!=template:raise ValueError('cohort profile changed outside its pinned operator endpoint')


def native(binary,command,root=None,extra=(),password=None):
    if command not in ('address','access-info','invite-issue'):raise ValueError('only offline native identity/admission commands are permitted')
    code_bytes(binary,512*1024*1024)
    args=[str(Path(binary).resolve()),command]
    if root is not None:args+=['--root',str(root)]
    result=subprocess.run([*args,*map(str,extra)],input=password,capture_output=True,timeout=40)
    if result.returncode:raise ValueError('native '+command+' failed; preserve original cohort files')
    if len(result.stdout)>65536:raise ValueError('bounded native result required')
    return decode(result.stdout)


def validate_plan(value):
    if (not isinstance(value,dict) or set(value)!=PLAN_KEYS or value['format']!='zolana-native-cohort-plan-v1'
            or value['pool_format']!='NPOOL004' or type(value['cohort_size']) is not int or value['cohort_size']!=10
            or any(type(value[key]) is not int or value[key]!=expected for key,expected in {
                'private_grant':20_000_000,'gas_grant':0,'attempts':3,'payment_cap':150_000_000,
                'private_budget':200_000_000,'public_budget':4_500_000_000}.items())
            or not public_key(value.get('source_fee_address')) or not isinstance(value.get('source_private_address'),str)
            or not 80<=len(value['source_private_address'])<=140
            or re.fullmatch('npriv1[1-9A-HJ-NP-Za-km-z]+',value['source_private_address']) is None):
        raise ValueError('exact finite native cohort plan required')
    network=value['network']
    if (not isinstance(network,dict) or set(network)!={'network','genesis_hash'}
            or not isinstance(network['network'],list) or len(network['network'])!=32 or not any(network['network'])
            or any(type(byte) is not int or not 0<=byte<=255 for byte in network['network'])
            or not public_key(network['genesis_hash'])):raise ValueError('invalid explicit original network')
    for key in PLAN_KEYS:
        if key.endswith('_sha256') and (not isinstance(value[key],str) or HEX.fullmatch(value[key]) is None):
            raise ValueError('exact cohort pin missing')
    return value


def inspect(root=ROOT,templates=ETC,password_file=None,base_config=BASE_CONFIG,faucet=FAUCET):
    root=Path(root).absolute();templates=Path(templates).absolute();rpc_port,faucet_port=mode(root)
    directory(root);directory(root/'faucet');directory(root/'relay')
    password_file=Path(password_file) if password_file is not None else root/'password'
    if password_file!=root/'password':raise ValueError('password must remain in its separate fixed cohort root')
    password=read(password_file,1024,secret=True)
    if not 12<=len(password)<=1024:raise ValueError('bounded private cohort password required')
    wallet_raw=read(root/'faucet/wallet.enc.json',65536,secret=True)
    source=public_json(templates/'source-profile.json');public=public_json(templates/'public-profile.json')
    operator=public_json(templates/'operator.json');relay=public_json(templates/'relay.json')
    network=public_json(base_config)['network']
    identity=('network','genesis_hash','program','pool','pool_format','recipient_withdrawals')
    if (source.get('format')!='native-wallet-profile-v1' or source.get('key_mode')!='user-wallet-v1'
            or source.get('pool_format')!='NPOOL004' or source.get('invite_required',False)
            or source.get('private_send_transport') is not None or source.get('faucet') is not None
            or source.get('rpc',{}).get('transport')!='loopback-http'
            or {key:source.get(key) for key in ('network','genesis_hash')}!=network
            or not public_key(source.get('program')) or not public_key(source.get('pool'))
            or public.get('format')!='native-wallet-profile-v1' or public.get('key_mode')!='user-wallet-v1'
            or any(public.get(key)!=source.get(key) for key in identity)
            or public.get('invite_required') is not True or public.get('private_send_transport')!='native-inline-v1'
            or public.get('rpc')!={'transport':'https','url':f'https://127.0.0.1:{rpc_port}'}
            or public.get('faucet')!={'transport':'https','url':f'https://127.0.0.1:{faucet_port}'}) or not public.get('local_tls_ca_pem'):
        raise ValueError('separate exact V4 source and fixed invited TLS profiles required')
    loopback(source['rpc']['url'],True)
    if any(operator.get(key)!=source[key] for key in identity):raise ValueError('operator identity differs from cohort profiles')
    for relative,template,mutable in [('source.json',source,True),('faucet/profile.json',source,True),
            ('public-profile.json',public,False),('operator.json',operator,False)]:
        profile_matches(private_json(root/relative,65536),template,mutable)
    expected={'network':network,'network_file':str(root/'operator.json'),'native_profile':str(root/'public-profile.json'),
        'payer_file':str(root.parent/'relay.key'),'binary':str(PREFIX/'bin/native-shielded'),
        'fee':3_000_000,'gross_cap':100_000,'max_jobs':60,'per_member':6,'pool_format':'NPOOL004'}
    if relay.get('format')!='native-shielded-relay-v1' or any(relay.get(key)!=value for key,value in expected.items()):
        raise ValueError('reviewed fixed native relay policy required')
    loopback(relay['rpc'],True)
    current_relay=private_json(root/'relay/config.json',65536)
    for value in (relay,current_relay):
        addresses=value.get('native_ingress')
        if not isinstance(addresses,list) or not 1<=len(addresses)<=3 or len(set(addresses))!=len(addresses):
            raise ValueError('bounded unique private native endpoints required')
        for address in addresses:loopback(address)
        loopback(value['rpc'],True)
    comparable=json.loads(canonical(current_relay));comparable['rpc']=relay['rpc'];comparable['native_ingress']=relay['native_ingress']
    if comparable!=relay:raise ValueError('relay changed outside reviewed runtime endpoint fields')
    claims=private_json(root/'faucet/claims.json');admission=private_json(root/'faucet/admission.json')
    p=claims['policy'];a=admission['policy']
    required={'format':'native-test-faucet-native-v1','network':network,'max_claims':10,'invite_required':True,
        'private_amount':20_000_000,'gas_amount':0,'max_attempts':3,'payment_cap':150_000_000}
    if (any(p.get(key)!=value or type(p.get(key)) is not type(value) for key,value in required.items())
            or not public_key(p.get('source_fee_address')) or not isinstance(p.get('source_private_address'),str)
            or re.fullmatch('npriv1[1-9A-HJ-NP-Za-km-z]{74,134}',p['source_private_address']) is None
            or p.get('operator_rpc',False) is not False or p.get('operator_unix',False) is not False
            or not isinstance(claims.get('claims'),list) or len(claims['claims'])>10):
        raise ValueError('authoritative native claims policy differs from reviewed ten-slot budget')
    if (a.get('format')!='native-invited-testnet-v1' or a.get('network')!=network
            or type(a.get('max_invites')) is not int or a['max_invites']!=10
            or type(a.get('daily_admissions')) is not int or a['daily_admissions']!=10
            or not bounded(a.get('rpc_per_minute'),1,10000) or a.get('rpc_audience')!=public['rpc']['url']
            or a.get('faucet_audience')!=public['faucet']['url']
            or not isinstance(admission.get('invitations'),list) or len(admission['invitations'])>10):
        raise ValueError('authoritative admission capacity or fixed audience changed')
    info=native(faucet,'access-info',root/'faucet')
    if (info.get('invite_required') is not True or info.get('network')!=network or info.get('max_invites')!=10
            or info.get('issued')!=len(admission['invitations']) or info.get('rpc_audience')!=a['rpc_audience']
            or info.get('faucet_audience')!=a['faucet_audience']):raise ValueError('native admission validation disagrees with original state')
    plan=validate_plan(dict(format='zolana-native-cohort-plan-v1',network=network,pool_format='NPOOL004',cohort_size=10,
        private_grant=20_000_000,gas_grant=0,attempts=3,payment_cap=150_000_000,private_budget=200_000_000,
        public_budget=4_500_000_000,source_private_address=p['source_private_address'],source_fee_address=p['source_fee_address'],
        source_wallet_sha256=raw_hash(wallet_raw),password_sha256=raw_hash(password),source_profile_sha256=hash_value(source),
        public_profile_sha256=hash_value(public),relay_policy_sha256=hash_value(relay),faucet_policy_sha256=hash_value(p),admission_policy_sha256=hash_value(a)))
    return plan,claims,admission,info


def build_plan(root=ROOT,templates=ETC,password_file=None,*,base_config=BASE_CONFIG,faucet=FAUCET,wallet=WALLET):
    root=Path(root).absolute();plan,claims,admission,_=inspect(root,templates,password_file,base_config,faucet)
    if claims['claims'] or admission['invitations']:raise ValueError('planning requires fresh unused native capacity; never reset existing state')
    addresses=native(wallet,'address',extra=['--network',root/'source.json','--wallet',root/'faucet/wallet.enc.json',
        '--password-file','-'],password=read(root/'password',1024,secret=True))
    if addresses.get('address')!=plan['source_private_address'] or addresses.get('fee_address')!=plan['source_fee_address']:
        raise ValueError('encrypted source wallet differs from authoritative policy')
    return plan


def checked(root,expected,templates=ETC,*,base_config=BASE_CONFIG,faucet=FAUCET):
    if not isinstance(expected,str) or HEX.fullmatch(expected) is None:raise ValueError('explicit reviewed plan hash required')
    sealed=validate_plan(public_json(Path(templates)/'plan.json'))
    if hash_value(sealed)!=expected:raise ValueError('sealed native plan hash changed')
    current,claims,admission,info=inspect(root,templates,None,base_config,faucet)
    if current!=sealed:raise ValueError('native cohort source, policies or private root pins changed')
    return sealed,claims,admission,info


@contextmanager
def locked(root):
    root=Path(root).absolute();directory(root)
    descriptor=os.open(root/'issuance.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        meta=os.fstat(descriptor)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_size:
            raise ValueError('invalid private cohort issuance lock')
        fcntl.flock(descriptor,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(descriptor)


def initialize_issuance(root,expected,templates=ETC,*,base_config=BASE_CONFIG,faucet=FAUCET):
    root=Path(root).absolute()
    with locked(root):
        _,claims,admission,_=checked(root,expected,templates,base_config=base_config,faucet=faucet)
        marker=root/'issuance-pin.json';journal=root/'issuance.json'
        pin=dict(format='zolana-native-cohort-issuance-pin-v1',plan_sha256=expected)
        if os.path.lexists(marker):
            if private_json(marker)!=pin or not os.path.lexists(journal):raise ValueError('issuance journal missing or changed; never recreate capacity')
            issuance(root,expected);return pin
        if os.path.lexists(journal) or claims['claims'] or admission['invitations'] or os.path.lexists(root/'invitations'):
            raise ValueError('issuance initialization requires fresh unused native state')
        create(marker,encode(pin));fsync_dir(root)
        create(journal,encode(dict(format='zolana-native-cohort-issuance-v1',plan_sha256=expected,slots={})));fsync_dir(root)
        return pin


def issuance(root,expected):
    pin=private_json(root/'issuance-pin.json')
    if pin!=dict(format='zolana-native-cohort-issuance-pin-v1',plan_sha256=expected):raise ValueError('original issuance pin changed')
    state=private_json(root/'issuance.json')
    if (not isinstance(state,dict) or set(state)!={'format','plan_sha256','slots'}
            or state['format']!='zolana-native-cohort-issuance-v1' or state['plan_sha256']!=expected
            or not isinstance(state['slots'],dict) or len(state['slots'])>10):raise ValueError('invalid original named-slot journal')
    for slot,item in state['slots'].items():
        if slot not in SLOTS or not isinstance(item,dict) or set(item)!={'bind_fee'} or item['bind_fee'] is not None and not public_key(item['bind_fee']):
            raise ValueError('named cohort slot or binding changed')
    return state


def exports(root,state,admission):
    native_invites=admission['invitations'];known={item['id']:item for item in native_invites}
    if len(known)!=len(native_invites):raise ValueError('duplicate native invitation')
    tracked={};folder=root/'invitations'
    if os.path.lexists(folder):
        directory(folder)
        for path in folder.iterdir():
            if path.suffix!='.json' or path.stem not in state['slots']:raise ValueError('untracked invitation export; preserve original state')
            value=private_json(path,1024)
            if (not isinstance(value,dict) or set(value)!={'invitation','invite_id','redeem_by'}
                    or not isinstance(value['invitation'],str) or re.fullmatch('invite1_[A-Za-z0-9_-]{43}',value['invitation']) is None
                    or not bounded(value['redeem_by'],1,2**64-1)):
                raise ValueError('invalid original invitation export')
            digest=hashlib.blake2b(value['invitation'].encode(),digest_size=32).hexdigest();item=known.get(digest)
            if (value['invite_id']!=digest or item is None or digest in tracked or item['redeem_by']!=value['redeem_by']
                    or item.get('bound_fee')!=state['slots'][path.stem]['bind_fee']):
                raise ValueError('invitation export/commit/binding mismatch; never replace it')
            tracked[digest]=(path.stem,item)
    if set(tracked)!=set(known):raise ValueError('committed native invitation export missing; never reissue its slot')
    return tracked


def issue(root,expected,slot,bind_fee=None,templates=ETC,*,base_config=BASE_CONFIG,faucet=FAUCET,ttl=86400):
    root=Path(root).absolute()
    if slot not in SLOTS or bind_fee is not None and not public_key(bind_fee) or not bounded(ttl,1,604800):
        raise ValueError('one of the ten named slots, valid binding and bounded TTL required')
    with locked(root):
        _,_,admission,_=checked(root,expected,templates,base_config=base_config,faucet=faucet)
        state=issuance(root,expected);exports(root,state,admission)
        if slot not in state['slots']:
            state['slots'][slot]=dict(bind_fee=bind_fee);atomic(root/'issuance.json',state)
        if state['slots'][slot]!=dict(bind_fee=bind_fee):raise ValueError('reserved slot binding cannot change')
        folder=root/'invitations'
        if not os.path.lexists(folder):folder.mkdir(mode=0o700);fsync_dir(root)
        output=folder/(slot+'.json')
        if not os.path.lexists(output):
            extra=['--output',output,'--expires-in',ttl]
            if bind_fee is not None:extra+=['--bind-fee',bind_fee]
            native(faucet,'invite-issue',root/'faucet',extra)
        _,_,admission,_=checked(root,expected,templates,base_config=base_config,faucet=faucet)
        tracked=exports(root,state,admission);value=private_json(output,1024);item=tracked[value['invite_id']][1]
        return dict(slot=slot,invite_id=value['invite_id'],redeem_by=value['redeem_by'],
            revoked=item['revoked'],redeemed=item['member'] is not None,export_written=True,published=False)


def progress_counts(root,claims):
    counts=dict(queued=0,funding=0,ready=0,needs_attention=0)
    for claim in claims['claims']:
        claim_id=hashlib.blake2b(claim['fee_address'].encode(),digest_size=32).hexdigest()
        value=private_json(root/'faucet'/(claim_id+'.json'),128*1024)
        required={'gas_attempts','gas','gas_done','private_attempts','proof','private_done'}
        if (not isinstance(value,dict) or not required<=set(value) or set(value)-required-{'submission_started'}
                or type(value['gas_attempts']) is not int or value['gas_attempts']!=0 or value['gas'] is not None
                or type(value['gas_done']) is not bool or type(value['private_done']) is not bool
                or type(value.get('submission_started',False)) is not bool or not bounded(value['private_attempts'],0,3)):
            raise ValueError('native claim progress is corrupt; never recreate or refund it')
        proof=value['proof']
        if proof is not None and (not isinstance(proof,list) or len(proof)!=9222
                or any(type(byte) is not int or not 0<=byte<=255 for byte in proof)):
            raise ValueError('original native grant proof is malformed')
        if not value['gas_done'] and (value['private_attempts'] or proof is not None
                or value['private_done'] or value.get('submission_started',False)):
            raise ValueError('private grant progress lacks its durable no-gas phase marker')
        state=('ready' if value['private_done'] else 'needs_attention' if value['private_attempts']==3 and proof is None
               else 'funding' if value['private_attempts'] else 'queued')
        counts[state]+=1
    return counts


def audit(root=ROOT,expected=None,templates=ETC,*,base_config=BASE_CONFIG,faucet=FAUCET):
    root=Path(root).absolute()
    with locked(root):
        plan,claims,admission,info=checked(root,expected,templates,base_config=base_config,faucet=faucet)
        state=issuance(root,expected);exports(root,state,admission)
        counts=progress_counts(root,claims)
        return dict(format='zolana-native-cohort-audit-v1',plan_sha256=expected,cohort_size=10,
            reserved_slots=len(state['slots']),issued=info['issued'],reserved_claims=len(claims['claims']),
            claim_states=counts,progress_source='durable-faucet-journals',canonical_execution_rechecked=False,
            private_budget=plan['private_budget'],public_budget=plan['public_budget'],gas_grant=0,
            funding_verified=False,network_verified=False,services_started=False,transfers_submitted=0,published=False)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('plan','initialize-issuance','issue','audit'))
    parser.add_argument('--rehearsal',action='store_true');parser.add_argument('--plan-sha256')
    parser.add_argument('--slot',choices=SLOTS);parser.add_argument('--bind-fee');parser.add_argument('--ttl',type=int,default=86400)
    args=parser.parse_args();suffix='-rehearsal' if args.rehearsal else ''
    root=ROOT.with_name(ROOT.name+suffix);templates=ETC.with_name(ETC.name+suffix)
    if args.command=='plan':value=build_plan(root,templates)
    else:
        if args.plan_sha256 is None:parser.error('explicit reviewed plan-sha256 required')
        if args.command=='initialize-issuance':value=initialize_issuance(root,args.plan_sha256,templates)
        elif args.command=='audit':value=audit(root,args.plan_sha256,templates)
        else:
            if args.slot is None:parser.error('one fixed slot required')
            value=issue(root,args.plan_sha256,args.slot,args.bind_fee,templates,ttl=args.ttl)
    print(json.dumps(value,sort_keys=True))


if __name__=='__main__':main()
