#!/usr/bin/env python3
"""Finite LOCAL-060 cohort service; attaches to original sealed validator only.

No provisioning, key generation, funding, invitation issuance or automatic refill
is performed by this entrypoint. The original LOCAL-058 faucet is never started
as a funding worker or reinterpreted as this separate finite cohort.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading
import time

PREFIX=Path('/opt/zolana-native-058')
ETC=Path('/etc/zolana-native-058/cohort-060')
ROOT=Path('/var/lib/zolana-native-058/gateway/cohort-060')
PORTS={'rpc':39443,'faucet':39444}
UNIT='zolana-native-060-gateway.service'
SOCKETS={name:'zolana-native-060-'+name+'.socket' for name in PORTS}
VALUNIT='zolana-native-058-validator.service'
HEX=re.compile('[a-f0-9]{64}')


def fixed_mode(rehearsal=False):
    if type(rehearsal) is not bool:raise ValueError('only the two fixed cohort modes are allowed')
    suffix='cohort-060-rehearsal' if rehearsal else 'cohort-060'
    name='zolana-native-060-rehearsal' if rehearsal else 'zolana-native-060'
    ports={'rpc':40443,'faucet':40444} if rehearsal else {'rpc':39443,'faucet':39444}
    return dict(root=Path('/var/lib/zolana-native-058/gateway')/suffix,
        etc=Path('/etc/zolana-native-058')/suffix,ports=ports,unit=name+'-gateway.service',
        sockets={role:name+'-'+role+'.socket' for role in ports})


def select_mode(rehearsal=False):
    global ROOT,ETC,PORTS,UNIT,SOCKETS
    mode=fixed_mode(rehearsal)
    ROOT,ETC,PORTS,UNIT,SOCKETS=(mode[k] for k in ('root','etc','ports','unit','sockets'))


def audience(name):return 'https://127.0.0.1:'+str(PORTS[name])


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def digest(raw):return hashlib.sha256(raw).hexdigest()

def hash_value(value):
    """Canonical sorted compact JSON SHA-256, with no trailing newline."""
    return digest(encode(value))


def load_base():
    # Python -I excludes siblings/PYTHONPATH. Load only the immutable fixed base
    # entrypoint; its complete bundle/config verification precedes other imports.
    path=PREFIX/'tools/native_linux_service.py'
    for ancestor in path.parents:
        meta=ancestor.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022 or ancestor.resolve()!=ancestor:
            raise ValueError('base runtime requires immutable real root-owned ancestors')
    meta=path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=0o444:
        raise ValueError('base runtime is not sealed root-owned code')
    spec=importlib.util.spec_from_file_location('zolana_sealed_base',path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    config,config_sha256=module.load_config()
    sys.path.insert(0,str(PREFIX/'tools'))
    return module,config,config_sha256


def units(rehearsal=False):
    mode=fixed_mode(rehearsal);sockets=' '.join(mode['sockets'].values())
    unit='''[Unit]
Description=Zolana LOCAL-060 finite native cohort gateway
Requires={validator}
Requires={sockets}
After={validator} {sockets}
BindsTo={validator}
PartOf={validator}
JoinsNamespaceOf={validator}
[Service]
Type=notify
NotifyAccess=main
User=zolana058g
Group=zolana058g
SupplementaryGroups=zolana058link
WorkingDirectory={prefix}
ExecStart=/usr/bin/python3 -I -B {prefix}/tools/native_cohort_service.py gateway{modeflag}
Sockets={sockets}
ReadWritePaths={root}
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
TemporaryFileSystem=/dev/shm:rw,nodev,nosuid,mode=1777
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
PrivateNetwork=yes
LimitNOFILE=1048576
LimitCORE=0
Nice=15
KillMode=control-group
TimeoutStartSec=240
TimeoutStopSec=90
Restart=on-failure
RestartSec=10s
[Install]
WantedBy=multi-user.target
'''.format(validator=VALUNIT,sockets=sockets,prefix=PREFIX,root=mode['root'],modeflag=' --rehearsal' if rehearsal else '')
    output={mode['unit']:unit}
    for name,port in mode['ports'].items():
        output[mode['sockets'][name]]=('''[Unit]
Description=Zolana LOCAL-060 {name} host TLS socket
[Socket]
ListenStream=127.0.0.1:{port}
FileDescriptorName={name}
Service={unit}
Accept=no
NoDelay=true
Backlog=8
[Install]
WantedBy=sockets.target
'''.format(name=name,port=port,unit=mode['unit']))
    return output


PLAN_KEYS={'format','network','pool_format','cohort_size','private_grant','gas_grant','attempts','payment_cap',
    'private_budget','public_budget','source_private_address','source_fee_address','source_wallet_sha256',
    'password_sha256','source_profile_sha256','public_profile_sha256','relay_policy_sha256',
    'faucet_policy_sha256','admission_policy_sha256'}
FUNDING_KEYS={'format','plan_sha256','network','source_private_address','source_fee_address','private_observed',
    'public_observed','finalized_slot','checked_at','canonical_funding'}
BINDING_KEYS={'format','base_config_sha256','plan_sha256','funding_ready_sha256'}
# This entrypoint imports no sibling before the sealed base; both values repeat
# the offline planner's native_pilot_cohort constants.
MAX_COHORT_SIZE=500
RELAY_MEMBER_JOBS=6


def validate_plan(value,config,base):
    size=value.get('cohort_size') if isinstance(value,dict) else None
    if type(size) is not int or not 1<=size<=MAX_COHORT_SIZE:raise ValueError('finite native cohort size must be an integer from 1 to 500')
    fixed=dict(format='zolana-native-cohort-plan-v1',network=config['network'],pool_format='NPOOL004',
        cohort_size=size,private_grant=20_000_000,gas_grant=0,attempts=3,payment_cap=150_000_000,
        private_budget=size*20_000_000,public_budget=size*3*150_000_000)
    if set(value)!=PLAN_KEYS or any(value.get(k)!=v or type(value[k]) is not type(v) for k,v in fixed.items()):
        raise ValueError('exact finite native cohort plan required')
    for name in PLAN_KEYS:
        if name.endswith('_sha256') and (not isinstance(value[name],str) or HEX.fullmatch(value[name]) is None):
            raise ValueError('plan requires every immutable authority/profile/policy digest')
    base.public_key(value['source_fee_address'])
    address=value['source_private_address']
    if not isinstance(address,str) or not 80<=len(address)<=140 or re.fullmatch(r'npriv1[1-9A-HJ-NP-Za-km-z]+',address) is None:
        raise ValueError('explicit original private funding authority required')
    return value


def validate_funding(value,plan,first,now):
    if (not isinstance(value,dict) or set(value)!=FUNDING_KEYS or value['format']!='zolana-native-cohort-funding-ready-v1' or
            value['plan_sha256']!=hash_value(plan) or value['network']!=plan['network'] or value['canonical_funding'] is not True or
            any(value[k]!=plan[k] for k in ('source_private_address','source_fee_address')) or
            any(type(value[k]) is not int or not 0<=value[k]<=2**64-1 for k in ('private_observed','public_observed','finalized_slot','checked_at')) or
            value['finalized_slot']==0 or value['checked_at']==0 or value['checked_at']>now or
            value['private_observed']<plan['private_budget'] or value['public_observed']<plan['public_budget']):
        raise ValueError('root-sealed canonical funding receipt does not cover this exact authority and budget')
    if first and now-value['checked_at']>3600:raise ValueError('first activation requires funding evidence at most one hour old')


def validate_binding(value,plan,funding,config_sha256):
    if (not isinstance(value,dict) or set(value)!=BINDING_KEYS or value['format']!='zolana-native-cohort-service-v1' or
            value['base_config_sha256']!=config_sha256 or value['plan_sha256']!=hash_value(plan) or
            value['funding_ready_sha256']!=hash_value(funding)):
        raise ValueError('cohort binding changed its original sealed base, plan or funding evidence')
    return value


def load_binding(base,config,config_sha256):
    binding=json.loads(base.sealed(ETC/'binding.json'))
    plan=validate_plan(json.loads(base.sealed(ETC/'plan.json')),config,base)
    funding=json.loads(base.sealed(ETC/'funding-ready.json'))
    validate_binding(binding,plan,funding,config_sha256)
    return binding,plan,funding


def authority(base,config,plan):
    uid=config['gateway_uid'];size=plan['cohort_size'];base.real_directory(ROOT,uid,0o700)
    for folder in ('faucet','relay'):base.real_directory(ROOT/folder,uid,0o700)
    wallet=base.owned(ROOT/'faucet/wallet.enc.json',uid,4096)
    password=base.owned(ROOT/'password',uid,1024)
    if digest(wallet)!=plan['source_wallet_sha256'] or digest(password)!=plan['password_sha256'] or len(password)<12:
        raise ValueError('original cohort funding wallet or password changed')
    claims=json.loads(base.owned(ROOT/'faucet/claims.json',uid,1024*1024))
    admission=json.loads(base.owned(ROOT/'faucet/admission.json',uid,1024*1024))
    policy=claims.get('policy');access=admission.get('policy')
    if not isinstance(policy,dict) or not isinstance(access,dict):raise ValueError('cohort native policies missing')
    expected=dict(format='native-test-faucet-native-v1',network=plan['network'],source_fee_address=plan['source_fee_address'],
        source_private_address=plan['source_private_address'],max_claims=size,invite_required=True,
        private_amount=20_000_000,gas_amount=0,max_attempts=3,payment_cap=150_000_000)
    if (any(policy.get(k)!=v or type(policy.get(k)) is not type(v) for k,v in expected.items()) or policy.get('operator_rpc',False) is not False or
            policy.get('operator_unix',False) is not False or hash_value(policy)!=plan['faucet_policy_sha256']):
        raise ValueError('native grant policy differs from root-approved finite authority')
    expected=dict(format='native-invited-testnet-v1',network=plan['network'],max_invites=size,
        rpc_audience=audience('rpc'),faucet_audience=audience('faucet'))
    if (any(access.get(k)!=v for k,v in expected.items()) or hash_value(access)!=plan['admission_policy_sha256'] or
            type(access['max_invites']) is not int or
            type(access.get('daily_admissions')) is not int or not 1<=access['daily_admissions']<=size or
            type(access.get('rpc_per_minute')) is not int or not 1<=access['rpc_per_minute']<=10000 or
            not isinstance(claims.get('claims'),list) or len(claims['claims'])>size or
            not isinstance(admission.get('invitations'),list) or len(admission['invitations'])>size):
        raise ValueError('native cohort admission authority or lifetime capacity changed')
    return claims


def activate(base,config,binding,plan,funding,claims,now):
    path=ROOT/'activation.json';uid=config['gateway_uid']
    expected=dict(format='zolana-native-cohort-activation-v1',binding_sha256=hash_value(binding),plan_sha256=hash_value(plan),
        funding_ready_sha256=hash_value(funding),network=plan['network'],source_wallet_sha256=plan['source_wallet_sha256'])
    first=not os.path.lexists(path)
    validate_funding(funding,plan,first,now)
    if first:
        if claims['claims']:raise ValueError('first activation requires unused claims; existing grants must never be reinitialized')
        expected['activated_at']=now;base.atomic(path,expected)
    else:
        value=json.loads(base.owned(path,uid))
        if (set(value)!=set(expected)|{'activated_at'} or any(value.get(k)!=v for k,v in expected.items()) or
                type(value['activated_at']) is not int or not 0<value['activated_at']<=now):
            raise ValueError('original cohort activation binding changed or clock regressed')
    return expected if first else value


def prepare(base,config,plan,ready):
    uid=config['gateway_uid'];upstream=ready['peers'][0]['rpc'];rpc='http://'+upstream;gate=None
    source=json.loads(base.sealed(ETC/'source-profile.json'))
    public=json.loads(base.sealed(ETC/'public-profile.json'))
    operator=json.loads(base.sealed(ETC/'operator.json'))
    relay=json.loads(base.sealed(ETC/'relay.json'))
    for name,value in (('source_profile_sha256',source),('public_profile_sha256',public),('relay_policy_sha256',relay)):
        if hash_value(value)!=plan[name]:raise ValueError('sealed cohort template differs from its original plan')
    identity=('network','genesis_hash','program','pool','pool_format','recipient_withdrawals')
    if (source.get('pool_format')!='NPOOL004' or source.get('rpc',{}).get('transport')!='loopback-http' or
            source.get('invite_required',False) or source.get('private_send_transport') is not None or
            any(source.get(k)!=plan['network'][k] for k in ('network','genesis_hash')) or
            any(value.get(k)!=source.get(k) for value in (public,operator) for k in identity) or
            public.get('private_send_transport')!='native-inline-v1' or public.get('invite_required') is not True or
            public.get('rpc')!={'transport':'https','url':audience('rpc')} or
            public.get('faucet')!={'transport':'https','url':audience('faucet')}):
        raise ValueError('cohort profiles substituted the original V4 network or separate invited TLS audiences')
    for name in ('public-profile.json','operator.json'):
        if base.owned(ROOT/name,uid,32768)!=base.sealed(ETC/name,32768):raise ValueError('owned cohort profile copy differs from sealed template')
    if base.owned(base.GWROOT/'server.crt',uid,32768)!=base.sealed(base.ETC/'server.crt',32768):raise ValueError('original TLS certificate changed')
    base.owned(base.GWROOT/'server.key',uid,32768)
    key=json.loads(base.owned(base.GWROOT/'relay.key',uid,4096))
    if (not isinstance(key,list) or len(key)!=64 or any(type(x) is not int or not 0<=x<=255 for x in key) or
            base.b58(bytes(key[32:]))!=config['relay_public_key'] or relay.get('payer')!=key[32:]):
        raise ValueError('cohort relay substituted the original public payer')
    paths=dict(binary=str(PREFIX/'bin/native-shielded'),payer_file=str(base.GWROOT/'relay.key'),
        network_file=str(ROOT/'operator.json'),native_profile=str(ROOT/'public-profile.json'))
    if (relay.get('network')!=plan['network'] or relay.get('pool_format')!='NPOOL004' or
            any(relay.get(k)!=v for k,v in paths.items()) or relay.get('fee')!=3_000_000 or
            relay.get('gross_cap')!=100_000 or relay.get('max_jobs')!=RELAY_MEMBER_JOBS*plan['cohort_size'] or
            relay.get('per_member')!=RELAY_MEMBER_JOBS):
        raise ValueError('cohort relay paths, native transport or finite budget changed')
    try:
        if config['test_mode']:
            from native_cohort_fault import GrantRpcGate
            gate=GrantRpcGate(upstream,plan['network'],uid,rehearsal=ROOT.name=='cohort-060-rehearsal',
                cohort_size=plan['cohort_size']);rpc='http://'+gate.endpoint
        for path in (ROOT/'source.json',ROOT/'faucet/profile.json'):
            current=json.loads(base.owned(path,uid));base.atomic(path,base.endpoint_update(current,source,{'rpc.url':rpc}))
        path=ROOT/'relay/config.json';current=json.loads(base.owned(path,uid))
        base.atomic(path,base.endpoint_update(current,relay,{'rpc':rpc,'native_ingress':[p['native_ingress'] for p in ready['peers']]}))
        return gate,rpc
    except BaseException:
        if gate:gate.close()
        raise


# A tick that has a grant to pay replays every finalized block since the source
# wallet's cached scan before it can build the proof, inside its time limit; the
# cache is written only when a scan completes, so a tick killed there keeps no
# progress. Idle ticks read no blocks, so the same worker keeps that cache
# current between grants; otherwise the first grant after a long quiet period
# could overrun the limit, which stops the gateway.
GRANT_TICK_LIMIT=180
SOURCE_REFRESH_SECONDS=300
SOURCE_REFRESH_LIMIT=3600
# Relay children that may run side by side (1..shielded_relay.MAX_WORKERS). One
# keeps the serial worker. More than one shares the private RPC and this
# unit's CPU allowance with the grant tick and its time limit, so raise it only
# after that load has been measured on the host.
RELAY_WORKERS=1


def idle_tick(output):
    try:value=json.loads(output)
    except (TypeError,ValueError):return False
    return isinstance(value,dict) and value.get('idle') is True


def paid_tick(output):
    """A tick that ended by completing a grant; another wallet may be queued behind it."""
    try:value=json.loads(output)
    except (TypeError,ValueError):return False
    return isinstance(value,dict) and value.get('state')=='ready' and value.get('private_finalized') is True


def supervised_faucet(parent):
    class CohortFaucet(parent):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs);self.failed=threading.Event();self.refreshed=None;self.refresh_failed=None
        def refresh(self):
            """Bring the source wallet's scan cache to the finalized tip; pays nothing.

            Called only by the grant worker after an idle tick, so it never runs
            beside a tick and never while a grant is unfinished. It counts no
            attempt and touches no claim. A failure or overrun is reported and
            retried after the interval; it never stops the gateway.
            """
            import subprocess
            if self.refreshed is not None and time.monotonic()-self.refreshed<SOURCE_REFRESH_SECONDS:return
            started=time.monotonic();child=None
            try:
                with self.child_lock:
                    if self.stop.is_set():return
                    self.child=child=subprocess.Popen([str(self.binary.with_name('native-wallet')),'balance',
                        '--network',str(self.root.parent/'source.json'),'--wallet',str(self.root/'wallet.enc.json'),
                        '--password-file','-'],stdin=subprocess.PIPE,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,text=True)
                child.communicate(input=self.password,timeout=SOURCE_REFRESH_LIMIT);failed=child.returncode!=0
            except subprocess.TimeoutExpired:
                child.kill();child.communicate(timeout=10);failed=True
            except OSError:
                failed=True
            finally:
                with self.child_lock:self.child=None
            self.refreshed=time.monotonic()
            if self.stop.is_set():return
            if failed is not self.refresh_failed:
                print(json.dumps(dict(event='cohort_source_refresh_failed' if failed else 'cohort_source_refreshed',
                    seconds=int(self.refreshed-started))),flush=True)
            self.refresh_failed=failed
        def work(self):
            import subprocess
            while not self.stop.is_set():
                with self.child_lock:
                    if self.stop.is_set():return
                    self.child=subprocess.Popen([str(self.binary),'tick','--root',str(self.root),'--password-file','-'],
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    child=self.child
                try:
                    output=child.communicate(input=self.password,timeout=GRANT_TICK_LIMIT)[0]
                    if child.returncode and not self.stop.is_set():self.failed.set();return
                except subprocess.TimeoutExpired:
                    child.kill();child.communicate(timeout=10);self.failed.set();return
                finally:
                    with self.child_lock:self.child=None
                if idle_tick(output):self.refresh()
                # The pause paces idle polling and a claim that makes no
                # progress. After a completed grant the next tick starts at once.
                if not paid_tick(output):self.stop.wait(2)
    return CohortFaucet


def gateway(base,config,config_sha256,ingress=None):
    import fcntl
    inode=base.sandbox(config,'gateway');stop=base.stop_event();uid=config['gateway_uid']
    base.real_directory(ROOT,uid,0o700)
    lock=os.fdopen(os.open(ROOT/'service.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600),'a+b')
    meta=os.fstat(lock.fileno())
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=uid or stat.S_IMODE(meta.st_mode)!=0o600 or meta.st_size:
        lock.close();raise ValueError('cohort service lock must be original empty owner-only file')
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BaseException:lock.close();raise
    streams={};servers=[];threads=[];worker=None;gate=faucet=relay=None
    published=False;generation=None
    try:
        binding,plan,funding=load_binding(base,config,config_sha256)
        claims=authority(base,config,plan)
        deadline=time.monotonic()+180
        while True:
            try:ready=base.read_ready(config,config_sha256,inode);break
            except FileNotFoundError:
                if stop.wait(.1):return
                if time.monotonic()>=deadline:raise TimeoutError('original validator finality readiness missing')
        gate,rpc=prepare(base,config,plan,ready)
        streams=base.activated_sockets(ports=PORTS) if ingress is None else ingress.activated_sockets()
        from test_faucet import Faucet, Handler as FaucetHandler
        from testnet_gateway import Gateway, Handler as GatewayHandler
        from service_tls import listener
        faucet=supervised_faucet(Faucet)(ROOT/'faucet',ROOT/'password',binary=PREFIX/'bin/native-faucet')
        # The sealed native faucet debits every unit of one request in a single
        # locked ledger write (authorize-many); budgets and admission are unchanged.
        app=Gateway(faucet,relay_root=ROOT/'relay',authorize_many=True);relay=app.relay
        if relay is None or relay.native_ingress is None:raise ValueError('cohort native relay required')
        if stop.is_set():return
        activation=activate(base,config,binding,plan,funding,claims,int(time.time()))
        channels={'rpc':(GatewayHandler,app),'faucet':(FaucetHandler,faucet)}
        if ingress is None:
            for name,(handler,current) in channels.items():
                servers.append(listener('https://127.0.0.1:'+str(PORTS[name]),PORTS[name],handler,current,
                    base.GWROOT/'server.crt',base.GWROOT/'server.key',activated_socket=streams[name]))
        else:servers.extend(ingress.listeners(base,channels,streams))
        if stop.is_set():return
        worker=threading.Thread(target=faucet.work,daemon=True);worker.start()
        if RELAY_WORKERS==1:relay.start()
        else:relay.start(RELAY_WORKERS)
        for server in servers:
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();threads.append(thread)
        if stop.is_set():return
        generation=ready['generation']
        ready_state=dict(format='zolana-native-cohort-ready-v1',binding_sha256=hash_value(binding),
            plan_sha256=hash_value(plan),network=plan['network'],namespace_inode=inode,supervisor_pid=os.getpid(),
            validator_generation=generation,private_rpc=ready['peers'][0]['rpc'],effective_rpc=rpc,
            grant_rpc_proxy=None if gate is None else gate.endpoint,mode='rehearsal' if ROOT.name.endswith('-rehearsal') else 'pilot',
            test_mode=config['test_mode'],grant_worker_started=True,relay_worker_started=True,
            activation_sha256=hash_value(activation),ready_at=int(time.time()))
        if ingress is not None:ready_state['public_ingress']=ingress.evidence()
        base.atomic(ROOT/'service-ready.json',ready_state)
        published=True;base.notify('READY=1\nSTATUS=Separate finite native cohort ready')
        while not stop.wait(.25):
            if base.read_ready(config,config_sha256,inode)['generation']!=generation:raise RuntimeError('original validator generation changed')
            if (not worker.is_alive() or faucet.failed.is_set() or any(not t.is_alive() for t in threads) or
                    relay.worker is None or not relay.worker.is_alive() or
                    (gate is not None and not gate.thread.is_alive())):raise RuntimeError('cohort grant, native relay or TLS worker stopped')
    finally:
        failures=[]
        def clean(action):
            try:action()
            except BaseException as error:failures.append(type(error).__name__)
        if published:
            path=ROOT/'service-ready.json'
            def remove_ready():
                try:
                    if json.loads(base.owned(path,uid)).get('supervisor_pid')==os.getpid():path.unlink();base.fsync_dir(ROOT)
                except FileNotFoundError:pass
            clean(remove_ready)
        # Stop/terminate the owned grant child before joining its worker; journals
        # remain untouched and canonical recovery runs on the next original tick.
        if faucet:clean(faucet.close)
        if worker:
            clean(lambda:worker.join(timeout=15))
            if worker.is_alive():failures.append('GrantWorkerDidNotStop')
        if relay:clean(relay.close)
        if gate:clean(gate.close)
        for index,server in enumerate(servers):
            if index<len(threads):clean(server.shutdown)
            clean(server.server_close)
        for thread in threads:clean(lambda thread=thread:thread.join(timeout=5))
        for stream in streams.values():clean(stream.close)
        clean(lock.close)
        if failures:raise RuntimeError('cohort cleanup failed: '+','.join(failures))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('check','gateway','render'));parser.add_argument('--output',type=Path)
    parser.add_argument('--rehearsal',action='store_true',help='use only the separate fixed disposable rehearsal cohort')
    args=parser.parse_args()
    select_mode(args.rehearsal)
    if args.command=='render':
        if args.output is None:parser.error('render requires a fresh output directory')
        args.output.mkdir(mode=0o700)
        for name,value in units(args.rehearsal).items():(args.output/name).write_text(value)
        return
    if sys.platform!='linux':raise ValueError('cohort service requires Linux')
    base,config,config_sha256=load_base()
    if args.command=='check':
        binding,plan,funding=load_binding(base,config,config_sha256);authority(base,config,plan)
        validate_funding(funding,plan,False,int(time.time()))
        print(json.dumps(dict(plan_sha256=hash_value(plan),binding_sha256=hash_value(binding),services_started=0)));return
    gateway(base,config,config_sha256)


if __name__=='__main__':main()
