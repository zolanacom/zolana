#!/usr/bin/env python3
"""Explicit funded-cohort host lifecycle; no key generation, funding or installer."""
import argparse
from contextlib import contextmanager,ExitStack
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import threading
import time

import direct_tls
import pilot_cohort as cohort
import pilot_funding as funding
from wallet_release import atomic,create,decode,encode,fsync_dir,hex64,read,sha
from test_faucet import Faucet

PROJECT=Path(__file__).resolve().parents[1]
FILES=('pilot-runtime.json','pilot-runtime-required.json','pilot-runtime-state.json','pilot-runtime-clock.json')
CODE=('pilot_runtime.py','pilot_cohort.py','pilot_funding.py','wallet_release.py','localnet.py','replay_localnet.py',
      'restart_localnet.py','wallet_localnet.py','rpc_isolation.py','operator_transport.py','service_tls.py',
      'direct_tls.py','test_faucet.py','testnet_gateway.py','gateway_history.py','gateway_archival.py',
      'history_retention.py','history_replica.py')
BINARIES=('native-wallet','native-faucet','native-localnet','agave-validator')


def path(value):
    p=Path(value).absolute()
    if p.resolve()!=p:raise ValueError('runtime paths must be absolute and real')
    return p


def pins():
    return {**{'tools/'+name:sha(cohort.code_bytes(PROJECT/'tools'/name,1024*1024)) for name in CODE},
            **{'target/debug/'+name:sha(cohort.code_bytes(PROJECT/'target/debug'/name,256*1024*1024)) for name in BINARIES}}


def network(root):
    from rpc_isolation import validate
    from localnet import offset
    root=path(root);cohort.directory(root)
    raw=read(root/'network.json',32768,secret=True);value=decode(raw)
    if (value.get('key_mode')!='local-testnet-rehearsal-v1' or value.get('fixture_keys_are_public') is not False or
            value.get('raw_rpc_host_isolation') is not True or value.get('raw_rpc_isolation') is not True):
        raise ValueError('pilot runtime requires original private keys and hardened Unix RPC')
    validate(root,value)
    return value,sha(raw),'http://127.0.0.1:'+str(18899+offset(value))


def original_intent(root,value,claims):
    p=claims['policy'];prepared=cohort.private_json(root/'prepared.json')
    if (prepared['private_address']!=p['source_private_address'] or prepared['fee_address']!=p['source_fee_address']):
        raise ValueError('prepared authority differs')
    expected=dict(format='zolana-pilot-funding-intent-v1',plan_sha256=sha(encode(value)),
                  network=value['source_profile']['network'],genesis_hash=value['source_profile']['genesis_hash'],
                  private_address=p['source_private_address'],fee_address=p['source_fee_address'],
                  encrypted_wallet_sha256=sha(read(root/'faucet/wallet.enc.json',16384,secret=True)),
                  private_units=value['budget']['private_grants'],public_units=value['budget']['conservative_public_units'],
                  automatic_refill=False,transfer_authorized=False)
    if cohort.private_json(root/'funding-intent.json')!=expected:raise ValueError('original funding authority/intent changed')
    return expected


def cohort_check(root,digest,net,rpc,network_root):
    value=cohort.checked(root,digest);claims,info=cohort.policy(root,value)
    cohort.checked_exports(root,cohort.issuance(root,value))
    if (value['source_profile']['rpc']['url']!=rpc or
            any(value['source_profile'][k]!=net[k] for k in ('network','genesis_hash','program','pool','pool_format','recipient_withdrawals')) or
            claims['policy'].get('operator_unix') is not True or
            read(root/'faucet/rpc-access.key',4096,secret=True)!=read(network_root/'rpc-access.key',4096,secret=True)):
        raise ValueError('cohort must use the exact network and original private RPC capability')
    return value,claims,info,original_intent(root,value,claims)


def unused(root,claims,info):
    source=root/'faucet/wallet.enc.json'
    if claims['claims'] or info.get('issued')!=0 or any(os.path.lexists(Path(str(source)+'.'+kind+'.json')) for kind in ('pending','staging')):
        raise ValueError('first activation requires unused cohort and recovered original funding journals')


def prepare(root,cohort_root,digest,check_id,password_file,listeners):
    root,cohort_root,password_file=path(root),path(cohort_root),path(password_file)
    net,network_sha,rpc=network(root)
    if any(os.path.lexists(root/name) for name in (*FILES,'ingress-setup.json')):
        raise ValueError('runtime or legacy ingress already exists; preserve original binding')
    if set(listeners)!={'rpc','faucet'}:raise ValueError('both reviewed HTTPS listeners required')
    with funding.frozen(cohort_root,digest):
        value,claims,info,intent=cohort_check(cohort_root,digest,net,rpc,root)
        receipt_path=cohort_root/'funding-checks'/(check_id+'.json')
        if not isinstance(check_id,str) or re.fullmatch('[a-z0-9][a-z0-9-]{0,31}',check_id) is None:
            raise ValueError('invalid funding check ID')
        receipt_raw=read(receipt_path,16384,secret=True)
        funding.validate_receipt(decode(receipt_raw),intent,funding.checked_clock(cohort_root))
        entries={}
        for name,item in listeners.items():
            if set(item)!={'config','sha256','cert','key'}:raise ValueError('invalid reviewed listener entry')
            entry={k:str(path(v)) if k!='sha256' else v for k,v in item.items()}
            cfg=decode(read(entry['config'],8192,secret=True))
            direct_tls.policy(entry['config'],entry['sha256'],value['tester_profile'][name]['url'],cfg['port'],entry['cert'],entry['key'])
            entries[name]=entry
        config=dict(format='zolana-pilot-runtime-v1',uid=os.getuid(),gid=os.getgid(),platform=platform.system().lower()+'-'+platform.machine().lower(),
                    network_root=str(root),network_sha256=network_sha,cohort_root=str(cohort_root),plan_sha256=digest,
                    funding_check_id=check_id,funding_receipt_sha256=sha(receipt_raw),password_file=str(password_file),
                    password_sha256=sha(read(password_file,1024,secret=True)),listeners=entries,pins=pins())
        binding_sha=sha(encode(config))
        # A partially written binding is never treated as a legacy faucet or rebuilt.
        create(root/FILES[0],encode(config));fsync_dir(root)
        create(root/FILES[2],encode(dict(format='zolana-pilot-runtime-state-v1',binding_sha256=binding_sha,
                                        phase='bound',activated_at=None,funding_receipt_sha256=sha(receipt_raw))))
        create(root/FILES[3],encode(dict(format='zolana-pilot-runtime-clock-v1',binding_sha256=binding_sha,last_time=int(time.time()))))
        create(root/FILES[1],encode(dict(format='zolana-pilot-runtime-required-v1',binding_sha256=binding_sha)));fsync_dir(root)
        return dict(binding_sha256=binding_sha,phase='bound',services_started=False,transfers_submitted=0)


def static(root,expected):
    root=path(root);net,network_sha,rpc=network(root)
    raw=read(root/FILES[0],32768,secret=True);value=decode(raw)
    keys={'format','uid','gid','platform','network_root','network_sha256','cohort_root','plan_sha256','funding_check_id',
          'funding_receipt_sha256','password_file','password_sha256','listeners','pins'}
    if (not hex64(expected) or sha(raw)!=expected or not isinstance(value,dict) or set(value)!=keys or
            value['format']!='zolana-pilot-runtime-v1' or value['uid']!=os.getuid() or value['gid']!=os.getgid() or
            value['platform']!=platform.system().lower()+'-'+platform.machine().lower() or value['network_root']!=str(root) or
            value['network_sha256']!=network_sha or value['pins']!=pins() or
            cohort.private_json(root/FILES[1])!=dict(format='zolana-pilot-runtime-required-v1',binding_sha256=expected) or
            (root/'ingress-setup.json').exists() or (root/'ingress-setup.json').is_symlink()):
        raise ValueError('reviewed runtime identity/configuration changed')
    return value,net,rpc


@contextmanager
def checked(root,expected):
    root=path(root);config,net,rpc=static(root,expected);cr=path(config['cohort_root'])
    with cohort.locked(cr),ExitStack() as stack:
        for name in ('worker.lock','claims.json.lock'):stack.enter_context(funding.native_lock(cr/'faucet'/name))
        value,claims,info,intent=cohort_check(cr,config['plan_sha256'],net,rpc,root)
        receipt_raw=read(cr/'funding-checks'/(config['funding_check_id']+'.json'),16384,secret=True)
        receipt=decode(receipt_raw)
        if sha(receipt_raw)!=config['funding_receipt_sha256']:raise ValueError('original initial funding receipt changed')
        funding.validate_receipt(receipt,intent,receipt['checked_at'])  # Historical evidence, not a renewed receipt.
        if sha(read(path(config['password_file']),1024,secret=True))!=config['password_sha256']:raise ValueError('faucet unlock input changed')
        for name,entry in config['listeners'].items():
            cfg=decode(read(path(entry['config']),8192,secret=True))
            direct_tls.policy(entry['config'],entry['sha256'],value['tester_profile'][name]['url'],cfg['port'],path(entry['cert']),path(entry['key']))
        state=cohort.private_json(root/FILES[2])
        if (set(state)!={'format','binding_sha256','phase','activated_at','funding_receipt_sha256'} or
                state['format']!='zolana-pilot-runtime-state-v1' or state['binding_sha256']!=expected or
                state['funding_receipt_sha256']!=config['funding_receipt_sha256'] or state['phase'] not in ('bound','active') or
                (state['phase']=='bound' and state['activated_at'] is not None) or
                (state['phase']=='active' and not cohort.bounded(state['activated_at'],1,int(time.time())))):
            raise ValueError('original activation state missing or invalid')
        clock=cohort.private_json(root/FILES[3]);now=int(time.time())
        if (set(clock)!={'format','binding_sha256','last_time'} or clock['format']!='zolana-pilot-runtime-clock-v1' or
                clock['binding_sha256']!=expected or not cohort.bounded(clock['last_time'],1,now)):
            raise ValueError('runtime clock moved backwards or evidence is missing')
        atomic(root/FILES[3],dict(clock,last_time=now))
        if state['phase']=='bound':
            unused(cr,claims,info);funding.validate_receipt(receipt,intent,now)
        yield config,value,state


def activate(root,expected):
    root=path(root)
    with checked(root,expected) as (config,value,state):
        cr=Path(config['cohort_root'])
        address=cohort.native(cohort.WALLET,'address',extra=['--network',cr/'source-profile.json','--wallet',cr/'faucet/wallet.enc.json','--password-file','-'],
                              password=read(config['password_file'],1024,secret=True))
        intent=cohort.private_json(cr/'funding-intent.json')
        if address['address']!=intent['private_address'] or address['fee_address']!=intent['fee_address']:raise ValueError('runtime wallet authority differs')
        if state['phase']=='bound':
            now=int(time.time())
            funding.validate_receipt(cohort.private_json(cr/'funding-checks'/(config['funding_check_id']+'.json')),intent,now)
            if now<cohort.private_json(root/FILES[3])['last_time']:raise ValueError('clock moved during activation')
            state=dict(state,phase='active',activated_at=now)
            atomic(root/FILES[2],state)  # Commit before any listener/worker starts.
        return config,value,state


class RuntimeFaucet(Faucet):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.failed=threading.Event()
    def work(self):
        while not self.stop.is_set():
            with self.child_lock:
                if self.stop.is_set():return
                self.child=subprocess.Popen([str(self.binary),'tick','--root',str(self.root),'--password-file','-'],
                                            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                child=self.child
            try:
                child.communicate(input=self.password,timeout=180)
                if child.returncode and not self.stop.is_set():self.failed.set();return
            except subprocess.TimeoutExpired:
                child.kill();child.communicate(timeout=10);self.failed.set();return
            finally:
                with self.child_lock:self.child=None
            self.stop.wait(2)


class Ingress:
    def __init__(self,root,expected,retention):
        self.services=[];self.threads=[];self.worker=None;self.faucet=None
        if retention.root!=Path(root) or not retention.healthy():raise ValueError('verified live retention required before pilot ingress')
        config,value,self.activation=activate(root,expected)
        from test_faucet import Handler as FaucetHandler
        from testnet_gateway import Gateway,Handler as GatewayHandler
        from service_tls import listener
        try:
            self.faucet=RuntimeFaucet(Path(config['cohort_root'])/'faucet',Path(config['password_file']))
            self.gateway=Gateway(self.faucet,history_root=retention.mirror,archive_rpc=value['source_profile']['rpc']['url'])
            for name,handler,app in [('faucet',FaucetHandler,self.faucet),('rpc',GatewayHandler,self.gateway)]:
                e=config['listeners'][name];port=decode(read(e['config'],8192,secret=True))['port']
                self.services.append(listener(value['tester_profile'][name]['url'],port,handler,app,Path(e['cert']),Path(e['key']),Path(e['config']),e['sha256']))
            for server in self.services:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.threads.append(thread)
            self.worker=threading.Thread(target=self.faucet.work,daemon=True);self.worker.start()
        except BaseException:self.close();raise
    def healthy(self):return self.worker is not None and self.worker.is_alive() and not self.faucet.failed.is_set() and all(t.is_alive() for t in self.threads)
    def close(self):
        if self.faucet:self.faucet.close()
        for i,server in reversed(list(enumerate(self.services))):
            if i<len(self.threads):server.shutdown()
            server.server_close()
        for thread in self.threads:thread.join(timeout=12)
        if self.worker:self.worker.join(timeout=15)
        if any(t.is_alive() for t in self.threads) or (self.worker and self.worker.is_alive()):raise RuntimeError('pilot ingress worker did not stop')
        self.services=[];self.threads=[];self.worker=None


def supervise(root,expected,duration=None):
    from localnet import load,start,stop,wait_rpc,quiet,rpc,port,offset
    from replay_localnet import prepare as replay
    from history_retention import Retention
    root=path(root)
    if os.getpgrp()!=os.getpid():raise ValueError('pilot host requires its own service process group')
    if duration is not None and not cohort.bounded(duration,1,3600):raise ValueError('invalid bounded runtime duration')
    with funding.native_lock(root/'pilot-runtime.lock'):
        children=[None,None];retention=None;ingress=None;shutdown=threading.Event()
        deadline=time.monotonic()+duration if duration is not None else float('inf')
        def terminate(*_):
            shutdown.set()
            if retention is not None:retention.stop.set()
        signal.signal(signal.SIGTERM,terminate);signal.signal(signal.SIGINT,terminate)
        def status(phase,**fields):
            nonlocal stage
            stage=phase
            grant=ingress.faucet.child if ingress else None
            atomic(root/'pilot-runtime-status.json',dict(format='zolana-pilot-runtime-status-v1',phase=phase,binding_sha256=expected,
                   pid=os.getpid(),process_group=os.getpgrp(),validators=[p.pid for p in children if p is not None],
                   grant_child=grant.pid if grant is not None else None,updated_at=int(time.time()),**fields))
        failed=False;stage='starting'
        try:
            with checked(root,expected):pass  # Fail before starting validators on invalid binding.
            config=load(root);shift=offset(config);primary=port(0,shift)
            status('replaying')
            horizon=replay(root).get('native_epoch_horizon_checkpoint') if any((root/f'consensus-{i}').exists() for i in (0,1)) else None
            for i in (0,1):
                if shutdown.is_set() or time.monotonic()>=deadline:raise ValueError('runtime stopped during startup')
                children[i]=start(root,i,coordinated=True,new_session=False,epoch_horizon=horizon);wait_rpc(root,i)
            quiet(root);status('syncing')
            tips=[p.restart_tip for p in children if p.restart_tip is not None];barrier=max(tips) if tips else 0
            end=min(deadline,time.monotonic()+120)
            while True:
                slots=[rpc(port(i,shift),'getSlot',[dict(commitment='finalized')]) for i in (0,1)]
                if min(slots)>barrier+8 and max(slots)-min(slots)<=12:break
                if shutdown.wait(.3) or time.monotonic()>=end:raise ValueError('fresh finality required')
            retention=Retention(root,cohort.WALLET,f'http://127.0.0.1:{primary}',lambda method,params:rpc(primary,method,params),credential=root/'rpc-access.key')
            status('retaining');retention.start()
            if shutdown.is_set() or time.monotonic()>=deadline:raise ValueError('runtime stopped before ingress')
            ingress=Ingress(root,expected,retention)
            progressed=time.monotonic();last=min(slots)
            while not shutdown.is_set() and time.monotonic()<deadline:
                if any(p.poll() is not None for p in children) or not retention.healthy() or not ingress.healthy():raise ValueError('owned runtime component failed')
                slots=[rpc(port(i,shift),'getSlot',[dict(commitment='finalized')]) for i in (0,1)]
                if min(slots)>last:last=min(slots);progressed=time.monotonic()
                if time.monotonic()-progressed>60:raise ValueError('pilot finality stalled')
                status('ready',finalized_slots=slots,activated_at=ingress.activation['activated_at'])
                shutdown.wait(1)
        except BaseException as error:
            failed=True
            atomic(root/'pilot-runtime-error.json',dict(format='zolana-pilot-runtime-error-v1',stage=stage,error_type=type(error).__name__,error=str(error)[:500]))
        finally:
            errors=[]
            for component in (ingress,retention):
                if component is not None:
                    try:component.close()
                    except BaseException:errors.append('component')
            for i in (1,0):
                if children[i] is not None and children[i].poll() is None:
                    try:stop(root,i)
                    except BaseException:
                        children[i].kill();children[i].wait(timeout=15);errors.append('validator')
            status('blocked' if failed or errors else 'paused')
            if failed or errors:raise ValueError('pilot runtime blocked; original binding and journals retained')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('bind','check','run'))
    parser.add_argument('--network-root',type=Path,required=True);parser.add_argument('--binding-sha256');parser.add_argument('--duration',type=int)
    parser.add_argument('--cohort-root',type=Path);parser.add_argument('--plan-sha256');parser.add_argument('--check-id');parser.add_argument('--password-file',type=Path)
    for name in ('rpc','faucet'):
        for arg in ('listener','sha256','cert','key'):parser.add_argument('--'+name+'-'+arg)
    args=parser.parse_args()
    if args.action=='bind':
        listeners={name:dict(config=getattr(args,name+'_listener'),sha256=getattr(args,name+'_sha256'),cert=getattr(args,name+'_cert'),key=getattr(args,name+'_key')) for name in ('rpc','faucet')}
        output=prepare(args.network_root,args.cohort_root,args.plan_sha256,args.check_id,args.password_file,listeners)
    elif args.action=='check':
        root=path(args.network_root);cohort.directory(root)
        # A diagnostic must not contend for native worker locks in a live host.
        with funding.native_lock(root/'pilot-runtime.lock'),checked(root,args.binding_sha256) as (_,__,state):
            output=dict(phase=state['phase'],activated_at=state['activated_at'],services_started=False)
    else:supervise(args.network_root,args.binding_sha256,args.duration);output=dict(phase='paused')
    print(encode(output).decode(),end='')


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        raise SystemExit('Pilot runtime failed closed. Preserve original binding, keys, activation and payment journals; no automatic initialization or refill.')
