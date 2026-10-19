#!/usr/bin/env python3
"""Funded pilot host/worker SIGKILL and original-wallet recovery; fresh local state."""
import argparse
import json
import os
from pathlib import Path
import secrets
import re
import signal
import socket
import subprocess
import sys
import time

from faucet_localnet import Distribution,WALLET
from fault_localnet import atomic_json,durable
from localnet import LAB,PROJECT,load,start,stop,quiet,wait_rpc
from local_test_tls import create as create_tls
from package_wallet import public_profile
import pilot_cohort as cohort
import pilot_funding as funding
import pilot_runtime as runtime
from rpc_isolation import enable
from wallet_localnet import private_new
from wallet_release import create,encode,read,sha
from wallet_ui import WalletApp


class PilotHost(Distribution):
    def __init__(self,*args):super().__init__(*args);self.host=None;self.host_generation=0
    def event(self,kind,**fields):
        self.result['events'].append(dict(kind=kind,**fields));atomic_json(self.root/'pilot-runtime-result.json',self.result);print(kind,flush=True)
    def host_status(self):
        return json.loads((self.root/'pilot-runtime-status.json').read_text())
    def start_host(self):
        self.host_generation+=1
        with (self.evidence/f'host-{self.host_generation}.log').open('xb') as log:
            self.host=subprocess.Popen([sys.executable,'-B',str(PROJECT/'tools/pilot_runtime.py'),'run','--network-root',str(self.root),
                       '--binding-sha256',self.binding,'--duration','600'],stdout=log,stderr=log,env=self.env,start_new_session=True)
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            if self.host.poll() is not None:raise RuntimeError('pilot host exited; inspect private runtime error/log')
            try:
                status=self.host_status()
                if status['pid']==self.host.pid and status['phase']=='ready':
                    if status['process_group']!=self.host.pid or any(os.getpgid(pid)!=self.host.pid for pid in status['validators']):
                        raise RuntimeError('owned child escaped host process group')
                    self.wait_for(self.ready_history,timeout=30);return status
            except (OSError,ValueError):pass
            time.sleep(.15)
        raise RuntimeError('bounded pilot host readiness deadline')
    def stop_host(self,crash=False):
        child=self.host
        if child is None:return
        if child.poll() is None:
            if os.getpgid(child.pid)!=child.pid:raise RuntimeError('host crash target is not its own process group')
            if crash:os.killpg(child.pid,signal.SIGKILL)
            else:child.terminate()
            child.wait(timeout=90)
            if crash and child.returncode!=-9:raise RuntimeError('host group did not receive SIGKILL')
            if not crash and child.returncode!=0:raise RuntimeError('host orderly shutdown failed')
        # The group is uniquely owned by this direct child; remove any descendant
        # left after an interrupted test/failed runtime cleanup, never by name/PID file.
        rows=subprocess.check_output(['/bin/ps','-A','-o','pgid=,uid=,stat='],text=True)
        live=[row.split() for row in rows.splitlines() if len(row.split())==3 and int(row.split()[0])==child.pid and not row.split()[2].startswith('Z')]
        if any(int(row[1])!=os.getuid() for row in live):raise RuntimeError('remaining group identity differs')
        if live:
            try:os.killpg(child.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        self.host=None
    def close(self):
        try:self.stop_host()
        finally:super().close()
    def operator_balances(self,config):
        values=[]
        for i in (0,1):
            # A public tester profile intentionally refuses operator overrides.
            # Use the original private network configuration for operator-only reads.
            current={who:self.command([str(WALLET),'balance','--network',str(self.root/'network.json'),
                '--wallet',str(self.clients[who].wallet),'--password-file',str(self.password_file),
                '--rpc',f'http://127.0.0.1:{18899+i*1000}','--rpc-access-file',str(self.root/'rpc-access.key')])['balance'] for who in ('alice','bob')}
            if current!={'alice':950_000,'bob':50_000}:raise RuntimeError('pilot host recovered different private balances')
            values.append(current)
        return values
    def resume_operator_check(self):
        began=time.monotonic();root=self.root;previous=checkpoint(root,self.evidence)
        self.result['events']=previous['events'];self.result['prior_failure']=previous['error']
        self.result['resumed_operator_check']=True
        sources={name:sha((PROJECT/'tools'/name).read_bytes()) for name in (*runtime.CODE,'pilot_runtime_localnet.py')}
        self.host_generation=max(int(p.stem.split('-')[1]) for p in self.evidence.glob('host-*.log'))
        binding=runtime.cohort.private_json(root/runtime.FILES[1])['binding_sha256'];self.binding=binding
        binding_value,config,_=runtime.static(root,binding);cr=Path(binding_value['cohort_root']);digest=binding_value['plan_sha256']
        self.password_file=Path(binding_value['password_file']);self.password=read(self.password_file,1024,secret=True).decode()
        self.faucet_root=cr/'faucet';self.source=self.faucet_root/'wallet.enc.json';self.profiles=[cr/'tester-profile.json']*2
        for who in ('alice','bob'):
            self.clients[who]=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client'))
            self.keys[who]=self.clients[who].cli('address',self.password)
        activation=read(root/runtime.FILES[2],4096,secret=True)
        prepared=cohort.private_json(cr/'prepared.json');sponsor={p.name:sha(p.read_bytes()) for p in root.glob('sponsor*.disabled')}
        if len(sponsor)!=3:raise ValueError('original disabled operator material missing')
        first={'claim_id':next(p.stem for p in self.faucet_root.glob('*.json') if re.fullmatch('[a-f0-9]{64}',p.stem))}
        self.start_host();state=durable(root,0);self.wait_for(lambda:durable(root,1)==state)
        if len(state)!=7:raise RuntimeError('operator-check resume requires original pool/six nullifiers')
        self.event('preserved_operator_check_resumed_without_funding_or_wallet_reset')
        self.finish(config,cr,digest,prepared,first,activation,state,began,sources,sponsor)
    def run(self):
        began=time.monotonic();root=self.root
        sources={name:sha((PROJECT/'tools'/name).read_bytes()) for name in (*runtime.CODE,'pilot_runtime_localnet.py')}
        operator=self.evidence/'operator';operator.mkdir(mode=0o700)
        self.password=secrets.token_urlsafe(36);self.password_file=operator/'faucet.password'
        cold,hot=operator/'cold.password',operator/'sponsor.password'
        for p in (cold,hot):private_new(p,secrets.token_urlsafe(36).encode())
        private_new(self.password_file,self.password.encode())
        self.command([str(LAB),'init-private',str(root),'--cold-password-file',str(cold),'--sponsor-password-file',str(hot)])
        enable(root,hardened=True)
        for i in (0,1):self.children[i]=start(root,i);wait_rpc(root,i)
        quiet(root);self.converge(0);self.wait_for(self.ready_history,timeout=45)
        config=load(root);self.tls=self.evidence/'tls';create_tls(self.tls)
        source=public_profile(config,'Zolana funded pilot host','http://127.0.0.1:18899','loopback-http')
        tester=public_profile(config,'Zolana funded pilot host','https://127.0.0.1:18898','https')
        tester.update(invite_required=True,faucet=dict(transport='https',url='https://127.0.0.1:13781'),local_tls_ca_pem=(self.tls/'ca.crt').read_text())
        value=cohort.plan(source,tester,count=1,daily=1);digest=sha(encode(value));cr=root/'pilot'
        prepared=cohort.prepare(value,cr,digest,self.password_file,rpc_access_file=root/'rpc-access.key')
        self.faucet_root=cr/'faucet';self.source=self.faucet_root/'wallet.enc.json'
        receipt=self.command([str(WALLET),'deposit','--network',str(root/'network.json'),'--wallet',str(self.source),
            '--password-file',str(self.password_file),'--rpc',source['rpc']['url'],'--rpc-access-file',str(root/'rpc-access.key'),
            '--sponsor-password-file',str(hot),'--sponsor-request-id','pilot-runtime-reservoir','--amount','5000000'])
        self.closed(receipt['staging_account'])
        self.command([str(LAB),'fund-faucet-check',str(root),str(self.source),str(self.password_file),str(cold),source['rpc']['url']])
        self.wait_for(lambda:self.native_balance(prepared['fee_address'])==1_000_000_000)
        funding.make_intent(cr,digest);verified=funding.verify(cr,digest,self.password_file,'initial')
        listeners={}
        for name,port in [('rpc',18898),('faucet',13781)]:
            path=self.evidence/(name+'-listener.json')
            create(path,encode(dict(format='zolana-direct-tls-v1',audience=tester[name]['url'],port=port,bind_ip='127.0.0.1',
                                   certificate_sha256=sha((self.tls/'server.crt').read_bytes()),key_sha256=sha((self.tls/'server.key').read_bytes()))))
            listeners[name]=dict(config=str(path),sha256=sha(path.read_bytes()),cert=str(self.tls/'server.crt'),key=str(self.tls/'server.key'))
        bound=runtime.prepare(root,cr,digest,'initial',self.password_file,listeners);self.binding=bound['binding_sha256']
        for i in (1,0):stop(root,i)
        self.children=[None,None]
        sponsor={}
        for name in ('sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json'):
            p=root/name;p.rename(root/(name+'.disabled'));sponsor[name+'.disabled']=sha((root/(name+'.disabled')).read_bytes())
        self.profiles=[cr/'tester-profile.json']*2
        for who in ('alice','bob'):
            self.clients[who]=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client'))
            self.keys[who]=self.user(who,'create');self.user(who,'ack-backup')
        first_host=self.start_host();activation=read(root/runtime.FILES[2],4096,secret=True)
        cohort.issue(cr,digest,'tester-01',bind_fee=self.keys['alice']['fee_address'])
        invitation=json.loads((cr/'invitations/tester-01.json').read_text())['invitation']
        first=self.user('alice','join',invitation=invitation)
        self.event('funded_bound_host_admitted_original_claim',private_observed=verified['private_observed'],public_observed=verified['public_observed'])
        progress=self.faucet_root/(first['claim_id']+'.json')
        deadline=time.monotonic()+120
        while time.monotonic()<deadline:
            if self.host.poll() is not None:raise RuntimeError('host exited before grant crash point')
            state=json.loads(progress.read_text());status=self.host_status();pid=status.get('grant_child')
            if state.get('gas_done') and not state.get('private_done') and pid:
                command=subprocess.check_output(['/bin/ps','-p',str(pid),'-o','command='],text=True)
                if str(cr/'faucet') not in command or 'native-faucet tick' not in command or os.getpgid(pid)!=self.host.pid:
                    raise RuntimeError('grant crash target differs from owned native worker')
                os.kill(pid,signal.SIGKILL);break
            time.sleep(.05)
        else:raise RuntimeError('native grant did not reach private work crash point')
        self.host.wait(timeout=90)
        if self.host.returncode==0:raise RuntimeError('failed grant child was treated as a healthy service')
        if self.host_status()['phase']!='blocked':raise RuntimeError('failed worker did not block host')
        self.stop_host();self.event('native_grant_child_sigkill_stopped_entire_host')
        # Missing activation must never recreate the initial budget or start validators.
        statepath=root/runtime.FILES[2];saved=root/(runtime.FILES[2]+'.retained');statepath.rename(saved)
        try:
            result=subprocess.run([sys.executable,'-B',str(PROJECT/'tools/pilot_runtime.py'),'run','--network-root',str(root),
                '--binding-sha256',self.binding,'--duration','30'],env=self.env,start_new_session=True,capture_output=True,timeout=30)
            if result.returncode==0 or statepath.exists():raise RuntimeError('missing activation was reconstructed')
        finally:saved.rename(statepath)
        recovered_host=self.start_host()
        # Observe the operator's durable progress while the automatic worker runs.
        # The generic wait_for loop is intentionally fast for local files; do not
        # put invited-wallet HTTP requests in it and consume membership quotas.
        def grant_ready():
            if self.host.poll() is not None:raise RuntimeError('host failed while recovering original grant')
            return json.loads(progress.read_text()).get('private_done') is True
        self.wait_for(grant_ready,timeout=180)
        again=self.user('alice','test-coins')
        if again['claim_id']!=first['claim_id'] or not again['gas_finalized'] or not again['private_finalized']:raise RuntimeError('grant recovery changed identity')
        if self.native_balance(self.keys['alice']['fee_address'])!=150_000_000:raise RuntimeError('gas grant duplicated')
        quote=self.user('alice','fees',payment='send')
        sent=self.user('alice','send',amount=50_000,recipient=self.keys['bob']['address'],fee_mode='user',max_fee_debit=quote['maximum_gross_debit'])
        self.closed(sent['staging_account']);state=durable(root,0);self.wait_for(lambda:durable(root,1)==state)
        if len(state)!=7:raise RuntimeError('expected exact pool and six nullifiers')
        self.finish(config,cr,digest,prepared,first,activation,state,began,sources,sponsor)

    def finish(self,config,cr,digest,prepared,first,activation,state,began,sources,sponsor):
        root=self.root
        self.operator_balances(config);barrier=max(self.slots());prior=self.host_status()
        create(self.evidence/f'precrash-generation-{self.host_generation}.json',encode(dict(native_state=state,barrier=barrier,activation_sha256=sha(activation))))
        self.stop_host(crash=True);self.event('entire_host_group_sigkilled_after_https_private_send')
        final_host=self.start_host()
        if set(prior['validators'])&set(final_host['validators']) or min(final_host['finalized_slots'])<=barrier:raise RuntimeError('host restart did not replace validators and advance finality')
        restored=WalletApp.from_profile(self.profiles[0],self.evidence/'alice-restored')
        recovered=restored.action(dict(action='restore',password=self.password,backup=json.loads(self.clients['alice'].backup.read_text())))
        claim=restored.action(dict(action='test-coins',password=self.password))
        balance=restored.action(dict(action='balance',password=self.password))['balance']
        if not restored.admitted or recovered['fee_address']!=self.keys['alice']['fee_address'] or claim['claim_id']!=first['claim_id'] or balance!=950_000:
            raise RuntimeError('original seed, membership, claim or private balance failed to recover')
        if durable(root,0)!=state or durable(root,1)!=state or read(root/runtime.FILES[2],4096,secret=True)!=activation:
            raise RuntimeError('restart changed original activation or native state')
        before=self.native_balance(prepared['fee_address']);time.sleep(3)
        if self.native_balance(prepared['fee_address'])!=before or durable(root,0)!=state:raise RuntimeError('completed grant retry changed chain state')
        if any(sha((root/name).read_bytes())!=value for name,value in sponsor.items()):raise RuntimeError('operator sponsor material changed')
        audit=cohort.audit(cr,digest)
        if (audit['issued'],audit['reserved_claims'])!=(1,1):raise RuntimeError('runtime reset lifetime capacity')
        final=self.operator_balances(config)
        for port in (18899,19899):
            with socket.socket() as probe:
                if probe.connect_ex(('127.0.0.1',port))==0:raise RuntimeError('hardened raw RPC became TCP-accessible')
        if any(sha((PROJECT/'tools'/name).read_bytes())!=digest for name,digest in sources.items()):raise RuntimeError('runtime acceptance source changed')
        self.result.update(status='passed',elapsed_seconds=round(time.monotonic()-began,2),source_tools_sha256=sources,
            binding_sha256=self.binding,host_generations=self.host_generation,private_balances=final,permanent_nullifiers=6,
            original_activation_unchanged=True,original_claim_id=first['claim_id'],private_rpc='owner-only-unix',cohort_size=1,
            grant_worker_sigkill=True,whole_host_group_sigkill=True,missing_activation_denied=True,sponsor_unchanged=True)
        self.event('funded_pilot_runtime_crash_restart_and_seed_restore_passed')


def checkpoint(root,evidence):
    raw=read(root/'pilot-runtime-result.json',1024*1024);value=json.loads(raw)
    expected='Wallet error: tester profile permits no operator sponsorship; use user-paid sends/withdrawals\n'
    kinds=['funded_bound_host_admitted_original_claim','native_grant_child_sigkill_stopped_entire_host']
    original=root/'pilot-runtime-failed-operator-check.json'
    resumed=value.get('resumed_operator_check') is True and value.get('prior_failure')==expected
    observed=[e['kind'] for e in value.get('events',[])]
    setup_failure=value.get('error')=='Unknown wallet action.' and observed==kinds
    cleanup_failure=value.get('error')=='[Errno 1] Operation not permitted' and observed==kinds+['preserved_operator_check_resumed_without_funding_or_wallet_reset']
    if value.get('status')=='failed' and resumed and (setup_failure or cleanup_failure):
        retained=root/('pilot-runtime-failed-resume-setup.json' if setup_failure else 'pilot-runtime-failed-group-cleanup.json')
        if retained.exists():
            if read(retained,1024*1024,secret=True)!=raw:raise ValueError('retained resume failure differs')
        else:create(retained,raw)
        raw=read(original,1024*1024,secret=True);value=json.loads(raw)
    if (value.get('status')!='failed' or value.get('error')!=expected or
            [e['kind'] for e in value.get('events',[])]!=kinds):
        raise ValueError('resume requires the exact preserved failed operator-check checkpoint')
    config,_,_=runtime.static(root,cohort.private_json(root/runtime.FILES[1])['binding_sha256'])
    if cohort.private_json(root/runtime.FILES[2])['phase']!='active' or (evidence/'alice-restored').exists():
        raise ValueError('resume phase or preserved client evidence differs')
    cr=Path(config['cohort_root']);info=cohort.audit(cr,config['plan_sha256'])
    progress=[p for p in (cr/'faucet').glob('*.json') if re.fullmatch('[a-f0-9]{64}',p.stem)]
    if info['cohort_size']!=1 or info['issued']!=1 or info['reserved_claims']!=1 or len(progress)!=1:
        raise ValueError('original single claim differs')
    grant=json.loads(progress[0].read_text())
    if grant.get('gas_done') is not True or grant.get('private_done') is not True or grant.get('gas_attempts')!=1:
        raise ValueError('original grant not finalized once')
    with funding.native_lock(root/'pilot-runtime.lock'):pass
    if original.exists():
        if read(original,1024*1024,secret=True)!=raw:raise ValueError('retained original failure changed')
    else:create(original,raw)
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--resume-operator-check',action='store_true')
    args=parser.parse_args();root=args.root.absolute();evidence=args.evidence.absolute()
    if root.parent!=PROJECT/'.data' or (os.path.lexists(root) and not args.resume_operator_check):parser.error('use a fresh direct .data child or the exact guarded failed checkpoint')
    if args.resume_operator_check:checkpoint(root,evidence)
    else:evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    trial=PilotHost(root,evidence,None,None)
    def interrupted(*_):raise KeyboardInterrupt('bounded pilot runtime acceptance interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    try:trial.resume_operator_check() if args.resume_operator_check else trial.run()
    except BaseException as error:trial.result.update(status='failed',error=str(error));raise
    finally:
        try:trial.close()
        finally:
            if root.exists():atomic_json(root/'pilot-runtime-result.json',trial.result)


if __name__=='__main__':main()
