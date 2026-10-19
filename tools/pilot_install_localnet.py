#!/usr/bin/env python3
"""Fresh ten-tester ceremony and installed-runtime recovery, loopback only."""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

from pilot_runtime_localnet import PilotHost
from fault_localnet import atomic_json,durable,crash_owned
from localnet import LAB,PROJECT,load,start,stop,quiet,wait_rpc,rpc
from local_test_tls import create as create_tls
from package_wallet import public_profile
import pilot_cohort as cohort
import pilot_funding as funding
import pilot_install as install
import pilot_provision as provision
import pilot_runtime as runtime
from replay_localnet import prepare as replay
from rpc_isolation import enable
from wallet_localnet import private_new
from wallet_release import create,encode,read,sha
from wallet_ui import WalletApp


class TenPilot(PilotHost):
    def event(self,kind,**fields):
        self.result['events'].append(dict(kind=kind,**fields));atomic_json(self.root/'pilot-install-result.json',self.result);print(kind,flush=True)
    def provision_child(self,phase=None):
        script='''import os,signal,sys,time
from pathlib import Path
import pilot_provision as p
from wallet_release import read,decode
args=decode(read(Path(sys.argv[1]),16384,secret=True))
def fault(stage):
 if stage==args.get('crash'):
  if stage=='public-broadcast':
   # Lose the funding process after actual canonical acceptance, before it saves
   # a completion receipt; the replacement must find the original signature.
   plan=decode(read(Path(args['root'])/'provision-plan.json',16384,secret=True));nr=Path(plan['network_root'])
   t=p.Transport('http://127.0.0.1:18899',nr/'rpc-access.key');sig=decode(read(Path(args['root'])/'treasury-signed.json',16384,secret=True))['signature']
   deadline=time.monotonic()+60
   while time.monotonic()<deadline:
    s=t.rpc('getSignatureStatuses',[[sig],{'searchTransactionHistory':True}])['value'][0]
    if s and s.get('confirmationStatus')=='finalized' and s.get('err') is None:break
    time.sleep(.2)
   else:raise ValueError('treasury canonical crash point timed out')
  os.kill(os.getpid(),signal.SIGKILL)
p.run(Path(args['root']),args['digest'],Path(args['password']),Path(args['cold']),Path(args['sponsor']),fault)
'''
        self.generation+=1;cfg=self.evidence/f'provision-{self.generation}.json'
        create(cfg,encode(dict(root=str(self.cr),digest=self.provision_digest,password=str(self.password_file),cold=str(self.cold),sponsor=str(self.hot),crash=phase)))
        with (self.evidence/f'provision-{self.generation}.log').open('xb') as log:
            child=subprocess.Popen([sys.executable,'-B','-c',script,str(cfg)],cwd=PROJECT/'tools',stdout=log,stderr=log,env=self.env)
            self.wallet_children.append(child);code=child.wait(timeout=240)
        if code!=(-9 if phase else 0):raise RuntimeError('funding child failed; preserve exact fixture and private log')
    def crash_pair(self):
        state=durable(self.root,0);self.wait_for(lambda:durable(self.root,1)==state)
        barrier=max(self.slots())
        for i in (1,0):crash_owned(self.root,i,self.children[i]);self.children[i]=None
        checkpoint=replay(self.root);horizon=checkpoint.get('native_epoch_horizon_checkpoint')
        for i in (0,1):self.children[i]=start(self.root,i,coordinated=True,epoch_horizon=horizon);wait_rpc(self.root,i)
        quiet(self.root);self.converge(barrier,expected=state)
        return state
    def run(self):
        began=time.monotonic();root=self.root;self.generation=0
        operator=self.evidence/'operator';operator.mkdir(mode=0o700)
        self.password=secrets.token_urlsafe(36);self.password_file=operator/'faucet.password';self.cold=operator/'cold.password';self.hot=operator/'sponsor.password'
        for p in (self.cold,self.hot):private_new(p,secrets.token_urlsafe(36).encode())
        private_new(self.password_file,self.password.encode())
        self.command([LAB,'init-private',root,'--cold-password-file',self.cold,'--sponsor-password-file',self.hot]);enable(root,hardened=True)
        for i in (0,1):self.children[i]=start(root,i);wait_rpc(root,i)
        quiet(root);self.converge(0);self.wait_for(self.ready_history,timeout=45)
        config=load(root);self.tls=self.evidence/'tls';create_tls(self.tls)
        source=public_profile(config,'Zolana ten-tester pilot','http://127.0.0.1:18899','loopback-http')
        tester=public_profile(config,'Zolana ten-tester pilot','https://127.0.0.1:18898','https')
        tester.update(invite_required=True,faucet=dict(transport='https',url='https://127.0.0.1:13781'),local_tls_ca_pem=(self.tls/'ca.crt').read_text())
        value=cohort.plan(source,tester,count=10,daily=10);digest=sha(encode(value));self.cr=cr=root/'pilot'
        prepared=cohort.prepare(value,cr,digest,self.password_file,rpc_access_file=root/'rpc-access.key');self.faucet_root=cr/'faucet';self.source=self.faucet_root/'wallet.enc.json'
        self.provision_digest=provision.prepare(root,cr,digest)['provision_sha256']
        self.provision_child('public-broadcast')
        signed=read(cr/'treasury-signed.json',16384,secret=True)
        if (cr/'treasury-finalized.json').exists():raise RuntimeError('funding process not killed before receipt')
        self.crash_pair();self.event('treasury_process_and_validator_pair_sigkill_original_signature_retained')
        self.provision_child('private-1-broadcast')
        if (cr/'pilot-ten-deposit-01.json').exists():raise RuntimeError('private process not killed before receipt')
        state=self.crash_pair();self.event('first_private_deposit_sigkill_without_checkpoint_recovered',native_accounts=len(state))
        self.provision_child()
        if read(cr/'treasury-signed.json',16384,secret=True)!=signed:raise RuntimeError('treasury was signed again')
        verified=funding.verify(cr,digest,self.password_file,'initial')
        if verified['private_observed']!=10_000_000 or verified['public_observed']!=6_000_300_000:raise RuntimeError('ten-tester allocation differs')
        original=read(cr/'provision-complete.json',16384,secret=True);before=durable(root,0);self.provision_child()
        if read(cr/'provision-complete.json',16384,secret=True)!=original or durable(root,0)!=before:raise RuntimeError('completed funding repeated a deposit')
        self.event('exact_ten_tester_funding_native_verified_no_refill_on_repeat')
        listeners={}
        for name,port in [('rpc',18898),('faucet',13781)]:
            path=self.evidence/(name+'-listener.json');create(path,encode(dict(format='zolana-direct-tls-v1',audience=tester[name]['url'],port=port,bind_ip='127.0.0.1',certificate_sha256=sha((self.tls/'server.crt').read_bytes()),key_sha256=sha((self.tls/'server.key').read_bytes()))))
            listeners[name]=dict(config=str(path),sha256=sha(path.read_bytes()),cert=str(self.tls/'server.crt'),key=str(self.tls/'server.key'))
        self.binding=runtime.prepare(root,cr,digest,'initial',self.password_file,listeners)['binding_sha256']
        for i in (1,0):stop(root,i)
        self.children=[None,None]
        for name in ('sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json'):(root/name).rename(root/(name+'.disabled'))
        self.profiles=[cr/'tester-profile.json']*2
        for who in ('alice','bob'):
            self.clients[who]=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client'));self.keys[who]=self.user(who,'create');self.user(who,'ack-backup')
        self.start_host();activation=read(root/runtime.FILES[2],4096,secret=True)
        for index in range(1,11):cohort.issue(cr,digest,f'tester-{index:02}',bind_fee=self.keys['alice']['fee_address'] if index==1 else None)
        invitation=json.loads((cr/'invitations/tester-01.json').read_text())['invitation'];first=self.user('alice','join',invitation=invitation)
        progress=self.faucet_root/(first['claim_id']+'.json')
        self.wait_for(lambda:progress.exists() and json.loads(progress.read_text()).get('private_done') is True,timeout=180)
        again=self.user('alice','test-coins')
        if again['claim_id']!=first['claim_id'] or self.native_balance(self.keys['alice']['fee_address'])!=150_000_000:raise RuntimeError('initial invited grant differs')
        quote=self.user('alice','fees',payment='send');sent=self.user('alice','send',amount=50_000,recipient=self.keys['bob']['address'],fee_mode='user',max_fee_debit=quote['maximum_gross_debit']);self.closed(sent['staging_account'])
        self.operator_balances(config);state=durable(root,0);self.wait_for(lambda:durable(root,1)==state)
        if len(state)!=9:raise RuntimeError('expected original pool and eight permanent nullifiers')
        barrier=max(self.slots());self.stop_host(crash=True);self.start_host()
        self.operator_balances(config)
        if read(root/runtime.FILES[2],4096,secret=True)!=activation or durable(root,0)!=state or durable(root,1)!=state or min(self.slots())<=barrier:raise RuntimeError('host crash lost activation/payment/nullifiers')
        retry=self.user('alice','test-coins')
        if retry['claim_id']!=first['claim_id'] or self.native_balance(self.keys['alice']['fee_address'])>=150_000_000:raise RuntimeError('host restart duplicated gas grant')
        try:cohort.issue(cr,digest,'tester-11')
        except ValueError:pass
        else:raise RuntimeError('eleventh lifetime invitation accepted')
        self.stop_host();self.event('funded_ten_slot_host_sigkill_private_payment_and_eight_nullifiers_recovered')
        # Rehearse the actual full runtime bundle independently of the funded
        # network. Never move that network or alter its absolute binding pins.
        packet=self.evidence/'host-bundle';receipt=install.prepare(packet);prefix=self.evidence/'installed-host'
        install.stage(packet,receipt['manifest_sha256'],prefix,os.getuid(),os.getgid(),True)
        probe=subprocess.run([sys.executable,'-B',str(prefix/'tools/pilot_runtime.py'),'--help'],capture_output=True,timeout=20)
        if probe.returncode:raise RuntimeError('staged runtime import failed')
        # An install retry must retain independently created original state bytes.
        create(prefix/'.data/preserved',b'original private rehearsal state');install.stage(packet,receipt['manifest_sha256'],prefix,os.getuid(),os.getgid(),True)
        if read(prefix/'.data/preserved',1024)!=b'original private rehearsal state':raise RuntimeError('installation retry replaced state')
        self.result.update(status='passed',seconds=round(time.monotonic()-began,2),funding=verified,provision_sha256=self.provision_digest,binding_sha256=self.binding,
            bundle_sha256=receipt['manifest_sha256'],issued_slots=10,grants_exercised=1,balances=dict(alice=950000,bob=50000),nullifiers=8,
            installation='current-UID filesystem rehearsal only',actual_launchd_tested=False,source_sha256={name:sha((PROJECT/'tools'/name).read_bytes()) for name in ('pilot_install.py','pilot_provision.py','pilot_install_localnet.py')})


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);a=p.parse_args()
    root=a.root.absolute();evidence=a.evidence.absolute()
    if root.parent!=PROJECT/'.data' or os.path.lexists(root):p.error('fresh direct .data child required; never reset existing state')
    evidence.mkdir(mode=0o700,parents=True,exist_ok=False);trial=TenPilot(root,evidence,None,None)
    def interrupted(*_):raise KeyboardInterrupt('bounded local acceptance interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    try:trial.run()
    except BaseException as error:trial.result.update(status='failed',error=str(error));raise
    finally:
        try:trial.close()
        finally:
            if root.exists():atomic_json(root/'pilot-install-result.json',trial.result)

if __name__=='__main__':main()
