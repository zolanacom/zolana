#!/usr/bin/env python3
"""Finite new-cohort payment/restart acceptance on fresh local ledgers only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import time

from faucet_localnet import Distribution, Acknowledgements, FAUCET, WALLET
from fault_localnet import atomic_json, crash_owned, durable
from localnet import LAB, PROJECT, load, quiet, start, stop, wait_rpc
from package_wallet import public_profile
from pilot_cohort import plan as cohort_plan, prepare as cohort_prepare, issue, audit
from replay_localnet import prepare as replay_prepare
from test_faucet import Faucet, Handler as FaucetHandler
from testnet_gateway import Gateway, Handler as GatewayHandler
from wallet_localnet import private_new
from wallet_release import encode, sha
from wallet_ui import WalletApp


class Pilot(Distribution):
    def event(self,kind,**fields):
        self.result['events'].append(dict(kind=kind,**fields));atomic_json(self.root/'pilot-result.json',self.result);print(kind,flush=True)

    def start_http(self):
        self.faucet=Faucet(self.faucet_root,self.password_file)
        self.serve(FaucetHandler,self.faucet,13781)
        self.serve(GatewayHandler,Gateway(self.faucet),18898)

    def stop_http(self):
        for server,thread in reversed(self.services):server.shutdown();server.server_close();thread.join(timeout=5)
        self.services=[]
        if self.faucet:self.faucet.close()

    def run(self):
        began=time.monotonic()
        sources={name:sha((PROJECT/'tools'/name).read_bytes()) for name in ('pilot_cohort.py','pilot_localnet.py')}
        self.result['source_tools_sha256']=sources
        root=self.root;operator=self.evidence/'operator';operator.mkdir(mode=0o700)
        cold,hot=operator/'cold.password',operator/'sponsor.password'
        self.password=secrets.token_urlsafe(36);self.password_file=operator/'faucet.password'
        for path in (cold,hot):private_new(path,secrets.token_urlsafe(36).encode())
        private_new(self.password_file,self.password.encode())
        self.command([str(LAB),'init-private',str(root),'--cold-password-file',str(cold),'--sponsor-password-file',str(hot)])
        for i in (0,1):self.children[i]=start(root,i);wait_rpc(root,i)
        quiet(root);self.converge(0);self.wait_for(self.ready_history,timeout=45)
        config=load(root)
        source=public_profile(config,'Zolana pilot acceptance','http://127.0.0.1:24899','loopback-http')
        tester=public_profile(config,'Zolana pilot acceptance','http://127.0.0.1:18898','loopback-http')
        tester.update(invite_required=True,faucet=dict(transport='loopback-http',url='http://127.0.0.1:13781'))
        # One newly admitted sender plus an offline receiver bounds live-test work/heat.
        # Multi-member capacity/redemption and exact grant accounting are tested offline.
        value=cohort_plan(source,tester,count=1,daily=1);digest=sha(encode(value))
        cohort=root/'pilot';prepared=cohort_prepare(value,cohort,digest,self.password_file)
        self.faucet_root=cohort/'faucet';self.source=self.faucet_root/'wallet.enc.json'
        self.proxy=Acknowledgements(self.source)
        self.profiles=[cohort/'tester-profile.json']*2
        receipt=self.command([str(WALLET),'deposit','--network',str(root/'network.json'),'--wallet',str(self.source),
                              '--password-file',str(self.password_file),'--rpc','http://127.0.0.1:18899',
                              '--sponsor-password-file',str(hot),'--sponsor-request-id','pilot-cohort-reservoir','--amount','5000000'])
        self.closed(receipt['staging_account'])
        self.command([str(LAB),'fund-faucet-check',str(root),str(self.source),str(self.password_file),str(cold),'http://127.0.0.1:18899'])
        self.wait_for(lambda:self.native_balance(prepared['fee_address'])==1_000_000_000)
        if prepared['budget']['conservative_public_units']>1_000_000_000:raise RuntimeError('fixture funding below reviewed conservative budget')
        preserved={}
        for name in ('sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json'):
            path=root/name;path.rename(root/(name+'.disabled'));preserved[name+'.disabled']=sha((root/(name+'.disabled')).read_bytes())
        for who in ('alice','bob'):
            self.clients[who]=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client'))
            self.keys[who]=self.user(who,'create');self.user(who,'ack-backup')
        exported=issue(cohort,digest,'tester-01',bind_fee=self.keys['alice']['fee_address'])
        invitation=json.loads((cohort/'invitations/tester-01.json').read_text())['invitation']
        self.start_http()
        first=self.user('alice','join',invitation=invitation)
        self.event('fresh_cohort_claim_queued',cohort_size=1,budget=prepared['budget'],claim_id=first['claim_id'])
        self.proxy.gate('gas');child=self.tick_child();self.wait_gate(child,45);self.kill(child);self.proxy.clear()
        self.wait_for(lambda:self.native_balance(self.keys['alice']['fee_address'])==150_000_000)
        self.stop_http();self.start_http()
        cohort_prepare(value,cohort,digest,self.password_file,resume=True)
        if audit(cohort,digest)['reserved_claims']!=1:raise RuntimeError('restart changed cohort claim capacity')
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            self.tick()
            if self.user('alice','test-coins')['state']=='ready':break
            time.sleep(1)
        else:raise RuntimeError('fresh cohort grant did not recover')
        self.event('grant_worker_sigkill_and_http_restart_recovered',claim_id=first['claim_id'])
        quote=self.user('alice','fees',payment='send')
        sent=self.user('alice','send',amount=50_000,recipient=self.keys['bob']['address'],fee_mode='user',max_fee_debit=quote['maximum_gross_debit'])
        self.closed(sent['staging_account']);state=durable(root,0)
        self.wait_for(lambda:durable(root,1)==state)
        if len(state)!=7:raise RuntimeError('expected pool plus six permanent nullifiers')
        # The offline receiver has no admission; only this fixture's operator reads its seed.
        def balances():
            result=[]
            for i in (0,1):
                reader=public_profile(config,'Zolana operator acceptance',f'http://127.0.0.1:{18899+i*1000}','loopback-http')
                path=self.evidence/f'operator-reader-{i}.json';path.write_bytes(encode(reader))
                values={who:self.command([str(WALLET),'balance','--network',str(path),'--wallet',str(self.clients[who].wallet),
                                         '--password-file',str(self.password_file)])['balance'] for who in ('alice','bob')}
                if values!={'alice':950_000,'bob':50_000}:raise RuntimeError('cohort payment balances differ')
                result.append(values)
            return result
        balances();self.event('new_tester_user_paid_private_send',signature=sent['signature'],permanent_nullifiers=6)
        barrier=max(self.slots());self.stop_http()
        for i in (1,0):crash_owned(root,i,self.children[i])
        replay_prepare(root)
        for i in (0,1):self.children[i]=start(root,i,coordinated=True);wait_rpc(root,i)
        quiet(root);self.converge(barrier,state);self.wait_for(self.ready_history,timeout=45);self.start_http()
        restored=WalletApp.from_profile(self.profiles[0],self.evidence/'alice-restored')
        recovered=restored.action(dict(action='restore',password=self.password,backup=json.loads(self.clients['alice'].backup.read_text())))
        if recovered['fee_address']!=self.keys['alice']['fee_address'] or not restored.admitted:raise RuntimeError('seed did not recover original membership')
        again=restored.action(dict(action='test-coins',password=self.password))
        if again['claim_id']!=first['claim_id'] or again['state']!='ready':raise RuntimeError('restored seed duplicated or lost grant')
        recovered_balance=restored.action(dict(action='balance',password=self.password))['balance']
        if recovered_balance!=950_000:raise RuntimeError('restored spent-note balance differs')
        if durable(root,0)!=state or durable(root,1)!=state:raise RuntimeError('restart changed nullifiers')
        final=balances()
        if any(sha((root/name).read_bytes())!=digest for name,digest in preserved.items()):raise RuntimeError('operator sponsor material changed')
        before=self.native_balance(prepared['fee_address']);self.tick()
        if self.native_balance(prepared['fee_address'])!=before or durable(root,0)!=state:raise RuntimeError('completed grant retry changed chain state')
        if audit(cohort,digest)['issued']!=1 or audit(cohort,digest)['reserved_claims']!=1:raise RuntimeError('finite cohort capacity changed')
        if any(sha((PROJECT/'tools'/name).read_bytes())!=digest for name,digest in sources.items()):raise RuntimeError('acceptance source changed during live run')
        self.result.update(status='passed',validators=2,cohort_size=1,private_balances=final,permanent_nullifiers=6,
                           gas_grant=150_000_000,private_grant=1_000_000,restored_claim_id=again['claim_id'],
                           operator_unchanged_after_setup=True,completed_retry_no_transactions=True,elapsed_seconds=round(time.monotonic()-began,2))
        self.event('validator_sigkill_restart_and_seed_restore_passed')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args();root=args.root.absolute();evidence=args.evidence.absolute()
    if not root.is_relative_to(PROJECT/'.data') or root.parent!=PROJECT/'.data' or os.path.lexists(root):parser.error('use a new short direct .data child; never reset existing ledgers')
    evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    trial=Pilot(root,evidence,None,None)
    def interrupted(*_):raise KeyboardInterrupt('local acceptance interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    try:trial.run()
    except BaseException as error:trial.result.update(status='failed',error=str(error));raise
    finally:
        try:trial.close()
        finally:
            if root.exists():atomic_json(root/'pilot-result.json',trial.result)


if __name__=='__main__':main()
