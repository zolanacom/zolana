#!/usr/bin/env python3
"""Bounded real funding-check/host-packet acceptance on a fresh local pilot."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from unittest.mock import patch

import pilot_funding as funding
import pilot_host as host
import pilot_localnet as pilot
from wallet_release import encode,read,sha
from fault_localnet import atomic_json


class FundingOnlyComplete(Exception):pass


class FundingPilot(pilot.Pilot):
    def __init__(self,*args):
        super().__init__(*args);self.funding_started=False;self.funding_accepted=False

    def closed(self,account):
        result=super().closed(account)
        if not self.funding_started and self.faucet_root is not None:
            self.funding_started=True;root=self.faucet_root.parent
            self.intent=funding.make_intent(root,self.cohort_digest(root))
            try:funding.verify(root,self.cohort_digest(root),self.password_file,'underfunded')
            except ValueError as error:
                if 'public funding is insufficient' not in str(error):raise
            else:raise RuntimeError('faucet with zero public gas passed funding verification')
            self.event('actual_public_shortfall_denied',transfers_by_checker=0)
        return result

    def cohort_digest(self,root):return sha(encode(json.loads((root/'plan.json').read_text())))

    def before_issue(self,root,digest,slot,**kwargs):
        if not self.funding_accepted:
            self.funding_accepted=True
            receipt=funding.verify(root,digest,self.password_file,'funded')
            if receipt['private_observed']!=5_000_000 or receipt['public_observed']!=1_000_000_000:raise RuntimeError('funding observation differs from real reservoir')
            if funding.check(root,digest,'funded')!=receipt:raise RuntimeError('funding retry renewed or changed receipt')
            seed=read(root/'faucet/wallet.enc.json',16384,secret=True)
            script='''import os,signal,sys
from pathlib import Path
from unittest.mock import patch
import pilot_funding as f
original=f.atomic
def crash(path,value):
    if path.parent.name=='funding-checks' and sys.argv[4]=='before':os.kill(os.getpid(),signal.SIGKILL)
    original(path,value)
    if path.parent.name=='funding-checks':os.kill(os.getpid(),signal.SIGKILL)
with patch.object(f,'atomic',side_effect=crash):
    f.verify(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]),'crash-'+sys.argv[4])
'''
            for phase in ('before','after'):
                child=subprocess.run([sys.executable,'-B','-c',script,str(root),digest,str(self.password_file),phase],
                                     cwd=pilot.PROJECT/'tools',capture_output=True,timeout=180)
                if child.returncode!=-9:raise RuntimeError('real funding checker did not reach its SIGKILL boundary')
                recovered=funding.verify(root,digest,self.password_file,'crash-'+phase)
                if recovered['transfers_submitted']!=0 or read(root/'faucet/wallet.enc.json',16384,secret=True)!=seed:raise RuntimeError('read-only funding recovery changed source')
            packet=self.evidence/'host-packet';review=host.prepare(json.loads((root/'plan.json').read_text()),packet)
            if host.check(packet,review['manifest_sha256'])['activation_allowed']:raise RuntimeError('local packet enabled host activation')
            self.result['funding_check']=dict(private_observed=receipt['private_observed'],public_observed=receipt['public_observed'],
                                            max_private_payment=receipt['max_private_payment'],
                                            conservative_public_required=receipt['public_units'],transfers_submitted=0,
                                            actual_sigkill_before_and_after_commit=True,packet_manifest_sha256=review['manifest_sha256'])
            self.event('real_funding_receipt_and_sigkill_recovery_passed',funding=self.result['funding_check'])
            if getattr(self,'funding_only',False):raise FundingOnlyComplete()
        return self.original_issue(root,digest,slot,**kwargs)

    def run(self):
        began=time.monotonic()
        sources={name:sha((pilot.PROJECT/'tools'/name).read_bytes()) for name in ('pilot_funding.py','pilot_host.py','pilot_funding_localnet.py')}
        self.original_issue=pilot.issue
        try:
            with patch.object(pilot,'issue',side_effect=self.before_issue):super().run()
        except FundingOnlyComplete:
            # No invitation has been issued. Exercise receipt/balance recovery across
            # a real validator restart without another grant or private send.
            from fault_localnet import durable,crash_owned
            from localnet import start,wait_rpc,quiet
            from replay_localnet import prepare
            state=durable(self.root,0);self.wait_for(lambda:durable(self.root,1)==state)
            if len(state)!=3:raise RuntimeError('unexpected funding-only native account map')
            barrier=max(self.slots())
            for i in (1,0):crash_owned(self.root,i,self.children[i])
            prepare(self.root)
            for i in (0,1):self.children[i]=start(self.root,i,coordinated=True);wait_rpc(self.root,i)
            quiet(self.root);self.converge(barrier,state)
            root=self.faucet_root.parent;digest=self.cohort_digest(root)
            funding.check(root,digest,'funded')
            receipt=funding.verify(root,digest,self.password_file,'after-validator-restart')
            if receipt['max_private_payment']<1_000_000 or durable(self.root,0)!=state or durable(self.root,1)!=state:raise RuntimeError('funding spendability/state did not recover')
            self.result.update(status='passed',funding_only=True,permanent_nullifiers=len(state)-1,
                               receipt_reused_after_validator_restart=True,initial_admission_issued=0)
            self.event('funding_only_validator_restart_passed')
        if any(sha((pilot.PROJECT/'tools'/name).read_bytes())!=digest for name,digest in sources.items()):raise RuntimeError('funding source changed during acceptance')
        if not getattr(self,'funding_only',False):
            root=self.faucet_root.parent
            try:funding.check(root,self.cohort_digest(root),'funded')
            except ValueError:pass
            else:raise RuntimeError('initial funding receipt accepted after cohort became active')
        self.result['funding_source_sha256']=sources;self.event('funding_and_host_acceptance_passed')
        self.result['elapsed_seconds']=round(time.monotonic()-began,2)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True);parser.add_argument('--funding-only',action='store_true')
    args=parser.parse_args();root=args.root.absolute();evidence=args.evidence.absolute()
    if root.parent!=pilot.PROJECT/'.data' or os.path.lexists(root):parser.error('use a fresh short direct .data child')
    evidence.mkdir(mode=0o700,parents=True,exist_ok=False)
    trial=FundingPilot(root,evidence,None,None)
    trial.funding_only=args.funding_only
    def interrupt(*_):raise KeyboardInterrupt('bounded pilot funding check interrupted')
    signal.signal(signal.SIGTERM,interrupt)
    try:trial.run()
    except BaseException as error:trial.result.update(status='failed',error=str(error));raise
    finally:
        try:trial.close()
        finally:
            if root.exists():atomic_json(root/'pilot-funding-result.json',trial.result)


if __name__=='__main__':main()
