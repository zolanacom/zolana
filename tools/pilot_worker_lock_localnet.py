#!/usr/bin/env python3
"""Reproduce the live-source audit lock failure, then recover the same completed cohort."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import signal
import time

from fault_localnet import durable
from localnet import PROJECT
from pilot_cohort_localnet import CohortRun
import pilot_cohort as cohort
import pilot_funding as funding
import pilot_runtime as runtime
from wallet_release import atomic,create,decode,encode,read,sha


def run(root,accepted,evidence):
    result=decode(read(accepted/'result.json',1024*1024,secret=True))
    if (root!=PROJECT/'.data/p46a' or result.get('status')!='passed' or result.get('payments')!=10 or result.get('nullifiers')!=46):
        raise ValueError('requires exact completed ten-wallet acceptance; never starts incomplete grant work')
    evidence.mkdir(mode=0o700,parents=True,exist_ok=False);create(evidence/'accepted-cohort.json',encode(result))
    trial=CohortRun(root,evidence,None,None);trial.binding=result['binding_sha256'];began=time.monotonic()
    def interrupted(*_):raise KeyboardInterrupt('bounded source lock test interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    try:
        config,_,__=runtime.static(root,trial.binding);cr=Path(config['cohort_root']);source=cr/'faucet/wallet.enc.json'
        claims=cohort.private_json(cr/'faucet/claims.json')['claims']
        if len(claims)!=10:raise ValueError('requires all original ten claims')
        for claim in claims:
            p=cohort.private_json(cr/'faucet'/(trial.claim_id(claim)+'.json'))
            if not p['private_done'] or not p['gas_done']:raise ValueError('no grant may be in flight during lock probe')
        activation=read(root/runtime.FILES[2],4096,secret=True)
        trial.start_host();state=durable(root,0)
        if len(state)!=47 or durable(root,1)!=state:raise ValueError('accepted pool/nullifier state differs')
        fee=cohort.private_json(cr/'prepared.json')['fee_address'];public=trial.native_balance(fee)
        # Same native flock primitive as WalletOperation. This deliberately
        # reproduces a conflicting balance/cache scan, without touching a key,
        # cache, pending journal or funding instruction.
        with ExitStack() as locks:
            end=time.monotonic()+10
            while True:
                try:locks.enter_context(funding.native_lock(Path(str(source)+'.lock')));break
                except BlockingIOError:
                    if time.monotonic()>=end:raise
                    time.sleep(.05)
            trial.host.wait(timeout=30)
            if trial.host.returncode==0:raise ValueError('worker lock conflict did not fail closed')
        diagnostic=decode(read(evidence/'grant-worker-1-error.json',8192,secret=True))
        if diagnostic['returncode']!=1 or 'cannot lock wallet operation' not in diagnostic['stderr']:
            raise ValueError('native worker failure did not identify the actual source operation lock')
        if trial.host_status()['phase']!='blocked':raise ValueError('worker conflict was treated as healthy')
        trial.stop_host();trial.event('actual_source_wallet_lock_contention_failed_closed_without_any_transfer')
        trial.start_host()
        if (durable(root,0)!=state or durable(root,1)!=state or trial.native_balance(fee)!=public or
                read(root/runtime.FILES[2],4096,secret=True)!=activation):raise ValueError('source lock recovery changed original native/funding state')
        trial.stop_host();trial.result.update(status='passed',seconds=round(time.monotonic()-began,2),source_lock_conflict_confirmed=True,
            original_activation=True,original_pool_and_46_nullifiers=True,source_public_balance_unchanged=True,validators_stopped=True,
            source_sha256=sha(Path(__file__).read_bytes()))
        trial.event('same_host_recovered_after_original_lock_released')
    except BaseException as error:trial.result.update(status='failed',error=str(error));raise
    finally:
        try:trial.close()
        finally:atomic(evidence/'result.json',trial.result)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--accepted',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);a=p.parse_args()
    with funding.native_lock(a.root.absolute()/'cohort-rehearsal.lock'):
        run(a.root.absolute(),a.accepted.absolute(),a.evidence.absolute())

if __name__=='__main__':main()
