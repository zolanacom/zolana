#!/usr/bin/env python3
"""Interrupt one real send on a previously accepted private pilot fixture.

Adds a single 50,000-unit test payment; never initializes, funds or repins it.
The original runtime acceptance receipt is retained as historical evidence.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import time

from fault_localnet import atomic_json, durable
from localnet import PROJECT, load, rpc
from pilot_runtime_localnet import PilotHost
import pilot_runtime as runtime
from wallet_release import create, read, sha
from wallet_ui import WalletApp


def run(root):
    root = root.absolute()
    if root.parent != PROJECT / '.data' or root.resolve() != root:
        raise ValueError('requires a real direct private fixture child')
    prior = json.loads(read(root / 'pilot-runtime-result.json', 1024 * 1024, secret=True))
    if (prior.get('status') != 'passed' or prior.get('cohort_size') != 1 or
            prior.get('permanent_nullifiers') != 6 or not prior.get('whole_host_group_sigkill')):
        raise ValueError('requires the completed original six-nullifier runtime acceptance')
    evidence = PROJECT / '.local' / (root.name + '-atomic-recovery')
    evidence.mkdir(mode=0o700)  # Refuse a repeat before starting services or sending.
    result = dict(status='running', original_runtime_receipt_sha256=sha(read(
        root / 'pilot-runtime-result.json', 1024 * 1024, secret=True)))
    original = PROJECT / '.local' / root.name
    trial = PilotHost(root, original, None, None)
    trial.host_generation = max(int(p.stem.split('-')[1]) for p in original.glob('host-*.log'))
    trial.binding = runtime.cohort.private_json(root / runtime.FILES[1])['binding_sha256']
    binding, _, _ = runtime.static(root, trial.binding)
    trial.password_file = Path(binding['password_file'])
    trial.password = read(trial.password_file, 1024, secret=True).decode()
    profile = Path(binding['cohort_root']) / 'tester-profile.json'
    for who in ('alice', 'bob'):
        storage = original / (who + '-client')
        if not (storage / 'wallet-ui/wallet.json').is_file():
            raise ValueError('original client wallet missing; never create a replacement')
        trial.clients[who] = WalletApp.from_profile(profile, storage)
        trial.keys[who] = trial.clients[who].cli('address', trial.password)
    child = None
    try:
        trial.start_host()
        load(root)  # Authenticate the original operator-only Unix RPC routes.
        before = durable(root, 0)
        if len(before) != 7 or durable(root, 1) != before:
            raise ValueError('original pool/six-nullifier checkpoint differs')
        for who, expected in (('alice', 950_000), ('bob', 50_000)):
            if trial.user(who, 'balance')['balance'] != expected:
                raise ValueError('original accepted private balances differ')
        app = trial.clients['alice']
        pending = Path(str(app.wallet) + '.pending.json')
        staging = Path(str(app.wallet) + '.staging.json')
        if pending.exists() or staging.exists():
            raise ValueError('recover existing journals before any new test payment')
        quote = trial.user('alice', 'fees', payment='send')
        args = [str(app.binary), 'send', '--network', str(profile), '--wallet', str(app.wallet),
                '--password-file', str(trial.password_file), '--fee-payer', 'user',
                '--max-fee-debit', str(quote['maximum_gross_debit']), '--amount', '50000',
                '--to', trial.keys['bob']['address']]
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=trial.env)
        trial.wallet_children.append(child)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError('client exited before the owned interruption point')
            if pending.exists():
                saved = read(pending, 4096, secret=True)
                identity = json.loads(saved)
                status = rpc(18899, 'getSignatureStatuses', [[identity['signature']],
                             {'searchTransactionHistory': True}])['value'][0]
                if status and status['err'] is None and status.get('confirmationStatus') == 'confirmed':
                    os.kill(child.pid, signal.SIGSTOP)
                    break
            time.sleep(.02)
        else:
            raise TimeoutError('confirmed original send was not observed')
        state = subprocess.check_output(['/bin/ps', '-p', str(child.pid), '-o', 'stat='], text=True)
        if 'T' not in state:
            raise RuntimeError('owned wallet did not stop before its finalized acknowledgement')
        stage = read(staging, 4096, secret=True)
        create(evidence / 'original-pending.json', saved)
        create(evidence / 'original-staging.json', stage)
        def finalized():
            status = rpc(18899, 'getSignatureStatuses', [[identity['signature']],
                         {'searchTransactionHistory': True}])['value'][0]
            return status and status['err'] is None and status.get('confirmationStatus') == 'finalized'
        trial.wait_for(finalized, timeout=90)
        trial.closed(identity['staging_account'])
        child.kill()
        child.communicate(timeout=15)
        if child.returncode != -signal.SIGKILL:
            raise RuntimeError('owned stopped wallet was not SIGKILLed')
        if read(pending, 4096, secret=True) != saved or read(staging, 4096, secret=True) != stage:
            raise RuntimeError('original journals changed during interruption')
        resolved = trial.user('alice', 'resolve')
        if (resolved['signature'] != identity['signature'] or not resolved['accepted'] or
                not resolved['pending_cleared'] or pending.exists()):
            raise RuntimeError('canonical recovery did not resolve the original payment')
        reclaimed = trial.user('alice', 'reclaim')
        if not reclaimed['recovery_cleared'] or reclaimed['close_signature'] is not None or staging.exists():
            raise RuntimeError('atomic-close recovery submitted another close or kept its journal')
        accepted = durable(root, 0)
        if len(accepted) != 9:
            raise RuntimeError('expected exactly eight permanent nullifiers after two sends')
        barrier = max(trial.slots())
        trial.wait_for(lambda: durable(root, 1) == accepted)
        trial.stop_host(crash=True)
        restarted = trial.start_host()
        if min(restarted['finalized_slots']) <= barrier:
            raise RuntimeError('restarted cluster did not advance finality')
        for who, expected in (('alice', 900_000), ('bob', 100_000)):
            if trial.user(who, 'balance')['balance'] != expected:
                raise RuntimeError('private balances failed to survive restart')
        if durable(root, 0) != accepted or durable(root, 1) != accepted:
            raise RuntimeError('nullifier/pool checkpoint changed on restart')
        if sha(read(root / 'pilot-runtime-result.json', 1024 * 1024, secret=True)) != result['original_runtime_receipt_sha256']:
            raise RuntimeError('original acceptance receipt changed')
        result.update(status='passed', signature=identity['signature'], permanent_nullifiers=8,
                      private_balances=dict(alice=900_000, bob=100_000), close_transactions_during_recovery=0,
                      wallet_sigkill_before_finalized_ack=True, whole_host_sigkill_after_recovery=True,
                      original_runtime_receipt_unchanged=True)
    except BaseException as error:
        result.update(status='failed', error=str(error))
        raise
    finally:
        try:
            trial.close()
        finally:
            atomic_json(evidence / 'result.json', result)
    print(json.dumps(result))


if __name__ == '__main__':
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    run(parser.parse_args().root)
