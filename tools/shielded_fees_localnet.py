#!/usr/bin/env python3
"""Linux-only native shielded fee/recovery acceptance on a fresh disposable chain.

Never starts Mac validators or opens a public listener. Existing ledgers and
wallets are not inputs. The public-key fixture is not a pilot deployment.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
import time

from localnet import PROJECT, LAB, load, quiet, rpc, start, stop, wait_rpc
from fault_localnet import durable
from package_wallet import public_profile
from replay_localnet import prepare
from shielded_relay import save
from test_faucet import Faucet, BoundedServer, Handler as FaucetHandler


class Trial:
    def __init__(self, name, resume=False):
        self.root = PROJECT / '.data' / name
        if sys.platform != 'linux' or self.root.exists() != resume:
            raise ValueError('Linux and a fresh fixture are required; never reset an old run')
        self.children = [None, None]
        self.gateway = None
        self.wallets = []
        self.services = []
        self.events = json.loads((self.root / 'acceptance.json').read_text())['events'] if resume else []
        if resume and (not self.events or self.events[-1]['kind'] != 'expiry_and_seed_restore_exact'):
            raise ValueError('only the original completed recovery fixture may resume once')
        self.env = dict(os.environ, RAYON_NUM_THREADS='2')
        self.faucet = None

    def event(self, kind, **fields):
        self.events.append(dict(kind=kind, **fields))
        save(self.root / 'acceptance.json', dict(events=self.events, mac_validators_started=False))
        print(json.dumps(self.events[-1]), flush=True)

    def command(self, args, expect=None):
        result = subprocess.run(list(map(str, args)), capture_output=True, text=True, env=self.env, timeout=200)
        if expect is not None:
            if result.returncode == 0 or expect not in result.stderr:
                raise RuntimeError('expected refusal: ' + result.stderr)
            return
        if result.returncode: raise RuntimeError(result.stderr)
        return json.loads(result.stdout) if result.stdout.strip() else None

    def wait(self, callback, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = callback()
            if value: return value
            time.sleep(.03)
        raise TimeoutError('bounded shielded acceptance observation')

    def wallet_args(self, command, who, profile=False, binary='native-wallet'):
        return [PROJECT / 'target/debug' / binary, command, '--network',
                self.root / ('tester.json' if profile else 'network.json'), '--wallet', self.root / (who + '.wallet'),
                '--password-file', self.root / 'password', *([] if profile else ['--rpc', 'http://127.0.0.1:18899'])]

    def wallet(self, command, who, extra=(), profile=False, **kwargs):
        return self.command(self.wallet_args(command, who, profile) + list(extra), **kwargs)

    def balance(self, who): return self.wallet('balance', who)['balance']

    def state(self, count):
        def check():
            a, b = [durable(self.root, i) for i in (0, 1)]
            return a if a == b and len(a) == count + 1 else None
        return self.wait(check)

    def start_gateway(self):
        log = open(self.root / ('gateway-' + str(time.time_ns()) + '.log'), 'xb')
        self.gateway = subprocess.Popen([sys.executable, '-B', str(PROJECT / 'tools/testnet_gateway.py'),
            '--root', str(self.root / 'faucet'), '--password-file', str(self.root / 'password'),
            '--port', '18898', '--shielded-relay', str(self.root / 'relay')],
            stdout=log, stderr=log, env=self.env, start_new_session=True)
        log.close()
        import socket
        def ready():
            if self.gateway.poll() is not None: raise RuntimeError('gateway failed; inspect its retained log')
            with socket.socket() as probe: return probe.connect_ex(('127.0.0.1', 18898)) == 0
        self.wait(ready, 20)

    def kill_gateway(self):
        if self.gateway and self.gateway.poll() is None:
            os.killpg(self.gateway.pid, signal.SIGKILL); self.gateway.wait(timeout=15)
        self.gateway = None

    def spawn_send(self):
        args = self.wallet_args('send', 'alice', True, 'native-shielded') + [
            '--amount', '1000000', '--to', self.keys['bob']['address'], '--max-shielded-fee', '3000000']
        output = open(self.root / ('send-' + str(time.time_ns()) + '.log'), 'xb')
        child = subprocess.Popen(list(map(str, args)), stdout=output, stderr=output, env=self.env)
        output.close(); self.wallets.append(child)
        return child

    def next_job(self, old):
        return self.wait(lambda: next((p for p in (self.root / 'relay/jobs').iterdir() if p.name not in old), None))

    def run(self):
        self.command([LAB, 'init', self.root])
        (self.root / 'password').write_text(secrets.token_urlsafe(36)); os.chmod(self.root / 'password', 0o600)
        for i in (0, 1): self.children[i] = start(self.root, i); wait_rpc(self.root, i)
        quiet(self.root)
        self.wait(lambda: rpc(18899, 'getSlot', [dict(commitment='finalized')]) > 8)
        self.keys = {who: self.wallet('init', who, ['--backup', self.root / (who + '.backup')]) for who in ('alice', 'bob')}
        self.wallet('deposit', 'alice', ['--sponsor', self.root / 'sponsor.keypair.json', '--amount', '50000000'])
        config = load(self.root)
        source = public_profile(config, 'Shielded fee acceptance', 'http://127.0.0.1:18899', 'loopback-http')
        save(self.root / 'source.json', source)
        tester = public_profile(config, 'Shielded fee acceptance', 'http://127.0.0.1:18898', 'loopback-http')
        tester.update(invite_required=True, faucet=dict(transport='loopback-http', url='http://127.0.0.1:8780'))
        save(self.root / 'tester.json', tester)
        faucet = PROJECT / 'target/debug/native-faucet'
        self.command([faucet, 'init', '--root', self.root / 'faucet', '--profile', self.root / 'source.json',
            '--password-file', self.root / 'password', '--max-claims', '2'])
        self.command([faucet, 'access-init', '--root', self.root / 'faucet', '--profile', self.root / 'tester.json',
            '--daily-admissions', '2', '--rpc-limit', '2000'])
        self.faucet = Faucet(self.root / 'faucet', self.root / 'password')
        server = BoundedServer(('127.0.0.1', 8780), FaucetHandler)
        server.authority, server.app = '127.0.0.1:8780', self.faucet
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start(); self.services.append((server, thread))
        for who in ('alice', 'bob'):
            self.command([faucet, 'invite-issue', '--root', self.root / 'faucet', '--output', self.root / (who + '.invite'),
                '--expires-in', '3600', '--bind-fee', self.keys[who]['fee_address']])
            self.wallet('join', who, ['--invitation-file', self.root / (who + '.invite')], profile=True)
        relay_root = self.root / 'relay'; relay_root.mkdir(mode=0o700)
        payer = json.loads((self.root / 'sponsor.keypair.json').read_text())[32:]
        save(relay_root / 'config.json', dict(format='native-shielded-relay-v1',
            network={key: config[key] for key in ('network', 'genesis_hash')}, network_file=str(self.root / 'network.json'),
            rpc='http://127.0.0.1:18899', payer=payer, payer_file=str(self.root / 'sponsor.keypair.json'),
            binary=str(PROJECT / 'target/debug/native-shielded'), fee=3_000_000, gross_cap=150_000_000, max_jobs=8, per_member=8))
        self.start_gateway()
        for who in ('alice', 'bob'):
            for key in ('fee_address', 'public_address'):
                assert rpc(18899, 'getBalance', [self.keys[who][key]])['value'] == 0
        child = self.spawn_send(); child.wait(timeout=180)
        if child.returncode: raise RuntimeError('first shielded send failed; inspect retained send log')
        self.state(4)
        assert self.balance('alice') == 46_000_000 and self.balance('bob') == 1_000_000
        self.event('shielded_send_without_public_gas', sender=46_000_000, receiver=1_000_000, fee=3_000_000, nullifiers=4)

        # Lose the user acknowledgement, then kill the actual relay worker while
        # its real finalization is durably pending. Validators restart on the
        # original ledgers/towers after canonical acceptance, without a reset.
        old = {p.name for p in (relay_root / 'jobs').iterdir()}
        child = self.spawn_send(); job = self.next_job(old)
        pending = self.wait(lambda: json.loads((job / 'relay.pending.json').read_text()) if (job / 'relay.pending.json').exists() else None)
        child.kill(); child.wait(timeout=15)
        signature = pending['signature']
        self.wait(lambda: (rpc(18899, 'getSignatureStatuses', [[signature], dict(searchTransactionHistory=True)])['value'][0] or {}).get('confirmationStatus') == 'finalized')
        self.kill_gateway()
        expected = self.state(6)
        for i in (1, 0):
            self.children[i].kill(); self.children[i].wait(timeout=20); self.children[i] = None
        recovery = prepare(self.root)
        epoch = recovery.get('native_epoch_horizon_checkpoint')
        for i in (0, 1): self.children[i] = start(self.root, i, coordinated=True, epoch_horizon=epoch); wait_rpc(self.root, i)
        self.wait(lambda: durable(self.root, 0) == expected and durable(self.root, 1) == expected, 120)
        self.start_gateway()
        recovered = self.command(self.wallet_args('resolve', 'alice', True, 'native-shielded'))
        assert recovered['accepted'] and recovered['signature'] == signature
        self.state(6)
        assert self.balance('alice') == 42_000_000 and self.balance('bob') == 2_000_000
        assert len(list((relay_root / 'jobs').iterdir())) == 2
        self.event('lost_ack_relay_and_validator_crash_recovery', receipt=recovered, nullifiers=6)

        # Real interruption after durable staging initialization, before any
        # possible finalization. The relay closes its buffer on restart; no
        # shielded debit is charged. Keep the user proof until native expiry.
        old = {p.name for p in (relay_root / 'jobs').iterdir()}
        child = self.spawn_send(); job = self.next_job(old)
        self.wait(lambda: (job / 'relay.staging.json').exists())
        if (job / 'relay.pending.json').exists(): raise RuntimeError('partial-upload crash point missed')
        self.kill_gateway(); child.kill(); child.wait(timeout=15)
        self.start_gateway()
        self.wait(lambda: (job / 'outcome.json').exists())
        assert json.loads((job / 'outcome.json').read_text()).get('accepted') is False
        assert not (job / 'relay.staging.json').exists()
        self.command(self.wallet_args('resolve', 'alice', True, 'native-shielded'), expect='unresolved')
        assert Path(str(self.root / 'alice.wallet') + '.shielded.json').exists()
        assert durable(self.root, 0) == expected
        packet_value = json.loads((job / 'packet.json').read_text())
        expiry = int.from_bytes(base64.b64decode(packet_value['payload'])[40:48], 'little')
        self.event('partial_upload_crash_no_private_debit', expires_at=expiry, nullifiers=6)
        self.wait(lambda: rpc(18899, 'getSlot', [dict(commitment='finalized')]) > expiry + 1, 360)
        expired = self.command(self.wallet_args('resolve', 'alice', True, 'native-shielded'))
        assert expired['accepted'] is False and expired['expired_without_execution'] is True
        assert self.balance('alice') == 42_000_000 and self.balance('bob') == 2_000_000
        self.wallet('restore', 'alice-restored', ['--backup', self.root / 'alice.backup'])
        assert self.balance('alice-restored') == 42_000_000
        for who in ('alice', 'bob'):
            for key in ('fee_address', 'public_address'):
                assert rpc(18899, 'getBalance', [self.keys[who][key]])['value'] == 0
        self.state(6)
        self.event('expiry_and_seed_restore_exact', sender=42_000_000, receiver=2_000_000, nullifiers=6, public_user_gas=0)

    def close(self):
        self.kill_gateway()
        for child in self.wallets:
            if child.poll() is None: child.kill(); child.wait(timeout=15)
        for server, thread in self.services: server.shutdown(); server.server_close(); thread.join(timeout=5)
        if self.faucet: self.faucet.close()
        for i in (1, 0):
            if self.children[i] and self.children[i].poll() is None: stop(self.root, i)

    def restored_send(self):
        # Final compiled CLI/validator entrypoint, original ledgers and encrypted
        # backup restoration. This does not initialize a network or fund again.
        recovery = prepare(self.root)
        epoch = recovery.get('native_epoch_horizon_checkpoint')
        for i in (0, 1):
            self.children[i] = start(self.root, i, coordinated=True, epoch_horizon=epoch)
            wait_rpc(self.root, i)
        self.state(6)
        self.start_gateway()
        bob = self.wallet('address', 'bob')
        result = self.command(self.wallet_args('send', 'alice-restored', True, 'native-shielded') + [
            '--amount', '1000000', '--to', bob['address'], '--max-shielded-fee', '3000000'])
        assert result['accepted'] and result['shielded_fee'] == 3_000_000
        self.state(8)
        assert self.balance('alice-restored') == 38_000_000 and self.balance('bob') == 3_000_000
        alice = self.wallet('address', 'alice-restored')
        public = [v[key] for v in (alice, bob) for key in ('fee_address', 'public_address')]
        tx = rpc(18899, 'getTransaction', [result['signature'], dict(encoding='json', commitment='finalized', maxSupportedTransactionVersion=0)])
        assert not any(key in tx['transaction']['message']['accountKeys'] for key in public)
        assert all(rpc(18899, 'getBalance', [key])['value'] == 0 for key in public)
        from explorer_model import b58
        relay = json.loads((self.root / 'relay/config.json').read_text())
        payer = b58(bytes(relay['payer']))
        signatures = rpc(18899, 'getSignaturesForAddress', [payer, dict(limit=1000, commitment='finalized')])
        assert len(signatures) < 1000
        fees, records = 0, []
        for entry in signatures:
            transaction = rpc(18899, 'getTransaction', [entry['signature'], dict(encoding='json', commitment='finalized', maxSupportedTransactionVersion=0)])
            accounts = transaction['transaction']['message']['accountKeys']
            assert accounts[0] == payer and not any(key in accounts for key in public)
            fees += transaction['meta']['fee']
            records.append(dict(signature=entry['signature'], fee=transaction['meta']['fee'], failed=transaction['meta']['err'] is not None))
        config = load(self.root)
        owned = rpc(18899, 'getProgramAccounts', [config['program'], dict(encoding='base64', commitment='finalized')])
        markers = [entry for entry in owned if base64.b64decode(entry['account']['data'][0])[:8] == b'NSPENT01']
        assert len(markers) == 8
        assert not any(base64.b64decode(entry['account']['data'][0])[:8] == b'NBUF0001' for entry in owned)
        rent = sum(entry['account']['lamports'] for entry in markers)
        actual = rpc(18899, 'getBalance', [payer, dict(commitment='finalized')])['value']
        assert actual == 10_000_000_000 - 50_000_000 + 9_000_000 - rent - fees
        save(self.root / 'accounting-final.json', dict(initial_relay_balance=10_000_000_000, deposit_debit=50_000_000,
            shielded_fee_reimbursement=9_000_000, permanent_marker_rent=rent, actual_transaction_fees=fees,
            final_relay_balance=actual, transactions=records, user_public_accounts_absent_from_all_transactions=True,
            user_public_balances_zero=True, staging_accounts_remaining=0))
        self.event('restored_wallet_can_send_on_final_build', receipt=result, sender=38_000_000, receiver=3_000_000, nullifiers=8)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--resume-restored', action='store_true', help='one final-build send on the completed original fixture')
    args = parser.parse_args()
    import re
    if re.fullmatch('f54[a-z]', args.name) is None: raise ValueError('new f54 fixture name required')
    trial = Trial(args.name, resume=args.resume_restored)
    try:
        if args.resume_restored: trial.restored_send()
        else: trial.run()
    finally:
        trial.close()


if __name__ == '__main__': main()
