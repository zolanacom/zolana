#!/usr/bin/env python3
"""Bounded stdin-controlled Linux fixture for Mac WAN acceptance, never a daemon API.

Only public profiles, invitation capabilities and public ledger observations leave
this process. Validator/faucet keys and their passwords remain on the Linux host.
"""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import base64
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'tools'))
from pilot_runtime_localnet import PilotHost
from localnet import LAB, load, quiet, rpc, start, stop, wait_rpc
from fault_localnet import account, durable
from local_test_tls import create as create_tls
from package_wallet import public_profile
import pilot_cohort as cohort
import pilot_funding as funding
import pilot_runtime as runtime
from rpc_isolation import enable
from wallet_localnet import private_new
from wallet_release import create, encode, read, sha


class Host(PilotHost):
    def resume_wan(self, binding):
        # Validate the existing sealed identities and code pins. This path never
        # initializes/funds a network or renews its original historical receipt.
        with runtime.checked(self.root, binding) as checked:
            config, value = checked[0], checked[1]
        self.binding = binding
        self.cohort_root = Path(config['cohort_root'])
        self.plan_digest = config['plan_sha256']
        value = cohort.checked(self.cohort_root, self.plan_digest)
        self.profile = value['tester_profile']
        issued = cohort.issuance(self.cohort_root, value)
        keys = [issued['slots'][name]['bind_fee'] for name in sorted(issued['slots'])]
        if len(keys) != 2 or any(not public_key(key) for key in keys):
            raise ValueError('original two-wallet cohort required for continuation')
        self.issued = dict(fee_addresses=keys)
        self.start_host()
        return dict(profile=self.profile, binding_sha256=binding, cohort_size=2,
                    raw_rpc='private-unix-only', resumed_original=True)

    def prepare_wan(self):
        root = self.root
        if root.exists():
            raise ValueError('WAN acceptance requires a fresh fixture; never reset existing state')
        operator = self.evidence / 'operator'
        operator.mkdir(mode=0o700)
        self.password = secrets.token_urlsafe(36)
        self.password_file = operator / 'faucet.password'
        cold, hot = operator / 'cold.password', operator / 'sponsor.password'
        for path in (cold, hot):
            private_new(path, secrets.token_urlsafe(36).encode())
        private_new(self.password_file, self.password.encode())
        self.command([str(LAB), 'init-private', str(root), '--cold-password-file', str(cold), '--sponsor-password-file', str(hot)])
        enable(root, hardened=True)
        for index in (0, 1):
            self.children[index] = start(root, index)
            wait_rpc(root, index)
        quiet(root)
        self.converge(0)
        self.wait_for(self.ready_history, timeout=45)
        config = load(root)
        self.tls = self.evidence / 'tls'
        create_tls(self.tls)
        source = public_profile(config, 'Zolana Mac WAN acceptance', 'http://127.0.0.1:18899', 'loopback-http')
        tester = public_profile(config, 'Zolana Mac WAN acceptance', 'https://127.0.0.1:28898', 'https')
        tester.update(invite_required=True, faucet=dict(transport='https', url='https://127.0.0.1:23781'),
                      local_tls_ca_pem=(self.tls / 'ca.crt').read_text())
        plan = cohort.plan(source, tester, count=2, daily=2)
        self.plan_digest = sha(encode(plan))
        self.cohort_root = root / 'pilot'
        prepared = cohort.prepare(plan, self.cohort_root, self.plan_digest, self.password_file,
                                  rpc_access_file=root / 'rpc-access.key')
        self.faucet_root = self.cohort_root / 'faucet'
        self.source = self.faucet_root / 'wallet.enc.json'
        receipt = self.command([str(PROJECT / 'target/debug/native-wallet'), 'deposit', '--network', str(root / 'network.json'),
            '--wallet', str(self.source), '--password-file', str(self.password_file), '--rpc', source['rpc']['url'],
            '--rpc-access-file', str(root / 'rpc-access.key'), '--sponsor-password-file', str(hot),
            '--sponsor-request-id', 'mac-wan-initial-reservoir', '--amount', '5000000'])
        self.closed(receipt['staging_account'])
        # The legacy single-wallet 1B grant is below a two-slot conservative
        # reserve. Use the existing exact, separately signed pilot allocation;
        # admission still limits this disposable fixture to two lifetime slots.
        signed = self.command([str(LAB), 'pilot-treasury-sign', str(root), str(self.source),
                               str(self.password_file), str(cold), source['rpc']['url']])
        create(self.evidence / 'treasury-signed.json', encode(signed))
        signature = rpc(18899, 'sendTransaction', [base64.b64encode(bytes(signed['transaction'])).decode(),
                        dict(encoding='base64', maxRetries=0, preflightCommitment='confirmed')])
        if signature != signed['signature'] or signed['amount'] != 6_000_300_000:
            raise ValueError('original bounded pilot allocation changed')
        self.wait_for(lambda: self.native_balance(prepared['fee_address']) == signed['amount'])
        funding.make_intent(self.cohort_root, self.plan_digest)
        funding.verify(self.cohort_root, self.plan_digest, self.password_file, 'initial')
        listeners = {}
        for name, port in (('rpc', 28898), ('faucet', 23781)):
            path = self.evidence / (name + '-listener.json')
            create(path, encode(dict(format='zolana-direct-tls-v1', audience=tester[name]['url'], port=port,
                bind_ip='127.0.0.1', certificate_sha256=sha((self.tls / 'server.crt').read_bytes()),
                key_sha256=sha((self.tls / 'server.key').read_bytes()))))
            listeners[name] = dict(config=str(path), sha256=sha(path.read_bytes()),
                                   cert=str(self.tls / 'server.crt'), key=str(self.tls / 'server.key'))
        self.binding = runtime.prepare(root, self.cohort_root, self.plan_digest, 'initial', self.password_file, listeners)['binding_sha256']
        for index in (1, 0):
            stop(root, index)
        self.children = [None, None]
        for name in ('sponsor.enc.json', 'sponsor-policy.json', 'sponsor-policy.json.reservations.json'):
            (root / name).rename(root / (name + '.disabled'))
        self.start_host()
        self.issued = None
        self.profile = tester
        return dict(profile=tester, binding_sha256=self.binding, cohort_size=2, raw_rpc='private-unix-only')

    def issue_wan(self, keys):
        if not isinstance(keys, list) or len(keys) != 2 or len(set(keys)) != 2 or any(not public_key(k) for k in keys):
            raise ValueError('requires two distinct Mac-generated public fee authorities')
        if self.issued is not None:
            if keys != self.issued['fee_addresses']:
                raise ValueError('original invitation authorities changed')
            return self.issued
        exports = []
        for index, key in enumerate(keys):
            label = 'mac-' + str(index + 1)
            cohort.issue(self.cohort_root, self.plan_digest, label, bind_fee=key)
            exports.append(json.loads(read(self.cohort_root / 'invitations' / (label + '.json'), 16384, secret=True)))
        self.issued = dict(fee_addresses=keys, invitations=exports)
        return self.issued

    def snapshot_wan(self):
        states = [durable(self.root, index) for index in (0, 1)]
        if states[0] != states[1]:
            raise ValueError('peers have not reached the same finalized native state')
        return dict(permanent_nullifiers=len(states[0]) - 1, state_sha256=sha(encode(states[0])),
                    finalized_slots=self.slots(), fee_balances={key: self.native_balance(key)
                    for key in (self.issued or {}).get('fee_addresses', [])})

    def observe(self, request):
        signature, buffer = request.get('signature'), request.get('buffer')
        commitment = request.get('commitment', 'finalized')
        if commitment not in ('processed', 'confirmed', 'finalized'):
            raise ValueError('invalid observation commitment')
        result = {}
        if signature is not None:
            if not isinstance(signature, str) or not re.fullmatch('[1-9A-HJ-NP-Za-km-z]{64,88}', signature):
                raise ValueError('invalid public signature')
            result['statuses'] = [rpc(18899 + i * 1000, 'getSignatureStatuses', [[signature], {'searchTransactionHistory': True}])['value'][0] for i in (0, 1)]
        if buffer is not None:
            if not public_key(buffer):
                raise ValueError('invalid public staging account')
            values = []
            for index in (0, 1):
                value = account(index, buffer, commitment)
                if value is None:
                    values.append(None)
                else:
                    raw = base64.b64decode(value['data'][0], validate=True)
                    if raw[:8] != b'NBUF0001':
                        raise ValueError('unexpected staging account format')
                    values.append(dict(length=int.from_bytes(raw[40:44], 'little'), received=int.from_bytes(raw[44:48], 'little'),
                                       state=raw[88], account_sha256=sha(encode(value))))
            result['staging'] = values
        return result


def public_key(value):
    return isinstance(value, str) and re.fullmatch('[1-9A-HJ-NP-Za-km-z]{32,44}', value) is not None


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--resume-binding')
    args = parser.parse_args()
    if not re.fullmatch('s52[a-z]', args.name):
        parser.error('use a new bounded WAN acceptance fixture name')
    root = PROJECT / '.data' / args.name
    suffix = '-wan' if args.resume_binding is None else '-wan-resume-' + secrets.token_hex(4)
    evidence = PROJECT / '.local' / (args.name + suffix)
    if (args.resume_binding is None and root.exists()) or evidence.exists():
        parser.error('preserve the existing fixture and evidence; never rerun/reset it')
    evidence.mkdir(mode=0o700)
    trial = Host(root, evidence, None, None)
    protocol = sys.stdout
    def interrupted(*_):
        raise TimeoutError('bounded WAN host lifetime ended')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(1800)
    prepared = False
    try:
        with (evidence / 'controller.log').open('x') as log, redirect_stdout(log), redirect_stderr(log):
            for line in sys.stdin:
                if len(line) > 32768:
                    raise ValueError('control request exceeds limit')
                request = json.loads(line)
                action = request.get('action')
                try:
                    if action == 'prepare' and not prepared:
                        result = trial.prepare_wan() if args.resume_binding is None else trial.resume_wan(args.resume_binding)
                        prepared = True
                    elif action == 'close':
                        result = dict(stopping=True)
                    elif prepared and action == 'issue':
                        result = trial.issue_wan(request.get('fee_addresses'))
                    elif prepared and action == 'snapshot':
                        result = trial.snapshot_wan()
                    elif prepared and action == 'observe':
                        result = trial.observe(request)
                    elif prepared and action == 'restart':
                        before = trial.snapshot_wan()
                        trial.stop_host(crash=True)
                        trial.start_host()
                        result = trial.snapshot_wan()
                        if result['state_sha256'] != before['state_sha256'] or min(result['finalized_slots']) <= max(before['finalized_slots']):
                            raise ValueError('runtime restart changed native state or did not advance finality')
                        result['whole_host_sigkill'] = True
                    else:
                        raise ValueError('unsupported control action or phase')
                    response = dict(id=request.get('id'), ok=True, result=result)
                except Exception as error:
                    response = dict(id=request.get('id'), ok=False, error=str(error))
                protocol.write('WAN052 ' + json.dumps(response) + '\n')
                protocol.flush()
                if action == 'close':
                    break
    finally:
        signal.alarm(0)
        with (evidence / 'shutdown.log').open('x') as log, redirect_stdout(log), redirect_stderr(log):
            trial.close()


if __name__ == '__main__':
    main()
