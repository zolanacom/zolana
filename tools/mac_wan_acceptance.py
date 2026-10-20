#!/usr/bin/env python3
"""Owned Mac wallet -> pinned SSH -> invited Linux HTTPS acceptance.

No Mac validators, public listeners, existing wallet mutation or automatic payment
retries. All private evidence stays in a fresh owner-only directory.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import secrets
import signal
import socket
import subprocess
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

from wallet_ui import Handler, WalletApp

PROJECT = Path(__file__).resolve().parents[1]


def save(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('wb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    temporary.replace(path)


class Trial:
    def __init__(self, directory, binary, name):
        self.directory, self.binary, self.name = directory, binary, name
        key = PROJECT / '.local/remote-host'
        self.ssh = ['ssh', '-F', '/dev/null', '-i', str(key / 'ssh_identity'),
                    '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(key / 'known_hosts'),
                    '-o', 'ConnectTimeout=20', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2']
        self.control = self.forward = self.server = None
        self.children, self.logs = [], []
        self.responses = queue.Queue()
        self.sequence = 0
        self.result = dict(status='running', transport='Mac -> pinned SSH forwarding -> invited HTTPS on remote Linux',
                           mac_validators_started=False, events=[])

    def event(self, kind, **fields):
        self.result['events'].append(dict(kind=kind, **fields))
        save(self.directory / 'result.json', self.result)
        print(json.dumps(dict(event=kind, **fields)), flush=True)

    def start_control(self):
        resumed = getattr(self, 'resume_binding', None)
        generation = '-recovery-' + str(time.time_ns()) if resumed else ''
        log = (self.directory / ('control-ssh' + generation + '.log')).open('xb'); self.logs.append(log)
        self.result['last_control_unit'] = 'zolana-mac-wan-' + self.name + generation
        self.control = subprocess.Popen(self.ssh + ['root@validator.example',
            'systemd-run', '--pipe', '--quiet', '--wait', '--unit=' + self.result['last_control_unit'],
            '--uid=builder', '--gid=builder', '--working-directory=/srv/zolana-live-src',
            '--property=Nice=15', '--property=MemoryMax=140G', '--property=CPUQuota=1200%',
            '--property=TasksMax=4096', '--property=LimitNOFILE=1048576', '--property=KillMode=control-group',
            '--property=RuntimeMaxSec=2000', '/usr/bin/python3', '-B',
            '/srv/zolana-live-src/.local/wan_host_control-052.py', '--name', self.name,
            *(['--resume-binding', resumed] if resumed else [])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
        def reader():
            for line in self.control.stdout:
                if line.startswith('WAN052 '):
                    self.responses.put(json.loads(line[7:]))
            self.responses.put(dict(eof=True))
        threading.Thread(target=reader, daemon=True).start()

    def request(self, action, timeout=45, **fields):
        self.sequence += 1
        self.control.stdin.write(json.dumps(dict(id=self.sequence, action=action, **fields)) + '\n')
        self.control.stdin.flush()
        reply = self.responses.get(timeout=timeout)
        if reply.get('eof') or reply.get('id') != self.sequence:
            raise RuntimeError('bounded host control closed or response identity changed')
        if not reply['ok']:
            raise RuntimeError(reply['error'])
        return reply['result']

    def start_forward(self):
        for port in (28898, 23781):
            with socket.socket() as probe:
                # Match OpenSSH's listener policy: a dead owned connection in
                # TIME_WAIT is reusable; a live listener still fails this bind.
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                probe.bind(('127.0.0.1', port))
        log = (self.directory / ('forward-' + str(time.time_ns()) + '.log')).open('xb'); self.logs.append(log)
        self.forward = subprocess.Popen(self.ssh + ['-o', 'ExitOnForwardFailure=yes', '-N',
            '-L', '127.0.0.1:28898:127.0.0.1:28898', '-L', '127.0.0.1:23781:127.0.0.1:23781',
            'root@validator.example'], stdout=log, stderr=log)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.forward.poll() is not None:
                raise RuntimeError('owned HTTPS forwarding failed')
            with socket.socket() as probe:
                if probe.connect_ex(('127.0.0.1', 28898)) == 0:
                    return
            time.sleep(.05)
        raise TimeoutError('owned forwarding readiness')

    def drop_forward(self):
        if self.forward is not None:
            self.forward.kill(); self.forward.wait(timeout=10); self.forward = None

    def snapshot(self, nullifiers):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                value = self.request('snapshot')
                if value['permanent_nullifiers'] == nullifiers:
                    return value
            except RuntimeError as error:
                if str(error) != 'peers have not reached the same finalized native state':
                    raise
            time.sleep(.3)
        raise RuntimeError('both peers did not reach exact expected nullifiers')

    def user(self, who, action, **fields):
        return self.apps[who].action(dict(action=action, password=self.password, **fields))

    def balances(self, amounts):
        values = {who: self.user(who, 'balance')['balance'] for who in ('sender', 'receiver')}
        if values != amounts:
            raise RuntimeError('Mac decrypted private balances differ: ' + repr(values))
        return values

    def streaming_send(self, amount):
        quote = self.user('sender', 'fees', payment='send')
        began = time.monotonic(); frames = []
        request = urllib.request.Request('http://' + self.server.authority + '/api/wallet',
            json.dumps(dict(action='send', password=self.password, recipient=self.keys['receiver']['address'],
                amount=amount, fee_mode='user', max_fee_debit=quote['maximum_gross_debit'])).encode(),
            {'Content-Type': 'application/json', 'Origin': 'http://' + self.server.authority,
             'X-Wallet-Token': self.apps['sender'].token, 'Accept': 'application/x-ndjson'})
        terminal = None
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=180) as reply:
            for line in reply:
                value = json.loads(line)
                frames.append(dict(seconds=round(time.monotonic() - began, 4), **value))
                if 'error' in value:
                    raise RuntimeError(value['error'])
                if 'result' in value:
                    terminal = value['result']
        if terminal is None or self.apps['sender'].status()['pending'] or self.apps['sender'].status()['staging']:
            raise RuntimeError('stream did not return a settled payment')
        return dict(seconds=round(time.monotonic() - began, 4), frames=frames, receipt=terminal)

    def spawn_send(self, label):
        app = self.apps['sender']; quote = self.user('sender', 'fees', payment='send')
        args = [str(self.binary), 'send', '--network', str(app.network_file), '--wallet', str(app.wallet),
                '--password-file', '-', '--fee-payer', 'user', '--max-fee-debit', str(quote['maximum_gross_debit']),
                '--amount', '10000', '--to', self.keys['receiver']['address']]
        out = (self.directory / (label + '.stdout')).open('xb')
        err = (self.directory / (label + '.stderr')).open('xb'); self.logs.extend((out, err))
        child = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                 env=dict(os.environ, RAYON_NUM_THREADS='2', NATIVE_WALLET_PROGRESS='1'))
        self.children.append(child); child.stdin.write(self.password.encode()); child.stdin.close()
        return child

    def wait_file(self, path, child, timeout=40):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return json.loads(path.read_text())
            if child.poll() is not None:
                raise RuntimeError('owned wallet exited before fault point')
            time.sleep(.002)
        raise TimeoutError('wallet did not reach selected journal point')

    def retain(self, label, *paths):
        for path in paths:
            if path.exists():
                (self.directory / (label + '-' + path.name)).write_bytes(path.read_bytes())

    def interrupted(self, child, label):
        self.drop_forward()
        child.send_signal(signal.SIGCONT)
        code = child.wait(timeout=45)
        if code == 0:
            raise RuntimeError('disconnected CLI unexpectedly reported successful finality')
        self.event(label + '_connection_dropped', cli_returncode=code)

    def run(self):
        began = time.monotonic()
        self.start_control()
        prepared = self.request('prepare', timeout=480)
        self.event('linux_fixture_ready', binding_sha256=prepared['binding_sha256'])
        profile = self.directory / 'profile.json'; save(profile, prepared['profile'])
        self.start_forward()
        self.password = secrets.token_urlsafe(36)
        # Isolated test credentials remain owner-only for failed-run recovery.
        # They are never an existing user's password or passed in process args.
        (self.directory / 'fixture-password').write_text(self.password)
        self.apps = {who: WalletApp.from_profile(profile, self.directory / who, binary=self.binary) for who in ('sender', 'receiver')}
        self.keys = {who: self.user(who, 'create') for who in self.apps}
        for who in self.apps:
            self.user(who, 'ack-backup')
        invitations = self.request('issue', fee_addresses=[self.keys[who]['fee_address'] for who in self.apps])
        claims = {}
        for who, invitation in zip(self.apps, invitations['invitations']):
            claims[who] = self.user(who, 'join', invitation=invitation['invitation'])
        deadline = time.monotonic() + 180
        for who in self.apps:
            while time.monotonic() < deadline:
                claim = self.user(who, 'test-coins')
                if claim.get('gas_finalized') and claim.get('private_finalized'):
                    claims[who] = claim; break
                time.sleep(2)
            else:
                raise TimeoutError('Mac invitation funding did not finalize')
        self.claims = claims
        cold = time.monotonic(); initial = self.balances(dict(sender=1000000, receiver=1000000))
        self.event('mac_onboarding_and_funding', balances=initial, first_balance_pair_seconds=round(time.monotonic()-cold, 4),
                   snapshot=self.snapshot(6))
        self.server = ThreadingHTTPServer(('127.0.0.1', 18772), Handler)
        self.server.authority = '127.0.0.1:18772'; self.server.app = self.apps['sender']
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        for index in range(3):
            sent = self.streaming_send(10000)
            save(self.directory / ('normal-' + str(index + 1) + '.json'), sent)
            self.event('mac_wan_private_send', number=index + 1, seconds=sent['seconds'], receipt=sent['receipt'],
                       phases=[dict(seconds=f['seconds'], phase=f['progress']) for f in sent['frames'] if 'progress' in f])
        before = self.snapshot(12)
        self.balances(dict(sender=970000, receiver=1030000))
        app = self.apps['sender']; stage = Path(str(app.wallet) + '.staging.json'); pending = Path(str(app.wallet) + '.pending.json')
        child = self.spawn_send('staging-drop'); record = self.wait_file(stage, child)
        child.send_signal(signal.SIGSTOP)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            observed = self.request('observe', buffer=record['staging_account'], commitment='processed')
            if any(value and 0 < value['received'] < value['length'] for value in observed['staging']):
                break
            child.send_signal(signal.SIGCONT); time.sleep(.015); child.send_signal(signal.SIGSTOP)
        else:
            raise RuntimeError('could not capture real partial staging prefix')
        if pending.exists():
            raise RuntimeError('partial upload reached payment broadcast')
        self.retain('partial-before-drop', stage)
        self.interrupted(child, 'partial_upload')
        self.retain('partial-after-drop', stage)
        if not stage.exists() or pending.exists() or self.snapshot(12)['state_sha256'] != before['state_sha256']:
            raise RuntimeError('partial transport loss changed value state or lost journal')
        self.start_forward()
        self.finish_recovery(profile, began, observed)

    def resume_partial(self):
        previous = json.loads((self.directory / 'result.json').read_text())
        allowed = {'OSError: [Errno 48] Address already in use',
                   'ValueError: Resolve the previous payment before requesting test coins.'}
        if (previous.get('status') != 'failed' or previous.get('error') not in allowed
                or [e['kind'] for e in previous['events']].count('mac_wan_private_send') != 3
                or not any(e['kind'] == 'partial_upload_connection_dropped' for e in previous['events'])):
            raise ValueError('only the original retained partial-upload port-reuse checkpoint may continue')
        original = self.directory / ('interrupted-run-result-' + str(time.time_ns()) + '.json')
        with original.open('xb') as saved:
            saved.write((self.directory / 'result.json').read_bytes())
        self.result = previous
        failure = self.result.pop('error')
        self.result.setdefault('prior_harness_errors', []).append(failure)
        self.result.update(status='running')
        self.resume_binding = next(e['binding_sha256'] for e in previous['events'] if e['kind'] == 'linux_fixture_ready')
        began = time.monotonic(); profile = self.directory / 'profile.json'
        self.password = (self.directory / 'fixture-password').read_text()
        self.apps = {who: WalletApp.from_profile(profile, self.directory / who, binary=self.binary) for who in ('sender', 'receiver')}
        stage = Path(str(self.apps['sender'].wallet) + '.staging.json')
        if (Path(str(self.apps['sender'].wallet) + '.pending.json').exists()
                or stage.read_bytes() != (self.directory / 'partial-after-drop-wallet.json.staging.json').read_bytes()):
            raise ValueError('original retained staging journal changed')
        self.start_control(); prepared = self.request('prepare', timeout=300)
        if prepared['profile'] != json.loads(profile.read_text()) or not prepared.get('resumed_original'):
            raise ValueError('continuation changed original profile')
        self.start_forward()
        self.keys = {who: self.user(who, 'unlock') for who in self.apps}
        # Reuse the protocol's deterministic claim identity without trying a
        # funding action while the original staging recovery is outstanding.
        self.claims = {who: dict(claim_id=hashlib.blake2b(self.keys[who]['fee_address'].encode(), digest_size=32).hexdigest())
                       for who in self.apps}
        self.snapshot(12); self.balances(dict(sender=970000, receiver=1030000))
        record = json.loads(stage.read_text())
        observed = self.request('observe', buffer=record['staging_account'])
        if not all(v and 0 < v['received'] < v['length'] for v in observed['staging']):
            raise ValueError('original partial prefix did not survive runtime restart')
        self.event('original_partial_checkpoint_resumed', original_binding_sha256=self.resume_binding, observed_prefix=observed)
        self.finish_recovery(profile, began, observed)

    def finish_recovery(self, profile, began, observed):
        app = self.apps['sender']
        stage = Path(str(app.wallet) + '.staging.json'); pending = Path(str(app.wallet) + '.pending.json')
        reclaimed = self.user('sender', 'reclaim')
        if stage.exists() or pending.exists():
            raise RuntimeError('partial staging recovery did not settle')
        self.balances(dict(sender=970000, receiver=1030000))
        self.event('partial_upload_recovered', observed_prefix=observed, reclaim=reclaimed, snapshot=self.snapshot(12))
        before_claims = self.snapshot(12)
        for who in self.apps:
            claim = self.user(who, 'test-coins')
            if (claim['claim_id'] != self.claims[who]['claim_id'] or not claim['gas_finalized'] or not claim['private_finalized']):
                raise ValueError('original completed invitation grant changed')
        if self.snapshot(12)['fee_balances'] != before_claims['fee_balances']:
            raise ValueError('original completed grants duplicated gas')
        child = self.spawn_send('finality-drop'); payment = self.wait_file(pending, child)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            statuses = self.request('observe', signature=payment['signature'])['statuses']
            if any(s and s['err'] is None and s['confirmationStatus'] == 'confirmed' for s in statuses):
                child.send_signal(signal.SIGSTOP); break
            time.sleep(.05)
        else:
            raise RuntimeError('payment did not reach actual confirmed crash point')
        self.retain('confirmed-before-drop', pending, stage)
        self.interrupted(child, 'confirmed_payment')
        if not pending.exists():
            raise RuntimeError('unknown outcome discarded original pending signature')
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            value = self.request('observe', signature=payment['signature'], buffer=payment['staging_account'])
            if all(s and s['err'] is None and s['confirmationStatus'] == 'finalized' for s in value['statuses']) and value['staging'] == [None, None]:
                break
            time.sleep(.3)
        else:
            raise RuntimeError('original disconnected payment did not finalize exactly once')
        final = self.snapshot(14)
        restarted = self.request('restart', timeout=240)
        if restarted['state_sha256'] != final['state_sha256']:
            raise RuntimeError('host crash changed finalized native state')
        self.start_forward()
        self.apps['sender'] = WalletApp.from_profile(profile, self.directory / 'sender', binary=self.binary)
        resolved = self.user('sender', 'resolve'); cleanup = self.user('sender', 'reclaim')
        if pending.exists() or stage.exists() or cleanup.get('close_signature') is not None:
            raise RuntimeError('finalized atomic close was duplicated or journal unresolved')
        after = self.snapshot(14)
        if after['state_sha256'] != final['state_sha256'] or after['fee_balances'] != final['fee_balances']:
            raise RuntimeError('resolution resubmitted payment or charged additional fees')
        self.event('confirmed_drop_and_linux_sigkill_recovered', original_signature=payment['signature'],
                   resolution=resolved, reclaim=cleanup, snapshot=after)
        self.balances(dict(sender=960000, receiver=1040000))
        restored = WalletApp.from_profile(profile, self.directory / 'restored', binary=self.binary)
        recovered = restored.action(dict(action='restore', password=self.password, backup=json.loads(app.backup.read_text())))
        claim = restored.action(dict(action='test-coins', password=self.password))
        balance = restored.action(dict(action='balance', password=self.password))
        restored_state = self.snapshot(14)
        if (recovered['fee_address'] != self.keys['sender']['fee_address'] or claim['claim_id'] != self.claims['sender']['claim_id']
                or balance['balance'] != 960000 or restored_state['state_sha256'] != after['state_sha256']
                or restored_state['fee_balances'] != after['fee_balances']):
            raise RuntimeError('Mac encrypted seed restore changed identity, grant or private balance')
        self.result.update(status='passed', elapsed_seconds=round(time.monotonic()-began, 3), permanent_nullifiers=14,
                           private_balances=dict(sender=960000, receiver=1040000), host_sigkill=True, seed_restore=True)
        self.event('mac_wan_acceptance_passed')

    def close(self):
        if self.server:
            self.server.shutdown(); self.server.server_close()
        for child in self.children:
            if child.poll() is None:
                child.send_signal(signal.SIGCONT); child.kill(); child.wait(timeout=10)
        self.drop_forward()
        if self.control:
            try:
                self.request('close', timeout=120)
                self.control.stdin.close(); self.control.wait(timeout=120)
                self.result['host_shutdown_returncode'] = self.control.returncode
            except Exception as error:
                self.result['shutdown_error'] = str(error)
                self.control.terminate()
                self.control.wait(timeout=30)
        for log in self.logs:
            log.close()
        save(self.directory / 'result.json', self.result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--name', choices=['s52' + c for c in 'abcdefghijklmnopqrstuvwxyz'], required=True)
    parser.add_argument('--resume-partial', action='store_true')
    args = parser.parse_args()
    os.umask(0o077); os.environ['RAYON_NUM_THREADS'] = '2'
    if not args.resume_partial:
        args.directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    trial = Trial(args.directory.resolve(), args.binary.resolve(), args.name)
    try:
        trial.resume_partial() if args.resume_partial else trial.run()
    except BaseException as error:
        trial.result.update(status='failed', error=type(error).__name__ + ': ' + str(error))
        trial.event('acceptance_failed', error=trial.result['error'])
        raise
    finally:
        trial.close()


if __name__ == '__main__':
    main()
