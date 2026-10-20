#!/usr/bin/env python3
"""Owned synthetic Mac -> pinned SSH -> Linux native-ingress acceptance.

No Mac validators, public listeners, existing wallet inputs or Linux process kills.
Preserves its complete fixture and private evidence, including on failure.

The SSH endpoint is operator configuration: ZOLANA_PILOT_SSH_TARGET (user@host),
ZOLANA_PILOT_SSH_IDENTITY (private key file) and ZOLANA_PILOT_SSH_KNOWN_HOSTS
(pinned host keys). All three are required; nothing is contacted by default.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time

PROJECT = Path(__file__).resolve().parents[1]
SSH_SETTINGS = ('ZOLANA_PILOT_SSH_TARGET', 'ZOLANA_PILOT_SSH_IDENTITY', 'ZOLANA_PILOT_SSH_KNOWN_HOSTS')


def pilot_ssh():
    """Operator-supplied pinned SSH endpoint; no host or key location is built in."""
    target, identity, known_hosts = (os.environ.get(name, '') for name in SSH_SETTINGS)
    if (target.count('@') != 1 or '' in target.split('@') or target.startswith('-')
            or any(character.isspace() for character in target)):
        raise ValueError('set ZOLANA_PILOT_SSH_TARGET to the operator user@host')
    for name, value in zip(SSH_SETTINGS[1:], (identity, known_hosts)):
        if not value or not Path(value).is_file():
            raise ValueError('set ' + name + ' to the existing operator file')
    return target, identity, known_hosts


def save(path, value):
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('w') as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write('\n'); output.flush(); os.fsync(output.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def host_ready(path):
    raw = path.read_text()
    try: values = [json.loads(raw)]
    except json.JSONDecodeError: values = [json.loads(line) for line in raw.splitlines() if line.strip()]
    matches = [value['data'] for value in values if value.get('event') == 'external_mac_fixture_ready']
    value = matches[-1] if matches else values[-1]
    peers = value.get('peers', [])
    if not 1 <= len(peers) <= 3 or not value.get('mac_relay'):
        raise ValueError('reviewed held Mac fixture with one to three peers required')
    endpoints = [value['peers'][0]['rpc']] + [peer['native_ingress'] for peer in peers]
    for endpoint in endpoints:
        host, port = endpoint.rsplit(':', 1)
        if host != '127.0.0.1' or not 0 < int(port) <= 65535:
            raise ValueError('host evidence must name loopback RPC/native listeners')
    return value, endpoints


class Trial:
    def __init__(self, args):
        self.args, self.root = args, args.output
        self.host, self.remote = host_ready(args.host_evidence)
        self.client = self.forward = self.proxy = None
        self.logs, self.sequence, self.generation = [], 0, 0
        self.result = dict(status='running', mac_validators_started=False, events=[],
            prover_threads=getattr(args, 'prover_threads', 2),
            scope='Mac local proving/decryption/durable recovery; pinned SSH and trusted RPC, not TLS/mobile/light-client finality',
            binary_sha256=hashlib.sha256(args.binary.read_bytes()).hexdigest(), network=self.host['network'])
        self.ssh_target, identity, known_hosts = pilot_ssh()
        self.ssh = ['ssh', '-F', '/dev/null', '-i', identity,
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + known_hosts, '-o', 'ConnectTimeout=20',
            '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2']

    def event(self, kind, **fields):
        self.result['events'].append(dict(kind=kind, **fields)); save(self.root / 'result.json', self.result)
        print(json.dumps(dict(event=kind, **fields)), flush=True)

    def log(self, name):
        output = (self.root / name).open('xb'); self.logs.append(output); return output

    def start_forward(self):
        for attempt in range(3):
            try:
                return self.start_forward_once()
            except (RuntimeError, TimeoutError) as exception:
                self.stop_forward()
                self.event('ssh_forward_connect_retry', attempt=attempt + 1, reason=str(exception))
                if attempt == 2:
                    raise
                time.sleep(.25)

    def start_forward_once(self):
        reservations = [socket.socket() for _ in self.remote]
        for reservation in reservations: reservation.bind(('127.0.0.1', 0))
        self.local = [reservation.getsockname()[1] for reservation in reservations]
        for reservation in reservations: reservation.close()
        command = self.ssh + ['-N']
        for local, remote in zip(self.local, self.remote):
            command += ['-L', '127.0.0.1:' + str(local) + ':' + remote]
        output = self.log('ssh-' + str(time.time_ns()) + '.log')
        self.forward = subprocess.Popen(command + [self.ssh_target], stdout=output, stderr=output)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.forward.poll() is not None: raise RuntimeError('owned pinned SSH forward exited')
            with socket.socket() as probe:
                if probe.connect_ex(('127.0.0.1', self.local[0])) == 0: return
            time.sleep(.05)
        raise TimeoutError('owned SSH forward readiness')

    def stop_forward(self):
        process = self.forward
        if process is not None and process.poll() is None:
            process.kill(); process.wait(timeout=10)
        self.forward = None

    def profile(self, ingress=None):
        save(self.root / 'profile.json', dict(format='zolana-fast-fixture-v1',
            network=self.host['network'], pool_format=self.host['pool_format'],
            rpc='http://127.0.0.1:' + str(self.local[0]),
            ingress=ingress or ['127.0.0.1:' + str(port) for port in self.local[1:]],
            relay_keypair=str(self.args.relay_keypair), shielded_fee=2))

    def start_client(self, resume=False):
        self.generation += 1; self.responses = queue.Queue(maxsize=64)
        output = self.log('client-' + str(self.generation) + '.stdout')
        error = self.log('client-' + str(self.generation) + '.stderr')
        command = [str(self.args.binary), 'serve', '--profile', str(self.root / 'profile.json'),
            '--directory', str(self.root / 'wallets'), '--password-file', str(self.args.password_file)]
        if resume: command += ['--resume']
        self.client = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=error, cwd=PROJECT, env=dict(os.environ,
                RAYON_NUM_THREADS=str(getattr(self.args, 'prover_threads', 2)), NATIVE_WALLET_PROGRESS='1'))
        process, responses = self.client, self.responses
        def reader():
            try:
                while True:
                    line = process.stdout.readline(131073)
                    if not line: break
                    output.write(line); output.flush()
                    if len(line) > 131072 or not line.endswith(b'\n'): raise ValueError('oversized client frame')
                    value = json.loads(line)
                    if 'wallet_progress' not in value: responses.put(value, timeout=5)
            except Exception as exception: responses.put(dict(reader_error=str(exception)), timeout=5)
            finally: responses.put(dict(eof=True), timeout=5)
        threading.Thread(target=reader, daemon=True).start()

    def stop_client(self, crash=False):
        process = self.client
        if process is not None and process.poll() is None:
            if crash: process.kill()
            else:
                try: process.stdin.close()
                except BrokenPipeError: pass
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired: process.kill(); process.wait(timeout=10)
        self.client = None
        return process.returncode if process is not None else None

    def request(self, op, allow_error=False, **fields):
        self.sequence += 1
        self.client.stdin.write((json.dumps(dict(id=self.sequence, op=op, **fields)) + '\n').encode())
        self.client.stdin.flush()
        value = self.responses.get(timeout=240)
        if value.get('id') != self.sequence: raise RuntimeError('client closed or response identity changed: ' + repr(value))
        if 'error' in value and not allow_error: raise RuntimeError(value['error'])
        return value if allow_error else value['result']

    def intent(self): return self.root / 'wallets/alice.wallet.native.json'

    def balances(self, expected):
        states = {name: self.request('sync', wallet=name) for name in ('alice', 'bob', 'charlie')}
        actual = {name: value['balance'] for name, value in states.items()}
        if actual != expected or not all(value['encrypted_checkpoint_durable'] for value in states.values()):
            raise RuntimeError('canonical durable balances differ: ' + repr(actual))
        return states

    def start_ack_fault(self):
        self.fault = threading.Event(); self.fault_result = {}
        self.proxy = socket.socket(); self.proxy.bind(('127.0.0.1', 0)); self.proxy.listen(1); self.proxy.settimeout(.2)
        endpoint = self.proxy.getsockname(); targets = self.local[1:]
        def exact(stream, length):
            value = b''
            while len(value) < length:
                piece = stream.recv(length - len(value))
                if not piece: raise EOFError('truncated native frame')
                value += piece
            return value
        def proxy():
            try:
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline and not self.fault.is_set():
                    try: connection, _ = self.proxy.accept()
                    except socket.timeout: continue
                    with connection:
                        connection.settimeout(2); header = exact(connection, 4); length = int.from_bytes(header, 'little')
                        if not 1232 < length <= 16384: raise ValueError('unexpected native packet bound')
                        packet = exact(connection, length); intent = json.loads(self.intent().read_text())
                        if hashlib.sha256(packet).hexdigest() != intent['packet_sha256']: raise ValueError('fault packet differs from durable intent')
                        reply = dict(status='not_leader_retry_identical_bytes', finalized=False)
                        for port in targets:
                            with socket.create_connection(('127.0.0.1', port), timeout=2) as upstream:
                                upstream.settimeout(2); upstream.sendall(header + packet)
                                reply = json.loads(upstream.makefile('rb').readline(2049))
                            if reply.get('status') == 'admitted':
                                if reply.get('finalized') is not False or reply.get('signature') != intent['signature']:
                                    raise ValueError('admitted acknowledgement identity changed')
                                self.fault_result = dict(signature=intent['signature'], packet_sha256=intent['packet_sha256'])
                                self.stop_forward(); self.fault.set(); return  # suppress the actual ACK
                        connection.sendall((json.dumps(reply) + '\n').encode())
                raise TimeoutError('no actual admitted ACK observed')
            except Exception as exception: self.fault_result = dict(error=str(exception)); self.fault.set()
        self.proxy_thread = threading.Thread(target=proxy, daemon=True); self.proxy_thread.start()
        return endpoint[0] + ':' + str(endpoint[1])

    def close_proxy(self):
        if self.proxy is not None:
            self.proxy.close(); self.proxy = None
            self.proxy_thread.join(timeout=3)

    def run(self):
        self.start_forward(); self.profile(); self.start_client()
        original = self.request('status')
        if original['relay'] != self.host['mac_relay']: raise ValueError('Mac relay differs from prefunded public key')
        self.request('deposit', wallet='alice', amount=1000)
        self.balances(dict(alice=1000, bob=0, charlie=0))
        # Sequential cold restores leave the first wallet behind the last one.
        # Catch up all three before the explicitly warm timing run; restoration
        # itself remains separately observable in the unmodified client logs.
        for _ in range(3):
            warmed = self.balances(dict(alice=1000, bob=0, charlie=0))
        self.event('warm_wallet_sync_complete', checkpoints={name: value['checkpoint'] for name, value in warmed.items()})
        self.event('mac_fixture_funded', relay=original['relay'], setup_ms=original['setup_ms'])
        measured = []
        for sender, recipient, amount in [('alice', 'bob', 100), ('bob', 'charlie', 40), ('alice', 'charlie', 20)]:
            fields = {'from': sender, 'to': recipient, 'amount': amount}
            result = self.request('send', **fields); measured.append(result)
            if not result['receipt']['accepted'] or not result['receipt']['encrypted_checkpoints_durable']: raise RuntimeError('send not durably ready')
            self.event('measured_mac_private_send', **fields, milliseconds=result['action_to_durable_recipient_ms'], signature=result['receipt']['signature'])
        save(self.root / 'normal-payments.json', measured)
        self.balances(dict(alice=876, bob=58, charlie=60))
        self.event('sdk_golden_raw_packet', path=measured[0]['prepared']['raw_packet_file'], sha256=measured[0]['prepared']['packet_sha256'])
        if self.args.timing_only:
            self.result.update(status='passed', mode='timing-only',
                private_balances=dict(alice=876, bob=58, charlie=60), linux_crash_test=False)
            return

        self.stop_client(); proxy = self.start_ack_fault(); self.profile([proxy]); self.start_client(resume=True)
        failed = self.request('send', allow_error=True, **{'from': 'alice', 'to': 'bob', 'amount': 10})
        if not self.fault.wait(timeout=5) or 'error' in self.fault_result or 'error' not in failed:
            raise RuntimeError('actual ACK-loss/tunnel-drop fault failed: ' + repr(self.fault_result))
        saved = self.intent().read_bytes(); intent = json.loads(saved)
        if any(intent[key] != self.fault_result[key] for key in ('signature', 'packet_sha256')): raise ValueError('pending identity changed')
        (self.root / 'ack-loss-original-intent.json').write_bytes(saved)
        self.stop_client(); self.close_proxy()
        if self.args.await_linux_resume:
            path = self.root / 'linux-resume-host.json'
            if path.exists(): raise ValueError('Linux resume evidence must be fresh after the actual ACK loss')
            self.event('awaiting_original_ledger_linux_resume', **self.fault_result)
            deadline = time.monotonic() + 180
            while not path.exists() and time.monotonic() < deadline: time.sleep(.1)
            if not path.exists(): raise TimeoutError('bounded wait for externally controlled original-ledger recovery')
            resumed, endpoints = host_ready(path)
            if any(resumed[key] != self.host[key] for key in ('network', 'pool_format', 'mac_relay')) or sorted(
                    peer['identity'] for peer in resumed['peers']) != sorted(peer['identity'] for peer in self.host['peers']):
                raise ValueError('Linux resume substituted the original genesis, profile, relay or validator identities')
            self.result['linux_resume_host_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
            self.host, self.remote = resumed, endpoints
            self.event('externally_controlled_linux_resume_evidence_loaded', sha256=self.result['linux_resume_host_sha256'])
        self.start_forward(); self.profile(); self.start_client(resume=True)
        recovered = self.request('resolve', wallet='alice')
        if any(recovered[key] != intent[key] for key in ('signature', 'packet_sha256')) or self.intent().exists(): raise ValueError('ACK-loss recovery changed identity')
        self.balances(dict(alice=864, bob=68, charlie=60)); self.event('actual_admitted_ack_lost_and_recovered', receipt=recovered)

        prepared = self.request('prepare', **{'from': 'alice', 'to': 'charlie', 'amount': 7})
        if prepared.get('broadcast') is not False: raise ValueError('prepare unexpectedly broadcast')
        saved = self.intent().read_bytes()
        if self.stop_client(crash=True) != -9: raise ValueError('owned client did not receive SIGKILL')
        if self.intent().read_bytes() != saved: raise ValueError('SIGKILL changed original durable intent')
        self.start_client(resume=True); recovered = self.request('resolve', wallet='alice')
        if any(recovered[key] != prepared[key] for key in ('signature', 'packet_sha256')): raise ValueError('crash recovery constructed a replacement')
        self.balances(dict(alice=855, bob=68, charlie=67)); self.event('client_sigkill_original_packet_recovered', receipt=recovered)

        self.stop_client(); directory = self.root / 'wallets'
        for name in ('alice.wallet', 'alice.wallet.scan-cache'):
            (directory / name).rename(directory / (name + '.before-restore'))
        shutil.copyfile(directory / 'alice.backup', directory / 'alice.wallet'); os.chmod(directory / 'alice.wallet', 0o600)
        self.start_client(resume=True); restored = self.request('status')
        if restored['wallets'][0]['address'] != original['wallets'][0]['address']: raise ValueError('restored seed address changed')
        state = self.request('sync', wallet='alice')
        if state['balance'] != 855 or state['scan']['cache_used'] or not state['encrypted_checkpoint_durable']: raise ValueError('seed restore did not rebuild canonical state')
        self.event('encrypted_backup_canonical_replay', balance=855, checkpoint=state['checkpoint'])
        self.result.update(status='passed', private_balances=dict(alice=855, bob=68, charlie=67),
            linux_crash_test='externally controlled; see host evidence' if self.args.await_linux_resume else False)

    def close(self):
        failures = []
        for action in (self.stop_client, self.close_proxy, self.stop_forward):
            try: action()
            except Exception as exception: failures.append(str(exception))
        for output in self.logs: output.close()
        if failures: self.result.update(status='failed', cleanup_errors=failures)
        save(self.root / 'result.json', self.result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('host-evidence', 'binary', 'relay-keypair', 'password-file', 'output'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--await-linux-resume', action='store_true')
    parser.add_argument('--timing-only', action='store_true', help='Measure three durable hops without fault injection')
    parser.add_argument('--prover-threads', type=int, choices=(1, 2, 4), default=2)
    args = parser.parse_args(); os.umask(0o077)
    if args.timing_only and args.await_linux_resume:
        parser.error('timing-only does not perform the Linux crash test')
    args.output = args.output.absolute()
    if sys.platform != 'darwin' or not args.output.is_relative_to(PROJECT / '.local') or args.output.parent.resolve() != args.output.parent:
        parser.error('run on Mac with a fresh real output directory under this project .local')
    for name in ('host_evidence', 'binary', 'relay_keypair', 'password_file'): setattr(args, name, getattr(args, name).resolve(strict=True))
    try: pilot_ssh()
    except ValueError as exception: parser.error(str(exception))
    args.output.mkdir(mode=0o700); trial = Trial(args)
    try: trial.run()
    except BaseException as exception:
        trial.result.update(status='failed', error=type(exception).__name__ + ': ' + str(exception))
        trial.event('acceptance_failed', error=trial.result['error']); raise
    finally: trial.close()


if __name__ == '__main__': main()
