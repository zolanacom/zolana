#!/usr/bin/env python3
"""Opt-in bounded private-fee transport, attached only to invited RPC ingress.

Packets contain ciphertexts/proofs only. Ingress still knows the admitted member.
Operator paths are fixed in an owner-only config, never supplied by clients.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import threading


def private(path, limit=20000):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        meta = os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > limit:
            raise ValueError('relay state must be bounded and owner-only')
        return source.read(limit + 1)


def save(path, value):
    import secrets
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.new')
    raw = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)
    sync_dir(path.parent)


def sync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def identity(raw):
    # Same domain-separated digest as native_payments::staging::payload_digest.
    return hashlib.blake2b(raw, digest_size=32, person=b'NativeStageV1!!!').digest()


def packet(value, network, payer, fee):
    if not isinstance(value, dict) or set(value) != {'network', 'payload'} or value['network'] != network:
        raise ValueError('relay network or packet shape mismatch')
    encoded = value['payload']
    if not isinstance(encoded, str) or len(encoded) != 12308:
        raise ValueError('relay packet size mismatch')
    raw = base64.b64decode(encoded, validate=True)
    if (len(raw) != 9230 or base64.b64encode(raw).decode() != encoded or raw[:8] != b'NPAY0003'
            or raw[8:40] != bytes(network['network']) or raw[56:88] != bytes(payer)
            or int.from_bytes(raw[48:56], 'little', signed=True) != fee
            or int.from_bytes(raw[88:96], 'little') != fee):
        raise ValueError('relay fee, payee or native encoding mismatch')
    return identity(raw).hex()


def native_options(config):
    """Only fixed operator configuration can select private native ingress."""
    fields = {'native_ingress', 'pool_format', 'native_profile'}
    if not fields.intersection(config):
        return None
    endpoints = config.get('native_ingress')
    network = config.get('network')
    if (not fields <= set(config) or config['pool_format'] != 'NPOOL004'
            or not isinstance(config.get('native_profile'), str)
            or not 1 <= len(config['native_profile']) <= 4096 or '\0' in config['native_profile']
            or not Path(config['native_profile']).is_absolute()
            or not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 3
            or any(not isinstance(value, str) or
                   re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}', value) is None or
                   not 1 <= int(value.rsplit(':', 1)[1]) <= 65535 for value in endpoints)
            or len(set(endpoints)) != len(endpoints)
            or not isinstance(network, dict) or set(network) != {'network', 'genesis_hash'}
            or not isinstance(network['network'], list) or len(network['network']) != 32
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in network['network'])
            or network['network'] == [0] * 32
            or not isinstance(config.get('payer'), list) or len(config['payer']) != 32
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in config['payer'])
            or config['payer'] == [0] * 32
            or not isinstance(network['genesis_hash'], str)
            or re.fullmatch('[1-9A-HJ-NP-Za-km-z]{32,44}', network['genesis_hash']) is None):
        raise ValueError('native relay requires an explicit V4 network and 1..3 unique pinned loopback ingress endpoints')
    return ','.join(endpoints)


# Six lifetime jobs for each wallet of the largest plannable 500-wallet cohort.
MAX_JOBS = 3000


class RelayCapacityError(ValueError):
    def __init__(self, scope):
        if scope not in ('member', 'network'):
            raise ValueError('invalid relay capacity scope')
        self.scope = scope
        super().__init__('relay lifetime quota exhausted')


# Public request IDs use hex; RPC client verifies the exact payload digest too.
class Relay:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if self.root.is_symlink() or self.root.stat().st_mode & 0o077:
            raise ValueError('relay root must be owner-only')
        self.lock_file = os.fdopen(os.open(self.root / 'worker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'a+b')
        try:
            if os.fstat(self.lock_file.fileno()).st_mode & 0o077: raise ValueError('relay lock must be owner-only')
            import fcntl
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.config = json.loads(private(self.root / 'config.json', 8192))
            required = {'format', 'network', 'network_file', 'rpc', 'payer', 'payer_file', 'binary',
                        'fee', 'gross_cap', 'max_jobs', 'per_member'}
            if (set(self.config) - (required | {'rpc_access_file', 'native_ingress', 'pool_format', 'native_profile'}) or not required <= set(self.config)
                    or self.config['format'] != 'native-shielded-relay-v1'
                    or any(type(self.config[k]) is not int or self.config[k] <= 0 for k in ('fee', 'gross_cap', 'max_jobs', 'per_member'))
                    or self.config['max_jobs'] > MAX_JOBS or self.config['per_member'] > 8
                    or self.config['fee'] > 100_000_000 or self.config['gross_cap'] > 250_000_000
                    or len(self.config['payer']) != 32):
                raise ValueError('invalid bounded relay configuration')
            self.native_ingress = native_options(self.config)
            self.transport_binding = (dict(format='native-inline-relay-binding-v1',
                transport='native-inline-v1', pool_format='NPOOL004',
                network=self.config['network'], payer=self.config['payer'], fee=self.config['fee'])
                if self.native_ingress is not None else None)
            self.jobs = self.root / 'jobs'
            self.jobs.mkdir(mode=0o700, exist_ok=True)
            if self.jobs.is_symlink() or self.jobs.stat().st_mode & 0o077:
                raise ValueError('invalid relay jobs directory')
            # Never reinterpret an existing job under another network, payer, fee,
            # pool version or transport. Endpoint rotations remain operator-owned.
            for job in self.jobs.iterdir():
                self.check_transport(job)
            self.mutex = threading.Lock()
            self.stop = threading.Event()
            self.wake = threading.Event()
            self.child = None
            self.worker = None

        except BaseException:
            # A retained initialization traceback can keep this object alive.
            # Release its lock before propagating any incomplete construction.
            self.lock_file.close()
            raise

    def check_transport(self, path):
        if path.is_symlink() or not path.is_dir() or re.fullmatch('[a-f0-9]{64}', path.name) is None:
            raise ValueError('invalid private relay job directory')
        binding = path / 'transport.json'
        if self.transport_binding is None:
            if binding.exists() or binding.is_symlink():
                raise ValueError('native relay jobs cannot fall back to staging')
        elif not binding.exists() or json.loads(private(binding, 4096)) != self.transport_binding:
            raise ValueError('native relay job transport binding mismatch; original state retained')

    @staticmethod
    def pending(path):
        return any((path / name).exists() for name in
                   ('relay.pending.json', 'relay.staging.json', 'relay.native.json'))

    def quote(self):
        # No refundable staging rent is charged to the user.
        from explorer_model import b58
        value = dict(format='native-shielded-fee-quote-v1', network=self.config['network'],
                     payer=b58(bytes(self.config['payer'])), fee=self.config['fee'])
        if self.native_ingress is not None:
            value.update(transport='native-inline-v1', pool_format='NPOOL004')
        return value

    def check_capacity(self, owner):
        """Check finite lifetime capacity while the caller holds self.mutex."""
        entries = list(self.jobs.iterdir())
        if len(entries) >= self.config['max_jobs']:
            raise RelayCapacityError('network')
        if sum(json.loads(private(path / 'owner.json')) == owner for path in entries) >= self.config['per_member']:
            raise RelayCapacityError('member')

    def dispatch(self, method, params, member):
        if method == 'getShieldedFeeQuote':
            if params != []:
                raise ValueError('quote accepts no parameters')
        elif not isinstance(params, list) or len(params) != 1:
            raise ValueError('one bounded relay parameter required')
        # Store a hash of the admitted identity; never expose another member's job.
        owner = hashlib.sha256(member.encode()).hexdigest()
        with self.mutex:
            if method == 'getShieldedFeeQuote':
                self.check_capacity(owner)
                return self.quote()
            if method == 'submitShieldedPayment':
                job_id = packet(params[0], self.config['network'], self.config['payer'], self.config['fee'])
                path = self.jobs / job_id
                if path.exists():
                    self.check_transport(path)
                    if json.loads(private(path / 'owner.json')) != owner:
                        raise ValueError('relay ownership mismatch')
                    if json.loads(private(path / 'packet.json')) != params[0]:
                        raise ValueError('relay payload identity collision')
                    return dict(id=job_id)
                self.check_capacity(owner)
                # Fully initialize an invisible directory, then publish atomically.
                import tempfile
                import shutil
                pending = Path(tempfile.mkdtemp(prefix='.relay-', dir=self.root))
                try:
                    save(pending / 'packet.json', params[0])
                    save(pending / 'owner.json', owner)
                    if self.transport_binding is not None:
                        save(pending / 'transport.json', self.transport_binding)
                    os.rename(pending, path); sync_dir(self.jobs)
                    self.wake.set()  # Notify only after the new job is durable.
                finally:
                    if pending.exists(): shutil.rmtree(pending)
                return dict(id=job_id)
            if method != 'getShieldedPaymentStatus' or not isinstance(params[0], str) or not re.fullmatch('[a-f0-9]{64}', params[0]):
                raise ValueError('invalid relay status request')
            path = self.jobs / params[0]
            if not path.exists(): return dict(id=params[0], state='unknown')
            self.check_transport(path)
            if json.loads(private(path / 'owner.json')) != owner:
                raise ValueError('relay ownership mismatch')
            if (path / 'outcome.json').exists():
                value = json.loads(private(path / 'outcome.json', 4096))
                return dict(id=params[0], state='accepted' if value.get('accepted') is True else 'aborted',
                            signature=value.get('signature'))
            return dict(id=params[0], state='pending')

    def work_once(self):
        for path in sorted(self.jobs.iterdir()):
            if self.stop.is_set(): return
            self.check_transport(path)
            if (path / 'done').exists() and not self.pending(path): continue
            tries = json.loads(private(path / 'tries.json')) if (path / 'tries.json').exists() else 0
            if tries >= 3 and not self.pending(path) and not (path / 'outcome.json').exists():
                save(path / 'outcome.json', dict(accepted=False, aborted=True))
                save(path / 'done', True)
                continue
            save(path / 'tries.json', tries + 1)
            args = [self.config['binary'], 'relay', '--network', self.config['network_file'],
                    '--rpc', self.config['rpc'], '--payer', self.config['payer_file'], '--job', str(path),
                    '--gross-cap', str(self.config['gross_cap']), '--fee', str(self.config['fee'])]
            if self.native_ingress is not None:
                args += ['--native-ingress', self.native_ingress, '--pool-format', 'NPOOL004']
            if self.config.get('rpc_access_file'):
                args += ['--rpc-access-file', self.config['rpc_access_file']]
            # One proof/worker at a time; an unknown transaction retains its
            # original journals. Never reset a cap or start a second payment.
            with self.mutex:
                if self.stop.is_set(): return
                self.child = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env=dict(os.environ, RAYON_NUM_THREADS='2'))
                child = self.child
            try:
                child.wait(timeout=180)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()
            finally:
                with self.mutex: self.child = None
            if child.returncode == 0 and (path / 'outcome.json').exists() and not self.pending(path):
                save(path / 'done', True)

    def start(self):
        if self.worker is not None: raise ValueError('relay worker already started')
        self.worker = threading.Thread(target=self.work, daemon=True)
        self.worker.start()

    def work(self):
        while not self.stop.is_set():
            # Clear before scanning: a publication during the scan must still
            # wake the following wait. Keep the periodic scan for old jobs,
            # cross-process publications and recovery without an event.
            self.wake.clear()
            self.work_once()
            if not self.stop.is_set():
                self.wake.wait(1)

    def close(self):
        with self.mutex:
            self.stop.set()
            self.wake.set()
            if self.child is not None:
                self.child.kill(); self.child.wait()
        if self.worker is not None:
            self.worker.join(timeout=15)
            if self.worker.is_alive(): raise RuntimeError("relay worker failed to stop; lock retained")
        self.lock_file.close()
