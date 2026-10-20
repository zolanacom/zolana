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


# Public request IDs use hex; RPC client verifies the exact payload digest too.
class Relay:
    def __init__(self, root):
        self.root = Path(root).absolute()
        if self.root.is_symlink() or self.root.stat().st_mode & 0o077:
            raise ValueError('relay root must be owner-only')
        self.lock_file = os.fdopen(os.open(self.root / 'worker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'a+b')
        if os.fstat(self.lock_file.fileno()).st_mode & 0o077: raise ValueError('relay lock must be owner-only')
        import fcntl
        try:
            fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.lock_file.close()
            raise
        self.config = json.loads(private(self.root / 'config.json', 8192))
        required = {'format', 'network', 'network_file', 'rpc', 'payer', 'payer_file', 'binary',
                    'fee', 'gross_cap', 'max_jobs', 'per_member'}
        if (set(self.config) - (required | {'rpc_access_file'}) or not required <= set(self.config)
                or self.config['format'] != 'native-shielded-relay-v1'
                or any(type(self.config[k]) is not int or self.config[k] <= 0 for k in ('fee', 'gross_cap', 'max_jobs', 'per_member'))
                or self.config['max_jobs'] > 64 or self.config['per_member'] > 8
                or self.config['fee'] > 100_000_000 or self.config['gross_cap'] > 250_000_000
                or len(self.config['payer']) != 32):
            raise ValueError('invalid bounded relay configuration')
        self.jobs = self.root / 'jobs'
        self.jobs.mkdir(mode=0o700, exist_ok=True)
        if self.jobs.is_symlink() or self.jobs.stat().st_mode & 0o077:
            raise ValueError('invalid relay jobs directory')
        self.mutex = threading.Lock()
        self.stop = threading.Event()
        self.child = None
        self.worker = None

    def quote(self):
        # No refundable staging rent is charged to the user.
        from explorer_model import b58
        return dict(format='native-shielded-fee-quote-v1', network=self.config['network'],
                    payer=b58(bytes(self.config['payer'])), fee=self.config['fee'])

    def dispatch(self, method, params, member):
        if method == 'getShieldedFeeQuote':
            if params != []:
                raise ValueError('quote accepts no parameters')
            return self.quote()
        if not isinstance(params, list) or len(params) != 1:
            raise ValueError('one bounded relay parameter required')
        # Store a hash of the admitted identity; never expose another member's job.
        owner = hashlib.sha256(member.encode()).hexdigest()
        with self.mutex:
            if method == 'submitShieldedPayment':
                job_id = packet(params[0], self.config['network'], self.config['payer'], self.config['fee'])
                path = self.jobs / job_id
                if path.exists():
                    if json.loads(private(path / 'owner.json')) != owner:
                        raise ValueError('relay ownership mismatch')
                    if json.loads(private(path / 'packet.json')) != params[0]:
                        raise ValueError('relay payload identity collision')
                    return dict(id=job_id)
                entries = list(self.jobs.iterdir())
                if len(entries) >= self.config['max_jobs'] or sum(
                        json.loads(private(p / 'owner.json')) == owner for p in entries) >= self.config['per_member']:
                    raise ValueError('relay lifetime quota exhausted')
                # Fully initialize an invisible directory, then publish atomically.
                import tempfile
                import shutil
                pending = Path(tempfile.mkdtemp(prefix='.relay-', dir=self.root))
                try:
                    save(pending / 'packet.json', params[0])
                    save(pending / 'owner.json', owner)
                    os.rename(pending, path); sync_dir(self.jobs)
                finally:
                    if pending.exists(): shutil.rmtree(pending)
                return dict(id=job_id)
            if method != 'getShieldedPaymentStatus' or not isinstance(params[0], str) or not re.fullmatch('[a-f0-9]{64}', params[0]):
                raise ValueError('invalid relay status request')
            path = self.jobs / params[0]
            if not path.exists(): return dict(id=params[0], state='unknown')
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
            if (path / 'done').exists() and not any((path / name).exists() for name in ('relay.pending.json', 'relay.staging.json')): continue
            tries = json.loads(private(path / 'tries.json')) if (path / 'tries.json').exists() else 0
            if tries >= 3 and not any((path / name).exists() for name in ('relay.pending.json', 'relay.staging.json', 'outcome.json')):
                save(path / 'outcome.json', dict(accepted=False, aborted=True))
                save(path / 'done', True)
                continue
            save(path / 'tries.json', tries + 1)
            args = [self.config['binary'], 'relay', '--network', self.config['network_file'],
                    '--rpc', self.config['rpc'], '--payer', self.config['payer_file'], '--job', str(path),
                    '--gross-cap', str(self.config['gross_cap']), '--fee', str(self.config['fee'])]
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
            if child.returncode == 0 and (path / 'outcome.json').exists() and not any(
                    (path / name).exists() for name in ('relay.pending.json', 'relay.staging.json')):
                save(path / 'done', True)

    def start(self):
        if self.worker is not None: raise ValueError('relay worker already started')
        self.worker = threading.Thread(target=self.work, daemon=True)
        self.worker.start()

    def work(self):
        while not self.stop.is_set():
            self.work_once()
            self.stop.wait(1)

    def close(self):
        with self.mutex:
            self.stop.set()
            if self.child is not None:
                self.child.kill(); self.child.wait()
        if self.worker is not None:
            self.worker.join(timeout=15)
            if self.worker.is_alive(): raise RuntimeError("relay worker failed to stop; lock retained")
        self.lock_file.close()
