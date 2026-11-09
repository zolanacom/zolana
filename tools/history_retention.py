"""Service-owned, verified public-history collection and captured-manifest backups.

Checksums/structure are not consensus proofs. The native collector verifies the
complete history against finalized RPC before publishing; restored wallets replay
all signatures/proofs and reconcile again. No spending key/password is used.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import threading
import time

MAX_MANIFEST = 4 * 1024 * 1024
MAX_SEGMENT = 32 * 1024 * 1024
MAX_SEGMENTS = 16384
STORE_BUDGET = 256 * 1024 * 1024
MIN_FREE = 1536 * 1024 * 1024
MAX_LAG = 1024
INTERVAL = 60
SUCCESS_AGE = 180


def directory(path, create=False, owner=None):
    path = Path(path).absolute()
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    meta = path.lstat()
    if path.resolve() != path or not stat.S_ISDIR(meta.st_mode) or meta.st_uid != (os.getuid() if owner is None else owner) or meta.st_mode & 0o077:
        raise ValueError('history directory must be real, owned and owner-only')
    return path


def read(path, maximum, owner=None):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        meta = os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != (os.getuid() if owner is None else owner) or meta.st_mode & 0o077 or not 0 < meta.st_size <= maximum:
            raise ValueError('invalid bounded owner-only history file')
        data = source.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError('history file exceeds bound')
        return data


def atomic(path, data):
    temporary = path.with_name('.' + path.name + '-' + os.urandom(12).hex() + '.tmp')
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def natural(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


def block_hash(value):
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        return False
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number = 0
    for char in value:
        if char not in alphabet: return False
        number = number * 58 + alphabet.index(char)
    return len(value) - len(value.lstrip('1')) + (number.bit_length() + 7) // 8 == 32


def manifest(path, network, owner=None):
    raw = read(path / 'manifest.json', MAX_MANIFEST, owner)
    return parse_manifest(raw, network)


def parse_manifest(raw, network):
    if not 0 < len(raw) <= MAX_MANIFEST:
        raise ValueError('history manifest exceeds bound')
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {'format', 'network', 'segments'} or value['format'] != 'native-payment-history-v1' or value['network'] != network or not isinstance(value['segments'], list) or len(value['segments']) > MAX_SEGMENTS:
        raise ValueError('history manifest identity or capacity mismatch')
    previous, files = 0, []
    for index, segment in enumerate(value['segments']):
        if not isinstance(segment, dict) or set(segment) != {'first_slot', 'last_slot', 'count', 'digest'} or not all(natural(segment[key]) for key in ('first_slot', 'last_slot', 'count')) or not previous < segment['first_slot'] <= segment['last_slot'] or not 1 <= segment['count'] <= 1024 or not isinstance(segment['digest'], str) or re.fullmatch('[0-9a-f]{64}', segment['digest']) is None:
            raise ValueError('invalid history descriptor')
        files.append(('segment-%08d-%s.json' % (index, segment['digest']), segment))
        previous = segment['last_slot']
    return raw, files, previous


def usage(path, budget=STORE_BUDGET):
    total = count = 0
    for entry in path.iterdir():
        count += 1
        try:
            meta = entry.lstat()
        except FileNotFoundError:
            # A collector can publish an atomic temporary file while this
            # inventory is running. Referenced segments are verified separately.
            continue
        if count > MAX_SEGMENTS * 4 + 16 or not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
            raise ValueError('unsafe history storage inventory')
        total += meta.st_size
        if total > budget:
            raise ValueError('history storage budget exceeded')
    return total


def capture(source, destination, network, budget=STORE_BUDGET, source_owner=None):
    """Publish a consistent backup from one captured manifest, never a live tree copy.

    Interrupted copies leave the old manifest intact. Only referenced immutable
    segments are copied; unrelated files, locks and uncommitted temps are excluded.
    """
    source = directory(source, owner=source_owner)
    destination = directory(destination, create=True)
    if source == destination or source in destination.parents or destination in source.parents:
        raise ValueError('history backup must be a separate sibling directory')
    fd = os.open(destination / '.mirror.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(fd, 'r+b') as lock:
        meta = os.fstat(lock.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077 or meta.st_size:
            raise ValueError('invalid history mirror lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw, files, tip = manifest(source, network, source_owner)
        if os.path.lexists(destination / 'manifest.json'):
            _, previous_files, previous_tip = manifest(destination, network)
            if tip < previous_tip or files[:len(previous_files)] != previous_files:
                raise ValueError('history backup rollback or immutable prefix change')
        total = len(raw)
        previous_slot, previous_hash, previous_height = 0, None, 0
        for name, descriptor in files:
            data = read(source / name, MAX_SEGMENT, source_owner)
            if hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest() != descriptor['digest']:
                raise ValueError('history segment checksum mismatch')
            records = json.loads(data)
            if not isinstance(records, list) or len(records) != descriptor['count'] or not all(isinstance(block, dict) and natural(block.get('slot')) for block in records) or records[0]['slot'] != descriptor['first_slot'] or records[-1]['slot'] != descriptor['last_slot']:
                raise ValueError('history segment boundary mismatch')
            for block in records:
                if (set(block) != {'slot', 'parent_slot', 'blockhash', 'previous_blockhash', 'block_height', 'transactions'}
                        or block['slot'] <= previous_slot or not natural(block['parent_slot']) or block['parent_slot'] != previous_slot
                        or not block_hash(block['blockhash']) or not block_hash(block['previous_blockhash'])
                        or (previous_hash is not None and block['previous_blockhash'] != previous_hash)
                        or type(block['block_height']) is not int or block['block_height'] != previous_height + 1
                        or not isinstance(block['transactions'], list) or len(json.dumps(block, separators=(',', ':')).encode()) > 8 * 1024 * 1024):
                    raise ValueError('history backup continuity or record bound mismatch')
                previous_slot, previous_hash, previous_height = block['slot'], block['blockhash'], block['block_height']
            total += len(data)
            if total > budget:
                raise ValueError('history backup capacity exceeded')
            target = destination / name
            if os.path.lexists(target):
                if read(target, MAX_SEGMENT) != data:
                    raise ValueError('existing immutable backup differs; preserve it')
            else:
                # Never replace an immutable name. A failed copy stays unreferenced.
                temporary = destination / ('.copy-' + os.urandom(12).hex() + '.tmp')
                try:
                    out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(out, 'wb') as output:
                        output.write(data); output.flush(); os.fsync(output.fileno())
                    os.link(temporary, target)
                finally:
                    temporary.unlink(missing_ok=True)
        usage(destination, budget)
        # All referenced payloads are durable before this publication point.
        sync_directory(destination)
        atomic(destination / 'manifest.json', raw)
        return {'manifest_sha256': hashlib.sha256(raw).hexdigest(), 'finalized_slot': tip, 'segments': len(files), 'referenced_bytes': total}


class Retention:
    def __init__(self, root, binary, rpc, query, credential=None, interval=INTERVAL,
                 primary=None, mirror=None, minimum_free=MIN_FREE, budget=STORE_BUDGET):
        self.root = directory(root)
        self.binary = Path(binary).resolve()
        self.rpc = rpc
        self.query = query
        self.credential = credential
        self.primary = directory(primary or self.root / 'recovery-history', create=True)
        self.mirror = directory(mirror or self.root / 'recovery-history-mirror', create=True)
        if self.primary.parent != self.root or self.mirror.parent != self.root or self.primary == self.mirror:
            raise ValueError('retention stores must be distinct children of the network root')
        config = json.loads(read(self.root / 'network.json', 32768))
        self.network = {key: config[key] for key in ('network', 'genesis_hash')}
        if not 1 <= interval <= INTERVAL or minimum_free < MIN_FREE or not MAX_SEGMENT <= budget <= STORE_BUDGET:
            raise ValueError('invalid bounded retention policy')
        self.interval, self.minimum_free, self.budget = interval, minimum_free, budget
        self.path = self.root / 'history-retention.json'
        self.replica_config = self.root / 'history-replica.json'
        self.replica_marker = self.root / 'history-replica-required.json'
        required = {'format': 'native-required-history-replica-v1'}
        if os.path.lexists(self.replica_marker):
            if json.loads(read(self.replica_marker, 1024)) != required:
                raise ValueError('invalid persistent replica requirement; preserve original policy')
        elif os.path.lexists(self.replica_config):
            atomic(self.replica_marker, json.dumps(required).encode())
        self.replica_required = os.path.lexists(self.replica_marker)
        self.stop = threading.Event(); self.lock = threading.Lock(); self.operation = threading.Lock()
        self.child = None; self.thread = None
        self.info = {'format': 'native-history-retention-v1', 'phase': 'starting', 'last_success': None, 'finalized_slot': 0, 'child_pid': None, 'error': None}

    def record(self, **fields):
        with self.lock:
            self.info.update(fields)
            atomic(self.path, json.dumps(self.info, sort_keys=True).encode())

    def resources(self):
        # Leave one maximum segment of headroom while the trusted collector runs.
        if shutil.disk_usage(self.root).free < self.minimum_free + MAX_SEGMENT:
            raise ValueError('retention_disk_guard')
        try:
            usage(self.primary, self.budget); usage(self.mirror, self.budget)
        except ValueError:
            raise ValueError('retention_storage_guard') from None

    def collect(self):
        with self.operation:
            try:
                self.resources()
                current = self.query('getSlot', [{'commitment': 'finalized'}])
                first = self.query('getFirstAvailableBlock', [])
                if not natural(current) or not natural(first):
                    raise ValueError('invalid_retention_checkpoint')
                tip = manifest(self.primary, self.network)[2] if (self.primary / 'manifest.json').exists() else 0
                if first > tip + 1:
                    raise ValueError('retention_history_gap')
                args = [str(self.binary), 'archive', '--network', str(self.root / 'network.json'), '--rpc', self.rpc, '--history', str(self.primary)]
                if self.credential is not None:
                    args += ['--rpc-access-file', str(self.credential)]
                self.record(phase='collecting', error=None)
                with self.lock:
                    if self.stop.is_set(): raise ValueError('retention_stopped')
                    self.child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                        env={'PATH': '/usr/bin:/bin', 'SOLANA_METRICS_CONFIG': '', 'RAYON_NUM_THREADS': '2'})
                    child = self.child
                self.record(child_pid=child.pid)
                end = time.monotonic() + 120
                try:
                    while True:
                        try:
                            stdout, stderr = child.communicate(timeout=.25)
                            break
                        except subprocess.TimeoutExpired:
                            self.resources()
                            if self.stop.is_set() or time.monotonic() > end:
                                raise ValueError('retention_collection_interrupted')
                    if child.returncode or len(stdout) > 4096:
                        # Keep bounded operator diagnostics inside the private
                        # service root; never expose them through the gateway.
                        atomic(self.root/'history-collector-error.json',json.dumps({'format':'native-history-collector-error-v1',
                            'returncode':child.returncode,'stderr':stderr[-4096:],'recorded_at':time.time()},sort_keys=True).encode())
                        raise ValueError('retention_collection_failed')
                    result = json.loads(stdout)
                    if not isinstance(result, dict) or result.get('manifest_committed') is not True or not natural(result.get('finalized_slot')) or result['finalized_slot'] < current:
                        raise ValueError('retention_unverified_collection')
                finally:
                    if child.poll() is None: child.kill()
                    child.communicate(timeout=10)
                    with self.lock: self.child = None
                self.resources()
                copied = capture(self.primary, self.mirror, self.network, self.budget)
                live = self.query('getSlot', [{'commitment': 'finalized'}])
                if not natural(live) or copied['finalized_slot'] != result['finalized_slot'] or live < copied['finalized_slot'] or live - copied['finalized_slot'] > MAX_LAG:
                    raise ValueError('retention_checkpoint_lag')
                replica = None
                if self.replica_required or os.path.lexists(self.replica_config):
                    self.replica_required = True
                    if not os.path.lexists(self.replica_marker):
                        atomic(self.replica_marker, json.dumps({'format':'native-required-history-replica-v1'}).encode())
                    from history_replica import replicate
                    policy = json.loads(read(self.replica_config, 4096))
                    if (not isinstance(policy, dict) or set(policy) != {'format', 'url', 'ca_sha256'}
                            or policy['format'] != 'native-history-replication-v1'
                            or not isinstance(policy['ca_sha256'], str)
                            or re.fullmatch('[0-9a-f]{64}', policy['ca_sha256']) is None):
                        raise ValueError('retention_replica_policy_invalid')
                    self.record(phase='replicating')
                    try:
                        replica = replicate(self.mirror, self.network, policy['url'],
                            self.root / 'history-replica.key', self.root / 'history-replica-ca.crt',
                            policy['ca_sha256'], self.stop)
                    except Exception:
                        raise ValueError('retention_replica_unavailable_or_unverified') from None
                    live = self.query('getSlot', [{'commitment': 'finalized'}])
                    if not natural(live) or live < copied['finalized_slot'] or live - copied['finalized_slot'] > MAX_LAG:
                        raise ValueError('retention_replica_checkpoint_lag')
                self.record(phase='ready', child_pid=None, error=None, last_success=time.time(), live_slot=live, first_available_slot=first,
                    primary_bytes=usage(self.primary, self.budget), mirror_bytes=usage(self.mirror, self.budget), storage_budget=self.budget,
                    replica=replica, **copied)
                return dict(self.info)
            except BaseException as error:
                code = str(error) if isinstance(error, ValueError) and str(error).startswith('retention_') else 'retention_verification_failed'
                self.record(phase='paused' if self.stop.is_set() else 'blocked', child_pid=None, error=code)
                raise

    def start(self):
        self.collect()  # A verified mirrored prefix is required before ingress.
        self.thread = threading.Thread(target=self.work, daemon=True)
        self.thread.start()

    def work(self):
        while not self.stop.wait(self.interval):
            try: self.collect()
            except Exception: return  # Supervisor pauses; never reset/reinitialize.

    def healthy(self):
        with self.lock:
            success = self.info['last_success']
            return self.info['phase'] in ('ready', 'collecting', 'replicating') and success is not None and 0 <= time.time() - success <= SUCCESS_AGE and (self.thread is None or self.thread.is_alive())

    def close(self):
        self.stop.set()
        with self.lock:
            if self.child is not None and self.child.poll() is None: self.child.kill()
        if self.thread is not None: self.thread.join(timeout=15)
        if self.thread is not None and self.thread.is_alive():
            raise RuntimeError('owned retention worker did not stop')
        self.record(phase='paused', child_pid=None)
