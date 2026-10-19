"""Bounded, sanitized service heartbeat. Contains no RPC or wallet capability."""
import json
import math
import os
from pathlib import Path
import secrets
import stat
import threading
import time

FORMAT = 'native-operator-health-v1'
PHASES = {'starting', 'replaying', 'syncing', 'retaining', 'ready', 'paused', 'blocked', 'failed'}
REASONS = {None, 'operator_stop', 'test_complete', 'disk_low', 'retention_failed',
           'finality_timeout', 'validator_exited', 'ingress_exited', 'startup_failed',
           'cleanup_failed', 'health_unavailable'}
KEYS = {'format', 'instance', 'pid', 'sequence', 'phase', 'reason', 'started_at',
        'phase_since', 'published_at', 'sampled_at', 'finalized_slot',
        'finality_progress_at', 'validator_count', 'ingress_ready', 'free_disk_mib'}


def timestamp(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def validate(data):
    if not isinstance(data, dict) or set(data) != KEYS or data['format'] != FORMAT:
        raise ValueError('invalid health schema')
    if (not isinstance(data['instance'], str) or len(data['instance']) != 32 or
            any(c not in '0123456789abcdef' for c in data['instance'])):
        raise ValueError('invalid health instance')
    for key in ('pid', 'sequence', 'validator_count'):
        if type(data[key]) is not int or data[key] < 0: raise ValueError('invalid health counter')
    if data['pid'] == 0 or data['validator_count'] > 2: raise ValueError('invalid health process count')
    if not isinstance(data['phase'], str) or data['phase'] not in PHASES: raise ValueError('invalid health phase')
    if data['reason'] is not None and (not isinstance(data['reason'], str) or data['reason'] not in REASONS):
        raise ValueError('invalid health reason')
    if type(data['ingress_ready']) is not bool: raise ValueError('invalid health ingress state')
    for key in ('started_at', 'phase_since', 'published_at'):
        if not timestamp(data[key]): raise ValueError('invalid health timestamp')
    for key in ('sampled_at', 'finality_progress_at'):
        if data[key] is not None and not timestamp(data[key]): raise ValueError('invalid health sample timestamp')
    for key in ('finalized_slot', 'free_disk_mib'):
        if data[key] is not None and (type(data[key]) is not int or not 0 <= data[key] < 2**64):
            raise ValueError('invalid health measurement')
    if data['phase_since'] < data['started_at'] or data['published_at'] < data['phase_since']:
        raise ValueError('invalid health timestamp order')
    if any(data[k] is not None and not data['started_at'] <= data[k] <= data['published_at']
           for k in ('sampled_at', 'finality_progress_at')):
        raise ValueError('invalid health sample order')
    if (data['finalized_slot'] is None) != (data['finality_progress_at'] is None):
        raise ValueError('invalid finality sample')
    return data


def directory(path, owner, mode):
    meta = Path(path).lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != owner or stat.S_IMODE(meta.st_mode) != mode:
        raise ValueError('unsafe health directory')


def read(path, owner):
    path = Path(path); directory(path.parent, owner, 0o755)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != owner or meta.st_nlink != 1 or
                stat.S_IMODE(meta.st_mode) != 0o644 or not 0 < meta.st_size <= 4096):
            raise ValueError('unsafe health file')
        return validate(json.loads(stream.read(4097)))


def atomic(path, data, mode):
    """Create in the validated directory; fsync file and rename before dirsync."""
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write((json.dumps(data, sort_keys=True, allow_nan=False) + '\n').encode())
            stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_NOFOLLOW)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        if temporary.exists(): temporary.unlink()


class Publisher:
    def __init__(self, path, interval=2, clock=time.time):
        self.path = Path(path); self.clock = clock; self.interval = interval
        directory(self.path.parent, os.getuid(), 0o755)
        self.lock = threading.Lock(); self.stop = threading.Event(); self.error = False
        now = clock()
        self.data = dict(format=FORMAT, instance=secrets.token_hex(16), pid=os.getpid(), sequence=0,
            phase='starting', reason=None, started_at=now, phase_since=now, published_at=now,
            sampled_at=None, finalized_slot=None, finality_progress_at=None, validator_count=0,
            ingress_ready=False, free_disk_mib=None)
        self.thread = threading.Thread(target=self._run, name='operator-heartbeat', daemon=True)

    def _write(self):
        self.data['sequence'] += 1; self.data['published_at'] = self.clock()
        validate(self.data); directory(self.path.parent, os.getuid(), 0o755)
        atomic(self.path, self.data, 0o644)

    def start(self):
        with self.lock: self._write()
        self.thread.start()
        return self

    def update(self, phase=None, reason=None, **metrics):
        if set(metrics) - {'validator_count', 'ingress_ready', 'free_disk_mib'}:
            raise ValueError('unapproved public health metric')
        with self.lock:
            if phase is not None:
                if phase != self.data['phase']: self.data['phase_since'] = self.clock()
                self.data.update(phase=phase, reason=reason)
            self.data.update(metrics); self._write()

    def observe(self, slot, **metrics):
        if type(slot) is not int or slot < 0: raise ValueError('invalid finality sample')
        with self.lock:
            now = self.clock()
            if self.data['finalized_slot'] is not None and slot < self.data['finalized_slot']:
                raise ValueError('finality regressed')
            if self.data['finalized_slot'] is None or slot > self.data['finalized_slot']:
                self.data['finality_progress_at'] = now
            self.data['finalized_slot'] = slot; self.data['sampled_at'] = now
        self.update(**metrics)

    def _run(self):
        while not self.stop.wait(self.interval):
            try:
                with self.lock: self._write()
            except Exception:
                self.error = True; return

    def healthy(self):
        return not self.error and self.thread.is_alive()

    def close(self):
        self.stop.set(); self.thread.join(timeout=5)
        if self.thread.is_alive(): raise RuntimeError('health publisher did not stop')
        if not self.error:
            if self.data['phase'] in ('blocked', 'failed', 'paused'):
                self.update(validator_count=0, ingress_ready=False)
            else: self.update('paused', 'operator_stop', validator_count=0, ingress_ready=False)
