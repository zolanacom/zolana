"""Explicit lifecycle for bounded rolling canonical capture windows.

Private operator configuration only. No listener, keys, Operator instance,
subprocess, admission change or alternative RPC route is created. All reads use
the already-bound Gateway.forward and its shared upstream permits. Diagnostics
are in-memory and never authoritative coverage; serving checks SQLite itself.
"""
import math
import os
from pathlib import Path
import stat
import threading
import time

import canonical_archive_capture as archive_capture
from canonical_archive_backend import HEADER, FULL, configuration
from canonical_archive_store import Reader, decoded, identity, local_file
from history_retention import natural

MIN_FREE_BYTES = 28 * 1024**3
POLICY_KEYS = {'network', 'max_database_bytes', 'min_free_bytes', 'batch_blocks',
               'max_batches', 'timeout', 'batch_timeout', 'poll_seconds'}


def check(value, reason):
    if not value:
        raise ValueError(reason)


def seconds(value, minimum, maximum):
    check(type(value) in (int, float) and math.isfinite(value)
          and minimum <= value <= maximum, 'bounded capture lifecycle interval required')
    return value


class _Stopped(Exception):
    pass


class RollingCapture:
    """One explicitly started worker, one bounded window, no retry queue.

    Each new window pins its own finalized target and resumes the committed
    prefix. An error ends that window; polling starts a new invocation later.
    close() is cooperative and bounded. If a broken transport ignores its
    timeout, close raises and latches failure; the owning service must stop.
    The stop flag rejects that late transport result before further capture.
    """
    def __init__(self, gateway, path, *, policy):
        check(gateway.info.get('invite_required') is True, 'capture requires the existing invited gateway')
        check(type(policy) is dict and set(policy) == POLICY_KEYS, 'exact private capture policy required')
        network = gateway.info['network']
        self._network = identity(network, network['genesis_hash'])
        check(identity(policy['network'], self._network['genesis_hash']) == self._network,
              'capture policy must pin the exact gateway network/genesis')
        check(type(policy['max_database_bytes']) is int
              and 1024**2 <= policy['max_database_bytes'] <= archive_capture.MAX_DATABASE_BYTES,
              'bounded capture database size required')
        check(type(policy['min_free_bytes']) is int
              and MIN_FREE_BYTES <= policy['min_free_bytes'] <= archive_capture.MAX_DATABASE_BYTES,
              'capture disk floor must retain at least28GiB')
        check(type(policy['batch_blocks']) is int and 1 <= policy['batch_blocks'] <= 16
              and type(policy['max_batches']) is int and 1 <= policy['max_batches'] <= 64,
              'capture window requires bounded block/batch counts')
        seconds(policy['timeout'], .001, 30)
        seconds(policy['batch_timeout'], .001, min(6, policy['timeout']))
        seconds(policy['poll_seconds'], 1, 300)
        self._policy = {key: policy[key] for key in POLICY_KEYS if key != 'network'}
        self._path = Path(path)
        check(self._path.is_absolute() and self._path.resolve() == self._path,
              'fixed real absolute capture store required')
        if os.path.lexists(self._path):
            local_file(self._path, False)
        else:
            parent = self._path.parent
            m = parent.lstat()
            check(parent.resolve() == parent and stat.S_ISDIR(m.st_mode)
                  and m.st_uid == os.geteuid() and stat.S_IMODE(m.st_mode) == 0o700,
                  'missing capture store requires an existing private owned parent')
        self._primary = gateway.forward
        check(callable(self._primary), 'existing bound gateway transport required')
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._wake_requested = False
        self._commits = 0
        self._thread = None
        self._phase = 'new'
        self._windows = self._failures = 0
        self._last_result = None
        self._last_error = 0

    def _progress(self, _event):
        # Capture calls this only after a whole batch commits, closes and is
        # fsynced. The notification is a hint; readers verify SQLite itself.
        with self._condition:
            self._commits += 1
            self._condition.notify_all()

    def ensure_coverage(self, target, deadline):
        """Wake capture and wait for a verified committed prefix, at most15s.

        Never hold a Reader transaction while waiting for a writer. Missing
        coverage, stop, corruption, a new failed window or timeout cannot be
        converted into an empty/complete page. The page still verifies its
        exact target against the fresh primary after this returns.
        """
        check(natural(target) and target > 0, 'positive canonical coverage target required')
        check(type(deadline) in (int, float) and math.isfinite(deadline)
              and 0 < deadline - time.monotonic() <= 15,
              'bounded canonical coverage deadline required')
        with self._condition:
            check(not self._stop.is_set() and self._phase in ('starting', 'capturing', 'idle')
                  and self._thread is not None and self._thread.is_alive(),
                  'canonical capture worker is not running')
            baseline_failures = self._failures
            requested_commit = None
        while True:
            with self._condition:
                check(not self._stop.is_set() and self._phase in ('starting', 'capturing', 'idle')
                      and self._thread is not None and self._thread.is_alive(),
                      'canonical capture worker is not running')
                version = self._commits
            check(time.monotonic() < deadline, 'canonical coverage deadline exceeded')
            # A fresh short transaction validates network, schema, state and
            # the complete stored head. CLOSE it before acquiring/waiting on
            # the condition, so SQLite's SHARED lock cannot block capture.
            if os.path.lexists(self._path):
                with Reader(self._path, self._network, self._network['genesis_hash']) as reader:
                    covered = reader.slot >= target
                check(time.monotonic() < deadline, 'canonical coverage deadline exceeded')
                if covered:
                    with self._condition:
                        check(not self._stop.is_set() and self._phase in ('starting', 'capturing', 'idle'),
                              'canonical capture worker stopped during coverage check')
                    return
            with self._condition:
                check(not self._stop.is_set() and self._phase in ('starting', 'capturing', 'idle'),
                      'canonical capture worker stopped before coverage')
                check(self._failures == baseline_failures, 'canonical capture window failed before coverage')
                left = deadline - time.monotonic()
                check(left > 0, 'canonical coverage deadline exceeded')
                if self._commits != version:
                    continue
                # Wake only after a CLOSED Reader proves missing coverage.
                # Covered pages need no extra capture RPC window. Continue
                # bounded windows after real progress; a stalled source keeps
                # the normal >=1s polling interval.
                if requested_commit is None or self._commits != requested_commit:
                    self._wake_requested = True
                    requested_commit = self._commits
                    self._condition.notify_all()
                self._condition.wait(timeout=min(left, .1))

    def _transport(self, raw, *, timeout, deadline):
        if self._stop.is_set():
            raise _Stopped()
        seconds(timeout, .000000001, 6)
        remaining = deadline - time.monotonic()
        check(remaining > 0, 'capture lifecycle window deadline exceeded')
        query = decoded(raw, 4096)
        check(type(query) is dict and set(query) == {'jsonrpc', 'id', 'method', 'params'}
              and query['jsonrpc'] == '2.0' and type(query['id']) is int and query['id'] == 1
              and type(query['params']) is list, 'fixed read-only capture transport envelope required')
        method, params = query['method'], query['params']
        allowed = ((method == 'getGenesisHash' and params == []) or
            (method == 'getSlot' and params == [{'commitment': 'finalized'}]) or
            (method == 'getBlocksWithLimit' and len(params) == 3 and natural(params[0])
             and params[0] > 0 and type(params[1]) is int and params[1] == 16
             and configuration(params[2], dict(commitment='finalized'))) or
            (method == 'getBlock' and len(params) == 2 and natural(params[0]) and params[0] > 0
             and (configuration(params[1], HEADER) or configuration(params[1], FULL))))
        check(allowed, 'capture transport permits only four fixed finalized reads')
        # Deliberately no Operator, opener, socket or per-worker semaphore.
        body = self._primary(raw, timeout=min(timeout, remaining))
        if self._stop.is_set():
            raise _Stopped()
        check(time.monotonic() < deadline, 'capture lifecycle window deadline exceeded')
        return body

    def _run(self):
        try:
            while not self._stop.is_set():
                with self._lock:
                    self._phase = 'capturing'
                    self._windows += 1
                deadline = time.monotonic() + self._policy['timeout']
                def source(raw, *, timeout):
                    return self._transport(raw, timeout=timeout, deadline=deadline)
                try:
                    result = archive_capture.capture(self._path, self._network, [source],
                        progress=self._progress,
                        **{key:value for key,value in self._policy.items() if key != 'poll_seconds'})
                except _Stopped:
                    break
                except Exception:
                    with self._condition:
                        self._failures += 1
                        self._last_error = 1  # No exception text/transport data is exported.
                        self._condition.notify_all()
                else:
                    committed = result['committed']
                    summary = dict(status=result['status'], target_slot=result['target']['slot'],
                        committed_slot=0 if committed is None else committed['slot'],
                        batches=result['batches'], blocks=result['blocks'],
                        database_bytes=result['database_bytes'], elapsed_ms=result['elapsed_ms'])
                    with self._condition:
                        self._last_result, self._last_error = summary, 0
                        self._condition.notify_all()
                if self._stop.is_set():
                    break
                with self._condition:
                    self._phase = 'idle'
                    self._condition.wait_for(lambda: self._stop.is_set() or self._wake_requested,
                                             timeout=self._policy['poll_seconds'])
                    self._wake_requested = False
        finally:
            with self._condition:
                if self._phase != 'failed':
                    self._phase = 'closed' if self._stop.is_set() else 'failed'
                    if self._phase == 'failed':
                        self._last_error = 3
                self._condition.notify_all()

    def start(self):
        with self._lock:
            check(self._phase == 'new' and not self._stop.is_set(), 'capture worker starts explicitly only once')
            self._phase = 'starting'
            self._thread = threading.Thread(target=self._run, name='canonical-archive-capture', daemon=True)
            try:
                self._thread.start()
            except BaseException:
                self._phase, self._last_error, self._thread = 'failed', 3, None
                self._stop.set()
                raise
        return self

    def close(self):
        self._stop.set()
        with self._condition:
            thread = self._thread
            if self._phase != 'failed':
                self._phase = 'stopping' if thread is not None and thread.is_alive() else 'closed'
            self._condition.notify_all()
        if thread is not None:
            check(thread is not threading.current_thread(), 'capture worker cannot join itself')
            thread.join(timeout=self._policy['timeout'] + 2)
            if thread.is_alive():
                with self._lock:
                    self._phase, self._last_error = 'failed', 2
                raise TimeoutError('capture worker exceeded bounded close; owning service must stop')

    def snapshotstatus(self):
        with self._lock:
            return dict(phase=self._phase, windows=self._windows, failures=self._failures,
                last_error=self._last_error,
                last_result=None if self._last_result is None else dict(self._last_result),
                thread_alive=self._thread is not None and self._thread.is_alive())
