"""One device-local, fixed-wallet command worker over owned anonymous pipes.

Only public proving material remains in the child between explicit requests.
A transport failure never retries a request or replaces a pending payment.
"""
import json
import os
import queue
import select
import subprocess
import threading
import time
from pathlib import Path

COMMANDS = frozenset({'balance', 'fees', 'send', 'resolve'})
PHASES = frozenset({'key', 'sync', 'prove', 'upload', 'confirm', 'finalize', 'native_packet_durable'})
FRAME_LIMIT = 65536
REQUEST_LIMIT = 16384
STDERR_LIMIT = 16384
FORMAT = 'native-wallet-command-session-v1'
PROTOCOL_ERROR = 'Wallet session ended unexpectedly; check the saved payment status before retrying.'


class SessionUnsupported(ValueError):
    """An old CLI rejected the worker command before receiving any request."""


class _Child:
    def __init__(self, process):
        self.process = process
        self.events = queue.Queue(maxsize=32)
        self.overflow = threading.Event()
        self.stopped = threading.Event()
        self.stdout_seen = threading.Event()
        self.request_started = False
        self.errors = bytearray()
        self.stderr_truncated = threading.Event()
        self.errors_lock = threading.Lock()
        self.readers = [threading.Thread(target=self._stdout, daemon=True),
                        threading.Thread(target=self._stderr, daemon=True)]
        for reader in self.readers:
            reader.start()

    def _event(self, event):
        try:
            self.events.put_nowait(event)
        except queue.Full:
            self.overflow.set()

    def _stdout(self):
        try:
            while not self.stopped.is_set():
                line = self.process.stdout.readline(FRAME_LIMIT + 1)
                if not line:
                    self._event(('eof', None))
                    return
                self.stdout_seen.set()
                if len(line) > FRAME_LIMIT or not line.endswith(b'\n'):
                    self._event(('invalid', None))
                    return
                self._event(('line', line))
                if self.overflow.is_set():
                    return
        except (OSError, ValueError):
            self._event(('invalid', None))

    def _stderr(self):
        try:
            while not self.stopped.is_set():
                chunk = self.process.stderr.read(4096)
                if not chunk:
                    return
                with self.errors_lock:
                    remaining = STDERR_LIMIT - len(self.errors)
                    if remaining > 0:
                        self.errors.extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        self.stderr_truncated.set()
        except (OSError, ValueError):
            pass

    def stderr(self):
        with self.errors_lock:
            return bytes(self.errors).decode('utf-8', errors='replace')

    def close(self):
        self.stopped.set()
        process = self.process
        # Signal only the Popen child we created; never a process group or PID
        # obtained from a wallet, receipt, browser request or external file.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        for reader in self.readers:
            reader.join(timeout=1)


class CommandSession:
    """Lazily start one native-inline worker bound to a profile and wallet."""
    def __init__(self, binary, network, wallet, threads=6, ready_timeout=30, env=None):
        if type(threads) is not int or not 1 <= threads <= 6:
            raise ValueError('Wallet proof threads must be between one and six.')
        if not 0 < ready_timeout <= 30:
            raise ValueError('Wallet session startup must be bounded to thirty seconds.')
        self.binary = str(Path(binary).resolve())
        self.network = str(Path(network).resolve())
        self.wallet = str(Path(wallet).resolve())
        self.threads = threads
        self.ready_timeout = ready_timeout
        self.environment = dict(os.environ if env is None else {**os.environ, **env},
                                NATIVE_WALLET_PROGRESS='1', RAYON_NUM_THREADS=str(threads))
        self.lock = threading.Lock()
        self.ready = None
        self._child = None

    @property
    def pid(self):
        child = self._child
        return child.process.pid if child is not None and child.process.poll() is None else None

    def _close(self):
        child, self._child = self._child, None
        if child is not None:
            child.close()

    def close(self):
        with self.lock:
            self._close()

    def _frame(self, child, deadline, timeout):
        if child.overflow.is_set():
            raise ValueError(PROTOCOL_ERROR)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired([self.binary, 'command-session'], timeout)
        try:
            kind, raw = child.events.get(timeout=remaining)
        except queue.Empty:
            raise subprocess.TimeoutExpired([self.binary, 'command-session'], timeout) from None
        if child.overflow.is_set() or kind != 'line':
            raise ValueError(PROTOCOL_ERROR)
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise ValueError(PROTOCOL_ERROR) from None
        if not isinstance(value, dict):
            raise ValueError(PROTOCOL_ERROR)
        return value, len(raw)

    def _start(self):
        if self._child is not None:
            if self._child.process.poll() is None:
                return self._child
            self._close()
        self.ready = None
        process = subprocess.Popen(
            [self.binary, 'command-session', '--network', self.network, '--wallet', self.wallet],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=self.environment)
        child = self._child = _Child(process)
        os.set_blocking(process.stdin.fileno(), False)
        deadline = time.monotonic() + self.ready_timeout
        try:
            value, _ = self._frame(child, deadline, self.ready_timeout)
        except ValueError:
            # The sole fallback condition is the old CLI's exact, offline
            # unknown-command rejection, with no stdout or request bytes.
            # Timeout, arbitrary failure and every post-write failure remain
            # errors; they never authorize another payment attempt.
            if not child.stdout_seen.is_set() and not child.request_started:
                remaining = min(1, max(0, deadline - time.monotonic()))
                try:
                    process.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    raise ValueError(PROTOCOL_ERROR) from None
                child.readers[1].join(timeout=min(1, max(0, deadline - time.monotonic())))
                error = child.stderr().strip()
                if (process.returncode != 0 and not child.readers[1].is_alive()
                        and not child.stderr_truncated.is_set() and error in {
                        'unknown wallet command; use --help',
                        'Wallet error: unknown wallet command; use --help'}):
                    raise SessionUnsupported('This wallet binary uses the original single-command interface.')
            raise
        if (value.get('session_ready') is not True or value.get('format') != FORMAT
                or value.get('public_key_only') is not True):
            raise ValueError(PROTOCOL_ERROR)
        self.ready = value
        return child

    def _write(self, child, payload, deadline, timeout):
        offset = 0
        while offset < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired([self.binary, 'command-session'], timeout)
            _, writable, _ = select.select([], [child.process.stdin], [], remaining)
            if not writable:
                raise subprocess.TimeoutExpired([self.binary, 'command-session'], timeout)
            try:
                written = os.write(child.process.stdin.fileno(), memoryview(payload)[offset:])
            except BlockingIOError:
                continue
            if written <= 0:
                raise ValueError(PROTOCOL_ERROR)
            offset += written

    def run(self, command, args, password, callback=None, timeout=180):
        """Perform exactly one request, without automatic payment retries."""
        if not isinstance(command, str) or command not in COMMANDS or not isinstance(args, (list, tuple)):
            raise ValueError('Unsupported wallet session command.')
        if not 0 < timeout <= 180:
            raise ValueError('Wallet session requests must be bounded to 180 seconds.')
        if (len(args) > 64 or any(not isinstance(item, str) or '\0' in item for item in args)
                or sum(len(item.encode('utf-8')) for item in args) > 16384
                or any(item in {'--network', '--wallet', '--password-file', '--rpc',
                                '--rpc-access-file', '--sponsor', '--sponsor-password-file'}
                       for item in args)):
            raise ValueError('Wallet session arguments cannot override their fixed bindings.')
        if not isinstance(password, str):
            raise ValueError('Use a password with at least 12 characters.')
        secret = bytearray(password.encode('utf-8'))
        if not 12 <= len(secret) <= 1024:
            secret[:] = b'\0' * len(secret)
            raise ValueError('Use a password with at least 12 characters.')
        request = {'args': [command, *args], 'password': list(secret)}
        payload = bytearray((json.dumps(request, separators=(',', ':')) + '\n').encode('utf-8'))
        try:
            if len(payload) > REQUEST_LIMIT:
                raise ValueError('Wallet session request exceeded its limit.')
            with self.lock:
                try:
                    child = self._start()
                    if child.overflow.is_set() or not child.events.empty():
                        raise ValueError(PROTOCOL_ERROR)
                    deadline = time.monotonic() + timeout
                    child.request_started = True
                    self._write(child, payload, deadline, timeout)
                    total = 0
                    while True:
                        value, size = self._frame(child, deadline, timeout)
                        total += size
                        if total > FRAME_LIMIT:
                            raise ValueError(PROTOCOL_ERROR)
                        if (set(value) == {'wallet_progress'}
                                and isinstance(value['wallet_progress'], str)
                                and value['wallet_progress'] in PHASES):
                            if callback is not None:
                                try:
                                    callback(value['wallet_progress'])
                                except (BrokenPipeError, ConnectionResetError, OSError):
                                    pass
                            continue
                        if 'wallet_progress' in value or 'session_ready' in value:
                            raise ValueError(PROTOCOL_ERROR)
                        if 'session_error' in value:
                            if (set(value) != {'session_error', 'error'}
                                    or value['session_error'] is not True
                                    or not isinstance(value['error'], str)):
                                raise ValueError(PROTOCOL_ERROR)
                            error = value['error'].replace(password, '[redacted]')
                            return subprocess.CompletedProcess([self.binary, command], 1, '', error)
                        return subprocess.CompletedProcess(
                            [self.binary, command], 0, json.dumps(value), child.stderr().replace(password, '[redacted]'))
                except OSError:
                    self._close()
                    raise ValueError(PROTOCOL_ERROR) from None
                except BaseException:
                    self._close()
                    raise
        finally:
            # No password, witness, proof or request is attached to the adapter.
            # The UI already owns its password string for this explicit action.
            secret[:] = b'\0' * len(secret)
            payload[:] = b'\0' * len(payload)
            request['password'].clear()

    def run_cli(self, args, password, callback=None, timeout=180):
        """Verify and remove the existing UI CLI's exact fixed file bindings."""
        if not isinstance(args, (list, tuple)) or len(args) < 2 or args[0] != self.binary:
            raise ValueError('Wallet session binary binding differs.')
        expected = {'--network': self.network, '--wallet': self.wallet, '--password-file': '-'}
        found, reduced = set(), []
        index = 2
        while index < len(args):
            flag = args[index]
            if index + 1 == len(args):
                raise ValueError('Wallet session CLI option is missing its value.')
            value = args[index + 1]
            if flag in expected:
                if flag in found or value != expected[flag]:
                    raise ValueError('Wallet session file binding differs.')
                found.add(flag)
            else:
                reduced.extend((flag, value))
            index += 2
        if found != set(expected):
            raise ValueError('Wallet session requires its original file bindings.')
        return self.run(args[1], reduced, password, callback=callback, timeout=timeout)
