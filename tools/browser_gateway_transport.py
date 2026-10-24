"""Bounded, certificate-verified invited HTTP connections. Never retries a request."""
from contextlib import contextmanager
import http.client
import ssl
import threading
import time
import urllib.parse

MAX_PER_ORIGIN = 2
MAX_IDLE_SECONDS = 3
MAX_LIFETIME_SECONDS = 20
MAX_REQUESTS = 48


def _address(url, fixture_http, *, root=False):
    if (not isinstance(url, str) or not url or len(url) > 2048 or '\\' in url
            or any(c.isspace() or ord(c) < 32 for c in url)):
        raise ValueError('Fixed invited service URL required.')
    value = urllib.parse.urlsplit(url)
    if (not value.hostname or value.username or value.password or value.query or value.fragment
            or value.path not in (('', '/') if root else ('', '/', '/join', '/status'))
            or value.port == 0):
        raise ValueError('Fixed invited service URL required.')
    if value.scheme != 'https' and not (fixture_http and value.scheme == 'http'
            and value.hostname == '127.0.0.1' and value.port):
        raise ValueError('Certificate-verified invited HTTPS required.')
    return (value.scheme, value.hostname, value.port or 443), value.path or '/'


class _Entry:
    def __init__(self, connection, now):
        self.connection = connection
        self.created = self.last_used = now
        self.requests = 0


class _Response:
    def __init__(self, original):
        self._original = original
        self.headers, self.status = original.headers, original.status
        self.complete = False

    def read(self, maximum):
        if type(maximum) is not int or maximum < 1:
            raise ValueError('Bounded invited response read required.')
        pieces, received = [], 0
        while received < maximum and not self._original.isclosed():
            part = self._original.read(maximum - received)
            pieces.append(part)
            received += len(part)
            if not part:
                break
        raw = b''.join(pieces)
        # read(n) can return a short Content-Length body without raising.
        # It must not be accepted, nor can its connection be reused.
        remaining = self._original.length
        if self._original.isclosed() and remaining not in (None, 0):
            raise ValueError('Incomplete invited HTTP response.')
        self.complete = self._original.isclosed() and remaining in (None, 0)
        return raw


class UpstreamTransport:
    def __init__(self, origins, *, fixture_http=False, context=None, observer=None):
        if not isinstance(origins, (tuple, list)) or not 1 <= len(origins) <= 2:
            raise ValueError('Only the two fixed invited origins are supported.')
        self._fixture_http = fixture_http is True
        self._origins = frozenset(_address(url, self._fixture_http, root=True)[0] for url in origins)
        self._context = ssl.create_default_context() if context is None else context
        if (not isinstance(self._context, ssl.SSLContext)
                or self._context.verify_mode != ssl.CERT_REQUIRED or not self._context.check_hostname):
            raise ValueError('Certificate and hostname verification must remain enabled.')
        if observer is not None and not callable(observer):
            raise ValueError('Optional numeric connection observer required.')
        self.observer = observer
        self._condition = threading.Condition()
        self._entries = {origin: set() for origin in self._origins}
        self._idle = {origin: [] for origin in self._origins}
        self._closed = False

    @staticmethod
    def _eligible(entry, now, *, idle=True):
        return (now - entry.created < MAX_LIFETIME_SECONDS and entry.requests < MAX_REQUESTS
                and (not idle or now - entry.last_used < MAX_IDLE_SECONDS))

    def _discard(self, origin, entry):
        self._entries[origin].discard(entry)
        try:
            entry.connection.close()
        except OSError:
            pass

    def _connection(self, origin, timeout):
        scheme, host, port = origin
        return (http.client.HTTPSConnection(host, port, timeout=timeout, context=self._context)
                if scheme == 'https' else http.client.HTTPConnection(host, port, timeout=timeout))

    def _acquire(self, origin, deadline):
        with self._condition:
            while True:
                if self._closed:
                    raise ValueError('Invited transport is closed.')
                now = time.monotonic()
                if now >= deadline:
                    raise ValueError('Invited transport capacity deadline exceeded.')
                while self._idle[origin]:
                    entry = self._idle[origin].pop()
                    if self._eligible(entry, now):
                        return entry
                    self._discard(origin, entry)
                if len(self._entries[origin]) < MAX_PER_ORIGIN:
                    remaining = deadline - now
                    entry = _Entry(self._connection(origin, remaining), now)
                    self._entries[origin].add(entry)
                    return entry
                self._condition.wait(timeout=deadline - now)

    def _release(self, origin, entry, reusable):
        with self._condition:
            now = time.monotonic()
            if reusable and not self._closed and self._eligible(entry, now, idle=False):
                entry.last_used = now
                self._idle[origin].append(entry)
            else:
                self._discard(origin, entry)
            self._condition.notify_all()

    def _connect(self, origin, entry, deadline):
        """A connection retry is possible only before any HTTP request exists."""
        began = time.monotonic()
        fresh = entry.connection.sock is None
        attempts = 0
        age = max(0, min(3600000, round((began - entry.created) * 1000)))
        try:
            if not fresh:
                return
            for attempt in range(2):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Invited transport capacity deadline exceeded.')
                entry.connection.timeout = remaining
                attempts += 1
                try:
                    entry.connection.connect()
                    if entry.connection.sock is None:
                        raise ValueError('Invited connection was not established.')
                    return
                except ssl.SSLCertVerificationError:
                    raise  # Neither certificate nor hostname failures can retry.
                except OSError:
                    if attempt != 0 or time.monotonic() >= deadline:
                        raise
                    # Keep the same bounded lease and its original creation
                    # time; never extend its idle/lifetime/request policy.
                    entry.connection.close()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError('Invited transport capacity deadline exceeded.')
                    entry.connection = self._connection(origin, remaining)
        finally:
            try:
                if self.observer is not None:
                    self.observer({'new': int(fresh), 'reused': int(not fresh), 'age_ms': age,
                        'connect_elapsed_ms': max(0, min(3600000, round((time.monotonic() - began) * 1000))),
                        'connect_attempts': attempts})
            except Exception:
                pass  # Numeric diagnostics cannot change transport decisions.

    @contextmanager
    def open(self, url, raw, headers, timeout=20):
        origin, path = _address(url, self._fixture_http)
        if origin not in self._origins or not isinstance(raw, bytes) or not isinstance(headers, dict):
            raise ValueError('Only fixed invited request bytes and origins are supported.')
        if (set(headers) - {'Content-Type', 'Accept-Encoding', 'X-Testnet-Access'}
                or headers.get('Content-Type') != 'application/json'
                or headers.get('Accept-Encoding') not in ('gzip', 'identity')
                or any(not isinstance(value, str) or '\r' in value or '\n' in value for value in headers.values())
                or type(timeout) not in (int, float) or not 0 < timeout <= 20):
            raise ValueError('Fixed bounded invited request transport required.')
        deadline = time.monotonic() + timeout
        entry = self._acquire(origin, deadline)
        response, reusable = None, False
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Invited transport capacity deadline exceeded.')
            entry.requests += 1
            self._connect(origin, entry, deadline)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Invited transport capacity deadline exceeded.')
            connection = entry.connection
            connection.timeout = remaining
            if connection.sock is not None:
                connection.sock.settimeout(remaining)
            # Exactly one HTTP request call. The explicit pre-HTTP connect
            # phase above never sees request bytes, methods or credentials.
            # Nothing at/after this call can reconnect and replay any request.
            connection.request('POST', path, body=raw, headers=dict(headers))
            response = connection.getresponse()
            lengths = response.headers.get_all('Content-Length', [])
            transfers = response.headers.get_all('Transfer-Encoding', [])
            if (len(lengths) > 1 or (lengths and (not lengths[0].isdigit() or len(lengths[0]) > 20))
                    or len(transfers) > 1 or transfers and transfers[0].lower() != 'chunked'
                    or lengths and transfers):
                raise ValueError('Ambiguous invited HTTP response framing.')
            borrowed = _Response(response)
            yield borrowed
            closes = response.headers.get_all('Connection', [])
            reusable = (borrowed.complete and not response.will_close and len(closes) <= 1
                        and not any(token.strip().lower() == 'close'
                                    for value in closes for token in value.split(','))
                        and connection.sock is not None and time.monotonic() < deadline)
        except http.client.HTTPException as error:
            if isinstance(error, OSError):
                raise
            raise ValueError('Invited HTTP response failed.') from error
        finally:
            try:
                if response is not None:
                    try:
                        response.close()
                    except BaseException:
                        reusable = False
                        raise
            finally:
                self._release(origin, entry, reusable)

    def close(self):
        with self._condition:
            self._closed = True
            for origin in self._origins:
                for entry in self._idle[origin]:
                    self._discard(origin, entry)
                self._idle[origin].clear()
            self._condition.notify_all()
