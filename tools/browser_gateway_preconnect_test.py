"""Inert pre-HTTP connection failures: no network, authority or wallet data."""
import http.client
import ssl
import unittest
from unittest.mock import patch

import browser_gateway_transport as T
from browser_gateway_transport_test import Response, HEADERS, URL


class Connection:
    instances = []
    outcomes = []
    request_error = None
    response_error = None
    reads_error = None

    def __init__(self, *args, timeout, **kwargs):
        self.sock = None; self.timeout = timeout; self.closed = False
        self.posts = []; self.connects = 0; self.instances.append(self)

    def connect(self):
        self.connects += 1
        outcome = self.outcomes.pop(0) if self.outcomes else None
        if callable(outcome): outcome = outcome()
        if isinstance(outcome, BaseException): raise outcome
        self.sock = self

    def settimeout(self, value): self.timeout = value

    def request(self, method, path, *, body, headers):
        self.posts.append((method, path, body, dict(headers), self.timeout))
        if self.request_error is not None: raise self.request_error

    def getresponse(self):
        if self.response_error is not None: raise self.response_error
        response = Response()
        if self.reads_error is not None:
            def read(_): raise self.reads_error
            response.read = read
        return response

    def close(self): self.closed = True; self.sock = None


class PreconnectTests(unittest.TestCase):
    def setUp(self):
        Connection.instances = []; Connection.outcomes = []
        Connection.request_error = Connection.response_error = Connection.reads_error = None
        mocked = patch.object(T.http.client, 'HTTPSConnection', Connection)
        mocked.start(); self.addCleanup(mocked.stop)
        self.metrics = []
        self.transport = T.UpstreamTransport([URL], observer=self.metrics.append)
        self.addCleanup(self.transport.close)

    def read(self):
        with self.transport.open(URL, b'{"original":"request"}', HEADERS) as response:
            self.assertEqual(response.read(10), b'{}')

    def test_first_connect_fails_then_fresh_connect_sends_exactly_one_original_post(self):
        Connection.outcomes = [ssl.SSLEOFError('fixture pre-HTTP EOF'), None]
        self.read()
        first, second = Connection.instances
        self.assertTrue(first.closed); self.assertEqual(first.posts, [])
        self.assertEqual(len(second.posts), 1)
        self.assertEqual(second.posts[0][:4], ('POST', '/', b'{"original":"request"}', HEADERS))
        self.assertEqual(self.metrics[-1]['connect_attempts'], 2)
        self.assertEqual(self.metrics[-1]['new'], 1)
        self.assertEqual(sum(len(x) for x in self.transport._entries.values()), 1)

    def test_both_connect_failures_never_send_http_and_release_bounded_lease(self):
        Connection.outcomes = [ssl.SSLEOFError('first'), OSError('second')]
        with self.assertRaises(OSError): self.read()
        self.assertEqual(len(Connection.instances), 2)
        self.assertTrue(all(c.closed and not c.posts and c.connects == 1 for c in Connection.instances))
        self.assertTrue(all(not x for x in self.transport._entries.values()))
        self.assertEqual(self.metrics[-1]['connect_attempts'], 2)

    def test_certificate_and_hostname_verification_failures_are_fatal_without_retry(self):
        for error in (ssl.SSLCertVerificationError('certificate'), ssl.CertificateError('hostname')):
            Connection.instances = []; Connection.outcomes = [error]
            with self.assertRaises(ssl.SSLCertVerificationError): self.read()
            self.assertEqual(len(Connection.instances), 1)
            self.assertEqual(Connection.instances[0].posts, [])
            self.assertEqual(self.metrics[-1]['connect_attempts'], 1)

    def test_partial_post_response_or_read_failures_never_reconnect_or_replay(self):
        for field, error in [('request_error', OSError('partial write')),
                             ('response_error', http.client.RemoteDisconnected('lost response')),
                             ('reads_error', ssl.SSLEOFError('partial read'))]:
            Connection.instances = []; setattr(Connection, field, error)
            with self.subTest(field=field), self.assertRaises((OSError, ValueError)): self.read()
            self.assertEqual(len(Connection.instances), 1)
            self.assertEqual(len(Connection.instances[0].posts), 1)
            self.assertTrue(Connection.instances[0].closed)
            setattr(Connection, field, None)

    def test_reused_stale_socket_cannot_enter_preconnect_retry(self):
        self.read(); existing = Connection.instances[0]
        Connection.request_error = OSError('stale write')
        with self.assertRaises(OSError): self.read()
        self.assertEqual(len(Connection.instances), 1)
        self.assertEqual(existing.connects, 1); self.assertEqual(len(existing.posts), 2)
        self.assertEqual(self.metrics[-1]['reused'], 1)
        self.assertEqual(self.metrics[-1]['connect_attempts'], 0)

    def test_connect_retry_has_same_absolute_deadline_and_remaining_timeout(self):
        clock = [0]
        def first(): clock[0] = 6; return ssl.SSLEOFError('fixture')
        def second(): clock[0] = 16
        Connection.outcomes = [first, second]
        with patch.object(T.time, 'monotonic', side_effect=lambda: clock[0]): self.read()
        self.assertEqual(Connection.instances[1].posts[0][-1], 4)
        Connection.instances = []; clock[0] = 0
        def exhausted(): clock[0] = 21; return ssl.SSLEOFError('fixture')
        Connection.outcomes = [exhausted]
        fresh = T.UpstreamTransport([URL], observer=self.metrics.append)
        try:
            with patch.object(T.time, 'monotonic', side_effect=lambda: clock[0]), self.assertRaises(OSError):
                with fresh.open(URL, b'{}', HEADERS): self.fail('expired connect sent HTTP')
        finally: fresh.close()
        self.assertEqual(len(Connection.instances), 1); self.assertEqual(Connection.instances[0].posts, [])

    def test_observer_emits_only_bounded_numbers_and_cannot_change_success(self):
        self.read(); self.read()
        for value in self.metrics:
            self.assertEqual(set(value), {'new', 'reused', 'age_ms', 'connect_elapsed_ms', 'connect_attempts'})
            self.assertTrue(all(type(number) is int and 0 <= number <= 3600000 for number in value.values()))
            self.assertEqual(value['new'] + value['reused'], 1)
            self.assertLessEqual(value['connect_attempts'], 2)
        self.transport.observer = lambda _: (_ for _ in ()).throw(RuntimeError('ignored observer'))
        self.read(); self.assertEqual(len(Connection.instances), 1)


if __name__ == '__main__': unittest.main()
