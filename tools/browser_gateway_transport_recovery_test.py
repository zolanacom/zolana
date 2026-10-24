"""Real disposable verified-TLS transport boundaries; no wallets or pilot RPC."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading
import unittest

from browser_gateway_transport import UpstreamTransport
from local_test_tls import create as create_tls


class TLSEndpoint:
    def __init__(self, certificates, leaf="server"):
        self.mode = "valid"
        self.redirect = None
        self.requests = []
        self.connections = 0
        self.lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def setup(self):
                super().setup()
                self.connection.settimeout(3)
                with owner.lock:
                    owner.connections += 1
                    self.connection_id = owner.connections

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                query = json.loads(raw)
                with owner.lock:
                    owner.requests.append(dict(connection=self.connection_id, raw=raw,
                        access=self.headers.get("X-Testnet-Access"), cookie=self.headers.get("Cookie")))
                    mode = owner.mode
                if mode == "lost-reply":
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                reply_id = query["id"] + 1 if mode == "wrong-id" else query["id"]
                body = json.dumps(dict(jsonrpc="2.0", id=reply_id, result="ok")).encode()
                if mode == "bad-json":
                    body = b"not-json"
                elif mode == "oversize":
                    body = b"x" * 512
                self.send_response(302 if mode == "redirect" else 200)
                self.send_header("Content-Type", "text/plain" if mode == "bad-type" else "application/json")
                self.send_header("Content-Length", str(len(body) + (20 if mode == "partial" else 0)))
                if mode == "redirect":
                    self.send_header("Location", owner.redirect)
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()
                if mode in ("partial", "stale"):
                    # Deliberately omit Connection:close. This represents an
                    # unexpected peer loss, not an advertised reusable socket.
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.handle_error = lambda *_: None  # Expected refused-body resets only.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificates / (leaf + ".crt"), certificates / (leaf + ".key"))
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.origin = "https://127.0.0.1:" + str(self.server.server_port)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=4)


def body(method="getWalletSyncSnapshot", identity=1):
    return json.dumps(dict(jsonrpc="2.0", id=identity, method=method, params=[])).encode()


def checked(transport, endpoint, *, raw=None, access=None, limit=4096):
    raw = body() if raw is None else raw
    headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
    if access is not None:
        headers["X-Testnet-Access"] = access
    with transport.open(endpoint.origin + "/", raw, headers, timeout=3) as response:
        if response.status != 200 or response.headers.get_content_type() != "application/json":
            raise ValueError("synthetic status/type validation failed")
        # Match production response_body's single bounded read exactly. The
        # transport must expose a truncated Content-Length on this call.
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("synthetic response size refused")
        value = json.loads(data)
        if value.get("id") != json.loads(raw)["id"]:
            raise ValueError("synthetic identity validation failed")
        return value


class RecoveryTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="browser-transport-tls-")
        cls.certificates = Path(cls.temporary.name) / "tls"
        create_tls(cls.certificates)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def server(self, leaf="server"):
        endpoint = TLSEndpoint(self.certificates, leaf)
        self.addCleanup(endpoint.close)
        return endpoint

    def transport(self, *endpoints, context=None):
        if context is None:
            context = ssl.create_default_context(cafile=str(self.certificates / "ca.crt"))
        transport = UpstreamTransport([e.origin for e in endpoints], context=context)
        self.addCleanup(transport.close)
        return transport

    def test_verified_tls_reuses_socket_with_fresh_access_headers_and_separate_origins(self):
        first, second = self.server(), self.server()
        transport = self.transport(first, second)
        checked(transport, first, access="fixture-A")
        checked(transport, first, access="fixture-B")
        checked(transport, first)
        checked(transport, second)
        self.assertEqual(first.connections, 1)
        self.assertEqual([r["access"] for r in first.requests], ["fixture-A", "fixture-B", None])
        self.assertTrue(all(r["cookie"] is None for r in first.requests + second.requests))
        self.assertEqual(second.connections, 1)
        self.assertIsNone(second.requests[0]["access"])

    def test_lost_submit_reply_never_reconnects_or_replays_the_original(self):
        endpoint = self.server()
        endpoint.mode = "lost-reply"
        transport = self.transport(endpoint)
        original = body("submitShieldedPayment")
        with self.assertRaises((OSError, ValueError, http.client.HTTPException)):
            checked(transport, endpoint, raw=original, access="fixture-proof")
        self.assertEqual(endpoint.connections, 1)
        self.assertEqual(len(endpoint.requests), 1)
        self.assertEqual(endpoint.requests[0]["raw"], original)

    def test_stale_reused_socket_failure_is_not_automatically_retried(self):
        endpoint = self.server()
        endpoint.mode = "stale"
        transport = self.transport(endpoint)
        checked(transport, endpoint)
        endpoint.mode = "valid"
        with self.assertRaises((OSError, ValueError, http.client.HTTPException)):
            checked(transport, endpoint, raw=body("submitShieldedPayment", 2))
        self.assertEqual(endpoint.connections, 1)
        self.assertEqual(len(endpoint.requests), 1)

    def test_failed_body_or_application_validation_discards_connection(self):
        for mode in ("bad-json", "bad-type", "wrong-id", "oversize", "partial"):
            with self.subTest(mode=mode):
                endpoint = self.server()
                transport = self.transport(endpoint)
                endpoint.mode = mode
                with self.assertRaises((OSError, ValueError, http.client.HTTPException)):
                    checked(transport, endpoint, limit=128)
                self.assertEqual(len(endpoint.requests), 1)
                endpoint.mode = "valid"
                checked(transport, endpoint)
                self.assertEqual(endpoint.connections, 2)
                self.assertEqual(len(endpoint.requests), 2)

    def test_redirect_is_not_followed_even_to_another_allowed_origin(self):
        first, second = self.server(), self.server()
        transport = self.transport(first, second)
        first.mode, first.redirect = "redirect", second.origin + "/"
        with self.assertRaises(ValueError):
            checked(transport, first)
        self.assertEqual(len(first.requests), 1)
        self.assertEqual(second.requests, [])
        first.mode = "valid"
        checked(transport, first)
        self.assertEqual(first.connections, 2)

    def test_untrusted_and_wrong_host_certificates_fail_before_rpc(self):
        endpoint = self.server()
        context = ssl.create_default_context()
        transport = self.transport(endpoint, context=context)
        with self.assertRaises(ssl.SSLCertVerificationError):
            checked(transport, endpoint)
        self.assertEqual(endpoint.requests, [])
        wrong = self.server("wrong-host")
        with self.assertRaises(ssl.SSLCertVerificationError):
            checked(self.transport(wrong), wrong)
        self.assertEqual(wrong.requests, [])


if __name__ == "__main__":
    unittest.main()
