"""Disposable HTTPS boundary tests; no real wallets, funding or external RPC.

The recording application uses the existing request validator, then replaces
only upstream execution. These tests establish TLS/browser delivery boundaries,
not cryptographic authorization or chain finality.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import http.client
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import browser_gateway as browser
import browser_gateway_https as public
from local_test_tls import create as create_tls

NETWORK = {"network": [7] * 32, "genesis_hash": "1" * 32}
RPC = "https://rpc.fixture.invalid"
FAUCET = "https://admission.fixture.invalid"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def proof(purpose="rpc"):
    return dict(purpose=purpose, network=NETWORK, audience=RPC if purpose == "rpc" else FAUCET,
                fee_address="2" * 32, issued_at=1000, expires_at=1600, nonce="A" * 32,
                body_digest="0" * 64, signature="3" * 88)


def access():
    return base64.urlsafe_b64encode(encoded(proof())).decode().rstrip("=")


class RecordingApp(browser.BrowserGateway):
    def __init__(self):
        profile = dict(format="native-wallet-profile-v1", key_mode="user-wallet-v1", **NETWORK,
                       label="HTTPS disposable fixture", invite_required=True, program="7" * 32,
                       pool="8" * 32, pool_format="NPOOL004", private_send_transport="native-inline-v1",
                       rpc=dict(transport="https", url=RPC), faucet=dict(transport="https", url=FAUCET))
        super().__init__(profile, {"/": (b"public fixture", "text/html")})
        self.calls = []

    def forward(self, path, body, token):
        self.calls.append((path, body, token))
        return 200, b'{"jsonrpc":"2.0","id":1,"result":123}', None


@contextmanager
def running(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def request(port, ca, host, *, method="GET", path="/", body=b"", headers=(),
            server_name="127.0.0.1", verify=True):
    ctx = ssl.create_default_context(cafile=str(ca)) if verify else ssl._create_unverified_context()
    with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
        with ctx.wrap_socket(sock, server_hostname=server_name) as stream:
            lines = [f"{method} {path} HTTP/1.1", f"Host: {host}", "Connection: close"]
            if method == "POST":
                lines += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
            lines += [key + ": " + value for key, value in headers]
            stream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
            response = http.client.HTTPResponse(stream)
            response.begin()
            return response.status, response.read(), dict(response.getheaders())


class HTTPSBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="zolana-browser-https-")
        cls.root = Path(cls.tmp.name)
        cls.tls = cls.root / "tls"
        create_tls(cls.tls)
        ext = cls.tls / "dns.cnf"
        ext.write_text("basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:wallet.fixture.invalid\n")
        subprocess.run(["openssl", "x509", "-req", "-in", str(cls.tls / "server.csr"),
                        "-CA", str(cls.tls / "ca.crt"), "-CAkey", str(cls.tls / "ca.key"),
                        "-set_serial", "99", "-out", str(cls.tls / "dns.crt"), "-days", "2",
                        "-sha256", "-extfile", str(ext)], check=True, capture_output=True, timeout=20)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.origin = f"https://127.0.0.1:{self.port}"
        self.host = f"127.0.0.1:{self.port}"
        self.cert, self.key = self.tls / "server.crt", self.tls / "server.key"
        self.path = self.root / "policy.json"
        self.app = RecordingApp()
        self.write_policy()

    def tearDown(self):
        self.app.close()

    def write_policy(self, **changes):
        value = dict(format="zolana-direct-tls-v1", audience=self.origin, bind_ip="127.0.0.1",
                     port=self.port, certificate_sha256=hashlib.sha256(self.cert.read_bytes()).hexdigest(),
                     key_sha256=hashlib.sha256(self.key.read_bytes()).hexdigest())
        value.update(changes)
        body = encoded(value)
        self.path.write_bytes(body)
        self.path.chmod(0o600)
        self.sha = hashlib.sha256(body).hexdigest()

    def server(self):
        return public.listener(self.origin, self.port, self.app, self.cert, self.key, self.path, self.sha)

    def call(self, **kwargs):
        return request(self.port, self.tls / "ca.crt", self.host, **kwargs)

    def rpc(self, headers=(), method="getSlot", token=None):
        body = encoded(dict(jsonrpc="2.0", id=1, method=method, params=[]))
        return self.call(method="POST", path="/rpc", body=body,
                         headers=[("Origin", self.origin), ("Sec-Fetch-Site", "same-origin"),
                                  ("X-Testnet-Access", access() if token is None else token), *headers])

    def test_loopback_default_unchanged_and_explicit_policy_fails_before_bind(self):
        with self.assertRaisesRegex(ValueError, "loopback"):
            browser.BrowserServer(("0.0.0.0", self.port), self.app)
        with patch.object(public, "TLSServer") as bind:
            for changes in ({"extra": True}, {"bind_ip": "localhost"}, {"bind_ip": "224.0.0.1"},
                            {"port": True}, {"port": self.port + 1}, {"certificate_sha256": "0" * 64},
                            {"key_sha256": "0" * 64}):
                self.write_policy(**changes)
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    self.server()
            self.write_policy()
            self.sha = "0" * 64
            with self.assertRaises(ValueError):
                self.server()
            bind.assert_not_called()

    def test_noncanonical_or_non_https_origin_and_public_policy_file_refuse(self):
        for origin in (self.origin + "/", self.origin + "?x", self.origin + "#x",
                       self.origin.replace("https:", "http:"), f"https://user@127.0.0.1:{self.port}",
                       f"https://0.0.0.0:{self.port}", f"https://127.1:{self.port}"):
            self.origin = origin
            self.write_policy()
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.server()
        self.origin = f"https://127.0.0.1:{self.port}"
        self.write_policy()
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            self.server()

    def test_real_https_static_config_and_cross_site_entry_navigation(self):
        with running(self.server()):
            status, body, headers = self.call()
            self.assertEqual((status, body), (200, b"public fixture"))
            self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
            self.assertEqual(headers["Cross-Origin-Embedder-Policy"], "require-corp")
            self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])
            self.assertEqual(self.call(headers=[("Sec-Fetch-Site", "cross-site"),
                                                ("Sec-Fetch-Mode", "navigate"),
                                                ("Sec-Fetch-Dest", "document")])[0], 200)
            self.assertEqual(self.call(path="/wallet-config.json", headers=[("Sec-Fetch-Site", "cross-site")])[0], 403)
            status, body, _ = self.call(path="/transport.json")
            self.assertEqual(status, 200)
            transport = json.loads(body)
            self.assertEqual(transport["rpc_path"], "/rpc")
            self.assertEqual(transport["rpc_audience"], RPC)
            self.assertTrue(transport["operator_metadata_visible"])
            self.assertFalse(transport["automatic_retry"])
            self.assertEqual(self.app.calls, [])

    def test_same_origin_signed_rpc_succeeds_without_relaxing_headers(self):
        with running(self.server()):
            self.assertEqual(self.rpc()[0], 200)
            self.assertEqual(len(self.app.calls), 1)
            self.assertEqual(self.app.calls[0][2], access())
            self.app.calls.clear()
            duplicates = [("Host", self.host), ("Origin", self.origin), ("Content-Length", "2"),
                          ("Content-Type", "text/plain"), ("X-Testnet-Access", access()),
                          ("Sec-Fetch-Site", "same-origin")]
            forbidden = [("Forwarded", "for=198.51.100.2"), ("X-Forwarded-For", "198.51.100.2"),
                         ("X-Forwarded-Host", self.host), ("X-Forwarded-Proto", "https"),
                         ("X-Real-IP", "198.51.100.2"), ("Authorization", "Bearer fixture"),
                         ("Proxy-Authorization", "fixture"), ("X-Native-Operator", "fixture"),
                         ("Transfer-Encoding", "chunked")]
            for header in duplicates + forbidden:
                with self.subTest(header=header):
                    self.assertEqual(self.rpc(headers=[header])[0], 403)
            for headers in ([], [("Origin", "https://evil.fixture.invalid")],
                            [("Origin", self.origin.replace("https:", "http:"))],
                            [("Origin", self.origin), ("Sec-Fetch-Site", "cross-site")]):
                self.assertEqual(self.call(method="POST", path="/rpc", body=b"{}", headers=headers)[0], 403)
            self.assertEqual(request(self.port, self.tls / "ca.crt", "wrong.fixture.invalid")[0], 403)
            self.assertEqual(self.app.calls, [])

    def test_rpc_access_allowlist_body_caps_and_admission_remain_enforced(self):
        with running(self.server()):
            self.assertEqual(self.rpc(method="sendTransaction")[0], 403)
            self.assertEqual(self.rpc(token="not_a_valid_capability")[0], 403)
            self.assertEqual(self.call(method="POST", path="/rpc", body=b" " * 32769,
                                      headers=[("Origin", self.origin)])[0], 403)
            self.assertEqual(self.call(method="POST", path="/rpc", body=b"{",
                                      headers=[("Origin", self.origin)])[0], 403)
            self.assertEqual(self.call(method="POST", path="/rpc", body=encoded({"password": "fixture-only"}),
                                      headers=[("Origin", self.origin)])[0], 403)
            self.assertEqual(self.app.calls, [])
            body = encoded({"proof": proof("status")})
            self.assertEqual(self.call(method="POST", path="/admission/status", body=body,
                                      headers=[("Origin", self.origin)])[0], 200)
            self.assertEqual(self.app.calls[0], ("/admission/status", body, None))

    def test_tls_hostname_trust_sni_and_plain_http_cannot_reach_app(self):
        self.origin = f"https://wallet.fixture.invalid:{self.port}"
        self.host = f"wallet.fixture.invalid:{self.port}"
        self.cert = self.tls / "dns.crt"
        self.write_policy()
        with running(self.server()):
            self.assertEqual(self.call(server_name="wallet.fixture.invalid")[0], 200)
            for name in ("rpc.fixture.invalid", "127.0.0.1", None):
                with self.subTest(sni=name), self.assertRaises(ssl.SSLError):
                    self.call(server_name=name, verify=False)
            with self.assertRaises(ssl.SSLCertVerificationError):
                ctx = ssl.create_default_context()
                with socket.create_connection(("127.0.0.1", self.port), timeout=4) as sock:
                    ctx.wrap_socket(sock, server_hostname="wallet.fixture.invalid")
            with socket.create_connection(("127.0.0.1", self.port), timeout=4) as plain:
                plain.sendall(b"GET / HTTP/1.1\r\nHost: wallet.fixture.invalid\r\n\r\n")
                try:
                    self.assertEqual(plain.recv(1024), b"")
                except ConnectionResetError:
                    pass
            self.assertEqual(self.app.calls, [])

    def test_socket_ip_limit_returns_429_before_body_or_upstream_and_bad_headers_still_403(self):
        server = self.server()
        server.request_budget = public.RequestBudget(clock=lambda: 0)
        for _ in range(64):
            self.assertTrue(server.request_budget.allow("127.0.0.1"))
        with running(server):
            status, body, headers = self.rpc()
            self.assertEqual(status, 429)
            self.assertEqual(headers["Retry-After"], "1")
            self.assertFalse(json.loads(body)["automatic_retry"])
            self.assertEqual(self.rpc(headers=[("X-Forwarded-For", "198.51.100.8")])[0], 403)
            self.assertEqual(self.rpc()[0], 429)
            self.assertEqual(set(server.request_budget.peers), {"127.0.0.1"})
            self.assertEqual(self.app.calls, [])


class RequestBudgetTests(unittest.TestCase):
    def test_concurrent_per_ip_and_global_bursts_are_atomic_and_bounded(self):
        budget = public.RequestBudget(clock=lambda: 0)
        with ThreadPoolExecutor(max_workers=16) as pool:
            self.assertEqual(sum(pool.map(budget.allow, ["198.51.100.1"] * 512)), 64)
        budget = public.RequestBudget(clock=lambda: 0)
        peers = [f"198.51.{i // 254}.{i % 254 + 1}" for i in range(512)]
        with ThreadPoolExecutor(max_workers=16) as pool:
            self.assertEqual(sum(pool.map(budget.allow, peers)), 256)
        self.assertEqual(len(budget.peers), 256)

    def test_rejection_does_not_refill_and_refill_uses_elapsed_time(self):
        now = [0.0]
        budget = public.RequestBudget(clock=lambda: now[0])
        for _ in range(64):
            self.assertTrue(budget.allow("198.51.100.1"))
        self.assertFalse(budget.allow("198.51.100.1"))
        now[0] = 1 / 32
        self.assertFalse(budget.allow("198.51.100.1"))
        now[0] = 1 / 16
        self.assertTrue(budget.allow("198.51.100.1"))
        self.assertFalse(budget.allow("198.51.100.1"))
        for peer in ("198.051.100.1", "localhost", "::1", "198.51.100.1, 1.2.3.4"):
            self.assertFalse(budget.allow(peer))
        self.assertEqual(len(budget.peers), 1)

    def test_full_table_refuses_new_addresses_without_evicting_active_buckets(self):
        now = [0.0]
        budget = public.RequestBudget(clock=lambda: now[0])
        for i in range(1024):
            now[0] = i / 64
            self.assertTrue(budget.allow(f"198.18.{i // 254}.{i % 254 + 1}"))
        self.assertEqual(len(budget.peers), 1024)
        for _ in range(32):
            self.assertFalse(budget.allow("203.0.113.1"))
        self.assertEqual(len(budget.peers), 1024)
        self.assertTrue(budget.allow("198.18.0.1"))
        now[0] += 60
        self.assertTrue(budget.allow("203.0.113.1"))
        self.assertEqual(set(budget.peers), {"203.0.113.1"})


if __name__ == "__main__":
    unittest.main()
