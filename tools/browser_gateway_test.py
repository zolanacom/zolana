"""Boundary/recovery tests; synthetic public packets, no chain or wallet state.

The upstream uses the existing native HTTP handlers with a disposable durable
authorization/relay fixture. These tests do not claim cryptographic verification
or validator finality: those remain the native service's responsibility.
"""
import base64
import copy
from email.message import Message
import gzip
import hashlib
import http.client
import io
from http.server import ThreadingHTTPServer
import json
import multiprocessing
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import browser_gateway as browser
from test_faucet import Handler as AdmissionHandler
from testnet_gateway import Handler as NativeHandler

NETWORK = {"network": [7] * 32, "genesis_hash": "1" * 32}
RPC_AUDIENCE = "https://rpc.fixture.invalid/"
FAUCET_AUDIENCE = "https://admission.fixture.invalid/"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def capability(purpose="rpc"):
    return dict(purpose=purpose, network=NETWORK,
                audience=RPC_AUDIENCE if purpose == "rpc" else FAUCET_AUDIENCE,
                fee_address="2" * 32, issued_at=1000, expires_at=1600,
                nonce="A" * 32, body_digest="0" * 64, signature="3" * 88)


def access():
    return base64.urlsafe_b64encode(encoded(capability())).decode().rstrip("=")


def query(method="getSlot", params=None, identity=17):
    return encoded(dict(jsonrpc="2.0", id=identity, method=method,
                        params=[] if params is None else params))


def packet():
    wire = bytearray(9230)
    wire[:8] = b"NPAY0003"
    wire[8:40] = bytes(NETWORK["network"])
    return dict(network=NETWORK, payload=base64.b64encode(wire).decode())


def profile(upstream):
    return dict(format="native-wallet-profile-v1", key_mode="user-wallet-v1",
                network=NETWORK["network"], genesis_hash=NETWORK["genesis_hash"],
                label="Disposable browser test", invite_required=True,
                program="7" * 32, pool="8" * 32,
                pool_format="NPOOL004", private_send_transport="native-inline-v1",
                rpc=dict(transport="loopback-http", url=upstream),
                faucet=dict(transport="loopback-http", url=upstream),
                access_audiences=dict(format="native-access-audiences-v1", **NETWORK,
                                      rpc=RPC_AUDIENCE, faucet=FAUCET_AUDIENCE))


class DurableFixture:
    """Known-fixture capability gate, not an implementation of signature checks."""
    required = True
    authorize_many = False
    compact_headers_per_unit = 16

    def __init__(self, root):
        self.path = Path(root) / "upstream-state.json"
        self.lock = threading.Lock()
        self.faucet = self
        self.info = {"network": NETWORK}
        self.seen = []
        self.block_submit = False
        self.committed = threading.Event()
        self.release_reply = threading.Event()
        self.set(auth_units=0, quota=100, revoked=False, submits=0, jobs={})

    def get(self):
        return json.loads(self.path.read_bytes())

    def set(self, **changes):
        with self.lock:
            state = self.get() if self.path.exists() else {}
            state.update(changes)
            pending = self.path.with_suffix(".new")
            pending.write_bytes(encoded(state))
            pending.replace(self.path)

    def ingress(self, channel, peer, units=1):
        self.seen.append(("ingress", channel, peer))

    def command(self, name, proof, extra=()):
        self.seen.append((name, copy.deepcopy(proof)))
        with self.lock:
            state = self.get()
            if name != "authorize" or proof != capability() or state["revoked"]:
                raise ValueError("invalid or revoked fixture capability")
            if state["auth_units"] >= state["quota"]:
                raise ValueError("request quota exhausted")
            state["auth_units"] += 1
            pending = self.path.with_suffix(".new")
            pending.write_bytes(encoded(state))
            pending.replace(self.path)

    def forward(self, raw):
        self.seen.append(("raw", raw))
        value = json.loads(raw)
        result = NETWORK["genesis_hash"] if value["method"] == "getGenesisHash" else 42
        return encoded(dict(jsonrpc="2.0", id=value["id"], result=result))

    def shielded(self, value, proof):
        if value["method"] == "submitShieldedPayment":
            identity = hashlib.sha256(encoded(value["params"][0])).hexdigest()
            with self.lock:
                state = self.get()
                state["submits"] += 1
                state["jobs"][identity] = "accepted"
                pending = self.path.with_suffix(".new")
                pending.write_bytes(encoded(state))
                pending.replace(self.path)
            self.committed.set()
            if self.block_submit:
                self.release_reply.wait(10)
            result = dict(id=identity, status="accepted")
        elif value["method"] == "getShieldedPaymentStatus":
            identity = value["params"][0]
            result = dict(id=identity, status=self.get()["jobs"].get(identity, "unknown"))
        else:
            result = dict(fee=3)
        return encoded(dict(jsonrpc="2.0", id=value["id"], result=result))

    def access_action(self, path, body):
        purpose = "join" if path == "/join" else "status"
        if body["proof"] != capability(purpose):
            raise ValueError("invalid fixture admission signature")
        self.seen.append(("admission", path, copy.deepcopy(body)))
        return dict(joined=True, fixture_only=True)


class ExistingNativeEntry(NativeHandler):
    def do_POST(self):
        self.server.app.seen.append(("headers", dict(self.headers)))
        if self.path in ("/join", "/status"):
            AdmissionHandler.do_POST(self)
        else:
            NativeHandler.do_POST(self)


def start_server(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def stop_server(server, thread):
    server.shutdown()
    server.server_close()
    thread.join(3)


def proxy_child(config, sender):
    app = browser.BrowserGateway(config, {"/": (b"fixture", "text/html")}, fixture_http=True)
    with browser.BrowserServer(("127.0.0.1", 0), app) as server:
        sender.send(server.server_port)
        sender.close()
        server.serve_forever()


class GzipResponseTests(unittest.TestCase):
    def body(self, raw, encodings=(), limit=256):
        class Response(io.BytesIO):
            pass
        response = Response(raw)
        response.headers = Message()
        for encoding in encodings:
            response.headers.add_header("Content-Encoding", encoding)
        return browser.response_body(response, limit)

    def test_identity_and_single_complete_gzip_preserve_exact_bytes(self):
        raw = b"x" * 256
        self.assertEqual(self.body(raw), raw)
        self.assertEqual(self.body(raw, ["identity"]), raw)
        self.assertEqual(self.body(gzip.compress(raw), ["gzip"]), raw)

    def test_compressed_identity_and_expanded_bounds_are_independent(self):
        with self.assertRaisesRegex(ValueError, "response exceeds byte bound"):
            self.body(b"x" * 257)
        with self.assertRaisesRegex(ValueError, "response exceeds byte bound"):
            self.body(bytes(range(256)) + b"x", ["gzip"])
        with self.assertRaisesRegex(ValueError, "decoded response exceeds byte bound"):
            self.body(gzip.compress(b"x" * 257), ["gzip"])

    def test_truncation_corruption_trailing_and_concatenated_members_refused(self):
        complete = gzip.compress(b'{"public":"fixture"}')
        corrupted = complete[:-8] + bytes([complete[-8] ^ 1]) + complete[-7:]
        for raw in (b"{}", complete[:-1], corrupted, complete + b"trailing", complete + complete):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                self.body(raw, ["gzip"])

    def test_unsupported_mixed_or_duplicate_encoding_refused(self):
        for encodings in (["br"], ["gzip, identity"], ["identity", "gzip"], ["gzip", "gzip"]):
            with self.subTest(encodings=encodings), self.assertRaisesRegex(ValueError, "encoding"):
                self.body(b"{}", encodings)


class BrowserGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.fixture = DurableFixture(self.temp.name)
        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), ExistingNativeEntry)
        self.upstream.app = self.fixture
        self.upstream.authority = f"127.0.0.1:{self.upstream.server_port}"
        self.upstream_thread = start_server(self.upstream)
        self.config = profile("http://" + self.upstream.authority + "/")
        self.app = browser.BrowserGateway(self.config, {"/": (b"public", "text/html")}, fixture_http=True)
        self.proxy = browser.BrowserServer(("127.0.0.1", 0), self.app)
        self.proxy_thread = start_server(self.proxy)

    def tearDown(self):
        self.fixture.release_reply.set()
        stop_server(self.proxy, self.proxy_thread)
        self.app.close()
        stop_server(self.upstream, self.upstream_thread)
        self.temp.cleanup()

    def send(self, raw=None, path="/rpc", headers=None, port=None, method="POST"):
        port = port or self.proxy.server_port
        defaults = {"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"}
        if path == "/rpc" and raw is not None:
            defaults["X-Testnet-Access"] = access()
        defaults.update(headers or {})
        for key in list(defaults):
            if defaults[key] is None:
                del defaults[key]
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=12)
        try:
            connection.request(method, path, raw, defaults)
            response = connection.getresponse()
            return response.status, response.read(), dict(response.getheaders())
        finally:
            connection.close()

    def test_same_origin_exact_bytes_original_audience_and_native_gate_unchanged(self):
        raw = b'{ "jsonrpc":"2.0", "id":17,"method":"getSlot", "params":[] }'
        code, body, _ = self.send(raw, headers={"Cookie": "never-forward=this"})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["result"], 42)
        self.assertIn(("raw", raw), self.fixture.seen)
        self.assertIn(("authorize", capability()), self.fixture.seen)
        upstream_headers = next(item[1] for item in self.fixture.seen if item[0] == "headers")
        self.assertNotIn("Origin", upstream_headers)
        self.assertNotIn("Cookie", upstream_headers)
        self.assertEqual(upstream_headers["X-Testnet-Access"], access())
        self.assertEqual(self.app.transport()["rpc_audience"], RPC_AUDIENCE)
        self.assertEqual(self.app.transport()["pool"], self.config["pool"])
        self.assertNotEqual(self.app.transport()["rpc_audience"], self.app.rpc_url)
        connection = http.client.HTTPConnection("127.0.0.1", self.upstream.server_port, timeout=3)
        connection.request("POST", "/", query(), {"Content-Type": "application/json", "Origin": self.proxy.origin, "X-Testnet-Access": access()})
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        connection.close()
        self.assertEqual(self.fixture.get()["auth_units"], 1)

    def test_external_wallet_link_can_open_only_the_public_entry_document(self):
        headers = {"Origin": None, "Sec-Fetch-Site": "cross-site",
                   "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}
        self.assertEqual(self.send(path="/", method="GET", headers=headers)[0], 200)
        self.assertEqual(self.send(path="/transport.json", method="GET", headers=headers)[0], 403)
        self.assertEqual(self.send(query(), headers=headers)[0], 403)
        self.assertEqual(self.send(path="/", method="GET", headers={**headers, "Sec-Fetch-Dest": "iframe"})[0], 403)
        self.assertEqual(self.fixture.get()["auth_units"], 0)

    def test_malformed_cross_origin_framing_and_secret_helpers_stop_before_upstream(self):
        for headers in ({"Host": "evil.invalid"}, {"Origin": "https://evil.invalid"},
                        {"Origin": None}, {"Origin": "null"}, {"Sec-Fetch-Site": "cross-site"},
                        {"Forwarded": "for=127.0.0.1"}, {"X-Forwarded-For": "127.0.0.1"},
                        {"X-Native-Operator": "secret"}, {"Authorization": "Bearer secret"},
                        {"Content-Type": "text/plain"}, {"Transfer-Encoding": "chunked"},
                        {"Content-Length": "32769"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.send(query(), headers=headers)[0], 403)
        for raw in (b'[]', b'{"jsonrpc":"2.0","jsonrpc":"2.0"}',
                    query("sendTransaction", ["public signed transaction"]),
                    query("wallet_unlock", ["password"]), query("getIdentity"),
                    query(params={}), query(identity=True),
                    query("getShieldedPaymentStatus", ["?" * 64]),
                    query("getWalletReadBatch", [[dict(method="sendTransaction", params=[])]]),
                    query("getHealth", [float("nan")])):
            with self.subTest(raw=raw[:80]):
                self.assertEqual(self.send(raw)[0], 403)
        for proof in (dict(capability(), audience="https://different.invalid/"),
                      dict(capability(), signature="?"), dict(capability(), password="never accepted"),
                      dict(capability(), network=dict(NETWORK, network=[8] * 32))):
            header = base64.urlsafe_b64encode(encoded(proof)).decode().rstrip("=")
            self.assertEqual(self.send(query(), headers={"X-Testnet-Access": header})[0], 403)
        self.assertEqual(self.fixture.seen, [])
        # Duplicate security/framing headers are refused too.
        connection = http.client.HTTPConnection("127.0.0.1", self.proxy.server_port, timeout=3)
        connection.putrequest("POST", "/rpc")
        connection.putheader("Origin", self.proxy.origin)
        connection.putheader("Origin", self.proxy.origin)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(query())))
        connection.endheaders(query())
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        connection.close()
        self.assertEqual(self.fixture.seen, [])

    def test_upstream_revocation_quota_and_each_read_remain_authoritative_after_restart(self):
        self.fixture.set(quota=2)
        for _ in range(2):
            self.assertEqual(self.send(query())[0], 200)
        code, _, headers = self.send(query())
        self.assertEqual(code, 429)
        self.assertTrue(1 <= int(headers["Retry-After"]) <= 61)
        stop_server(self.proxy, self.proxy_thread)
        self.proxy = browser.BrowserServer(("127.0.0.1", 0), self.app)
        self.proxy_thread = start_server(self.proxy)
        self.assertEqual(self.send(query())[0], 429)
        self.fixture.set(quota=100, revoked=True)
        self.assertEqual(self.send(query())[0], 403)
        self.assertEqual(self.fixture.get()["auth_units"], 2)
        self.assertEqual(sum(item[0] == "authorize" for item in self.fixture.seen), 5)

    def test_sync_account_read_uses_existing_bounded_public_read_contract(self):
        valid = query("getAccountInfo", ["6" * 32, {"commitment": "confirmed", "encoding": "base64"}])
        self.assertEqual(self.send(valid)[0], 200)
        finalized = query("getAccountInfo", ["6" * 32, {"commitment": "finalized", "encoding": "base64"}])
        self.assertEqual(self.send(finalized)[0], 200)
        before = len(self.fixture.seen)
        for params in (["6" * 32, {"commitment": "processed", "encoding": "base64"}],
                       ["?", {"commitment": "finalized"}], ["6" * 32],
                       ["6" * 32, {"commitment": "confirmed", "encoding": "base64", "dataSlice": {"offset": 0, "length": 1}}]):
            self.assertEqual(self.send(query("getAccountInfo", params))[0], 403)
        self.assertEqual(len(self.fixture.seen), before)

    def test_compact_history_preserves_existing_invited_request_bounds(self):
        for method in ("getWalletRetainedHistoryV2", "getWalletRetainedHistoryV3"):
            raw = query(method, [0, 100, None, 32768])
            url, value = self.app.request("/rpc", raw, access())
            self.assertEqual(url, self.config["rpc"]["url"])
            self.assertEqual(value, json.loads(raw))
            with self.assertRaises(ValueError): self.app.request("/rpc", raw, None)
            for params in ([0, 100, None, 32769], [False, 100, None],
                           [0, 100, {"segments": 1, "sha256": "changed"}],
                           [0, 100, None, 32768, "extra"]):
                with self.assertRaises(ValueError): self.app.request("/rpc", query(method, params), access())

    def test_sync_snapshot_only_accepts_one_saved_slot_and_signed_access(self):
        for slot in (0, 1, 2**64 - 1):
            raw = query("getWalletSyncSnapshot", [slot])
            url, value = self.app.request("/rpc", raw, access())
            self.assertEqual(url, self.config["rpc"]["url"])
            self.assertEqual(value, json.loads(raw))
            with self.assertRaises(ValueError):
                self.app.request("/rpc", raw, None)
        for params in ([], [False], [-1], [2**64], [1.5], ["1"], [1, 2],
                       [{"slot": 1}], [1, {"url": "https://other.invalid/"}]):
            with self.assertRaises(ValueError):
                self.app.request("/rpc", query("getWalletSyncSnapshot", params), access())

    def test_admission_is_signed_public_opaque_and_does_not_bypass_existing_origin(self):
        claim = dict(format="native-test-grant-v1", network=NETWORK,
                     private_address="npriv1" + "4" * 100, fee_address="2" * 32, signature="3" * 88)
        join = dict(claim=claim, invitation="fixture_invitation", proof=capability("join"))
        self.assertEqual(self.send(encoded(join), "/admission/join")[0], 200)
        self.assertIn(("admission", "/join", join), self.fixture.seen)
        self.assertEqual(self.send(encoded(dict(proof=capability("status"))), "/admission/status")[0], 200)
        before = len(self.fixture.seen)
        for bad in (dict(join, password="never accepted"),
                    dict(join, proof=capability("rpc")), dict(join, invitation="?"),
                    dict(join, claim=dict(claim, fee_address="5" * 32))):
            self.assertEqual(self.send(encoded(bad), "/admission/join")[0], 403)
        self.assertEqual(len(self.fixture.seen), before)

    def test_responses_match_original_identity_and_redirect_or_malformed_encoding_is_refused(self):
        for result in (dict(jsonrpc="2.0", id="17", result=42),
                       dict(jsonrpc="2.0", id=17, result=42, error=None),
                       dict(jsonrpc="1.0", id=17, result=42)):
            with patch.object(self.fixture, "forward", return_value=encoded(result)):
                code, raw, _ = self.send(query())
                self.assertEqual(code, 502)
                self.assertEqual(json.loads(raw)["outcome"], "unknown")
        with patch.object(self.fixture, "forward", return_value=encoded(dict(jsonrpc="2.0", id=17, result="2" * 32))):
            self.assertEqual(self.send(query("getGenesisHash"), headers={"X-Testnet-Access": None})[0], 502)
        with patch("browser_gateway.RESPONSE_LIMIT", 64):
            with patch.object(self.fixture, "forward", return_value=encoded(dict(jsonrpc="2.0", id=17, result="x" * 65))):
                self.assertEqual(self.send(query())[0], 502)
        # A redirect is not followed; a malformed gzip body is refused.
        class BadUpstream(ExistingNativeEntry):
            def do_POST(self):
                self.server.count += 1
                self.send_response(302 if self.server.redirect else 200)
                self.send_header("Location", "/stolen")
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Encoding", "gzip")
                self.end_headers()
                self.wfile.write(b'{}')
        server = ThreadingHTTPServer(("127.0.0.1", 0), BadUpstream)
        server.count, server.redirect = 0, True
        thread = start_server(server)
        original = self.app.rpc_url
        original_transport = self.app.upstream_transport
        try:
            self.app.rpc_url = f"http://127.0.0.1:{server.server_port}/"
            self.app.upstream_transport = browser.UpstreamTransport((self.app.rpc_url,), fixture_http=True)
            self.assertEqual(self.send(query())[0], 502)
            self.assertEqual(server.count, 1)
            server.redirect = False
            self.assertEqual(self.send(query())[0], 502)
            self.assertEqual(server.count, 2)
        finally:
            self.app.upstream_transport.close()
            self.app.upstream_transport = original_transport
            self.app.rpc_url = original
            stop_server(server, thread)

    def test_gzip_upstream_is_decoded_once_with_original_request_and_plain_browser_reply(self):
        class GzipUpstream(ExistingNativeEntry):
            def do_POST(self):
                self.server.seen.append((self.rfile.read(int(self.headers["Content-Length"])), dict(self.headers)))
                raw = gzip.compress(encoded(dict(jsonrpc="2.0", id=17, result=42)), mtime=0)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Encoding", "gzip")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
        server = ThreadingHTTPServer(("127.0.0.1", 0), GzipUpstream)
        server.seen = []
        thread = start_server(server)
        original = self.app.rpc_url
        original_transport = self.app.upstream_transport
        raw = b'{ "jsonrpc":"2.0", "id":17,"method":"getSlot", "params":[] }'
        try:
            self.app.rpc_url = f"http://127.0.0.1:{server.server_port}/"
            self.app.upstream_transport = browser.UpstreamTransport((self.app.rpc_url,), fixture_http=True)
            code, body, headers = self.send(raw)
            self.assertEqual((code, body), (200, encoded(dict(jsonrpc="2.0", id=17, result=42))))
            self.assertNotIn("Content-Encoding", headers)
            self.assertEqual(len(server.seen), 1)
            sent, upstream = server.seen[0]
            self.assertEqual(sent, raw)
            self.assertEqual(upstream["Accept-Encoding"], "gzip")
            self.assertEqual(upstream["X-Testnet-Access"], access())
        finally:
            self.app.upstream_transport.close()
            self.app.upstream_transport = original_transport
            self.app.rpc_url = original
            stop_server(server, thread)

    def test_public_config_static_routes_and_security_policy_have_no_secret_routes(self):
        code, raw, headers = self.send(path="/wallet-config.json", method="GET")
        self.assertEqual(code, 200)
        self.assertEqual(set(json.loads(raw)), {"format", "network", "label", "coin", "environment"})
        self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertEqual(headers["Cross-Origin-Embedder-Policy"], "require-corp")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn("blob:", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.app.allow_blob_workers = True
        self.assertIn("worker-src 'self' blob:", self.send(path="/", method="GET")[2]["Content-Security-Policy"])
        for path in ("/seed.json", "/wallet_unlock", "/../private", "/?download=seed"):
            self.assertEqual(self.send(path=path, method="GET")[0], 404)
        self.assertEqual(self.send(query(), path="/rpc?upstream=https://evil.invalid")[0], 404)

    def test_abrupt_proxy_crash_after_commit_recovers_original_status_without_resubmitting(self):
        self.fixture.block_submit = True
        context = multiprocessing.get_context("spawn")
        processes = []
        def launch():
            reader, writer = context.Pipe(duplex=False)
            child = context.Process(target=proxy_child, args=(self.config, writer))
            child.start()
            writer.close()
            processes.append(child)
            self.assertTrue(reader.poll(5), "Disposable proxy failed to bind")
            port = reader.recv()
            reader.close()
            return child, port
        errors = []
        child, port = launch()
        raw = query("submitShieldedPayment", [packet()])
        identity = hashlib.sha256(encoded(packet())).hexdigest()
        def submit():
            try:
                self.send(raw, port=port)
            except (OSError, http.client.HTTPException) as error:
                errors.append(type(error).__name__)
        sender = threading.Thread(target=submit)
        try:
            sender.start()
            self.assertTrue(self.fixture.committed.wait(5), "Synthetic upstream did not commit")
            child.kill()
            child.join(5)
            self.assertFalse(child.is_alive())
            self.fixture.release_reply.set()
            sender.join(5)
            self.assertFalse(sender.is_alive())
            self.assertTrue(errors, "The killed proxy must not acknowledge success")
            _, resumed_port = launch()
            code, reply, _ = self.send(query("getShieldedPaymentStatus", [identity]), port=resumed_port)
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(reply)["result"], {"id": identity, "status": "accepted"})
            state = self.fixture.get()
            self.assertEqual(state["submits"], 1)
            self.assertEqual(state["auth_units"], 2)
        finally:
            self.fixture.release_reply.set()
            sender.join(5)
            for process in processes:
                if process.is_alive():
                    process.kill()
                process.join(5)


class PinnedPreparationTests(unittest.TestCase):
    def test_only_reviewed_public_assets_are_served_and_hashes_are_checked_before_bind(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "index.html").write_bytes(b"reviewed")
            (root / "operator.key").write_bytes(b"never served")
            item = dict(path="index.html", sha256=hashlib.sha256(b"reviewed").hexdigest())
            doc = dict(format="zolana-browser-assets-v1", assets={"/": item})
            raw = encoded(doc)
            digest = hashlib.sha256(raw).hexdigest()
            bundle = browser.assets(root, raw, digest)
            (root / "index.html").write_bytes(b"changed")
            self.assertEqual(bundle["/"][0], b"reviewed")
            with self.assertRaises(ValueError):
                browser.assets(root, raw, digest)
            with self.assertRaises(ValueError):
                browser.assets(root, raw, "0" * 64)
            (root / "linked.html").symlink_to(root / "index.html")
            linked = encoded(dict(format=doc["format"], assets={"/": dict(item, path="linked.html")}))
            with self.assertRaises(ValueError):
                browser.assets(root, linked, hashlib.sha256(linked).hexdigest())
            for url, path in (("/rpc", "index.html"), ("/../key", "index.html"),
                              ("/key", "../operator.key"), ("/key", "operator.key")):
                bad = encoded(dict(format=doc["format"], assets={"/": item, url: dict(item, path=path)}))
                with self.assertRaises(ValueError):
                    browser.assets(root, bad, hashlib.sha256(bad).hexdigest())

    def test_live_configuration_requires_fixed_validated_https_and_exact_network_audiences(self):
        fixture = profile("http://127.0.0.1:1234/")
        with self.assertRaises(ValueError):
            browser.BrowserGateway(fixture, {})
        live = copy.deepcopy(fixture)
        for key in ("rpc", "faucet"):
            live[key] = dict(transport="https", url=f"https://{key}.fixture.invalid/")
        browser.BrowserGateway(live, {})
        for mutate in (lambda p: p.update(local_tls_ca_pem="custom CA"),
                       lambda p: p.update(invite_required=False),
                       lambda p: p["rpc"].update(url="https://user:pass@rpc.fixture.invalid/"),
                       lambda p: p["rpc"].update(url="https://rpc.fixture.invalid/arbitrary"),
                       lambda p: p["rpc"].update(url="https://rpc.fixture.invalid/?secret=x"),
                       lambda p: p["rpc"].update(url=42),
                       lambda p: p["access_audiences"].update(network=[8] * 32)):
            changed = copy.deepcopy(live)
            mutate(changed)
            with self.assertRaises(ValueError):
                browser.BrowserGateway(changed, {})
        with self.assertRaises(ValueError):
            browser.BrowserServer(("0.0.0.0", 0), browser.BrowserGateway(live, {}))


if __name__ == "__main__":
    unittest.main()
