#!/usr/bin/env python3
"""Isolated same-origin browser ingress preparation; no wallet secrets or raw RPC.

This loopback-only preparation proxies public, already signed packets to fixed
invited services. Existing admission, revocation, durable quotas and relay
journals stay authoritative upstream. It never retries an uncertain request.
"""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path, PurePosixPath
import re
import urllib.error
import urllib.parse
import zlib

from test_faucet import BoundedServer
from testnet_gateway import read_calls, history_slots, retained_window
from browser_gateway_transport import UpstreamTransport

RPC_LIMIT = 32768
ACCESS_LIMIT = 4096
RESPONSE_LIMIT = 16 * 1024 * 1024
METHODS = frozenset({
    "getGenesisHash", "getHealth", "getSlot", "getBlockHeight", "getEpochInfo",
    "getWalletReadBatch", "getWalletSyncSnapshot", "getWalletHistoryBlocks", "getWalletRetainedHistory",
    "getWalletRetainedHistoryV2", "getWalletRetainedHistoryV3", "getWalletCanonicalHistory",
    "getShieldedFeeQuote", "submitShieldedPayment", "getShieldedPaymentStatus",
    "getAccountInfo", "getMultipleAccounts", "getBlocks", "getBlock", "getSignaturesForAddress",
    "getSignatureStatuses", "getTransaction",
})
PROOF_FIELDS = {"purpose", "network", "audience", "fee_address", "issued_at", "expires_at", "nonce", "body_digest", "signature"}
B58 = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".wasm": "application/wasm", ".svg": "image/svg+xml",
        ".woff2": "font/woff2", ".json": "application/json"}
RESERVED = {"/rpc", "/admission/join", "/admission/status", "/wallet-config.json", "/transport.json"}


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Ambiguous JSON object.")
        value[key] = item
    return value


def decode(raw):
    def invalid(_):
        raise ValueError("Nonfinite JSON value.")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def response_body(response, limit):
    encodings = response.headers.get_all("Content-Encoding", [])
    if len(encodings) > 1 or (encodings and encodings[0] not in ("identity", "gzip")):
        raise ValueError("Unexpected invited response encoding.")
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Invited response exceeds byte bound.")
    if encodings != ["gzip"]:
        return raw
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        body = decoder.decompress(raw, limit + 1)
    except zlib.error as error:
        raise ValueError("Invalid invited gzip response.") from error
    if len(body) > limit:
        raise ValueError("Invited decoded response exceeds byte bound.")
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("Incomplete or ambiguous invited gzip response.")
    return body


def bounded_text(value, minimum, maximum, pattern=None):
    return (isinstance(value, str) and minimum <= len(value) <= maximum and
            (pattern is None or re.fullmatch(pattern, value) is not None))


def network(value):
    if (not isinstance(value, dict) or set(value) != {"network", "genesis_hash"} or
            not isinstance(value["network"], list) or len(value["network"]) != 32 or
            any(type(n) is not int or not 0 <= n <= 255 for n in value["network"]) or
            not any(value["network"]) or not bounded_text(value["genesis_hash"], 32, 44, B58)):
        raise ValueError("Invalid pinned public network.")
    return value


def endpoint(value, fixture_http=False):
    if not bounded_text(value, 1, 2048) or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        raise ValueError("Invalid fixed invited endpoint.")
    parsed = urllib.parse.urlsplit(value)
    if (not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or
            parsed.path not in ("", "/") or parsed.port == 0):
        raise ValueError("Only fixed invited service roots are supported.")
    if parsed.scheme != "https":
        if not (fixture_http and parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port):
            raise ValueError("Invited upstream requires certificate-validated HTTPS.")
    return value


def public_profile(value, fixture_http=False):
    if (not isinstance(value, dict) or value.get("format") != "native-wallet-profile-v1" or
            value.get("key_mode") != "user-wallet-v1" or value.get("invite_required") is not True or
            value.get("pool_format") != "NPOOL004" or value.get("private_send_transport") != "native-inline-v1" or
            value.get("local_tls_ca_pem") is not None or not bounded_text(value.get("label"), 1, 64, r"[A-Za-z0-9 ._-]+")):
        raise ValueError("Explicit invited V4 public profile required.")
    pin = network({"network": value.get("network"), "genesis_hash": value.get("genesis_hash")})
    if any(not bounded_text(value.get(key), 32, 44, B58) for key in ("program", "pool")):
        raise ValueError("Reviewed public program and pool addresses required.")
    for key in ("rpc", "faucet"):
        item = value.get(key)
        if (not isinstance(item, dict) or set(item) != {"transport", "url"} or not isinstance(item["url"], str) or
                item["transport"] != ("loopback-http" if fixture_http and item["url"].startswith("http:") else "https")):
            raise ValueError("Explicit invited transport required.")
        endpoint(item["url"], fixture_http)
    audiences = value.get("access_audiences")
    if audiences is None:
        rpc_audience, faucet_audience = value["rpc"]["url"], value["faucet"]["url"]
    else:
        if (not isinstance(audiences, dict) or set(audiences) != {"format", "network", "genesis_hash", "rpc", "faucet"} or
                audiences["format"] != "native-access-audiences-v1" or audiences["network"] != pin["network"] or
                audiences["genesis_hash"] != pin["genesis_hash"]):
            raise ValueError("Signed audience migration differs from the network pin.")
        rpc_audience = endpoint(audiences["rpc"], fixture_http)
        faucet_audience = endpoint(audiences["faucet"], fixture_http)
    return pin, rpc_audience, faucet_audience


def assets(root, manifest_raw, expected_sha256):
    if hashlib.sha256(manifest_raw).hexdigest() != expected_sha256 or len(manifest_raw) > 1024 * 1024:
        raise ValueError("Reviewed browser asset manifest differs.")
    doc = decode(manifest_raw)
    if not isinstance(doc, dict) or set(doc) != {"format", "assets"} or doc["format"] != "zolana-browser-assets-v1" or not isinstance(doc["assets"], dict) or not 1 <= len(doc["assets"]) <= 128:
        raise ValueError("Explicit browser asset inventory required.")
    root = Path(root).resolve()
    result, size = {}, 0
    for url, item in doc["assets"].items():
        if (url in RESERVED or not bounded_text(url, 1, 512, r"/[A-Za-z0-9_./-]*") or
                (url != "/" and str(PurePosixPath(url)) != url) or ".." in PurePosixPath(url).parts or
                not isinstance(item, dict) or set(item) != {"path", "sha256"} or
                not bounded_text(item["sha256"], 64, 64, r"[a-f0-9]{64}") or not isinstance(item["path"], str)):
            raise ValueError("Invalid public browser asset entry.")
        relative = PurePosixPath(item["path"])
        path = root / relative
        if relative.is_absolute() or ".." in relative.parts or path.is_symlink() or not path.resolve().is_relative_to(root) or path.suffix not in MIME:
            raise ValueError("Browser assets must stay in the reviewed public bundle.")
        raw = path.read_bytes()
        size += len(raw)
        if len(raw) > 32 * 1024 * 1024 or size > 64 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError("Browser asset bytes differ or exceed the bundle limit.")
        result[url] = (raw, MIME[path.suffix])
    if "/" not in result:
        raise ValueError("A reviewed browser index is required.")
    return result


class BrowserGateway:
    def __init__(self, profile, bundle, *, fixture_http=False, allow_blob_workers=False, upstream_context=None):
        self.network, self.rpc_audience, self.faucet_audience = public_profile(profile, fixture_http)
        self.profile, self.bundle = profile, bundle
        self.allow_blob_workers = bool(allow_blob_workers)
        self.rpc_url = profile["rpc"]["url"]
        self.faucet_url = profile["faucet"]["url"].rstrip("/")
        self.upstream_transport = UpstreamTransport((self.rpc_url, self.faucet_url), fixture_http=fixture_http,
                                                    context=upstream_context)

    def close(self):
        self.upstream_transport.close()

    def config(self):
        return {"format": "zolana-browser-wallet-config-v1", "network": self.network,
                "label": self.profile["label"], "coin": "ZOL", "environment": "testnet"}

    def transport(self):
        return {"format": "zolana-browser-transport-v1", "network": self.network,
                "rpc_path": "/rpc", "join_path": "/admission/join", "status_path": "/admission/status",
                "program": self.profile["program"], "pool": self.profile["pool"],
                "rpc_audience": self.rpc_audience, "faucet_audience": self.faucet_audience,
                "operator_metadata_visible": True, "automatic_retry": False}

    def proof(self, value, purpose):
        if (not isinstance(value, dict) or set(value) != PROOF_FIELDS or value["purpose"] != purpose or
                value["network"] != self.network or value["audience"] != (self.rpc_audience if purpose == "rpc" else self.faucet_audience) or
                not bounded_text(value["fee_address"], 32, 44, B58) or not bounded_text(value["signature"], 64, 88, B58) or
                not bounded_text(value["nonce"], 32, 32, r"[A-Za-z0-9_-]{32}") or
                not bounded_text(value["body_digest"], 64, 64, r"[a-f0-9]{64}") or
                type(value["issued_at"]) is not int or type(value["expires_at"]) is not int or
                not 0 <= value["issued_at"] <= 2**64 - 601 or value["expires_at"] != value["issued_at"] + 600):
            raise ValueError("Malformed public access capability.")
        # Signature, expiry, membership, revocation and quota checks remain
        # authoritative upstream on EVERY request. This is only a shape gate.

    def request(self, path, raw, access):
        value = decode(raw)
        if path == "/rpc":
            if (not isinstance(value, dict) or set(value) - {"jsonrpc", "id", "method", "params"} or
                    value.get("jsonrpc") != "2.0" or type(value.get("id")) not in (str, int) or
                    len(str(value["id"])) > 64 or not isinstance(value.get("method"), str) or value["method"] not in METHODS or
                    ("params" in value and not isinstance(value["params"], list))):
                raise ValueError("Browser RPC envelope or method refused.")
            method, params = value["method"], value.get("params", [])
            if method in ("getShieldedFeeQuote", "getGenesisHash", "getHealth") and params != []:
                raise ValueError("No RPC parameters expected.")
            if method == "getWalletSyncSnapshot":
                # Read-only snapshot of this fixed upstream and pool. No caller
                # URL, account, target, range or transaction policy is accepted.
                if len(params) != 1 or type(params[0]) is not int or not 0 <= params[0] <= 2**64 - 1:
                    raise ValueError("Bounded saved checkpoint slot required.")
            elif method == "getWalletReadBatch":
                read_calls(value)
            elif method == "getAccountInfo":
                # Direct pool sync requires finalized/base64, a configuration
                # accepted by upstream's direct account route. The aggregate
                # helper currently supports only confirmed/base64, so retain
                # its small public-address bound with an explicit config gate.
                if (len(params) != 2 or not bounded_text(params[0], 32, 44, B58) or
                        params[1] not in ({"commitment": "confirmed", "encoding": "base64"},
                                          {"commitment": "finalized", "encoding": "base64"})):
                    raise ValueError("Bounded public base64 account read required.")
            elif method == "getWalletHistoryBlocks":
                history_slots(value)
            elif method in ("getWalletRetainedHistoryV2", "getWalletRetainedHistoryV3"):
                retained_window(value)
            elif method == "getWalletRetainedHistory":
                from gateway_history import parameters
                parameters(value)
            elif method == "getWalletCanonicalHistory":
                from gateway_archival import parameters
                parameters(value)
            elif method == "getShieldedPaymentStatus":
                if len(params) != 1 or not bounded_text(params[0], 64, 64, r"[a-f0-9]{64}"):
                    raise ValueError("Original packet identity required.")
            elif method == "submitShieldedPayment":
                if (len(params) != 1 or not isinstance(params[0], dict) or set(params[0]) != {"network", "payload"} or params[0]["network"] != self.network or
                        not bounded_text(params[0]["payload"], 12308, 12308)):
                    raise ValueError("A public authorized V3 packet is required.")
                packet = base64.b64decode(params[0]["payload"], validate=True)
                if (len(packet) != 9230 or base64.b64encode(packet).decode() != params[0]["payload"] or packet[:8] != b"NPAY0003" or packet[8:40] != bytes(self.network["network"])):
                    raise ValueError("Public packet network or encoding differs.")
            if method != "getGenesisHash" or access:
                if not bounded_text(access, 1, 3072, r"[A-Za-z0-9_-]+"):
                    raise ValueError("Existing invited access capability required.")
                proof = decode(base64.b64decode(access + "=" * (-len(access) % 4), altchars=b"-_", validate=True))
                self.proof(proof, "rpc")
            return self.rpc_url, value
        if path not in ("/admission/join", "/admission/status") or access is not None or not isinstance(value, dict):
            raise ValueError("Browser admission route refused.")
        if path.endswith("/join"):
            if set(value) != {"claim", "invitation", "proof"}:
                raise ValueError("Signed public join request required.")
            claim = value["claim"]
            if (not isinstance(claim, dict) or set(claim) != {"format", "network", "private_address", "fee_address", "signature"} or
                    claim["format"] != "native-test-grant-v1" or claim["network"] != self.network or
                    not bounded_text(claim["private_address"], 64, 300, r"npriv1[1-9A-HJ-NP-Za-km-z]+") or
                    not bounded_text(claim["fee_address"], 32, 44, B58) or not bounded_text(claim["signature"], 64, 88, B58) or
                    (value["invitation"] is not None and not bounded_text(value["invitation"], 1, 512, r"[A-Za-z0-9_-]+"))):
                raise ValueError("Malformed public invitation claim.")
            self.proof(value["proof"], "join")
            if claim["fee_address"] != value["proof"]["fee_address"]:
                raise ValueError("Claim and capability identities differ.")
            return self.faucet_url + "/join", value
        if set(value) != {"proof"}:
            raise ValueError("Signed public status request required.")
        self.proof(value["proof"], "status")
        return self.faucet_url + "/status", value

    def forward(self, path, raw, access):
        url, value = self.request(path, raw, access)
        headers = {"Content-Type": "application/json", "Accept-Encoding": "gzip"}
        if access is not None:
            headers["X-Testnet-Access"] = access
        # One attempt only. A lost reply, including after a committed submit,
        # never triggers an automatic retry or a replacement payment.
        with self.upstream_transport.open(url, raw, headers, timeout=20) as response:
            if not (200 <= response.status < 300 or response.status in (400, 403, 409, 429, 500, 502, 503, 504)):
                raise ValueError("Upstream redirect or unsupported response refused.")
            limit = RESPONSE_LIMIT if path == "/rpc" else ACCESS_LIMIT
            if response.headers.get_content_type() != "application/json":
                raise ValueError("Unexpected invited response encoding.")
            body = response_body(response, limit)
            result = decode(body)
            if not isinstance(result, dict):
                raise ValueError("Invalid invited response object.")
            if response.status == 200 and path == "/rpc":
                if result.get("jsonrpc") != "2.0" or type(result.get("id")) != type(value["id"]) or result.get("id") != value["id"] or ("result" in result) == ("error" in result):
                    raise ValueError("Invited response identity differs.")
                if value["method"] == "getGenesisHash" and result.get("result") != self.network["genesis_hash"]:
                    raise ValueError("Invited genesis differs from the reviewed profile.")
            retry = response.headers.get("Retry-After", "")
            retry = retry if re.fullmatch(r"[0-9]{1,3}", retry) and 1 <= int(retry) <= 120 else None
            return response.status, body, retry


class BrowserServer(BoundedServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, app):
        if address[0] != "127.0.0.1":
            raise ValueError("Preparation listener is loopback only; public HTTPS deployment is separate.")
        self.app = app
        super().__init__(address, BrowserHandler)
        self.authority = f"127.0.0.1:{self.server_port}"
        self.origin = "http://" + self.authority

class BrowserHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body, mime="application/json", retry=None):
        if isinstance(body, dict):
            body = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        for key, value in {"Content-Type": mime, "Content-Length": str(len(body)), "Cache-Control": "no-store",
                           "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                           "Cross-Origin-Opener-Policy": "same-origin", "Cross-Origin-Embedder-Policy": "require-corp",
                           "Cross-Origin-Resource-Policy": "same-origin", "Permissions-Policy": "camera=(), microphone=(), geolocation=()"}.items():
            self.send_header(key, value)
        workers = "'self' blob:" if self.server.app.allow_blob_workers else "'self'"
        self.send_header("Content-Security-Policy", f"default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; worker-src {workers}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
        if retry is not None:
            self.send_header("Retry-After", retry)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def allowed(self, post=False):
        singles = ("Host", "Origin", "Content-Length", "Content-Type", "X-Testnet-Access", "Sec-Fetch-Site")
        # A wallet link may be opened from another site. Only the public static
        # entry document permits that top-level navigation. Subresource reads
        # and every signed operation retain the same-origin boundary.
        entry_navigation = (not post and self.path == "/" and self.headers.get("Origin") is None and
                            self.headers.get("Sec-Fetch-Site") in ("cross-site", "same-site") and
                            self.headers.get("Sec-Fetch-Mode") == "navigate" and
                            self.headers.get("Sec-Fetch-Dest") == "document")
        if (self.headers.get_all("Host", []) != [self.server.authority] or
                any(len(self.headers.get_all(name, [])) > 1 for name in singles) or
                self.headers.get("Origin") not in ([self.server.origin] if post else [None, self.server.origin]) or
                (self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin") and not entry_navigation) or
                any(name.lower() in ("forwarded", "authorization", "proxy-authorization", "x-native-operator", "x-real-ip") or name.lower().startswith("x-forwarded-") for name in self.headers)):
            self.close_connection = True
            self.reply(403, {"error": "access_denied"})
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        if self.path == "/wallet-config.json":
            self.reply(200, self.server.app.config())
        elif self.path == "/transport.json":
            self.reply(200, self.server.app.transport())
        elif self.path in self.server.app.bundle:
            body, mime = self.server.app.bundle[self.path]
            self.reply(200, body, mime)
        else:
            self.reply(404, {"error": "not_found"})

    def do_POST(self):
        if not self.allowed(post=True):
            return
        if self.path not in ("/rpc", "/admission/join", "/admission/status"):
            self.reply(404, {"error": "not_found"})
            return
        length = self.headers.get("Content-Length", "")
        limit = RPC_LIMIT if self.path == "/rpc" else ACCESS_LIMIT
        if (self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding") is not None or
                re.fullmatch(r"[0-9]{1,5}", length) is None or not 1 <= int(length) <= limit):
            self.close_connection = True
            self.reply(403, {"error": "access_denied"})
            return
        try:
            self.connection.settimeout(10)
            raw = self.rfile.read(int(length))
            if len(raw) != int(length):
                raise ValueError("Incomplete browser request.")
            # Validate before any upstream socket or durable quota work.
            self.server.app.request(self.path, raw, self.headers.get("X-Testnet-Access"))
        except (ValueError, UnicodeError, RecursionError, OSError):
            self.close_connection = True
            self.reply(403, {"error": "access_denied"})
            return
        try:
            status, body, retry = self.server.app.forward(self.path, raw, self.headers.get("X-Testnet-Access"))
            self.reply(status, body, retry=retry)
        except (ValueError, UnicodeError, RecursionError, OSError, urllib.error.URLError):
            self.close_connection = True
            self.reply(502, {"error": "upstream_unavailable", "outcome": "unknown", "automatic_retry": False})


def pinned_json(path, expected, maximum):
    raw = Path(path).read_bytes()
    if len(raw) > maximum or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("Reviewed public configuration differs.")
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18996)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--assets-root", type=Path, required=True)
    parser.add_argument("--assets-manifest", type=Path, required=True)
    parser.add_argument("--assets-sha256", required=True)
    parser.add_argument("--allow-reviewed-blob-workers", action="store_true", help="Explicit preparation policy for the pinned Rayon1.3 no-bundler helper")
    args = parser.parse_args()
    profile = decode(pinned_json(args.profile, args.profile_sha256, 8192))
    manifest = pinned_json(args.assets_manifest, args.assets_sha256, 1024 * 1024)
    app = BrowserGateway(profile, assets(args.assets_root, manifest, args.assets_sha256), allow_blob_workers=args.allow_reviewed_blob_workers)
    try:
        with BrowserServer(("127.0.0.1", args.port), app) as server:
            print(f"Prepared browser ingress: {server.origin}/", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
    finally:
        app.close()


if __name__ == "__main__":
    main()
