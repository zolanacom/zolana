#!/usr/bin/env python3
"""Loopback invited-wallet RPC ingress. Raw validator RPC remains operator-local."""
import argparse
import base64
from http.server import BaseHTTPRequestHandler
import json
import subprocess
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from test_faucet import BoundedServer, Faucet

METHODS = {
    "getGenesisHash", "getHealth", "getVersion", "getAccountInfo", "getMultipleAccounts",
    "getBlocks", "getBlock", "getBlockHeight", "getSlot", "getEpochInfo", "getBalance",
    "getSignaturesForAddress", "getSignatureStatuses", "getTransaction", "getLatestBlockhash",
    "getMinimumBalanceForRentExemption", "getFeeForMessage", "sendTransaction", "getProgramAccounts",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Gateway:
    def __init__(self, faucet):
        self.faucet = faucet
        self.info = faucet.command("access-info")
        if self.info.get("invite_required") is not True:
            raise ValueError("RPC gateway requires durable invitation admission")
        profile = json.loads((faucet.root / "profile.json").read_bytes())
        self.upstream = profile["rpc"]["url"]
        parsed = urllib.parse.urlsplit(self.upstream)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or self.upstream == self.info["rpc_audience"]:
            raise ValueError("gateway needs a separate pinned loopback validator RPC")
        self.operator_headers={}
        ledger=json.loads((faucet.root/'claims.json').read_bytes())
        if ledger['policy'].get('operator_rpc'):
            from service_tls import operator_token
            self.operator_headers['X-Native-Operator']=operator_token(faucet.root/'rpc-access.key')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        result = self.forward(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getGenesisHash"}).encode())
        if json.loads(result).get("result") != self.info["network"]["genesis_hash"]:
            raise ValueError("upstream genesis mismatch")

    def forward(self, raw):
        request = urllib.request.Request(self.upstream, raw, {"Content-Type": "application/json", **self.operator_headers})
        with self.opener.open(request, timeout=15) as response:
            body = response.read(16 * 1024 * 1024 + 1)
            if len(body) > 16 * 1024 * 1024:
                raise ValueError("RPC response exceeds gateway limit")
            return body


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # No access proofs, requests, addresses or invitation codes in logs.

    def do_POST(self):
        code, data = 200, b""
        try:
            if self.path != "/" or self.headers.get("Host") != self.server.authority or self.headers.get("Origin") is not None:
                raise ValueError("access denied")
            self.server.app.faucet.ingress("rpc", self.client_address[0])
            if self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding") is not None:
                raise ValueError("invalid RPC body")
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 32768:
                raise ValueError("RPC body exceeds limit")
            raw = self.rfile.read(size)
            request = json.loads(raw)
            if not isinstance(request, dict) or set(request) - {"jsonrpc", "id", "method", "params"} or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str) or request["method"] not in METHODS or type(request.get("id")) not in (str, int) or len(str(request["id"])) > 64 or (request.get("params") is not None and not isinstance(request["params"], list)):
                raise ValueError("RPC method or envelope denied")
            if request["method"] != "getGenesisHash":
                header = self.headers.get("X-Testnet-Access", "")
                if not 1 <= len(header) <= 3072:
                    raise ValueError("invitation required")
                proof = json.loads(base64.b64decode(header + "=" * (-len(header) % 4), altchars=b"-_", validate=True))
                self.server.app.faucet.command("authorize", proof)
            data = self.server.app.forward(raw)
        except (ValueError, RecursionError, OSError, urllib.error.URLError, subprocess.SubprocessError) as error:
            code = 429 if "quota exhausted" in str(error) else 403
            data = json.dumps({"error": "request_limit" if code == 429 else "access_denied"}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18898)
    parser.add_argument("--tls-cert",type=Path)
    parser.add_argument("--tls-key",type=Path)
    args = parser.parse_args()
    # Reuse the bounded, owner-only operator service interface; no worker starts here.
    faucet = Faucet(args.root, args.password_file)
    app = Gateway(faucet)
    from service_tls import listener
    server=listener(app.info['rpc_audience'],args.port,Handler,app,args.tls_cert,args.tls_key)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        faucet.close()


if __name__ == "__main__":
    main()
