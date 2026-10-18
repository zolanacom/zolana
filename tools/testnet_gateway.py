#!/usr/bin/env python3
"""Loopback invited-wallet RPC ingress. Raw validator RPC remains operator-local."""
import argparse
import base64
from http.server import BaseHTTPRequestHandler
import json
import subprocess
import time
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from test_faucet import BoundedServer, Faucet

METHODS = {
    "getWalletHistoryBlocks", "getWalletRetainedHistory",
    "getGenesisHash", "getHealth", "getVersion", "getAccountInfo", "getMultipleAccounts",
    "getBlocks", "getBlock", "getBlockHeight", "getSlot", "getEpochInfo", "getBalance",
    "getSignaturesForAddress", "getSignatureStatuses", "getTransaction", "getLatestBlockhash",
    "getMinimumBalanceForRentExemption", "getFeeForMessage", "sendTransaction", "getProgramAccounts",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Gateway:
    def __init__(self, faucet, history_root=None):
        self.faucet = faucet
        self.info = faucet.command("access-info")
        if self.info.get("invite_required") is not True:
            raise ValueError("RPC gateway requires durable invitation admission")
        profile = json.loads((faucet.root / "profile.json").read_bytes())
        self.upstream = profile["rpc"]["url"]
        parsed = urllib.parse.urlsplit(self.upstream)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or self.upstream == self.info["rpc_audience"]:
            raise ValueError("gateway needs a separate pinned loopback validator RPC")
        self.operator=None
        ledger=json.loads((faucet.root/'claims.json').read_bytes())
        if ledger['policy'].get('operator_rpc'):
            from operator_transport import Operator
            self.operator=Operator(self.upstream,faucet.root/'rpc-access.key')
            if ledger['policy'].get('operator_unix') and self.operator.path is None:raise ValueError('faucet private RPC transport cannot be downgraded')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        result = self.forward(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getGenesisHash"}).encode())
        if json.loads(result).get("result") != self.info["network"]["genesis_hash"]:
            raise ValueError("upstream genesis mismatch")

        self.history = None
        if history_root is not None:
            from gateway_history import History
            self.history = History(history_root, self.info['network'])

    def retained_history(self, request):
        if self.history is None:
            return json.dumps({'jsonrpc':'2.0','id':request['id'],'result':None}).encode()
        return self.history.page(request)

    def forward(self, raw, timeout=15):
        if self.operator is not None:return self.operator.forward(raw, timeout=timeout)
        request = urllib.request.Request(self.upstream, raw, {"Content-Type": "application/json"})
        with self.opener.open(request, timeout=timeout) as response:
            body = response.read(16 * 1024 * 1024 + 1)
            if len(body) > 16 * 1024 * 1024:
                raise ValueError("RPC response exceeds gateway limit")
            return body

    def history_blocks(self, request, slots):
        # Read-only aggregation, never arbitrary JSON-RPC batches. Every full
        # finalized block is returned; clients still authenticate continuity and
        # replay every payment proof. The aggregate has the ordinary response cap.
        prefix = json.dumps({"jsonrpc": "2.0", "id": request["id"]}).encode()[:-1] + b',"result":['
        items, total = [], len(prefix) + 2
        deadline = time.monotonic() + 15
        for slot in slots:
            raw = json.dumps({"jsonrpc": "2.0", "id": slot, "method": "getBlock", "params": [slot, {
                "encoding": "base64", "transactionDetails": "full", "rewards": False,
                "commitment": "finalized", "maxSupportedTransactionVersion": 0}]}).encode()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("history read deadline exceeded")
            response = json.loads(self.forward(raw, timeout=remaining))
            if not isinstance(response, dict) or response.get("id") != slot or response.get("error") is not None or not isinstance(response.get("result"), dict):
                raise ValueError("complete finalized history is unavailable")
            item = json.dumps({"slot": slot, "block": response["result"]}, separators=(",", ":")).encode()
            total += len(item) + (1 if items else 0)
            if total > 16 * 1024 * 1024:
                raise ValueError("RPC response exceeds gateway limit")
            items.append(item)
        return prefix + b','.join(items) + b']}'


def history_slots(request):
    params = request.get("params")
    if not isinstance(params, list) or len(params) != 1 or not isinstance(params[0], list):
        raise ValueError("invalid history request")
    slots = params[0]
    if not 1 <= len(slots) <= 16 or any(type(slot) is not int or not 1 <= slot <= 2**64 - 1 for slot in slots) or any(a >= b for a, b in zip(slots, slots[1:])):
        raise ValueError("invalid history block range")
    return slots


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
                if request['method'] == 'getWalletRetainedHistory':
                    from gateway_history import parameters
                    parameters(request)
                slots = history_slots(request) if request["method"] == "getWalletHistoryBlocks" else None
                header = self.headers.get("X-Testnet-Access", "")
                if not 1 <= len(header) <= 3072:
                    raise ValueError("invitation required")
                proof = json.loads(base64.b64decode(header + "=" * (-len(header) % 4), altchars=b"-_", validate=True))
                self.server.app.faucet.command("authorize", proof)
            if request['method'] == 'getWalletRetainedHistory':data = self.server.app.retained_history(request)
            else:data = self.server.app.history_blocks(request, slots) if request["method"] == "getWalletHistoryBlocks" else self.server.app.forward(raw)
        except (ValueError, RecursionError, OSError, urllib.error.URLError, subprocess.SubprocessError) as error:
            code = 429 if "quota exhausted" in str(error) else 403
            data = json.dumps({"error": "request_limit" if code == 429 else "access_denied"}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if code == 429:
            # The native HTTP sender honors this bounded delay. Retrying a
            # read does not reset durable quotas or spin against the gateway.
            self.send_header("Retry-After", str(61 - int(time.time()) % 60))
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
    parser.add_argument("--history",type=Path,help="operator-configured retained mirror; never supplied by a client")
    parser.add_argument("--tls-cert",type=Path)
    parser.add_argument("--tls-key",type=Path)
    args = parser.parse_args()
    # Reuse the bounded, owner-only operator service interface; no worker starts here.
    faucet = Faucet(args.root, args.password_file)
    app = Gateway(faucet,history_root=args.history)
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
