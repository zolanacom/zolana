#!/usr/bin/env python3
"""Device-local wallet UI backed by the real encrypted-seed CLI. No bridge."""
import argparse
import json
import os
import secrets
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from localnet import PROJECT, load, quiet, start, stop, wait_rpc

ASSETS = PROJECT / "clients/wallet-ui"
WALLET = PROJECT / "target/debug/native-wallet"


class WalletApp:
    def __init__(self, root, profile="default", rpc_index=0):
        self.root = root.resolve()
        if not self.root.is_relative_to(PROJECT / ".data"):
            raise ValueError("wallet UI requires a local .data fixture")
        config = load(self.root)
        if config.get("pool_format") != "NPOOL003" or config.get("fixture_keys_are_public") is not True:
            raise ValueError("wallet UI requires a disposable NPOOL003 fixture")
        if not isinstance(profile, str) or not 1 <= len(profile) <= 24 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in profile):
            raise ValueError("use a short lowercase wallet profile name")
        self.directory = self.root / ("wallet-ui" if profile == "default" else "wallet-ui-" + profile)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_mode & 0o077:
            raise ValueError("wallet UI directory must be owner-only")
        self.wallet = self.directory / "wallet.json"
        if type(rpc_index) is not int or rpc_index not in (0, 1):
            raise ValueError("use one of this fixture's two local RPC peers")
        self.rpc_index = rpc_index
        self.backup = self.directory / "recovery.json"
        self.ack = self.directory / "backup-confirmed"
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()

    def status(self):
        return {"exists": self.wallet.exists() or self.backup.exists(), "needs_backup": not self.ack.exists(),
                "pending": Path(str(self.wallet) + ".pending.json").exists(),
                "staging": Path(str(self.wallet) + ".staging.json").exists(),
                "network": "Local test network", "solana_funding_available": False}

    def cli(self, command, password, extra=()):
        if not isinstance(password, str) or not 12 <= len(password.encode()) <= 1024:
            raise ValueError("Use a password with at least 12 characters.")
        # Send passwords only through a bounded CLI stdin pipe, never a file,
        # environment variable, command argument, URL or browser storage.
        args = [str(WALLET), command, "--network", str(self.root / "network.json"),
                "--wallet", str(self.wallet), "--password-file", "-",
                "--rpc", f"http://127.0.0.1:{18899+self.rpc_index*1000}", *extra]
        history = self.root / "recovery-history"
        if command in {"balance", "deposit", "send", "withdraw"} and (history / "manifest.json").exists():
            args += ["--history", str(history)]
        result = subprocess.run(args, input=password, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise ValueError(result.stderr.strip().removeprefix("Wallet error: "))
        return json.loads(result.stdout)

    def action(self, request):
        action = request.get("action")
        password = request.get("password")
        if action not in {"create", "restore", "unlock", "backup", "ack-backup", "balance", "fund", "send", "resolve", "reclaim"}:
            raise ValueError("Unknown wallet action.")
        if action == "create":
            return self.cli("init", password, ["--backup", str(self.backup)])
        if action == "restore":
            if self.wallet.exists() or self.backup.exists():
                raise ValueError("This device already has a wallet. Lock it instead of replacing it.")
            data = request.get("backup")
            if not isinstance(data, dict) or len(json.dumps(data).encode()) > 4096:
                raise ValueError("Choose an encrypted wallet recovery file.")
            with tempfile.NamedTemporaryFile(dir=self.directory, prefix=".restore-") as recovery:
                recovery.write(json.dumps(data).encode())
                recovery.flush()
                result = self.cli("restore", password, ["--backup", recovery.name])
            with os.fdopen(os.open(self.backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as saved:
                saved.write(self.wallet.read_bytes())
                saved.flush()
                os.fsync(saved.fileno())
            self.ack.touch(mode=0o600)
            return result
        if action == "balance":
            return self.cli("balance", password)
        if action in {"fund", "send", "resolve", "reclaim"}:
            if not self.ack.exists():
                raise ValueError("Save and confirm your encrypted recovery file before making payments.")
            sponsor = ["--sponsor", str(self.root / "sponsor.keypair.json")]
            if action == "fund":
                return self.cli("deposit", password, sponsor + ["--amount", "100"])
            if action == "send":
                amount = request.get("amount")
                recipient = request.get("recipient")
                if type(amount) is not int or not 1 <= amount <= 1_000_000_000 or not isinstance(recipient, str) or not recipient.startswith("npriv1") or len(recipient) > 140:
                    raise ValueError("Enter a private receiving address and a positive whole amount.")
                return self.cli("send", password, sponsor + ["--amount", str(amount), "--to", recipient])
            return self.cli(action, password, sponsor)
        if action == "unlock" and not self.wallet.exists() and self.backup.exists():
            self.cli("restore", password, ["--backup", str(self.backup)])
        address = self.cli("address", password)
        if action == "backup":
            return {"backup": json.loads(self.backup.read_bytes())}
        if action == "ack-backup":
            self.ack.touch(mode=0o600)
        return {**address, **self.status()}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # No payment, password or address logging.

    def allowed(self, mutation=False):
        return (self.headers.get("Host") == self.server.authority and
                (not mutation or (self.headers.get("Origin") == "http://" + self.server.authority and
                 secrets.compare_digest(self.headers.get("X-Wallet-Token", ""), self.server.app.token))))

    def respond(self, status, data, content_type="application/json"):
        raw = json.dumps(data).encode() if content_type == "application/json" else data
        self.send_response(status)
        for key, value in {"Content-Type": content_type, "Content-Length": str(len(raw)),
                           "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                           "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
                           "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if not self.allowed():
            return self.respond(403, {"error": "Use the local wallet address."})
        if self.path == "/api/session":
            return self.respond(200, {"token": self.server.app.token, **self.server.app.status()})
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/style.css": ("style.css", "text/css; charset=utf-8")}
        if self.path not in assets:
            return self.respond(404, {"error": "Not found."})
        name, mime = assets[self.path]
        self.respond(200, (ASSETS / name).read_bytes(), mime)

    def do_POST(self):
        if self.path != "/api/wallet" or not self.allowed(mutation=True):
            return self.respond(403, {"error": "Wallet request origin or session was rejected."})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 1 <= size <= 16384 or self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding"):
                raise ValueError("Invalid wallet request.")
            request = json.loads(self.rfile.read(size))
            if not isinstance(request, dict):
                raise ValueError("Invalid wallet request.")
            if not self.server.app.lock.acquire(blocking=False):
                return self.respond(409, {"error": "Another wallet operation is running. Wait for it to finish."})
            try:
                data = self.server.app.action(request)
            finally:
                self.server.app.lock.release()
            self.respond(200, {"result": data, "status": self.server.app.status()})
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            self.respond(400, {"error": str(error), "status": self.server.app.status()})


def serve(app, port, duration):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.authority = f"127.0.0.1:{port}"
    server.app = app
    timer = threading.Timer(duration, server.shutdown)
    timer.daemon = True
    timer.start()
    print(f"Local wallet: http://{server.authority} (session limited to {duration} seconds)", flush=True)
    try:
        server.serve_forever()
    finally:
        timer.cancel()
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--duration", type=int, default=1800)
    parser.add_argument("--start-network", action="store_true")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--rpc-index", type=int, choices=[0, 1], default=0)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not 60 <= args.duration <= 3600:
        parser.error("use a nonprivileged port and a session of 60..3600 seconds")
    app = WalletApp(args.root, args.profile, args.rpc_index)
    children = [None, None]
    try:
        if args.start_network:
            for index in [0, 1]:
                children[index] = start(app.root, index, coordinated=True)
                wait_rpc(app.root, index)
            quiet(app.root)
        serve(app, args.port, args.duration)
    finally:
        for index in [1, 0]:
            if children[index] is not None and children[index].poll() is None:
                stop(app.root, index)
