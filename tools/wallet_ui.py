#!/usr/bin/env python3
"""Device-local wallet UI backed by the real encrypted-seed CLI. No bridge."""
import argparse
import json
import os
import secrets
import stat
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


def load(root):
    from localnet import load as load_fixture
    return load_fixture(root)

ASSETS = PROJECT / "clients/wallet-ui"
WALLET = PROJECT / "target/debug/native-wallet"


class WalletApp:
    def __init__(self, root, profile="default", rpc_index=0, sponsor_password_file=None):
        self.root = root.resolve()
        self.tester = False
        self.test_faucet = False
        self.invite_required = False
        self.admitted = False
        self.network_file = self.root / "network.json"
        self.binary = WALLET
        if not self.root.is_relative_to(PROJECT / ".data"):
            raise ValueError("wallet UI requires a local .data fixture")
        config = load(self.root)
        self.genesis_hash = config.get('genesis_hash')
        self.previous_wallet_port = None
        self.withdrawal_enabled = config.get("recipient_withdrawals") is True
        self.faucet_amount = config.get("faucet_amount", 100)
        if type(self.faucet_amount) is not int or not 1 <= self.faucet_amount <= 1_000_000_000:
            raise ValueError("invalid local faucet amount")
        self.private_setup = config.get("key_mode") == "local-testnet-rehearsal-v1" and config.get("fixture_keys_are_public") is False
        if config.get("pool_format") != "NPOOL003" or (config.get("fixture_keys_are_public") is not True and not self.private_setup):
            raise ValueError("wallet UI requires a local NPOOL003 fixture or rehearsal")
        self.sponsor_password_file = None
        if self.private_setup and sponsor_password_file is not None:
            path = Path(sponsor_password_file).absolute()
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as secret:
                metadata = os.fstat(secret.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or not 12 <= metadata.st_size <= 1024:
                    raise ValueError("sponsor password file must be bounded and owner-only")
            self.sponsor_password_file = path
        self._storage(profile)
        if type(rpc_index) is not int or rpc_index not in (0, 1):
            raise ValueError("use one of this fixture's two local RPC peers")
        self.rpc_index = rpc_index

    def _storage(self, profile):
        if not isinstance(profile, str) or not 1 <= len(profile) <= 24 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in profile):
            raise ValueError("use a short lowercase wallet profile name")
        self.directory = self.root / ("wallet-ui" if profile == "default" else "wallet-ui-" + profile)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        if self.directory.is_symlink() or self.directory.stat().st_mode & 0o077:
            raise ValueError("wallet UI directory must be owner-only")
        self.wallet = self.directory / "wallet.json"
        self.backup = self.directory / "recovery.json"
        self.ack = self.directory / "backup-confirmed"
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()

    @classmethod
    def from_profile(cls, network_file, data_directory, profile="default", binary=WALLET):
        """Standalone client: public configuration only, never a validator root."""
        result = subprocess.run([str(binary), "profile", "--network", str(network_file)], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise ValueError(result.stderr.strip().removeprefix("Wallet error: "))
        config = json.loads(result.stdout)
        data_directory = Path(data_directory).absolute()
        if data_directory.is_symlink():
            raise ValueError("wallet data directory must not be a symlink")
        data_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        metadata = data_directory.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise ValueError("wallet data directory must be owner-only")
        app = cls.__new__(cls)
        app.root = data_directory.resolve()
        app.network_file = app.root / "network.json"
        encoded = (json.dumps(config, sort_keys=True, indent=2) + "\n").encode()
        try:
            with os.fdopen(os.open(app.network_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as saved:
                saved.write(encoded)
                saved.flush()
                os.fsync(saved.fileno())
        except FileExistsError:
            with os.fdopen(os.open(app.network_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as saved:
                metadata = os.fstat(saved.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_size > 8192 or saved.read(8193) != encoded:
                    raise ValueError("wallet data is bound to a different profile; preserve it and select its original profile")
        app.tester = True
        app.network_label = config["label"]
        app.genesis_hash = config['genesis_hash']
        app.previous_wallet_port = None
        app.private_setup = True
        app.withdrawal_enabled = True
        app.faucet_amount = 0
        app.test_faucet = config.get("faucet") is not None
        app.invite_required = config.get("invite_required") is True
        app.admitted = False
        app.sponsor_password_file = None
        app.binary = Path(binary).resolve()
        app._storage(profile)
        return app

    def status(self):
        return {"exists": self.wallet.exists() or self.backup.exists(), "needs_backup": not self.ack.exists(),
                "pending": Path(str(self.wallet) + ".pending.json").exists(),
                "staging": Path(str(self.wallet) + ".staging.json").exists(),
                "network": self.network_label if self.tester else ("Local testnet rehearsal" if self.private_setup else "Local test network"), "solana_funding_available": False,
                "recipient_withdrawals": self.withdrawal_enabled, "faucet_amount": self.faucet_amount, "operator_sponsor_available": not self.private_setup or self.sponsor_password_file is not None, "user_paid_fees": True, "user_paid_sends": True, "test_faucet_available": self.test_faucet, "invite_required": self.invite_required, "testnet_admitted": self.admitted,
                "genesis_hash": getattr(self,'genesis_hash',None), "previous_wallet_port": getattr(self,'previous_wallet_port',None)}

    def cli(self, command, password, extra=()):
        if not isinstance(password, str) or not 12 <= len(password.encode()) <= 1024:
            raise ValueError("Use a password with at least 12 characters.")
        # Send passwords only through a bounded CLI stdin pipe, never a file,
        # environment variable, command argument, URL or browser storage.
        args = [str(self.binary), command, "--network", str(self.network_file),
                "--wallet", str(self.wallet), "--password-file", "-",
                *([] if self.tester else ["--rpc", f"http://127.0.0.1:{18899+self.rpc_index*1000}"]), *extra]
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
        if action not in {"create", "restore", "unlock", "backup", "ack-backup", "balance", "fees", "test-coins", "join", "access-status", "fund", "send", "withdraw", "resolve", "reclaim"}:
            raise ValueError("Unknown wallet action.")
        if action not in {"send", "withdraw"} and ("fee_mode" in request or "max_fee_debit" in request):
            raise ValueError("Fee selection is only supported for sends and withdrawals.")
        if action != "fees" and "payment" in request:
            raise ValueError("Payment quote selection is only supported for fees.")
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
            if self.invite_required:
                try: self.admitted = self.cli("access-status", password).get("admitted") is True
                except ValueError: self.admitted = False
            return result
        if action in {"join", "access-status"}:
            if not self.invite_required:
                raise ValueError("This profile does not require invitation access.")
            if action == "join":
                if not self.ack.exists():
                    raise ValueError("Save and confirm your recovery file before redeeming an invitation.")
                code = request.get("invitation")
                if not isinstance(code, str) or len(code.strip()) != 51 or not code.strip().startswith("invite1_"):
                    raise ValueError("Enter the invitation code provided for this testnet.")
                with tempfile.NamedTemporaryFile(dir=self.directory, prefix=".invite-") as invitation:
                    invitation.write(code.strip().encode()); invitation.flush()
                    result = self.cli("join", password, ["--invitation-file", invitation.name])
            else:
                result = self.cli("access-status", password)
            self.admitted = result.get("admitted") is True
            return result
        if self.invite_required and action in {"balance", "fees", "test-coins", "send", "withdraw", "resolve", "reclaim"}:
            access = self.cli("access-status", password)
            self.admitted = access.get("admitted") is True
            if not self.admitted:
                raise ValueError("Testnet access is unavailable for this wallet. Check your invitation access; your recovery file and payment records are preserved.")
        if action in {"balance", "fees"}:
            if action == "fees" and "payment" in request:
                if request["payment"] not in ("send", "withdraw"):
                    raise ValueError("Choose a send or withdrawal fee quote.")
                return self.cli("fees", password, ["--payment", request["payment"]])
            return self.cli(action, password)
        if action == "test-coins":
            if not self.ack.exists():
                raise ValueError("Save and confirm your encrypted recovery file before requesting test coins.")
            if not self.test_faucet:
                raise ValueError("This profile has no test faucet.")
            if self.status()["pending"] or self.status()["staging"]:
                raise ValueError("Resolve the previous payment before requesting test coins.")
            return self.cli("test-coins", password)
        if action in {"fund", "send", "withdraw", "resolve", "reclaim"}:
            if not self.ack.exists():
                raise ValueError("Save and confirm your encrypted recovery file before making payments.")
            user_paid = action in {"send", "withdraw"} and request.get("fee_mode", "sponsor" if (not self.private_setup or self.sponsor_password_file is not None) else "user") == "user"
            if action in {"send", "withdraw"} and request.get("fee_mode", "user") not in ("user", "sponsor"):
                raise ValueError("Choose user-paid or sponsored fees.")
            if action in {"send", "withdraw"} and not user_paid and "max_fee_debit" in request:
                raise ValueError("A fee debit cap requires user-paid fees.")
            if action == "reclaim":
                stage = Path(str(self.wallet) + ".staging.json")
                if stage.exists():
                    record = json.loads(stage.read_text())
                    if not isinstance(record, dict):
                        raise ValueError("Invalid staging recovery record; keep it for recovery.")
                    if record.get("user_fee") is not None:
                        return self.cli("reclaim", password)
            if action == "resolve":
                return self.cli("resolve", password)
            if self.private_setup and self.sponsor_password_file is None and not user_paid:
                raise ValueError("Operator sponsorship is unavailable. Use your funded fee account for sends or withdrawals.")
            sponsor = ["--sponsor", str(self.root / "sponsor.keypair.json")]
            if user_paid:
                cap = request.get("max_fee_debit")
                if type(cap) is not int or not 1 <= cap <= 1_000_000_000_000:
                    raise ValueError("Review and authorize a bounded fee debit first.")
                sponsor = ["--fee-payer", "user", "--max-fee-debit", str(cap)]
            elif self.private_setup:
                sponsor = ["--sponsor-password-file", str(self.sponsor_password_file)]
                if action in {"fund", "send", "withdraw"}:
                    sponsor += ["--sponsor-request-id", secrets.token_hex(16)]
            if action == "fund":
                return self.cli("deposit", password, sponsor + ["--amount", str(self.faucet_amount)])
            if action == "withdraw":
                if not self.withdrawal_enabled:
                    raise ValueError("This preserved network does not enable recipient-bound withdrawals. Use a fresh rehearsal network.")
                amount, recipient = request.get("amount"), request.get("recipient")
                if type(amount) is not int or not 1 <= amount <= 1_000_000_000:
                    raise ValueError("Enter a positive whole withdrawal amount.")
                extra = ["--amount", str(amount)]
                if recipient is not None:
                    if not isinstance(recipient, str) or not 32 <= len(recipient) <= 44 or any(c not in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for c in recipient):
                        raise ValueError("Enter a public address on this chain.")
                    extra += ["--to", recipient]
                return self.cli("withdraw", password, sponsor + extra)
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
        if action == "unlock" and self.invite_required:
            try: self.admitted = self.cli("access-status", password).get("admitted") is True
            except ValueError: self.admitted = False
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
        if self.path == '/api/network':
            data=self.server.app.status()
            return self.respond(200,{key:data[key] for key in ('network','genesis_hash')})
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


def main(argv=None):
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--root", type=Path)
    source.add_argument("--network-profile", type=Path)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--duration", type=int, default=1800)
    parser.add_argument("--start-network", action="store_true")
    parser.add_argument("--profile", default="default")
    parser.add_argument("--rpc-index", type=int, choices=[0, 1], default=0)
    parser.add_argument("--sponsor-password-file", type=Path)
    parser.add_argument('--previous-wallet-port',type=int)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535 or not 60 <= args.duration <= 3600:
        parser.error("use a nonprivileged port and a session of 60..3600 seconds")
    if args.network_profile:
        if not args.data_dir or args.start_network or args.sponsor_password_file or args.rpc_index != 0:
            parser.error("standalone mode requires --data-dir and forbids validator/sponsor options")
        app = WalletApp.from_profile(args.network_profile, args.data_dir, args.profile, WALLET)
    else:
        if args.data_dir:
            parser.error("--data-dir is only for standalone profiles")
        app = WalletApp(args.root, args.profile, args.rpc_index, args.sponsor_password_file)
    children = [None, None]
    if args.previous_wallet_port is not None:
        if not 1024<=args.previous_wallet_port<=65535 or args.previous_wallet_port==args.port:parser.error('previous wallet needs a separate local port')
        app.previous_wallet_port=args.previous_wallet_port
    try:
        if args.start_network:
            from localnet import quiet, start, stop, wait_rpc
            if all(list((app.root / f"consensus-{index}").glob("tower-*.bin")) for index in [0, 1]):
                from replay_localnet import prepare
                prepare(app.root)
            for index in [0, 1]:
                children[index] = start(app.root, index, coordinated=True)
                wait_rpc(app.root, index)
            quiet(app.root)
        serve(app, args.port, args.duration)
    finally:
        for index in [1, 0]:
            if children[index] is not None and children[index].poll() is None:
                stop(app.root, index)


if __name__ == "__main__":
    main()
