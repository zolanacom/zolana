#!/usr/bin/env python3
"""Bounded loopback test faucet. Keys stay in a dedicated local worker process."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading
import time

PROJECT = Path(__file__).resolve().parents[1]
FAUCET = PROJECT / "target/debug/native-faucet"


class Faucet:
    def __init__(self, root, password_file, binary=FAUCET):
        self.root = Path(root).resolve()
        if self.root.stat().st_mode & 0o077:
            raise ValueError("faucet directory must be owner-only")
        self.binary = Path(binary).resolve()
        with os.fdopen(os.open(password_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
            meta = os.fstat(source.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or not 12 <= meta.st_size <= 1024:
                raise ValueError("faucet password file must be bounded and owner-only")
            self.password = source.read(1025).decode()
        self.stop = threading.Event()
        self.accept_lock = threading.Lock()
        self.next_accept = 0
        self.child_lock = threading.Lock()
        self.child = None

    @property
    def required(self):
        path = self.root / "claims.json"
        return path.exists() and json.loads(path.read_bytes())["policy"].get("invite_required") is True

    def command(self, command, data=None, extra=()):
        args = [str(self.binary), command, "--root", str(self.root), *extra]
        with tempfile.NamedTemporaryFile(dir=self.root, prefix=".access-") as request:
            if data is not None:
                request.write(json.dumps(data, allow_nan=False).encode())
                request.flush()
                args += ["--request-file", request.name]
            result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise ValueError(result.stderr.strip().removeprefix("Faucet error: "))
        return json.loads(result.stdout)

    def ingress(self, channel, peer, units=1):
        if self.required:
            self.command("edge", extra=["--channel", channel, "--peer", peer, "--units", str(units)])

    def access_action(self, path, data):
        if not self.required or not isinstance(data, dict):
            raise ValueError("invitation required")
        return self.command("join" if path == "/join" else "access-status", data)

    def accept(self, data):
        if self.required:
            raise ValueError("invitation required; legacy claims are disabled")
        # Only the fixed claim schema is accepted; no caller RPC, amount or key paths.
        if not isinstance(data, dict) or set(data) != {"format", "network", "private_address", "fee_address", "signature"}:
            raise ValueError("invalid signed claim")
        with self.accept_lock:
            if time.monotonic() < self.next_accept:
                raise ValueError("check the same claim again in a moment")
            self.next_accept = time.monotonic() + 1
            with tempfile.NamedTemporaryFile(dir=self.root, prefix=".claim-") as request:
                request.write(json.dumps(data).encode())
                request.flush()
                result = subprocess.run([str(self.binary), "accept", "--root", str(self.root), "--request-file", request.name], capture_output=True, text=True, timeout=10)
            if result.returncode:
                raise ValueError(result.stderr.strip().removeprefix("Faucet error: "))
            return json.loads(result.stdout)

    def work(self):
        while not self.stop.is_set():
            # Password through stdin only. No cold treasury/validator keys are loaded.
            with self.child_lock:
                if self.stop.is_set():
                    return
                self.child = subprocess.Popen([str(self.binary), "tick", "--root", str(self.root), "--password-file", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                child = self.child
            try:
                child.communicate(input=self.password, timeout=180)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=10)
            finally:
                with self.child_lock:
                    self.child = None
            self.stop.wait(2)

    def close(self):
        self.stop.set()
        with self.child_lock:
            if self.child is not None and self.child.poll() is None:
                self.child.kill()  # Original journals remain authoritative for restart.
        self.password = ""


class BoundedServer(ThreadingHTTPServer):
    request_queue_size = 8

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(10)
        return request, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        try:
            if self.path not in ({"/join", "/status"} if self.server.app.required else {"/"}) or self.headers.get("Host") != self.server.authority or self.headers.get("Origin") is not None:
                raise ValueError("invalid faucet authority or browser origin")
            if self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding") is not None:
                raise ValueError("use bounded JSON")
            self.server.app.ingress("faucet", self.client_address[0])
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= (4096 if self.server.app.required else 2048):
                raise ValueError("claim exceeds limit")
            body = json.loads(self.rfile.read(length))
            result = self.server.app.access_action(self.path, body) if self.server.app.required else self.server.app.accept(body)
            code = 200
        except (ValueError, RecursionError, OSError, subprocess.SubprocessError) as error:
            text = str(error)
            if "lifetime capacity exhausted" in text:
                result, code = {"error": "capacity_exhausted"}, 409
            elif "again in a moment" in text or "quota exhausted" in text:
                result, code = {"error": "try_later"}, 429
            else:
                result, code = {"error": "access_denied" if self.server.app.required else "claim_unavailable"}, 403 if self.server.app.required else 400
        data = json.dumps(result).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8780)
    parser.add_argument("--tls-cert",type=Path)
    parser.add_argument("--tls-key",type=Path)
    args = parser.parse_args()
    app = Faucet(args.root, args.password_file)
    info=app.command("access-info")  # Missing/partial admission state fails before listening.
    from service_tls import listener
    endpoint=info['faucet_audience'] if info.get('invite_required') else f'http://127.0.0.1:{args.port}'
    server=listener(endpoint,args.port,Handler,app,args.tls_cert,args.tls_key)
    worker = threading.Thread(target=app.work, daemon=True)
    worker.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.close()
        server.server_close()
        worker.join(timeout=15)


if __name__ == "__main__":
    main()
