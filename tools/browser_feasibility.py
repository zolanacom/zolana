#!/usr/bin/env python3
"""Loopback-only synthetic WASM lab. Never opens a wallet or contacts a chain."""
import argparse
import json
import math
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import threading

REPO = Path(__file__).resolve().parents[1]
LAB = REPO / "clients/browser-lab"
STORAGE_LAB = REPO / "clients/browser-wallet"
MAX_FIXTURE_BYTES = 128 * 1024
WASM_NAMES = ("browser_core.js", "browser_core_bg.wasm")


def public_fixture(value):
    """Only the public synthetic contract may reach the native subprocess."""
    if not isinstance(value, dict):
        raise ValueError("Expected a public synthetic fixture object.")
    fields = {"format", "fixture_only", "network_hex", "funding_payload_hex", "payment_payload_hex", "envelope_hex", "timings_ms"}
    if set(value) != fields or value["format"] != "zolana-browser-synthetic-fixture-v1" or value["fixture_only"] is not True:
        raise ValueError("Unknown public fixture contract.")
    for field in ("network_hex", "funding_payload_hex", "payment_payload_hex", "envelope_hex"):
        packet = value[field]
        if not isinstance(packet, str) or not packet or len(packet) % 2 or len(packet) > 100_000:
            raise ValueError("Invalid public packet encoding.")
        if any(c not in "0123456789abcdef" for c in packet):
            raise ValueError("Expected canonical lowercase hexadecimal.")
    if len(value["network_hex"]) != 64:
        raise ValueError("Invalid synthetic network identity.")
    times = value["timings_ms"]
    if not isinstance(times, dict) or set(times) != {"funding_proof", "payment_proof", "local_verify"}:
        raise ValueError("Invalid synthetic timing record.")
    if any(type(v) not in (int, float) or not math.isfinite(v) or not 0 <= v < 1e9 for v in times.values()):
        raise ValueError("Invalid synthetic timing values.")
    return value


def verify_native(checker, fixture):
    result = subprocess.run([str(checker)], input=json.dumps(fixture).encode(),
                            capture_output=True, timeout=45, check=False)
    if result.returncode or len(result.stdout) > 16_384:
        raise ValueError("Native checker rejected the public synthetic fixture.")
    output = json.loads(result.stdout)
    if (not isinstance(output, dict) or output.get("ok") is not True or
            output.get("format") != "zolana-browser-native-parity-v1" or output.get("fixture_only") is not True or
            output.get("backing_after") != 97 or output.get("commitments") != 4):
        raise ValueError("Native checker did not confirm compatibility.")
    checks = output.get("checks", [])
    if not isinstance(checks, list) or not 1 <= len(checks) <= 20 or not all(isinstance(c, str) and len(c) <= 300 for c in checks):
        raise ValueError("Invalid native checker response.")
    return {"ok": True, "checks": checks}


class LabServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, wasm_dir, checker=None, parallel_wasm_dir=None, parallel_snippets=()):
        if address[0] != "127.0.0.1":
            raise ValueError("The synthetic lab binds only to 127.0.0.1.")
        self.wasm_dir = Path(wasm_dir).resolve()
        self.checker = Path(checker).resolve() if checker else None
        self.parallel_assets = {}
        if parallel_wasm_dir:
            base = Path(parallel_wasm_dir).resolve()
            self.parallel_assets = {f"/wasm-parallel/{n}": base / n for n in WASM_NAMES}
            if not parallel_snippets:
                raise ValueError("Explicit generated Rayon snippet paths are required.")
            for name in parallel_snippets:
                if not re.fullmatch(r"snippets/wasm-bindgen-rayon-[0-9a-f]+/src/workerHelpers\.no-bundler\.js", name):
                    raise ValueError("Only the explicit generated Rayon helper is accepted.")
                target = (base / name).resolve()
                if not target.is_relative_to(base) or not target.is_file():
                    raise ValueError("Generated Rayon helper must exist inside the selected package.")
                self.parallel_assets[f"/wasm-parallel/{name}"] = target
        self.verify_slot = threading.BoundedSemaphore(1)
        super().__init__(address, LabHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"


class LabHandler(BaseHTTPRequestHandler):
    server_version = "ZolanaSyntheticLab"

    def log_message(self, *_args):
        pass  # No request bodies, public packets or browser headers in logs.

    def reply(self, status, content, mime="application/json"):
        if isinstance(content, dict):
            content = json.dumps(content, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # The pinned Rayon no-bundler helper creates Blob module workers. This
        # exception is opt-in for the synthetic parallel lab, not wallet policy.
        worker_sources = "'self' blob:" if self.server.parallel_assets else "'self'"
        self.send_header("Content-Security-Policy", f"default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; worker-src {worker_sources}; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
        self.end_headers()
        self.wfile.write(content)

    def allowed(self, require_origin=False):
        if self.headers.get("Host") != self.server.origin.removeprefix("http://"):
            self.reply(403, {"error": "Host refused."})
            return False
        origin = self.headers.get("Origin")
        if (require_origin and origin != self.server.origin) or (origin and origin != self.server.origin):
            self.reply(403, {"error": "Request origin refused."})
            return False
        if self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin"):
            self.reply(403, {"error": "Cross-site request refused."})
            return False
        return True

    def do_GET(self):
        if not self.allowed():
            return
        if self.path == "/api/config":
            self.reply(200, {"test_only": True,
                             "wasm_ready": all((self.server.wasm_dir / n).is_file() for n in WASM_NAMES),
                             "parallel_ready": bool(self.server.parallel_assets) and all(p.is_file() for p in self.server.parallel_assets.values()),
                             "native_checker_ready": bool(self.server.checker and self.server.checker.is_file())})
            return
        static = {"/": (LAB / "index.html", "text/html; charset=utf-8"),
                  "/lab.css": (LAB / "lab.css", "text/css; charset=utf-8"),
                  "/lab.js": (LAB / "lab.js", "text/javascript; charset=utf-8"),
                  "/worker.js": (LAB / "worker.js", "text/javascript; charset=utf-8"),
                  "/storage-test.html": (STORAGE_LAB / "storage-test.html", "text/html; charset=utf-8"),
                  "/storage-test.js": (STORAGE_LAB / "storage-test.js", "text/javascript; charset=utf-8"),
                  "/vault-test.html": (STORAGE_LAB / "vault-test.html", "text/html; charset=utf-8"),
                  "/vault-test.js": (STORAGE_LAB / "vault-test.js", "text/javascript; charset=utf-8"),
                  "/vault-worker.js": (STORAGE_LAB / "vault-worker.js", "text/javascript; charset=utf-8"),
                  "/storage.js": (STORAGE_LAB / "storage.js", "text/javascript; charset=utf-8")}
        static.update({f"/wasm/{n}": (self.server.wasm_dir / n,
                       "application/wasm" if n.endswith(".wasm") else "text/javascript; charset=utf-8") for n in WASM_NAMES})
        static.update({name: (target, "application/wasm" if name.endswith(".wasm") else "text/javascript; charset=utf-8")
                       for name, target in self.server.parallel_assets.items()})
        target = static.get(self.path)
        if not target or not target[0].is_file():
            self.reply(404, {"error": "Local lab asset not found."})
            return
        self.reply(200, target[0].read_bytes(), target[1])

    def do_POST(self):
        if not self.allowed(require_origin=True):
            return
        if self.path != "/api/verify":
            self.reply(404, {"error": "Unknown lab operation."})
            return
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Type") != "application/json":
            self.reply(415, {"error": "Expected a bounded JSON body."})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_FIXTURE_BYTES:
            self.reply(413, {"error": "Public fixture exceeds the lab limit."})
            return
        if not self.server.checker or not self.server.checker.is_file():
            self.reply(503, {"error": "Native compatibility checker is not configured."})
            return
        if not self.server.verify_slot.acquire(blocking=False):
            self.reply(429, {"error": "A native check is already running."})
            return
        try:
            self.connection.settimeout(10)
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete public fixture.")
            fixture = public_fixture(json.loads(raw))
            self.reply(200, verify_native(self.server.checker, fixture))
        except (ValueError, UnicodeError, TimeoutError, subprocess.SubprocessError, OSError):
            self.reply(400, {"error": "Public synthetic fixture or native compatibility check failed."})
        finally:
            self.server.verify_slot.release()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18994)
    parser.add_argument("--wasm-dir", type=Path, default=REPO / "clients/browser-core/pkg")
    parser.add_argument("--native-checker", type=Path)
    parser.add_argument("--parallel-wasm-dir", type=Path)
    parser.add_argument("--parallel-snippet", action="append", default=[], help="Exact generated Rayon helper path relative to the parallel package")
    args = parser.parse_args()
    if args.native_checker and not args.native_checker.is_file():
        parser.error("The explicit native checker does not exist.")
    with LabServer(("127.0.0.1", args.port), args.wasm_dir, args.native_checker, args.parallel_wasm_dir, args.parallel_snippet) as server:
        print(f"Synthetic local lab: {server.origin}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
