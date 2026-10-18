#!/usr/bin/env python3
"""Read-only extracted-package acceptance against a preserved local rehearsal."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.request

from localnet import PROJECT, load, quiet, rpc, start, stop, wait_rpc
from replay_localnet import prepare


class RpcProbe(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.server.hits += 1
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.server.redirect:
            self.send_response(307)
            self.send_header("Location", self.server.redirect)
            self.end_headers()
        else:
            raw = json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": "1" * 32}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True, help="preserved stopped private rehearsal with a funded user wallet")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--browser-script", type=Path, required=True)
    parser.add_argument("--playwright-module", required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    config = load(root)
    if config.get("key_mode") != "local-testnet-rehearsal-v1":
        parser.error("use a preserved private rehearsal")
    evidence = Path(tempfile.mkdtemp(prefix="tester-package-LOCAL-014-"))
    children, wallet, probes, threads = [None, None], None, [], []
    result = {"status": "running", "archive_sha256": hashlib.sha256(args.archive.read_bytes()).hexdigest(), "events": []}
    def event(kind, **values):
        result["events"].append({"kind": kind, **values})
        (evidence / "result.json").write_text(json.dumps(result, indent=2))
        print(kind, flush=True)
    def command(values, expect=None, password=None):
        completed = subprocess.run([str(v) for v in values], input=password, capture_output=True, text=True, timeout=180)
        if expect:
            if completed.returncode == 0 or expect not in completed.stderr:
                raise RuntimeError("expected rejection: " + expect + "; " + completed.stderr)
            return None
        if completed.returncode:
            raise RuntimeError(completed.stderr)
        return json.loads(completed.stdout)
    def launch(data, profile="default"):
        stream = (evidence / (profile + "-wallet.log")).open("ab")
        child = subprocess.Popen(["sh", str(bundle / "start-wallet.command"), "--no-browser", "--data-dir", str(data),
                                  "--profile", profile, "--port", "8771", "--duration", "600"], cwd=evidence, stdout=stream, stderr=subprocess.STDOUT)
        stream.close()
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError("extracted launcher exited; inspect wallet log")
            try:
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open("http://127.0.0.1:8771/api/session", timeout=1) as response:
                    if json.load(response)["network"] == "Invited tester rehearsal":
                        return child
            except OSError:
                time.sleep(.1)
        child.terminate()
        child.wait(timeout=10)
        raise RuntimeError("extracted wallet did not start")
    def probe(tls=False, redirect=None):
        server = ThreadingHTTPServer(("127.0.0.1", 0), RpcProbe)
        server.hits, server.redirect = 0, redirect
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(evidence / "certificate.pem", evidence / "tls.key")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        probes.append(server)
        threads.append(thread)
        return server, ("https" if tls else "http") + f"://127.0.0.1:{server.server_port}"
    try:
        with tarfile.open(args.archive) as archive:
            archive.extractall(evidence, filter="data")
        bundle = evidence / "native-wallet"
        launcher = bundle / "start-wallet.command"
        executable = bundle / "bin/native-wallet"
        profile_file = bundle / "wallet-profile.json"
        profile = json.loads(profile_file.read_text())
        if profile["genesis_hash"] != config["genesis_hash"] or profile["rpc"] != {"url": "http://127.0.0.1:18899", "transport": "loopback-http"}:
            raise RuntimeError("archive does not pin this fixture")
        verified = command(["sh", launcher, "--verify"])
        event("extracted_integrity_passed", **verified)
        # Explicit overrides are rejected before a password/RPC is needed.
        command([executable, "check", "--network", profile_file, "--rpc", "http://127.0.0.1:19899"], "override is forbidden")
        command([executable, "send", "--network", profile_file], "no operator sponsorship")
        command([executable, "check", "--network", profile_file, "--sponsor", "missing-key"], "no operator sponsorship")
        def changed(name, endpoint, transport):
            path = evidence / (name + ".json")
            path.write_text(json.dumps({**profile, "rpc": {"url": endpoint, "transport": transport}}))
            return path
        destination, destination_url = probe()
        redirect, redirect_url = probe(redirect=destination_url)
        command([executable, "check", "--network", changed("redirect", redirect_url, "loopback-http")], "unsupported HTTP status 307")
        if destination.hits:
            raise RuntimeError("RPC followed a redirect")
        command([executable, "check", "--network", changed("wrong-chain", destination_url, "loopback-http")], "genesis does not match")
        before = destination.hits
        command([executable, "check", "--network", changed("downgrade", destination_url, "https")], "requires explicit HTTPS")
        if destination.hits != before:
            raise RuntimeError("invalid transport contacted RPC")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(evidence / "tls.key"),
                        "-out", str(evidence / "certificate.pem"), "-days", "1", "-subj", "/CN=localhost"], check=True, capture_output=True)
        (evidence / "tls.key").chmod(0o600)
        tls, tls_url = probe(tls=True)
        command([executable, "check", "--network", changed("untrusted-tls", tls_url, "https")], "Wallet error:")
        if tls.hits:
            raise RuntimeError("RPC accepted an untrusted TLS certificate")
        event("transport_rejections_passed", redirected_requests=0, untrusted_tls_rpc_requests=0, rpc_override_rejected=True, operator_options_rejected=True)
        offline_password = secrets.token_urlsafe(36)
        with os.fdopen(os.open(evidence / "offline.password", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as saved:
            saved.write(offline_password)
        for phase in ["offline", "offline-restore"]:
            wallet = launch(evidence / "offline-state", phase)
            completed = subprocess.run(["node", str(args.browser_script), str(evidence), phase], input=json.dumps({"password": offline_password}), capture_output=True, text=True,
                                       env=dict(os.environ, PLAYWRIGHT_MODULE=args.playwright_module), timeout=180)
            (evidence / (phase + "-browser.log")).write_text(completed.stdout + completed.stderr)
            if completed.returncode:
                raise RuntimeError("offline browser failed; see evidence")
            wallet.terminate()
            wallet.wait(timeout=10)
            wallet = None
        event("offline_creation_backup_and_restore_passed")
        # Reuse stopped fixture, preserving signed towers, ledgers, budgets and wallets.
        event("coordinated_prepare", result=prepare(root))
        for i in [0, 1]:
            children[i] = start(root, i, coordinated=True)
            wait_rpc(root, i)
        quiet(root)
        health = command(["sh", launcher, "--check"])
        wrong_domain = evidence / "wrong-domain.json"
        wrong_domain.write_text(json.dumps({**profile, "network": [8] * 32}))
        command([executable, "check", "--network", wrong_domain], "native pool owner, domain or backing mismatch")
        pool_before = rpc(18899, "getAccountInfo", [config["pool"], {"encoding": "base64", "commitment": "finalized"}])["value"]
        role_balances = {role: rpc(18899, "getBalance", [key, {"commitment": "finalized"}])["value"] for role, key in config["roles"].items() if role in ("treasury", "sponsor")}
        password = (root / "wallets/unlock.password").read_text()
        state = evidence / "online-state"
        wallet = launch(state)
        completed = subprocess.run(["node", str(args.browser_script), str(evidence), "online"],
                                   input=json.dumps({"password": password, "backup": json.loads((root / "wallet-ui-user-fees/recovery.json").read_text())}),
                                   capture_output=True, text=True, env=dict(os.environ, PLAYWRIGHT_MODULE=args.playwright_module), timeout=240)
        (evidence / "online-browser.log").write_text(completed.stdout + completed.stderr)
        if completed.returncode:
            raise RuntimeError("online browser failed; see evidence")
        args_base = [executable, "balance", "--network", profile_file, "--wallet", state / "wallet-ui/wallet.json", "--password-file", "-"]
        balance = command(args_base, password=password)
        fee_quote = command([executable, "fees", *args_base[2:]], password=password)
        if balance["balance"] != 2_000_000 or balance["public_balance"] != 3_000_000 or fee_quote["funding_shortfall"]:
            raise RuntimeError("restored package wallet accounting differs")
        # Full package replacement remains byte-for-byte deterministic and reuses state.
        wallet.terminate()
        wallet.wait(timeout=10)
        wallet = None
        before_files = {p.relative_to(state).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in state.rglob("*") if p.is_file()}
        with tarfile.open(args.archive) as archive:
            archive.extractall(evidence, filter="data")
        wallet = launch(state)
        after_files = {p.relative_to(state).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in state.rglob("*") if p.is_file()}
        if before_files != after_files:
            raise RuntimeError("package replacement changed wallet state")
        pool_after = rpc(18899, "getAccountInfo", [config["pool"], {"encoding": "base64", "commitment": "finalized"}])["value"]
        if pool_before != pool_after or role_balances != {role: rpc(18899, "getBalance", [config["roles"][role], {"commitment": "finalized"}])["value"] for role in role_balances}:
            raise RuntimeError("read-only package acceptance changed payment or operator state")
        for i in [0, 1]:
            peer = rpc(18899 + i*1000, "getAccountInfo", [config["pool"], {"encoding": "base64", "commitment": "finalized"}])["value"]
            if peer != pool_before:
                raise RuntimeError("validators differ on native pool")
        result.update(status="passed", health=health, balance=balance, fee_quote=fee_quote, package_replacement_preserved_state=True,
                      operator_balances_unchanged=True, native_pool_unchanged=True)
        event("standalone_package_acceptance_passed")
    except Exception as error:
        result.update(status="failed", error=str(error))
        raise
    finally:
        if wallet is not None and wallet.poll() is None:
            wallet.terminate()
            wallet.wait(timeout=10)
        for server in probes:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
        errors = []
        for i in [1, 0]:
            if children[i] is not None and children[i].poll() is None:
                try:
                    stop(root, i)
                except Exception as error:
                    errors.append(str(error))
        if errors:
            result.update(status="failed", cleanup_errors=errors)
        (evidence / "result.json").write_text(json.dumps(result, indent=2))
        print("Evidence: " + str(evidence), flush=True)
        if errors:
            raise RuntimeError("owned validator cleanup failed")


if __name__ == "__main__":
    main()
