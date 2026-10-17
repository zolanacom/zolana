#!/usr/bin/env python3
"""Own bounded mobile-browser acceptance and both loopback validators."""
import argparse
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import threading

from fault_localnet import durable
from localnet import LAB, PROJECT, quiet, start, stop, wait_rpc
from wallet_ui import Handler, WalletApp, WALLET


def run(root, evidence):
    children, servers = [None, None], []
    result = {"status": "running"}
    try:
        subprocess.run([str(LAB), "init", str(root)], check=True, capture_output=True)
        for index in [0, 1]:
            children[index] = start(root, index)
            wait_rpc(root, index)
        quiet(root)
        bob = WalletApp(root, "mobile-recipient")
        password = "Disposable recipient acceptance password"
        recipient = bob.cli("init", password, ["--backup", str(bob.backup)])["address"]
        for profile, port in [("mobile", 8769), ("mobile-restored", 8770)]:
            server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            server.authority = f"127.0.0.1:{port}"
            server.app = WalletApp(root, profile)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        browser = subprocess.run(["node", str(PROJECT / "tools/wallet_mobile_test.cjs"), str(root), recipient, str(evidence)], capture_output=True, text=True, timeout=600)
        (root / "mobile-browser.log").write_text(browser.stdout + browser.stderr)
        if browser.returncode:
            raise RuntimeError(browser.stderr)
        balances = []
        for index in [0, 1]:
            response = subprocess.run([str(WALLET), "balance", "--network", str(root / "network.json"), "--wallet", str(bob.wallet), "--password-file", "-", "--rpc", f"http://127.0.0.1:{18899+index*1000}"], input=password, capture_output=True, text=True, timeout=180)
            if response.returncode:
                raise RuntimeError(response.stderr)
            balance = json.loads(response.stdout)
            if balance["balance"] != 7:
                raise RuntimeError("mobile payment recipient has the wrong balance")
            balances.append(balance)
        if durable(root, 0) != durable(root, 1) or len(durable(root, 0)) != 5:
            raise RuntimeError("mobile payments did not preserve exact pool and four permanent nullifiers")
        result.update(status="passed", recipient_balances=balances, exact_pool_and_four_nullifiers=True)
        print("Mobile browser recovery/payment acceptance passed", flush=True)
    except Exception as error:
        result.update(status="failed", error=str(error))
        raise
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        errors = []
        for index in [1, 0]:
            if children[index] is not None and children[index].poll() is None:
                try:
                    stop(root, index)
                except Exception as error:
                    errors.append(str(error))
        if errors:
            result.update(status="failed", cleanup_errors=errors)
        if root.exists():
            (root / "mobile-result.json").write_text(json.dumps(result, indent=2))
        if errors:
            raise RuntimeError("owned validator cleanup failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data") or root.exists():
        parser.error("use a new ignored .data fixture")
    run(root, args.evidence.resolve())
