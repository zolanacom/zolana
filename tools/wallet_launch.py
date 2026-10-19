#!/usr/bin/env python3
"""Launch a verified standalone bundle; wallet secrets stay outside the bundle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import threading
import webbrowser


def verify(bundle):
    manifest_file = bundle / "MANIFEST.json"
    if manifest_file.is_symlink() or manifest_file.stat().st_size > 1_000_000:
        raise ValueError("invalid bundle manifest")
    manifest = json.loads(manifest_file.read_text())
    if manifest["format"] != "native-wallet-bundle-v1":
        raise ValueError("unsupported bundle format")
    expected = manifest["files"]
    actual = set()
    for path in bundle.rglob("*"):
        if path.is_symlink():
            raise ValueError("bundle must not contain symlinks")
        if path.is_file():
            actual.add(path.relative_to(bundle).as_posix())
    if actual != set(expected) | {"MANIFEST.json"}:
        raise ValueError("bundle file inventory differs from its manifest")
    for name, record in expected.items():
        path = bundle / name
        if path.stat().st_size != record["size"] or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
            raise ValueError("bundle integrity check failed: " + name)
    host = f"{platform.system().lower()}-{platform.machine().lower()}"
    if manifest["platform"] != host:
        raise ValueError("this bundle requires " + manifest["platform"] + "; this machine is " + host)
    return manifest


def main(argv=None):
    sys.dont_write_bytecode = True
    bundle = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Device-local test wallet; test coins only", allow_abbrev=False)
    parser.add_argument("--verify", action="store_true", help="verify bundle integrity without a network connection")
    parser.add_argument("--check", action="store_true", help="check the pinned RPC without opening a seed")
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--duration", type=int, default=3600)
    parser.add_argument("--profile", default="default")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    if sys.version_info < (3, 10):
        parser.error("Python 3.10 or newer is required")
    manifest = verify(bundle)
    binary = bundle / "bin/native-wallet"
    network = bundle / "wallet-profile.json"
    if args.verify:
        print(json.dumps({"verified": True, "platform": manifest["platform"], "source_commit": manifest["source_commit"]}))
        return
    if args.check:
        subprocess.run([str(binary), "check", "--network", str(network)], check=True)
        return
    if not 1024 <= args.port <= 65535 or not 60 <= args.duration <= 3600:
        parser.error("use a nonprivileged port and a session of 60..3600 seconds")
    profile = json.loads(network.read_text())
    base = Path.home() / ("Library/Application Support" if platform.system() == "Darwin" else ".local/share")
    # Preserve the established directory after the Zolana branding change.
    # Renaming it would silently create an apparently empty replacement wallet.
    data = args.data_dir or base / "Zolana Test Wallet" / profile["genesis_hash"]
    if data.resolve().is_relative_to(bundle):
        parser.error("wallet data must be outside the replaceable package directory")
    # The independently trusted release runner uses isolated Python. Add only
    # the verified runtime directory, after validating the complete manifest.
    sys.path.insert(0, str(bundle / "runtime"))
    import wallet_ui
    wallet_ui.ASSETS = bundle / "assets"
    app = wallet_ui.WalletApp.from_profile(network, data, args.profile, binary)
    timer = None
    if not args.no_browser:
        timer = threading.Timer(1, webbrowser.open, [f"http://127.0.0.1:{args.port}/"])
        timer.daemon = True
        timer.start()
    try:
        wallet_ui.serve(app, args.port, args.duration)
    finally:
        if timer:
            timer.cancel()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print("Wallet launcher: " + str(error), file=sys.stderr)
        sys.exit(1)
