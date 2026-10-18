#!/usr/bin/env python3
"""Build an allowlisted, deterministic local tester archive. Never publishes."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import platform
import subprocess
import tarfile

PROJECT = Path(__file__).resolve().parents[1]


def public_profile(network, label, rpc, transport):
    return {"format": "native-wallet-profile-v1", "label": label, "key_mode": "user-wallet-v1",
            **{key: network[key] for key in ("network", "genesis_hash", "program", "pool", "pool_format", "recipient_withdrawals")},
            "rpc": {"transport": transport, "url": rpc}}


def dependencies():
    metadata = json.loads(subprocess.check_output(["sh", "tools/dev.sh", "metadata", "--offline", "--locked", "--format-version", "1"], cwd=PROJECT))
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    root = next(p["id"] for p in metadata["packages"] if p["name"] == "native-wallet")
    seen, pending = set(), [root]
    while pending:
        package_id = pending.pop()
        if package_id in seen:
            continue
        seen.add(package_id)
        pending += [d["pkg"] for d in nodes[package_id]["deps"] if any(k["kind"] != "dev" for k in d["dep_kinds"])]
    records, files = [], {}
    for p in sorted((packages[i] for i in seen), key=lambda p: (p["name"], p["version"])):
        directory = Path(p["manifest_path"]).parent
        names = sorted({f for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*") for f in directory.glob(pattern) if f.is_file() and not f.is_symlink()})
        if p.get("license_file"):
            license_file = directory / p["license_file"]
            if license_file.is_file() and not license_file.is_symlink():
                names = sorted(set(names) | {license_file})
        entries = []
        for index, f in enumerate(names):
            name = f"notices/{p['name']}-{p['version']}/{index}-{f.name}"
            files[name] = f.read_bytes()
            entries.append(name)
        records.append({"name": p["name"], "version": p["version"], "license": p["license"], "repository": p.get("repository"), "notices": entries})
    files["DEPENDENCIES.json"] = encode(records)
    return files


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def archive(files, modes):
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo("native-wallet/" + name)
                info.size = len(data)
                info.mode = modes.get(name, 0o644)
                info.mtime = 0
                tar.addfile(info, io.BytesIO(data))
    return result.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--network", type=Path, required=True, help="existing network configuration; only public identity fields are copied")
    parser.add_argument("--label", required=True)
    parser.add_argument("--rpc", required=True)
    parser.add_argument("--transport", choices=["loopback-http", "https"], required=True)
    parser.add_argument("--local-tls-ca",type=Path,help="public local test CA only; HTTPS loopback endpoints required")
    parser.add_argument("--invite-only", action="store_true", help="require admission through the pinned faucet and RPC gateway")
    parser.add_argument("--faucet", help="explicit test faucet endpoint; uses the selected transport")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, default=PROJECT / "target/debug/native-wallet")
    args = parser.parse_args()
    if args.binary.resolve() == (PROJECT / "target/debug/native-wallet").resolve():
        subprocess.run(["sh", "tools/dev.sh", "build", "--offline", "--locked", "-p", "native-wallet"], cwd=PROJECT, check=True)
    profile = public_profile(json.loads(args.network.read_text()), args.label, args.rpc, args.transport)
    if args.faucet:
        profile["faucet"] = {"transport": args.transport, "url": args.faucet}
    if args.invite_only:
        profile["invite_required"] = True
    if args.local_tls_ca:
        profile["local_tls_ca_pem"]=args.local_tls_ca.read_text()
    # Validate with the same parser used at every wallet invocation, offline.
    import tempfile
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory) / "profile.json"
        temporary.write_bytes(encode(profile))
        subprocess.run([str(args.binary.resolve()), "profile", "--network", str(temporary)], check=True, stdout=subprocess.DEVNULL)
    files = dependencies()
    for destination, source in {
        "bin/native-wallet": args.binary,
        "runtime/wallet_ui.py": PROJECT / "tools/wallet_ui.py",
        "runtime/wallet_launch.py": PROJECT / "tools/wallet_launch.py",
        "LICENSE": PROJECT / "LICENSE", "THIRD_PARTY.md": PROJECT / "THIRD_PARTY.md",
        "AGAVE-LICENSE": PROJECT / "node/agave/LICENSE",
        "README.txt": PROJECT / "docs/tester-wallet-quickstart.txt",
        **{"assets/" + name: PROJECT / "clients/wallet-ui" / name for name in ("index.html", "style.css", "app.js")},
    }.items():
        if source.is_symlink() or not source.is_file():
            raise ValueError("bundle input must be a regular file: " + destination)
        files[destination] = source.read_bytes()
    files["wallet-profile.json"] = encode(profile)
    files["start-wallet.command"] = b'#!/bin/sh\nset -eu\nexec python3 -B "$(dirname -- "$0")/runtime/wallet_launch.py" "$@"\n'
    modes = {"bin/native-wallet": 0o755, "start-wallet.command": 0o755}
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=PROJECT))
    files["MANIFEST.json"] = encode({"format": "native-wallet-bundle-v1", "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
        "source_commit": revision, "source_dirty": dirty, "binary_kind": "local-development",
        "files": {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in sorted(files.items())}})
    data = archive(files, modes)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as output:
        output.write(data)
    digest = hashlib.sha256(data).hexdigest()
    with Path(str(args.output) + ".sha256").open("x") as checksum:
        checksum.write(digest + "  " + args.output.name + "\n")
    print(json.dumps({"archive": str(args.output), "sha256": digest, "bytes": len(data), "files": len(files), "published": False}))


if __name__ == "__main__":
    main()
