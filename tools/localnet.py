#!/usr/bin/env python3
"""Run only this repository's disposable, loopback native-payment network."""
import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.request

PROJECT = Path(__file__).resolve().parents[1]
VALIDATOR = PROJECT / "target/debug/agave-validator"
LAB = PROJECT / "target/debug/native-localnet"
LOG_FILTER = "warn,solana_runtime::snapshot_bank_utils=info,solana_runtime::bank=info"


def rpc(port, method, params=None):
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}",
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []}).encode(),
        {"Content-Type": "application/json"},
    )
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as response:
        result = json.load(response)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]


def load(root):
    config = json.loads((root / "network.json").read_text())
    if config.get("fixture_keys_are_public") is not True:
        raise RuntimeError("not a disposable fixture network")
    return config


def port(index):
    return 18899 + index * 1000


def ledger(root, index):
    active = root / f"active-ledger-{index}.json"
    name = json.loads(active.read_text()) if active.exists() else f"ledger-{index}"
    path = root / name
    if path.parent != root or not path.is_dir():
        raise RuntimeError("invalid local ledger path")
    return path


def wait_rpc(root, index, timeout=120):
    config = load(root)
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if rpc(port(index), "getGenesisHash") != config["genesis_hash"]:
                raise RuntimeError("loopback port belongs to another network")
            actual = rpc(port(index), "getIdentity")["identity"]
            if actual != config["identities"][index]:
                raise RuntimeError("unexpected validator identity")
            return rpc(port(index), "getSlot", [{"commitment": "confirmed"}])
        except (OSError, ValueError, RuntimeError) as error:
            last = error
            time.sleep(0.3)
    raise RuntimeError(f"validator {index} did not become ready: {last}; inspect its local log")


def start(root, index, archive=False):
    config = load(root)
    if config.get("pool_format") != "NPOOL002":
        raise RuntimeError("incompatible development pool format; preserve this network and initialize a fresh --root")
    with socket.socket() as probe:
        # Ignore completed TCP connections in TIME_WAIT, while rejecting a live listener.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port(index)))
    path = ledger(root, index)
    if len(os.fsencode(path / "admin.rpc")) >= 104:
        raise RuntimeError("ledger path exceeds the portable local admin socket limit")
    tower = root / f"consensus-{index}"
    tower.mkdir(mode=0o700, exist_ok=True)
    args = [str(VALIDATOR), "--ledger", str(path),
        "--identity", str(root / f"identity-{index}.keypair.json"),
        "--tower", str(tower),
        "--vote-account", str(root / f"vote-{index}.keypair.json"),
        "--authorized-voter", str(root / f"vote-{index}.keypair.json"),
        "--expected-genesis-hash", config["genesis_hash"],
        "--bind-address", "127.0.0.1", "--gossip-host", "127.0.0.1",
        "--gossip-port", str(18000 + index * 1000),
        "--dynamic-port-range", f"{18100 + index * 1000}-{18200 + index * 1000}",
        "--rpc-bind-address", "127.0.0.1", "--rpc-port", str(port(index)),
        "--private-rpc", "--full-rpc-api", "--allow-private-addr",
        "--no-genesis-fetch", "--no-snapshot-fetch", "--no-port-check",
        "--no-os-network-limits-test", "--no-poh-speed-test",
        "--no-incremental-snapshots",
        "--snapshot-interval-slots", "40", "--maximum-full-snapshots-to-retain", "2",
        "--limit-ledger-size", "50000000", "--rpc-threads", "2", "--rpc-blocking-threads", "2",
        "--rayon-global-threads", "2", "--accounts-db-foreground-threads", "2",
        "--accounts-db-background-threads", "1", "--accounts-db-hash-threads", "1",
        "--accounts-index-flush-threads", "1", "--replay-transactions-threads", "2",
        "--block-production-num-workers", "2", "--rocksdb-compaction-threads", "1",
        "--rocksdb-flush-threads", "1", "--log", str(root / f"validator-{index}.log")]
    if list(tower.glob("tower-*.bin")):
        args += ["--require-tower"]
    elif index == 0:
        args += ["--no-wait-for-vote-to-start-leader"]
    if index:
        args += ["--entrypoint", "127.0.0.1:18000"]
    if archive:
        args += ["--use-snapshot-archives-at-startup", "always"]
    env = dict(os.environ, SOLANA_METRICS_CONFIG="", RUST_LOG=LOG_FILTER)
    with (root / f"validator-{index}.console.log").open("ab") as output:
        process = subprocess.Popen(args, cwd=PROJECT, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
    (root / f"validator-{index}.pid").write_text(str(process.pid))
    (root / f"validator-{index}.command.json").write_text(json.dumps(args, indent=2))
    print(f"Started local validator {index}; PID {process.pid}, RPC http://127.0.0.1:{port(index)}", flush=True)


def stop(root, index):
    load(root)
    saved_pid = int((root / f"validator-{index}.pid").read_text())
    try:
        os.kill(saved_pid, 0)
    except ProcessLookupError:
        print(f"Local validator {index} is already stopped", flush=True)
        return
    # Address the managed ledger's admin socket; never terminate an arbitrary saved PID.
    subprocess.run([str(VALIDATOR), "--ledger", str(ledger(root, index)), "exit", "--force", "--no-wait-for-exit"], check=True, timeout=15)
    saved_pid = int((root / f"validator-{index}.pid").read_text())
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            # Reap our own child if this command started it; otherwise query the orphan.
            finished, _ = os.waitpid(saved_pid, os.WNOHANG)
            if finished == saved_pid:
                break
        except ChildProcessError:
            pass
        try:
            os.kill(saved_pid, 0)  # Liveness query only; no terminating signal.
        except ProcessLookupError:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError(f"validator {index} has not exited after its admin shutdown request")
    print(f"Stopped local validator {index}", flush=True)


def quiet(root):
    load(root)
    for index in [0, 1]:
        wait_rpc(root, index, timeout=10)
        subprocess.run([str(VALIDATOR), "--ledger", str(ledger(root, index)), "set-log-filter", "warn"], check=True, timeout=10)
    print("Both local validators now log warnings/errors while running in the background", flush=True)


def lab(root, command, primary=0, peer=1):
    subprocess.run([str(LAB), command, str(root), f"http://127.0.0.1:{port(primary)}", f"http://127.0.0.1:{port(peer)}"], check=True, env=dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost"))


def newer_full_snapshot(directory, after_slot):
    candidates = []
    for item in directory.glob("snapshot-*.tar.zst"):
        match = re.fullmatch(r"snapshot-([0-9]+)-([1-9A-HJ-NP-Za-km-z]{32,44})\.tar\.zst", item.name)
        if match and int(match[1]) > after_slot:
            candidates.append((int(match[1]), item))
    return max(candidates, key=lambda entry: entry[0]) if candidates else None


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify(root):
    wait_rpc(root, 0)
    if (root / "recovery-result.json").exists():
        raise RuntimeError("this network already completed recovery verification; use status or a fresh network")
    if (root / "payment-result.json").exists():
        # Resume only after authenticating the leader's persisted payment state.
        lab(root, "recovery-check", 0, 0)
    else:
        wait_rpc(root, 1)
        lab(root, "exercise")
    result = json.loads((root / "payment-result.json").read_text())
    stop(root, 1)
    # A fresh ledger must not recreate slots this identity already signed.
    # Wait for a finalized full archive beyond the cluster tip at shutdown.
    snapshot_barrier = max(result["slot"], rpc(port(0), "getSlot", [{"commitment": "processed"}]))
    deadline = time.monotonic() + 100
    archive = None
    while time.monotonic() < deadline:
        candidate = newer_full_snapshot(ledger(root, 0), snapshot_barrier)
        if candidate:
            archive_slot, archive = candidate
            break
        time.sleep(0.5)
    if archive is None:
        raise RuntimeError("no full snapshot newer than the payment state was produced")
    # The new ledger has only genesis slot zero; no old account files or transaction
    # ledger are copied. Startup is forced to extract the selected full archive.
    recovery_index = 1
    while (root / f"ledger-recovered-{recovery_index}").exists():
        recovery_index += 1
    recovery_name = f"ledger-recovered-{recovery_index}"
    subprocess.run([str(LAB), "prepare-recovery", str(root), recovery_name], check=True)
    recovered = root / recovery_name
    destination = recovered / archive.name
    archive_digest = digest(archive)
    shutil.copy2(archive, destination)
    if digest(destination) != archive_digest:
        raise RuntimeError("snapshot copy digest mismatch")
    (root / "snapshot-input.json").write_text(json.dumps({"archive": archive.name, "archive_slot": archive_slot, "archive_sha256": archive_digest, "fresh_ledger": recovered.name}, indent=2))
    (root / "active-ledger-1.json").write_text(json.dumps(recovered.name))
    log = root / "validator-1.log"
    previous_size = log.stat().st_size
    start(root, 1, archive=True)
    restored_slot = wait_rpc(root, 1)
    lab(root, "recovery-check", 1, 0)
    with log.open("rb") as stream:
        stream.seek(previous_size)
        recovery_log = stream.read().decode(errors="replace")
    if ("Loading bank from full snapshot archive:" not in recovery_log
            or archive.name not in recovery_log
            or "rebuild bank from snapshots took" not in recovery_log
            or "Verifying bank... Done." not in recovery_log):
        raise RuntimeError("missing snapshot restoration log evidence")
    result["snapshot_recovery"] = {
        "passed": True, "archive": archive.name, "archive_slot": archive_slot, "archive_sha256": archive_digest,
        "restored_slot": restored_slot, "fresh_ledger": True,
        "shutdown_slot_barrier": snapshot_barrier, "consensus_tower_preserved": True,
        "old_accounts_copied": False, "old_transaction_ledger_copied": False,
    }
    (root / "snapshot-result.json").write_text(json.dumps(result, indent=2))
    # Restart the recovered ledger immediately, then exercise the native handler again.
    stop(root, 1)
    start(root, 1)
    restart_slot = wait_rpc(root, 1)
    lab(root, "recovery-check", 1, 0)
    result["restart"] = {"passed": True, "slot": restart_slot, "same_ledger": True}
    result["validators"] = [
        {"rpc": f"http://127.0.0.1:{port(index)}", "identity": rpc(port(index), "getIdentity")["identity"],
         "genesis_hash": rpc(port(index), "getGenesisHash"), "slot": rpc(port(index), "getSlot")}
        for index in [0, 1]
    ]
    (root / "recovery-result.json").write_text(json.dumps(result, indent=2))
    quiet(root)
    print(json.dumps(result, indent=2), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["init", "start", "stop", "status", "verify", "quiet"])
    parser.add_argument("--root", type=Path, default=PROJECT / ".data/localnet")
    parser.add_argument("--validator", type=int, choices=[0, 1], help="start or stop only this validator")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data"):
        raise RuntimeError("local networks must stay inside this project's ignored .data directory")
    if args.command == "init":
        subprocess.run([str(LAB), "init", str(root)], check=True)
    elif args.command == "start":
        for index in ([args.validator] if args.validator is not None else [0, 1]):
            start(root, index)
            wait_rpc(root, index)
    elif args.command == "stop":
        for index in ([args.validator] if args.validator is not None else [1, 0]):
            stop(root, index)
    elif args.command == "quiet":
        quiet(root)
    elif args.command == "status":
        for index in [0, 1]:
            config = load(root)
            slot = wait_rpc(root, index, timeout=5)
            account = rpc(port(index), "getAccountInfo", [config["pool"], {"encoding": "base64", "commitment": "confirmed"}])["value"]
            data = base64.b64decode(account["data"][0])
            print(json.dumps({"validator": index, "slot": slot, "backing": int.from_bytes(data[48:56], "little"), "commitments": int.from_bytes(data[56:64], "little"), "pool_digest": hashlib.sha256(data).hexdigest()}))
    else:
        verify(root)


if __name__ == "__main__":
    main()
