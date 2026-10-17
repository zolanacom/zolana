#!/usr/bin/env python3
"""Replay one received/unfrozen child offline; never delete shreds or reset towers."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

from localnet import LAB, PROJECT, VALIDATOR, digest, ledger, load, restart_state
from restart_localnet import preserved
from wallet_localnet import private_new


def plan(root, index):
    result = subprocess.run([str(LAB), "replay-plan", str(root), str(index), ledger(root, index).name],
                            check=True, capture_output=True, text=True, timeout=30)
    state = json.loads(result.stdout)
    config = load(root)
    if state["identity"] != config["identities"][index] or state["genesis_hash"] != config["genesis_hash"]:
        raise RuntimeError("offline replay identity/genesis mismatch")
    return state


def prepare(root):
    """Both PRIMARY blockstore inspections must succeed before any replay starts."""
    config = load(root)
    before = [plan(root, i) for i in [0, 1]]
    candidates = [i for i in [0, 1] if before[i]["complete_tail_replay_slot"] is not None]
    if not candidates:
        return {"replayed": False}
    if len(candidates) != 1:
        raise RuntimeError("multiple unfrozen tails require explicit ledger repair")
    index = candidates[0]
    slot = before[index]["complete_tail_replay_slot"]
    expected = before[1-index]["frozen_hashes"].get(str(slot))
    if expected is None:
        raise RuntimeError("peer has no frozen bank hash for this child; refusing uncorroborated replay")
    # Keep the corroborating peer stopped while the selected child owns its
    # own ledger lock. Concurrent normal launches must fail instead of racing it.
    with (ledger(root,1-index) / "ledger.lock").open("a+") as peer_lock:
        fcntl.flock(peer_lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        return _replay(root,config,before,index,slot,expected)


def _replay(root,config,before,index,slot,expected):
    sponsor_ledger = root / "sponsor-policy.json.reservations.json"
    sponsor_digest = digest(sponsor_ledger) if sponsor_ledger.exists() else None
    towers = {str(p.relative_to(root)): digest(p) for i in [0, 1] for p in (root / f"consensus-{i}").glob("tower-*.bin")}
    directory = Path(tempfile.mkdtemp(prefix=f"tail-replay-{index}-{slot}-", dir=root))
    private_new(directory / "before.json", json.dumps(before).encode())
    private = config.get("key_mode") == "local-testnet-rehearsal-v1"
    args = [str(VALIDATOR), "--ledger", str(ledger(root, index)),
            "--identity", str(root / f"identity-{index}.keypair.json"), "--tower", str(root / f"consensus-{index}"),
            "--vote-account", config["vote_accounts"][index] if private else str(root / f"vote-{index}.keypair.json"),
            "--authorized-voter", str(root / f"{'voter' if private else 'vote'}-{index}.keypair.json"),
            "--expected-genesis-hash", config["genesis_hash"], "--require-tower", "--no-voting",
            "--dev-halt-at-slot", str(slot), "--process-ledger-before-services",
            "--bind-address", "127.0.0.1", "--gossip-host", "127.0.0.1", "--gossip-port", str(28000+index*1000),
            "--dynamic-port-range", f"{28100+index*1000}-{28200+index*1000}",
            "--rpc-bind-address", "127.0.0.1", "--rpc-port", str(28899+index*1000), "--private-rpc", "--allow-private-addr",
            "--no-genesis-fetch", "--no-snapshot-fetch", "--no-port-check", "--no-os-network-limits-test", "--no-poh-speed-test",
            "--no-incremental-snapshots", "--snapshot-interval-slots", "40", "--maximum-full-snapshots-to-retain", "2",
            "--rpc-threads", "2", "--rpc-blocking-threads", "2", "--rayon-global-threads", "2",
            "--accounts-db-foreground-threads", "2", "--accounts-db-background-threads", "1", "--accounts-db-hash-threads", "1",
            "--accounts-index-flush-threads", "1", "--replay-transactions-threads", "2", "--block-production-num-workers", "2",
            "--rocksdb-compaction-threads", "1", "--rocksdb-flush-threads", "1", "--log", str(directory / "validator.log")]
    private_new(directory / "command.json", json.dumps(args).encode())
    env = dict(os.environ, SOLANA_METRICS_CONFIG="", RUST_LOG="warn,solana_runtime::bank=info")
    env.pop("NATIVE_LOCAL_SHRED_FAULT", None)
    child = None
    try:
        with (directory / "console.log").open("xb") as output:
            child = subprocess.Popen(args, cwd=PROJECT, env=env, stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic()+120
            while time.monotonic() < deadline:
                log = directory / "validator.log"
                if log.exists() and "Validator halted" in log.read_text():
                    break
                if child.poll() is not None:
                    raise RuntimeError("offline replay exited before its inspection halt; inspect its retained log")
                time.sleep(0.1)
            else:
                raise RuntimeError("offline replay did not reach its bounded inspection halt")
    finally:
        # The upstream inspection halt parks its main thread indefinitely. Signal
        # only this owned no-voting child, after replay; no live validator is targeted.
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=20)
    after = [restart_state(root, i) for i in [0, 1]]
    for first, second in zip(before, after):
        preserved(first, second)
    if after[index]["frozen_hashes"].get(str(slot)) != expected or after[index]["slot"] != slot:
        raise RuntimeError("replayed child bank hash differs from the peer's retained frozen bank")
    current_towers = {str(p.relative_to(root)): digest(p) for i in [0, 1] for p in (root / f"consensus-{i}").glob("tower-*.bin")}
    if current_towers != towers:
        raise RuntimeError("offline replay changed a signed tower")
    if sponsor_digest is not None and digest(sponsor_ledger) != sponsor_digest:
        raise RuntimeError("offline replay changed sponsor accounting")
    result = {"replayed": True, "validator": index, "slot": slot, "bank_hash": expected,
              "retained_shreds_and_frozen_hashes_unchanged": True, "signed_towers_unchanged": True, "sponsor_reservations_unchanged": True,
              "inspection_rpc_never_used_for_payments": True}
    private_new(directory / "after.json", json.dumps(after).encode())
    private_new(directory / "result.json", json.dumps(result).encode())
    print(json.dumps(result), flush=True)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data"):
        parser.error("use a managed local .data network with both validators stopped")
    prepare(root)
