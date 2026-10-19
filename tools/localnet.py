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
import stat
import subprocess
import time
import urllib.request

PROJECT = Path(__file__).resolve().parents[1]
VALIDATOR = PROJECT / "target/debug/agave-validator"
LAB = PROJECT / "target/debug/native-localnet"
RPC_CREDENTIALS = {}

LOG_FILTER = "warn,solana_runtime::snapshot_bank_utils=info,solana_runtime::bank=info"


class NoRpcRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def rpc(port, method, params=None):
    raw=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params or []}).encode()
    if port in RPC_CREDENTIALS:
        from operator_transport import Operator
        result=json.loads(Operator(f"http://127.0.0.1:{port}",RPC_CREDENTIALS[port]).forward(raw,timeout=5))
    else:
        request=urllib.request.Request(f"http://127.0.0.1:{port}",raw,{"Content-Type":"application/json"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRpcRedirect()).open(request,timeout=5) as response:
            result=json.load(response)
    if "error" in result:
        raise RuntimeError(result["error"])
    return result["result"]


def load(root):
    config = json.loads((root / "network.json").read_text())
    if config.get("fixture_keys_are_public") is not True:
        if (config.get("fixture_keys_are_public") is not False or
                config.get("key_mode") != "local-testnet-rehearsal-v1" or
                root.is_symlink() or not root.resolve().is_relative_to(PROJECT / ".data") or
                root.stat().st_mode & 0o077):
            raise RuntimeError("not a disposable fixture or owner-only local testnet rehearsal")
    from rpc_isolation import validate as validate_rpc_policy
    credential=validate_rpc_policy(root,config)
    shift=offset(config)
    for i in [0,1]:
        if credential: RPC_CREDENTIALS[port(i,shift)]=credential
        else: RPC_CREDENTIALS.pop(port(i,shift),None)
    return config


def offset(config):
    value=config.get("local_port_offset",0)
    if type(value) is not int or value not in (0,5000):
        raise ValueError("unsupported local port layout")
    return value


def port(index, shift=0):
    return 18899 + index * 1000 + shift


def ledger(root, index):
    active = root / f"active-ledger-{index}.json"
    name = json.loads(active.read_text()) if active.exists() else f"ledger-{index}"
    path = root / name
    if path.parent != root or not path.is_dir():
        raise RuntimeError("invalid local ledger path")
    return path


def wait_rpc(root, index, timeout=120):
    config = load(root)
    shift=offset(config)
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if rpc(port(index,shift), "getGenesisHash") != config["genesis_hash"]:
                raise RuntimeError("loopback port belongs to another network")
            actual = rpc(port(index,shift), "getIdentity")["identity"]
            if actual != config["identities"][index]:
                raise RuntimeError("unexpected validator identity")
            return rpc(port(index,shift), "getSlot", [{"commitment": "confirmed"}])
        except (OSError, ValueError, RuntimeError) as error:
            last = error
            time.sleep(0.3)
    raise RuntimeError(f"validator {index} did not become ready: {last}; inspect its local log")


def restart_state(root, index):
    config = load(root)
    result = subprocess.run([str(LAB), "restart-state", str(root), str(index), ledger(root, index).name],
                            check=True, capture_output=True, text=True, timeout=30)
    state = json.loads(result.stdout)
    if state["genesis_hash"] != config["genesis_hash"] or state["identity"] != config["identities"][index]:
        raise RuntimeError("restart checkpoint identity/genesis mismatch")
    # Upstream treats wait_slot == restored root as a hard fork and relaxes
    # tower restoration. This helper never authorizes that branch.
    archives = newer_full_snapshot(ledger(root, index), -1)
    bank_snapshots = ledger(root, index) / "snapshots"
    snapshot_slots = [int(p.name) for p in bank_snapshots.iterdir() if p.is_dir() and p.name.isdigit()] if bank_snapshots.exists() else []
    if archives:
        snapshot_slots.append(archives[0])
    if any(slot >= state["slot"] for slot in snapshot_slots):
        raise RuntimeError("snapshot root reaches restart checkpoint; refusing tower-discard hard-fork path")
    return state


def start(root, index, archive=False, coordinated=False, faults=False, new_session=True, epoch_horizon=None):
    config = load(root)
    shift=offset(config)
    private = config.get("key_mode") == "local-testnet-rehearsal-v1"
    if private and faults:
        raise RuntimeError("fault fixtures require disposable keys")
    if private:
        for role in ["identity", "voter"]:
            key_path = root / f"{role}-{index}.keypair.json"
            with os.fdopen(os.open(key_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as key:
                metadata = os.fstat(key.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077 or metadata.st_size > 4096:
                    raise RuntimeError("rehearsal validator hot keys must be bounded owner-only regular files")
    if config.get("pool_format") != "NPOOL003":
        raise RuntimeError("incompatible development pool format; preserve this network and initialize a fresh --root")
    if not config.get("raw_rpc_host_isolation"):
        with socket.socket() as probe:
            # Ignore completed connections in TIME_WAIT, reject live listeners.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind(("127.0.0.1", port(index,shift)))
    path = ledger(root, index)
    if len(os.fsencode(path / "admin.rpc")) >= 104:
        raise RuntimeError("ledger path exceeds the portable local admin socket limit")
    tower = root / f"consensus-{index}"
    tower.mkdir(mode=0o700, exist_ok=True)
    has_tower = bool(list(tower.glob("tower-*.bin")))
    launched = root / f"validator-{index}.started"
    if not has_tower and ((root / f"validator-{index}.pid").exists() or launched.exists()):
        raise RuntimeError("previously launched identity has no saved tower; refusing bootstrap leadership")
    if not has_tower:
        if list(path.glob("snapshot-*.tar.zst")) or (path / "snapshots").exists():
            raise RuntimeError("snapshot ledger requires a saved tower")
        subprocess.run([str(LAB), "bootstrap-check", str(root), path.name], check=True, capture_output=True, timeout=30)
    checkpoint = restart_state(root, index) if coordinated and has_tower else None
    if epoch_horizon is not None:
        if (not checkpoint or type(epoch_horizon) is not dict or set(epoch_horizon)!={'slot','bank_hash','genesis_hash'}
            or checkpoint.get('genesis_hash')!=epoch_horizon['genesis_hash']
            or checkpoint.get('restart_ancestors',{}).get(str(epoch_horizon['slot']),{}).get('bank_hash')!=epoch_horizon['bank_hash']):
            raise RuntimeError('native epoch horizon requires the same peer-corroborated frozen checkpoint')
    args = [str(VALIDATOR), "--ledger", str(path),
        "--native-durable-votes",
        "--identity", str(root / f"identity-{index}.keypair.json"),
        "--tower", str(tower),
        "--vote-account", config["vote_accounts"][index] if private else str(root / f"vote-{index}.keypair.json"),
        "--authorized-voter", str(root / f"{'voter' if private else 'vote'}-{index}.keypair.json"),
        "--expected-genesis-hash", config["genesis_hash"],
        "--bind-address", "127.0.0.1", "--gossip-host", "127.0.0.1",
        "--gossip-port", str(18000 + index * 1000 + shift),
        "--dynamic-port-range", f"{18100 + index * 1000 + shift}-{18200 + index * 1000 + shift}",
        "--rpc-bind-address", "127.0.0.1", "--rpc-port", str(port(index,shift)),
        "--private-rpc", "--full-rpc-api", "--enable-rpc-transaction-history", "--allow-private-addr",
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
    if config.get("raw_rpc_isolation") is True:
        args += ["--native-rpc-access-file",str(root/"rpc-access.key")]
    if has_tower:
        args += ["--require-tower"]
    elif index == 0:
        args += ["--no-wait-for-vote-to-start-leader"]
    if index:
        args += ["--entrypoint", f"127.0.0.1:{18000+shift}"]
    if checkpoint:
        args += ["--wait-for-supermajority", str(checkpoint["slot"]),
                 "--native-restart-checkpoint",
                 "--expected-bank-hash", checkpoint["bank_hash"],
                 "--expected-shred-version", str(checkpoint["shred_version"])]
        if epoch_horizon is not None:args += ['--native-restart-epoch-horizon','--native-restart-epoch-anchor-slot',str(epoch_horizon['slot']),
            '--native-restart-epoch-anchor-hash',epoch_horizon['bank_hash']]
        if not index:
            args += ["--entrypoint", f"127.0.0.1:{19000+shift}"]
        # Retain the signed inputs for review. Never copy, delete or reset a tower.
        checkpoint["tower_files"] = {p.name: digest(p) for p in tower.glob("tower-*.bin")}
        (root / f"restart-checkpoint-{index}.json").write_text(json.dumps(checkpoint, indent=2))
    if archive:
        args += ["--use-snapshot-archives-at-startup", "always"]
    env = dict(os.environ, SOLANA_METRICS_CONFIG="", RUST_LOG=LOG_FILTER + ",solana_core::validator=info")
    # Never inherit fault injection into an ordinary validator launch.
    env.pop("NATIVE_LOCAL_SHRED_FAULT", None)
    if faults:
        env["NATIVE_LOCAL_SHRED_FAULT"] = str(root / f"fault-{index}.json")
        args += ["--tpu-enable-udp"]
    launched.touch(mode=0o600, exist_ok=True)
    with (root / f"validator-{index}.console.log").open("ab") as output:
        process = subprocess.Popen(args, cwd=PROJECT, env=env, stdout=output, stderr=subprocess.STDOUT, start_new_session=new_session)
    process.restart_tip = checkpoint['highest_stored_slot'] if checkpoint else None
    (root / f"validator-{index}.pid").write_text(str(process.pid))
    (root / f"validator-{index}.command.json").write_text(json.dumps(args, indent=2))
    transport=f"private Unix socket rpc-{port(index,shift)}.sock" if config.get("raw_rpc_host_isolation") else f"http://127.0.0.1:{port(index,shift)}"
    print(f"Started local validator {index}; PID {process.pid}, RPC {transport}", flush=True)
    return process


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


def wait_finalized_progress(root, indices, checkpoint, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        slots = [rpc(port(index), "getSlot", [{"commitment": "finalized"}]) for index in indices]
        if min(slots) > checkpoint + 8 and max(slots) - min(slots) <= 12:
            print(f"New finalized slots after coordinated restart: {slots}", flush=True)
            return slots
        time.sleep(0.5)
    raise RuntimeError("coordinated startup has not resumed finalization; preserve ledgers/towers and inspect logs")


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
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def prepare_snapshot_recovery(root, name, shutdown_tip):
    """Copy a newer full archive to a genesis-only ledger before selecting it."""
    load(root)
    if len(os.fsencode(root / name / "admin.rpc")) >= 104:
        raise RuntimeError("recovered ledger path exceeds the portable local admin socket limit")
    selected = newer_full_snapshot(ledger(root, 0), shutdown_tip)
    if selected is None:
        raise RuntimeError("no full snapshot beyond the shutdown tip")
    slot, archive = selected
    checksum = digest(archive)
    subprocess.run([str(LAB), "prepare-recovery", str(root), name], check=True, capture_output=True, timeout=30)
    destination = root / name / archive.name
    shutil.copy2(archive, destination)
    if digest(destination) != checksum:
        raise RuntimeError("snapshot copy digest mismatch; active ledger unchanged")
    return {"archive": archive.name, "archive_slot": slot, "archive_sha256": checksum,
            "fresh_ledger": name, "shutdown_slot_barrier": shutdown_tip}


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
    snapshot = prepare_snapshot_recovery(root, recovery_name, snapshot_barrier)
    archive_slot, archive_digest = snapshot["archive_slot"], snapshot["archive_sha256"]
    archive = Path(snapshot["archive"])
    (root / "snapshot-input.json").write_text(json.dumps(snapshot, indent=2))
    (root / "active-ledger-1.json").write_text(json.dumps(recovery_name))
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
    parser.add_argument("command", choices=["init", "start", "coordinated-start", "stop", "status", "verify", "quiet"])
    parser.add_argument("--root", type=Path, default=PROJECT / ".data/localnet")
    parser.add_argument("--validator", type=int, choices=[0, 1], help="start or stop only this validator")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data"):
        raise RuntimeError("local networks must stay inside this project's ignored .data directory")
    if args.command == "init":
        subprocess.run([str(LAB), "init", str(root)], check=True)
    elif args.command in ["start", "coordinated-start"]:
        indices = [args.validator] if args.validator is not None else [0, 1]
        for index in indices:
            # Only the majority identity uses the explicit checkpoint gate when
            # bringing up the whole fixture; the minority catches up normally.
            start(root, index, coordinated=args.command == "coordinated-start" and (args.validator is not None or index == 0))
            wait_rpc(root, index)
        if args.command == "coordinated-start":
            checkpoint = json.loads((root / f"restart-checkpoint-{indices[0]}.json").read_text())["highest_stored_slot"]
            wait_finalized_progress(root, indices, checkpoint)
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
