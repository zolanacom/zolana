#!/usr/bin/env python3
"""Adverse restart acceptance for an existing disposable wallet fixture. Local only."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from unittest.mock import patch

from localnet import PROJECT, LAB, load, port, quiet, restart_state, rpc, start, stop, wait_rpc


def program_accounts(root, index):
    config = load(root)
    return {entry["pubkey"]: entry["account"] for entry in rpc(port(index), "getProgramAccounts", [
        config["program"], {"encoding": "base64", "commitment": "finalized"}])}


def progress(root, after, timeout=100, epoch=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        slots = [rpc(port(i), "getSlot", [{"commitment": "finalized"}]) for i in [0, 1]]
        if min(slots) > after + 8 and abs(slots[0] - slots[1]) <= 12:
            if epoch is None or min(s // 128 for s in slots) > epoch:
                if program_accounts(root, 0) == program_accounts(root, 1):
                    return slots
        time.sleep(0.5)
    raise RuntimeError("restart did not produce new finalized, converged state")


def preserved(before, after):
    for field in ["frozen_hashes", "shred_digests"]:
        for key, value in before[field].items():
            if after[field].get(key) != value:
                raise RuntimeError(f"restart altered or lost retained {field}: {key}")


def b58decode(value):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number = 0
    for char in value:
        number = number * 58 + alphabet.index(char)
    return b"\0" * (len(value) - len(value.lstrip("1"))) + number.to_bytes((number.bit_length() + 7) // 8, "big")


def capture_public_payment(root, receipt):
    """Recover already-public staging bytes from successful archive transactions."""
    config = load(root)
    buffer = receipt["staging_account"]
    signatures = rpc(port(0), "getSignaturesForAddress", [buffer, {"commitment": "finalized"}])
    payload, length = bytearray(), None
    accepted = False
    for item in reversed(signatures):
        if item["err"] is not None:
            continue
        result = rpc(port(0), "getTransaction", [item["signature"], {"encoding": "json", "commitment": "finalized", "maxSupportedTransactionVersion": 0}])
        message = result["transaction"]["message"]
        keys = message["accountKeys"]
        for ix in message["instructions"]:
            if keys[ix["programIdIndex"]] != config["program"]:
                continue
            data = b58decode(ix["data"])
            if data[0] == 0 and keys[ix["accounts"][0]] == buffer:
                length = int.from_bytes(data[1:5], "little")
            if data[0] == 1 and keys[ix["accounts"][0]] == buffer:
                if int.from_bytes(data[1:5], "little") != len(payload):
                    raise RuntimeError("staging archive is incomplete")
                payload.extend(data[5:])
            if data == b"\x03" and keys[ix["accounts"][1]] == buffer and item["signature"] == receipt["signature"]:
                accepted = True
    if not accepted or len(payload) != length:
        raise RuntimeError("cannot reconstruct the accepted payment for replay testing")
    (root / "restart-spent-payment.bin").write_bytes(payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--resume-evidence", help="resume a journaled submitted send without sending twice")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data"):
        raise RuntimeError("fixture must be inside ignored .data")
    result_file = root / "coordinated-restart-result.json"
    if result_file.exists():
        raise RuntimeError("acceptance already completed; preserve its receipt")
    config = load(root)
    if args.resume_evidence:
        evidence = root / args.resume_evidence
        if evidence.parent != root or not evidence.name.startswith("restart-evidence-") or not evidence.is_dir():
            raise RuntimeError("invalid resume evidence directory")
        for i in [0, 1]:
            wait_rpc(root, i)
        baseline = json.loads((evidence / "program-accounts.json").read_text())
    else:
        evidence = root / f"restart-evidence-{time.time_ns()}"
        evidence.mkdir(mode=0o700)
        for i in [0, 1]:
            wait_rpc(root, i)
            shutil.copy2(root / f"validator-{i}.log", evidence / f"before-validator-{i}.log")
            shutil.copytree(root / f"consensus-{i}", evidence / f"consensus-{i}")
        baseline = program_accounts(root, 0)
        if baseline != program_accounts(root, 1):
            raise RuntimeError("initial program state differs")
        (evidence / "program-accounts.json").write_text(json.dumps(baseline))
    before_slot = min(rpc(port(i), "getSlot", [{"commitment": "finalized"}]) for i in [0, 1])
    checks, cycles, receipts = [], [], []

    def wallet(action, who, extra=()):
        command = [str(PROJECT / "target/debug/native-wallet"), "withdraw-legacy" if action == "withdraw" else action,
                   "--network", str(root / "network.json"),
                   "--wallet", str(root / "wallets" / f"{who}-restored.wallet.json"),
                   "--password-file", str(root / "wallets/unlock.password"),
                   "--rpc", f"http://127.0.0.1:{port(0)}"] + list(extra)
        result = subprocess.run(command, text=True, capture_output=True, timeout=180,
                                env=dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost"))
        if result.returncode:
            raise RuntimeError(f"wallet {action} failed: {result.stderr}")
        return json.loads(result.stdout)

    def balances(a, b):
        for who, expected in [("alice", a), ("bob", b)]:
            if wallet("balance", who)["balance"] != expected:
                raise RuntimeError(f"restored {who} balance differs")

    def closed(receipt):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if all(rpc(port(i), "getAccountInfo", [receipt["staging_account"], {"encoding": "base64", "commitment": "finalized"}])["value"] is None for i in [0, 1]):
                return
            time.sleep(0.5)
        raise RuntimeError("staging rent cleanup did not finalize on both peers")

    def payment(action, who, amount, to=None):
        extra = ["--sponsor", str(root / "sponsor.keypair.json"), "--amount", str(amount)]
        if to:
            extra += ["--to", to]
        receipt = wallet(action, who, extra)
        if not receipt["staging_rent_reclaimed"]:
            raise RuntimeError("payment staging rent not reclaimed")
        receipts.append(receipt)
        (evidence / "payment-receipts.json").write_text(json.dumps(receipts))
        # Wallet reports confirmed rent cleanup separately from finalized
        # payment acceptance. Compare persistent state only after close roots.
        closed(receipt)
        print(f"Finalized post-restart {action} by {who}", flush=True)
        return receipt

    if args.resume_evidence:
        initial = json.loads((evidence / "initial-balances.json").read_text())
        initial_a, initial_b = initial["alice"], initial["bob"]
    else:
        initial_a = wallet("balance", "alice")["balance"]
        initial_b = wallet("balance", "bob")["balance"]
    initial_data = base64.b64decode(baseline[config["pool"]]["data"][0])
    initial_count = int.from_bytes(initial_data[56:64], "little")
    initial_backing = int.from_bytes(initial_data[48:56], "little")
    if initial_a < 1 or initial_b < 1 or initial_a + initial_b != initial_backing or len(baseline) != initial_count + 1:
        raise RuntimeError("fixture must have two funded wallets, exact native backing and no open staging accounts")
    (evidence / "initial-balances.json").write_text(json.dumps({"alice": initial_a, "bob": initial_b, "commitments": initial_count, "backing": initial_backing}))
    if args.resume_evidence:
        journal = json.loads((evidence / "before-send-journal.json").read_text())
        checks, cycles = journal["checks"], journal["cycles"]
        receipts = json.loads((evidence / "payment-receipts.json").read_text())
        if len(receipts) != 1:
            raise RuntimeError("resume requires exactly one journaled send; do not repeat payments")
        receipt = receipts[0]
        closed(receipt)
        states = [json.loads((evidence / f"initial-checkpoint-{i}.json").read_text()) for i in [0, 1]]
        checks.append("resumed_submitted_send_without_duplicate_payment")
    else:
        stop(root, 1)
        stop(root, 0)
        stopped_at = time.monotonic()
        states = [restart_state(root, i) for i in [0, 1]]
        for i, state in enumerate(states):
            (evidence / f"initial-checkpoint-{i}.json").write_text(json.dumps(state))

        # Exercise missing/corrupt towers before any validator can sign.
        tower_files = list((root / "consensus-0").glob("tower-*.bin"))
        moved = [(p, p.with_suffix(".saved")) for p in tower_files]
        try:
            for src, dst in moved:
                src.rename(dst)
            try:
                start(root, 0)
                raise AssertionError("missing tower accepted")
            except RuntimeError as error:
                if "no saved tower" not in str(error):
                    raise
        finally:
            for src, dst in moved:
                if dst.exists():
                    dst.rename(src)
        checks.append("missing_tower_rejected_before_launch")
        tower = next(p for p in tower_files if p.name.startswith("tower-1_9-"))
        saved = tower.read_bytes()
        try:
            changed = bytearray(saved)
            changed[8] ^= 1  # Corrupt signed tower bytes, keeping its filename/identity.
            tower.write_bytes(changed)
            try:
                restart_state(root, 0)
                raise AssertionError("corrupt tower accepted")
            except subprocess.CalledProcessError:
                pass
        finally:
            tower.write_bytes(saved)
        if tower.read_bytes() != saved or restart_state(root, 0) != states[0]:
            raise RuntimeError("negative test did not restore the exact tower/ledger")
        checks.append("corrupt_signed_tower_rejected")

        def invalid_validator(field, value, expected):
            altered = dict(states[0], **{field: value})
            log = root / "validator-0.log"
            offset = log.stat().st_size
            console_path = root / "validator-0.console.log"
            console_offset = console_path.stat().st_size
            with patch("localnet.restart_state", return_value=altered):
                process = start(root, 0, coordinated=True)
            try:
                code = process.wait(timeout=50)
            except subprocess.TimeoutExpired:
                stop(root, 0)
                raise RuntimeError(f"invalid {field} did not stop startup")
            output = log.read_text()[offset:]
            console = console_path.read_text()[console_offset:]
            (evidence / f"rejected-{field}.log").write_text(output + console)
            if code == 0 or expected not in output + console or "Supermajority reached" in output:
                raise RuntimeError(f"invalid {field} did not fail closed")
            preserved(states[0], restart_state(root, 0))
            checks.append(f"wrong_{field}_rejected_by_validator")
            print(f"Rejected invalid restart {field}", flush=True)

        invalid_validator("bank_hash", "1" * 32, "bank hash mismatch")
        invalid_validator("shred_version", (states[0]["shred_version"] + 1) % 65536, "shred version mismatch")
        # Old saved gossip contacts must age out before testing absence of quorum.
        time.sleep(max(0, stopped_at + 17 - time.monotonic()))
        log = root / "validator-1.log"
        offset = log.stat().st_size
        start(root, 1, coordinated=True)
        wait_rpc(root, 1)
        until = time.monotonic() + 16
        while time.monotonic() < until:
            # RPC can appear before ledger replay finishes and update its root
            # during replay. It must never advance beyond the stored checkpoint.
            if rpc(port(1), "getSlot", [{"commitment": "processed"}]) > states[1]["slot"]:
                raise RuntimeError("20% minority produced blocks without quorum")
            time.sleep(0.5)
        output = log.read_text()[offset:]
        if "Waiting for 80%" not in output or "Supermajority reached" in output:
            raise RuntimeError("minority did not remain behind stake gate")
        checks.append("minority_without_quorum_stays_parked")
        start(root, 0, coordinated=True)
        wait_rpc(root, 0)
        slots = progress(root, max(before_slot, states[0]["highest_stored_slot"], states[1]["highest_stored_slot"]))
        if program_accounts(root, 0) != baseline:
            raise RuntimeError("restart changed existing native payment accounts")
        balances(initial_a, initial_b)
        cycles.append({"kind": "whole_cluster_after_negative_tests", "slots": slots})
        print(f"Whole cluster resumed finalization: {slots}", flush=True)

        # Restart the 80% identity while the minority remains online.
        before = min(slots)
        stop(root, 0)
        current = restart_state(root, 0)
        preserved(states[0], current)
        states[0] = current
        (evidence / "majority-checkpoint-0.json").write_text(json.dumps(current))
        start(root, 0, coordinated=True)
        wait_rpc(root, 0)
        slots = progress(root, max(before, current["highest_stored_slot"]))
        cycles.append({"kind": "majority_only", "checkpoint": current["slot"], "highest_stored": current["highest_stored_slot"], "slots": slots})
        if program_accounts(root, 0) != baseline:
            raise RuntimeError("majority restart changed native accounts")
        balances(initial_a, initial_b)
        bob = wallet("address", "bob")["address"]
        (evidence / "before-send-journal.json").write_text(json.dumps({"checks": checks, "cycles": cycles}))
        receipt = payment("send", "alice", 1, bob)
    balances(initial_a - 1, initial_b + 1)
    capture_public_payment(root, receipt)
    after_payment = program_accounts(root, 0)
    (evidence / "after-send-accounts.json").write_text(json.dumps(after_payment))
    checks.append("fresh_private_send_after_majority_restart")

    # Whole cluster downtime across an epoch, retaining every signed shred.
    before = min(rpc(port(i), "getSlot", [{"commitment": "finalized"}]) for i in [0, 1])
    stop(root, 1)
    stop(root, 0)
    for i in [0, 1]:
        current = restart_state(root, i)
        preserved(states[i], current)
        states[i] = current
    time.sleep(5)
    start(root, 0, coordinated=True)
    wait_rpc(root, 0)
    start(root, 1)
    wait_rpc(root, 1)
    slots = progress(root, max(s["highest_stored_slot"] for s in states), timeout=150, epoch=before // 128)
    if program_accounts(root, 0) != after_payment:
        raise RuntimeError("whole-cluster restart lost a finalized payment or nullifier")
    balances(initial_a - 1, initial_b + 1)
    subprocess.run([str(LAB), "replay-check", str(root), f"http://127.0.0.1:{port(0)}", f"http://127.0.0.1:{port(1)}"], check=True, timeout=90)
    cycles.append({"kind": "whole_cluster_epoch_boundary", "before_finalized": before, "slots": slots})
    checks += ["epoch_boundary_finalization", "live_spent_proof_rejected_after_restart", "existing_nullifiers_and_backing_preserved"]
    payment("deposit", "alice", 3)
    balances(initial_a + 2, initial_b + 1)
    payment("withdraw", "bob", 2)
    balances(initial_a + 2, initial_b - 1)
    final_slots = progress(root, min(slots))
    # Final offline audit, then leave the same two validators running.
    stop(root, 1)
    stop(root, 0)
    final_barrier = max(final_slots)
    for i in [0, 1]:
        current = restart_state(root, i)
        preserved(states[i], current)
        final_barrier = max(final_barrier, current["highest_stored_slot"])
        (evidence / f"final-checkpoint-{i}.json").write_text(json.dumps(current))
    start(root, 0, coordinated=True)
    wait_rpc(root, 0)
    start(root, 1)
    wait_rpc(root, 1)
    final_slots = progress(root, final_barrier)
    balances(initial_a + 2, initial_b - 1)
    accounts = program_accounts(root, 0)
    pool = accounts[config["pool"]]
    data = base64.b64decode(pool["data"][0])
    backing, count = (int.from_bytes(data[a:a + 8], "little") for a in [48, 56])
    floor = int.from_bytes(data[40:48], "little")
    if backing != initial_backing + 1 or count != initial_count + 6 or pool["lamports"] != floor + backing or len(accounts) != count + 1:
        raise RuntimeError("final pool backing, commitments, permanent markers or staging cleanup differs")
    checks += ["deposit_and_withdraw_after_restart", "seed_restored_wallet_balances_exact", "staging_rent_close_finalized_on_both_peers", "all_retained_frozen_hashes_and_shreds_unchanged", "final_restart_forward_progress"]
    if any("Hard fork is detected; discarding tower" in (root / f"validator-{i}.log").read_text() for i in [0, 1]):
        raise RuntimeError("a restart discarded saved tower restoration")
    checks.append("no_tower_discard_hard_fork_path")
    quiet(root)
    result = {"genesis_hash": config["genesis_hash"], "cycles": cycles, "checks": checks,
              "final_slots": final_slots, "backing": backing, "commitments": count,
              "initial_balances": [initial_a, initial_b], "initial_commitments": initial_count,
              "alice_balance": initial_a + 2, "bob_balance": initial_b - 1, "permanent_markers": len(accounts) - 1,
              "receipts": receipts, "evidence": evidence.name}
    result_file.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
