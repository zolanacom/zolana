#!/usr/bin/env python3
"""Exercise random-key wallets and seed recovery on disposable loopback validators."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time

from localnet import PROJECT, LAB, ledger, load, rpc, start, stop, wait_rpc, quiet, newer_full_snapshot, digest

WALLET = PROJECT / "target/debug/native-wallet"


def private_new(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as stream:
        stream.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=PROJECT / ".data/wallet-net")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data") or root.exists():
        raise RuntimeError("choose a new directory under the project's ignored .data folder")
    if not WALLET.is_file():
        raise RuntimeError("build native-wallet first")
    subprocess.run([str(LAB), "init", str(root)], check=True)
    for index in [0, 1]:
        start(root, index)
        wait_rpc(root, index)
    quiet(root)
    directory = root / "wallets"
    directory.mkdir(mode=0o700)
    password = directory / "unlock.password"
    wrong_password = directory / "wrong.password"
    private_new(password, secrets.token_bytes(48))
    private_new(wrong_password, secrets.token_bytes(48))
    env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")

    def command(action, who, extra=(), index=0, restored=False, expect=None, password_path=password):
        file = directory / f"{who}{'-restored' if restored else ''}.wallet.json"
        params = [str(WALLET), "withdraw-legacy" if action == "withdraw" else action, "--network", str(root / "network.json"),
                  "--wallet", str(file), "--password-file", str(password_path),
                  "--rpc", f"http://127.0.0.1:{18899 + index * 1000}"]
        if action in ["init", "restore"]:
            params += ["--backup", str(directory / f"{who}.seed-backup.json")]
        result = subprocess.run(params + list(extra), text=True, capture_output=True, env=env, timeout=180)
        if expect is not None:
            if result.returncode == 0 or expect not in result.stderr:
                raise RuntimeError(f"expected {expect!r} rejection; exit={result.returncode}, error={result.stderr}")
            return None
        if result.returncode:
            raise RuntimeError(f"wallet {action} failed: {result.stderr}")
        return json.loads(result.stdout)

    alice = command("init", "alice")["address"]
    bob = command("init", "bob")["address"]
    if alice == bob:
        raise RuntimeError("independent random wallets have the same address")
    command("balance", "alice", password_path=wrong_password, expect="password is incorrect")
    sponsor = ["--sponsor", str(root / "sponsor.keypair.json")]
    receipts = []

    def pay(action, who, amount, recipient=None, restored=False):
        extra = sponsor + ["--amount", str(amount)]
        if recipient:
            extra += ["--to", recipient]
        receipt = command(action, who, extra, restored=restored)
        if not receipt["staging_rent_reclaimed"]:
            raise RuntimeError("successful payment did not reclaim staging rent")
        receipts.append(receipt)
        print(f"Confirmed wallet {action} by {who}", flush=True)

    def balances(a, b, index=0, restored=False):
        for who, expected in [("alice", a), ("bob", b)]:
            actual = command("balance", who, index=index, restored=restored)
            if actual["balance"] != expected:
                raise RuntimeError(f"{who} balance differs: {actual['balance']} != {expected}")

    balances(0, 0)
    pay("deposit", "alice", 100)
    balances(100, 0)
    pay("send", "alice", 40, bob)
    balances(60, 40)
    pay("withdraw", "bob", 15)
    balances(60, 25)
    pay("send", "bob", 10, alice)
    balances(70, 15)
    # Alice now needs both her 60-unit change and the new 10-unit receipt.
    pay("withdraw", "alice", 65)
    balances(5, 15)
    balances(5, 15, index=1)

    # Resolve a durable accepted intent as if the client lost its final response.
    # No private data or invented signature is used: this is the actual last tx.
    import base64
    raw = rpc(18899, "getLatestBlockhash", [{"commitment": "confirmed"}])["value"]
    pending = directory / "alice.wallet.json.pending.json"
    config = load(root)
    private_new(pending, json.dumps({"network": {"network": config["network"], "genesis_hash": config["genesis_hash"]},
                 "signature": receipts[-1]["signature"], "staging_account": receipts[-1]["staging_account"],
                 "last_valid_block_height": raw["lastValidBlockHeight"]}).encode())
    command("deposit", "alice", sponsor + ["--amount", "1"], expect="unresolved payment")
    resolved = command("resolve", "alice")
    if not resolved["accepted"] or not resolved["pending_cleared"] or pending.exists():
        raise RuntimeError("accepted pending payment was not resolved safely")
    unknown = {"network": {"network": config["network"], "genesis_hash": config["genesis_hash"]},
               "signature": "1" * 64, "staging_account": receipts[-1]["staging_account"],
               "last_valid_block_height": raw["lastValidBlockHeight"] + 1000}
    private_new(pending, json.dumps(unknown).encode())
    command("resolve", "alice", expect="still pending")
    if not pending.exists():
        raise RuntimeError("live unknown pending transaction was cleared")
    # The synthetic identity above was never broadcast. Move only this test
    # record's declared expiry behind the authenticated finalized checkpoint.
    unknown["last_valid_block_height"] = 0
    pending.write_text(json.dumps(unknown))
    expired = command("resolve", "alice")
    if expired["accepted"] or not expired["expired_without_execution"] or pending.exists():
        raise RuntimeError("expired non-executed pending transaction was not resolved")
    balances(5, 15)

    for who, expected_address in [("alice", alice), ("bob", bob)]:
        restored = command("restore", who, restored=True)
        if restored["address"] != expected_address:
            raise RuntimeError("seed-only restore changed the address")
    balances(5, 15, restored=True)

    # Keep >2/3 stake live. Restoring old state alone is not evidence that the
    # restarted process has rejoined a progressing, finalizing cluster.
    before_restart = rpc(18899, "getSlot", [{"commitment": "finalized"}])
    stop(root, 1)
    start(root, 1)
    wait_rpc(root, 1)
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        tip = rpc(18899, "getSlot", [{"commitment": "finalized"}])
        peer_tip = rpc(19899, "getSlot", [{"commitment": "finalized"}])
        if tip > before_restart + 8 and peer_tip + 12 >= tip:
            break
        time.sleep(0.3)
    else:
        raise RuntimeError("validator restart did not regain finalized forward progress")
    balances(5, 15, index=1, restored=True)
    print("Restored wallets retained balances after minority restart and fresh finalization", flush=True)

    # A compact validator snapshot contains state, but not pruned note ciphertext
    # history. The wallet must refuse an incomplete balance on that endpoint.
    stop(root, 1)
    barrier = rpc(18899, "getSlot", [{"commitment": "processed"}])
    deadline = time.monotonic() + 100
    selected = None
    while time.monotonic() < deadline:
        selected = newer_full_snapshot(ledger(root, 0), barrier)
        if selected:
            break
        time.sleep(0.5)
    if selected is None:
        raise RuntimeError("no fresh full snapshot for the history availability check")
    archive_slot, archive = selected
    subprocess.run([str(LAB), "prepare-recovery", str(root), "ledger-recovered-1"], check=True)
    destination = root / "ledger-recovered-1" / archive.name
    source_digest = digest(archive)
    shutil.copy2(archive, destination)
    if digest(destination) != source_digest:
        raise RuntimeError("snapshot digest differs after copy")
    (root / "active-ledger-1.json").write_text(json.dumps("ledger-recovered-1"))
    start(root, 1, archive=True)
    wait_rpc(root, 1)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        first = rpc(18899, "getAccountInfo", [config["pool"], {"encoding": "base64", "commitment": "finalized"}])["value"]
        second = rpc(19899, "getAccountInfo", [config["pool"], {"encoding": "base64", "commitment": "finalized"}])["value"]
        if first == second:
            break
        time.sleep(0.3)
    else:
        raise RuntimeError("snapshot peer did not recover the same native pool")
    command("balance", "alice", index=1, restored=True, expect="history")
    balances(5, 15, restored=True)
    quiet(root)
    data = base64.b64decode(first["data"][0])
    if int.from_bytes(data[48:56], "little") != 20 or int.from_bytes(data[56:64], "little") != 10:
        raise RuntimeError("wallet payments did not conserve backing or commitments")
    result = {"genesis_hash":config["genesis_hash"], "alice_balance":5,"bob_balance":15,
              "backing":20,"commitments":10,"payments":len(receipts), "archive_rpc":"http://127.0.0.1:18899",
              "snapshot_slot":archive_slot,"snapshot_sha256":source_digest,
              "restart_validator":1,"restart_before_finalized_slot":before_restart,"restart_after_finalized_slot":tip,
              "checks":["random_private_wallet_keys","wrong_password_rejected","deposit","private_send_and_change",
                        "withdrawal","two_note_spend","peer_note_discovery","pending_blocks_duplicate_deposit",
                        "accepted_pending_resolved","seed_only_restore","validator_restart",
                        "live_unknown_stays_pending","expired_nonexecuted_cleared",
                        "snapshot_state_equal","missing_archive_history_rejected"],"receipts":receipts}
    (root / "wallet-result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
