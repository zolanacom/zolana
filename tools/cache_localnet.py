#!/usr/bin/env python3
"""Bounded incremental-scan acceptance on owned, disposable loopback validators."""
import argparse
import json
from pathlib import Path
import secrets
import subprocess
import time

from fault_localnet import Experiment, atomic_json, durable
from localnet import LAB, PROJECT, load, port, quiet, rpc, start, stop, wait_rpc
from wallet_localnet import private_new


class CacheExperiment(Experiment):
    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "cache-result.json", self.result)
        print(kind, flush=True)

    def balance(self, who, expected, *, index=0, restored=False, cached=None, proofs=None):
        before = time.monotonic()
        result = self.wallet("balance", who, index=index, restored=restored)
        elapsed = round(time.monotonic() - before, 3)
        if result["balance"] != expected or not result["sync"]["cache_saved"]:
            raise RuntimeError("incorrect balance or unsuccessful checkpoint save")
        if cached is not None and result["sync"]["cache_used"] != cached:
            raise RuntimeError("unexpected checkpoint reuse")
        if proofs is not None and result["sync"]["payments_verified"] != proofs:
            raise RuntimeError("unexpected number of verified proofs")
        self.event("balance", who=who, index=index, restored=restored, seconds=elapsed, result=result)
        return result

    def run(self):
        root = self.root
        subprocess.run([str(LAB), "init", str(root)], check=True, capture_output=True)
        self.result["genesis_hash"] = load(root)["genesis_hash"]
        for index in [0, 1]:
            self.children[index] = start(root, index)
            wait_rpc(root, index)
        quiet(root)
        (root / "wallets").mkdir(mode=0o700)
        private_new(root / "wallets/unlock.password", secrets.token_bytes(48))
        addresses = {
            who: self.wallet("init", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")])["address"]
            for who in ["alice", "bob"]
        }
        self.pay("deposit", "alice", 100)
        self.pay("send", "alice", 17, addresses["bob"])
        paths = {who: root / "wallets" / f"{who}.wallet.json.scan-cache" for who in addresses}
        # These disposable caches contain no unique recovery material.
        paths["alice"].unlink()
        for who, expected in [("alice", 83), ("bob", 17)]:
            self.balance(who, expected, cached=False, proofs=2)
            self.balance(who, expected, cached=True, proofs=0)
        receipt = self.pay("send", "bob", 5, addresses["alice"])
        for index in [0, 1]:
            for who, expected in [("alice", 88), ("bob", 12)]:
                self.balance(who, expected, index=index, cached=True, proofs=1 if index == 0 else 0)
        expected_state = durable(root, 0)
        if len(expected_state) != 7 or expected_state != durable(root, 1):
            raise RuntimeError("pool and six permanent nullifiers did not agree")
        self.event("cached_witness_spent", exact_pool_and_six_nullifiers=True)

        damaged = bytearray(paths["alice"].read_bytes())
        damaged[-1] ^= 1
        paths["alice"].write_bytes(damaged)
        reset = self.balance("alice", 88, cached=False, proofs=3)
        if reset["sync"]["cache_reset"] != "invalid_cache":
            raise RuntimeError("corrupt cache was not rejected")
        paths["bob"].write_bytes(paths["alice"].read_bytes())
        self.balance("bob", 12, cached=False, proofs=3)
        self.wallet("restore", "bob", ["--backup", str(root / "wallets/bob.seed-backup.json")], restored=True)
        self.balance("bob", 12, restored=True, cached=False, proofs=3)
        self.event("corruption_wrong_wallet_and_seed_only_recovery")

        tip = max(rpc(port(i), "getSlot", [{"commitment": "processed"}]) for i in [0, 1])
        for index in [1, 0]:
            stop(root, index)
        for index in [0, 1]:
            self.children[index] = start(root, index, coordinated=True)
            wait_rpc(root, index)
        roots = self.converge(tip, expected_state, timeout=180)
        for index in [0, 1]:
            self.balance("alice", 88, index=index, cached=True, proofs=0)
            self.balance("bob", 12, index=index, cached=True, proofs=0)
        self.event("coordinated_restart", tip=tip, finalized_slots=roots, exact_pool_and_nullifiers=True)

        # A cache cannot bypass the durable unknown-finalization guard. Use the
        # real accepted transaction identity as a lost-response recovery case.
        config = load(root)
        pending = root / "wallets/bob.wallet.json.pending.json"
        private_new(pending, json.dumps({
            "network": {"network": config["network"], "genesis_hash": config["genesis_hash"]},
            "signature": receipt["signature"], "staging_account": receipt["staging_account"],
            "last_valid_block_height": 0,
        }).encode())
        blocked = subprocess.run(self.wallet_args("deposit", "bob", ["--sponsor", str(root / "sponsor.keypair.json"), "--amount", "1"]), capture_output=True, text=True, timeout=30)
        if blocked.returncode == 0 or "unresolved payment" not in blocked.stderr:
            raise RuntimeError("cache bypassed pending-payment protection")
        resolved = self.wallet("resolve", "bob")
        if not resolved["accepted"] or not resolved["pending_cleared"] or pending.exists():
            raise RuntimeError("uncached accepted-payment recovery failed")
        self.event("pending_guard_and_uncached_resolution", result=resolved)
        self.result["status"] = "passed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data") or root.exists():
        parser.error("use a new directory under .data")
    trial = CacheExperiment(root)
    try:
        trial.run()
    except Exception as error:
        trial.result.update(status="failed", error=str(error))
        raise
    finally:
        errors = []
        for index in [1, 0]:
            child = trial.children[index]
            if child is not None and child.poll() is None:
                try:
                    stop(root, index)
                except Exception as error:
                    errors.append(str(error))
        if errors:
            trial.result.update(status="failed", cleanup_errors=errors)
        if root.exists():
            atomic_json(root / "cache-result.json", trial.result)
        if errors:
            raise RuntimeError("owned validator cleanup failed; inspect cache-result.json")


if __name__ == "__main__":
    main()
