#!/usr/bin/env python3
"""Interrupt owned wallet processes and recover staging rent over local RPC."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import time

from fault_localnet import Experiment, account, atomic_json, durable
from localnet import PROJECT, LAB, load, port, quiet, rpc, start, wait_rpc
from wallet_localnet import private_new


class StagingExperiment(Experiment):
    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "staging-result.json", self.result)
        print(kind, flush=True)

    def launch(self, index, coordinated=False):
        self.children[index] = start(self.root, index, coordinated=coordinated)
        wait_rpc(self.root, index)

    def recovery_path(self, who):
        return self.root / "wallets" / f"{who}.wallet.json.staging.json"

    def sponsor(self, poor=False):
        return ["--sponsor", str(self.root / ("unfunded.keypair.json" if poor else "sponsor.keypair.json"))]

    def expect_error(self, action, who, expected, extra=()):
        result = subprocess.run(self.wallet_args(action, who, extra), capture_output=True, text=True, env=self.env, timeout=30)
        if result.returncode == 0 or expected not in result.stderr:
            raise RuntimeError(f"expected {expected!r}: exit={result.returncode}, error={result.stderr}")

    def spawn_payment(self, who, amount):
        child = subprocess.Popen(self.wallet_args("deposit", who, self.sponsor() + ["--amount", str(amount)]),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
        self.wallet_children.append(child)
        return child

    def kill_wallet(self, child):
        if child not in self.wallet_children or child.poll() is not None:
            raise RuntimeError("wallet crash target is not an owned live child")
        wait_rpc(self.root, 0, timeout=5)
        child.kill()
        stdout, stderr = child.communicate(timeout=15)
        if child.returncode != -9:
            raise RuntimeError("wallet interruption did not return SIGKILL")
        self.event("wallet_sigkill", pid=child.pid, exit_code=child.returncode, stdout=stdout, error=stderr)

    def upload_started(self, child, who):
        until = time.monotonic() + 180
        while time.monotonic() < until:
            if child.poll() is not None:
                raise RuntimeError("wallet ended before interrupted upload could be observed")
            try:
                record = json.loads(self.recovery_path(who).read_text())
                buffer = account(0, record["staging_account"], "processed")
                if buffer:
                    raw = base64.b64decode(buffer["data"][0])
                    received = int.from_bytes(raw[44:48], "little")
                    length = int.from_bytes(raw[40:44], "little")
                    if raw[88] == 0 and received < length:
                        return record
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            time.sleep(0.025)
        raise RuntimeError("no live partial upload observed")

    def reclaim_with_accounting(self, who, record):
        sponsor = record["sponsor"]
        buffer = account(0, record["staging_account"])
        if buffer is None:
            raise RuntimeError("rent accounting requires an existing finalized staging account")
        before = rpc(port(0), "getBalance", [sponsor, {"commitment": "finalized"}])["value"]
        receipt = self.wallet("reclaim", who, self.sponsor())
        self.closed(record["staging_account"])
        transaction = rpc(port(0), "getTransaction", [receipt["close_signature"], {"encoding": "json", "commitment": "finalized", "maxSupportedTransactionVersion": 0}])
        fee = transaction["meta"]["fee"]
        after = rpc(port(0), "getBalance", [sponsor, {"commitment": "finalized"}])["value"]
        if after - before != buffer["lamports"] - fee or self.recovery_path(who).exists():
            raise RuntimeError("staging rent refund or recovery journal clearing differs")
        self.event("staging_rent_reclaimed", who=who, rent=buffer["lamports"], fee=fee, sponsor_delta=after-before, receipt=receipt)

    def run(self):
        root = self.root
        subprocess.run([str(LAB), "init", str(root)], check=True, capture_output=True)
        self.result["genesis_hash"] = load(root)["genesis_hash"]
        for i in [0, 1]:
            self.launch(i)
        quiet(root)
        (root / "wallets").mkdir(mode=0o700)
        private_new(root / "wallets/unlock.password", secrets.token_bytes(48))
        addresses = {}
        for who in ["alice", "bob", "carol"]:
            addresses[who] = self.wallet("init", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")])["address"]
        self.pay("deposit", "alice", 20)
        baseline = durable(root, 0)
        child = self.spawn_payment("alice", 7)
        record = self.upload_started(child, "alice")
        self.expect_error("reclaim", "alice", "cannot lock wallet operation", self.sponsor())
        self.kill_wallet(child)
        raw = base64.b64decode(account(0, record["staging_account"], "processed")["data"][0])
        if raw[88] != 0 or int.from_bytes(raw[44:48], "little") >= record["payload_len"]:
            raise RuntimeError("wallet did not die during a partial upload")
        self.converge(max(self.slots("processed")), baseline)
        self.expect_error("deposit", "alice", "unfinished staging", self.sponsor() + ["--amount", "7"])
        self.expect_error("reclaim", "alice", "sponsor mismatch", self.sponsor(poor=True))
        self.reclaim_with_accounting("alice", record)
        if durable(root, 0) != baseline or durable(root, 1) != baseline:
            raise RuntimeError("partial upload recovery changed native payment state")
        self.result["checks"] += ["sigkill_during_partial_upload", "concurrent_reclaim_excluded", "new_payment_blocked_until_reclaim", "wrong_sponsor_cannot_reclaim", "partial_upload_refunds_rent_less_exact_fee", "partial_recovery_leaves_pool_and_nullifiers_unchanged"]
        self.pay("send", "alice", 5, addresses["bob"])

        # This real signed initialization fails preflight with an unfunded signer.
        # Its original lifetime is never edited to make recovery easier.
        self.expect_error("deposit", "carol", "staging remains recorded", self.sponsor(poor=True) + ["--amount", "1"])
        never_created = json.loads(self.recovery_path("carol").read_text())
        self.expect_error("reclaim", "carol", "initialization is still pending", self.sponsor(poor=True))
        self.event("unlanded_initialization_retained", record=never_created)

        child = self.spawn_payment("alice", 3)
        pending_path = root / "wallets/alice.wallet.json.pending.json"
        until = time.monotonic() + 180
        pending = None
        while time.monotonic() < until:
            if child.poll() is not None:
                raise RuntimeError("payment ended before finalization interruption")
            try:
                pending = json.loads(pending_path.read_text())
                status = rpc(port(0), "getSignatureStatuses", [[pending["signature"]]])["value"][0]
                if status and status["err"] is None and status["confirmationStatus"] != "finalized":
                    break
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            time.sleep(0.025)
        else:
            raise RuntimeError("no executed unfinalized payment to interrupt")
        self.kill_wallet(child)
        self.finalized_signature(pending["signature"])
        record = json.loads(self.recovery_path("alice").read_text())
        self.expect_error("reclaim", "alice", "unresolved payment", self.sponsor())
        resolved = self.wallet("resolve", "alice")
        if not resolved["accepted"] or not resolved["staging_recovery_required"]:
            raise RuntimeError("accepted payment did not preserve its rent recovery record")
        self.event("accepted_payment_resolved", resolution=resolved)
        expected = durable(root, 0)
        self.reclaim_with_accounting("alice", record)
        if durable(root, 0) != expected:
            raise RuntimeError("consumed-buffer cleanup changed accepted payment state")
        self.result["checks"] += ["sigkill_after_execution_before_cleanup", "pending_payment_blocks_reclaim", "accepted_intent_resolved_once", "consumed_staging_refunds_rent_less_exact_fee"]

        until = time.monotonic() + 120
        while time.monotonic() < until:
            checkpoint = rpc(port(0), "getEpochInfo", [{"commitment": "finalized"}])
            if checkpoint["blockHeight"] > never_created["last_valid_block_height"]:
                break
            time.sleep(0.3)
        else:
            raise RuntimeError("unlanded initialization did not reach finalized expiry")
        untouched = durable(root, 0)
        cleared = self.wallet("reclaim", "carol", self.sponsor(poor=True))
        if cleared["rent_reclaimed"] or self.recovery_path("carol").exists() or durable(root, 0) != untouched:
            raise RuntimeError("unlanded recovery incorrectly moved native value")
        self.result["checks"].append("unlanded_initialization_cleared_only_after_real_expiry")
        for who in ["alice", "bob"]:
            self.wallet("restore", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")], restored=True)
        self.balances(18, 5, (0, 1), restored=True)
        final = durable(root, 0)
        roots = self.converge(0, final)
        data = base64.b64decode(final[load(root)["pool"]]["data"][0])
        if len(final) != 7 or int.from_bytes(data[48:56], "little") != 23 or int.from_bytes(data[56:64], "little") != 6:
            raise RuntimeError("recovery duplicated a payment or changed final backing")
        if list((root / "wallets").glob("*.pending.json")) or list((root / "wallets").glob("*.staging.json")):
            raise RuntimeError("recovery left unresolved wallet records")
        atomic_json(root / "final-native-accounts.json", final)
        self.result["checks"].append("seed_only_recovery_after_upload_interruptions")
        self.result.update(status="passed", final_slots=roots, alice_balance=18, bob_balance=5,
                           backing=23, commitments=6, permanent_markers=6, pool_sha256=hashlib.sha256(data).hexdigest())
        self.event("acceptance_passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if root.exists() or not root.is_relative_to(PROJECT / ".data"):
        raise RuntimeError("select a new ignored .data fixture directory")
    if shutil.disk_usage(PROJECT).free < 2 * 1024**3:
        raise RuntimeError("need 2 GiB free for bounded staging acceptance")
    trial = StagingExperiment(root)
    try:
        trial.run()
    except Exception as error:
        trial.result.update(status="failed", error=str(error))
        if root.exists():
            trial.event("acceptance_failed", error=str(error))
        raise
    finally:
        trial.cleanup()


if __name__ == "__main__":
    main()
