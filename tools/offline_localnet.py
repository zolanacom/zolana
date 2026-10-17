#!/usr/bin/env python3
"""Bounded multi-epoch catch-up and damaged/full-snapshot acceptance on loopback."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import time

from fault_localnet import Experiment, account, atomic_json, durable, sealed_on_both
from localnet import PROJECT, LAB, digest, ledger, load, newer_full_snapshot, port, prepare_snapshot_recovery, quiet, rpc, start, stop, wait_rpc
from restart_localnet import capture_public_payment
from wallet_localnet import private_new


def offline_target(expiry, epoch, slots_per_epoch):
    # Four complete epoch boundaries and an expired authorization, not a sleep.
    return max(expiry + 8, (epoch + 4) * slots_per_epoch)


def towers(root):
    return {p.name: digest(p) for p in (root / "consensus-1").glob("tower-*.bin")}


def resumable_offline(result):
    payments = [(e["action"], e["who"], e["amount"]) for e in result["events"] if e["kind"] == "payment_finalized"]
    stopped = [e for e in result["events"] if e["kind"] == "minority_offline"]
    if (result["status"] != "failed" or result.get("checks")
            or result.get("error") != "cluster did not regain fresh finalization and exact native state"
            or payments != [("deposit", "alice", 100), ("send", "alice", 20), ("send", "alice", 5), ("withdraw", "bob", 2)]
            or len(stopped) != 1):
        raise RuntimeError("journal is not an interrupted offline-catchup attempt; refusing to repeat payments")
    return stopped[0]


class OfflineExperiment(Experiment):
    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "offline-result.json", self.result)
        print(kind, flush=True)

    def launch(self, index, coordinated=False, archive=False):
        self.children[index] = start(self.root, index, coordinated=coordinated, archive=archive)
        wait_rpc(self.root, index)

    def snapshot(self, name, barrier):
        until = time.monotonic() + 150
        while time.monotonic() < until:
            if newer_full_snapshot(ledger(self.root, 0), barrier):
                result = prepare_snapshot_recovery(self.root, name, barrier)
                atomic_json(self.root / f"{name}-input.json", result)
                return result
            time.sleep(0.5)
        raise RuntimeError("no full snapshot newer than shutdown history")

    def offline_snapshot(self, context):
        barrier = max(context["shutdown_tip"], rpc(port(0), "getSlot", [{"commitment": "processed"}]))
        if self.children[1] is not None and self.children[1].poll() is None:
            barrier = max(barrier, rpc(port(1), "getSlot", [{"commitment": "processed"}]))
            stop(self.root, 1)
        snapshot = self.snapshot("ledger-recovered-off", barrier)
        atomic_json(self.root / "active-ledger-1.json", snapshot["fresh_ledger"])
        self.launch(1, archive=True)
        roots = self.converge(max(context["target"], snapshot["archive_slot"]), context["expected_native"])
        self.event("offline_snapshot_recovered", snapshot=snapshot, roots=roots)
        return roots

    def catch_up_offline(self, context):
        self.launch(1)
        try:
            return self.converge(context["target"], context["expected_native"], timeout=60), False
        except RuntimeError as error:
            if str(error) != "cluster did not regain fresh finalization and exact native state":
                raise
            self.event("ordinary_catchup_stalled", roots=self.slots(), processed_slots=self.slots("processed"))
            return self.offline_snapshot(context), True

    def resume(self):
        root = self.root
        previous = json.loads((root / "offline-result.json").read_text())
        stopped = resumable_offline(previous)
        if previous["genesis_hash"] != load(root)["genesis_hash"]:
            raise RuntimeError("resume genesis differs from recorded experiment")
        backup = root / "offline-failed-attempt.json"
        if backup.exists():
            raise RuntimeError("this offline attempt already has a continuation")
        atomic_json(backup, previous)
        self.result = previous
        self.result.update(status="running")
        self.result.pop("error", None)
        self.event("resuming_offline_snapshot_recovery", original_attempt=backup.name)
        self.launch(0, coordinated=True)
        expected = durable(root, 0)
        data = base64.b64decode(expected[load(root)["pool"]]["data"][0])
        if len(expected) != 9 or int.from_bytes(data[48:56], "little") != 98 or int.from_bytes(data[56:64], "little") != 8:
            raise RuntimeError("preserved source state differs from the four recorded payments")
        self.balances(75, 23)
        context = {
            "candidate": stopped["candidate"], "staged": json.loads((root / "majority-staging.json").read_text()),
            "expected_native": expected, "shutdown_tip": stopped["shutdown_tip"],
            "target": offline_target(stopped["candidate"]["expiry"], stopped["epoch"]["epoch"], stopped["epoch"]["slotsInEpoch"]),
            "addresses": {who: self.wallet("address", who)["address"] for who in ["alice", "bob"]},
            "epoch_before_restart": rpc(port(0), "getEpochInfo", [{"commitment": "finalized"}])["epoch"],
        }
        atomic_json(root / "offline-context.json", context)
        roots = self.offline_snapshot(context)
        self.finish_offline(context, roots, via_snapshot=True)

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
        for who in ["alice", "bob"]:
            addresses[who] = self.wallet("init", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")])["address"]
        self.pay("deposit", "alice", 100)
        self.pay("send", "alice", 20, addresses["bob"])
        # An unused deposit has independent dummy nullifiers, so expiry rejection
        # cannot accidentally qualify through an already-spent real note.
        expired = self.lab("fault-prepare-deposit", "majority", 1)
        staged = self.lab("fault-stage", "majority")
        until = time.monotonic() + 60
        while not sealed_on_both(staged["staging_account"]):
            if time.monotonic() >= until:
                raise RuntimeError("unused deposit did not seal on both validators")
            time.sleep(0.3)
        atomic_json(root / "expired-sealed-account.json", account(0, staged["staging_account"]))
        before = max(self.slots("processed"))
        epoch = rpc(port(0), "getEpochInfo", [{"commitment": "finalized"}])
        saved = durable(root, 0)
        stop(root, 1)
        saved_towers = towers(root)
        if not saved_towers:
            raise RuntimeError("offline identity has no saved signed tower")
        self.event("minority_offline", shutdown_tip=before, epoch=epoch, towers=saved_towers, candidate=expired)
        self.pay("send", "alice", 5, addresses["bob"], indices=(0,))
        self.pay("withdraw", "bob", 2, indices=(0,))
        expected = durable(root, 0)
        for key, value in saved.items():
            if key != load(root)["pool"] and expected.get(key) != value:
                raise RuntimeError("old nullifier changed while peer was offline")
        target = offline_target(expired["expiry"], epoch["epoch"], epoch["slotsInEpoch"])
        until = time.monotonic() + 420
        last_epoch = None
        while time.monotonic() < until:
            current = rpc(port(0), "getEpochInfo", [{"commitment": "finalized"}])
            if current["epoch"] != last_epoch:
                self.event("offline_epoch_progress", epoch=current["epoch"], finalized_slot=current["absoluteSlot"], target=target)
                last_epoch = current["epoch"]
            if current["absoluteSlot"] >= target:
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("majority did not finalize across the required offline interval")
        if towers(root) != saved_towers:
            raise RuntimeError("stopped identity's signed tower changed")
        context = {"candidate": expired, "staged": staged, "expected_native": expected,
                   "shutdown_tip": before, "target": target, "addresses": addresses,
                   "epoch_before_restart": current["epoch"]}
        atomic_json(root / "offline-context.json", context)
        roots, via_snapshot = self.catch_up_offline(context)
        self.finish_offline(context, roots, via_snapshot)

    def finish_offline(self, context, roots, via_snapshot):
        root = self.root
        expired, staged, expected = context["candidate"], context["staged"], context["expected_native"]
        addresses = context["addresses"]
        self.balances(75, 23, (0,) if via_snapshot else (0, 1))
        self.lab("fault-expired", "majority", 1)
        if durable(root, 1, "confirmed") != expected:
            raise RuntimeError("expired payment changed canonical state")
        for i in [0, 1]:
            if any(account(i, marker, "confirmed") is not None for marker in expired["markers"]):
                raise RuntimeError("unused expired deposit has a nullifier")
        self.lab("fault-close", "majority", 1)
        self.closed(staged["staging_account"])
        self.result["checks"] += ["offline_across_four_epoch_boundaries", "payments_finalize_while_peer_offline", "old_nullifiers_unchanged", "expired_sealed_deposit_rejected_without_effects", "expired_staging_rent_reclaimed"]
        self.result["checks"].append("snapshot_recovers_offline_native_state" if via_snapshot else "ordinary_restart_catches_up_exact_native_state")
        self.event("offline_catchup_passed", roots=roots, offline_tip=context["shutdown_tip"], target=context["target"], resumed_epoch=context["epoch_before_restart"], via_snapshot=via_snapshot)

        receipt = self.pay("send", "alice", 1, addresses["bob"])
        expected = durable(root, 0)
        capture_public_payment(root, receipt)
        subprocess.run([str(LAB), "replay-check", str(root), "http://127.0.0.1:19899", "http://127.0.0.1:18899"], check=True, env=self.env, timeout=90)
        self.result["checks"].append("live_spent_proof_rejected_after_offline_catchup")
        before = max(self.slots("processed"))
        stop(root, 1)
        barrier = max(before, rpc(port(0), "getSlot", [{"commitment": "processed"}]))
        original_towers = towers(root)
        bad = self.snapshot("ledger-recovered-bad", barrier)
        damaged = root / bad["fresh_ledger"] / bad["archive"]
        with damaged.open("r+b") as stream:
            stream.truncate(max(1, damaged.stat().st_size // 2))
        if digest(damaged) == bad["archive_sha256"]:
            raise RuntimeError("corruption injection did not change snapshot")
        atomic_json(root / "active-ledger-1.json", bad["fresh_ledger"])
        log = root / "validator-1.log"
        offset = log.stat().st_size
        self.children[1] = start(root, 1, archive=True)
        code = self.children[1].wait(timeout=60)
        with log.open("rb") as stream:
            stream.seek(offset)
            failure = stream.read().decode(errors="replace")
        (root / "damaged-snapshot-rejection.log").write_text(failure)
        if code == 0 or "Loading bank from full snapshot archive:" not in failure or bad["archive"] not in failure:
            raise RuntimeError("damaged snapshot did not fail during the selected archive load")
        if towers(root) != original_towers:
            raise RuntimeError("damaged snapshot startup changed the signed tower")
        self.event("damaged_snapshot_rejected", exit_code=code, snapshot=bad, damaged_sha256=digest(damaged), towers_unchanged=original_towers)

        good = self.snapshot("ledger-recovered-good", barrier)
        atomic_json(root / "active-ledger-1.json", good["fresh_ledger"])
        offset = log.stat().st_size
        self.launch(1, archive=True)
        roots = self.converge(max(barrier, good["archive_slot"]), expected)
        with log.open("rb") as stream:
            stream.seek(offset)
            restored_log = stream.read().decode(errors="replace")
        if any(token not in restored_log for token in ["Loading bank from full snapshot archive:", good["archive"], "rebuild bank from snapshots took", "Verifying bank... Done."]):
            raise RuntimeError("missing verified full snapshot restoration evidence")
        subprocess.run([str(LAB), "replay-check", str(root), "http://127.0.0.1:19899", "http://127.0.0.1:18899"], check=True, env=self.env, timeout=90)
        self.result["checks"] += ["damaged_snapshot_rejected_before_tower_mutation", "clean_snapshot_recovers_all_native_accounts", "live_replay_rejected_on_snapshot_peer"]
        self.event("snapshot_recovered", snapshot=good, roots=roots)

        # Create a new real private deposit through the restored validator's RPC.
        fresh = self.lab("fault-prepare-deposit", "minority", 1)
        new_staging = self.lab("fault-stage", "minority", 1)
        self.lab("fault-finalize", "minority", 1)
        receipt = self.finalization_receipt(new_staging["staging_account"])
        self.finalized_signature(receipt["signature"])
        self.event("snapshot_peer_payment_finalized", receipt=receipt, candidate=fresh)
        self.lab("fault-close", "minority", 1)
        self.closed(new_staging["staging_account"])
        capture_public_payment(root, receipt)
        subprocess.run([str(LAB), "replay-check", str(root), "http://127.0.0.1:19899", "http://127.0.0.1:18899"], check=True, env=self.env, timeout=90)
        missing = subprocess.run(self.wallet_args("balance", "alice", index=1), capture_output=True, text=True, env=self.env, timeout=180)
        if missing.returncode == 0 or "history" not in missing.stderr:
            raise RuntimeError("snapshot-only wallet failed to reject missing ciphertext history")
        for who in ["alice", "bob"]:
            self.wallet("restore", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")], restored=True)
        self.balances(75, 24, restored=True)
        expected = durable(root, 0)
        roots = self.converge(good["archive_slot"], expected)
        data = base64.b64decode(expected[load(root)["pool"]]["data"][0])
        if len(expected) != 13 or int.from_bytes(data[48:56], "little") != 99 or int.from_bytes(data[56:64], "little") != 12:
            raise RuntimeError("final native state differs from exact payment accounting")
        pool = expected[load(root)["pool"]]
        if pool["lamports"] != int.from_bytes(data[40:48], "little") + 99:
            raise RuntimeError("native public backing differs")
        atomic_json(root / "final-native-accounts.json", expected)
        self.result["checks"] += ["new_private_payment_executes_on_snapshot_peer", "new_payment_replay_rejected", "snapshot_rpc_missing_history_fails_closed", "seed_only_balances_recovered_from_archive"]
        self.result.update(status="passed", final_slots=roots, alice_balance=75, bob_balance=24, backing=99, commitments=12, permanent_markers=12, pool_sha256=hashlib.sha256(data).hexdigest())
        self.event("acceptance_passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--resume-offline", action="store_true", help="continue only a preserved failed ordinary-catchup attempt without repeating payments")
    args = parser.parse_args()
    root = args.root.resolve()
    if (root.exists() != args.resume_offline) or not root.is_relative_to(PROJECT / ".data"):
        raise RuntimeError("select a new ignored .data fixture directory")
    if len(os.fsencode(root / "ledger-recovered-good/admin.rpc")) >= 104:
        raise RuntimeError("choose a shorter root for recovered-ledger admin sockets")
    if shutil.disk_usage(PROJECT).free < 2 * 1024**3:
        raise RuntimeError("need 2 GiB free for bounded offline acceptance")
    trial = OfflineExperiment(root)
    try:
        if args.resume_offline:
            trial.resume()
        else:
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
