#!/usr/bin/env python3
"""Real SIGKILL and shred-partition acceptance on a new, local-only wallet fixture."""
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

from localnet import PROJECT, LAB, ledger, load, port, quiet, restart_state, rpc, start, stop, wait_rpc
from restart_localnet import capture_public_payment
from wallet_localnet import private_new

WALLET = PROJECT / "target/debug/native-wallet"


def atomic_json(path, value):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value, indent=2))
    temp.replace(path)


def account(index, key, commitment="finalized"):
    return rpc(port(index), "getAccountInfo", [key, {"encoding": "base64", "commitment": commitment}])["value"]


def durable(root, index, commitment="finalized"):
    config = load(root)
    entries = rpc(port(index), "getProgramAccounts", [config["program"], {"encoding": "base64", "commitment": commitment}])
    result = {}
    for item in entries:
        data = base64.b64decode(item["account"]["data"][0])
        if data[:8] in [b"NPOOL003", b"NSPENT01"]:
            result[item["pubkey"]] = item["account"]
        elif data[:8] != b"NBUF0001":
            raise RuntimeError("unexpected native account format")
    return result


def sealed_on_both(buffer):
    first, second = [account(i, buffer) for i in [0, 1]]
    return first is not None and first == second and base64.b64decode(first["data"][0])[88] == 1


def crash_owned(root, index, process):
    """Only signal a live direct child owned by this runner, after RPC authentication."""
    if process is None or process.poll() is not None or int((root / f"validator-{index}.pid").read_text()) != process.pid:
        raise RuntimeError("crash target is not this runner's live validator child")
    wait_rpc(root, index, timeout=5)
    process.kill()  # SIGKILL: no admin shutdown and no validator exit hooks.
    code = process.wait(timeout=15)
    if code != -9:
        raise RuntimeError(f"expected SIGKILL exit, received {code}")
    return {"validator": index, "pid": process.pid, "exit_code": code}


class Experiment:
    def __init__(self, root):
        self.root = root
        self.children = [None, None]
        self.wallet_children = []
        self.result = {"status": "running", "events": [], "checks": []}
        self.env = dict(os.environ, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost")

    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "fault-result.json", self.result)
        print(kind, flush=True)

    def wallet_args(self, action, who, extra=(), index=0, restored=False):
        return [str(WALLET), action, "--network", str(self.root / "network.json"),
                "--wallet", str(self.root / "wallets" / f"{who}{'-restored' if restored else ''}.wallet.json"),
                "--password-file", str(self.root / "wallets/unlock.password"),
                "--rpc", f"http://127.0.0.1:{port(index)}"] + list(extra)

    def wallet(self, action, who, extra=(), index=0, restored=False):
        result = subprocess.run(self.wallet_args(action, who, extra, index, restored), capture_output=True, text=True, env=self.env, timeout=180)
        if result.returncode:
            raise RuntimeError(f"wallet {action}: {result.stderr}")
        return json.loads(result.stdout)

    def lab(self, command, label, index=0):
        result = subprocess.run([str(LAB), command, str(self.root), label, str(index)], capture_output=True, text=True, env=self.env, timeout=120)
        if result.returncode:
            (self.root / f"failed-{command}-{label}.log").write_text(result.stdout + result.stderr)
            raise RuntimeError(f"{command} {label}: {result.stderr.strip()}")
        return json.loads(result.stdout)

    def launch(self, index, coordinated=False):
        self.children[index] = start(self.root, index, coordinated=coordinated, faults=True)
        wait_rpc(self.root, index)

    def slots(self, commitment="finalized"):
        return [rpc(port(i), "getSlot", [{"commitment": commitment}]) for i in [0, 1]]

    def converge(self, after, expected=None, timeout=120):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            slots = self.slots()
            first, second = durable(self.root, 0), durable(self.root, 1)
            if min(slots) > after + 8 and abs(slots[0] - slots[1]) <= 12 and first == second and (expected is None or first == expected):
                return slots
            time.sleep(0.3)
        raise RuntimeError("cluster did not regain fresh finalization and exact native state")

    def balances(self, alice, bob, indices=(0,), restored=False):
        for index in indices:
            for who, expected in [("alice", alice), ("bob", bob)]:
                actual = self.wallet("balance", who, index=index, restored=restored)["balance"]
                if actual != expected:
                    raise RuntimeError(f"{who} balance {actual} differs from {expected} on node {index}")

    def closed(self, buffer, indices=(0, 1)):
        deadline = time.monotonic() + 50
        while time.monotonic() < deadline:
            if all(account(i, buffer) is None for i in indices):
                return
            time.sleep(0.3)
        raise RuntimeError("staging rent cleanup did not finalize")

    def pay(self, action, who, amount, to=None, indices=(0, 1)):
        extra = ["--sponsor", str(self.root / "sponsor.keypair.json"), "--amount", str(amount)]
        if to:
            extra += ["--to", to]
        receipt = self.wallet(action, who, extra)
        self.event("payment_finalized", action=action, who=who, amount=amount, receipt=receipt)
        if not receipt["staging_rent_reclaimed"]:
            raise RuntimeError("staging rent was not reclaimed")
        self.closed(receipt["staging_account"], indices)
        return receipt

    def gate(self, active):
        if active:
            for i in [0, 1]:
                subprocess.run([str(PROJECT / "target/debug/agave-validator"), "--ledger", str(ledger(self.root, i)), "set-log-filter", "warn,solana_core::replay_stage=info,solana_runtime::bank=info"], check=True, capture_output=True, timeout=10)
        for i in [0, 1]:
            atomic_json(self.root / f"fault-{i}.json", {"drop_shreds": active})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                acks = [json.loads((self.root / f"fault-{i}.ack.json").read_text()) for i in [0, 1]]
                if all(ack["drop_shreds"] == active and ack["pid"] == self.children[i].pid for i, ack in enumerate(acks)):
                    self.event("shred_gate", active=active, acknowledgments=acks)
                    return
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            time.sleep(0.05)
        raise RuntimeError("validator did not acknowledge fault gate")

    def finalized_signature(self, signature, timeout=80):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = rpc(port(0), "getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])["value"][0]
            if status and status["confirmationStatus"] == "finalized":
                if status["err"] is not None:
                    raise RuntimeError(f"candidate finalization failed: {status['err']}")
                return status["slot"]
            time.sleep(0.2)
        raise RuntimeError("candidate did not finalize")

    def finalization_receipt(self, buffer):
        config = load(self.root)
        for row in rpc(port(0), "getSignaturesForAddress", [buffer, {"commitment": "confirmed"}]):
            if row["err"] is not None:
                continue
            tx = rpc(port(0), "getTransaction", [row["signature"], {"encoding": "json", "commitment": "confirmed", "maxSupportedTransactionVersion": 0}])
            if tx is None:
                continue
            message = tx["transaction"]["message"]
            if any(message["accountKeys"][ix["programIdIndex"]] == config["program"] and ix["data"] == "4" for ix in message["instructions"]):
                return {"signature": row["signature"], "staging_account": buffer}
        raise RuntimeError("accepted finalization receipt not found")

    def restart_majority(self):
        try:
            state = restart_state(self.root, 0)
        except subprocess.CalledProcessError:
            # Replay/repair under the ordinary vote guard before selecting a
            # checkpoint. Never erase a tower or truncate a crashed ledger.
            self.launch(0)
            time.sleep(5)
            stop(self.root, 0)
            state = restart_state(self.root, 0)
            self.event("guarded_replay_before_checkpoint", slot=state["slot"])
        self.launch(0, coordinated=True)
        return state

    def run(self):
        root = self.root
        subprocess.run([str(LAB), "init", str(root)], check=True, capture_output=True)
        self.result["genesis_hash"] = load(root)["genesis_hash"]
        for i in [0, 1]:
            atomic_json(root / f"fault-{i}.json", {"drop_shreds": False})
            self.launch(i)
        self.gate(False)
        quiet(root)
        (root / "wallets").mkdir(mode=0o700)
        private_new(root / "wallets/unlock.password", secrets.token_bytes(48))
        addresses = {}
        for who in ["alice", "bob"]:
            addresses[who] = self.wallet("init", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")])["address"]
        self.pay("deposit", "alice", 100)
        self.pay("send", "alice", 20, addresses["bob"])
        self.balances(80, 20, (0, 1))
        self.event("baseline", slots=self.slots())

        # Two authorizations spend the same private note, with different
        # commitments and one different dummy nullifier on each fork.
        a = self.lab("fault-prepare", "majority", 1)
        b = self.lab("fault-prepare", "minority", 2)
        common = set(a["markers"]) & set(b["markers"])
        orphan = set(b["markers"]) - set(a["markers"])
        if len(common) != 1 or len(orphan) != 1:
            raise RuntimeError("fixture does not contain distinct conflicting note spends")
        staged = {label: self.lab("fault-stage", label) for label in ["majority", "minority"]}
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if all(sealed_on_both(r["staging_account"]) for r in staged.values()):
                break
            time.sleep(0.3)
        else:
            raise RuntimeError("candidate staging did not finalize on both peers")
        sealed = account(0, staged["minority"]["staging_account"])
        atomic_json(root / "partition-sealed-account.json", sealed)
        # Enter before an upcoming minority leader window, leaving time to
        # commit the majority candidate before direct minority delivery.
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            tip = rpc(port(0), "getSlot", [{"commitment": "processed"}])
            leaders = rpc(port(0), "getSlotLeaders", [tip, 24])
            if leaders[0] == load(root)["identities"][0] and any(identity == load(root)["identities"][1] for identity in leaders[8:20]):
                break
            time.sleep(0.3)
        else:
            raise RuntimeError("no suitable minority leader window")
        self.gate(True)
        barrier = max(self.slots("processed"))
        # RPC sendTransaction deliberately targets upcoming remote leaders;
        # direct TPU delivery keeps each conflicting candidate on its own fork.
        receipt = self.lab("fault-direct", "majority", 0)
        if any(account(1, key, "processed") is not None for key in a["markers"]):
            raise RuntimeError("majority candidate leaked into isolated minority execution")
        competing = self.lab("fault-direct", "minority", 1)
        for key in orphan:
            if account(1, key, "processed") is None or account(0, key, "processed") is not None:
                raise RuntimeError("orphan-only nullifier was not isolated to minority fork")
        if self.slots()[1] >= competing["slot"]:
            raise RuntimeError("minority payment unexpectedly finalized")
        self.finalized_signature(receipt["signature"])
        until = time.monotonic() + 60
        while rpc(port(0), "getSlot", [{"commitment": "finalized"}]) <= barrier + 8:
            if time.monotonic() >= until:
                raise RuntimeError("majority did not finalize through partition")
            time.sleep(0.2)
        expected = durable(root, 0)
        minority = durable(root, 1, "processed")
        atomic_json(root / "partition-canonical-native.json", expected)
        atomic_json(root / "partition-minority-native.json", minority)
        if expected == minority:
            raise RuntimeError("partition did not create distinct native fork effects")
        before_heal = rpc(port(0), "getSlot", [{"commitment": "finalized"}])
        self.event("competing_forks", majority=receipt, minority=competing, orphan_markers=sorted(orphan), barrier=barrier, roots=self.slots())
        self.gate(False)
        roots = self.converge(before_heal, expected, timeout=140)
        for index in [0, 1]:
            for key in orphan:
                if account(index, key, "processed") is not None or account(index, key) is not None:
                    raise RuntimeError("orphan nullifier survived canonical rejoin")
            if account(index, staged["minority"]["staging_account"]) != sealed:
                atomic_json(root / f"partition-rejoined-account-{index}.json", account(index, staged["minority"]["staging_account"]))
                raise RuntimeError("orphan staging consumption did not roll back")
        if max(self.slots("processed")) >= b["expiry"]:
            raise RuntimeError("conflicting proof expired before replay rejection check")
        self.lab("fault-reject", "minority", 0)
        if durable(root, 0, "confirmed") != expected:
            raise RuntimeError("conflicting replay changed canonical native state")
        for label in ["majority", "minority"]:
            self.lab("fault-close", label, 0)
            self.closed(staged[label]["staging_account"])
        self.balances(79, 21, (0, 1))
        self.result["checks"] += ["partition_live_rpc_distinct_forks", "majority_payment_finalized", "orphan_nullifier_removed", "orphan_staging_consumption_rolled_back", "conflicting_spend_rejected_after_rejoin"]
        self.event("partition_rejoined", slots=roots)

        # SIGKILL the minority; finalize a new private send while it is dead.
        before = max(self.slots("processed"))
        saved = durable(root, 0)
        self.event("sigkill_minority", **crash_owned(root, 1, self.children[1]))
        receipt = self.pay("send", "alice", 3, addresses["bob"], indices=(0,))
        expected = durable(root, 0)
        for key, value in saved.items():
            if key != load(root)["pool"] and expected.get(key) != value:
                raise RuntimeError("existing nullifier changed while minority was dead")
        self.launch(1)
        roots = self.converge(before, expected)
        self.balances(76, 24, (0, 1))
        capture_public_payment(root, receipt)
        subprocess.run([str(LAB), "replay-check", str(root), "http://127.0.0.1:19899", "http://127.0.0.1:18899"], check=True, env=self.env, timeout=90)
        self.closed(receipt["staging_account"])
        self.result["checks"] += ["sigkill_minority_catches_up_payments_and_nullifiers", "recovered_peer_rejects_live_spent_proof"]
        self.event("minority_crash_recovered", slots=roots)

        # Kill the majority after a real payment executes but before it roots.
        before_state = durable(root, 0)
        extra = ["--sponsor", str(root / "sponsor.keypair.json"), "--amount", "2"]
        client = subprocess.Popen(self.wallet_args("deposit", "alice", extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
        self.wallet_children.append(client)
        pending_file = root / "wallets/alice.wallet.json.pending.json"
        until = time.monotonic() + 120
        pending, status, payload = None, None, None
        while time.monotonic() < until:
            if pending_file.exists():
                try:
                    pending = json.loads(pending_file.read_text())
                except json.JSONDecodeError:
                    time.sleep(0.025)
                    continue
                buffer = account(0, pending["staging_account"], "processed")
                if buffer:
                    raw = base64.b64decode(buffer["data"][0]); length = int.from_bytes(raw[40:44], "little")
                    payload = raw[96:96 + length]
                status = rpc(port(0), "getSignatureStatuses", [[pending["signature"]], {"searchTransactionHistory": True}])["value"][0]
                if status and status["err"] is None and status["confirmationStatus"] != "finalized" and payload:
                    break
            if client.poll() is not None:
                raise RuntimeError("payment completed before crash injection")
            time.sleep(0.025)
        else:
            raise RuntimeError("no in-flight executed payment to crash")
        (root / "crash-payment.bin").write_bytes(payload)
        atomic_json(root / "crash-staging.json", {"staging_account": pending["staging_account"]})
        self.event("sigkill_majority_inflight", transaction=pending, execution_status=status, **crash_owned(root, 0, self.children[0]))
        state = self.restart_majority()
        self.converge(max(status["slot"], state["highest_stored_slot"]))
        stdout, stderr = client.communicate(timeout=90)
        self.event("interrupted_wallet_returned", exit_code=client.returncode, stdout=stdout, error=stderr)
        if pending_file.exists():
            duplicate = subprocess.run(self.wallet_args("deposit", "alice", extra), capture_output=True, text=True, env=self.env, timeout=15)
            if duplicate.returncode == 0 or "unresolved payment" not in duplicate.stderr:
                raise RuntimeError("unresolved intent did not block duplicate payment")
            until = time.monotonic() + 110
            while time.monotonic() < until:
                resolved = subprocess.run(self.wallet_args("resolve", "alice"), capture_output=True, text=True, env=self.env, timeout=180)
                if resolved.returncode == 0:
                    resolution = json.loads(resolved.stdout)
                    break
                if "still pending" not in resolved.stderr:
                    raise RuntimeError(resolved.stderr)
                time.sleep(0.5)
            else:
                raise RuntimeError("in-flight payment remained unresolved beyond blockhash expiry")
            self.event("interrupted_payment_resolved", **resolution)
            accepted = resolution["accepted"]
        else:
            accepted = client.returncode == 0
        # New wallets preserve upload recovery independently of finalization.
        # Resolve acceptance first, then reclaim the original buffer through the
        # same guarded command used for interrupted ordinary wallet uploads.
        staging_record = root / "wallets/alice.wallet.json.staging.json"
        if staging_record.exists():
            cleanup = self.wallet("reclaim", "alice", ["--sponsor", str(root / "sponsor.keypair.json")])
            self.event("interrupted_wallet_staging_reclaimed", receipt=cleanup)
        if not accepted:
            if durable(root, 0) != before_state:
                raise RuntimeError("noncanonical payment left backing or nullifier effects")
            if account(0, pending["staging_account"], "confirmed") is not None:
                self.lab("fault-close", "crash", 0)
            self.lab("fault-stage", "crash", 0)
            self.lab("fault-finalize", "crash", 0)
            receipt = self.finalization_receipt(json.loads((root / "crash-staging.json").read_text())["staging_account"])
            self.finalized_signature(receipt["signature"])
            self.event("orphaned_payment_reincluded_once", receipt=receipt)
        self.balances(78, 24)
        staged_crash = json.loads((root / "crash-staging.json").read_text())["staging_account"]
        if account(0, staged_crash, "confirmed") is not None:
            self.lab("fault-close", "crash", 0)
        self.closed(staged_crash)
        expected = durable(root, 0)
        self.converge(status["slot"], expected)
        self.result["checks"] += ["sigkill_majority_inflight", "pending_intent_resolved_without_duplicate_deposit", "native_effects_applied_exactly_once"]

        # Both processes die without exit hooks, then restore signed towers.
        barrier = max(self.slots("processed"))
        for i in [1, 0]:
            self.event("sigkill_whole_cluster", **crash_owned(root, i, self.children[i]))
        self.restart_majority()
        self.launch(1)
        roots = self.converge(barrier, expected)
        shutil.copyfile(root / "crash-payment.bin", root / "restart-spent-payment.bin")
        subprocess.run([str(LAB), "replay-check", str(root), "http://127.0.0.1:18899", "http://127.0.0.1:19899"], check=True, env=self.env, timeout=90)
        for who in ["alice", "bob"]:
            self.wallet("restore", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")], restored=True)
        self.balances(78, 24, (0, 1), restored=True)
        final = durable(root, 0)
        atomic_json(root / "final-native-accounts.json", final)
        if final != durable(root, 1) or len(final) != 11:
            raise RuntimeError("final permanent marker set differs")
        pool = final[load(root)["pool"]]; data = base64.b64decode(pool["data"][0])
        if int.from_bytes(data[48:56], "little") != 102 or int.from_bytes(data[56:64], "little") != 10 or pool["lamports"] != int.from_bytes(data[40:48], "little") + 102:
            raise RuntimeError("final native backing or commitments differ")
        self.result.update(status="passed", final_slots=roots, alice_balance=78, bob_balance=24, backing=102, commitments=10, permanent_markers=10, pool_sha256=hashlib.sha256(data).hexdigest())
        self.result["checks"] += ["sigkill_both_validators_recover", "live_replay_rejected_after_whole_cluster_crash", "seed_only_restoration_after_faults"]
        self.event("acceptance_passed")

    def cleanup(self):
        if not self.root.exists():
            return
        for i in [0, 1]:
            atomic_json(self.root / f"fault-{i}.json", {"drop_shreds": False})
        for child in self.wallet_children:
            if child.poll() is None:
                child.kill(); child.wait(timeout=15)
        for i in [1, 0]:
            if self.children[i] is not None and self.children[i].poll() is None:
                stop(self.root, i)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if root.exists() or not root.is_relative_to(PROJECT / ".data"):
        raise RuntimeError("select a new ignored .data fixture directory")
    if shutil.disk_usage(PROJECT).free < 2 * 1024**3:
        raise RuntimeError("need 2 GiB free for bounded fault testing")
    trial = Experiment(root)
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
