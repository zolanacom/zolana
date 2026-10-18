#!/usr/bin/env python3
"""Verify retained ciphertext recovery against an actual snapshot-only peer."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import subprocess
import time

from fault_localnet import Experiment, WALLET, atomic_json, durable
from localnet import LAB, PROJECT, ledger, load, newer_full_snapshot, port, prepare_snapshot_recovery, quiet, rpc, start, stop, wait_rpc
from wallet_localnet import private_new
from wallet_ui import WalletApp


class ArchiveExperiment(Experiment):
    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "archive-result.json", self.result)
        print(kind, flush=True)

    def export(self):
        args = [str(WALLET), "archive", "--network", str(self.root / "network.json"),
                "--rpc", "http://127.0.0.1:18899", "--history", str(self.root / "recovery-history")]
        response = subprocess.run(args, capture_output=True, text=True, env=self.env, timeout=180)
        if response.returncode:
            raise RuntimeError(response.stderr)
        result = json.loads(response.stdout)
        if not result["manifest_committed"]:
            raise RuntimeError("archive manifest was not committed")
        self.event("history_exported", result=result)
        return result

    def reject(self, args, reason=None):
        response = subprocess.run(args, capture_output=True, text=True, env=self.env, timeout=180)
        if response.returncode == 0 or response.stdout.strip() or (reason and reason not in response.stderr):
            raise RuntimeError(f"expected fail-closed history rejection: {response.stdout} {response.stderr}")
        return response.stderr.strip()

    def run(self):
        root = self.root
        subprocess.run([str(LAB), "init", str(root)], check=True, capture_output=True)
        self.result["genesis_hash"] = load(root)["genesis_hash"]
        for index in [0, 1]:
            self.children[index] = start(root, index)
            wait_rpc(root, index)
        quiet(root)
        (root / "wallets").mkdir(mode=0o700)
        private_new(root / "wallets/unlock.password", secrets.token_urlsafe(36).encode())
        addresses = {who: self.wallet("init", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")])["address"] for who in ["alice", "bob"]}
        self.pay("deposit", "alice", 100)
        self.pay("send", "alice", 17, addresses["bob"])
        self.export()
        history = root / "recovery-history"
        first_files = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in history.glob("segment-*.json")}
        self.export()
        if not all(hashlib.sha256((history / name).read_bytes()).hexdigest() == digest for name, digest in first_files.items()):
            raise RuntimeError("archive restart changed an immutable segment")
        self.event("writer_restart_preserves_prefix", immutable_segments=len(first_files))

        expected = durable(root, 0)
        barrier = rpc(port(1), "getSlot", [{"commitment": "processed"}])
        stop(root, 1)
        deadline = time.monotonic() + 150
        while not newer_full_snapshot(ledger(root, 0), barrier):
            if time.monotonic() > deadline:
                raise RuntimeError("newer finalized full snapshot was unavailable")
            time.sleep(0.4)
        snapshot = prepare_snapshot_recovery(root, "ledger-recovered-1", barrier)
        atomic_json(root / "active-ledger-1.json", snapshot["fresh_ledger"])
        log = root / "validator-1.log"
        offset = log.stat().st_size
        self.children[1] = start(root, 1, archive=True)
        wait_rpc(root, 1)
        roots = self.converge(snapshot["archive_slot"], expected)
        with log.open("rb") as stream:
            stream.seek(offset)
            text = stream.read().decode(errors="replace")
        if any(token not in text for token in ["Loading bank from full snapshot archive:", snapshot["archive"], "Verifying bank... Done."]):
            raise RuntimeError("actual snapshot extraction and bank verification evidence is missing")
        self.event("snapshot_peer_progresses", snapshot=snapshot, finalized_slots=roots)
        self.export()

        self.wallet("restore", "bob", ["--backup", str(root / "wallets/bob.seed-backup.json")], restored=True)
        missing = self.reject(self.wallet_args("balance", "bob", index=1, restored=True), "history")
        recovered = self.wallet("balance", "bob", ["--history", str(history)], index=1, restored=True)
        if recovered["balance"] != 17 or recovered["sync"]["history_blocks_read"] == 0:
            raise RuntimeError("seed-only restoration did not use retained history")
        self.event("fresh_seed_recovers_on_snapshot_rpc", missing_history_error=missing, recovered=recovered)
        receipt = self.wallet("send", "bob", ["--history", str(history), "--sponsor", str(root / "sponsor.keypair.json"), "--amount", "5", "--to", addresses["alice"]], index=1, restored=True)
        self.closed(receipt["staging_account"])
        if not receipt["staging_rent_reclaimed"]:
            raise RuntimeError("snapshot-peer payment did not reclaim staging rent")
        self.export()
        self.wallet("restore", "bob-final", ["--backup", str(root / "wallets/bob.seed-backup.json")])
        final = self.wallet("balance", "bob-final", ["--history", str(history)], index=1)
        if final["balance"] != 12 or final["sync"]["payments_verified"] != 3:
            raise RuntimeError("a second seed-only recovery lost payment or spent-nullifier effects")
        self.event("recovered_witness_spends_on_snapshot_peer", receipt=receipt, balance=final)

        # The local UI backend discovers the fixed retained-history directory
        # and authenticates the same seed/password through the snapshot peer.
        ui = WalletApp(root, "archive-recovery", rpc_index=1)
        password = (root / "wallets/unlock.password").read_text()
        seed = json.loads((root / "wallets/bob.seed-backup.json").read_text())
        restored_ui = ui.action({"action":"restore", "password":password, "backup":seed})
        ui_balance = ui.action({"action":"balance", "password":password})
        if restored_ui["address"] != addresses["bob"] or ui_balance["balance"] != 12 or not ui_balance["sync"]["history_blocks_read"]:
            raise RuntimeError("device-local backend did not recover through retained history on the snapshot peer")
        self.event("device_local_ui_uses_snapshot_peer_history", balance=ui_balance)

        corrupt = root / "history-damaged"
        shutil.copytree(history, corrupt)
        manifest = json.loads((corrupt / "manifest.json").read_text())
        descriptor = manifest["segments"][0]
        segment = corrupt / f"segment-00000000-{descriptor['digest']}.json"
        original = segment.read_bytes()
        segment.write_bytes(original[:-1])
        self.reject(self.wallet_args("balance", "alice", ["--history", str(corrupt)], index=1), "checksum")
        segment.write_bytes(original)
        segment.rename(segment.with_suffix(".held"))
        self.reject(self.wallet_args("balance", "alice", ["--history", str(corrupt)], index=1))
        segment.with_suffix(".held").rename(segment)
        records = json.loads(original)
        changed = False
        for block in records:
            if block["transactions"]:
                block["transactions"] = []
                changed = True
        if not changed:
            raise RuntimeError("history fixture has no native bodies to remove")
        forged = json.dumps(records, separators=(",", ":")).encode()
        forged_digest = hashlib.blake2b(forged, digest_size=32, person=b"NPayArchiveV1").hexdigest()
        descriptor["digest"] = forged_digest
        (corrupt / f"segment-00000000-{forged_digest}.json").write_bytes(forged)
        (corrupt / "manifest.json").write_text(json.dumps(manifest))
        self.reject(self.wallet_args("balance", "alice", ["--history", str(corrupt)], index=1))
        self.event("missing_corrupt_and_rehashed_payment_omission_rejected")

        # Retained metadata is never accepted as canonical outer-tx inclusion.
        # Use a genuinely fresh device: bob-restored now has a verified RPC
        # checkpoint and can legitimately resolve the post-snapshot signature.
        # Retained metadata alone must not supply that canonical evidence.
        self.wallet("restore", "bob-pending", ["--backup", str(root / "wallets/bob.seed-backup.json")])
        pending = root / "wallets/bob-pending.wallet.json.pending.json"
        if Path(str(root / "wallets/bob-pending.wallet.json") + ".scan-cache").exists():
            raise RuntimeError("unknown-payment fixture unexpectedly has a verified checkpoint")
        config = load(root)
        private_new(pending, json.dumps({"network": {"network": config["network"], "genesis_hash": config["genesis_hash"]},
                    "signature": receipt["signature"], "staging_account": receipt["staging_account"], "last_valid_block_height": 0}).encode())
        self.reject(self.wallet_args("resolve", "bob-pending", ["--history", str(history)], index=1), "canonical full RPC history")
        self.reject(self.wallet_args("resolve", "bob-pending", index=1), "history")
        if not pending.exists():
            raise RuntimeError("missing canonical history cleared an unknown payment")
        resolved = self.wallet("resolve", "bob-pending", index=0)
        if not resolved["accepted"] or pending.exists():
            raise RuntimeError("canonical archive RPC did not resolve the actual accepted payment")
        final_state = durable(root, 0)
        if len(final_state) != 7 or final_state != durable(root, 1):
            raise RuntimeError("snapshot recovery did not preserve exact pool and six permanent nullifiers")
        self.result.update(status="passed", final_balance=12, exact_pool_and_six_nullifiers=True,
                           archive_bytes=sum(p.stat().st_size for p in history.iterdir() if p.is_file()))
        self.event("archive_acceptance_passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data") or root.exists():
        parser.error("use a new directory under .data")
    trial = ArchiveExperiment(root)
    try:
        trial.run()
    except Exception as error:
        trial.result.update(status="failed", error=str(error))
        raise
    finally:
        errors = []
        for index in [1, 0]:
            if trial.children[index] is not None and trial.children[index].poll() is None:
                try:
                    stop(root, index)
                except Exception as error:
                    errors.append(str(error))
        if errors:
            trial.result.update(status="failed", cleanup_errors=errors)
        if root.exists():
            atomic_json(root / "archive-result.json", trial.result)
        if errors:
            raise RuntimeError("owned validator cleanup failed")
