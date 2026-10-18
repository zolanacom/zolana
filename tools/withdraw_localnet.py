#!/usr/bin/env python3
"""Recipient-bound native withdrawals, lost acknowledgements and retained recovery.

Local-only acceptance: new owner-only rehearsal root, real validators/RPC, no
synthetic chain responses, no secret exports and no remote publication.
"""
import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import subprocess
import threading
import time
import urllib.request

from fault_localnet import Experiment, account, atomic_json, crash_owned, durable
from localnet import LAB, PROJECT, ledger, load, newer_full_snapshot, port, prepare_snapshot_recovery, quiet, rpc, start, stop, wait_rpc
from replay_localnet import prepare as prepare_restart
from sponsor_localnet import SponsorExperiment
from wallet_localnet import private_new
from wallet_ui import Handler, WalletApp


class LostAcknowledgement:
    """Withhold one real finalized status response; never invent RPC state."""
    def __init__(self, pending):
        self.pending = pending
        self.reached = threading.Event()
        self.release = threading.Event()
        owner = self
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                size = int(self.headers.get("Content-Length", "0"))
                if not 1 <= size <= 100_000:
                    self.send_error(400)
                    return
                raw = self.rfile.read(size)
                request = json.loads(raw)
                upstream = urllib.request.Request("http://127.0.0.1:18899", raw, {"Content-Type": "application/json"})
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(upstream, timeout=30) as response:
                    data = response.read()
                if request.get("method") == "getSignatureStatuses" and owner.pending.exists():
                    pending = json.loads(owner.pending.read_text())
                    signatures = request.get("params", [[]])[0]
                    statuses = json.loads(data).get("result", {}).get("value", [])
                    for signature, status in zip(signatures, statuses):
                        if signature == pending["signature"] and status and status.get("confirmationStatus") == "finalized" and status.get("err") is None:
                            owner.reached.set()
                            owner.release.wait(8)
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 24899), Proxy)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class WithdrawalExperiment(SponsorExperiment):
    recipient_withdrawals = True

    def __init__(self, root, browser_module, evidence):
        super().__init__(root)
        self.browser_module = browser_module
        self.evidence = evidence
        self.services = []

    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "withdrawal-result.json", self.result)
        print(kind, flush=True)

    def pay(self, action, who, amount, request, recipient=None):
        extra = self.sponsor(request) + ["--amount", str(amount)]
        if recipient:
            extra += ["--to", recipient]
        receipt = self.wallet(action, who, extra)
        if not receipt["staging_rent_reclaimed"]:
            raise RuntimeError("finalized payment needs staging recovery")
        self.closed(receipt["staging_account"])
        self.event("recipient_payment_finalized", action=action, who=who, amount=amount, receipt=receipt)
        return receipt

    def assert_balances(self, alice, bob, public_alice, public_bob, indices=(0, 1), history=False):
        extra = ["--history", str(self.root / "recovery-history")] if history else []
        for index in indices:
            for who, private, public in [("alice", alice, public_alice), ("bob", bob, public_bob)]:
                actual = self.wallet("balance", who, extra, index=index)
                if (actual["balance"], actual["public_balance"]) != (private, public):
                    raise RuntimeError(f"{who} private/public balance differs on validator {index}: {actual}")
                if actual["public_address"] != self.public[who]:
                    raise RuntimeError("seed-derived public authority changed")

    def archive(self):
        return self.command([str(PROJECT / "target/debug/native-wallet"), "archive", "--network", str(self.root / "network.json"),
                             "--rpc", "http://127.0.0.1:18899", "--history", str(self.root / "recovery-history")])

    def run(self):
        root = self.root
        operator = PROJECT / ".local" / ("operator-" + root.name)
        operator.mkdir(mode=0o700)
        cold = operator / "cold.password"
        self.hot_password = operator / "sponsor.password"
        for path in [cold, self.hot_password]:
            private_new(path, secrets.token_urlsafe(36).encode())
        self.command([str(LAB), "init-private", str(root), "--cold-password-file", str(cold),
                      "--sponsor-password-file", str(self.hot_password)])
        for index in [0, 1]:
            self.children[index] = start(root, index)
            wait_rpc(root, index)
        quiet(root)
        self.converge(0)
        (root / "wallets").mkdir(mode=0o700)
        password = secrets.token_urlsafe(36)
        private_new(root / "wallets/unlock.password", password.encode())
        self.app = WalletApp(root, "withdrawal-qa", sponsor_password_file=self.hot_password)
        alice = self.app.action({"action": "create", "password": password})
        self.app.action({"action": "ack-backup", "password": password})
        bob = self.wallet("init", "bob", ["--backup", str(root / "wallets/bob.seed-backup.json")])
        self.public = {"alice": alice["public_address"], "bob": bob["public_address"]}
        atomic_json(root / "public-test-addresses.json", self.public)
        self.app.action({"action": "fund", "password": password})
        self.command(self.wallet_args("withdraw", "alice", self.sponsor("dust-rejected-0001") + ["--amount", "1"]), "at least")
        self.command(self.wallet_args("withdraw", "alice", self.sponsor("operator-rejected-0001") + ["--amount", "1000000", "--to", load(root)["roles"]["sponsor"]]), "operator")
        if len(self.journal()["requests"]) != 1:
            raise RuntimeError("invalid withdrawal consumed sponsor allowance")
        self.event("dust_and_operator_destination_rejected_without_reservation", public_addresses=self.public)

        server = ThreadingHTTPServer(("127.0.0.1", 8769), Handler)
        server.authority = "127.0.0.1:8769"
        server.app = self.app
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.services.append((server, thread))
        browser = subprocess.run(["node", str(PROJECT / "tools/withdraw_browser_test.cjs"), str(root), str(self.evidence)],
                                 input=json.dumps({"password": password, "public_address": self.public["alice"]}),
                                 capture_output=True, text=True, env=dict(self.env, PLAYWRIGHT_MODULE=self.browser_module), timeout=240)
        (root / "withdraw-browser.log").write_text(browser.stdout + browser.stderr)
        if browser.returncode:
            raise RuntimeError("withdrawal browser acceptance failed; see withdraw-browser.log")
        self.assert_balances(4_000_000, 0, 1_000_000, 0)
        self.event("real_mobile_withdrawal_and_review", result=json.loads((root / "withdraw-browser-result.json").read_text()))

        self.after_browser(password)

    def resume_before_upload(self):
        root = self.root
        saved = json.loads((root / "withdrawal-result.json").read_text())
        if saved.get("status") != "failed" or saved["events"][-1]["kind"] != "real_mobile_withdrawal_and_review":
            raise RuntimeError("resume requires the preserved failure immediately after browser acceptance")
        self.hot_password = PROJECT / ".local" / ("operator-" + root.name) / "sponsor.password"
        self.app = WalletApp(root, "withdrawal-qa", sponsor_password_file=self.hot_password)
        if len(self.journal()["requests"]) != 2 or self.journal()["reserved"] != 300_000_000:
            raise RuntimeError("resume must preserve exactly the two completed reservations")
        if Path(str(self.app.wallet) + ".pending.json").exists() or Path(str(self.app.wallet) + ".staging.json").exists():
            raise RuntimeError("resume requires the completed browser withdrawal, with no newer upload")
        self.public = json.loads((root / "public-test-addresses.json").read_text())
        self.result = saved
        self.result["status"] = "running"
        prior = self.result.pop("error")
        from replay_localnet import plan
        barrier = max(plan(root, i)["highest_stored_slot"] for i in [0, 1])
        replay = prepare_restart(root)
        for i in [0, 1]:
            self.children[i] = start(root, i, coordinated=True)
            wait_rpc(root, i)
        quiet(root)
        self.converge(barrier)
        self.assert_balances(4_000_000, 0, 1_000_000, 0)
        self.event("preserved_run_resumed_without_budget_reset", prior_error=prior, offline_tail_replay=replay)
        self.after_browser((root / "wallets/unlock.password").read_text())

    def after_browser(self, password):
        root = self.root
        child = self.launch_wallet("withdraw", "alice", "alice-upload-crash-0001", 1_000_000)
        staged_path = Path(str(self.app.wallet) + ".staging.json")
        def live_upload():
            if child.poll() is not None:
                self.fail_child(child)
            try:
                state = json.loads(staged_path.read_text())
                if account(0, state["staging_account"], "confirmed"):
                    return state
            except (FileNotFoundError, json.JSONDecodeError):
                return None
        staged = self.wait_for(live_upload)
        self.kill_client(child)
        if Path(str(self.app.wallet) + ".pending.json").exists():
            raise RuntimeError("upload crash missed pre-finalization window")
        self.assert_balances(4_000_000, 0, 1_000_000, 0)
        self.event("withdrawal_upload_sigkill", original_request=staged["sponsor_request_id"], staging_account=staged["staging_account"])
        self.pay("deposit", "bob", 5_000_000, "bob-deposit-0001")

        pending_path = root / "wallets/bob.wallet.json.pending.json"
        proxy = LostAcknowledgement(pending_path)
        try:
            args = self.wallet_args("withdraw", "bob", self.sponsor("bob-lost-ack-0001") + ["--amount", "1000000"])
            args[args.index("--rpc") + 1] = "http://127.0.0.1:24899"
            child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
            self.wallet_children.append(child)
            self.wait_for(lambda: proxy.reached.is_set() or (child.poll() is not None and self.fail_child(child)))
            self.kill_client(child)
            if not pending_path.exists():
                raise RuntimeError("finalized withdrawal was acknowledged before crash")
        finally:
            proxy.close()
        self.after_lost_ack(password, staged)

    def resume_after_lost_ack(self):
        root = self.root
        saved = json.loads((root / "withdrawal-result.json").read_text())
        self.hot_password = PROJECT / ".local" / ("operator-" + root.name) / "sponsor.password"
        self.app = WalletApp(root, "withdrawal-qa", sponsor_password_file=self.hot_password)
        if saved.get("status") != "failed" or len(self.journal()["requests"]) != 5 or self.journal()["reserved"] != 750_000_000:
            raise RuntimeError("resume requires the preserved five-reservation lost-ack case")
        pending_path = root / "wallets/bob.wallet.json.pending.json"
        pending = json.loads(pending_path.read_text())
        self.public = json.loads((root / "public-test-addresses.json").read_text())
        if pending.get("withdrawal") != {"amount": 1_000_000, "recipient": self.public["bob"], "sponsor": load(root)["roles"]["sponsor"]}:
            raise RuntimeError("original lost-ack withdrawal intent was not preserved")
        # Correct only the test's replacement file mode, keeping original bytes.
        pending_path.chmod(0o600)
        staged = json.loads(Path(str(self.app.wallet) + ".staging.json").read_text())
        if staged["sponsor_request_id"] != "alice-upload-crash-0001":
            raise RuntimeError("original interrupted upload is missing")
        self.result = saved
        self.result["status"] = "running"
        prior = self.result.pop("error")
        from replay_localnet import plan
        barrier = max(plan(root, i)["highest_stored_slot"] for i in [0, 1])
        replay = prepare_restart(root)
        for i in [0, 1]:
            self.children[i] = start(root, i, coordinated=True)
            wait_rpc(root, i)
        quiet(root)
        self.converge(barrier)
        self.event("preserved_lost_ack_case_resumed", prior_error=prior, offline_tail_replay=replay)
        self.after_lost_ack((root / "wallets/unlock.password").read_text(), staged)

    def after_lost_ack(self, password, staged):
        root = self.root
        pending_path = root / "wallets/bob.wallet.json.pending.json"
        staged_path = Path(str(self.app.wallet) + ".staging.json")
        pending_bytes = pending_path.read_bytes()
        pending = json.loads(pending_bytes)
        if pending["withdrawal"] != {"amount": 1_000_000, "recipient": self.public["bob"], "sponsor": load(root)["roles"]["sponsor"]}:
            raise RuntimeError("pending withdrawal intent is incomplete")
        changed = json.loads(pending_bytes)
        changed["withdrawal"]["recipient"] = self.public["alice"]
        temporary = pending_path.with_suffix(".intent-test.tmp")
        private_new(temporary, json.dumps(changed).encode())
        temporary.replace(pending_path)
        try:
            self.command(self.wallet_args("resolve", "bob"), "saved recipient")
            if not pending_path.exists():
                raise RuntimeError("intent mismatch deleted recovery journal")
        finally:
            pending_path.write_bytes(pending_bytes)
        self.assert_balances(4_000_000, 4_000_000, 1_000_000, 1_000_000)
        self.event("finalized_withdrawal_sigkill_and_intent_tamper_rejection", receipt=pending["withdrawal"], signature=pending["signature"])

        expected = durable(root, 0)
        barrier = max(self.slots("processed"))
        crash = crash_owned(root, 1, self.children[1])
        self.children[1] = start(root, 1)
        wait_rpc(root, 1)
        self.converge(barrier, expected)
        self.event("abrupt_validator_crash_rejoin", crash=crash, exact_native_accounts=len(expected))
        barrier = max(self.slots("processed"))
        for index in [1, 0]:
            stop(root, index)
        replay = prepare_restart(root)
        for index in [0, 1]:
            self.children[index] = start(root, index, coordinated=True)
            wait_rpc(root, index)
        quiet(root)
        self.converge(barrier, expected)
        if not pending_path.exists() or not staged_path.exists():
            raise RuntimeError("restart lost unresolved withdrawal/upload journals")
        self.assert_balances(4_000_000, 4_000_000, 1_000_000, 1_000_000)
        self.event("coordinated_majority_restart", exact_native_accounts=len(expected), offline_tail_replay=replay)
        self.snapshot_and_finish(password, staged, pending, expected)

    @staticmethod
    def fail_child(child):
        out, err = child.communicate(timeout=5)
        raise RuntimeError(f"wallet exited before lost-ack crash: {out} {err}")

    def snapshot_and_finish(self, password, staged, pending, expected):
        root = self.root
        self.archive()
        barrier = max(self.slots("processed"))
        stop(root, 1)
        self.wait_for(lambda: newer_full_snapshot(ledger(root, 0), barrier), timeout=150)
        snapshot = prepare_snapshot_recovery(root, "ledger-recovered-w", barrier)
        (root / "active-ledger-1.json").write_text(json.dumps(snapshot["fresh_ledger"]))
        self.children[1] = start(root, 1, archive=True)
        wait_rpc(root, 1)
        self.converge(barrier, expected)
        log = (root / "validator-1.log").read_text()
        if "Loading bank from full snapshot archive:" not in log or snapshot["archive"] not in log:
            raise RuntimeError("missing forced snapshot recovery evidence")
        self.archive()
        # Retained history restores notes, but must never decide unknown-payment acceptance.
        self.command(self.wallet_args("resolve", "bob", index=1), "history")
        pending_path = root / "wallets/bob.wallet.json.pending.json"
        if not pending_path.exists():
            raise RuntimeError("pruned peer incorrectly resolved unknown withdrawal")
        resolved = self.wallet("resolve", "bob")
        if not resolved["accepted"] or resolved["withdrawal"] != pending["withdrawal"] or pending_path.exists():
            raise RuntimeError("canonical recovery did not return the exact finalized recipient")
        self.wallet("reclaim", "bob", self.sponsor())
        self.closed(pending["staging_account"])
        self.assert_balances(4_000_000, 4_000_000, 1_000_000, 1_000_000, history=True)
        self.event("snapshot_and_canonical_unknown_withdrawal_recovery", snapshot=snapshot, resolved=resolved)
        extra = self.sponsor("bob-after-restart-0001") + ["--amount", "1000000", "--to", self.public["alice"], "--history", str(root / "recovery-history")]
        receipt = self.wallet("withdraw", "bob", extra, index=1)
        if not receipt["staging_rent_reclaimed"] or receipt["withdrawal"]["recipient"] != self.public["alice"]:
            raise RuntimeError("post-recovery explicit-recipient withdrawal did not finalize correctly")
        self.archive()
        if len(self.journal()["requests"]) != 6 or self.journal()["reserved"] != 900_000_000:
            raise RuntimeError("unexpected durable sponsor reservation count")
        reclaim = self.app.action({"action": "reclaim", "password": password})
        if not reclaim["rent_reclaimed"]:
            raise RuntimeError("original interrupted upload could not recover after global cap")
        self.closed(staged["staging_account"])
        self.assert_balances(4_000_000, 3_000_000, 2_000_000, 1_000_000, history=True)
        self.wallet("restore", "alice", ["--backup", str(self.app.backup)], restored=True)
        restored = self.wallet("balance", "alice", ["--history", str(root / "recovery-history")], index=1, restored=True)
        if restored["public_address"] != self.public["alice"] or restored["balance"] != 4_000_000:
            raise RuntimeError("seed/history restore lost user-controlled withdrawal authority or notes")
        self.finish_control()

    def resume_after_payments(self):
        root = self.root
        saved = json.loads((root / "withdrawal-result.json").read_text())
        self.hot_password = PROJECT / ".local" / ("operator-" + root.name) / "sponsor.password"
        self.app = WalletApp(root, "withdrawal-qa", sponsor_password_file=self.hot_password)
        if saved.get("status") != "failed" or len(self.journal()["requests"]) != 6 or self.journal()["reserved"] != 900_000_000 or "Transaction simulation failed: Blockhash not found" not in saved.get("error", ""):
            raise RuntimeError("resume requires the preserved six-reservation completed-payment case")
        self.public = json.loads((root / "public-test-addresses.json").read_text())
        if any(root.glob("wallets/*.pending.json")) or any(root.glob("wallets/*.staging.json")) or Path(str(self.app.wallet) + ".staging.json").exists():
            raise RuntimeError("payment recovery must already be complete")
        self.result = saved
        self.result["status"] = "running"
        prior = self.result.pop("error")
        from replay_localnet import plan
        barrier = max(plan(root, i)["highest_stored_slot"] for i in [0, 1])
        replay = prepare_restart(root)
        for i in [0, 1]:
            self.children[i] = start(root, i, coordinated=True)
            wait_rpc(root, i)
        quiet(root)
        self.converge(barrier)
        # Never repeat an unknown user transfer: require the exact pre-transfer
        # balances on both peers and the already-restored public authority.
        self.assert_balances(4_000_000, 3_000_000, 2_000_000, 1_000_000, history=True)
        restored = self.wallet("address", "alice", restored=True)
        if restored["public_address"] != self.public["alice"]:
            raise RuntimeError("restored public signer differs")
        self.event("preserved_completed_payments_resumed", prior_error=prior, offline_tail_replay=replay)
        self.finish_control()

    def finish_control(self):
        root = self.root
        transfer = self.command([str(LAB), "owner-transfer-check", str(root), str(root / "wallets/alice-restored.wallet.json"),
                                 str(root / "wallets/unlock.password"), self.public["bob"], "10000", "http://127.0.0.1:18899"])
        self.wait_for(lambda: rpc(port(0), "getBalance", [self.public["bob"], {"commitment": "finalized"}])["value"] == 1_010_000)
        self.assert_balances(4_000_000, 3_000_000, 1_985_000, 1_010_000, history=True)
        final = durable(root, 0)
        self.converge(max(self.slots()) - 8, final)
        if len(final) != 11:
            raise RuntimeError("expected pool plus ten permanent nullifier accounts")
        roles = load(root)["roles"]
        signatures = rpc(port(0), "getSignaturesForAddress", [roles["sponsor"], {"commitment": "finalized", "limit": 1000}])
        transactions = [rpc(port(0), "getTransaction", [item["signature"], {"encoding": "json", "commitment": "finalized", "maxSupportedTransactionVersion": 0}]) for item in signatures]
        if any(tx is None or tx["meta"]["err"] for tx in transactions):
            raise RuntimeError("sponsor transaction history incomplete or failed")
        fees = sum(tx["meta"]["fee"] for tx in transactions)
        marker_rent = rpc(port(0), "getMinimumBalanceForRentExemption", [40])
        sponsor_balance = rpc(port(0), "getBalance", [roles["sponsor"], {"commitment": "finalized"}])["value"]
        if 1_000_000_000 - sponsor_balance != 10_000_000 + fees + 10 * marker_rent:
            raise RuntimeError("sponsor received withdrawal value or fees/rent do not reconcile")
        if rpc(port(0), "getBalance", [roles["treasury"], {"commitment": "finalized"}])["value"] != 10_000_000_000:
            raise RuntimeError("offline treasury changed")
        self.result.update(status="passed", accepted_payments=5, permanent_nullifiers=10, pool_private_backing=7_000_000,
                           public_balances={"alice": 1_985_000, "bob": 1_010_000}, private_balances={"alice": 4_000_000, "bob": 3_000_000},
                           user_signed_public_transfer=transfer, sponsor_balance=sponsor_balance, sponsor_fees=fees,
                           sponsor_permanent_rent=10 * marker_rent, lifetime_reserved=self.journal()["reserved"], treasury_untouched=True)
        self.event("withdrawal_acceptance_passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--playwright-module", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    resume = parser.add_mutually_exclusive_group()
    resume.add_argument("--resume-before-upload-crash", action="store_true")
    resume.add_argument("--resume-after-lost-ack", action="store_true")
    resume.add_argument("--resume-after-payments", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data") or (root.exists() and not (args.resume_before_upload_crash or args.resume_after_lost_ack or args.resume_after_payments)):
        parser.error("use a new short local directory under .data; preserved runs are never replaced")
    trial = WithdrawalExperiment(root, args.playwright_module, args.evidence.resolve())
    try:
        if args.resume_before_upload_crash:
            trial.resume_before_upload()
        elif args.resume_after_payments:
            trial.resume_after_payments()
        elif args.resume_after_lost_ack:
            trial.resume_after_lost_ack()
        else:
            trial.run()
    except Exception as error:
        trial.result.update(status="failed", error=str(error))
        raise
    finally:
        for child in trial.wallet_children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
        for server, thread in trial.services:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
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
            atomic_json(root / "withdrawal-result.json", trial.result)
        if errors:
            raise RuntimeError("owned validator cleanup failed")


if __name__ == "__main__":
    main()
