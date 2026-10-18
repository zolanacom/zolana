#!/usr/bin/env python3
"""Local user-paid withdrawal acceptance with operator sponsorship unavailable."""
import argparse
import hashlib
import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import secrets
import subprocess
import threading

from fault_localnet import account, atomic_json, crash_owned, durable
from localnet import LAB, PROJECT, load, port, quiet, rpc, start, stop, wait_rpc
from replay_localnet import prepare
from sponsor_localnet import SponsorExperiment
from wallet_localnet import private_new
from wallet_ui import Handler, WalletApp
from withdraw_localnet import LostAcknowledgement


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class UserFees(SponsorExperiment):
    recipient_withdrawals = True

    def __init__(self, root, module, evidence, browser_script):
        super().__init__(root)
        self.module, self.evidence, self.browser_script = module, evidence, browser_script
        self.server = None
        self.thread = None

    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "userfees-result.json", self.result)
        print(kind, flush=True)

    def user_args(self, action, extra=(), index=0, restored=False):
        return self.wallet_args(action, "alice", extra, index=index, restored=restored)

    def user(self, action, extra=(), index=0, restored=False):
        return self.command(self.user_args(action, extra, index, restored))

    def withdrawal(self, index=0, history=False):
        extra = ["--fee-payer", "user", "--max-fee-debit", "150000000", "--amount", "1000000"]
        if history:
            extra += ["--history", str(self.root / "recovery-history")]
        return self.user("withdraw", extra, index=index)

    def check(self, private, public, history=False):
        extra = ["--history", str(self.root / "recovery-history")] if history else []
        for i in [0, 1]:
            value = self.user("balance", extra, index=i)
            if (value["balance"], value["public_balance"], value["fee_address"]) != (private, public, self.fee_address):
                raise RuntimeError("private/public balance or restored fee authority differs")

    def browser(self, phase, password):
        result = subprocess.run(["node", str(self.browser_script), str(self.root), str(self.evidence), phase],
                                input=json.dumps({"password": password, "fee_address": self.fee_address}),
                                capture_output=True, text=True, env=dict(self.env, PLAYWRIGHT_MODULE=self.module), timeout=240)
        (self.root / f"userfees-browser-{phase}.log").write_text(result.stdout + result.stderr)
        if result.returncode:
            raise RuntimeError(f"browser {phase} acceptance failed; see preserved log")
        self.event("browser_" + phase, result=json.loads((self.root / f"userfees-browser-{phase}.json").read_text()))

    def run(self):
        root = self.root
        operator = PROJECT / ".local" / ("operator-" + root.name)
        operator.mkdir(mode=0o700)
        cold = operator / "cold.password"
        self.hot_password = operator / "sponsor.password"
        for p in [cold, self.hot_password]:
            private_new(p, secrets.token_urlsafe(36).encode())
        self.command([str(LAB), "init-private", str(root), "--cold-password-file", str(cold), "--sponsor-password-file", str(self.hot_password)])
        for i in [0, 1]:
            self.children[i] = start(root, i)
            wait_rpc(root, i)
        quiet(root)
        self.converge(0)
        (root / "wallets").mkdir(mode=0o700)
        password = secrets.token_urlsafe(36)
        private_new(root / "wallets/unlock.password", password.encode())
        self.app = WalletApp(root, "user-fees", sponsor_password_file=self.hot_password)
        key = self.app.action({"action": "create", "password": password})
        self.app.action({"action": "ack-backup", "password": password})
        self.fee_address = key["fee_address"]
        self.public_address = key["public_address"]
        self.app.action({"action": "fund", "password": password})
        self.sponsor_baseline = rpc(18899, "getBalance", [load(root)["roles"]["sponsor"], {"commitment": "finalized"}])["value"]
        self.sponsor_files = {}
        for name in ["sponsor.enc.json", "sponsor-policy.json", "sponsor-policy.json.reservations.json"]:
            source = root / name
            self.sponsor_files[name + ".disabled"] = digest(source)
            source.rename(root / (name + ".disabled"))
        # No sponsor credentials supplied to the wallet API for the entire test.
        self.app = WalletApp(root, "user-fees")
        quote = self.user("fees")
        if not quote["funding_shortfall"] or quote["fee_address"] != self.fee_address:
            raise RuntimeError("unfunded fee quote is wrong")
        self.command(self.user_args("withdraw", ["--fee-payer", "user", "--max-fee-debit", "150000000", "--amount", "1000000"]), "fund user fee address")
        self.command(self.user_args("withdraw", ["--fee-payer", "user", "--max-fee-debit", "1", "--amount", "1000000"]), "below the current withdrawal quote")
        self.command(self.user_args("withdraw", ["--fee-payer", "user", "--sponsor-password-file", str(self.hot_password), "--max-fee-debit", "150000000", "--amount", "1000000"]), "cannot be combined")
        if Path(str(self.app.wallet) + ".staging.json").exists():
            raise RuntimeError("preflight failure created an upload")
        self.server = ThreadingHTTPServer(("127.0.0.1", 8769), Handler)
        self.server.authority = "127.0.0.1:8769"
        self.server.app = self.app
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.browser("unfunded", password)
        funding = self.command([str(LAB), "fund-user-fee-check", str(root), str(self.app.wallet), str(root / "wallets/unlock.password"), str(cold), "http://127.0.0.1:18899"])
        self.wait_for(lambda: rpc(18899, "getBalance", [self.fee_address, {"commitment": "finalized"}])["value"] == 300_000_000)
        self.event("user_fee_account_funded_once", funding=funding, operator_sponsor_unavailable=True, quote=quote)
        self.browser("funded", password)
        self.check(4_000_000, 1_000_000)

        args = self.user_args("withdraw", ["--fee-payer", "user", "--max-fee-debit", "150000000", "--amount", "1000000"])
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
        self.wallet_children.append(child)
        stage_path = Path(str(self.app.wallet) + ".staging.json")
        def live_stage():
            if child.poll() is not None:
                out, err = child.communicate(); raise RuntimeError(out + err)
            try:
                record = json.loads(stage_path.read_text())
                return record if account(0, record["staging_account"], "confirmed") else None
            except (FileNotFoundError, json.JSONDecodeError):
                return None
        record = self.wait_for(live_stage)
        self.kill_client(child)
        if Path(str(self.app.wallet) + ".pending.json").exists() or not record.get("user_fee") or record.get("sponsor_request_id"):
            raise RuntimeError("user-paid upload crash journal is wrong")
        self.check(4_000_000, 1_000_000)
        self.command(self.user_args("reclaim", ["--sponsor-password-file", str(self.hot_password)]), "never accepts operator")
        self.user("reclaim")
        self.closed(record["staging_account"])
        self.event("user_upload_sigkill_and_owner_only_reclaim", maximum=record["user_fee"]["maximum"])

        pending = Path(str(self.app.wallet) + ".pending.json")
        proxy = LostAcknowledgement(pending)
        try:
            args[args.index("--rpc") + 1] = "http://127.0.0.1:24899"
            child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)
            self.wallet_children.append(child)
            def finalized():
                if child.poll() is not None:
                    out, err = child.communicate(); raise RuntimeError(out + err)
                return proxy.reached.is_set()
            self.wait_for(finalized)
            self.kill_client(child)
        finally:
            proxy.close()
        if not pending.exists():
            raise RuntimeError("lost acknowledgement did not retain user pending record")
        stage = json.loads(stage_path.read_text())
        charged = stage["user_fee"]["charged"]
        self.check(3_000_000, 2_000_000)
        self.event("user_withdrawal_finalized_ack_sigkill", charged=charged)
        expected = durable(root, 0)
        barrier = max(self.slots("processed"))
        crash = crash_owned(root, 1, self.children[1])
        self.children[1] = start(root, 1)
        wait_rpc(root, 1)
        self.converge(barrier, expected)
        self.event("validator_sigkill_rejoin", crash=crash, native_accounts=len(expected))
        barrier = max(self.slots("processed"))
        for i in [1, 0]: stop(root, i)
        replay = prepare(root)
        for i in [0, 1]:
            self.children[i] = start(root, i, coordinated=True)
            wait_rpc(root, i)
        quiet(root)
        self.converge(barrier, expected)
        if json.loads(stage_path.read_text())["user_fee"]["charged"] != charged:
            raise RuntimeError("restart reset user fee charges")
        resolved = self.user("resolve")
        if not resolved["accepted"] or resolved["withdrawal"]["sponsor"] != self.fee_address:
            raise RuntimeError("canonical recovery changed the user's fee payer")
        self.app.action({"action": "reclaim", "password": password})
        self.closed(stage["staging_account"])
        self.event("majority_restart_and_original_user_cap_recovery", replay=replay, resolved=resolved)
        self.user("restore", ["--backup", str(self.app.backup)], restored=True)
        restored = self.user("address", restored=True)
        if restored["fee_address"] != self.fee_address:
            raise RuntimeError("seed backup did not restore the fee authority")
        last = self.command(self.user_args("withdraw", ["--fee-payer", "user", "--max-fee-debit", "150000000", "--amount", "1000000"], restored=True))
        self.closed(last["staging_account"])
        self.check(2_000_000, 3_000_000)
        self.finish(last)

    def finish(self, last):
        root = self.root
        state = durable(root, 0)
        self.converge(max(self.slots()) - 8, state)
        if len(state) != 9:
            raise RuntimeError("expected pool plus eight nullifiers for four accepted native payments")
        signatures = rpc(18899, "getSignaturesForAddress", [self.fee_address, {"commitment": "finalized", "limit": 1000}])
        transactions = [rpc(18899, "getTransaction", [item["signature"], {"encoding": "json", "commitment": "finalized", "maxSupportedTransactionVersion": 0}]) for item in signatures]
        fees = 0
        for tx in transactions:
            if tx is None or tx["meta"]["err"]:
                raise RuntimeError("user-paid history is missing or failed")
            message = tx["transaction"]["message"]
            if message["accountKeys"][0] == self.fee_address:
                fees += tx["meta"]["fee"]
                if set(load(root)["roles"].values()).intersection(message["accountKeys"]):
                    raise RuntimeError("withdrawal depended on an operator authority")
        marker_rent = rpc(18899, "getMinimumBalanceForRentExemption", [40])
        balance = rpc(18899, "getBalance", [self.fee_address, {"commitment": "finalized"}])["value"]
        if 300_000_000 - balance != fees + 6 * marker_rent:
            raise RuntimeError("user fees/rent do not reconcile after all refunds")
        if rpc(18899, "getBalance", [load(root)["roles"]["sponsor"], {"commitment": "finalized"}])["value"] != self.sponsor_baseline:
            raise RuntimeError("operator sponsor paid for a user withdrawal")
        if any(digest(root / name) != value for name, value in self.sponsor_files.items()):
            raise RuntimeError("disabled sponsor vault/policy/journal changed")
        self.result.update(status="passed", accepted_native_payments=4, permanent_nullifiers=8, private_balance=2_000_000,
                           public_balance=3_000_000, user_fee_balance=balance, user_transaction_fees=fees,
                           user_permanent_rent=6 * marker_rent, sponsor_unchanged=True, operator_credentials_unavailable=True,
                           last_receipt=last)
        self.event("user_paid_fee_acceptance_passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--playwright-module", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--browser-script", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data") or root.exists(): parser.error("use a new short .data root")
    trial = UserFees(root, args.playwright_module, args.evidence.resolve(), args.browser_script.resolve())
    try:
        trial.run()
    except Exception as error:
        trial.result.update(status="failed", error=str(error))
        raise
    finally:
        for child in trial.wallet_children:
            if child.poll() is None: child.kill(); child.communicate(timeout=10)
        if trial.server:
            trial.server.shutdown(); trial.server.server_close(); trial.thread.join(timeout=5)
        errors = []
        for i in [1, 0]:
            if trial.children[i] is not None and trial.children[i].poll() is None:
                try: stop(root, i)
                except Exception as error: errors.append(str(error))
        if errors: trial.result.update(status="failed", cleanup_errors=errors)
        if root.exists(): atomic_json(root / "userfees-result.json", trial.result)
        if errors: raise RuntimeError("owned validator cleanup failed")
