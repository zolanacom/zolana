#!/usr/bin/env python3
"""Local-only key ceremony, sponsor crash/recovery and real payment acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import time

from fault_localnet import Experiment, WALLET, account, atomic_json, durable
from localnet import LAB, PROJECT, load, port, quiet, rpc, start, stop, wait_rpc
from wallet_localnet import private_new
from wallet_ui import WalletApp
from replay_localnet import plan, prepare as prepare_restart


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SponsorExperiment(Experiment):
    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "sponsor-result.json", self.result)
        print(kind, flush=True)

    def wallet_args(self, action, who, extra=(), index=0, restored=False):
        args = super().wallet_args(action, who, extra, index, restored)
        if who == "alice" and not restored:
            args[args.index("--wallet") + 1] = str(self.app.wallet)
        return args

    def command(self, args, reject=None):
        result = subprocess.run(args, capture_output=True, text=True, env=self.env, timeout=180)
        if reject is not None:
            if result.returncode == 0 or result.stdout.strip() or reject not in result.stderr:
                raise RuntimeError(f"expected {reject!r}: {result.stdout} {result.stderr}")
            return result.stderr.strip()
        if result.returncode:
            raise RuntimeError(result.stderr)
        return json.loads(result.stdout)

    def sponsor(self, request=None):
        extra = ["--sponsor-password-file", str(self.hot_password)]
        if request:
            extra += ["--sponsor-request-id", request]
        return extra

    def journal(self):
        return json.loads((self.root / "sponsor-policy.json.reservations.json").read_text())

    def launch_wallet(self, action, who, request, amount, to=None):
        extra = self.sponsor(request) + ["--amount", str(amount)]
        if to:
            extra += ["--to", to]
        child = subprocess.Popen(self.wallet_args(action, who, extra), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=self.env, text=True)
        self.wallet_children.append(child)
        return child

    def wait_for(self, predicate, timeout=150):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.02)
        raise RuntimeError("bounded acceptance condition timed out")

    def kill_client(self, child):
        if child not in self.wallet_children or child.poll() is not None:
            raise RuntimeError("wallet crash target is not a live owned child")
        child.kill()
        child.communicate(timeout=10)
        if child.returncode != -9:
            raise RuntimeError("wallet did not exit by SIGKILL")

    def run(self):
        root = self.root
        operator = PROJECT / ".local" / ("operator-" + root.name)
        operator.mkdir(mode=0o700)
        cold_password = operator / "cold.password"
        self.hot_password = operator / "sponsor.password"
        for path in [cold_password, self.hot_password]:
            private_new(path, secrets.token_urlsafe(36).encode())
        init_args = [str(LAB), "init-private", str(root), "--cold-password-file", str(cold_password),
                     "--sponsor-password-file", str(self.hot_password)]
        self.command(init_args)
        config = load(root)
        roles = config["roles"]
        if len(roles) != 14 or len(set(roles.values())) != 14 or config["fixture_keys_are_public"]:
            raise RuntimeError("rehearsal did not separate fourteen private roles")
        expected_hot = {f"{role}-{i}.keypair.json" for i in [0, 1] for role in ["identity", "voter"]}
        if {p.name for p in root.glob("*.keypair.json")} != expected_hot:
            raise RuntimeError("unexpected plaintext operator keys")
        for path in [root, *root.glob("*.keypair.json"), *root.glob("*.enc.json"), root / "sponsor-policy.json"]:
            if path.stat().st_mode & 0o077:
                raise RuntimeError("operator material permissions are too broad")
        self.command(init_args, "refusing to replace")
        restore = [str(LAB), "restore-hot", str(root), "--cold-password-file", str(cold_password)]
        self.command(restore[:-1] + [str(self.hot_password)], "incorrect operator password")
        preserved = root / "preserved-hot"
        preserved.mkdir(mode=0o700)
        before = {name: sha(root / name) for name in expected_hot}
        for name in ["identity-1.keypair.json", "voter-1.keypair.json"]:
            (root / name).rename(preserved / name)
        recovered = self.command(restore)
        if recovered["restored_hot_files"] != 2 or any(sha(root / name) != value for name, value in before.items()):
            raise RuntimeError("hot recovery did not restore the exact original identity/voter")
        if self.command(restore)["restored_hot_files"] != 0:
            raise RuntimeError("hot recovery replaced existing material")
        self.event("encrypted_ceremony_and_hot_recovery", distinct_roles=14, restored=recovered,
                   no_plaintext_cold_or_sponsor_keys=True)

        for index in [0, 1]:
            self.children[index] = start(root, index)
            wait_rpc(root, index)
        quiet(root)
        self.converge(0)
        (root / "wallets").mkdir(mode=0o700)
        password = secrets.token_urlsafe(36)
        private_new(root / "wallets/unlock.password", password.encode())
        self.app = WalletApp(root, "operator-qa", sponsor_password_file=self.hot_password)
        addresses = {"alice": self.app.action({"action": "create", "password": password})["address"]}
        self.app.action({"action": "ack-backup", "password": password})
        for who in ["bob", "carol", "dave"]:
            addresses[who] = self.wallet("init", who, ["--backup", str(root / "wallets" / f"{who}.seed-backup.json")])["address"]
        self.command(self.wallet_args("deposit", "bob", ["--sponsor", "forbidden", "--amount", "100"]), "plaintext sponsor override")
        self.command(self.wallet_args("deposit", "bob", ["--sponsor-password-file", str(cold_password),
                     "--sponsor-request-id", "wrong-password-request", "--amount", "100"]), "incorrect operator password")
        self.command(self.wallet_args("deposit", "bob", self.sponsor("over-limit-request") + ["--amount", "101"]), "exceeds policy")
        self.command(self.wallet_args("withdraw", "alice", self.sponsor("withdraw-request-denied") + ["--amount", "1"]), "withdrawals are not sponsored")
        self.command(self.wallet_args("deposit", "bob", self.sponsor("bad-address-request-0001") + ["--amount", "100", "--to", "npriv11111"]), "receiving address")
        self.command(self.wallet_args("send", "bob", self.sponsor("empty-wallet-request-0001") + ["--amount", "1", "--to", addresses["alice"]]), "insufficient value")
        if self.journal()["reserved"]:
            raise RuntimeError("rejected requests consumed a reservation")
        receipts = []
        receipts.append(self.app.action({"action": "fund", "password": password}))
        receipts.append(self.app.action({"action": "send", "password": password, "amount": 7, "recipient": addresses["bob"]}))
        receipts.append(self.wallet("send", "bob", self.sponsor("bob-send-request-0001") + ["--amount", "2", "--to", addresses["alice"]]))
        self.balances(95, 5, indices=(0, 1))
        self.event("guarded_ui_and_rpc_payments", accepted_payments=3, balances={"alice": 95, "bob": 5}, receipts=receipts)

        # Hold the shared sponsor lock while another wallet tries to obtain funds.
        crash_id = "alice-crash-request-0001"
        child = self.launch_wallet("send", "alice", crash_id, 1, addresses["bob"])
        self.wait_for(lambda: len(self.journal()["requests"]) == 4)
        self.command(self.wallet_args("deposit", "bob", self.sponsor("concurrent-request-0001") + ["--amount", "100"]), "cannot lock wallet operation")
        staged_path = Path(str(self.app.wallet) + ".staging.json")
        def staged_live():
            try:
                staged = json.loads(staged_path.read_text())
            except (FileNotFoundError, json.JSONDecodeError):
                return None
            return staged if account(0, staged["staging_account"], "confirmed") else None
        staged = self.wait_for(staged_live)
        self.kill_client(child)
        if Path(str(self.app.wallet) + ".pending.json").exists() or staged["sponsor_request_id"] != crash_id:
            raise RuntimeError("client crash missed the bounded pre-finalization upload window")
        self.command(self.wallet_args("send", "alice", self.sponsor("alice-per-wallet-limit") + ["--amount", "1", "--to", addresses["bob"]]), "unfinished staging")
        self.event("upload_sigkill_and_cross_wallet_lock", sponsor_reserved=self.journal()["reserved"], staging_account=staged["staging_account"])

        # Stop and restore the encrypted sponsor; preserve the original journal/towers.
        expected = durable(root, 0)
        barrier = max(self.slots("processed"))
        for index in [1, 0]:
            stop(root, index)
        original_ledger = sha(root / "sponsor-policy.json.reservations.json")
        (root / "sponsor.enc.json").rename(root / "sponsor-original.enc.json")
        self.hot_password.rename(operator / "sponsor-original.password")
        private_new(self.hot_password, secrets.token_urlsafe(36).encode())
        sponsor_restored = self.command([str(LAB), "restore-sponsor", str(root), "--cold-password-file", str(cold_password),
                                         "--sponsor-password-file", str(self.hot_password)])
        if sha(root / "sponsor-policy.json.reservations.json") != original_ledger or sponsor_restored["policy_reset"]:
            raise RuntimeError("sponsor recovery reset reservations")
        self.command(restore)
        self.finish(addresses, password, staged, expected, barrier, sponsor_restored)

    def resume_restart(self):
        root = self.root
        self.result = json.loads((root / "sponsor-result.json").read_text())
        if self.result.get("status") != "failed" or len(self.journal()["requests"]) != 4 or self.journal()["reserved"] != 600_000_000:
            raise RuntimeError("resume requires the preserved four-reservation restart failure")
        previous_error = self.result.pop("error", "")
        self.result["status"] = "running"
        self.hot_password = PROJECT / ".local" / ("operator-" + root.name) / "sponsor.password"
        self.app = WalletApp(root, "operator-qa", sponsor_password_file=self.hot_password)
        password = (root / "wallets/unlock.password").read_text()
        addresses = {who:self.wallet("address", who)["address"] for who in ["alice","bob","carol","dave"]}
        staged = json.loads(Path(str(self.app.wallet)+".staging.json").read_text())
        if staged.get("sponsor_request_id") != "alice-crash-request-0001" or Path(str(self.app.wallet)+".pending.json").exists():
            raise RuntimeError("preserved interrupted upload does not match this rehearsal")
        states = [plan(root,i) for i in [0,1]]
        barrier = max(state["highest_stored_slot"] for state in states)
        self.command([str(LAB),"restore-hot",str(root),"--cold-password-file",str(self.hot_password.parent / "cold.password")])
        evidence = [json.loads(p.read_text()) for p in root.glob("tail-replay-*/result.json")]
        self.event("resume_preserved_restart", previous_error=previous_error, offline_replay=evidence)
        self.finish(addresses,password,staged,None,barrier,{"encrypted_sponsor_restored":True,"policy_reset":False})

    def finish(self, addresses, password, staged, expected, barrier, sponsor_restored):
        root = self.root
        roles = load(root)["roles"]
        staged_path = Path(str(self.app.wallet)+".staging.json")
        crash_id = staged["sponsor_request_id"]
        repair = prepare_restart(root)
        if repair["replayed"]:
            self.event("verified_offline_tail_replay", result=repair)
        for index in [0, 1]:
            self.children[index] = start(root, index, coordinated=True)
            wait_rpc(root, index)
        roots = self.converge(barrier, expected)
        if not staged_path.exists() or account(0, staged["staging_account"]) is None:
            raise RuntimeError("restart lost the original staging recovery")
        self.balances(95, 5, indices=(0, 1))
        if len(durable(root,0)) != 7 or durable(root,0) != durable(root,1):
            raise RuntimeError("restart lost the original pool or six permanent nullifiers")
        self.event("restart_and_encrypted_sponsor_recovery", finalized_slots=roots, restored=sponsor_restored,
                   exact_native_state_retained=True, interrupted_upload_still_recoverable=True)

        # Crash after reservation but before any upload; neither death nor a new
        # seed-file copy may make the same request available again.
        child = self.launch_wallet("deposit", "carol", "carol-reserve-crash-0001", 100)
        self.wait_for(lambda: len(self.journal()["requests"]) == 5)
        self.kill_client(child)
        if Path(str(root / "wallets/carol.wallet.json") + ".staging.json").exists() or self.journal()["requests"][-1]["charged"] != 0:
            raise RuntimeError("reservation-only crash missed its pre-upload window")
        self.wallet("restore", "carol", ["--backup", str(root / "wallets/carol.seed-backup.json")], restored=True)
        self.command(self.wallet_args("deposit", "carol", self.sponsor("carol-reserve-crash-0001") + ["--amount", "100"], restored=True), "already reserved")
        receipt = self.wallet("deposit", "carol", self.sponsor("carol-final-request-0001") + ["--amount", "100"])
        self.closed(receipt["staging_account"])
        self.command(self.wallet_args("deposit", "dave", self.sponsor("global-limit-request-0001") + ["--amount", "100"]), "lifetime allowance exhausted")
        self.event("reservation_crash_duplicates_and_global_cap", reserved=self.journal()["reserved"], requests=len(self.journal()["requests"]))
        reclaimed = self.app.action({"action": "reclaim", "password": password})
        self.closed(staged["staging_account"])
        if len(self.journal()["requests"]) != 6 or not reclaimed["rent_reclaimed"]:
            raise RuntimeError("cleanup did not use the original surviving reservation after the global cap")
        self.command(self.wallet_args("send", "alice", self.sponsor(crash_id) + ["--amount", "1", "--to", addresses["bob"]]), "already reserved")
        self.command(self.wallet_args("send", "alice", self.sponsor("alice-per-wallet-limit") + ["--amount", "1", "--to", addresses["bob"]]), "wallet sponsor allowance exhausted")
        self.event("original_reservation_cleanup_after_global_exhaustion", reclaimed=reclaimed, requests=6)

        final = durable(root, 0)
        self.converge(max(self.slots()) - 8, final)
        if final != durable(root, 1) or len(final) != 9:
            raise RuntimeError("expected identical pool and eight permanent nullifiers")
        self.balances(95, 5, indices=(0, 1))
        if self.wallet("balance", "carol")["balance"] != 100:
            raise RuntimeError("final sponsored deposit was lost")
        sponsor = roles["sponsor"]
        signatures = rpc(port(0), "getSignaturesForAddress", [sponsor, {"commitment": "finalized", "limit": 1000}])
        transactions = [rpc(port(0), "getTransaction", [item["signature"], {"encoding": "json", "commitment": "finalized", "maxSupportedTransactionVersion": 0}]) for item in signatures]
        if not transactions or any(tx is None or tx["meta"]["err"] for tx in transactions):
            raise RuntimeError("sponsor transaction history is incomplete or failed")
        fees = sum(tx["meta"]["fee"] for tx in transactions)
        marker_rent = rpc(port(0), "getMinimumBalanceForRentExemption", [40])
        balance = rpc(port(0), "getBalance", [sponsor, {"commitment": "finalized"}])["value"]
        if 1_000_000_000 - balance != fees + 8 * marker_rent + 200:
            raise RuntimeError("sponsor balance does not reconcile with fees, permanent rent and deposits")
        journal = self.journal()
        if journal["reserved"] != 900_000_000 or any(r["charged"] > r["allowance"] for r in journal["requests"]):
            raise RuntimeError("durable sponsor cap was exceeded")
        treasury = rpc(port(0), "getBalance", [roles["treasury"], {"commitment": "finalized"}])["value"]
        if treasury != 10_000_000_000:
            raise RuntimeError("hot sponsor work spent offline treasury funds")
        self.result.update(status="passed", accepted_payments=4, exact_pool_and_eight_nullifiers=True,
                           sponsor_balance=balance, transaction_fees=fees, permanent_rent=8 * marker_rent,
                           lifetime_reserved=journal["reserved"], gross_charged=sum(r["charged"] for r in journal["requests"]),
                           treasury_untouched=True, sponsor_transactions=len(transactions))
        self.event("sponsor_acceptance_passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--resume-after-restart", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / ".data") or (root.exists() and not args.resume_after_restart):
        parser.error("use a new directory under .data, or explicitly resume the preserved restart case")
    trial = SponsorExperiment(root)
    try:
        trial.resume_restart() if args.resume_after_restart else trial.run()
    except Exception as error:
        trial.result.update(status="failed", error=str(error))
        raise
    finally:
        for child in trial.wallet_children:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
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
            atomic_json(root / "sponsor-result.json", trial.result)
        if errors:
            raise RuntimeError("owned validator cleanup failed")
