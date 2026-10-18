#!/usr/bin/env python3
"""Sponsor-free private-send acceptance on a new private loopback rehearsal."""
import argparse
import base64
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading

from fault_localnet import account, atomic_json, crash_owned, durable
from localnet import LAB, PROJECT, load, quiet, rpc, start, stop, wait_rpc
from package_wallet import public_profile
from replay_localnet import prepare
from restart_localnet import capture_public_payment
from sponsor_localnet import SponsorExperiment
from wallet_localnet import private_new
from wallet_ui import Handler, WalletApp
from withdraw_localnet import LostAcknowledgement


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_checkpoint(root, kind):
    """Reject incompatible/completed runs before entering mutation/cleanup paths."""
    previous=json.loads((root/"private-send-result.json").read_text())
    original="Wallet error: missing --rpc\n"
    if kind=="setup":
        allowed=[original,"wallet balance: Wallet error: finalized history does not reach the pool checkpoint; archive history is required\n"]
        matches=previous.get("error") in allowed and not previous.get("events") and (previous.get("error")==original or previous.get("resumed_pre_deposit_error")==original)
    else:
        matches=kind=="upload" and "expected 'never accepts operator'" in previous.get("error","") and [e["kind"] for e in previous.get("events",[])]==["browser_unfunded","browser_funded"]
    if previous.get("status")!="failed" or not matches:
        raise ValueError("resume requires its exact preserved failed checkpoint; running/completed evidence is never overwritten")
    return previous


class PrivateSends(SponsorExperiment):
    recipient_withdrawals = True

    def __init__(self, root, module, evidence, browser_script):
        super().__init__(root)
        self.module, self.evidence, self.browser_script = module, evidence, browser_script
        self.server = self.thread = None
        self.clients, self.keys = {}, {}

    def event(self, kind, **fields):
        self.result["events"].append({"kind": kind, **fields})
        atomic_json(self.root / "private-send-result.json", self.result)
        print(kind, flush=True)

    def wallet_args(self, action, who, extra=(), index=0, restored=False):
        path = self.root / "wallets" / f"{who}-restored.wallet.json" if restored else self.clients[who].wallet
        return [str(PROJECT / "target/debug/native-wallet"), action, "--network", str(self.profiles[index]),
                "--wallet", str(path), "--password-file", str(self.root / "wallets/unlock.password"), *extra]

    def send_args(self, who, amount, recipient, restored=False):
        return self.wallet_args("send", who, ["--fee-payer", "user", "--max-fee-debit", "150000000",
                                            "--amount", str(amount), "--to", self.keys[recipient]["address"]], restored=restored)

    def send(self, who, amount, recipient, restored=False):
        receipt = self.command(self.send_args(who, amount, recipient, restored))
        self.closed(receipt["staging_account"])
        if receipt["withdrawal"] is not None or not receipt["staging_rent_reclaimed"]:
            raise RuntimeError("private send changed public value or did not reclaim rent")
        self.event("user_private_send", sender=who, amount=amount, recipient=recipient, receipt=receipt)
        return receipt

    def history_ready(self):
        # Account RPC is available briefly before finalized blockstore history
        # at startup. Never weaken wallet scanning or manufacture missing blocks.
        for i in [0,1]:
            target=rpc(18899+i*1000,"getAccountInfo",[load(self.root)["pool"],{"encoding":"base64","commitment":"finalized"}])["context"]["slot"]
            blocks=rpc(18899+i*1000,"getBlocks",[1,target,{"commitment":"finalized"}])
            if not target or target not in blocks: return None
        return True

    def check(self, alice, bob, backing=5_000_000, public_alice=0):
        for i in [0, 1]:
            for who, expected in [("alice", alice), ("bob", bob)]:
                value = self.wallet("balance", who, index=i)
                expected_public = public_alice if who == "alice" else 0
                if value["balance"] != expected or value["fee_address"] != self.keys[who]["fee_address"] or value["public_balance"] != expected_public:
                    raise RuntimeError(f"{who} private/public balance or fee authority differs on validator {i}")
            data = base64.b64decode(account(i, load(self.root)["pool"])["data"][0])
            if int.from_bytes(data[48:56], "little") != backing:
                raise RuntimeError("pool backing changed across a private send")

    def browser(self, phase, password):
        completed = subprocess.run(["node", str(self.browser_script), str(self.evidence), phase],
                                   input=json.dumps({"password":password,"recipient":self.keys["bob"]["address"],"fee_address":self.keys["alice"]["fee_address"]}),
                                   capture_output=True, text=True, timeout=240, env=dict(self.env, PLAYWRIGHT_MODULE=self.module))
        (self.evidence / (phase + "-browser.log")).write_text(completed.stdout + completed.stderr)
        if completed.returncode:
            raise RuntimeError("private-send browser failed; inspect preserved evidence")
        result = json.loads((self.evidence / (phase + "-browser.json")).read_text())
        self.event("browser_" + phase, result=result)
        return result

    def run(self, resume_setup=False, resume_upload=False):
        if resume_upload:
            return self.resume_after_upload()
        root = self.root
        operator = PROJECT / ".local" / ("operator-" + root.name)
        if resume_setup:
            previous=load_checkpoint(root,"setup")
            original="Wallet error: missing --rpc\n"
            self.result["resumed_pre_deposit_error"]=original
            self.result["prior_setup_errors"]=[original]+([previous["error"]] if previous["error"]!=original else [])
        operator.mkdir(mode=0o700,exist_ok=resume_setup)
        cold, hot = operator / "cold.password", operator / "sponsor.password"
        if not resume_setup:
            for path in [cold, hot]: private_new(path, secrets.token_urlsafe(36).encode())
            self.command([str(LAB), "init-private", str(root), "--cold-password-file", str(cold), "--sponsor-password-file", str(hot)])
        else:
            prepare(root)
        for i in [0, 1]:
            self.children[i] = start(root, i,coordinated=resume_setup)
            wait_rpc(root, i)
        quiet(root)
        self.converge(0)
        self.wait_for(self.history_ready,timeout=30)
        config = load(root)
        (root / "wallets").mkdir(mode=0o700,exist_ok=resume_setup)
        password = (root/"wallets/unlock.password").read_text() if resume_setup else secrets.token_urlsafe(36)
        if not resume_setup: private_new(root / "wallets/unlock.password", password.encode())
        self.profiles = []
        for i in [0, 1]:
            path = self.evidence / f"profile-{i}.json"
            profile=public_profile(config, "Sponsor-free send rehearsal", f"http://127.0.0.1:{18899+i*1000}", "loopback-http")
            if resume_setup:
                if json.loads(path.read_text())!=profile: raise RuntimeError("preserved public profile changed")
            else: path.write_text(json.dumps(profile))
            self.profiles.append(path)
        for who in ["alice", "bob"]:
            self.clients[who] = WalletApp.from_profile(self.profiles[0], self.evidence / (who + "-client"))
            self.keys[who] = self.clients[who].action({"action":"unlock" if resume_setup else "create","password":password})
            if not resume_setup: self.clients[who].action({"action":"ack-backup","password":password})
            if any(self.clients[who].status()[key] for key in ("pending","staging")):
                raise RuntimeError("setup resume has an unresolved payment")
        self.app = self.clients["alice"]
        if resume_setup:
            self.check(0,0,backing=0)
            reservations=json.loads((root/"sponsor-policy.json.reservations.json").read_text())
            if len(durable(root,0))!=1 or reservations.get("reserved")!=0 or reservations.get("requests")!=[]:
                raise RuntimeError("setup was already funded or a sponsor reservation exists; do not repeat it")
        # One explicit setup deposit, before making all sponsor files unavailable.
        initial = self.wallet_args("deposit", "alice", ["--rpc","http://127.0.0.1:18899","--amount","5000000","--sponsor-password-file",str(hot),"--sponsor-request-id","private-send-setup-deposit"])
        initial[initial.index("--network")+1] = str(root / "network.json")
        deposit = self.command(initial)
        self.closed(deposit["staging_account"])
        self.sponsor_files = {}
        for name in ["sponsor.enc.json","sponsor-policy.json","sponsor-policy.json.reservations.json"]:
            source = root / name
            self.sponsor_files[name + ".disabled"] = digest(source)
            source.rename(root / (name + ".disabled"))
        self.sponsor_balance = rpc(18899,"getBalance",[config["roles"]["sponsor"],{"commitment":"finalized"}])["value"]
        self.check(5_000_000,0)
        quote = self.wallet("fees","alice",["--payment","send"])
        if quote["payment"] != "send" or not quote["funding_shortfall"]:
            raise RuntimeError("unfunded private-send quote is wrong")
        args = self.send_args("alice",1_000_000,"bob")
        self.command(args,"fund user fee address")
        small = args.copy(); small[small.index("--max-fee-debit")+1] = "1"
        self.command(small,"below the current send quote")
        self.command(args+["--sponsor-password-file",str(hot)],"cannot be combined")
        self.command(self.wallet_args("deposit","alice",["--fee-payer","user"]),"must select user or sponsor")
        self.command(self.wallet_args("fees","alice",["--payment","deposit"]),"only supported for fees")
        if Path(str(self.app.wallet)+".staging.json").exists():
            raise RuntimeError("preflight rejection created a staging upload")
        self.server = ThreadingHTTPServer(("127.0.0.1",8772), Handler)
        self.server.authority, self.server.app = "127.0.0.1:8772", self.app
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.browser("unfunded",password)
        for who in ["alice","bob"]:
            self.command([str(LAB),"fund-user-fee-check",str(root),str(self.clients[who].wallet),str(root/"wallets/unlock.password"),str(cold),"http://127.0.0.1:18899"])
            self.wait_for(lambda:rpc(18899,"getBalance",[self.keys[who]["fee_address"],{"commitment":"finalized"}])["value"]==300_000_000)
        self.treasury_balance = rpc(18899,"getBalance",[config["roles"]["treasury"],{"commitment":"finalized"}])["value"]
        self.browser("funded",password)
        self.check(4_000_000,1_000_000)

        # Kill a real wallet after the upload account is confirmed, before finalization.
        bob_args = self.send_args("bob",100_000,"alice")
        child = subprocess.Popen(bob_args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
        self.wallet_children.append(child)
        stage_path = Path(str(self.clients["bob"].wallet)+".staging.json")
        def live_stage():
            if child.poll() is not None:
                out,err=child.communicate(); raise RuntimeError(out+err)
            try:
                record=json.loads(stage_path.read_text())
                return record if account(0,record["staging_account"],"confirmed") else None
            except (FileNotFoundError,json.JSONDecodeError): return None
        stage=self.wait_for(live_stage)
        self.kill_client(child)
        if stage["payload_len"]!=9222 or stage["user_fee"]["maximum"]!=150_000_000 or stage.get("sponsor_request_id") or Path(str(self.clients["bob"].wallet)+".pending.json").exists():
            raise RuntimeError("private-send upload crash journal differs")
        self.after_upload(password,hot,stage)

    def resume_after_upload(self):
        root=self.root
        previous=load_checkpoint(root,"upload")
        self.result=previous
        self.result.update(status="running",prior_upload_assertion_error=self.result.pop("error"))
        config=load(root)
        self.profiles=[self.evidence/f"profile-{i}.json" for i in [0,1]]
        password=(root/"wallets/unlock.password").read_text()
        for i,path in enumerate(self.profiles):
            if json.loads(path.read_text())!=public_profile(config,"Sponsor-free send rehearsal",f"http://127.0.0.1:{18899+i*1000}","loopback-http"):
                raise RuntimeError("preserved connection profile changed")
        for who in ["alice","bob"]:
            self.clients[who]=WalletApp.from_profile(self.profiles[0],self.evidence/(who+"-client"))
            self.keys[who]=self.clients[who].action({"action":"unlock","password":password})
            status=self.clients[who].status()
            if status["pending"] or status["staging"]!=(who=="bob"):
                raise RuntimeError("preserved wallet is not at the upload-only checkpoint")
        self.app=self.clients["alice"]
        stage_path=Path(str(self.clients["bob"].wallet)+".staging.json")
        stage=json.loads(stage_path.read_text())
        if stage["payload_len"]!=9222 or stage["user_fee"]["maximum"]!=150_000_000 or stage.get("sponsor_request_id"):
            raise RuntimeError("preserved upload has the wrong authorization")
        original=digest(stage_path)
        prepare(root)
        for i in [0,1]:
            self.children[i]=start(root,i,coordinated=True)
            wait_rpc(root,i)
        quiet(root)
        self.converge(0)
        self.wait_for(self.history_ready,timeout=30)
        self.check(4_000_000,1_000_000)
        if len(durable(root,0))!=5 or digest(stage_path)!=original:
            raise RuntimeError("upload resume changed native state or its cap")
        self.sponsor_files={name:digest(root/name) for name in ["sponsor.enc.json.disabled","sponsor-policy.json.disabled","sponsor-policy.json.reservations.json.disabled"]}
        if any((root/name.removesuffix(".disabled")).exists() for name in self.sponsor_files):
            raise RuntimeError("operator sponsor unexpectedly available")
        journal=json.loads((root/"sponsor-policy.json.reservations.json.disabled").read_text())
        if journal["reserved"]!=150_000_000 or len(journal["requests"])!=1 or journal["requests"][0]["kind"]!="deposit" or journal["requests"][0]["charged"]!=122_995_240:
            raise RuntimeError("original one-deposit sponsor budget changed")
        # Reconstruct the original baseline from all canonical operator activity,
        # requiring precisely the setup deposit and two fixed gas grants.
        role_balances={}
        for role,count,initial,public_debit,rent in [("sponsor",12,1_000_000_000,5_000_000,2*rpc(18899,"getMinimumBalanceForRentExemption",[40])),("treasury",2,10_000_000_000,600_000_000,0)]:
            key=config["roles"][role]
            signatures=rpc(18899,"getSignaturesForAddress",[key,{"commitment":"finalized","limit":1000}])
            if len(signatures)!=count: raise RuntimeError("operator history differs from original setup")
            fees=0
            for item in signatures:
                tx=rpc(18899,"getTransaction",[item["signature"],{"encoding":"json","commitment":"finalized","maxSupportedTransactionVersion":0}])
                if tx is None or tx["meta"]["err"] or tx["transaction"]["message"]["accountKeys"][0]!=key:
                    raise RuntimeError("operator transaction history is missing or unexpected")
                fees+=tx["meta"]["fee"]
            expected=initial-public_debit-rent-fees
            if rpc(18899,"getBalance",[key,{"commitment":"finalized"}])["value"]!=expected:
                raise RuntimeError("operator balance differs from original setup")
            role_balances[role]=expected
        self.sponsor_balance,self.treasury_balance=role_balances["sponsor"],role_balances["treasury"]
        self.server=ThreadingHTTPServer(("127.0.0.1",8772),Handler)
        self.server.authority,self.server.app="127.0.0.1:8772",self.app
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.event("resumed_original_upload_without_repeating_payments",authorization=stage["user_fee"],operator_baselines=role_balances)
        self.after_upload(password,PROJECT/".local"/("operator-"+root.name)/"sponsor.password",stage)

    def after_upload(self,password,hot,stage):
        root=self.root
        config=load(root)
        bob_args=self.send_args("bob",100_000,"alice")
        self.command(bob_args,"unfinished staging upload")
        self.command(self.wallet_args("reclaim","bob",["--sponsor-password-file",str(hot)]),"no operator sponsorship")
        self.wallet("reclaim","bob")
        self.closed(stage["staging_account"])
        self.check(4_000_000,1_000_000)
        self.event("private_upload_sigkill_and_original_cap_cleanup", maximum=stage["user_fee"]["maximum"])

        # Withhold an actual finalized reply; never fabricate RPC acceptance.
        pending_path=Path(str(self.app.wallet)+".pending.json")
        stage_path=Path(str(self.app.wallet)+".staging.json")
        proxy=LostAcknowledgement(pending_path)
        try:
            proxy_profile=self.evidence/"proxy-profile.json"
            proxy_profile.write_text(json.dumps(public_profile(config,"Sponsor-free send rehearsal","http://127.0.0.1:24899","loopback-http")))
            args=self.send_args("alice",500_000,"bob")
            args[args.index("--network")+1]=str(proxy_profile)
            child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
            self.wallet_children.append(child)
            def finalized():
                if child.poll() is not None:
                    out,err=child.communicate(); raise RuntimeError(out+err)
                return proxy.reached.is_set()
            self.wait_for(finalized)
            self.kill_client(child)
        finally: proxy.close()
        pending=json.loads(pending_path.read_text())
        stage=json.loads(stage_path.read_text())
        journal_hashes=[digest(p) for p in [pending_path,stage_path]]
        if pending.get("withdrawal") is not None or stage["payload_len"]!=9222 or not stage["user_fee"]:
            raise RuntimeError("private pending record includes wrong public intent or fee mode")
        self.command(self.send_args("alice",1,"bob"),"unresolved payment")
        self.command(self.wallet_args("reclaim","alice"),"unresolved payment")
        capture_public_payment(root,pending)
        self.check(3_500_000,1_500_000)
        expected=durable(root,0)
        barrier=max(self.slots("processed"))
        crash=crash_owned(root,1,self.children[1])
        self.children[1]=start(root,1)
        wait_rpc(root,1)
        self.converge(barrier,expected)
        self.wait_for(self.history_ready,timeout=30)
        self.event("validator_sigkill_rejoin",crash=crash,native_accounts=len(expected))
        barrier=max(self.slots("processed"))
        for i in [1,0]: stop(root,i)
        replay=prepare(root)
        for i in [0,1]:
            self.children[i]=start(root,i,coordinated=True)
            wait_rpc(root,i)
        quiet(root)
        self.converge(barrier,expected)
        self.wait_for(self.history_ready,timeout=30)
        if [digest(p) for p in [pending_path,stage_path]]!=journal_hashes:
            raise RuntimeError("restart altered pending identity or original fee cap/charges")
        recovery=self.browser("recovery",password)
        if recovery["resolved"]["signature"]!=pending["signature"] or not recovery["resolved"]["accepted"]:
            raise RuntimeError("canonical private-send recovery resolved a different payment")
        self.closed(stage["staging_account"])
        if pending_path.exists() or stage_path.exists():
            raise RuntimeError("resolved/reclaimed private-send journal remains")
        self.event("majority_restart_and_private_pending_recovery",replay=replay,original_authorization=stage["user_fee"])
        self.check(3_500_000,1_500_000)

        # New sealed buffer, same proof: permanent nullifiers must reject replay.
        replay_wallet=root/"wallets/alice-replay.wallet.json"
        restore=self.wallet_args("restore","alice",["--backup",str(self.app.backup)])
        restore[restore.index("--wallet")+1]=str(replay_wallet)
        self.command(restore)
        rejection=self.command([str(LAB),"replay-user-send-check",str(root),str(replay_wallet),str(root/"wallets/unlock.password"),"http://127.0.0.1:18899"])
        recovery_args=self.wallet_args("resolve","alice")
        recovery_args[recovery_args.index("--wallet")+1]=str(replay_wallet)
        replay_stage=Path(str(replay_wallet)+".staging.json")
        original_replay_cap=json.loads(replay_stage.read_text())["user_fee"]
        def expired():
            completed=subprocess.run(recovery_args,capture_output=True,text=True,env=self.env,timeout=180)
            if completed.returncode:
                if "still pending" not in completed.stderr: raise RuntimeError(completed.stderr)
                return None
            return json.loads(completed.stdout)
        resolved=self.wait_for(expired,timeout=180)
        if resolved["accepted"] or not resolved["expired_without_execution"]:
            raise RuntimeError("replayed proof unexpectedly executed")
        if json.loads(replay_stage.read_text())["user_fee"]!=original_replay_cap:
            raise RuntimeError("failed replay resolution reset user charges")
        recovery_args[1]="reclaim"
        self.command(recovery_args)
        self.check(3_500_000,1_500_000)
        self.event("restaged_spent_proof_rejected_after_restart",rejection=rejection,resolution=resolved)

        for who in ["alice","bob"]:
            restored=self.wallet("restore",who,["--backup",str(self.clients[who].backup)],restored=True)
            if restored["fee_address"]!=self.keys[who]["fee_address"]:
                raise RuntimeError("restored seed changed fee signing authority")
        self.send("bob",250_000,"alice",restored=True)
        self.check(3_750_000,1_250_000)
        last=self.send("alice",750_000,"bob",restored=True)
        self.check(3_000_000,2_000_000)
        withdrawal=self.wallet("withdraw","alice",["--fee-payer","user","--max-fee-debit","150000000","--amount","1000000"],restored=True)
        self.closed(withdrawal["staging_account"])
        self.check(2_000_000,2_000_000,4_000_000,1_000_000)
        self.finish(last,withdrawal)

    def finish(self,last,withdrawal):
        root=self.root
        config=load(root)
        state=durable(root,0)
        self.converge(max(self.slots())-8,state)
        if len(state)!=13: raise RuntimeError("expected pool plus 12 permanent nullifiers for six accepted payments")
        rent=rpc(18899,"getMinimumBalanceForRentExemption",[40])
        accounting={}
        for who, count in [("alice",4),("bob",1)]:
            payer=self.keys[who]["fee_address"]
            signatures=rpc(18899,"getSignaturesForAddress",[payer,{"commitment":"finalized","limit":1000}])
            fees=0
            for item in signatures:
                tx=rpc(18899,"getTransaction",[item["signature"],{"encoding":"json","commitment":"finalized","maxSupportedTransactionVersion":0}])
                if tx is None or tx["meta"]["err"]: raise RuntimeError("user-paid transaction is missing or failed")
                message=tx["transaction"]["message"]
                if message["accountKeys"][0]==payer:
                    fees+=tx["meta"]["fee"]
                    if set(config["roles"].values()).intersection(message["accountKeys"]):
                        raise RuntimeError("a user-paid transfer depended on an operator authority")
            balance=rpc(18899,"getBalance",[payer,{"commitment":"finalized"}])["value"]
            permanent=2*count*rent
            if 300_000_000-balance!=fees+permanent: raise RuntimeError("user gas/rent accounting does not reconcile")
            accounting[who]={"initial":300_000_000,"balance":balance,"transaction_fees":fees,"permanent_nullifier_rent":permanent}
        for role,expected in [("sponsor",self.sponsor_balance),("treasury",self.treasury_balance)]:
            if rpc(18899,"getBalance",[config["roles"][role],{"commitment":"finalized"}])["value"]!=expected:
                raise RuntimeError("operator paid for a user transfer")
        if any(digest(root/name)!=value for name,value in self.sponsor_files.items()):
            raise RuntimeError("disabled operator vault/policy/journal changed")
        self.result.update(status="passed",accepted_native_payments=6,permanent_nullifiers=12,private_balances={"alice":2_000_000,"bob":2_000_000},
                           pool_backing=4_000_000,public_withdrawal=1_000_000,accounting=accounting,sponsor_unchanged=True,treasury_unchanged_after_setup=True,
                           last_private_receipt=last,withdrawal_regression_receipt=withdrawal)
        self.event("sponsor_free_private_send_acceptance_passed")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--playwright-module",required=True)
    parser.add_argument("--evidence",type=Path,required=True)
    parser.add_argument("--browser-script",type=Path,required=True)
    parser.add_argument("--resume-setup",action="store_true",help="only resume the exact preserved pre-deposit missing-RPC failure")
    parser.add_argument("--resume-upload",action="store_true",help="only resume the exact preserved upload-assertion failure")
    args=parser.parse_args()
    root=args.root.resolve()
    if args.resume_setup and args.resume_upload: parser.error("choose one preserved checkpoint")
    if not root.is_relative_to(PROJECT/".data") or (root.exists() and not (args.resume_setup or args.resume_upload)): parser.error("use a new short .data root, or explicitly resume a preserved checkpoint")
    if args.resume_setup or args.resume_upload:
        try: load_checkpoint(root,"setup" if args.resume_setup else "upload")
        except (OSError,ValueError) as error: parser.error(str(error))
    evidence=args.evidence.resolve()
    evidence.mkdir(mode=0o700,parents=True,exist_ok=args.resume_setup or args.resume_upload)
    trial=PrivateSends(root,args.playwright_module,evidence,args.browser_script.resolve())
    try: trial.run(args.resume_setup,args.resume_upload)
    except Exception as error:
        trial.result.update(status="failed",error=str(error))
        raise
    finally:
        for child in trial.wallet_children:
            if child.poll() is None: child.kill(); child.communicate(timeout=10)
        if trial.server:
            trial.server.shutdown(); trial.server.server_close(); trial.thread.join(timeout=5)
        errors=[]
        for i in [1,0]:
            if trial.children[i] is not None and trial.children[i].poll() is None:
                try: stop(root,i)
                except Exception as error: errors.append(str(error))
        if errors: trial.result.update(status="failed",cleanup_errors=errors)
        if root.exists(): atomic_json(root/"private-send-result.json",trial.result)
        if errors: raise RuntimeError("owned validator cleanup failed")
