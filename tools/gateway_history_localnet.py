#!/usr/bin/env python3
"""Finite invited/snapshot/retained-history crash acceptance on a new fixture."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import threading
import time

from archive_localnet import ArchiveExperiment
from fault_localnet import WALLET, atomic_json, crash_owned, durable
from gateway_ack_loss import admission_identity
from history_retention import manifest, atomic
from invite_localnet import post
from localnet import LAB, PROJECT, ledger, load, newer_full_snapshot, prepare_snapshot_recovery, quiet, rpc, start, stop, wait_rpc
from package_wallet import public_profile
from replay_localnet import prepare
from retention_localnet import RetentionExperiment
from test_faucet import BoundedServer, Faucet, Handler as FaucetHandler
from testnet_gateway import Gateway, Handler as GatewayHandler
from wallet_localnet import private_new

FAUCET=PROJECT/'target/debug/native-faucet'


def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


class GatewayRecovery(RetentionExperiment):
    gateway=None
    server=None
    server_thread=None
    def event(self,kind,**fields):
        self.result['events'].append(dict(kind=kind,**fields))
        atomic_json(self.root/'gateway-history-result.json',self.result);print(kind,flush=True)
    def command(self,args,timeout=180):
        done=subprocess.run([str(a) for a in args],capture_output=True,text=True,env=self.env,timeout=timeout)
        if done.returncode:raise RuntimeError(done.stderr)
        return json.loads(done.stdout)
    def user_args(self,action,name,extra=()):
        return [WALLET,action,'--network',self.profile,'--wallet',self.root/'wallets'/(name+'.wallet.json'),
                '--password-file',self.root/'wallets/unlock.password',*extra]
    def user(self,action,name,extra=()):return self.command(self.user_args(action,name,extra))
    def restored(self,name):
        return self.user('restore',name,['--backup',self.root/'wallets/bob.seed-backup.json'])
    def wait(self,predicate,timeout=90):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if predicate():return
            time.sleep(.2)
        raise TimeoutError('bounded gateway-history acceptance wait')
    def launch_gateway(self,history=True,gate=None,pending=None):
        log=open(self.root/'gateway.log','ab')
        args=['/usr/bin/python3','-B',str(Path(__file__).resolve()),'--gateway-child','--root',str(self.root)]
        if history:args+=['--history']
        if gate:args+=['--gate',gate]
        if pending:args+=['--pending',str(pending)]
        self.gateway=subprocess.Popen(args,stdout=log,stderr=log,env=self.env);log.close()
        def ready():
            if self.gateway.poll() is not None:raise RuntimeError('gateway child failed; retain gateway.log')
            try:return post(18898,'/',dict(jsonrpc='2.0',id=1,method='getGenesisHash'))[0]==200
            except OSError:return False
        self.wait(ready,20)
    def close_gateway(self,kill=False):
        if self.gateway is not None and self.gateway.poll() is None:
            self.gateway.kill() if kill else self.gateway.terminate()
            code=self.gateway.wait(timeout=15)
            if kill and code!=-9:raise RuntimeError('gateway was not actually SIGKILLed')
        self.gateway=None
    def restart_group(self):
        self.worker.close()
        expected=durable(self.root,0);barrier=max(self.slots());identity=admission_identity(self.root/'faucet/admission.json')
        usage=(self.root/'faucet/admission.json').read_bytes()
        for i in [1,0]:crash_owned(self.root,i,self.children[i])
        prepare(self.root)
        for i in [0,1]:self.children[i]=start(self.root,i,coordinated=True);wait_rpc(self.root,i)
        quiet(self.root);roots=self.converge(barrier,expected)
        if (self.root/'faucet/admission.json').read_bytes()!=usage or admission_identity(self.root/'faucet/admission.json')!=identity:
            raise RuntimeError('validator restart changed admission identities or usage')
        self.worker=self.collector();self.worker.start()
        self.event('actual_validator_sigkill_restart_preserves_native_state_and_quotas',slots=roots,native_accounts=len(expected))
    def setup_invited(self):
        config=load(self.root);self.profile=self.root/'invited-profile.json'
        client=public_profile(config,'Invited retained history','http://127.0.0.1:18898','loopback-http')
        client.update(invite_required=True,faucet={'transport':'loopback-http','url':'http://127.0.0.1:8780'})
        self.profile.write_text(json.dumps(client))
        source=self.root/'source-profile.json';source.write_text(json.dumps(public_profile(config,'Snapshot upstream','http://127.0.0.1:19899','loopback-http')))
        self.command([FAUCET,'init','--root',self.root/'faucet','--profile',source,'--password-file',self.root/'wallets/unlock.password','--max-claims','2'])
        self.command([FAUCET,'access-init','--root',self.root/'faucet','--profile',self.profile,'--daily-admissions','2','--rpc-limit','2000'])
        invite=self.root/'invite.json';self.invitation=self.command([FAUCET,'invite-issue','--root',self.root/'faucet','--output',invite,'--expires-in','3600'])
        self.faucet=Faucet(self.root/'faucet',self.root/'wallets/unlock.password')
        self.server=BoundedServer(('127.0.0.1',8780),FaucetHandler);self.server.authority='127.0.0.1:8780';self.server.app=self.faucet
        self.server_thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.server_thread.start()
        self.launch_gateway(history=False)
        self.user('join','bob',['--invitation-file',invite])
        self.event('existing_seed_admitted_without_faucet_worker_or_operator_key_export')
    def run(self):
        root=self.root;operator=PROJECT/'.local'/('operator-'+root.name);operator.mkdir(mode=0o700)
        cold,hot=operator/'cold.password',operator/'hot.password'
        for path in [cold,hot]:private_new(path,secrets.token_urlsafe(36).encode())
        self.command([LAB,'init-private',root,'--cold-password-file',cold,'--sponsor-password-file',hot])
        for i in [0,1]:self.children[i]=start(root,i);wait_rpc(root,i)
        quiet(root);self.converge(0)
        (root/'wallets').mkdir(mode=0o700);private_new(root/'wallets/unlock.password',secrets.token_urlsafe(36).encode())
        keys={name:self.wallet('init',name,['--backup',str(root/'wallets'/(name+'.seed-backup.json'))]) for name in ['alice','bob']}
        for action,amount in [('deposit',100),('send',17)]:
            extra=['--sponsor-password-file',str(hot),'--sponsor-request-id','retained-027-'+action,'--amount',str(amount)]
            if action=='send':extra+=['--to',keys['bob']['address']]
            receipt=self.wallet(action,'alice',extra);self.closed(receipt['staging_account'])
        self.command([LAB,'fund-user-fee-check',root,root/'wallets/bob.wallet.json',root/'wallets/unlock.password',cold,'http://127.0.0.1:18899'])
        self.wait(lambda:rpc(18899,'getBalance',[keys['bob']['fee_address'],{'commitment':'finalized'}])['value']==300_000_000)
        self.export();self.export();self.setup_invited()
        expected=durable(root,0);barrier=rpc(19899,'getSlot',[{'commitment':'processed'}]);stop(root,1)
        self.wait(lambda:newer_full_snapshot(ledger(root,0),barrier),150)
        snapshot=prepare_snapshot_recovery(root,'ledger-recovered-1',barrier);atomic_json(root/'active-ledger-1.json',snapshot['fresh_ledger'])
        offset=(root/'validator-1.log').stat().st_size;self.children[1]=start(root,1,archive=True);wait_rpc(root,1)
        self.converge(snapshot['archive_slot'],expected)
        with (root/'validator-1.log').open('rb') as source:source.seek(offset);text=source.read().decode(errors='replace')
        if any(s not in text for s in ['Loading bank from full snapshot archive:',snapshot['archive'],'Verifying bank... Done.']):raise RuntimeError('missing actual snapshot loading evidence')
        self.export();self.restored('browser-equivalent')
        attempt=subprocess.run([str(a) for a in self.user_args('balance','browser-equivalent')],capture_output=True,text=True,env=self.env,timeout=60)
        if not attempt.returncode or 'history' not in attempt.stderr:raise RuntimeError('snapshot-only gateway unexpectedly recovered without retained data')
        self.event('fresh_invited_seed_fails_without_retained_history',snapshot_slot=snapshot['archive_slot'])
        self.close_gateway();self.launch_gateway(gate='read')
        wallet=root/'wallets/browser-equivalent.wallet.json';original=digest(wallet)
        reader=subprocess.Popen([str(a) for a in self.user_args('balance','browser-equivalent')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
        gate=root/'gateway-held-read.json'
        try:
            self.wait(lambda:gate.exists() or reader.poll() is not None,45)
            if not gate.exists():raise RuntimeError('wallet did not reach actual retained HTTP response gate')
            reader.kill();reader.communicate(timeout=15)
            if reader.returncode!=-9:raise RuntimeError('reader not SIGKILLed')
            self.close_gateway(kill=True)
        finally:
            if reader.poll() is None:reader.kill();reader.communicate(timeout=10)
        if digest(wallet)!=original or Path(str(wallet)+'.scan-cache').exists():raise RuntimeError('interrupted read changed seed or published partial checkpoint')
        saved_cursor=json.loads(gate.read_text())['params']
        self.restart_group();self.launch_gateway()
        proof=json.loads((root/'gateway-proof.json').read_text())
        header=base64.urlsafe_b64encode(json.dumps(proof).encode()).decode()
        code,resumed=post(18898,'/',{'jsonrpc':'2.0','id':99,'method':'getWalletRetainedHistory','params':saved_cursor},{'X-Testnet-Access':header})
        if code!=200 or resumed['result']['checkpoint']!=saved_cursor[2]:raise RuntimeError('immutable HTTP cursor did not resume after gateway restart')
        self.event('captured_http_cursor_resumes_after_gateway_and_mirror_restart')
        recovered=self.user('balance','browser-equivalent')
        if recovered['balance']!=17 or recovered['sync']['history_blocks_read']==0:raise RuntimeError('invited fresh seed did not replay retained pages')
        self.event('fresh_invited_seed_recovers_after_client_gateway_and_validator_crashes',balance=recovered)
        pending=Path(str(wallet)+'.pending.json');self.close_gateway();self.launch_gateway(gate='send',pending=pending)
        sender=subprocess.Popen([str(a) for a in self.user_args('send','browser-equivalent',['--fee-payer','user','--max-fee-debit','150000000','--amount','5','--to',keys['alice']['address']])],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
        try:
            self.wait(lambda:(root/'gateway-held-send.json').exists() or sender.poll() is not None,150)
            if not (root/'gateway-held-send.json').exists():
                out,err=sender.communicate(timeout=10);raise RuntimeError('send did not reach real finalized ACK gate: '+err)
            saved=pending.read_bytes();target=json.loads(saved)['signature'];staging=Path(str(wallet)+'.staging.json');stage=staging.read_bytes()
            sender.kill();sender.communicate(timeout=15);self.close_gateway(kill=True)
        finally:
            if sender.poll() is None:sender.kill();sender.communicate(timeout=10)
        self.restart_group();self.launch_gateway()
        if pending.read_bytes()!=saved or staging.read_bytes()!=stage:raise RuntimeError('original payment journals changed during crash')
        receipt=self.user('resolve','browser-equivalent')
        if receipt['signature']!=target or not receipt['accepted'] or not receipt['pending_cleared']:raise RuntimeError('original gateway payment did not resolve exactly once')
        self.user('reclaim','browser-equivalent');self.closed(receipt['staging_account'])
        self.export();self.restored('final-fresh')
        final=self.user('balance','final-fresh')
        if final['balance']!=12 or final['sync']['payments_verified']!=3:raise RuntimeError('second restored seed lost spent note effects')
        unknown=root/'wallets/final-fresh.wallet.json.pending.json';saved_unknown=dict(json.loads(saved),last_valid_block_height=0)
        private_new(unknown,json.dumps(saved_unknown).encode());unchanged=unknown.read_bytes()
        refused=subprocess.run([str(a) for a in self.user_args('resolve','final-fresh')],capture_output=True,text=True,env=self.env,timeout=60)
        if not refused.returncode or 'cannot prove absence' not in refused.stderr or unknown.read_bytes()!=unchanged:
            raise RuntimeError('retained-derived checkpoint cleared an ambiguous outcome')
        self.event('canonical_pending_resolves_once_but_retained_checkpoint_cannot_assert_absence',signature=target)
        # Corrupt only the disposable mirror; preserve and restore its exact
        # committed manifest. A recomputed checksum is not a payment proof.
        self.worker.close();mirror=root/'recovery-history';manifest_path=mirror/'manifest.json'
        original_manifest=manifest_path.read_bytes();descriptors=json.loads(original_manifest)
        chosen=None
        for index,descriptor in enumerate(descriptors['segments']):
            name='segment-%08d-%s.json'%(index,descriptor['digest']);records=json.loads((mirror/name).read_bytes())
            if any(b['transactions'] for b in records):chosen=(index,name,records);break
        if chosen is None:raise RuntimeError('missing native transaction fixture')
        index,name,records=chosen
        self.restored('missing-history');held=mirror/(name+'.held');(mirror/name).rename(held)
        try:
            rejected=subprocess.run([str(a) for a in self.user_args('balance','missing-history')],capture_output=True,text=True,env=self.env,timeout=60)
            if not rejected.returncode:raise RuntimeError('missing retained segment was accepted')
        finally:held.rename(mirror/name)
        for record in records:record['transactions']=[]
        forged=json.dumps(records,separators=(',',':')).encode();forged_digest=hashlib.blake2b(forged,digest_size=32,person=b'NPayArchiveV1').hexdigest()
        forged_name='segment-%08d-%s.json'%(index,forged_digest);private_new(mirror/forged_name,forged)
        descriptors['segments'][index]['digest']=forged_digest
        self.restored('rehashed-omission');atomic(manifest_path,json.dumps(descriptors).encode())
        try:
            rejected=subprocess.run([str(a) for a in self.user_args('balance','rehashed-omission')],capture_output=True,text=True,env=self.env,timeout=60)
            if not rejected.returncode or (root/'wallets/rehashed-omission.wallet.json.scan-cache').exists():raise RuntimeError('rehashed native omission produced a partial balance/cache')
        finally:atomic(manifest_path,original_manifest)
        self.event('invited_missing_and_rehashed_omitted_native_history_rejected')
        proof=json.loads((root/'gateway-proof.json').read_text());header=base64.urlsafe_b64encode(json.dumps(proof).encode()).decode()
        request={'jsonrpc':'2.0','id':1,'method':'getWalletRetainedHistory','params':[0,2**64-1,None]}
        if post(18898,'/',request)[0]!=403 or post(18898,'/',request,{'X-Testnet-Access':header})[0]!=200:raise RuntimeError('retained admission bypass or denied genuine proof')
        self.command([FAUCET,'invite-revoke','--root',root/'faucet','--invite-id',self.invitation['invite_id']])
        if post(18898,'/',request,{'X-Testnet-Access':header})[0]!=403:raise RuntimeError('revocation failed for retained history')
        final_state=durable(root,0)
        if final_state!=durable(root,1) or len(final_state)!=7:raise RuntimeError('pool/six permanent nullifiers differ')
        self.result.update(status='passed',final_bob_balance=12,native_accounts=7,permanent_nullifiers=6,
            no_duplicate_payment=True,invited_history_verified=True,original_seed_unchanged=digest(wallet)==original)
        self.event('invited_retained_history_acceptance_passed')
    def close(self):
        self.close_gateway()
        if self.server:self.server.shutdown();self.server.server_close();self.server_thread.join(5)
        if getattr(self,'faucet',None):self.faucet.close()
        if self.worker:self.worker.close()


def child(args):
    root=args.root.resolve();faucet=Faucet(root/'faucet',root/'wallets/unlock.password')
    original=faucet.command
    def authorize(command,data=None,extra=()):
        result=original(command,data,extra)
        if command=='authorize':
            temporary=root/'gateway-proof.tmp';temporary.write_text(json.dumps(data));temporary.chmod(0o600);temporary.replace(root/'gateway-proof.json')
        return result
    faucet.command=authorize
    class TestGateway(Gateway):
        def retained_history(self,request):
            result=super().retained_history(request)
            if args.gate=='read' and request['params'][0]>=16:
                private_new(root/'gateway-held-read.json',json.dumps({'held':True,'params':request['params']}).encode())
                time.sleep(60);raise OSError('test retained response withheld')
            return result
        def forward(self,raw,timeout=15):
            result=super().forward(raw,timeout=timeout);request=json.loads(raw)
            if args.gate=='send' and request.get('method')=='getSignatureStatuses' and args.pending and args.pending.exists():
                signature=json.loads(args.pending.read_text())['signature']
                for sig,status in zip(request['params'][0],json.loads(result).get('result',{}).get('value',[])):
                    if sig==signature and status and status.get('confirmationStatus')=='finalized' and status.get('err') is None:
                        private_new(root/'gateway-held-send.json',json.dumps({'signature':sig,'slot':status['slot']}).encode())
                        time.sleep(60);raise OSError('test finalized response withheld')
            return result
    gateway=TestGateway(faucet,history_root=root/'recovery-history' if args.history else None)
    server=BoundedServer(('127.0.0.1',18898),GatewayHandler);server.authority='127.0.0.1:18898';server.app=gateway
    try:server.serve_forever()
    finally:server.server_close();faucet.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--gateway-child',action='store_true');parser.add_argument('--history',action='store_true')
    parser.add_argument('--gate',choices=['read','send']);parser.add_argument('--pending',type=Path)
    args=parser.parse_args()
    if args.gateway_child:child(args)
    else:
        root=args.root.resolve()
        if root.parent!=PROJECT/'.data' or root.exists() or len(bytes(root/'ledger-recovered-1/admin.rpc'))>=104:parser.error('new short root under .data required')
        trial=GatewayRecovery(root)
        def limit(*_):raise TimeoutError('ten-minute local acceptance limit')
        signal.signal(signal.SIGALRM,limit);signal.alarm(600)
        try:trial.run()
        except BaseException as error:trial.result.update(status='failed',error=str(error));raise
        finally:
            signal.alarm(0)
            try:trial.close()
            finally:
                for i in [1,0]:
                    if trial.children[i] is not None and trial.children[i].poll() is None:stop(root,i)
                if root.exists():atomic_json(root/'gateway-history-result.json',trial.result)
