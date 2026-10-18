#!/usr/bin/env python3
"""Finite real snapshot/archival-RPC pending-payment crash acceptance."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import signal
import subprocess
import time

from gateway_history_localnet import GatewayRecovery, FAUCET, digest
from fault_localnet import WALLET, atomic_json, durable
from invite_localnet import post
from localnet import LAB, PROJECT, ledger, load, newer_full_snapshot, prepare_snapshot_recovery, quiet, rpc, start, stop, wait_rpc
from history_retention import atomic
from test_faucet import BoundedServer, Faucet
from testnet_gateway import Gateway, Handler
from wallet_localnet import private_new


class CanonicalRecovery(GatewayRecovery):
    archive_enabled = False

    def event(self, kind, **fields):
        self.result['events'].append(dict(kind=kind, **fields))
        atomic_json(self.root/'canonical-archive-result.json', self.result)
        print(kind, flush=True)

    def launch_gateway(self, history=True, gate=None, pending=None):
        args=['/usr/bin/python3','-B',str(Path(__file__).resolve()),'--gateway-child','--root',str(self.root)]
        if history:args+=['--history']
        if self.archive_enabled:args+=['--archive']
        if gate:args+=['--gate',gate]
        if pending:args+=['--pending',str(pending)]
        with (self.root/'gateway.log').open('ab') as output:
            self.gateway=subprocess.Popen(args,stdout=output,stderr=output,env=self.env)
        def ready():
            if self.gateway.poll() is not None:raise RuntimeError('gateway child failed; retain gateway.log')
            try:return post(18898,'/',dict(jsonrpc='2.0',id=1,method='getGenesisHash'))[0]==200
            except OSError:return False
        self.wait(ready,20)

    def interrupted_payment(self, who, action, extra):
        wallet=self.root/'wallets'/(who+'.wallet.json');pending=Path(str(wallet)+'.pending.json')
        marker=self.root/'gateway-held-send.json'
        if marker.exists():marker.rename(self.root/('gateway-held-'+who+'.json'))
        self.close_gateway();self.launch_gateway(gate='send',pending=pending)
        sender=subprocess.Popen([str(a) for a in self.user_args(action,who,extra)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
        self.wallet_children.append(sender)
        try:
            self.wait(lambda:marker.exists() or sender.poll() is not None,150)
            if not marker.exists():
                _,err=sender.communicate(timeout=10);raise RuntimeError('payment did not reach real finalized ACK gate: '+err)
            saved=pending.read_bytes();stage=Path(str(wallet)+'.staging.json').read_bytes()
            signature=json.loads(saved)['signature'];slot=json.loads(marker.read_text())['slot']
            sender.kill();sender.communicate(timeout=15);self.close_gateway(kill=True)
            if sender.returncode!=-9:raise RuntimeError('payment client was not SIGKILLed')
        finally:
            if sender.poll() is None:sender.kill();sender.communicate(timeout=10)
        self.event('real_'+action+'_finalized_response_lost',signature=signature,slot=slot)
        return dict(wallet=wallet,pending=pending,saved=saved,stage=stage,signature=signature,slot=slot)

    def broadcasts(self):
        path=self.root/'gateway-broadcasts.json'
        return json.loads(path.read_text()) if path.exists() else []

    def unchanged(self, payment):
        if payment['pending'].read_bytes()!=payment['saved'] or Path(str(payment['wallet'])+'.staging.json').read_bytes()!=payment['stage']:
            raise RuntimeError('original pending/staging journal changed')

    def run(self):
        root=self.root;operator=PROJECT/'.local'/('operator-'+root.name);operator.mkdir(mode=0o700)
        cold,hot=operator/'cold.password',operator/'hot.password'
        for path in [cold,hot]:private_new(path,secrets.token_urlsafe(36).encode())
        self.command([LAB,'init-private',root,'--cold-password-file',cold,'--sponsor-password-file',hot])
        for i in [0,1]:self.children[i]=start(root,i);wait_rpc(root,i)
        quiet(root);self.converge(0)
        (root/'wallets').mkdir(mode=0o700);private_new(root/'wallets/unlock.password',secrets.token_urlsafe(36).encode())
        keys={who:self.wallet('init',who,['--backup',str(root/'wallets'/(who+'.seed-backup.json'))]) for who in ['alice','bob']}
        for action,amount in [('deposit',5_000_000),('send',2_000_000)]:
            extra=['--sponsor-password-file',str(hot),'--sponsor-request-id','canonical-028-'+action,'--amount',str(amount)]
            if action=='send':extra+=['--to',keys['bob']['address']]
            receipt=self.wallet(action,'alice',extra);self.closed(receipt['staging_account'])
        for who in ['alice','bob']:
            self.command([LAB,'fund-user-fee-check',root,root/'wallets'/(who+'.wallet.json'),root/'wallets/unlock.password',cold,'http://127.0.0.1:18899'])
        self.export();self.setup_invited()
        invite=root/'alice-invite.json'
        self.alice_invitation=self.command([FAUCET,'invite-issue','--root',root/'faucet','--output',invite,'--expires-in','3600'])
        self.user('join','alice',['--invitation-file',invite])
        fees=['--fee-payer','user','--max-fee-debit','150000000']
        sent=self.interrupted_payment('bob','send',fees+['--amount','500000','--to',keys['alice']['address']])
        withdrawal=self.interrupted_payment('alice','withdraw',fees+['--amount','1000000'])
        self.launch_gateway()
        expected=durable(root,0);barrier=rpc(19899,'getSlot',[{'commitment':'processed'}]);stop(root,1)
        self.wait(lambda:newer_full_snapshot(ledger(root,0),barrier),150)
        snapshot=prepare_snapshot_recovery(root,'ledger-recovered-1',barrier)
        atomic_json(root/'active-ledger-1.json',snapshot['fresh_ledger'])
        offset=(root/'validator-1.log').stat().st_size
        self.children[1]=start(root,1,archive=True);wait_rpc(root,1);self.converge(snapshot['archive_slot'],expected)
        with (root/'validator-1.log').open('rb') as source:source.seek(offset);log=source.read().decode(errors='replace')
        if any(s not in log for s in ['Loading bank from full snapshot archive:',snapshot['archive'],'Verifying bank... Done.']):raise RuntimeError('missing real snapshot extraction evidence')
        for payment in [sent,withdrawal]:
            if payment['slot']>=snapshot['archive_slot']:raise RuntimeError('payment is not older than snapshot')
            try:rpc(19899,'getBlock',[payment['slot'],{'transactionDetails':'none','commitment':'finalized'}])
            except (RuntimeError,OSError):pass
            else:raise RuntimeError('snapshot primary unexpectedly retained old canonical payment block')
        self.export()
        refused=subprocess.run([str(a) for a in self.user_args('resolve','bob')],capture_output=True,text=True,env=self.env,timeout=90)
        if not refused.returncode or 'cannot prove absence' not in refused.stderr:raise RuntimeError('pruned primary without canonical archive resolved old payment')
        self.unchanged(sent);self.unchanged(withdrawal)
        self.event('old_payments_pruned_from_actual_snapshot_primary_journals_preserved',snapshot_slot=snapshot['archive_slot'])
        self.archive_enabled=True;self.close_gateway();self.launch_gateway(gate='archive')
        before_broadcasts=self.broadcasts();before_state=durable(root,0)
        resolver=subprocess.Popen([str(a) for a in self.user_args('resolve','bob')],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env)
        self.wallet_children.append(resolver);marker=root/'gateway-held-archive.json'
        try:
            self.wait(lambda:marker.exists() or resolver.poll() is not None,90)
            if not marker.exists():
                _,err=resolver.communicate(timeout=10);raise RuntimeError('resolver did not reach actual canonical page gate: '+err)
            cursor=json.loads(marker.read_text())['params']
            resolver.kill();resolver.communicate(timeout=15);self.close_gateway(kill=True)
            if resolver.returncode!=-9:raise RuntimeError('resolver not actually SIGKILLed')
        finally:
            if resolver.poll() is None:resolver.kill();resolver.communicate(timeout=10)
        self.unchanged(sent);self.unchanged(withdrawal)
        self.restart_group();self.launch_gateway()
        proof=json.loads((root/'gateway-proof.json').read_text());header=base64.urlsafe_b64encode(json.dumps(proof).encode()).decode()
        code,resumed=post(18898,'/',dict(jsonrpc='2.0',id=99,method='getWalletCanonicalHistory',params=cursor),{'X-Testnet-Access':header})
        if code!=200 or resumed['result']['anchor']!=cursor[2]:raise RuntimeError('captured canonical anchor/cursor failed after restart')
        self.event('canonical_http_cursor_resumes_after_resolver_gateway_and_both_validator_sigkill')
        # Recipient and staging identity must match the original saved intent.
        saved=json.loads(withdrawal['saved']);wrong=dict(saved,withdrawal=dict(saved['withdrawal'],amount=saved['withdrawal']['amount']+1))
        atomic(withdrawal['pending'],json.dumps(wrong).encode())
        rejected=subprocess.run([str(a) for a in self.user_args('resolve','alice')],capture_output=True,text=True,env=self.env,timeout=90)
        if not rejected.returncode or 'saved recipient/amount/sponsor intent' not in rejected.stderr:raise RuntimeError('changed historical withdrawal intent accepted')
        if json.loads(withdrawal['pending'].read_text())!=wrong:raise RuntimeError('rejected intent lost its journal')
        atomic(withdrawal['pending'],withdrawal['saved'])
        receipts={who:self.user('resolve',who) for who in ['bob','alice']}
        for who,payment in [('bob',sent),('alice',withdrawal)]:
            receipt=receipts[who]
            if receipt['signature']!=payment['signature'] or not receipt['accepted'] or not receipt['pending_cleared'] or receipt['sync']['archival_rpc_requests']==0:
                raise RuntimeError('historical original payment did not resolve through canonical archive')
        if receipts['alice']['withdrawal']!=saved['withdrawal']:raise RuntimeError('withdrawal exact intent changed')
        if self.broadcasts()!=before_broadcasts or durable(root,0)!=before_state or durable(root,1)!=before_state:
            raise RuntimeError('read-only recovery broadcast a transaction or changed native state')
        self.event('old_private_send_and_exact_withdrawal_resolve_once_without_payment_broadcasts',receipts=receipts)
        for who,payment in [('bob',sent),('alice',withdrawal)]:
            self.user('reclaim',who);self.closed(json.loads(payment['saved'])['staging_account'])
            again=subprocess.run([str(a) for a in self.user_args('resolve',who)],capture_output=True,text=True,env=self.env,timeout=30)
            if not again.returncode:raise RuntimeError('cleared payment resolved a second time')
        self.restored('final-fresh');balance=self.user('balance','final-fresh')
        if balance['balance']!=1_500_000:raise RuntimeError('recovered old private payment balance differs')
        request=dict(jsonrpc='2.0',id=1,method='getWalletCanonicalHistory',params=[0,cursor[1],None])
        if post(18898,'/',request)[0]!=403:raise RuntimeError('uninvited canonical archive access')
        self.command([FAUCET,'invite-revoke','--root',root/'faucet','--invite-id',self.invitation['invite_id']])
        proof=json.loads((root/'gateway-proof.json').read_text());header=base64.urlsafe_b64encode(json.dumps(proof).encode()).decode()
        if post(18898,'/',request,{'X-Testnet-Access':header})[0]!=403:raise RuntimeError('revoked canonical archive access')
        if durable(root,0)!=before_state or len(before_state)!=9:raise RuntimeError('pool/eight permanent nullifiers changed')
        self.result.update(status='passed',native_accounts=9,permanent_nullifiers=8,final_bob_balance=1_500_000,
            no_recovery_broadcasts=True,original_send_signature=sent['signature'],original_withdrawal_signature=withdrawal['signature'])
        self.event('canonical_archival_recovery_acceptance_passed')


def child(args):
    root=args.root.resolve();faucet=Faucet(root/'faucet',root/'wallets/unlock.password');original=faucet.command
    def authorize(command,data=None,extra=()):
        result=original(command,data,extra)
        if command=='authorize':atomic_json(root/'gateway-proof.json',data)
        return result
    faucet.command=authorize
    class TestGateway(Gateway):
        def canonical_history(self,request):
            result=super().canonical_history(request)
            if args.gate=='archive' and request['params'][0]>0:
                private_new(root/'gateway-held-archive.json',json.dumps({'params':request['params']}).encode())
                time.sleep(60);raise OSError('canonical page response withheld')
            return result
        def forward(self,raw,timeout=15):
            query=json.loads(raw)
            if query.get('method')=='sendTransaction':
                path=root/'gateway-broadcasts.json';entries=json.loads(path.read_text()) if path.exists() else []
                entries.append(hashlib.sha256(raw).hexdigest());atomic_json(path,entries)
            result=super().forward(raw,timeout=timeout)
            if args.gate=='send' and query.get('method')=='getSignatureStatuses' and args.pending and args.pending.exists():
                signature=json.loads(args.pending.read_text())['signature']
                for sig,status in zip(query['params'][0],json.loads(result).get('result',{}).get('value',[])):
                    if sig==signature and status and status.get('confirmationStatus')=='finalized' and status.get('err') is None:
                        private_new(root/'gateway-held-send.json',json.dumps({'signature':sig,'slot':status['slot']}).encode())
                        time.sleep(60);raise OSError('finalized response withheld')
            return result
    gateway=TestGateway(faucet,history_root=root/'recovery-history' if args.history else None,archive_rpc='http://127.0.0.1:18899' if args.archive else None)
    server=BoundedServer(('127.0.0.1',18898),Handler);server.authority='127.0.0.1:18898';server.app=gateway
    try:server.serve_forever()
    finally:server.server_close();faucet.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True)
    for flag in ['gateway-child','history','archive']:parser.add_argument('--'+flag,action='store_true')
    parser.add_argument('--gate',choices=['send','archive']);parser.add_argument('--pending',type=Path)
    args=parser.parse_args()
    if args.gateway_child:child(args)
    else:
        root=args.root.resolve()
        if root.parent!=PROJECT/'.data' or root.exists() or len(bytes(root/'ledger-recovered-1/admin.rpc'))>=104:parser.error('new short fixture root under .data required')
        trial=CanonicalRecovery(root)
        def limit(*_):raise TimeoutError('ten-minute local acceptance limit')
        signal.signal(signal.SIGALRM,limit);signal.alarm(600)
        try:trial.run()
        except BaseException as error:trial.result.update(status='failed',error=str(error));raise
        finally:
            signal.alarm(0)
            for child_process in trial.wallet_children:
                if child_process.poll() is None:child_process.kill();child_process.communicate(timeout=10)
            try:trial.close()
            finally:
                for i in [1,0]:
                    if trial.children[i] is not None and trial.children[i].poll() is None:stop(root,i)
                if root.exists():atomic_json(root/'canonical-archive-result.json',trial.result)
