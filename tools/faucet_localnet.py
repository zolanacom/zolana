#!/usr/bin/env python3
"""Self-service test distribution acceptance; real loopback validators only."""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import threading
import time
import urllib.request

from fault_localnet import account, atomic_json, durable
from localnet import LAB, PROJECT, load, quiet, rpc, start, stop, wait_rpc
from package_wallet import public_profile
from replay_localnet import plan, prepare
from sponsor_localnet import SponsorExperiment
from test_faucet import BoundedServer, Faucet, Handler as FaucetHandler
from wallet_localnet import private_new
from wallet_ui import Handler, WalletApp

WALLET=PROJECT/'target/debug/native-wallet'
FAUCET=PROJECT/'target/debug/native-faucet'


class Acknowledgements:
    """Forward authentic RPC results, holding only the selected real acknowledgement."""
    def __init__(self, source):
        self.source=source; self.mode=None; self.reached=threading.Event(); self.release=threading.Event()
        owner=self
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self,*_): pass
            def do_POST(self):
                size=int(self.headers.get('Content-Length','0'))
                if not 1<=size<=100_000: self.send_error(400); return
                raw=self.rfile.read(size); request=json.loads(raw)
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
                try:
                    with opener.open(urllib.request.Request('http://127.0.0.1:18899',raw,{'Content-Type':'application/json'}),timeout=30) as reply: data=reply.read()
                    hold=owner.mode=='gas' and request.get('method')=='sendTransaction' and 'result' in json.loads(data)
                    pending=Path(str(owner.source)+'.pending.json')
                    if owner.mode=='private' and request.get('method')=='getSignatureStatuses' and pending.exists():
                        signature=json.loads(pending.read_text())['signature']
                        for sig,status in zip(request.get('params',[[]])[0],json.loads(data).get('result',{}).get('value',[])):
                            if sig==signature and status and status.get('confirmationStatus')=='finalized' and status.get('err') is None: hold=True
                    if hold:
                        owner.reached.set(); owner.release.wait(10)
                    self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError): pass
        self.server=ThreadingHTTPServer(('127.0.0.1',24899),Proxy)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
    def gate(self,mode): self.mode=mode; self.reached.clear(); self.release.clear()
    def clear(self): self.mode=None; self.release.set()
    def close(self): self.clear(); self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)


class Distribution(SponsorExperiment):
    def __init__(self,root,evidence,browser,module):
        super().__init__(root); self.evidence=evidence; self.browser_script=browser; self.module=module
        self.services=[]; self.proxy=None; self.faucet=None; self.worker=None; self.clients={}; self.keys={}
    def event(self,kind,**fields):
        self.result['events'].append(dict(kind=kind,**fields)); atomic_json(self.root/'faucet-result.json',self.result); print(kind,flush=True)
    def faucet_args(self,action): return [str(FAUCET),action,'--root',str(self.faucet_root),'--password-file',str(self.password_file)]
    def tick(self): return self.command(self.faucet_args('tick'))
    def tick_child(self):
        child=subprocess.Popen(self.faucet_args('tick'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env); self.wallet_children.append(child); return child
    def kill(self,child):
        if child.poll() is not None:
            out,err=child.communicate(); raise RuntimeError('worker exited before crash point: '+out+err)
        child.kill(); child.communicate(timeout=15)
        if child.returncode!=-9: raise RuntimeError('worker did not receive SIGKILL')
    def serve(self,handler,app,port):
        server=(BoundedServer if handler is FaucetHandler else ThreadingHTTPServer)(('127.0.0.1',port),handler); server.authority,server.app=f'127.0.0.1:{port}',app
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start(); self.services.append((server,thread)); return server
    def ready_history(self):
        for i in [0,1]:
            target=rpc(18899+i*1000,'getAccountInfo',[load(self.root)['pool'],{'encoding':'base64','commitment':'finalized'}])['context']['slot']
            if not target or target not in rpc(18899+i*1000,'getBlocks',[1,target,{'commitment':'finalized'}]): return None
        return True
    def user(self,who,action,**kwargs): return self.clients[who].action(dict(action=action,password=self.password,**kwargs))
    def claim(self,who):
        time.sleep(1.1)
        return self.user(who,'test-coins')
    def balance(self,who,index=0):
        app=self.clients[who]
        args=[str(WALLET),'balance','--network',str(self.profiles[index]),'--wallet',str(app.wallet),'--password-file',str(self.password_file)]
        return self.command(args)
    def native_balance(self,address): return rpc(18899,'getBalance',[address,{'commitment':'finalized'}])['value']
    def assert_ready(self,who):
        result=self.claim(who)
        if result['state']!='ready' or not result['gas_finalized'] or not result['private_finalized']: raise RuntimeError('grant not ready')
        return result
    def browser(self,phase):
        result=subprocess.run(['node',str(self.browser_script),str(self.evidence),phase],input=json.dumps(dict(password=self.password,recipient=self.keys['alice']['address'])),capture_output=True,text=True,env=dict(self.env,PLAYWRIGHT_MODULE=self.module),timeout=240)
        (self.evidence/f'{phase}-browser.log').write_text(result.stdout+result.stderr)
        if result.returncode: raise RuntimeError('browser failed; inspect preserved evidence')
        return json.loads((self.evidence/f'{phase}-browser.json').read_text())
    def wait_gate(self,child,timeout):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            if self.proxy.reached.wait(.1): return
            if child.poll() is not None:
                out,err=child.communicate(); (self.evidence/'failed-worker.log').write_text(out+err)
                raise RuntimeError('worker exited before acknowledgement: '+err.strip())
        raise RuntimeError('acknowledgement gate not reached')
    def run(self,resume=None):
        if resume: return self.resume_pregas(resume)
        root=self.root; operator=PROJECT/'.local'/('operator-'+root.name); operator.mkdir(mode=0o700)
        cold,hot=operator/'cold.password',operator/'sponsor.password'
        for path in [cold,hot]: private_new(path,secrets.token_urlsafe(36).encode())
        self.command([str(LAB),'init-private',str(root),'--cold-password-file',str(cold),'--sponsor-password-file',str(hot)])
        for i in [0,1]: self.children[i]=start(root,i); wait_rpc(root,i)
        quiet(root); self.converge(0); self.wait_for(self.ready_history,timeout=30)
        config=load(root)
        self.password=secrets.token_urlsafe(36); self.password_file=operator/'faucet.password'; private_new(self.password_file,self.password.encode())
        self.profiles=[]
        for i in [0,1]:
            profile=public_profile(config,'Test coins rehearsal',f'http://127.0.0.1:{18899+i*1000}','loopback-http'); profile['faucet']=dict(transport='loopback-http',url='http://127.0.0.1:8780')
            path=self.evidence/f'profile-{i}.json'; path.write_text(json.dumps(profile)); self.profiles.append(path)
        server_profile=json.loads(self.profiles[0].read_text()); server_profile['rpc']['url']='http://127.0.0.1:24899'
        source_profile=self.evidence/'source-profile.json'; source_profile.write_text(json.dumps(server_profile))
        self.faucet_root=root/'faucet'
        setup=self.command([str(FAUCET),'init','--root',str(self.faucet_root),'--profile',str(source_profile),'--password-file',str(self.password_file),'--max-claims','3'])
        self.source=self.faucet_root/'wallet.enc.json'; self.proxy=Acknowledgements(self.source)
        # Explicit, one-time reservoir setup; cold material never enters the server.
        receipt=self.command([str(WALLET),'deposit','--network',str(root/'network.json'),'--wallet',str(self.source),'--password-file',str(self.password_file),'--rpc','http://127.0.0.1:18899','--sponsor-password-file',str(hot),'--sponsor-request-id','test-faucet-initial-reservoir','--amount','5000000'])
        self.closed(receipt['staging_account'])
        self.command([str(LAB),'fund-faucet-check',str(root),str(self.source),str(self.password_file),str(cold),'http://127.0.0.1:18899'])
        self.wait_for(lambda:self.native_balance(setup['fee_address'])==1_000_000_000)
        preserved={}
        for name in ['sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json']:
            path=root/name; path.rename(root/(name+'.disabled')); preserved[name+'.disabled']=hashlib.sha256((root/(name+'.disabled')).read_bytes()).hexdigest()
        operator_balances={role:self.native_balance(config['roles'][role]) for role in ['sponsor','treasury']}
        for who in ['alice','bob','carol','dave']:
            app=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client')); self.clients[who]=app
            if who!='carol': self.keys[who]=self.user(who,'create'); self.user(who,'ack-backup')
        self.faucet=Faucet(self.faucet_root,self.password_file); self.serve(FaucetHandler,self.faucet,8780)
        first=self.claim('alice'); time.sleep(1.1); duplicate=self.claim('alice')
        if first!=duplicate or first['state']!='queued': raise RuntimeError('claim retry changed reservation')
        ledger_path=self.faucet_root/'claims.json'; ledger=json.loads(ledger_path.read_text())
        if len(ledger['claims'])!=1: raise RuntimeError('claim duplicate reserved capacity')
        self.event('signed_claim_reserved_once',claim=first,source=setup)
        return self.finish(first,setup,config,preserved,operator_balances)

    def resume_pregas(self,kind):
        previous=checkpoint(self.root,kind)
        self.result['prior_errors']=previous.get('prior_errors',[])+[previous['error']]
        self.result['events']=previous['events']
        root=self.root; operator=PROJECT/'.local'/('operator-'+root.name)
        self.password_file=operator/'faucet.password'; self.password=self.password_file.read_text()
        self.faucet_root=root/'faucet'; self.source=self.faucet_root/'wallet.enc.json'
        self.profiles=[self.evidence/f'profile-{i}.json' for i in [0,1]]
        config=load(root); setup=previous['events'][0]['source']; first=previous['events'][0]['claim']
        record=json.loads((self.faucet_root/(first['claim_id']+'.json')).read_text())
        if kind=='pregas':
            if record != dict(gas_attempts=0,gas=None,gas_done=False,private_attempts=0,proof=None,private_done=False): raise RuntimeError('pre-gas checkpoint changed; refusing resume')
            if Path(str(self.source)+'.staging.json').exists(): raise RuntimeError('pre-gas checkpoint has an active upload')
        elif kind=='upload' and not (record['gas_done'] and record['gas_attempts']==1 and record['private_attempts']==1 and len(record['proof'])==9222 and not record['private_done'] and Path(str(self.source)+'.staging.json').exists()): raise RuntimeError('upload checkpoint changed; refusing resume')
        if Path(str(self.source)+'.pending.json').exists(): raise RuntimeError('checkpoint has an unexpected pending payment')
        prepare(root)
        barrier=max(plan(root,i)['slot'] for i in [0,1])
        for i in [0,1]: self.children[i]=start(root,i,coordinated=True); wait_rpc(root,i)
        quiet(root); self.converge(barrier); self.wait_for(self.ready_history,timeout=30)
        if (kind=='pregas' and self.native_balance(setup['fee_address'])!=1_000_000_000) or len(durable(root,0))!=(11 if kind in ['browser','checks'] else 3): raise RuntimeError('checkpoint funding state changed')
        preserved={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ['sponsor.enc.json.disabled','sponsor-policy.json.disabled','sponsor-policy.json.reservations.json.disabled']}
        operator_balances={role:self.native_balance(config['roles'][role]) for role in ['sponsor','treasury']}
        for who in ['alice','bob','carol','dave']:
            self.clients[who]=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client'))
            if who!='carol' or kind in ['browser','checks']: self.keys[who]=self.user(who,'unlock')
        self.proxy=Acknowledgements(self.source)
        self.faucet=Faucet(self.faucet_root,self.password_file); self.serve(FaucetHandler,self.faucet,8780)
        if kind in ['browser','checks']:
            ledger=json.loads((self.faucet_root/'claims.json').read_text())
            if len(ledger['claims'])!=3 or any(not json.loads((self.faucet_root/(self.claim_id(c)+'.json')).read_text())['private_done'] for c in ledger['claims']): raise RuntimeError('browser checkpoint does not have three completed grants')
            if any(self.clients[w].status()[key] for w in ['alice','bob','carol'] for key in ['pending','staging']): raise RuntimeError('browser checkpoint has an unfinished tester payment')
            if kind=='browser':
                self.serve(Handler,self.clients['carol'],8774)
                self.event('browser_recovered_after_accepted_send',result=self.browser('resume'))
            return self.finish_after_browser(setup,config,preserved,operator_balances)
        return self.finish(first,setup,config,preserved,operator_balances,resume_upload=kind=='upload')

    def claim_id(self,claim): return hashlib.blake2b(claim['fee_address'].encode(),digest_size=32).hexdigest()

    def finish(self,first,setup,config,preserved,operator_balances,resume_upload=False):
        root=self.root; ledger_path=self.faucet_root/'claims.json'
        staging=Path(str(self.source)+'.staging.json')
        progress=self.faucet_root/(first['claim_id']+'.json')
        if not resume_upload:
            self.proxy.gate('gas'); child=self.tick_child()
            self.wait_gate(child,30)
            self.kill(child); self.proxy.clear()
            self.wait_for(lambda:self.native_balance(self.keys['alice']['fee_address'])==150_000_000)
            progress=self.faucet_root/(first['claim_id']+'.json'); before=json.loads(progress.read_text())
            if before['gas_done'] or before['gas_attempts']!=1: raise RuntimeError('gas crash did not retain original unsigned acknowledgement')
            self.event('gas_acknowledgement_lost',signed_transaction_retained=True,gas_balance=150_000_000)
            child=self.tick_child(); staging=Path(str(self.source)+'.staging.json')
            def live_stage():
                if child.poll() is not None:
                    out,err=child.communicate(); raise RuntimeError('worker exited before upload: '+out+err)
                if staging.exists():
                    record=json.loads(staging.read_text())
                    if account(0,record['staging_account'],'confirmed'): return record
            record=self.wait_for(live_stage,timeout=120); self.kill(child)
            if Path(str(self.source)+'.pending.json').exists(): raise RuntimeError('upload crash reached finalization too early')
            self.event('private_upload_crash',staging_account=record['staging_account'])
        # Recovery owns the original cap, closes the interrupted buffer, then grants once.
        self.tick(); self.assert_ready('alice')
        if self.balance('alice')['balance']!=1_000_000 or self.native_balance(self.keys['alice']['fee_address'])!=150_000_000: raise RuntimeError('Alice grant duplicated or missing')
        if json.loads(progress.read_text())['gas_attempts']!=1: raise RuntimeError('gas retry created a second transaction')
        self.event('upload_recovered',receipt=self.assert_ready('alice'))
        time.sleep(1.1); bob=self.claim('bob'); self.tick() # Gas sent, original identity retained.
        self.wait_for(lambda:self.native_balance(self.keys['bob']['fee_address'])==150_000_000)
        self.proxy.gate('private'); child=self.tick_child()
        self.wait_gate(child,150)
        self.kill(child); self.proxy.clear()
        pending=Path(str(self.source)+'.pending.json'); pending_hash=hashlib.sha256(pending.read_bytes()).hexdigest()
        state=durable(root,0); barrier=max(self.slots())
        self.event('private_finalization_acknowledgement_lost',pending_signature=json.loads(pending.read_text())['signature'])
        # Reconstruct services and restart both actual validators, preserving every journal.
        for i in [1,0]: stop(root,i)
        prepare(root)
        for i in [0,1]: self.children[i]=start(root,i,coordinated=True); wait_rpc(root,i)
        quiet(root); self.converge(barrier,state); self.wait_for(self.ready_history,timeout=30)
        if hashlib.sha256(pending.read_bytes()).hexdigest()!=pending_hash: raise RuntimeError('restart changed pending identity')
        self.tick(); self.assert_ready('bob')
        if self.balance('bob')['balance']!=1_000_000: raise RuntimeError('Bob grant duplicated after restart')
        self.event('coordinated_restart_recovered',native_state_equal=True,receipt=self.assert_ready('bob'))
        # Real rendered create -> backup -> get coins+gas -> private send.
        self.serve(Handler,self.clients['carol'],8774)
        self.worker=threading.Thread(target=self.faucet.work,daemon=True); self.worker.start()
        self.event('browser_onboarding_and_send',result=self.browser('onboard'))
        return self.finish_after_browser(setup,config,preserved,operator_balances)

    def finish_after_browser(self,setup,config,preserved,operator_balances):
        root=self.root; ledger_path=self.faucet_root/'claims.json'; staging=Path(str(self.source)+'.staging.json'); pending=Path(str(self.source)+'.pending.json')
        self.faucet.close()
        if self.worker: self.worker.join(timeout=15); self.worker=None
        self.keys['carol']=self.user('carol','unlock')
        self.assert_ready('carol')
        before_source=self.native_balance(setup['fee_address']); before_state=durable(root,0)
        for who in ['alice','bob','carol']:
            time.sleep(1.1); self.assert_ready(who)
        self.tick()
        if self.native_balance(setup['fee_address'])!=before_source or durable(root,0)!=before_state: raise RuntimeError('completed retry changed gas or nullifiers')
        time.sleep(1.1)
        try: self.claim('dave')
        except ValueError as error:
            if 'no grants left' not in str(error): raise
        else: raise RuntimeError('exhausted faucet accepted fourth wallet')
        if len(json.loads(ledger_path.read_text())['claims'])!=3: raise RuntimeError('lifetime claim capacity changed')
        restored=WalletApp.from_profile(self.profiles[0],self.evidence/'bob-restored')
        if not restored.status()['exists']:
            recovered=restored.action(dict(action='restore',password=self.password,backup=json.loads(self.clients['bob'].backup.read_text())))
        else:
            recovered=restored.action(dict(action='unlock',password=self.password))
        if recovered['address']!=self.keys['bob']['address']: raise RuntimeError('restored Bob seed differs')
        time.sleep(1.1)
        if restored.action(dict(action='test-coins',password=self.password))['claim_id']!=self.claim_id(next(c for c in json.loads(ledger_path.read_text())['claims'] if c['fee_address']==self.keys['bob']['fee_address'])): raise RuntimeError('restored seed acquired a new claim')
        quote=self.user('alice','fees',payment='send')
        send=self.user('alice','send',amount=200_000,recipient=self.keys['bob']['address'],fee_mode='user',max_fee_debit=quote['maximum_gross_debit'])
        self.closed(send['staging_account']); self.event('independent_user_paid_send',receipt=send)
        expected={'alice':850_000,'bob':1_200_000,'carol':950_000}
        for i in [0,1]:
            for who,value in expected.items():
                if self.balance(who,i)['balance']!=value: raise RuntimeError(f'{who} final private balance differs on validator {i}')
        final=durable(root,0)
        if final!=durable(root,1) or len(final)!=13: raise RuntimeError('expected pool plus 12 nullifiers on both peers')
        pool=base64.b64decode(account(0,config['pool'])['data'][0])
        if int.from_bytes(pool[48:56],'little')!=5_000_000: raise RuntimeError('private distribution changed public backing')
        # All public gas inflows must be exactly one fixed grant, independent of spending.
        for who in ['alice','bob','carol']:
            address=self.keys[who]['fee_address']; incoming=[]
            for item in rpc(18899,'getSignaturesForAddress',[address,{'commitment':'finalized','limit':1000}]):
                tx=rpc(18899,'getTransaction',[item['signature'],{'encoding':'json','commitment':'finalized','maxSupportedTransactionVersion':0}])
                keys=tx['transaction']['message']['accountKeys']
                if keys[0]==setup['fee_address'] and address in keys:
                    index=keys.index(address); incoming.append(tx['meta']['postBalances'][index]-tx['meta']['preBalances'][index])
            if incoming!=[150_000_000]: raise RuntimeError('gas was duplicated or redirected')
        for role,value in operator_balances.items():
            if self.native_balance(config['roles'][role])!=value: raise RuntimeError('distribution used an operator account after setup')
        if any(hashlib.sha256((root/name).read_bytes()).hexdigest()!=value for name,value in preserved.items()): raise RuntimeError('operator budgets changed')
        if staging.exists() or pending.exists(): raise RuntimeError('faucet recovery journal not closed')
        self.result.update(status='passed',grants=3,gas_per_wallet=150_000_000,private_per_wallet=1_000_000,private_balances=expected,pool_backing=5_000_000,permanent_nullifiers=12,operator_unchanged_after_setup=True,repeated_claims_created_no_transactions=True,restored_seed_reused_claim=True)
        self.event('self_service_distribution_passed')
    def close(self):
        if self.faucet: self.faucet.close()
        if self.worker: self.worker.join(timeout=15)
        for child in self.wallet_children:
            if child.poll() is None: child.kill(); child.communicate(timeout=10)
        for server,thread in reversed(self.services): server.shutdown(); server.server_close(); thread.join(timeout=5)
        if self.proxy: self.proxy.close()
        for i in [1,0]:
            if self.children[i] is not None and self.children[i].poll() is None: stop(self.root,i)


def checkpoint(root,kind):
    previous=json.loads((root/'faucet-result.json').read_text())
    events=[e['kind'] for e in previous.get('events',[])]
    valid=kind=='pregas' and events==['signed_claim_reserved_once'] and (previous.get('error')=='gas acknowledgement gate not reached' or 'replay-plan' in previous.get('error',''))
    valid=valid or (kind=='browser' and events==['signed_claim_reserved_once','gas_acknowledgement_lost','private_upload_crash','upload_recovered','private_finalization_acknowledgement_lost','coordinated_restart_recovered'] and previous.get('error')=='browser failed; inspect preserved evidence')
    valid=valid or (kind=='checks' and events==['signed_claim_reserved_once','gas_acknowledgement_lost','private_upload_crash','upload_recovered','private_finalization_acknowledgement_lost','coordinated_restart_recovered','browser_recovered_after_accepted_send'] and previous.get('error')=="name 'bob' is not defined")
    valid=valid or (kind=='upload' and events==['signed_claim_reserved_once','gas_acknowledgement_lost','private_upload_crash'] and previous.get('error')=='Faucet error: secret file exceeds its size bound\n')
    if previous.get('status')!='failed' or not valid:
        raise ValueError('resume requires its exact preserved failed checkpoint; completed evidence is never overwritten')
    return previous


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True); parser.add_argument('--evidence',type=Path,required=True)
    parser.add_argument('--browser-script',type=Path,required=True); parser.add_argument('--playwright-module',required=True)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--resume-pregas',action='store_true')
    group.add_argument('--resume-upload',action='store_true')
    group.add_argument('--resume-browser',action='store_true')
    group.add_argument('--resume-final-checks',action='store_true')
    args=parser.parse_args(); root=args.root.resolve(); evidence=args.evidence.resolve()
    resume='pregas' if args.resume_pregas else 'upload' if args.resume_upload else 'browser' if args.resume_browser else 'checks' if args.resume_final_checks else None
    if not root.is_relative_to(PROJECT/'.data') or (root.exists() and not resume): parser.error('use a new short .data root; never reset a faucet budget')
    if resume:
        try: checkpoint(root,resume)
        except (OSError,ValueError) as error: parser.error(str(error))
    evidence.mkdir(mode=0o700,parents=True,exist_ok=bool(resume))
    trial=Distribution(root,evidence,args.browser_script.resolve(),args.playwright_module)
    try: trial.run(resume)
    except Exception as error: trial.result.update(status='failed',error=str(error)); raise
    finally:
        try: trial.close()
        finally:
            if root.exists(): atomic_json(root/'faucet-result.json',trial.result)


if __name__=='__main__': main()
