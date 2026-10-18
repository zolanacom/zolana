#!/usr/bin/env python3
"""Fresh, local-only invite/RPC/faucet acceptance. Never resets existing budgets."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request

from faucet_localnet import Distribution, Acknowledgements, FAUCET, WALLET
from fault_localnet import account, atomic_json, durable
from localnet import LAB, PROJECT, load, quiet, rpc, start, stop, wait_rpc
from package_wallet import public_profile
from replay_localnet import prepare
from test_faucet import BoundedServer, Faucet, Handler as FaucetHandler
from testnet_gateway import Gateway, Handler as GatewayHandler
from wallet_localnet import private_new
from wallet_ui import Handler as WalletHandler, WalletApp


def post(port, path, data, headers=None):
    request = urllib.request.Request(f'http://127.0.0.1:{port}{path}', json.dumps(data).encode(), {'Content-Type':'application/json', **(headers or {})})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=20) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


class Invites(Distribution):
    def __init__(self, *args):
        super().__init__(*args)
        self.service_children=[]; self.proofs={}; self.codes={}; self.ids={}
    def event(self, kind, **fields):
        self.result['events'].append(dict(kind=kind, **fields)); atomic_json(self.root/'invite-result.json', self.result); print(kind, flush=True)
    def serve(self, handler, app, port):
        server=BoundedServer(('127.0.0.1',port),handler); server.authority,server.app=f'127.0.0.1:{port}',app
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start(); self.services.append((server,thread)); return server
    def http_services(self):
        self.faucet=Faucet(self.faucet_root,self.password_file)
        original=self.faucet.command
        def capture(command,data=None,extra=()):
            if command=='authorize': self.proofs['rpc']=data
            if command=='access-status': self.proofs['status']=data
            return original(command,data,extra)
        self.faucet.command=capture
        self.serve(FaucetHandler,self.faucet,8780); self.serve(GatewayHandler,Gateway(self.faucet),18898)
    def close_http(self):
        for server,thread in reversed(self.services): server.shutdown(); server.server_close(); thread.join(timeout=5)
        self.services=[]
        if self.faucet: self.faucet.close()
    def issue(self, name, ttl=3600, bound=None):
        path=self.operator/(name+'.invite.json')
        args=[str(FAUCET),'invite-issue','--root',str(self.faucet_root),'--output',str(path),'--expires-in',str(ttl)]
        if bound: args+=['--bind-fee',bound]
        result=self.command(args); self.ids[name]=result['invite_id']; self.codes[name]=json.loads(path.read_text())['invitation']
    def deny(self, who, code):
        try: self.user(who,'join',invitation=code)
        except ValueError: return
        raise RuntimeError('unauthorized invitation was accepted')
    def browser(self,phase):
        result=subprocess.run(['node',str(self.browser_script),str(self.evidence),phase], input=json.dumps(dict(password=self.password,recipient=self.keys['alice']['address'],invitation=self.codes['carol'],backup=json.loads(self.clients['carol'].backup.read_text()) if self.clients['carol'].backup.exists() else None)),capture_output=True,text=True,env=dict(self.env,PLAYWRIGHT_MODULE=self.module),timeout=300)
        (self.evidence/f'{phase}-browser.log').write_text(result.stdout+result.stderr)
        if result.returncode: raise RuntimeError('browser failed; preserved evidence contains details')
        return json.loads((self.evidence/f'{phase}-browser.json').read_text())
    def subprocess_services(self):
        for script,port in [('test_faucet.py',8780),('testnet_gateway.py',18898)]:
            log=open(self.evidence/(script+'.log'),'ab')
            child=subprocess.Popen(['python3','-B',str(PROJECT/'tools'/script),'--root',str(self.faucet_root),'--password-file',str(self.password_file),'--port',str(port)],stdout=log,stderr=log,env=self.env)
            log.close(); self.service_children.append(child)
        def ready():
            if any(p.poll() is not None for p in self.service_children): raise RuntimeError('invited service startup failed')
            try: return post(18898,'/',dict(jsonrpc='2.0',id=1,method='getGenesisHash'))[0]==200 and post(8780,'/status',self.proofs['status'])[0] in [200,429]
            except OSError: return False
        self.wait_for(ready,timeout=20)
    def kill_services(self):
        for child in self.service_children:
            if child.poll() is None: child.kill(); child.wait(timeout=15)
            if child.returncode!=-9: raise RuntimeError('service did not receive SIGKILL')
        self.service_children=[]
    def run(self,resume=None):
        if resume: raise ValueError('fresh root required; never automatically resubmit a failed payment')
        root=self.root; self.operator=PROJECT/'.local'/('operator-'+root.name); self.operator.mkdir(mode=0o700)
        cold,hot=self.operator/'cold.password',self.operator/'sponsor.password'
        for path in [cold,hot]: private_new(path,secrets.token_urlsafe(36).encode())
        self.command([str(LAB),'init-private',str(root),'--cold-password-file',str(cold),'--sponsor-password-file',str(hot)])
        for i in [0,1]: self.children[i]=start(root,i); wait_rpc(root,i)
        quiet(root); self.converge(0); self.wait_for(self.ready_history,timeout=30); config=load(root)
        self.password=secrets.token_urlsafe(36); self.password_file=self.operator/'faucet.password'; private_new(self.password_file,self.password.encode())
        source_profile=public_profile(config,'Invite rehearsal source','http://127.0.0.1:24899','loopback-http')
        source_file=self.evidence/'source-profile.json'; source_file.write_text(json.dumps(source_profile))
        client_profile=public_profile(config,'Invited testnet rehearsal','http://127.0.0.1:18898','loopback-http')
        client_profile.update(invite_required=True,faucet=dict(transport='loopback-http',url='http://127.0.0.1:8780'))
        self.profiles=[self.evidence/'profile.json']; self.profiles[0].write_text(json.dumps(client_profile))
        self.faucet_root=root/'faucet'
        setup=self.command([str(FAUCET),'init','--root',str(self.faucet_root),'--profile',str(source_file),'--password-file',str(self.password_file),'--max-claims','6'])
        self.source=self.faucet_root/'wallet.enc.json'; self.proxy=Acknowledgements(self.source)
        self.command([str(FAUCET),'access-init','--root',str(self.faucet_root),'--profile',str(self.profiles[0]),'--daily-admissions','3','--rpc-limit','2000'])
        receipt=self.command([str(WALLET),'deposit','--network',str(root/'network.json'),'--wallet',str(self.source),'--password-file',str(self.password_file),'--rpc','http://127.0.0.1:18899','--sponsor-password-file',str(hot),'--sponsor-request-id','invited-testnet-reservoir','--amount','5000000'])
        self.closed(receipt['staging_account'])
        self.command([str(LAB),'fund-faucet-check',str(root),str(self.source),str(self.password_file),str(cold),'http://127.0.0.1:18899'])
        self.wait_for(lambda:self.native_balance(setup['fee_address'])==1_000_000_000)
        preserved={}
        for name in ['sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json']:
            path=root/name; path.rename(root/(name+'.disabled')); preserved[name+'.disabled']=hashlib.sha256((root/(name+'.disabled')).read_bytes()).hexdigest()
        operator_balances={role:self.native_balance(config['roles'][role]) for role in ['sponsor','treasury']}
        for who in ['alice','bob','dave','eve','carol']:
            self.clients[who]=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client'))
            if who!='carol': self.keys[who]=self.user(who,'create'); self.user(who,'ack-backup')
        self.http_services()
        self.issue('alice',bound=self.keys['alice']['fee_address']); self.issue('race'); self.issue('carol'); self.issue('expired',ttl=1); self.issue('revoked'); self.issue('spare')
        self.command([str(FAUCET),'invite-revoke','--root',str(self.faucet_root),'--invite-id',self.ids['revoked']]); time.sleep(1.2)
        for code in ['invite1_'+'A'*43,self.codes['expired'],self.codes['revoked'],self.codes['alice']]: self.deny('eve',code)
        for method in ['getBalance','sendTransaction','getProgramAccounts']:
            if post(18898,'/',dict(jsonrpc='2.0',id=1,method=method,params=[]))[0]!=403: raise RuntimeError('uninvited RPC bypass')
        if post(8780,'/',{})[0]!=403: raise RuntimeError('legacy claim bypass')
        if json.loads((self.faucet_root/'claims.json').read_text())['claims']: raise RuntimeError('invalid access reserved funds')
        self.event('uninvited_rpc_and_faucet_denied',source_funding_unchanged=self.native_balance(setup['fee_address'])==1_000_000_000)
        alice=self.user('alice','join',invitation=self.codes['alice'])
        def redeem(who):
            try: return who,self.user(who,'join',invitation=self.codes['race'])
            except ValueError: return who,None
        with ThreadPoolExecutor(max_workers=2) as pool: winners=[r for r in pool.map(redeem,['bob','dave']) if r[1]]
        if len(winners)!=1: raise RuntimeError('redemption race did not have one winner')
        winner,race=winners[0]
        if winner=='dave': self.clients['bob'],self.clients['dave']=self.clients['dave'],self.clients['bob']; self.keys['bob'],self.keys['dave']=self.keys['dave'],self.keys['bob']
        self.deny('dave',self.codes['race'])
        if self.user('alice','test-coins')['claim_id']!=alice['claim_id']: raise RuntimeError('same-wallet retry changed grant')
        if len(json.loads((self.faucet_root/'claims.json').read_text())['claims'])!=2: raise RuntimeError('race reserved duplicate grants')
        self.event('one_invite_one_wallet_race_and_retry',claims=2)
        self.proxy.gate('gas'); child=self.tick_child(); self.wait_gate(child,30); self.kill(child); self.proxy.clear()
        self.wait_for(lambda:self.native_balance(self.keys['alice']['fee_address'])==150_000_000)
        admission_before=hashlib.sha256((self.faucet_root/'admission.json').read_bytes()).hexdigest(); state=durable(root,0); barrier=max(self.slots())
        self.close_http()
        for i in [1,0]: stop(root,i)
        prepare(root)
        for i in [0,1]: self.children[i]=start(root,i,coordinated=True); wait_rpc(root,i)
        quiet(root); self.converge(barrier,state); self.wait_for(self.ready_history,timeout=30)
        if hashlib.sha256((self.faucet_root/'admission.json').read_bytes()).hexdigest()!=admission_before: raise RuntimeError('restart changed invitation state')
        self.http_services(); self.deny('dave',self.codes['race'])
        return self.finish_invited(setup,config,preserved,operator_balances,race)

    def finish_invited(self,setup,config,preserved,operator_balances,race):
        root=self.root
        deadline=time.monotonic()+480
        while time.monotonic()<deadline:
            self.tick()
            if self.user('alice','test-coins')['state']=='ready' and self.user('bob','test-coins')['state']=='ready': break
            time.sleep(2)
        else: raise RuntimeError('grant recovery failed')
        self.event('gas_ack_crash_and_validator_restart_recovered',admission_unchanged=True)
        self.serve(WalletHandler,self.clients['carol'],8776)
        self.worker=threading.Thread(target=self.faucet.work,daemon=True); self.worker.start()
        self.event('browser_invite_onboarding_and_private_send',result=self.browser('onboard'))
        return self.after_browser(setup,config,preserved,operator_balances,race)

    def after_browser(self,setup,config,preserved,operator_balances,race):
        root=self.root
        self.faucet.close()
        if self.worker: self.worker.join(timeout=15)
        self.worker=None
        self.keys['carol']=self.user('carol','unlock')
        restored=WalletApp.from_profile(self.profiles[0],self.evidence/'bob-restored')
        result=restored.action(dict(action='restore',password=self.password,backup=json.loads(self.clients['bob'].backup.read_text())))
        if result['fee_address']!=self.keys['bob']['fee_address'] or not restored.admitted: raise RuntimeError('seed restore did not recover invitation access')
        if restored.action(dict(action='test-coins',password=self.password))['claim_id']!=race['claim_id']: raise RuntimeError('restore created another grant')
        restored_ui=WalletApp.from_profile(self.profiles[0],self.evidence/'carol-ui-restored')
        self.serve(WalletHandler,restored_ui,8777)
        self.event('browser_seed_restore_without_invitation',result=self.browser('restore'))
        self.deny('eve',self.codes['spare'])  # Daily admission ceiling, even with a genuine unused invitation.
        expected={'alice':1_050_000,'bob':1_000_000,'carol':950_000}
        for who,value in expected.items():
            if self.balance(who)['balance']!=value: raise RuntimeError('private balances differ')
        self.converge(0); final=durable(root,0)
        if final!=durable(root,1) or len(final)!=11: raise RuntimeError('expected pool and ten permanent nullifiers')
        pool=base64.b64decode(account(0,config['pool'])['data'][0])
        if int.from_bytes(pool[48:56],'little')!=5_000_000: raise RuntimeError('pool backing changed during admission/distribution')
        for who in expected:
            incoming=[]; address=self.keys[who]['fee_address']
            for item in rpc(18899,'getSignaturesForAddress',[address,{'commitment':'finalized','limit':1000}]):
                tx=rpc(18899,'getTransaction',[item['signature'],{'encoding':'json','commitment':'finalized','maxSupportedTransactionVersion':0}]); keys=tx['transaction']['message']['accountKeys']
                if keys[0]==setup['fee_address'] and address in keys:
                    i=keys.index(address); incoming.append(tx['meta']['postBalances'][i]-tx['meta']['preBalances'][i])
            if incoming!=[150_000_000]: raise RuntimeError('gas duplicated across recovery')
        self.event('seed_restore_reuses_admission_and_grant',grants=3,private_balances=expected,permanent_nullifiers=10)
        # Capture fresh signed session proofs in memory, then replace all HTTP services
        # with independently launched production processes and SIGKILL them twice.
        self.user('bob','balance'); self.user('bob','access-status'); rpc_proof=self.proofs['rpc']; status_proof=self.proofs['status']
        header=base64.urlsafe_b64encode(json.dumps(rpc_proof).encode()).rstrip(b'=').decode()
        self.close_http(); self.subprocess_services()
        if post(18898,'/',dict(jsonrpc='2.0',id=1,method='getBalance',params=[self.keys['bob']['fee_address']]),{'X-Testnet-Access':header})[0]!=200: raise RuntimeError('restored gateway rejected member')
        # Keep the quota test within one real minute; no synthetic clock or ledger edits.
        if time.time()%60>40: time.sleep(61-time.time()%60)
        for _ in range(35):
            code,_=post(8780,'/status',status_proof)
            if code==429: break
            if code!=200: raise RuntimeError('status failed before quota')
        else: raise RuntimeError('faucet member quota not enforced')
        self.kill_services(); self.subprocess_services()
        if post(8780,'/status',status_proof)[0]!=429: raise RuntimeError('process restart reset faucet quota')
        self.command([str(FAUCET),'invite-revoke','--root',str(self.faucet_root),'--invite-id',self.ids['race']])
        if post(18898,'/',dict(jsonrpc='2.0',id=1,method='getBalance',params=[self.keys['bob']['fee_address']]),{'X-Testnet-Access':header})[0]!=403: raise RuntimeError('revoked session retained RPC access')
        self.kill_services(); self.subprocess_services()
        if post(18898,'/',dict(jsonrpc='2.0',id=1,method='getBalance',params=[self.keys['bob']['fee_address']]),{'X-Testnet-Access':header})[0]!=403: raise RuntimeError('restart restored revoked session')
        self.event('production_service_sigkill_preserves_quotas_and_revocation',same_signed_session_denied_after_restart=True)
        for role,value in operator_balances.items():
            if self.native_balance(config['roles'][role])!=value: raise RuntimeError('used operator funds after setup')
        if any(hashlib.sha256((root/name).read_bytes()).hexdigest()!=value for name,value in preserved.items()): raise RuntimeError('operator budgets changed')
        if len(json.loads((self.faucet_root/'claims.json').read_text())['claims'])!=3 or durable(root,0)!=final or durable(root,1)!=final: raise RuntimeError('abuse/restarts changed accepted value')
        for code in self.codes.values():
            if code in (self.faucet_root/'admission.json').read_text(): raise RuntimeError('raw invitation saved in server ledger')
        self.result.update(status='passed',grants=3,private_balances=expected,permanent_nullifiers=10,operator_unchanged_after_setup=True,raw_validator_rpc_operator_loopback_only=True)
        self.event('invited_testnet_acceptance_passed')
    def resume_gas_poll(self,compat=False):
        previous=compat_checkpoint(self.root,self.evidence) if compat else gas_checkpoint(self.root)
        self.result['events']=previous['events']; self.result['prior_errors']=previous.get('prior_errors',[])+[previous['error']]
        root=self.root; self.operator=PROJECT/'.local'/('operator-'+root.name)
        self.password_file=self.operator/'faucet.password'; self.password=self.password_file.read_text()
        self.faucet_root=root/'faucet'; self.source=self.faucet_root/'wallet.enc.json'; self.profiles=[self.evidence/'profile.json']
        for name in ['alice','race','carol','expired','revoked','spare']:
            export=json.loads((self.operator/(name+'.invite.json')).read_text()); self.codes[name]=export['invitation']; self.ids[name]=export['invite_id']
        state=json.loads((self.faucet_root/'admission.json').read_text()); race_member=next(i['member'] for i in state['invitations'] if i['id']==self.ids['race'])
        for who in ['alice','bob','dave','eve','carol']:
            self.clients[who]=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client'))
            if who!='carol' or compat: self.keys[who]=self.user(who,'unlock')
        if self.keys['dave']['fee_address']==race_member['claim']['fee_address']:
            self.clients['bob'],self.clients['dave']=self.clients['dave'],self.clients['bob']; self.keys['bob'],self.keys['dave']=self.keys['dave'],self.keys['bob']
        if self.keys['bob']['fee_address']!=race_member['claim']['fee_address']: raise RuntimeError('original race authority changed')
        prepare(root)
        for i in [0,1]: self.children[i]=start(root,i,coordinated=True); wait_rpc(root,i)
        quiet(root); self.converge(0); self.wait_for(self.ready_history,timeout=30)
        if len(durable(root,0))!=(9 if compat else 5): raise RuntimeError('gas-poll native checkpoint changed')
        config=load(root); ledger=json.loads((self.faucet_root/'claims.json').read_text()); setup={'fee_address':ledger['policy']['source_fee_address']}
        operator_balances={'sponsor':992_596_440,'treasury':8_999_995_000}
        if any(self.native_balance(config['roles'][r])!=v for r,v in operator_balances.items()): raise RuntimeError('operator setup balances changed')
        preserved={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ['sponsor.enc.json.disabled','sponsor-policy.json.disabled','sponsor-policy.json.reservations.json.disabled']}
        self.proxy=Acknowledgements(self.source); self.http_services(); race={'claim_id':self.claim_id(race_member['claim'])}
        if compat:
            self.event('original_grants_resumed_after_rpc_compatibility_fix')
            self.serve(WalletHandler,self.clients['carol'],8776)
            self.event('browser_invite_onboarding_and_private_send',result=self.browser('continue-invited'))
            return self.after_browser(setup,config,preserved,operator_balances,race)
        self.event('original_gas_poll_checkpoint_resumed_without_new_funding')
        return self.finish_invited(setup,config,preserved,operator_balances,race)

    def close(self):
        for child in self.service_children:
            if child.poll() is None: child.kill(); child.wait(timeout=15)
        self.service_children=[]
        super().close()


def gas_checkpoint(root):
    previous=json.loads((root/'invite-result.json').read_text())
    if previous.get('status')!='failed' or previous.get('error')!='Faucet error: RPC response error -32002: Transaction simulation failed: This transaction has already been processed; \n' or [e['kind'] for e in previous.get('events',[])]!=['uninvited_rpc_and_faucet_denied','one_invite_one_wallet_race_and_retry']:
        raise ValueError('resume requires the exact failed pre-finality gas checkpoint; completed evidence is never overwritten')
    faucet=root/'faucet'; ledger=json.loads((faucet/'claims.json').read_text())
    if len(ledger['claims'])!=2 or not ledger['policy']['invite_required'] or Path(str(faucet/'wallet.enc.json')+'.pending.json').exists() or Path(str(faucet/'wallet.enc.json')+'.staging.json').exists(): raise ValueError('original grant checkpoint changed')
    progress=[json.loads((faucet/(hashlib.blake2b(c['fee_address'].encode(),digest_size=32).hexdigest()+'.json')).read_text()) for c in ledger['claims']]
    if [(p['gas_attempts'],p['gas_done'],p['private_attempts'],p['private_done']) for p in progress]!=[(1,True,1,True),(1,False,0,False)]: raise ValueError('original progress/attempt identities changed')
    return previous

def compat_checkpoint(root,evidence):
    previous=json.loads((root/'invite-result.json').read_text())
    if previous.get('status')!='failed' or previous.get('error')!='browser failed; preserved evidence contains details' or [e['kind'] for e in previous.get('events',[])]!=['uninvited_rpc_and_faucet_denied','one_invite_one_wallet_race_and_retry','original_gas_poll_checkpoint_resumed_without_new_funding','gas_ack_crash_and_validator_restart_recovered']:
        raise ValueError('resume requires the exact failed RPC compatibility checkpoint')
    browser=json.loads((evidence/'onboard-browser.json').read_text())
    if browser.get('sends')!=0 or browser.get('receipt') or browser['claims'][-1]['state']!='ready': raise ValueError('browser may have submitted value; refusing to repeat it')
    faucet=root/'faucet'; ledger=json.loads((faucet/'claims.json').read_text())
    if len(ledger['claims'])!=3 or not ledger['policy']['invite_required']: raise ValueError('claim checkpoint changed')
    for c in ledger['claims']:
        p=json.loads((faucet/(hashlib.blake2b(c['fee_address'].encode(),digest_size=32).hexdigest()+'.json')).read_text())
        if (p['gas_attempts'],p['gas_done'],p['private_attempts'],p['private_done'])!=(1,True,1,True): raise ValueError('grant checkpoint changed')
    for base in [faucet/'wallet.enc.json',evidence/'carol-client/wallet-ui/wallet.json']:
        if any(Path(str(base)+suffix).exists() for suffix in ['.pending.json','.staging.json']): raise ValueError('unfinished value operation at checkpoint')
    return previous

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True); parser.add_argument('--evidence',type=Path,required=True)
    group=parser.add_mutually_exclusive_group()
    group.add_argument('--resume-gas-poll',action='store_true'); group.add_argument('--resume-rpc-compat',action='store_true')
    parser.add_argument('--browser-script',type=Path,required=True); parser.add_argument('--playwright-module',required=True)
    args=parser.parse_args(); root=args.root.resolve(); evidence=args.evidence.resolve()
    if not root.is_relative_to(PROJECT/'.data') or (root.exists() and not (args.resume_gas_poll or args.resume_rpc_compat)): parser.error('a fresh short .data root is required; never reset an existing budget')
    if args.resume_gas_poll: gas_checkpoint(root)
    if args.resume_rpc_compat: compat_checkpoint(root,evidence)
    evidence.mkdir(mode=0o700,parents=True,exist_ok=args.resume_gas_poll or args.resume_rpc_compat)
    trial=Invites(root,evidence,args.browser_script.resolve(),args.playwright_module)
    try:
        if args.resume_gas_poll or args.resume_rpc_compat: trial.resume_gas_poll(compat=args.resume_rpc_compat)
        else: trial.run()
    except Exception as error: trial.result.update(status='failed',error=str(error)); raise
    finally:
        try: trial.close()
        finally:
            if root.exists(): atomic_json(root/'invite-result.json',trial.result)


if __name__=='__main__': main()
