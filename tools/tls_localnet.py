#!/usr/bin/env python3
"""Real local TLS, protected raw RPC, payment and restart acceptance on fresh keys."""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request

from faucet_localnet import Distribution, FAUCET, WALLET
from fault_localnet import atomic_json, durable
from localnet import LAB, PROJECT, load, quiet, rpc, start, stop, wait_rpc
from local_test_tls import create as certificates
from package_wallet import public_profile
from replay_localnet import prepare
from rpc_isolation import enable
from service_tls import TLSServer, context, listener, operator_token
from test_faucet import Faucet, Handler as FaucetHandler
from testnet_gateway import Gateway, Handler as GatewayHandler
from wallet_localnet import private_new
from wallet_ui import WalletApp


def request(url,data=None,ca=None,headers=None,method=None):
    body=None if data is None else json.dumps(data).encode()
    ctx=ssl.create_default_context(cafile=str(ca) if ca else None)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
    req=urllib.request.Request(url,body,{'Content-Type':'application/json',**(headers or {})},method=method)
    try:
        with opener.open(req,timeout=8) as response:return response.status,response.read()
    except urllib.error.HTTPError as error:return error.code,error.read()


class GatedGateway(Gateway):
    def __init__(self,faucet):
        self.pending=None;self.reached=threading.Event();self.release=threading.Event()
        super().__init__(faucet)
    def forward(self,raw):
        result=super().forward(raw);query=json.loads(raw)
        if self.pending and self.pending.exists() and query.get('method')=='getSignatureStatuses':
            signature=json.loads(self.pending.read_text())['signature']
            for sig,status in zip(query.get('params',[[]])[0],json.loads(result).get('result',{}).get('value',[])):
                if sig==signature and status and status.get('confirmationStatus')=='finalized' and status.get('err') is None:
                    self.reached.set();self.release.wait(10)
        return result


class TLSExperiment(Distribution):
    def __init__(self,root,evidence):
        super().__init__(root,evidence,None,None);self.processes=[];self.proofs={};self.gated=None
    def event(self,kind,**values):
        self.result['events'].append(dict(kind=kind,**values));atomic_json(self.root/'tls-result.json',self.result);print(kind,flush=True)
    def public(self,method='getGenesisHash',headers=None):
        return request('https://127.0.0.1:18898',dict(jsonrpc='2.0',id=1,method=method),self.ca,headers)
    def raw_probes(self):
        for port in [18899,19899]:
            for path in ['','/health','/genesis.tar.bz2','/snapshot.tar.bz2','/?x-native-operator=not-a-credential']:
                code,_=request(f'http://127.0.0.1:{port}'+path,dict(jsonrpc='2.0',id=1,method='getGenesisHash') if not path else None)
                if code!=403:raise RuntimeError('raw HTTP bypass reached a route')
            code,_=request(f'http://127.0.0.1:{port}',dict(jsonrpc='2.0',id=1,method='sendTransaction',params=[]),headers={'X-Native-Operator':'0'*64})
            if code!=403:raise RuntimeError('wrong operator credential accepted')
            try:
                with socket.create_connection(('127.0.0.1',port+1),timeout=.5):pass
            except OSError:pass
            else:raise RuntimeError('protected validator opened raw WebSockets')
    def serve_tls(self,handler,app,port,cert='server'):
        endpoint=f'https://127.0.0.1:{port}'
        server=listener(endpoint,port,handler,app,self.tls/(cert+'.crt'),self.tls/(cert+'.key'))
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.services.append((server,thread));return server
    def launch_tls(self):
        self.faucet=Faucet(self.faucet_root,self.password_file);original=self.faucet.command
        def capture(command,data=None,extra=()):
            if command=='authorize':self.proofs['rpc']=data
            if command=='access-status':self.proofs['status']=data
            return original(command,data,extra)
        self.faucet.command=capture;self.gated=GatedGateway(self.faucet)
        self.serve_tls(FaucetHandler,self.faucet,8780);self.serve_tls(GatewayHandler,self.gated,18898)
    def close_tls(self):
        if self.gated:self.gated.release.set()
        for server,thread in reversed(self.services):server.shutdown();server.server_close();thread.join(timeout=5)
        self.services=[]
        if self.faucet:self.faucet.close()
    def production(self):
        for script,port in [('test_faucet.py',8780),('testnet_gateway.py',18898)]:
            stream=(self.evidence/(script+'.log')).open('ab')
            child=subprocess.Popen(['python3','-B',str(PROJECT/'tools'/script),'--root',str(self.faucet_root),'--password-file',str(self.password_file),'--port',str(port),'--tls-cert',str(self.tls/'rotated.crt'),'--tls-key',str(self.tls/'rotated.key')],stdout=stream,stderr=stream,env=self.env);stream.close();self.processes.append(child)
        def ready():
            if any(p.poll() is not None for p in self.processes):raise RuntimeError('TLS production startup failed')
            try:return self.public()[0]==200 and request('https://127.0.0.1:8780/status',self.proofs['status'],self.ca)[0] in [200,429]
            except OSError:return False
        self.wait_for(ready,timeout=20)
    def kill_tls(self):
        for child in self.processes:
            if child.poll() is None:child.kill();child.wait(timeout=15)
            if child.returncode!=-9:raise RuntimeError('TLS child did not receive SIGKILL')
        self.processes=[]
    def startup_probes(self):
        for script,port in [('testnet_gateway.py',18898),('test_faucet.py',8780)]:
            base=['python3','-B',str(PROJECT/'tools'/script),'--root',str(self.faucet_root),'--password-file',str(self.password_file),'--port',str(port)]
            for extra in [[],['--tls-cert',str(self.tls/'rotated.crt'),'--tls-key',str(self.tls/'missing.key')],['--tls-cert',str(self.tls/'rotated.crt'),'--tls-key',str(self.tls/'server.key')]]:
                result=subprocess.run(base+extra,capture_output=True,text=True,env=self.env,timeout=20)
                if result.returncode==0:raise RuntimeError('invalid TLS startup was accepted')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.3):pass
                except OSError:pass
                else:raise RuntimeError('invalid TLS startup opened a listener')
        self.event('missing_or_mismatched_tls_material_never_opened_http')
    def certificate_probes(self):
        # Default roots cannot trust this isolated local CA.
        try:self.public_without_ca()
        except (OSError,urllib.error.URLError):pass
        else:raise RuntimeError('untrusted local CA was accepted')
        for port in [18898,8780]:
            try:request(f'http://127.0.0.1:{port}',dict(jsonrpc='2.0',id=1,method='getGenesisHash'))
            except OSError:pass
            else:raise RuntimeError('TLS listener accepted cleartext HTTP')
        owner=self
        class Probe(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                self.server.hits+=1;raw=json.dumps(dict(jsonrpc='2.0',id=1,result=load(owner.root)['genesis_hash'])).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        for name,key in [('wrong-host','wrong-host'),('expired','server')]:
            server=TLSServer(('127.0.0.1',18897),Probe,context(self.tls/(name+'.crt'),self.tls/(key+'.key')));server.hits=0
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            try:
                bad=json.loads(self.profiles[0].read_text());bad['rpc']['url']='https://127.0.0.1:18897';path=self.evidence/(name+'-profile.json');path.write_text(json.dumps(bad))
                result=subprocess.run([str(WALLET),'check','--network',str(path)],capture_output=True,text=True,env=self.env,timeout=25)
                if result.returncode==0 or server.hits:raise RuntimeError('Rust wallet accepted invalid TLS before HTTP')
            finally:server.shutdown();server.server_close();thread.join(timeout=5)
        self.event('tls_certificate_hostname_and_plaintext_rejections_passed')
    def public_without_ca(self):return request('https://127.0.0.1:18898',dict(jsonrpc='2.0',id=1,method='getGenesisHash'))
    def run(self):
        root=self.root;self.operator=PROJECT/'.local'/('operator-'+root.name);self.operator.mkdir(mode=0o700)
        cold,hot=self.operator/'cold.password',self.operator/'sponsor.password'
        for path in [cold,hot]:private_new(path,secrets.token_urlsafe(36).encode())
        self.command([str(LAB),'init-private',str(root),'--cold-password-file',str(cold),'--sponsor-password-file',str(hot)])
        enable(root);self.tls=self.operator/'tls';certificates(self.tls);self.ca=self.tls/'ca.crt'
        self.secret_digest=hashlib.sha256((root/'rpc-access.key').read_bytes()).hexdigest()
        for i in [0,1]:self.children[i]=start(root,i);wait_rpc(root,i)
        quiet(root);self.converge(0);self.wait_for(self.ready_history,timeout=30);config=load(root);self.raw_probes();self.event('raw_http_routes_protected_and_websockets_closed')
        self.password=secrets.token_urlsafe(36);self.password_file=self.operator/'faucet.password';private_new(self.password_file,self.password.encode())
        source_profile=public_profile(config,'TLS operator source','http://127.0.0.1:18899','loopback-http');source_file=self.evidence/'source-profile.json';source_file.write_text(json.dumps(source_profile))
        profile=public_profile(config,'Local HTTPS rehearsal','https://127.0.0.1:18898','https');profile.update(invite_required=True,local_tls_ca_pem=self.ca.read_text(),faucet={'transport':'https','url':'https://127.0.0.1:8780'})
        self.profiles=[self.evidence/'profile.json'];self.profiles[0].write_text(json.dumps(profile));self.faucet_root=root/'faucet'
        setup=self.command([str(FAUCET),'init','--root',str(self.faucet_root),'--profile',str(source_file),'--password-file',str(self.password_file),'--max-claims','2','--rpc-access-file',str(root/'rpc-access.key')])
        self.source=self.faucet_root/'wallet.enc.json'
        receipt=self.command([str(WALLET),'deposit','--network',str(root/'network.json'),'--wallet',str(self.source),'--password-file',str(self.password_file),'--rpc','http://127.0.0.1:18899','--rpc-access-file',str(root/'rpc-access.key'),'--sponsor-password-file',str(hot),'--sponsor-request-id','https-test-reservoir','--amount','5000000']);self.closed(receipt['staging_account'])
        self.command([str(LAB),'fund-faucet-check',str(root),str(self.source),str(self.password_file),str(cold),'http://127.0.0.1:18899']);self.wait_for(lambda:self.native_balance(setup['fee_address'])==1_000_000_000)
        self.preserved={}
        for name in ['sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json']:
            path=root/name;path.rename(root/(name+'.disabled'));self.preserved[name+'.disabled']=hashlib.sha256((root/(name+'.disabled')).read_bytes()).hexdigest()
        self.operator_balances={role:self.native_balance(config['roles'][role]) for role in ['sponsor','treasury']}
        self.command([str(FAUCET),'access-init','--root',str(self.faucet_root),'--profile',str(self.profiles[0]),'--daily-admissions','2','--rpc-limit','2000'])
        self.launch_tls();self.certificate_probes()
        if self.public('getBalance')[0]!=403:raise RuntimeError('HTTPS bypassed admission')
        no_ca={k:v for k,v in profile.items() if k!='local_tls_ca_pem'};path=self.evidence/'untrusted-profile.json';path.write_text(json.dumps(no_ca))
        self.command([str(WALLET),'check','--network',str(path)],reject='Wallet error:')
        self.command([str(WALLET),'check','--network',str(self.profiles[0])])
        self.invite_ids={}
        for who in ['alice','bob']:
            app=WalletApp.from_profile(self.profiles[0],self.evidence/(who+'-client'));self.clients[who]=app;self.keys[who]=self.user(who,'create');self.user(who,'ack-backup')
            export=self.operator/(who+'.invite.json');issued=self.command([str(FAUCET),'invite-issue','--root',str(self.faucet_root),'--output',str(export),'--expires-in','86400','--bind-fee',self.keys[who]['fee_address']]);self.invite_ids[who]=issued['invite_id']
            self.user(who,'join',invitation=json.loads(export.read_text())['invitation'])
        deadline=time.monotonic()+480
        while time.monotonic()<deadline:
            self.tick()
            if all(self.user(w,'test-coins')['state']=='ready' for w in ['alice','bob']):break
            time.sleep(2)
        else:raise RuntimeError('HTTPS grant queue did not finish')
        self.event('two_private_grants_through_verified_https',source=setup)
        quote=self.user('alice','fees',payment='send');app=self.clients['alice'];self.gated.pending=Path(str(app.wallet)+'.pending.json')
        args=[str(WALLET),'send','--network',str(self.profiles[0]),'--wallet',str(app.wallet),'--password-file',str(self.password_file),'--amount','50000','--to',self.keys['bob']['address'],'--fee-payer','user','--max-fee-debit',str(quote['maximum_gross_debit'])]
        child=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=self.env);self.wallet_children.append(child)
        deadline=time.monotonic()+180
        while not self.gated.reached.wait(.1):
            if child.poll() is not None:
                out,err=child.communicate();raise RuntimeError('payment exited before TLS acknowledgement gate: '+out+err)
            if time.monotonic()>deadline:raise RuntimeError('TLS acknowledgement gate timeout')
        self.kill(child);self.gated.release.set();pending=self.gated.pending;pending_digest=hashlib.sha256(pending.read_bytes()).hexdigest();state=durable(root,0);barrier=max(self.slots())
        self.event('real_private_finality_reply_lost_over_tls',pending_signature=json.loads(pending.read_text())['signature'])
        self.close_tls();admission_digest=hashlib.sha256((self.faucet_root/'admission.json').read_bytes()).hexdigest()
        for i in [1,0]:stop(root,i)
        # Missing files cannot change a managed restart into an open raw listener.
        credential=root/'rpc-access.key';saved=root/'rpc-access.key.preserved';credential.rename(saved)
        try:
            try:start(root,0,coordinated=True)
            except (ValueError,OSError):pass
            else:raise RuntimeError('missing credential permitted restart')
        finally:saved.rename(credential)
        prepare(root)
        for i in [0,1]:self.children[i]=start(root,i,coordinated=True);wait_rpc(root,i)
        quiet(root);self.converge(barrier,state);self.wait_for(self.ready_history,timeout=30);self.raw_probes()
        if hashlib.sha256(pending.read_bytes()).hexdigest()!=pending_digest or hashlib.sha256((self.faucet_root/'admission.json').read_bytes()).hexdigest()!=admission_digest:raise RuntimeError('restart reset original payment or admission')
        self.startup_probes()
        self.production() # New leaf certificate, original CA/profile/keys/journals.
        resolution=self.user('alice','resolve')
        if not resolution.get('accepted'):raise RuntimeError('original pending payment did not resolve')
        if self.clients['alice'].status()['staging']:self.user('alice','reclaim')
        if self.balance('alice')['balance']!=950_000 or self.balance('bob')['balance']!=1_050_000:raise RuntimeError('TLS recovery private balances differ')
        if durable(root,0)!=durable(root,1) or len(durable(root,0))!=9:raise RuntimeError('TLS restart changed permanent nullifiers')
        self.event('tls_rotation_validator_restart_and_original_payment_recovered',private_balances={'alice':950000,'bob':1050000},permanent_nullifiers=8)
        # Exhaust and reload the same durable per-member bucket over HTTPS.
        if time.time()%60>40:time.sleep(61-time.time()%60)
        for _ in range(35):
            code,_=request('https://127.0.0.1:8780/status',self.proofs['status'],self.ca)
            if code==429:break
            if code!=200:raise RuntimeError('HTTPS status failed before quota')
        else:raise RuntimeError('HTTPS quota not enforced')
        self.kill_tls();self.production()
        if request('https://127.0.0.1:8780/status',self.proofs['status'],self.ca)[0]!=429:raise RuntimeError('TLS process restart reset quota')
        fee=self.proofs['rpc']['fee_address'];who=next(w for w in ['alice','bob'] if self.keys[w]['fee_address']==fee)
        self.command([str(FAUCET),'invite-revoke','--root',str(self.faucet_root),'--invite-id',self.invite_ids[who]])
        header=base64.urlsafe_b64encode(json.dumps(self.proofs['rpc']).encode()).rstrip(b'=').decode()
        if self.public('getBalance',{'X-Testnet-Access':header})[0]!=403:raise RuntimeError('revocation bypassed HTTPS')
        self.kill_tls();self.production()
        if self.public('getBalance',{'X-Testnet-Access':header})[0]!=403:raise RuntimeError('TLS restart reset revocation')
        self.raw_probes()
        if hashlib.sha256((root/'rpc-access.key').read_bytes()).hexdigest()!=self.secret_digest:raise RuntimeError('raw credential changed')
        if any(self.native_balance(config['roles'][role])!=value for role,value in self.operator_balances.items()):raise RuntimeError('operator account used after setup')
        if any(hashlib.sha256((root/name).read_bytes()).hexdigest()!=value for name,value in self.preserved.items()):raise RuntimeError('operator budget changed')
        if len(json.loads((self.faucet_root/'claims.json').read_text())['claims'])!=2 or durable(root,0)!=state or durable(root,1)!=state:raise RuntimeError('TLS abuse or recovery repeated a payment')
        self.result.update(status='passed',grants=2,permanent_nullifiers=8,private_balances={'alice':950000,'bob':1050000},tls_leaf_rotation_recovered=True,raw_rpc_protected_after_restart=True,quotas_and_revocation_survived_tls_sigkill=True,operator_unchanged_after_setup=True)
        self.event('local_tls_and_rpc_isolation_passed')
    def close(self):
        if self.gated:self.gated.release.set()
        for child in self.processes:
            if child.poll() is None:child.kill();child.wait(timeout=15)
        self.processes=[];super().close()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True);args=parser.parse_args()
    root=args.root.resolve();evidence=args.evidence.resolve()
    if not root.is_relative_to(PROJECT/'.data') or root.exists():parser.error('use a fresh short root; never reset keys or funding')
    evidence.mkdir(mode=0o700,parents=True,exist_ok=False);trial=TLSExperiment(root,evidence)
    try:trial.run()
    except Exception as error:trial.result.update(status='failed',error=str(error));raise
    finally:
        try:trial.close()
        finally:
            if root.exists():atomic_json(root/'tls-result.json',trial.result)


if __name__=='__main__':main()
