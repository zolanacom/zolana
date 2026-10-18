#!/usr/bin/env python3
"""Desktop-UID acceptance through the isolated service's invited HTTPS ingress."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request

from wallet_ui import WalletApp,WALLET
from wallet_localnet import private_new


def validate_ca_refresh(original,replacement):
    if {k:v for k,v in original.items() if k!='local_tls_ca_pem'}!={k:v for k,v in replacement.items() if k!='local_tls_ca_pem'}:
        raise ValueError('certificate refresh cannot change genesis, network, endpoints or admission policy')
    certificates=[]
    for profile in (original,replacement):
        certificate=profile.get('local_tls_ca_pem','')
        if (not isinstance(certificate,str) or not 1<=len(certificate)<=16384 or
            certificate.count('-----BEGIN CERTIFICATE-----')!=1 or certificate.count('-----END CERTIFICATE-----')!=1 or
            not certificate.strip().startswith('-----BEGIN CERTIFICATE-----') or not certificate.strip().endswith('-----END CERTIFICATE-----')):
            raise ValueError('one bounded public local CA required; additional trust anchors forbidden')
        certificates.append(certificate)
    keys=[subprocess.run(['/usr/bin/openssl','x509','-pubkey','-noout'],input=certificate,text=True,capture_output=True,check=True,timeout=10).stdout for certificate in certificates]
    if not keys[0] or keys[0]!=keys[1]:raise ValueError('certificate refresh cannot replace original trusted CA public key')


def refresh_ca(root,export):
    root=root.resolve();profile=root/'profile.json'
    wallets=[root/(who+'-client')/'wallet-ui'/name for who in ('alice','bob') for name in ('wallet.json','recovery.json')]
    wallet_hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in wallets}
    original=json.loads(profile.read_text());replacement=json.loads(export.read_text())['profile']
    validate_ca_refresh(original,replacement)
    if original==replacement:return {'public_profile_already_current':True}
    targets={profile:json.dumps(replacement).encode()}
    for who in ('alice','bob'):
        network=root/(who+'-client')/'network.json'
        if json.loads(network.read_text())!=original:raise ValueError('original client profile differs; recover explicitly')
        targets[network]=(json.dumps(replacement,sort_keys=True,indent=2)+'\n').encode()
        path=root/(who+'-export.json');data=json.loads(path.read_text())
        if data['profile']!=original:raise ValueError('original export differs; recover explicitly')
        data['profile']=replacement;targets[path]=json.dumps(data).encode()
    temporary=root/'refreshed-profile.json';private_new(temporary,json.dumps(replacement).encode())
    subprocess.run([str(WALLET),'profile','--network',str(temporary)],check=True,capture_output=True,text=True,timeout=20)
    for path in targets:private_new(path.with_name(path.name+'.before-ca-identifiers'),path.read_bytes())
    for path,raw in targets.items():
        pending=path.with_name(path.name+'.ca-refresh');private_new(pending,raw);os.replace(pending,path)
    if wallet_hashes!={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in wallets}:raise ValueError('original wallet or recovery file changed')
    return {'original_ca_public_key_unchanged':True,'profile_certificates_refreshed':len(targets),'wallets_backups_and_funding_untouched':True}


class Acceptance:
    def __init__(self,root,exports):
        self.root=root.resolve();self.root.mkdir(mode=0o700,exist_ok=True)
        if self.root.stat().st_mode&0o077:raise ValueError('private acceptance directory required')
        self.record=self.root/'acceptance.json'
        if not self.record.exists():
            if exports is None:raise ValueError('first run requires the two private client exports')
            private_new(self.root/'password',secrets.token_urlsafe(36).encode())
            for who,path in zip(('alice','bob'),exports):
                if path.is_symlink() or path.stat().st_uid!=os.getuid() or path.stat().st_mode&0o077:raise ValueError('unsafe client export')
                data=path.read_bytes()
                if len(data)>16384:raise ValueError('client export exceeds bound')
                private_new(self.root/(who+'-export.json'),data)
            a=json.loads((self.root/'alice-export.json').read_text());b=json.loads((self.root/'bob-export.json').read_text())
            if a['profile']!=b['profile']:raise ValueError('client network mismatch')
            private_new(self.root/'profile.json',json.dumps(a['profile']).encode())
            self.save({'phase':'created'})
        self.state=json.loads(self.record.read_text());self.password=(self.root/'password').read_text()
        self.clients={who:WalletApp.from_profile(self.root/'profile.json',self.root/(who+'-client')) for who in ('alice','bob')}

    def save(self,state):
        temporary=self.record.with_suffix('.new');private_new(temporary,json.dumps(state,sort_keys=True).encode());os.replace(temporary,self.record);self.state=state

    def user(self,who,action,**values):return self.clients[who].action(dict(action=action,password=self.password,**values))

    def balances(self):return {who:self.user(who,'balance')['balance'] for who in self.clients}

    def fingerprints(self):
        return {who:{name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in
            [('wallet',app.wallet),('backup',app.backup),('network',app.network_file),('ack',app.ack)]} for who,app in self.clients.items()}

    def security(self):
        denied={}
        for name in ('identity-0.keypair.json','voter-0.keypair.json','rpc-access.key'):
            try:
                with open('/Library/NativePayLocal/.data/s20/'+name,'rb'):pass
            except PermissionError:denied[name]=True
            else:raise ValueError('desktop accessed private service material')
        for port in (23899,24899):
            with socket.socket(socket.AF_UNIX) as client:
                try:client.connect('/Library/NativePayLocal/.data/s20/rpc-'+str(port)+'.sock')
                except PermissionError:denied[str(port)]=True
                else:raise ValueError('desktop accessed raw service RPC')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.5):pass
            except OSError:pass
            else:raise ValueError('raw validator TCP opened')
        profile=json.loads((self.root/'profile.json').read_text());context=ssl.create_default_context(cadata=profile['local_tls_ca_pem'])
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        def request(method,headers=None):
            req=urllib.request.Request(profile['rpc']['url'],json.dumps({'jsonrpc':'2.0','id':1,'method':method}).encode(),{'Content-Type':'application/json',**(headers or {})})
            try:
                with opener.open(req,timeout=10) as response:return response.status
            except urllib.error.HTTPError as e:return e.code
        if request('getGenesisHash')!=200 or request('getBalance')!=403 or request('getGenesisHash',{'Origin':'http://untrusted.invalid'})!=403 or request('validatorExit')!=403:
            raise ValueError('invited gateway bypass')
        return {'desktop_file_and_socket_denials':denied,'raw_tcp_closed':True,'unauthenticated_methods_and_browser_origins_denied':True,'pinned_https_verified':True}

    def onboard(self):
        if self.state['phase'] not in ('created','funded'):raise ValueError('onboarding already left setup phase')
        deadline=time.monotonic()+120
        while True:
            check=subprocess.run([str(WALLET),'check','--network',str(self.root/'profile.json')],capture_output=True,text=True,timeout=20)
            if check.returncode==0:break
            if time.monotonic()>deadline:raise ValueError('original pinned HTTPS ingress not ready: '+check.stderr[-800:])
            time.sleep(2)
        for who,app in self.clients.items():
            if not app.status()['exists']:self.user(who,'create')
            self.user(who,'ack-backup')
            if self.user(who,'access-status').get('admitted') is not True:
                self.user(who,'join',invitation=json.loads((self.root/(who+'-export.json')).read_text())['invitation'])
        deadline=time.monotonic()+480
        while True:
            statuses={who:self.user(who,'test-coins') for who in self.clients}
            if all(r['state']=='ready' and r['gas_finalized'] and r['private_finalized'] for r in statuses.values()):break
            if time.monotonic()>deadline:raise ValueError('original grant queue not ready; retain original claims and journals')
            time.sleep(7)
        balances=self.balances()
        if balances!={'alice':1_000_000,'bob':1_000_000}:raise ValueError('initial private grants differ')
        self.state.update(phase='funded',initial_balances=balances,security_before=self.security());self.save(self.state)
        return {'phase':'funded','private_balances':balances,'independent_desktop_wallets':2,'self_service_grants':2}

    def payment(self):
        if self.state['phase']!='funded':raise ValueError('never repeat a started payment; recover its original pending journal')
        quote=self.user('alice','fees',payment='send');recipient=self.user('bob','unlock')['address']
        self.state.update(phase='send_started',maximum_fee_debit=quote['maximum_gross_debit']);self.save(self.state)
        receipt=self.user('alice','send',amount=50_000,recipient=recipient,fee_mode='user',max_fee_debit=quote['maximum_gross_debit'])
        self.state.update(phase='sent',signature=receipt.get('signature'));self.save(self.state)
        return self.checkpoint()

    def checkpoint(self):
        if self.state['phase'] not in ('sent','checkpoint'):raise ValueError('original payment must complete before checkpoint')
        for who,app in self.clients.items():
            if app.status()['pending']:raise ValueError('original pending payment requires explicit resolution')
            if app.status()['staging']:self.user(who,'reclaim')
        balances=self.balances()
        if balances!={'alice':950_000,'bob':1_050_000}:raise ValueError('private send balances differ')
        self.state.update(phase='checkpoint',private_balances=balances,fingerprints=self.fingerprints());self.save(self.state)
        return {'phase':'checkpoint','private_balances':balances,'fee_mode':'user','signature':self.state.get('signature')}

    def verify(self):
        if self.state['phase'] not in ('checkpoint','passed'):raise ValueError('no original recovery checkpoint')
        if self.fingerprints()!=self.state['fingerprints'] or self.balances()!=self.state['private_balances']:
            raise ValueError('original desktop wallet or balances changed after restart')
        for who in self.clients:
            if not self.user(who,'access-status').get('admitted') or self.user(who,'test-coins')['state']!='ready':raise ValueError('original admission/grant did not recover')
        self.state.update(phase='passed',security_after=self.security());self.save(self.state)
        return {'phase':'passed','private_balances':self.state['private_balances'],'original_wallets_and_backups_unchanged':True,'admission_and_existing_grants_recovered':True,'desktop_cannot_access_raw_rpc_or_validator_keys':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=['onboard','payment','checkpoint','verify','refresh-ca'])
    parser.add_argument('--root',type=Path,required=True);parser.add_argument('--alice-export',type=Path);parser.add_argument('--bob-export',type=Path);parser.add_argument('--new-export',type=Path)
    args=parser.parse_args();exports=(args.alice_export,args.bob_export) if args.alice_export and args.bob_export else None
    if args.action=='refresh-ca':
        if args.new_export is None:parser.error('refresh-ca requires --new-export')
        result=refresh_ca(args.root,args.new_export)
    else:result=getattr(Acceptance(args.root,exports),args.action)()
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
