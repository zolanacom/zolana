"""Invited desktop-wallet ingress inside the sealed service UID boundary."""
import hashlib
import json
from pathlib import Path
import secrets
import threading
import time

from local_test_tls import create as certificates
from service_runtime import ROOT, OPERATORS, BASE, LAB, WALLET, ready, load, private, save, run_json, rpc, sponsor
from service_tls import listener
from test_faucet import Faucet, Handler as FaucetHandler
from testnet_gateway import Gateway, Handler as GatewayHandler

FAUCET=BASE/'target/debug/native-faucet'
STATE=ROOT/'ingress-setup.json'
FAUCET_ROOT=ROOT/'faucet'
PASSWORD=OPERATORS/'faucet.password'
TLS=OPERATORS/'ingress-tls'
PROFILE=ROOT/'client-profile.json'
RPC_PORT=23898
FAUCET_PORT=13780


def public_profile(config,ca=None):
    result={'format':'native-wallet-profile-v1','label':'Local isolated privacy testnet',
        'key_mode':'user-wallet-v1',**{key:config[key] for key in ('network','genesis_hash','program','pool','pool_format','recipient_withdrawals')},
        'rpc':{'transport':'loopback-http' if ca is None else 'https','url':'http://127.0.0.1:23899' if ca is None else f'https://127.0.0.1:{RPC_PORT}'}}
    if ca is not None:result.update(invite_required=True,local_tls_ca_pem=ca,
        faucet={'transport':'https','url':f'https://127.0.0.1:{FAUCET_PORT}'})
    return result


def faucet(command,extra=()):
    return run_json([FAUCET,command,'--root',FAUCET_ROOT,*extra])


def source(command,extra=()):
    return run_json([WALLET,command,'--network',ROOT/'network.json','--wallet',FAUCET_ROOT/'wallet.enc.json',
        '--password-file',PASSWORD,'--rpc','http://127.0.0.1:23899','--rpc-access-file',ROOT/'rpc-access.key',*extra])


def check_ready():
    state=json.loads(STATE.read_text())
    if state.get('phase')!='ready' or hashlib.sha256(PROFILE.read_bytes()).hexdigest()!=state['profile_sha256']:
        raise ValueError('ingress setup/profile incomplete or changed; preserve original state')
    profile=json.loads(PROFILE.read_text())
    if profile!=public_profile(load(ROOT),(TLS/'ca.crt').read_text()):raise ValueError('client profile no longer matches service identity')
    info=faucet('access-info')
    if not info.get('invite_required') or info['rpc_audience']!=profile['rpc']['url'] or info['faucet_audience']!=profile['faucet']['url']:
        raise ValueError('original invitation policy changed')
    return state


def initialize():
    """One finite reservoir; interrupted value operations require journal recovery."""
    ready()
    if STATE.exists():
        state=json.loads(STATE.read_text())
        if state.get('phase')=='ready':check_ready();return {'ready':True,'existing_setup':True}
        raise ValueError('ingress setup interrupted at '+str(state.get('phase'))+'; recover its original journals explicitly, never reinitialize or resubmit funding')
    if any(path.exists() for path in (FAUCET_ROOT,PASSWORD,TLS,PROFILE,ROOT/'source-profile.json')):
        raise ValueError('unrecorded ingress state exists; refusing initialization')
    state={'phase':'preparing'};save(STATE,state)
    private(PASSWORD,secrets.token_urlsafe(36).encode());certificates(TLS)
    config=load(ROOT);save(ROOT/'source-profile.json',public_profile(config))
    save(PROFILE,public_profile(config,(TLS/'ca.crt').read_text()))
    run_json([WALLET,'profile','--network',PROFILE])
    setup=faucet('init',['--profile',ROOT/'source-profile.json','--password-file',PASSWORD,'--max-claims','2','--rpc-access-file',ROOT/'rpc-access.key'])
    state.update(phase='deposit_submitting',source_fee_address=setup['fee_address']);save(STATE,state)
    receipt=source('deposit',sponsor('isolated-ingress-reservoir-v1')+['--amount','5000000'])
    state.update(phase='deposit_finalized',deposit_signature=receipt.get('signature'));save(STATE,state)
    if Path(str(FAUCET_ROOT/'wallet.enc.json')+'.staging.json').exists():source('reclaim',sponsor())
    if source('balance')['balance']!=5_000_000:raise ValueError('original reservoir deposit not recovered exactly')
    state['phase']='gas_submitting';save(STATE,state)
    funding=run_json([LAB,'fund-faucet-check',ROOT,FAUCET_ROOT/'wallet.enc.json',PASSWORD,OPERATORS/'cold.password','http://127.0.0.1:23899'])
    state.update(phase='gas_pending',gas_signature=funding['signature']);save(STATE,state)
    end=time.monotonic()+120
    while rpc(23899,'getBalance',[setup['fee_address'],{'commitment':'finalized'}])['value']!=1_000_000_000:
        if time.monotonic()>end:raise ValueError('original reservoir gas funding not finalized; retain original signature')
        time.sleep(.5)
    state['phase']='admission_initializing';save(STATE,state)
    faucet('access-init',['--profile',PROFILE,'--daily-admissions','2','--rpc-limit','2000'])
    state.update(phase='ready',profile_sha256=hashlib.sha256(PROFILE.read_bytes()).hexdigest(),
        setup_sponsor_sha256={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in ['sponsor.enc.json','sponsor-policy.json','sponsor-policy.json.reservations.json']})
    save(STATE,state);check_ready()
    return {'ready':True,'max_claims':2,'public_profile_contains_service_keys':False,'restart_required_to_open_ingress':True}


def export_client(client):
    check_ready()
    if client not in ('alice','bob'):raise ValueError('unknown fixed local test client')
    path=ROOT/(client+'-desktop-invite.json')
    if not path.exists():faucet('invite-issue',['--output',path,'--expires-in','86400'])
    invitation=json.loads(path.read_text())
    return {'profile':json.loads(PROFILE.read_text()),'invitation':invitation['invitation'],'invite_id':invitation['invite_id']}


class Ingress:
    def __init__(self):
        check_ready();self.services=[];self.threads=[];self.worker=None;self.faucet=None
        try:
            self.faucet=Faucet(FAUCET_ROOT,PASSWORD,binary=FAUCET)
            gateway=Gateway(self.faucet)
            for port,handler,app,endpoint in [(FAUCET_PORT,FaucetHandler,self.faucet,gateway.info['faucet_audience']),
                (RPC_PORT,GatewayHandler,gateway,gateway.info['rpc_audience'])]:
                self.services.append(listener(endpoint,port,handler,app,TLS/'server.crt',TLS/'server.key'))
            for server in self.services:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.threads.append(thread)
            self.worker=threading.Thread(target=self.faucet.work,daemon=True);self.worker.start()
        except BaseException:self.close();raise

    def healthy(self):return self.worker is not None and self.worker.is_alive() and all(t.is_alive() for t in self.threads)

    def close(self):
        if self.faucet:self.faucet.close()
        for index,server in reversed(list(enumerate(self.services))):
            if index<len(self.threads):server.shutdown()
            server.server_close()
        for thread in self.threads:thread.join(timeout=12)
        if self.worker:self.worker.join(timeout=12)
        self.services=[];self.threads=[];self.worker=None
