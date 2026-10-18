"""Invited desktop-wallet ingress inside the sealed service UID boundary."""
import hashlib
import json
import os
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
ACK_GATE=ROOT/'gateway-ack-test-022.json'
ACK_BROADCASTS=ROOT/'gateway-ack-broadcasts-022.json'


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


def signature(value):
    if not isinstance(value,str) or not 64<=len(value)<=88 or any(c not in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in value):
        raise ValueError('invalid exact test transaction signature')
    return value


def browser_test_paths():
    """Fixed service-only namespace; preserve prior acceptance evidence."""
    global ACK_GATE,ACK_BROADCASTS
    ACK_GATE=ROOT/'browser-ack-test-024.json'
    ACK_BROADCASTS=ROOT/'browser-ack-broadcasts-024.json'


def restore_test_paths():
    """Keep first-restore acceptance separate from earlier crash evidence."""
    global ACK_GATE,ACK_BROADCASTS
    ACK_GATE=ROOT/'restore-ack-test-025.json'
    ACK_BROADCASTS=ROOT/'restore-ack-broadcasts-025.json'


def arm_ack_gate(target):
    signature(target)
    if os.path.lexists(ACK_GATE):raise ValueError('acknowledgement experiment already started; retain its original record')
    private(ACK_GATE,json.dumps({'phase':'armed','signature':target,'expires_at':time.time()+180}).encode())
    return {'phase':'armed','signature':target}


def ack_gate():
    if not os.path.lexists(ACK_GATE):return None
    from service_tls import private_bytes
    gate=json.loads(private_bytes(ACK_GATE,4096))
    signature(gate.get('signature'))
    if gate.get('phase') not in ('armed','held') or type(gate.get('expires_at')) not in (int,float):raise ValueError('invalid private test gate')
    return gate


class FinalityGateGateway(Gateway):
    """Only selected by the temporary administrator-owned run-ack-test job."""
    def __init__(self,faucet,history_root=None,archive_rpc=None):
        self.gate_lock=threading.Lock();self.release=threading.Event()
        ack_gate()  # Unsafe existing controls fail before opening a listener.
        super().__init__(faucet,history_root=history_root,archive_rpc=archive_rpc)

    def forward(self,raw,timeout=15):
        query=json.loads(raw);attempt=None
        if query.get('method')=='sendTransaction':
            with self.gate_lock:
                log=self.broadcasts()
                if len(log['attempts'])>=256:raise ValueError('bounded test broadcast log exhausted')
                attempt=len(log['attempts']);log['attempts'].append({'request_sha256':hashlib.sha256(raw).hexdigest(),'signature':None})
                save(ACK_BROADCASTS,log)  # Count even a failed/interrupted attempt.
        result=super().forward(raw,timeout=timeout)
        if attempt is not None:
            with self.gate_lock:
                log=self.broadcasts();log['attempts'][attempt]['signature']=json.loads(result).get('result')
                save(ACK_BROADCASTS,log)
        if query.get('method')!='getSignatureStatuses':return result
        held=False
        with self.gate_lock:
            gate=ack_gate()
            if gate and gate['phase']=='armed' and time.time()<gate['expires_at']:
                for target,status in zip(query.get('params',[[]])[0],json.loads(result).get('result',{}).get('value',[])):
                    if target==gate['signature'] and status and status.get('confirmationStatus')=='finalized' and status.get('err') is None:
                        gate.update(phase='held',response_sha256=hashlib.sha256(result).hexdigest(),finalized_slot=status['slot'])
                        save(ACK_GATE,gate);held=True;break
        if held:
            self.release.wait(60)
            # Never return this selected acknowledgement, including on timeout.
            raise OSError('local test withheld the original finalized acknowledgement')
        return result

    def broadcasts(self):
        if not os.path.lexists(ACK_BROADCASTS):return {'attempts':[]}
        from service_tls import private_bytes
        log=json.loads(private_bytes(ACK_BROADCASTS,65536))
        if set(log)!={'attempts'} or not isinstance(log['attempts'],list) or len(log['attempts'])>256:raise ValueError('invalid bounded broadcast log')
        return log


def ack_checkpoint():
    from service_runtime import canonical,slots
    # A fresh service action has no process-local Unix RPC routes until load.
    # Initialize them before the first status query, just as ready/canonical do.
    load(ROOT)
    gate=ack_gate()
    if not gate or gate['phase']!='held':raise ValueError('original finalized acknowledgement not held')
    status=rpc(23899,'getSignatureStatuses',[[gate['signature']],{'searchTransactionHistory':True}])['value'][0]
    if not status or status.get('confirmationStatus')!='finalized' or status.get('err') is not None:raise ValueError('original signature is not canonically finalized')
    return {'signature':gate['signature'],'native_state':canonical(),'slots':slots(),'gate':gate}


def browser_close_checkpoint(target):
    config=load(ROOT);signature(target)
    value=rpc(23899,'getTransaction',[target,{'encoding':'json','commitment':'finalized','maxSupportedTransactionVersion':0}])
    if not value or value['meta']['err'] is not None:raise ValueError('staging cleanup is not finalized successfully')
    message=value['transaction']['message'];keys=message['accountKeys'];native=[]
    for instruction in message['instructions']:
        program=keys[instruction['programIdIndex']]
        if program==config['program']:native.append(instruction)
        elif program!='ComputeBudget111111111111111111111111111111':raise ValueError('unexpected program in staging cleanup')
    # Native Close is one byte 0x04, encoded as base58 "5" in JSON RPC.
    if len(native)!=1 or native[0]['data']!='5' or len(native[0]['accounts'])!=2:raise ValueError('recovery broadcast was not an original staging close')
    return {'signature':target,'staging_account':keys[native[0]['accounts'][0]],'only_native_close':True}


class PackageRecoveryGateway(Gateway):
    """Bounded package-recovery test: record and reject any broadcast attempt."""
    def forward(self,raw,timeout=15):
        if json.loads(raw).get('method')=='sendTransaction':
            private(ROOT/'package-recovery-broadcast-attempt-023.json',
                json.dumps({'request_sha256':hashlib.sha256(raw).hexdigest(),'attempted':True}).encode())
            raise ValueError('package journal recovery must not broadcast a transaction')
        return super().forward(raw,timeout=timeout)


class Ingress:
    def __init__(self,ack_test=False,package_test=False,browser_test=False,restore_test=False):
        check_ready();self.services=[];self.threads=[];self.worker=None;self.faucet=None
        try:
            if restore_test:restore_test_paths()
            elif browser_test:browser_test_paths()
            self.faucet=Faucet(FAUCET_ROOT,PASSWORD,binary=FAUCET)
            gateway=(PackageRecoveryGateway if package_test else FinalityGateGateway if ack_test or browser_test or restore_test else Gateway)(self.faucet,history_root=ROOT/'recovery-history-mirror',archive_rpc='http://127.0.0.1:23899')
            self.gateway=gateway
            for port,handler,app,endpoint in [(FAUCET_PORT,FaucetHandler,self.faucet,gateway.info['faucet_audience']),
                (RPC_PORT,GatewayHandler,gateway,gateway.info['rpc_audience'])]:
                self.services.append(listener(endpoint,port,handler,app,TLS/'server.crt',TLS/'server.key'))
            for server in self.services:
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.threads.append(thread)
            self.worker=threading.Thread(target=self.faucet.work,daemon=True);self.worker.start()
        except BaseException:self.close();raise

    def healthy(self):return self.worker is not None and self.worker.is_alive() and all(t.is_alive() for t in self.threads)

    def close(self):
        if getattr(self,'gateway',None) is not None and isinstance(self.gateway,FinalityGateGateway):self.gateway.release.set()
        if self.faucet:self.faucet.close()
        for index,server in reversed(list(enumerate(self.services))):
            if index<len(self.threads):server.shutdown()
            server.server_close()
        for thread in self.threads:thread.join(timeout=12)
        if self.worker:self.worker.join(timeout=12)
        self.services=[];self.threads=[];self.worker=None
