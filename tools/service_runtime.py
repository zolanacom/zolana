#!/usr/bin/env python3
"""Sealed service-side lifecycle and bounded private-payment recovery acceptance."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import math
import os
from pathlib import Path
import secrets
import signal
import shutil
import socket
import subprocess
import sys
import threading
import time

BASE=Path(__file__).resolve().parents[1]
# -I excludes both the desktop environment and the script directory. Only the
# sealed root-owned tools directory is added, before importing service helpers.
if BASE!=Path('/Library/NativePayLocal'):
    raise PermissionError('service runtime requires the sealed installation')
sys.path.insert(0,str(BASE/'tools'))
from service_account import verify_install
CONFIG=verify_install()
if os.getuid()!=CONFIG['uid'] or os.geteuid()!=CONFIG['uid'] or os.getgid()!=CONFIG['gid']:
    raise PermissionError('service runtime requires its dedicated unprivileged identity')
from localnet import LAB, VALIDATOR, load, start, stop, wait_rpc, quiet, rpc
from replay_localnet import prepare
from rpc_isolation import enable
from operator_transport import Operator, credential

ROOT=BASE/'.data/s20'
OPERATORS=BASE/'.data/operators'
WALLET=BASE/'target/debug/native-wallet'
SHIFT=5000


def private(path,raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def save(path,data):
    temporary=path.with_suffix(path.suffix+'.new')
    private(temporary,json.dumps(data,sort_keys=True).encode());os.replace(temporary,path)
    directory=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(directory)
    finally:os.close(directory)


def run_json(args,timeout=180):
    result=subprocess.run([str(a) for a in args],capture_output=True,text=True,timeout=timeout,env={'PATH':'/usr/bin:/bin','SOLANA_METRICS_CONFIG':''})
    if result.returncode:raise RuntimeError('service command failed; original private state retained: '+result.stderr[-1500:])
    return json.loads(result.stdout)


def initialize():
    marker=BASE/'.data/setup.started'
    if marker.exists() or ROOT.exists():raise ValueError('never reinitialize service genesis, keys or budgets')
    private(marker,b'native-service-setup-v1')
    OPERATORS.mkdir(mode=0o700)
    for name in ['cold.password','sponsor.password','wallet.password']:private(OPERATORS/name,secrets.token_urlsafe(36).encode())
    run_json([LAB,'init-private',ROOT,'--cold-password-file',OPERATORS/'cold.password','--sponsor-password-file',OPERATORS/'sponsor.password'])
    config=load(ROOT);config['local_port_offset']=SHIFT;save(ROOT/'network.json',config);enable(ROOT,hardened=True)
    private(BASE/'.data/setup.complete',b'native-service-setup-v1')
    return {'initialized':True,'keys_generated_as_uid':os.getuid(),'raw_tcp_disabled':True}


def slots():return [rpc(p,'getSlot',[{'commitment':'finalized'}]) for p in [23899,24899]]


def canonical():
    config=load(ROOT);states=[]
    for port in [23899,24899]:
        entries=rpc(port,'getProgramAccounts',[config['program'],{'encoding':'base64','commitment':'finalized'}])
        states.append({e['pubkey']:e['account'] for e in entries if base64.b64decode(e['account']['data'][0])[:8] in [b'NPOOL003',b'NSPENT01']})
    if states[0]!=states[1]:raise RuntimeError('service peers have not converged')
    return states[0]


def ready(timeout=120):
    load(ROOT);end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            for index in [0,1]:wait_rpc(ROOT,index,timeout=2)
            if min(slots())>0:return
        except (OSError,ValueError,RuntimeError):pass
        time.sleep(.3)
    raise RuntimeError('service validators not ready')


def supervise(ack_test=False,package_test=False,browser_test=False,restore_test=False,retention_test=False):
    if ack_test or package_test or browser_test or restore_test or retention_test:os.nice(10)
    load(ROOT)
    if not (BASE/'.data/setup.complete').is_file():raise RuntimeError('setup incomplete; keys cannot be regenerated')
    children=[None,None];shutdown=threading.Event();ingress=None;retention=None
    def terminate(*_):
        shutdown.set()
        if retention is not None:retention.stop.set()
    signal.signal(signal.SIGTERM,terminate);signal.signal(signal.SIGINT,terminate)
    def pause_owned():
        nonlocal ingress,retention
        errors=[]
        for name,worker in [('ingress',ingress),('retention',retention)]:
            if name=='ingress':ingress=None
            else:retention=None
            if worker is not None:
                try:worker.close()
                except Exception:errors.append(name)
        for i in [1,0]:
            if children[i] is not None and children[i].poll() is None:
                try:stop(ROOT,i)
                except Exception:errors.append('validator-'+str(i))
        if errors:raise RuntimeError('owned service cleanup failed: '+','.join(errors))
    def park(reason):
        pause_owned()
        print(reason+'; validators paused and original private state retained.',flush=True)
        while not shutdown.wait(5):pass

    try:
        test_deadline=None
        if ack_test or package_test or browser_test or restore_test or retention_test:
            from service_tls import private_bytes
            session_name='history-retention-session-026.json' if retention_test else 'restore-recovery-session-025.json' if restore_test else 'browser-recovery-session-024.json' if browser_test else 'package-recovery-session-023.json' if package_test else 'gateway-ack-session-022.json'
            session_format='local-history-retention-test-v1' if retention_test else 'local-restore-recovery-test-v1' if restore_test else 'local-browser-recovery-test-v1' if browser_test else 'local-package-recovery-test-v1' if package_test else 'local-gateway-ack-test-v1'
            session=json.loads(private_bytes(ROOT/session_name,4096))
            test_deadline=session.get('expires_at')
            if (set(session)!={'format','expires_at'} or session['format']!=session_format or
                type(test_deadline) not in (float,int) or not math.isfinite(test_deadline) or test_deadline>time.time()+600):
                raise ValueError('invalid bounded acknowledgement experiment session')
            if time.time()>=test_deadline:
                print('Acknowledgement experiment expired; validators kept paused.',flush=True)
                while not shutdown.wait(5):pass
                return
        if shutil.disk_usage(ROOT).free<1536*1024*1024:
            print('Service kept paused: less than 1.5 GiB free; private state retained.',flush=True)
            while not shutdown.wait(5):pass
            return
        if any((ROOT/f'consensus-{i}').exists() for i in [0,1]):prepare(ROOT)
        for i in [0,1]:children[i]=start(ROOT,i,coordinated=True,new_session=False);wait_rpc(ROOT,i)
        quiet(ROOT)
        save(ROOT/'service-instance.json',{'supervisor':os.getpid(),'validators':[p.pid for p in children],'started_at':time.time(),'uid':os.getuid(),'gid':os.getgid(),'process_groups':[os.getpgid(p.pid) for p in children]})
        from history_retention import Retention
        try:
            retention=Retention(ROOT,WALLET,'http://127.0.0.1:23899',lambda method,params:rpc(23899,method,params),
                credential=ROOT/'rpc-access.key')
            retention.start()
        except Exception:
            park('History retention initialization failed')
            return
        if shutdown.is_set():return
        if test_deadline is not None and time.time()>=test_deadline:
            park('Test-duration guard before ingress')
            return
        if (ROOT/'ingress-setup.json').exists():
            from service_ingress import Ingress
            if json.loads((ROOT/'ingress-setup.json').read_text()).get('phase')=='ready':
                ingress=Ingress(restore_test=True) if restore_test else Ingress(browser_test=True) if browser_test else Ingress(package_test=True) if package_test else Ingress(ack_test=True) if ack_test else Ingress()
        while not shutdown.wait(1):
            if any(p.poll() is not None for p in children):raise RuntimeError('owned validator exited; restart the coordinated service group')
            if not retention.healthy():
                park('History retention verification, lag or capacity guard')
                return
            if ingress is not None and not ingress.healthy():raise RuntimeError('wallet ingress worker exited; restart original service group')
            if shutil.disk_usage(ROOT).free<1024*1024*1024 or (test_deadline is not None and time.time()>=test_deadline):
                park('Disk or test-duration guard')
                return
    finally:
        pause_owned()


def args(who,action,extra=(),proxy=False):
    return [WALLET,action,'--network',ROOT/'network.json','--wallet',ROOT/(who+'.wallet.json'),
        '--password-file',OPERATORS/'wallet.password','--rpc','http://127.0.0.1:63899' if proxy else 'http://127.0.0.1:23899',
        '--rpc-access-file',ROOT/('test-proxy.key' if proxy else 'rpc-access.key'),*extra]


def sponsor(request=None):
    result=['--sponsor-password-file',OPERATORS/'sponsor.password']
    if request:result+=['--sponsor-request-id',request]
    return result


def balance(who):return run_json(args(who,'balance'))['balance']


def test_begin():
    ready();record=ROOT/'service-acceptance.json'
    if record.exists():raise ValueError('acceptance already started; recover original journals instead of creating payments')
    original_instance=json.loads((ROOT/'service-instance.json').read_text())
    save(record,{'phase':'started','original_instance':original_instance})
    for who in ['alice','bob']:
        run_json([WALLET,'init','--network',ROOT/'network.json','--wallet',ROOT/(who+'.wallet.json'),'--password-file',OPERATORS/'wallet.password','--backup',ROOT/(who+'.backup.json')])
    recipient=run_json(args('bob','address'))['address']
    deposit=run_json(args('alice','deposit',sponsor('service-test-deposit')+['--amount','100']))
    if Path(str(ROOT/'alice.wallet.json')+'.staging.json').exists():run_json(args('alice','reclaim',sponsor()))
    if balance('alice')!=100 or balance('bob')!=0:raise RuntimeError('service deposit state mismatch')
    token,routes=credential(ROOT/'rpc-access.key');proxy_path=ROOT/'ack-proxy.sock';pending=Path(str(ROOT/'alice.wallet.json')+'.pending.json')
    reached=threading.Event();release=threading.Event();upstream=Operator('http://127.0.0.1:23899',ROOT/'rpc-access.key')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_POST(self):
            import hmac
            if self.headers.get('Origin') or self.path!='/' or not hmac.compare_digest(self.headers.get('X-Native-Operator',''),token):self.send_error(403);return
            size=int(self.headers.get('Content-Length','0'))
            if not 1<=size<=100000:self.send_error(400);return
            raw=self.rfile.read(size);query=json.loads(raw);data=upstream.forward(raw)
            if query.get('method')=='getSignatureStatuses' and pending.exists():
                signature=json.loads(pending.read_text())['signature']
                for sig,status in zip(query.get('params',[[]])[0],json.loads(data).get('result',{}).get('value',[])):
                    if sig==signature and status and status.get('confirmationStatus')=='finalized' and status.get('err') is None:reached.set();release.wait(10)
            self.send_response(200);self.send_header('Content-Length',str(len(data)));self.send_header('Content-Type','application/json');self.end_headers()
            try:self.wfile.write(data)
            except (BrokenPipeError,ConnectionResetError):pass
    class UnixServer(HTTPServer):
        address_family=socket.AF_UNIX
        def server_bind(self):
            self.socket.bind(self.server_address)
            self.server_name='localhost';self.server_port=0
    server=UnixServer(str(proxy_path),Handler);proxy_path.chmod(0o600)
    private(ROOT/'test-proxy.key',json.dumps({'format':'native-rpc-unix-v1','token':token,'sockets':{'63899':str(proxy_path)}}).encode())
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();child=None
    try:
        child=subprocess.Popen([str(a) for a in args('alice','send',sponsor('service-test-send')+['--amount','10','--to',recipient],proxy=True)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        end=time.monotonic()+180
        while not reached.wait(.1):
            if child.poll() is not None:raise RuntimeError('private send exited before real finalized acknowledgement gate')
            if time.monotonic()>end:raise RuntimeError('private send gate timed out; original journal retained')
        child.kill();child.communicate(timeout=15)
        if child.returncode!=-9:raise RuntimeError('wallet was not SIGKILLed')
        deadline=time.monotonic()+20
        while True:
            try:state=canonical();break
            except RuntimeError:
                if time.monotonic()>deadline:raise
                time.sleep(.2)
        checkpoint={'phase':'pending','pending_sha256':hashlib.sha256(pending.read_bytes()).hexdigest(),
            'signature':json.loads(pending.read_text())['signature'],'native_state':state,'slots':slots(),'original_instance':original_instance,
            'credential_sha256':hashlib.sha256((ROOT/'rpc-access.key').read_bytes()).hexdigest(),
            'key_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in ROOT.glob('*.keypair.json')}}
        save(record,checkpoint)
        return {'phase':'pending','original_signature':checkpoint['signature'],'native_accounts':len(state),'uid':os.getuid()}
    finally:
        release.set()
        if child is not None and child.poll() is None:child.kill();child.communicate(timeout=15)
        server.shutdown();server.server_close();thread.join(timeout=5)
        proxy_path.unlink(missing_ok=True)


def test_finish():
    record=ROOT/'service-acceptance.json';checkpoint=json.loads(record.read_text())
    if checkpoint['phase']=='passed':return checkpoint['result']
    if checkpoint['phase']!='pending':raise RuntimeError('explicit recovery of incomplete acceptance required')
    ready(timeout=4)
    instance=json.loads((ROOT/'service-instance.json').read_text())
    if instance['supervisor']==checkpoint['original_instance']['supervisor'] or set(instance['validators'])&set(checkpoint['original_instance']['validators']):
        raise RuntimeError('all original validator processes must be replaced by launchd')
    if len(set(instance['process_groups']+[os.getpgid(instance['supervisor'])]))!=1:raise RuntimeError('validator escaped launchd process group')
    if min(slots())<=max(checkpoint['slots'])+8:raise RuntimeError('no new finality beyond crash checkpoint')
    if canonical()!=checkpoint['native_state']:raise RuntimeError('pool/nullifier state changed during service recovery')
    pending=Path(str(ROOT/'alice.wallet.json')+'.pending.json')
    if pending.exists():
        if hashlib.sha256(pending.read_bytes()).hexdigest()!=checkpoint['pending_sha256']:raise RuntimeError('original pending identity changed')
        result=run_json(args('alice','resolve'))
        if result.get('accepted') is not True:raise RuntimeError('original payment was not canonically accepted')
    if Path(str(ROOT/'alice.wallet.json')+'.staging.json').exists():run_json(args('alice','reclaim',sponsor()))
    if balance('alice')!=90 or balance('bob')!=10 or len(canonical())!=5:raise RuntimeError('private balances/nullifiers changed after recovery')
    if hashlib.sha256((ROOT/'rpc-access.key').read_bytes()).hexdigest()!=checkpoint['credential_sha256']:raise RuntimeError('RPC credential changed')
    if any(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=value for name,value in checkpoint['key_sha256'].items()):raise RuntimeError('original service keys changed')
    result={'status':'passed','service_uid':os.getuid(),'supervisor_and_both_validator_pids_changed':True,'private_balances':{'alice':90,'bob':10},'permanent_nullifiers':4,'original_signature':checkpoint['signature'],'credential_and_validator_keys_unchanged':True,'finalized_slots':slots()}
    checkpoint['phase']='passed';checkpoint['result']=result;save(record,checkpoint)
    return result


if __name__=='__main__':
    action=sys.argv[1] if len(sys.argv)>=2 else ''
    if action in ('client-export','ack-arm','browser-ack-arm','browser-close-checkpoint','restore-ack-arm'):
        if len(sys.argv)!=3 or (action=='client-export' and sys.argv[2] not in ('alice','bob')):raise ValueError('unexpected service arguments')
    elif len(sys.argv)!=2:raise ValueError('unexpected service arguments')
    if action=='init':output=initialize()
    elif action=='run':output=supervise()
    elif action=='run-ack-test':output=supervise(ack_test=True)
    elif action=='run-package-test':output=supervise(package_test=True)
    elif action=='run-browser-test':output=supervise(browser_test=True)
    elif action=='run-restore-test':output=supervise(restore_test=True)
    elif action=='run-retention-test':output=supervise(retention_test=True)
    elif action=='test-begin':output=test_begin()
    elif action=='test-finish':output=test_finish()
    elif action=='status':
        ready(timeout=4)
        from history_retention import read
        output={'slots':slots(),'native_state':canonical(),'uid':os.getuid(),
            'history_retention':json.loads(read(ROOT/'history-retention.json',8192)) if (ROOT/'history-retention.json').exists() else {'phase':'starting'}}
    elif action=='history-status':
        from history_retention import read
        output=json.loads(read(ROOT/'history-retention.json',8192))
    elif action=='ingress-init':
        from service_ingress import initialize as initialize_ingress
        output=initialize_ingress()
    elif action=='client-export':
        from service_ingress import export_client
        output=export_client(sys.argv[2])
    elif action=='ack-arm':
        from service_ingress import arm_ack_gate
        output=arm_ack_gate(sys.argv[2])
    elif action=='ack-checkpoint':
        from service_ingress import ack_checkpoint
        output=ack_checkpoint()
    elif action in ('browser-ack-arm','browser-ack-checkpoint'):
        from service_ingress import browser_test_paths,arm_ack_gate,ack_checkpoint
        browser_test_paths()
        output=arm_ack_gate(sys.argv[2]) if action=='browser-ack-arm' else ack_checkpoint()
    elif action in ('restore-ack-arm','restore-ack-checkpoint'):
        from service_ingress import restore_test_paths,arm_ack_gate,ack_checkpoint
        restore_test_paths()
        output=arm_ack_gate(sys.argv[2]) if action=='restore-ack-arm' else ack_checkpoint()
    elif action=='browser-close-checkpoint':
        from service_ingress import browser_close_checkpoint
        output=browser_close_checkpoint(sys.argv[2])
    else:raise ValueError('unknown sealed service action')
    if output is not None:print(json.dumps(output,sort_keys=True))
