#!/usr/bin/env python3
"""LOCAL-058 sealed original-ledger services; never installs, funds or resets.

The only external listeners are systemd-owned host TCP descriptors. Validator
RPC and native ingress live in a separate network namespace shared by two UIDs.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import queue
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request

PREFIX = Path('/opt/zolana-native-058')
ETC = Path('/etc/zolana-native-058')
STATE = Path('/var/lib/zolana-native-058')
RUN = Path('/run/zolana-native-058')
VALROOT = STATE/'validator/network'
GWROOT = STATE/'gateway'
READY = RUN/'ready.json'
PORTS = {'rpc':38443, 'faucet':38444}
UNITS = {'validator':'zolana-native-058-validator.service', 'gateway':'zolana-native-058-gateway.service'}
CONFIG_KEYS = {'format','manifest_sha256','validator_uid','validator_gid','gateway_uid','gateway_gid',
               'link_gid','network','validator_identities','relay_public_key','test_mode',
               'host_namespace_inode','validator_layout'}
HEX = re.compile('[a-f0-9]{64}')
B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
REQUIRED_BINS = {'zolana-fast-check','native-wallet','native-faucet','native-shielded'}


def public_key(value):
    if not isinstance(value,str) or not 32 <= len(value) <= 44 or any(c not in B58 for c in value):
        raise ValueError('public identity must be canonical base58 of 32 bytes')
    number=0
    for c in value: number=number*58+B58.index(c)
    length=(number.bit_length()+7)//8 + len(value)-len(value.lstrip('1'))
    if length!=32: raise ValueError('public identity must decode to exactly 32 bytes')
    return value


def b58(raw):
    number=int.from_bytes(raw,'big');result=''
    while number:number,index=divmod(number,58);result=B58[index]+result
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+result


def endpoint(value):
    if not isinstance(value,str) or not re.fullmatch(r'127\.0\.0\.1:[1-9][0-9]{0,4}',value):
        raise ValueError('private endpoint must be exact IPv4 loopback with a canonical port')
    port=int(value.split(':')[1])
    if not 1 <= port <= 65535: raise ValueError('invalid private endpoint port')
    return value


def validate_config(value):
    if not isinstance(value,dict) or set(value)!=CONFIG_KEYS or value['format']!='zolana-native-linux-service-v1':
        raise ValueError('unsupported sealed service configuration')
    if not isinstance(value['manifest_sha256'],str) or HEX.fullmatch(value['manifest_sha256']) is None:
        raise ValueError('sealed bundle digest required')
    names=('validator_uid','validator_gid','gateway_uid','gateway_gid','link_gid')
    if any(type(value[k]) is not int or not 1 <= value[k] < 65534 for k in names):
        raise ValueError('non-root fixed service identities required')
    if value['validator_uid']==value['gateway_uid'] or len({value[k] for k in ('validator_gid','gateway_gid','link_gid')})!=3:
        raise ValueError('separate role identities and read-only link group required')
    network=value['network']
    if (not isinstance(network,dict) or set(network)!={'network','genesis_hash'} or
            not isinstance(network['network'],list) or len(network['network'])!=32 or
            any(type(x) is not int or not 0<=x<=255 for x in network['network']) or network['network']==[0]*32):
        raise ValueError('explicit original network domain required')
    public_key(network['genesis_hash']);public_key(value['relay_public_key'])
    identities=value['validator_identities']
    if (not isinstance(identities,list) or len(identities)!=3 or
            any(not isinstance(key,str) for key in identities) or len(set(identities))!=3):
        raise ValueError('three unique original validators required')
    for key in identities:public_key(key)
    if type(value['test_mode']) is not bool or type(value['host_namespace_inode']) is not int or value['host_namespace_inode']<=0:
        raise ValueError('explicit test policy and original host namespace required')
    layout=value['validator_layout']
    if not isinstance(layout,list) or len(layout)!=3:raise ValueError('original validator layout required')
    for node in layout:
        if not isinstance(node,dict) or set(node)!={'identity','voter','ledger','identity_file','voter_file'}:
            raise ValueError('invalid original validator layout')
        public_key(node['identity']);public_key(node['voter'])
        for name in ('ledger','identity_file','voter_file'):
            text=node[name]
            if (not isinstance(text,str) or not text or '\\' in text or
                    any(p in ('','.','..') for p in text.split('/')) or PurePosixPath(text).is_absolute()):
                raise ValueError('original layout paths must be simple relative paths')
        if not node['ledger'].startswith('ledgers/') or '/' in node['identity_file'] or '/' in node['voter_file']:
            raise ValueError('original ledger/key layout escaped its fixed root')
    if sorted(n['identity'] for n in layout)!=sorted(identities):raise ValueError('layout identity mismatch')
    paths=[n[k] for n in layout for k in ('ledger','identity_file','voter_file')]
    if len(paths)!=len(set(paths)):raise ValueError('original validator paths must be distinct')
    return value


def real_directory(path,uid,mode=None,gid=None):
    path=Path(path);meta=path.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or path.resolve()!=path or meta.st_uid!=uid or
            (mode is not None and stat.S_IMODE(meta.st_mode)!=mode) or (gid is not None and meta.st_gid!=gid)):
        raise ValueError('directory ownership, mode or real path mismatch')


def root_ancestors(path):
    for parent in (Path(path).parent,*Path(path).parent.parents):
        meta=parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022 or parent.resolve()!=parent:
            raise ValueError('sealed file requires immutable root-owned ancestors')


def owned(path,uid,maximum=65536,mode=0o600):
    path=Path(path)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as source:
        meta=os.fstat(source.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=uid or stat.S_IMODE(meta.st_mode)!=mode or
                not 1 <= meta.st_size <= maximum):raise ValueError('bounded regular file with exact ownership/mode required')
        raw=source.read(maximum+1)
        if len(raw)>maximum:raise ValueError('file exceeded bound')
        return raw


def sealed(path,maximum=65536,mode=0o444):
    root_ancestors(path)
    return owned(path,0,maximum,mode)


def verify_bundle(config):
    raw=sealed(PREFIX/'MANIFEST.json',1024*1024)
    if hashlib.sha256(raw).hexdigest()!=config['manifest_sha256']:raise ValueError('sealed bundle manifest digest mismatch')
    manifest=json.loads(raw)
    if not isinstance(manifest,dict) or set(manifest)!={'format','files'} or manifest['format']!='zolana-native-service-bundle-v1':
        raise ValueError('invalid sealed bundle manifest')
    files=manifest['files']
    if not isinstance(files,dict) or not 4<=len(files)<=256:raise ValueError('bounded complete sealed inventory required')
    required={'tools/native_linux_service.py','tools/service_tls.py'}|{'bin/'+n for n in REQUIRED_BINS}
    if config['test_mode']:required.add('tools/native_service_acceptance.py')
    if not required<=set(files):raise ValueError('sealed runtime inventory incomplete')
    for name,entry in files.items():
        if not isinstance(name,str) or re.fullmatch(r'(tools/[A-Za-z0-9_]+\.py|bin/[a-z0-9-]+)',name) is None:
            raise ValueError('only explicit sealed Python modules and binaries may execute')
        mode=0o555 if name.startswith('bin/') else 0o444
        if (not isinstance(entry,dict) or set(entry)!={'sha256','size','mode'} or entry['mode']!=mode or
                type(entry['size']) is not int or not 1<=entry['size']<=768*1024*1024 or
                not isinstance(entry['sha256'],str) or HEX.fullmatch(entry['sha256']) is None):
            raise ValueError('invalid sealed artifact identity')
        path=PREFIX/name
        root_ancestors(path)
        # Hash large binaries incrementally, without loading them into memory.
        with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as source:
            meta=os.fstat(source.fileno())
            if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=mode or meta.st_size!=entry['size']):
                raise ValueError('sealed artifact ownership/mode/size mismatch')
            digest=hashlib.file_digest(source,'sha256').hexdigest()
        if digest!=entry['sha256']:raise ValueError('sealed artifact content mismatch')
    # An omitted mutable sibling must never become an importable runtime module.
    for path in (PREFIX/'tools').iterdir():
        if path.name!='__pycache__' and 'tools/'+path.name not in files:raise ValueError('unmanifested runtime module')
    if (PREFIX/'tools/__pycache__').exists():raise ValueError('sealed runtime must not load bytecode cache')
    for path in (PREFIX/'bin').iterdir():
        if 'bin/'+path.name not in files:raise ValueError('unmanifested executable')


def load_config():
    raw=sealed(ETC/'config.json')
    config=validate_config(json.loads(raw));verify_bundle(config)
    return config,hashlib.sha256(raw).hexdigest()


def sandbox(config,role):
    expected=pwd.getpwnam('zolana058v' if role=='validator' else 'zolana058g')
    if (os.geteuid()!=config[role+'_uid'] or os.getegid()!=config[role+'_gid'] or
            expected.pw_uid!=os.geteuid() or expected.pw_gid!=os.getegid() or
            expected.pw_shell not in ('/usr/sbin/nologin','/sbin/nologin','/bin/false')):
        raise ValueError('service must run as its fixed unprivileged non-login identity')
    status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    if status.get('NoNewPrivs','').strip()!='1' or any(int(status.get(k,'-1').strip(),16)!=0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')):
        raise ValueError('service requires no new privileges and zero capabilities')
    inode=Path('/proc/self/ns/net').stat().st_ino
    if inode==config['host_namespace_inode']:raise ValueError('service must not share the host network namespace')
    real_directory(STATE/role,os.geteuid(),0o700)
    canary=STATE/(role+'-canary')
    try:
        fd=os.open(canary,os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
    except OSError as error:
        if error.errno!=errno.EROFS:raise ValueError('sandbox canary requires read-only mount denial, not DAC denial') from error
    else:
        os.close(fd);raise ValueError('service escaped its explicit write paths')
    return inode


def atomic(path,value,mode=0o600,gid=None):
    path=Path(path);raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
    temp=path.with_name('.'+path.name+'.'+secrets.token_hex(8))
    try:
        fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        with os.fdopen(fd,'wb') as target:
            if gid is not None:os.fchown(target.fileno(),-1,gid)
            os.fchmod(target.fileno(),mode);target.write(raw);target.flush();os.fsync(target.fileno())
        os.replace(temp,path);fsync_dir(path.parent)
    finally:
        if temp.exists():temp.unlink()


def fsync_dir(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def validate_ready(value,config):
    if (not isinstance(value,dict) or value.get('network')!=config['network'] or value.get('pool_format')!='NPOOL004' or
            value.get('mac_relay')!=config['relay_public_key'] or value.get('operator_private_keys_exported') is not False or
            value.get('shared_private_smoke_skipped') is not True or value.get('hold_seconds')!=0 or value.get('service_mode') is not True):
        raise ValueError('managed original-ledger service identity or profile mismatch')
    peers=value.get('peers')
    if (not isinstance(peers,list) or len(peers)!=3 or
            sorted(p.get('identity','') for p in peers if isinstance(p,dict))!=sorted(config['validator_identities'])):
        raise ValueError('managed original validator topology mismatch')
    cleaned=[]
    for peer in peers:
        # SDK4 runner reports RPC as a host:port, not a URL.
        cleaned.append({k:peer[k] for k in ('identity','rpc','native_ingress')})
        endpoint(peer['rpc']);endpoint(peer['native_ingress'])
    if len({p[k] for p in cleaned for k in ('rpc','native_ingress')})!=6:
        raise ValueError('managed validator endpoints must be distinct')
    if value.get('ingress')!=[p['native_ingress'] for p in peers]:raise ValueError('managed native endpoint list mismatch')
    return dict(network=config['network'],pool_format='NPOOL004',peers=cleaned,mac_relay=config['relay_public_key'])


def verify_original(config):
    real_directory(VALROOT,config['validator_uid'],0o700)
    original=json.loads(owned(VALROOT/'resume.json',config['validator_uid']))
    if (original.get('format')!='zolana-fast-process-resume-v1' or original.get('original_root')!=str(VALROOT) or
            original.get('ledger_prefix')!=str(VALROOT/'ledgers') or original.get('genesis_hash')!=config['network']['genesis_hash'] or
            original.get('upstream_commit')!='a203300045b405f86c9c84308b2eae76af69ac3b' or
            original.get('private') is not True or original.get('slot_anchors') is not True or
            original.get('mac_relay')!=config['relay_public_key']):
        raise ValueError('original resume identity changed; refusing initialization or migration')
    nodes=original.get('nodes')
    if not isinstance(nodes,list) or len(nodes)!=3:raise ValueError('original resume topology changed')
    layout=[{k:n.get(k) for k in ('identity','voter','ledger','identity_file','voter_file')} for n in nodes]
    if sorted(layout,key=lambda n:n['identity'])!=sorted(config['validator_layout'],key=lambda n:n['identity']):
        raise ValueError('original ledger/voter/key layout changed')
    # Rust independently opens each original key and verifies signed vote history,
    # certified BANK hashes, genesis and retained-root ancestry under the root lock.


def notify(message):
    address=os.environ.get('NOTIFY_SOCKET')
    if not address:raise ValueError('Type=notify supervisor requires NOTIFY_SOCKET')
    if address.startswith('@'):address='\0'+address[1:]
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as channel:
        channel.connect(address);channel.sendall(message.encode())


def stop_event():
    stop=threading.Event()
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,lambda *_:stop.set())
    return stop


def read_rpc(address,method,params,timeout=2):
    if method not in ('getSlot','getBlock') or not 0<timeout<=2:
        raise ValueError('only bounded fixed validator readiness reads allowed')
    request=urllib.request.Request('http://'+endpoint(address),
        json.dumps(dict(jsonrpc='2.0',id=1,method=method,params=params)).encode(),
        {'Content-Type':'application/json'})
    # Namespace-local fixed raw RPC; never environment proxies or caller URLs.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    with opener.open(request,timeout=timeout) as response:
        if response.status!=200:raise ValueError('managed validator health RPC failed')
        raw=response.read(4097)
        if len(raw)>4096:raise ValueError('managed health response exceeded bound')
    value=json.loads(raw)
    if (not isinstance(value,dict) or value.get('jsonrpc')!='2.0' or value.get('id')!=1 or
            'result' not in value or 'error' in value):
        raise ValueError('managed readiness RPC response invalid')
    return value['result']


def finalized_slot(address,timeout=2):
    value=read_rpc(address,'getSlot',[{'commitment':'finalized'}],timeout)
    if type(value) is not int or value<0:raise ValueError('managed finalized-slot health response invalid')
    return value


def finalized_block(value,slot):
    if (not isinstance(value,dict) or type(value.get('parentSlot')) is not int or
            not 0<=value['parentSlot']<slot or type(value.get('blockHeight')) is not int or value['blockHeight']<0):
        raise ValueError('managed finalized history is not available at the restored root')
    public_key(value.get('blockhash'));public_key(value.get('previousBlockhash'))


def wait_finalized_history(peers,child,stop,deadline,clock=time.monotonic):
    """getSlot may fall back to replayed Bank root before RPC finality is ready.

    Pin each startup root, then require fresh progress and the actual finalized
    getBlock read at that pinned root on every peer. Never publish ready from
    the fallback slot alone; retained canonical history remains authoritative.
    """
    addresses=[peer['rpc'] for peer in peers]
    if len(addresses)!=3 or len(set(addresses))!=3:raise ValueError('three distinct managed peer RPCs required')
    startup={};complete={}
    while not stop.is_set():
        if child.poll() is not None:raise RuntimeError('managed runner exited during finalized-history readiness')
        if clock()>=deadline:raise TimeoutError('all-peer finalized-history readiness timed out')
        for address in addresses:
            if address in complete:continue
            if stop.is_set():return None
            if child.poll() is not None:raise RuntimeError('managed runner exited during finalized-history readiness')
            remaining=deadline-clock()
            if remaining<=0:raise TimeoutError('all-peer finalized-history readiness timed out')
            try:
                slot=finalized_slot(address,timeout=min(2,remaining))
                if address not in startup:
                    if slot>0:startup[address]=slot
                    continue
                if slot<startup[address]:raise RuntimeError('managed finalized root regressed during readiness')
                if slot==startup[address]:continue
                remaining=deadline-clock()
                if remaining<=0:raise TimeoutError('all-peer finalized-history readiness timed out')
                value=read_rpc(address,'getBlock',[startup[address],dict(encoding='base64',
                    transactionDetails='none',rewards=False,commitment='finalized',maxSupportedTransactionVersion=0)],
                    timeout=min(2,remaining))
                finalized_block(value,startup[address])
                complete[address]=dict(identity=next(peer['identity'] for peer in peers if peer['rpc']==address),
                    startup_root=startup[address],advanced_root=slot,finalized_block_slot=startup[address],
                    finalized_blockhash=value['blockhash'])
            except (OSError,ValueError):
                # Missing/error history is not absence proof or readiness.
                continue
        if clock()>=deadline:raise TimeoutError('all-peer finalized-history readiness timed out')
        if stop.is_set():return None
        if child.poll() is not None:raise RuntimeError('managed runner exited during finalized-history readiness')
        if len(complete)==3:return dict(format='zolana-native-finality-readiness-v1',
                                       peers=[complete[address] for address in addresses])
        stop.wait(.1)
    return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_):return None


def validator(config,digest):
    inode=sandbox(config,'validator');verify_original(config)
    real_directory(RUN,config['validator_uid'],0o750,config['link_gid'])
    stop=stop_event();events=queue.Queue(maxsize=64);generation=secrets.token_hex(32)
    env={'PATH':'/usr/bin:/bin','HOME':str(STATE/'validator'),'RAYON_NUM_THREADS':'4','SOLANA_RAYON_THREADS':'4','RUST_BACKTRACE':'0'}
    logfd=os.open(STATE/'validator/runner.stderr',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
    child=None;published=False;last_slot=-1;last_progress=0;next_probe=0;health_endpoint=None
    try:
        with os.fdopen(logfd,'ab',buffering=0) as log:
            if stat.S_IMODE(os.fstat(log.fileno()).st_mode)!=0o600:raise ValueError('private runner log required')
            child=subprocess.Popen([str(PREFIX/'bin/zolana-fast-check'),'--resume-root',str(VALROOT),'--service'],
                                   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=log,env=env,close_fds=True)
            def read_events():
                try:
                    while True:
                        raw=child.stdout.readline(131073)
                        if not raw:break
                        if len(raw)>131072:raise ValueError('managed runner stdout record exceeds bound')
                        try:value=json.loads(raw)
                        except (ValueError,UnicodeError):continue
                        if isinstance(value,dict) and value.get('event')=='external_mac_fixture_ready':
                            events.put(value.get('data'),timeout=1)
                except BaseException as error:
                    try:events.put(error,timeout=1)
                    except queue.Full:pass
            reader=threading.Thread(target=read_events,daemon=True);reader.start()
            deadline=time.monotonic()+180
            while not stop.wait(.1):
                if child.poll() is not None:raise RuntimeError('managed original-ledger runner exited')
                if not published:
                    if time.monotonic()>deadline:raise TimeoutError('original-ledger service readiness timed out')
                    try:value=events.get_nowait()
                    except queue.Empty:continue
                    if isinstance(value,BaseException):raise value
                    value=validate_ready(value,config)
                    readiness=wait_finalized_history(value['peers'],child,stop,deadline)
                    if readiness is None:break
                    value['finality_readiness']=readiness
                    health_endpoint=value['peers'][0]['rpc']
                    last_slot=readiness['peers'][0]['advanced_root'];last_progress=time.monotonic();next_probe=last_progress+5
                    if stop.is_set():break
                    if child.poll() is not None:raise RuntimeError('managed runner exited before readiness publication')
                    if last_progress>=deadline:raise TimeoutError('original-ledger service readiness timed out')
                    value.update(format='zolana-native-service-ready-v1',config_sha256=digest,generation=generation,
                                 namespace_inode=inode,supervisor_pid=os.getpid(),child_pid=child.pid,ready_at=int(time.time()))
                    atomic(READY,value,0o640,config['link_gid']);published=True
                    notify('READY=1\nSTATUS=Original three-validator private network restored')
                elif not reader.is_alive():raise RuntimeError('managed runner event reader stopped')
                if published and time.monotonic()>=next_probe:
                    next_probe=time.monotonic()+5
                    try:slot=finalized_slot(health_endpoint)
                    except (OSError,ValueError):slot=last_slot
                    if slot<last_slot:raise RuntimeError('managed finalized root regressed')
                    if slot>last_slot:last_slot=slot;last_progress=time.monotonic()
                    if time.monotonic()-last_progress>=60:raise RuntimeError('managed finalized root stalled for sixty seconds')
    finally:
        if published:
            try:
                if json.loads(owned(READY,config['validator_uid'],mode=0o640)).get('generation')==generation:
                    READY.unlink();fsync_dir(RUN)
            except FileNotFoundError:pass
        if child is not None and child.poll() is None:
            child.terminate()
            try:child.wait(timeout=80)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=5)
        if child is not None and child.stdout is not None:child.stdout.close()


def activated_sockets(environment=None,factory=socket.socket,ports=None):
    environment=os.environ if environment is None else environment
    ports=PORTS if ports is None else ports
    if (not isinstance(ports,dict) or set(ports)!={'rpc','faucet'} or
            any(type(port) is not int or not 1<=port<=65535 for port in ports.values()) or
            len(set(ports.values()))!=2):
        raise ValueError('exact two distinct pinned TLS ports required')
    if (environment.get('LISTEN_PID')!=str(os.getpid()) or environment.get('LISTEN_FDS')!='2' or
            sorted(environment.get('LISTEN_FDNAMES','').split(':'))!=['faucet','rpc']):
        raise ValueError('exact two named descriptors for this process required')
    names=environment['LISTEN_FDNAMES'].split(':');streams={}
    try:
        from service_tls import check_activated_socket
        for index,name in enumerate(names):
            stream=factory(fileno=3+index);streams[name]=stream
            check_activated_socket(stream,ports[name]);os.set_inheritable(stream.fileno(),False)
        return streams
    except BaseException:
        for stream in streams.values():stream.close()
        raise


def endpoint_update(current,template,updates):
    """No budgets, audiences, paths, identities or policy can change at repin."""
    baseline=json.loads(json.dumps(current))
    expected=json.loads(json.dumps(template))
    for name in updates:
        if name=='rpc.url':
            if not isinstance(baseline.get('rpc'),dict) or not isinstance(expected.get('rpc'),dict):raise ValueError('profile RPC missing')
            baseline['rpc']['url']=expected['rpc']['url']
        else:baseline[name]=expected[name]
    if baseline!=expected:raise ValueError('mutable service configuration differs from sealed policy')
    result=json.loads(json.dumps(template))
    for name,value in updates.items():
        if name=='rpc.url':result['rpc']['url']=value
        else:result[name]=value
    return result


def prepare_gateway(config,ready):
    uid=config['gateway_uid'];rpc='http://'+ready['peers'][0]['rpc']
    for name in ('server.crt','public-profile.json','operator.json'):
        if owned(GWROOT/name,uid,32768)!=sealed(ETC/name,32768):raise ValueError('owned gateway copy differs from sealed template')
    for name in ('server.key','relay.key','password'):owned(GWROOT/name,uid,32768)
    template=json.loads(sealed(ETC/'source-profile.json'))
    if (template.get('pool_format')!='NPOOL004' or any(template.get(k)!=config['network'][k] for k in ('network','genesis_hash')) or
            template.get('rpc',{}).get('transport')!='loopback-http'):
        raise ValueError('sealed private profile differs from original network')
    for path in (GWROOT/'source.json',GWROOT/'faucet/profile.json'):
        current=json.loads(owned(path,uid));atomic(path,endpoint_update(current,template,{'rpc.url':rpc}))
    template=json.loads(sealed(ETC/'relay.json'))
    expected_paths={'binary':str(PREFIX/'bin/native-shielded'),'payer_file':str(GWROOT/'relay.key'),
                    'network_file':str(GWROOT/'operator.json'),'native_profile':str(GWROOT/'public-profile.json')}
    if (template.get('network')!=config['network'] or template.get('pool_format')!='NPOOL004' or
            any(template.get(k)!=v for k,v in expected_paths.items())):
        raise ValueError('sealed relay policy or executable path mismatch')
    payer=template.get('payer');keypair=json.loads(owned(GWROOT/'relay.key',uid,4096))
    if (not isinstance(payer,list) or len(payer)!=32 or any(type(x) is not int or not 0<=x<=255 for x in payer) or
            b58(bytes(payer))!=config['relay_public_key'] or not isinstance(keypair,list) or len(keypair)!=64 or
            any(type(x) is not int or not 0<=x<=255 for x in keypair) or keypair[32:]!=payer):
        raise ValueError('relay key/payer differs from original public relay identity')
    public=json.loads(owned(GWROOT/'public-profile.json',uid))
    if (public.get('private_send_transport')!='native-inline-v1' or public.get('pool_format')!='NPOOL004' or
            public.get('rpc',{}).get('url')!='https://127.0.0.1:38443' or
            public.get('faucet',{}).get('url')!='https://127.0.0.1:38444' or public.get('invite_required') is not True or
            any(public.get(k)!=config['network'][k] for k in ('network','genesis_hash'))):
        raise ValueError('sealed invited TLS audience or native profile mismatch')
    ingress=[p['native_ingress'] for p in ready['peers']];gate=None
    try:
        if config['test_mode']:
            from native_service_acceptance import NativeAckGate
            gate=NativeAckGate(ingress,directory=GWROOT/'acceptance-gate');ingress=gate.endpoints
        path=GWROOT/'relay/config.json';current=json.loads(owned(path,uid))
        atomic(path,endpoint_update(current,template,{'rpc':rpc,'native_ingress':ingress}))
        return gate
    except BaseException:
        if gate:gate.close()
        raise


def read_ready(config,digest,inode):
    value=json.loads(owned(READY,config['validator_uid'],mode=0o640))
    if (value.get('format')!='zolana-native-service-ready-v1' or value.get('config_sha256')!=digest or
            value.get('namespace_inode')!=inode or not isinstance(value.get('generation'),str) or
            HEX.fullmatch(value['generation']) is None or value.get('network')!=config['network'] or
            value.get('pool_format')!='NPOOL004' or value.get('mac_relay')!=config['relay_public_key']):
        raise ValueError('sanitized validator readiness is stale or belongs to another namespace')
    # Validate sanitized endpoints through the same original topology guard.
    validate_ready(dict(value,operator_private_keys_exported=False,shared_private_smoke_skipped=True,
                        hold_seconds=0,service_mode=True,ingress=[p['native_ingress'] for p in value['peers']]),config)
    return value


def gateway(config,digest):
    inode=sandbox(config,'gateway');stop=stop_event();streams=activated_sockets()
    servers=[];threads=[];gate=faucet=relay=None
    try:
        deadline=time.monotonic()+180
        while True:
            try:ready=read_ready(config,digest,inode);break
            except FileNotFoundError:
                if stop.wait(.1):return
                if time.monotonic()>deadline:raise TimeoutError('validator readiness missing')
        gate=prepare_gateway(config,ready)
        from test_faucet import Faucet, Handler as FaucetHandler
        from testnet_gateway import Gateway, Handler as GatewayHandler
        from service_tls import listener
        faucet=Faucet(GWROOT/'faucet',GWROOT/'password',binary=PREFIX/'bin/native-faucet')
        app=Gateway(faucet,relay_root=GWROOT/'relay');relay=app.relay
        if relay is None or relay.native_ingress is None:raise ValueError('native relay required')
        for name,handler,current in (('rpc',GatewayHandler,app),('faucet',FaucetHandler,faucet)):
            servers.append(listener('https://127.0.0.1:'+str(PORTS[name]),PORTS[name],handler,current,
                GWROOT/'server.crt',GWROOT/'server.key',activated_socket=streams[name]))
        relay.start()
        threads=[threading.Thread(target=s.serve_forever,daemon=True) for s in servers]
        for thread in threads:thread.start()
        notify('READY=1\nSTATUS=Invited native TLS gateway ready; raw endpoints isolated')
        while not stop.wait(.25):
            if read_ready(config,digest,inode)['generation']!=ready['generation']:raise RuntimeError('validator namespace generation changed')
            if any(not t.is_alive() for t in threads) or relay.worker is None or not relay.worker.is_alive():
                raise RuntimeError('owned gateway worker stopped')
    finally:
        for server in servers:
            if threads:server.shutdown()
            server.server_close()
        for thread in threads:thread.join(timeout=5)
        for stream in streams.values():stream.close()
        if relay:relay.close()
        if faucet:faucet.close()
        if gate:gate.close()


def units():
    common='''UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
PrivateIPC=yes
TemporaryFileSystem=/dev/shm:rw,nodev,nosuid,mode=1777
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
PrivateNetwork=yes
LimitNOFILE=1048576
LimitCORE=0
Nice=15
KillMode=control-group
TimeoutStartSec=240
TimeoutStopSec=90
Restart=on-failure
RestartSec=10s
'''
    output={}
    for role in ('validator','gateway'):
        dependencies=('After=network.target\n' if role=='validator' else
            'Requires='+UNITS['validator']+'\nRequires=zolana-native-058-rpc.socket zolana-native-058-faucet.socket\n'+
            'After='+UNITS['validator']+' zolana-native-058-rpc.socket zolana-native-058-faucet.socket\n'+
            'BindsTo='+UNITS['validator']+'\nPartOf='+UNITS['validator']+'\nJoinsNamespaceOf='+UNITS['validator']+'\n')
        service=('[Unit]\nDescription=Zolana LOCAL-058 '+role+'\n'+dependencies+
            '[Service]\nType=notify\nNotifyAccess=main\nUser=zolana058'+('v' if role=='validator' else 'g')+'\nGroup=zolana058'+('v' if role=='validator' else 'g')+'\n'+
            'SupplementaryGroups=zolana058link\nWorkingDirectory='+str(PREFIX)+'\n'+
            'ExecStart=/usr/bin/python3 -I -B '+str(PREFIX/'tools/native_linux_service.py')+' '+role+'\n'+
            ('Sockets=zolana-native-058-rpc.socket zolana-native-058-faucet.socket\n' if role=='gateway' else '')+
            'ReadWritePaths='+str(STATE/role)+(' '+str(RUN) if role=='validator' else '')+'\n'+common+
            '[Install]\nWantedBy=multi-user.target\n')
        output[UNITS[role]]=service
    for name,port in PORTS.items():
        output['zolana-native-058-'+name+'.socket']=('[Unit]\nDescription=Zolana LOCAL-058 '+name+' host TLS socket\n'+
            '[Socket]\nListenStream=127.0.0.1:'+str(port)+'\nFileDescriptorName='+name+'\n'+
            'Service='+UNITS['gateway']+'\nAccept=no\nNoDelay=true\nBacklog=8\n'+
            '[Install]\nWantedBy=sockets.target\n')
    return output


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('check','validator','gateway','render'))
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    if args.command=='render':
        if args.output is None:parser.error('render requires a fresh output directory')
        args.output.mkdir(mode=0o700)
        for name,raw in units().items():(args.output/name).write_text(raw)
        return
    if sys.platform!='linux':raise ValueError('LOCAL-058 service requires Linux')
    config,digest=load_config()
    # Isolated Python excludes mutable source/PYTHONPATH; imports begin only
    # after the complete fixed root-owned module inventory has been verified.
    sys.path.insert(0,str(PREFIX/'tools'))
    if args.command=='check':
        print(json.dumps(dict(sealed_bundle_verified=True,config_sha256=digest,services_started=0)));return
    globals()[args.command](config,digest)


if __name__=='__main__':main()
