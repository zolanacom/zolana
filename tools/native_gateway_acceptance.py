#!/usr/bin/env python3
"""Attach real invited TLS/wallet APIs to an owned, already-running V4 fixture.

Linux only; never launches validators, SSH, installers, or an existing wallet.
The controller owns whole-network SIGKILL/resume and supplies checked new endpoints.
All created clients, relay workers, keys, journals and evidence stay in a fresh root.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import socket
import socketserver
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from explorer_model import b58, public_key

HERE = Path(__file__).resolve()
PROGRAM = b58(bytes([91,34,9,203,140,74,92,11,167,20,210,73,64,155,3,220,
                    25,87,194,52,122,28,170,241,29,131,42,88,76,107,13,190]))
LIMIT = 16384


def private(path, maximum=65536):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        meta = os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077 or meta.st_size > maximum:
            raise ValueError('bounded current-owner private file required')
        raw = source.read(maximum + 1)
        if len(raw) > maximum: raise ValueError('private file exceeds bound')
        return raw


def save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.new')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as output:
        output.write(raw); output.flush(); os.fsync(output.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)


def endpoint(value):
    if not isinstance(value, str) or not value.startswith('127.0.0.1:'):
        raise ValueError('literal private loopback endpoint required')
    port = value.removeprefix('127.0.0.1:')
    if not port.isascii() or not port.isdecimal() or str(int(port)) != port or not 1 <= int(port) <= 65535:
        raise ValueError('invalid private loopback port')
    return ('127.0.0.1', int(port))


def host(path):
    raw = private(path, 4 * 1024 * 1024).decode()
    try: values = [json.loads(raw)]
    except json.JSONDecodeError: values = [json.loads(line) for line in raw.splitlines() if line.strip()]
    ready = [value['data'] for value in values if value.get('event') == 'external_mac_fixture_ready']
    value = ready[-1] if ready else values[-1]
    peers, network = value.get('peers'), value.get('network')
    if (value.get('pool_format') != 'NPOOL004' or not isinstance(peers, list) or len(peers) != 3
            or not isinstance(network, dict) or set(network) != {'network', 'genesis_hash'}
            or not isinstance(network['network'], list) or len(network['network']) != 32
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in network['network'])
            or not any(network['network']) or not public_key(network['genesis_hash'])
            or not public_key(value.get('mac_relay'))):
        raise ValueError('exact reviewed three-node V4 held fixture required')
    identities = []
    for peer in peers:
        if not public_key(peer.get('identity')): raise ValueError('invalid original validator identity')
        identities.append(peer['identity']); endpoint(peer['rpc']); endpoint(peer['native_ingress'])
    if len(set(identities)) != 3 or len({p['native_ingress'] for p in peers}) != 3:
        raise ValueError('duplicate original validator or native endpoint')
    return value


def same_network(before, after):
    if (any(before[key] != after[key] for key in ('network', 'pool_format', 'mac_relay'))
            or sorted(p['identity'] for p in before['peers']) != sorted(p['identity'] for p in after['peers'])):
        raise ValueError('controller substituted original genesis, relay, profile or validators')


def pending_resolution_error(error):
    # These are the client's two explicit unknown-outcome results. Transport,
    # authorization, corrupt history and unrelated failures are not retried.
    return any(str(error).endswith(message) for message in (
        'shielded payment remains unresolved; original proof retained, no new spend authorized',
        'native outcome remains unresolved; original proof retained, no replacement authorized'))


def read_exact(stream, count):
    chunks = bytearray()
    while len(chunks) < count:
        part = stream.recv(count - len(chunks))
        if not part: raise ValueError('incomplete native frame')
        chunks.extend(part)
    return bytes(chunks)


def wire_identity(wire):
    # Only identifies the exact Legacy packet. The real native Bank verifies its
    # signatures, canonical encoding, feature gates and payment proof execution.
    if not 1232 < len(wire) <= LIMIT or wire[0] != 1 or len(wire) <= 65:
        raise ValueError('one-signature full native packet required')
    return b58(wire[1:65]), hashlib.sha256(wire).hexdigest()


def admitted(ack, signature):
    return (isinstance(ack, dict) and ack.get('status') == 'admitted'
            and ack.get('finalized') is False and ack.get('signature') == signature
            and type(ack.get('slot')) is int and ack['slot'] > 0)


class Faults:
    def __init__(self, root):
        self.root, self.lock = root, threading.Lock()
        self.triggered = threading.Event(); self.armed = False; self.record = None
        self.packets = {}
    def observe(self, wire, ack):
        signature, digest = wire_identity(wire)
        with self.lock:
            packet = dict(sha256=digest, bytes=len(wire))
            if signature in self.packets and self.packets[signature] != packet:
                raise ValueError('one signature was reused for different packet bytes')
            self.packets[signature] = packet
            if self.armed and admitted(ack, signature):
                if self.record is None:
                    self.record = dict(signature=signature, packet_sha256=digest, packet_bytes=len(wire), ack=ack)
                    packet = self.root / 'dropped-ack.packet'
                    with os.fdopen(os.open(packet, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
                        out.write(wire); out.flush(); os.fsync(out.fileno())
                    save(self.root / 'dropped-ack.json', self.record)
                    self.triggered.set()
                return True  # Suppress every other admitted ACK until the worker dies.
        return False


class NativeProxy:
    def __init__(self, target, faults):
        self.target, self.faults, self.lock = endpoint(target), faults, threading.Lock()
        owner = self
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(3)
                    length = struct.unpack('<I', read_exact(self.request, 4))[0]
                    if not 1 <= length <= LIMIT: raise ValueError('native frame bound')
                    wire = read_exact(self.request, length)
                    with owner.lock: destination = owner.target
                    with socket.create_connection(destination, timeout=3) as upstream:
                        upstream.sendall(struct.pack('<I', length) + wire)
                        with upstream.makefile('rb') as source: raw = source.readline(4097)
                    if not raw.endswith(b'\n') or len(raw) > 4096: raise ValueError('bounded native ACK required')
                    ack = json.loads(raw)
                    if owner.faults.observe(wire, ack): return
                    self.request.sendall(raw)
                except (OSError, ValueError, json.JSONDecodeError): return
        class Server(socketserver.TCPServer): allow_reuse_address = True
        self.server = Server(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
    @property
    def address(self): return '127.0.0.1:' + str(self.server.server_address[1])
    def repin(self, target):
        with self.lock: self.target = endpoint(target)
    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)


def free_port():
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0)); return reservation.getsockname()[1]


def service(config_path, wallet=None):
    """Internal owned subprocess; no source defaults or legacy binary selection."""
    config = json.loads(private(config_path))
    if wallet is not None:
        from wallet_ui import WalletApp, Handler
        item = config['clients'][wallet]
        app = WalletApp.from_profile(Path(config['tester']), Path(item['directory']), binary=Path(config['wallet']))
        server = ThreadingHTTPServer(('127.0.0.1', item['port']), Handler)
        server.authority, server.app = '127.0.0.1:' + str(item['port']), app
        servers = [server]; relay = faucet = None
    else:
        from test_faucet import Faucet, Handler as FaucetHandler
        from testnet_gateway import Gateway, Handler as GatewayHandler
        from service_tls import listener
        faucet = Faucet(Path(config['faucet_root']), Path(config['password']), binary=Path(config['faucet_binary']))
        app = Gateway(faucet, relay_root=Path(config['relay_root']))
        relay = app.relay
        servers = []
        try:
            for name, handler, current in [('faucet', FaucetHandler, faucet), ('rpc', GatewayHandler, app)]:
                servers.append(listener(config[name + '_url'], config[name + '_port'], handler, current,
                    Path(config['certificate']), Path(config['tls_key'])))
            if relay is None: raise ValueError('native relay not configured')
            relay.start()
        except BaseException:
            for server in servers: server.server_close()
            if relay: relay.close()
            faucet.close(); raise
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
    for thread in threads: thread.start()
    try:
        deadline = time.monotonic() + config['timeout']
        while not stop.wait(.1) and time.monotonic() < deadline:
            if any(not thread.is_alive() for thread in threads): raise RuntimeError('owned listener stopped')
    finally:
        for server in servers: server.shutdown(); server.server_close()
        for thread in threads: thread.join(timeout=5)
        if relay: relay.close()
        if faucet: faucet.close()


class Trial:
    def __init__(self, args):
        self.args, self.root = args, args.root
        self.deadline = time.monotonic() + args.timeout
        self.children, self.logs, self.proxies, self.tokens = {}, [], [], {}
        self.original = self.host = host(args.host_evidence)
        self.password = private(args.password_file, 1024).decode()
        self.result = dict(format='zolana-native-gateway-acceptance-v1', status='running', events=[],
            validators_started_by_script=False, mac_validators_started=False,
            scope='invited TLS and actual local wallet HTTP API; trusted operator RPC and co-located Linux validators')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.environment = dict(os.environ, RAYON_NUM_THREADS=str(args.prover_threads))
        self.environment.pop('NATIVE_WALLET_PROGRESS',None)
    def event(self, kind, **fields):
        self.result['events'].append(dict(kind=kind, **fields)); save(self.root / 'result.json', self.result)
        print(json.dumps(dict(event=kind, **fields)), flush=True)
    def wait(self, callback, seconds=90):
        until = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < until:
            value = callback()
            if value: return value
            time.sleep(.05)
        raise TimeoutError('bounded acceptance phase deadline')
    def cli(self, binary, command, *extra, password=False):
        result = subprocess.run([str(binary), command, *map(str, extra)], input=self.password if password else None,
            capture_output=True, text=True, timeout=min(180, max(1, self.deadline-time.monotonic())), env=self.environment)
        if result.returncode: raise RuntimeError('owned CLI failed: ' + result.stderr[-1200:])
        return json.loads(result.stdout)
    def rpc(self, address, method, params=()):
        endpoint(address)
        request = urllib.request.Request('http://' + address, json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=list(params))).encode(), {'Content-Type':'application/json'})
        with self.opener.open(request, timeout=10) as response: raw = response.read(16*1024*1024+1)
        if len(raw) > 16*1024*1024: raise ValueError('bounded RPC response required')
        value = json.loads(raw)
        if value.get('id') != 1 or value.get('error') is not None or 'result' not in value: raise ValueError('complete matching RPC result required')
        return value['result']
    def start(self, name):
        log = (self.root / (name + '-' + str(time.time_ns()) + '.log')).open('xb'); self.logs.append(log)
        command = [sys.executable, '-B', str(HERE), '--service-config', str(self.root/'services.json')]
        if name != 'gateway': command += ['--wallet-service', name]
        child = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True, env=self.environment)
        self.children[name] = child
        def ready():
            if child.poll() is not None: raise RuntimeError('owned service exited; inspect its private log')
            port = self.config['rpc_port'] if name == 'gateway' else self.config['clients'][name]['port']
            with socket.socket() as probe: return probe.connect_ex(('127.0.0.1', port)) == 0
        self.wait(ready, 25)
        if name != 'gateway':
            with self.opener.open('http://127.0.0.1:'+str(self.config['clients'][name]['port'])+'/api/session', timeout=10) as response:
                self.tokens[name] = json.load(response)['token']
    def stop(self, name, crash=False):
        child = self.children.get(name)
        if child is None:return
        if child.poll() is not None:
            self.children.pop(name,None);return
        if os.getpgid(child.pid) != child.pid: raise ValueError('owned child process group changed')
        os.killpg(child.pid, signal.SIGKILL if crash else signal.SIGTERM)
        try: child.wait(timeout=20)
        except subprocess.TimeoutExpired: os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=10)
        if crash and child.returncode != -signal.SIGKILL: raise RuntimeError('owned service did not receive SIGKILL')
        self.children.pop(name,None)
    def api(self, who, action, **fields):
        authority = '127.0.0.1:'+str(self.config['clients'][who]['port'])
        request = urllib.request.Request('http://'+authority+'/api/wallet',
            json.dumps(dict(action=action, password=self.password, **fields)).encode(),
            {'Content-Type':'application/json','Origin':'http://'+authority,'X-Wallet-Token':self.tokens[who]})
        try:
            with self.opener.open(request, timeout=min(190,max(1,self.deadline-time.monotonic()))) as response: result = json.load(response)
        except urllib.error.HTTPError as error:
            result=json.loads(error.read(65537))
            raise RuntimeError('actual wallet HTTP API: '+str(result.get('error', error.code))) from error
        if 'error' in result: raise RuntimeError('actual wallet API refused operation: '+result['error'])
        return result['result']
    def balances(self, expected):
        values = {who:self.api(who, 'balance') for who in expected}
        actual = {who:value['balance'] for who,value in values.items()}
        if actual != expected: raise ValueError('canonical wallet balances differ: '+repr(actual))
        for value in values.values():
            if value['fee_balance'] != 0 or value['public_balance'] != 0: raise ValueError('user public gas or value wallet was funded')
        return values
    def setup(self):
        from local_test_tls import create
        keys = json.loads(private(self.args.relay_key, 4096))
        if not isinstance(keys, list) or len(keys) != 64 or any(type(byte) is not int or not 0 <= byte <= 255 for byte in keys): raise ValueError('bounded synthetic relay key required')
        if b58(bytes(keys[32:])) != self.host['mac_relay']: raise ValueError('host did not prefund this original relay public key')
        first = self.host['peers'][0]['rpc']
        if self.rpc(first, 'getGenesisHash') != self.host['network']['genesis_hash']: raise ValueError('candidate genesis mismatch')
        accounts = self.rpc(first, 'getProgramAccounts', [PROGRAM, {'encoding':'base64','commitment':'finalized'}])
        pools = [a for a in accounts if base64.b64decode(a['account']['data'][0])[:8] == b'NPOOL004']
        if len(pools) != 1: raise ValueError('exact fresh V4 pool missing')
        raw = base64.b64decode(pools[0]['account']['data'][0])
        if len(raw)!=25728 or int.from_bytes(raw[56:64], 'little') != 0: raise ValueError('use a fresh initially empty candidate; never reset a pool')
        self.pool = pools[0]['pubkey']
        tls = create(self.root/'tls')
        self.faults = Faults(self.root)
        self.proxies = [NativeProxy(peer['native_ingress'], self.faults) for peer in self.host['peers']]
        binaries = {name: str((self.args.binary_dir/name).resolve(strict=True)) for name in ('native-wallet','native-faucet','native-shielded')}
        self.config = dict(timeout=self.args.timeout, wallet=binaries['native-wallet'], faucet_binary=binaries['native-faucet'],
            password=str(self.args.password_file), tester=str(self.root/'tester.json'), faucet_root=str(self.root/'faucet'),
            relay_root=str(self.root/'relay'), certificate=tls['certificate'], tls_key=tls['private_key'],
            rpc_port=free_port(), faucet_port=free_port(), clients={name:dict(directory=str(self.root/name),port=free_port()) for name in ('alice','bob','charlie')})
        self.config.update(rpc_url='https://127.0.0.1:'+str(self.config['rpc_port']), faucet_url='https://127.0.0.1:'+str(self.config['faucet_port']))
        identity=dict(**self.host['network'], program=PROGRAM, pool=self.pool, pool_format='NPOOL004', recipient_withdrawals=True)
        source=dict(format='native-wallet-profile-v1', label='Owned gateway source', key_mode='user-wallet-v1', **identity, rpc=dict(transport='loopback-http', url='http://'+first))
        tester=dict(source, label='Owned invited native payments', rpc=dict(transport='https',url=self.config['rpc_url']),
            faucet=dict(transport='https',url=self.config['faucet_url']), invite_required=True,
            local_tls_ca_pem=Path(tls['ca']).read_text(), private_send_transport='native-inline-v1')
        save(self.root/'source.json',source); save(self.root/'tester.json',tester); save(self.root/'services.json',self.config)
        self.operator=dict(format='native-gateway-operator-fixture-v1',fixture_keys_are_public=True, **identity)
        save(self.root/'operator.json', self.operator)
        self.cli(binaries['native-faucet'],'init','--root',self.root/'faucet','--profile',self.root/'source.json','--password-file','-','--max-claims','3', password=True)
        self.cli(binaries['native-faucet'],'access-init','--root',self.root/'faucet','--profile',self.root/'tester.json','--daily-admissions','3','--rpc-limit','10000')
        (self.root/'relay').mkdir(mode=0o700)
        relay=dict(format='native-shielded-relay-v1',network=self.host['network'],network_file=str(self.root/'operator.json'),
            native_profile=str(self.root/'tester.json'),rpc='http://'+first,payer=keys[32:],payer_file=str(self.args.relay_key),
            binary=binaries['native-shielded'],fee=self.args.fee,gross_cap=150_000_000,max_jobs=8,per_member=8,
            pool_format='NPOOL004',native_ingress=[proxy.address for proxy in self.proxies])
        save(self.root/'relay/config.json',relay)
        self.start('gateway')
        self.deny_anonymous_tls(tls['ca'])
        self.addresses = {}
        for name in self.config['clients']:
            self.start(name)
            self.addresses[name] = self.api(name,'create')
            self.api(name,'backup'); self.api(name,'ack-backup')
            invitation=self.root/(name+'.invite')
            self.cli(binaries['native-faucet'],'invite-issue','--root',self.root/'faucet','--output',invitation,'--expires-in','3600','--bind-fee',self.addresses[name]['fee_address'])
            self.api(name,'join',invitation=json.loads(private(invitation,1024))['invitation'])
            if not self.api(name,'access-status')['admitted']: raise ValueError('real invitation membership missing')
        # An operator-only wallet deposits directly to a public private-address;
        # neither faucet nor relay ever opens a user's spending/viewing seed.
        self.cli(binaries['native-wallet'],'init','--network',self.root/'operator.json','--wallet',self.root/'operator.wallet','--backup',self.root/'operator.backup','--password-file','-',password=True)
        self.cli(binaries['native-wallet'],'deposit','--network',self.root/'operator.json','--wallet',self.root/'operator.wallet',
            '--password-file','-','--rpc','http://'+first,'--sponsor',self.args.relay_key,'--to',self.addresses['alice']['address'],'--amount','50000000',password=True)
        self.balances(dict(alice=50_000_000,bob=0,charlie=0))
        self.event('actual_invited_tls_wallets_funded',binary_sha256={name:hashlib.sha256(Path(path).read_bytes()).hexdigest() for name,path in binaries.items()},
            genesis_hash=self.host['network']['genesis_hash'], users_public_gas_zero=True, faucet_grant_worker_started=False)
    def deny_anonymous_tls(self, ca):
        context=ssl.create_default_context(cafile=ca)
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        query=json.dumps(dict(jsonrpc='2.0',id=1,method='getSlot',params=[{'commitment':'finalized'}])).encode()
        request=urllib.request.Request(self.config['rpc_url'],query,{'Content-Type':'application/json'})
        try:
            opener.open(request,timeout=5).close()
        except urllib.error.HTTPError as error:
            if error.code!=403:raise ValueError('anonymous invited RPC was not denied') from error
        else:raise ValueError('anonymous invited RPC bypassed admission')
        try:
            self.opener.open(request,timeout=5).close()
        except urllib.error.URLError:pass
        else:raise ValueError('untrusted local TLS certificate was accepted')
        self.event('real_tls_and_anonymous_access_denials',local_ca_pinned=True,global_trust_changed=False)
    def audit(self, expected_count, expected_backing):
        canonical = None; observations=[]
        for peer in self.host['peers']:
            accounts=self.rpc(peer['rpc'],'getProgramAccounts',[PROGRAM,{'encoding':'base64','commitment':'finalized'}])
            markers=[];pool=None
            for item in accounts:
                account=item['account'];raw=base64.b64decode(account['data'][0],validate=True)
                if account['owner'] != PROGRAM or account['executable']: raise ValueError('invalid native account owner')
                if item['pubkey'] == self.pool:
                    if (len(raw)!=25728 or raw[:8]!=b'NPOOL004' or list(raw[8:40])!=self.host['network']['network']
                            or int.from_bytes(raw[48:56],'little')!=expected_backing or int.from_bytes(raw[56:64],'little')!=expected_count
                            or account['lamports'] < int.from_bytes(raw[40:48],'little')+expected_backing): raise ValueError('native pool accounting mismatch')
                    pool=dict(prefix_sha256=hashlib.sha256(raw[:1088]).hexdigest(),lamports=account['lamports'])
                else:
                    if len(raw)!=40 or raw[:8]!=b'NSPENT01' or account['lamports']<1: raise ValueError('missing permanent positive-lamport nullifier')
                    markers.append((item['pubkey'],raw.hex(),account['lamports']))
            if len(markers)!=expected_count or pool is None: raise ValueError('incorrect permanent nullifier count')
            state=dict(pool=pool,markers=sorted(markers))
            if canonical is not None and state!=canonical: raise ValueError('all-peer native state disagreement')
            canonical=state
            payments=[]
            for signature, packet in self.faults.packets.copy().items():
                statuses=self.rpc(peer['rpc'],'getSignatureStatuses',[[signature],{'searchTransactionHistory':True}])
                status=statuses['value'][0]
                if status is None or status.get('err') is not None or status.get('confirmationStatus')!='finalized' or status.get('confirmations') is not None: raise ValueError('native packet not successfully finalized on every peer')
                tx=self.rpc(peer['rpc'],'getTransaction',[signature,{'encoding':'base64','commitment':'finalized','maxSupportedTransactionVersion':0}])
                if not isinstance(tx,dict) or tx.get('slot')!=status['slot'] or tx.get('meta',{}).get('err') is not None: raise ValueError('recorded native transaction mismatch')
                wire=base64.b64decode(tx['transaction'][0],validate=True)
                if hashlib.sha256(wire).hexdigest()!=packet['sha256'] or len(wire)!=packet['bytes']: raise ValueError('recorded full native packet differs')
                payments.append(dict(signature=signature,slot=status['slot'],**packet))
            observations.append(dict(identity=peer['identity'],payments=payments))
        return dict(state=canonical,peers=observations)
    def resume_linux(self):
        if not self.args.await_linux_resume: return
        ready=self.root/'linux-resumed.json'
        if ready.exists(): raise ValueError('resume coordination file must initially be absent')
        self.event('awaiting_linux_original_ledger_resume',coordination_file=str(ready),seconds=self.args.await_linux_resume,
            original_network=self.host['network'],original_identities=sorted(p['identity'] for p in self.host['peers']))
        after=self.wait(lambda: host(ready) if ready.exists() else None,self.args.await_linux_resume)
        same_network(self.original,after)
        before_by_id={p['identity']:index for index,p in enumerate(self.host['peers'])}
        for peer in after['peers']: self.proxies[before_by_id[peer['identity']]].repin(peer['native_ingress'])
        first=after['peers'][0]['rpc']
        if self.rpc(first,'getGenesisHash')!=self.original['network']['genesis_hash']: raise ValueError('resumed genesis mismatch')
        # Public tester profile/audiences and job transport identity stay byte-for-byte unchanged.
        for path in (self.root/'source.json',self.root/'faucet/profile.json'):
            value=json.loads(private(path));value['rpc']['url']='http://'+first;save(path,value)
        relay=json.loads(private(self.root/'relay/config.json'));relay['rpc']='http://'+first;save(self.root/'relay/config.json',relay)
        self.host=after
        self.event('controller_original_network_repin_verified',original_identity_and_genesis_preserved=True)
    def resolve_original(self, job, user_journal, original_user, original_native):
        native = json.loads(original_native)
        signature, digest = self.faults.record['signature'], self.faults.record['packet_sha256']
        if native.get('signature') != signature or native.get('packet_sha256') != digest:
            raise ValueError('saved native reservation differs from the dropped original packet')
        def server_state():
            pending = job/'relay.native.json'
            if pending.exists():
                if private(pending,65536) != original_native:
                    raise ValueError('native packet or gross reservation changed during recovery')
            else:
                outcome = json.loads(private(job/'outcome.json'))
                if (outcome.get('accepted') is not True or outcome.get('signature') != signature
                        or outcome.get('packet_sha256') != digest
                        or outcome.get('reserved_gross_debit') != native['reserved_debit']):
                    raise ValueError('native reservation vanished without its original canonical outcome')
        def accepted(value):
            if (not isinstance(value,dict) or value.get('accepted') is not True
                    or value.get('encrypted_checkpoint_durable') is not True
                    or value.get('signature') != signature or value.get('id') != job.name):
                raise ValueError('original recovery needs the exact accepted durable client receipt')
            if user_journal.exists(): raise ValueError('accepted client receipt left its proof reserved')
            server_state()
            return value
        def attempt():
            server_state()
            if not user_journal.exists():
                return accepted(json.loads(private(user_journal.with_suffix('.receipt.json'))))
            if private(user_journal,20000) != original_user:
                raise ValueError('original user proof changed during recovery')
            try:
                result = self.api('alice','resolve')
            except RuntimeError as error:
                if not pending_resolution_error(error): raise
                if user_journal.exists() and private(user_journal,20000) != original_user:
                    raise ValueError('pending recovery substituted the original user proof') from error
                server_state()
                return None
            return accepted(result)
        return self.wait(attempt,90)

    def run(self):
        self.setup()
        expected=dict(alice=50_000_000,bob=0,charlie=0)
        for sender,recipient,amount in [('alice','bob',20_000_000),('bob','charlie',5_000_000),('alice','charlie',2_000_000)]:
            began=time.monotonic()
            result=self.api(sender,'send',recipient=self.addresses[recipient]['address'],amount=amount,fee_mode='shielded',max_shielded_fee=self.args.fee)
            expected[sender]-=amount+self.args.fee;expected[recipient]+=amount
            self.balances(expected)
            self.event('actual_wallet_private_receive_respend',sender=sender,recipient=recipient,amount=amount,
                action_to_all_durable_balances_ms=(time.monotonic()-began)*1000,receipt=result)
        self.event('all_peer_full_packets_and_nullifiers',audit=self.audit(8,sum(expected.values())))
        with self.faults.lock: self.faults.armed=True
        with ThreadPoolExecutor(max_workers=1) as pool:
            sending=pool.submit(self.api,'alice','send',recipient=self.addresses['bob']['address'],amount=1_000_000,fee_mode='shielded',max_shielded_fee=self.args.fee)
            self.wait(lambda:self.faults.triggered.is_set(),90)
            self.stop('gateway',crash=True);self.stop('alice',crash=True)
            try:sending.result(timeout=10)
            except (OSError,ValueError,RuntimeError):pass
        user_journal=self.root/'alice/wallet-ui/wallet.json.shielded.json'
        original_user=private(user_journal,20000)
        jobs=list((self.root/'relay/jobs').iterdir())
        pending=[job for job in jobs if (job/'relay.native.json').exists()]
        if len(pending)!=1: raise ValueError('one original durable native relay journal required')
        job=pending[0];original_native=private(job/'relay.native.json',65536)
        save(self.root/'original-fault-journals.json',dict(job_id=job.name,user_sha256=hashlib.sha256(original_user).hexdigest(),
            native_sha256=hashlib.sha256(original_native).hexdigest(),**self.faults.record))
        self.event('real_admitted_ack_dropped_gateway_worker_and_client_sigkilled',job_id=job.name,**self.faults.record)
        self.resume_linux()
        if private(user_journal,20000)!=original_user or private(job/'relay.native.json',65536)!=original_native: raise ValueError('original pending identity changed before recovery')
        with self.faults.lock:self.faults.armed=False
        self.start('gateway');self.start('alice')
        self.resolve_original(job,user_journal,original_user,original_native)
        expected['alice']-=1_000_000+self.args.fee;expected['bob']+=1_000_000
        self.balances(expected)
        outcome=json.loads(private(job/'outcome.json'))
        if outcome.get('accepted') is not True or outcome.get('signature')!=self.faults.record['signature']: raise ValueError('recovery replaced original signed packet or was not canonically accepted')
        self.event('original_packet_recovered_once',job_id=job.name,signature=outcome['signature'],balances=expected,
            audit=self.audit(10,sum(expected.values())),actual_client_sigkill=True,actual_gateway_worker_sigkill=True)
        self.result['status']='passed'
    def close(self):
        failures=[]
        for name in list(self.children):
            try:self.stop(name)
            except BaseException as error:failures.append(type(error).__name__)
        for proxy in self.proxies:
            try:proxy.close()
            except BaseException as error:failures.append(type(error).__name__)
        for log in self.logs:log.close()
        if failures:self.result.update(status='failed',cleanup_errors=failures)
        self.result['owned_services_stopped']=not failures
        save(self.root/'result.json',self.result)
        if failures:raise RuntimeError('owned cleanup failed; inspect retained evidence')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service-config',type=Path);parser.add_argument('--wallet-service',choices=('alice','bob','charlie'))
    parser.add_argument('--root',type=Path);parser.add_argument('--host-evidence',type=Path);parser.add_argument('--binary-dir',type=Path)
    parser.add_argument('--relay-key',type=Path);parser.add_argument('--password-file',type=Path)
    parser.add_argument('--fee',type=int,default=3_000_000);parser.add_argument('--prover-threads',type=int,default=4)
    parser.add_argument('--timeout',type=int,default=600);parser.add_argument('--await-linux-resume',type=int,default=0)
    args=parser.parse_args()
    if platform.system()!='Linux':raise ValueError('Linux acceptance only; never start Mac clients or validators here')
    if args.service_config:
        service(args.service_config,args.wallet_service);return
    if any(getattr(args,key) is None for key in ('root','host_evidence','binary_dir','relay_key','password_file')):parser.error('root, host-evidence, binary-dir, relay-key and password-file are required')
    if args.fee!=3_000_000 or not 1<=args.prover_threads<=4 or not 60<=args.timeout<=900 or not 0<=args.await_linux_resume<=600:raise ValueError('reviewed fee/thread/lifetime bounds required')
    for key in ('host_evidence','binary_dir','relay_key','password_file'):setattr(args,key,getattr(args,key).resolve(strict=True))
    args.root=args.root.absolute()
    if args.root.parent.resolve()!=args.root.parent or args.root.name in ('','.','..'):raise ValueError('fresh canonical child root required')
    args.root.mkdir(mode=0o700)
    def interrupted(*_):raise KeyboardInterrupt('owned acceptance interrupted; preserving journals')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    trial=None
    try:
        trial=Trial(args);trial.run()
    except BaseException as error:
        if trial is not None:
            trial.result.update(status='failed',error_type=type(error).__name__,error=str(error)[:1500]);trial.event('failed',error=str(error)[:1500])
        raise
    finally:
        if trial is not None:trial.close()


if __name__=='__main__':main()
