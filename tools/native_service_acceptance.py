#!/usr/bin/env python3
"""Fixed LOCAL-058 isolation/recovery acceptance; never provisions or resets state.

NativeAckGate is imported only by the sealed service's explicit test_mode path.
The controller and outsider probes are separate processes and operating identities.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import errno
import grp
import hashlib
import json
import platform
import secrets
import ssl
import os
from pathlib import Path
import pwd
import re
import signal
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.request

import native_gateway_acceptance as previous

PREFIX = Path('/opt/zolana-native-058')
CONFIG = Path('/etc/zolana-native-058/config.json')
STATE = Path('/var/lib/zolana-native-058')
VALROOT = STATE/'validator'
NETWORK = VALROOT/'network'
GWROOT = STATE/'gateway'
CLIENT = STATE/'client'
READY = Path('/run/zolana-native-058/ready.json')
GATE = GWROOT/'acceptance-gate'
ACCOUNTS = ('zolana058v','zolana058g','zolana058t')
UNITS = {'validator':'zolana-native-058-validator.service','gateway':'zolana-native-058-gateway.service'}
SOCKET_UNITS = ('zolana-native-058-rpc.socket','zolana-native-058-faucet.socket')
TLS_PORTS = (38443,38444)
HEX64 = re.compile('[a-f0-9]{64}')
MAXIMUM = 16384


def identity(name):
    if name not in ACCOUNTS: raise ValueError('only fixed LOCAL-058 identities are allowed')
    return pwd.getpwnam(name)


def read_owned(path, uid, maximum=65536, mode=None):
    path=Path(path)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as source:
        meta=os.fstat(source.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=uid or meta.st_size>maximum
                or (mode is not None and stat.S_IMODE(meta.st_mode)!=mode)):
            raise ValueError('bounded regular file with exact expected ownership/mode required')
        raw=source.read(maximum+1)
        if len(raw)>maximum:raise ValueError('owned file exceeded bound')
        return raw


def checked_directory(path, uid, mode=0o700):
    path=Path(path);meta=path.lstat()
    if (not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=uid or stat.S_IMODE(meta.st_mode)!=mode
            or path.resolve()!=path):raise ValueError('exact real private owned directory required')


def same_original(before,after):
    previous.same_network(before,after)
    if before['config_sha256']!=after['config_sha256']:
        raise ValueError('sealed configuration changed across service restart')


def admitted_identity(wire,ack):
    signature,digest=previous.wire_identity(wire)
    if (not previous.admitted(ack,signature)
            or set(ack)!={'status','signature','paymentId','slot','finalized'}
            or not isinstance(ack['paymentId'],list) or len(ack['paymentId'])!=32
            or any(type(byte) is not int or not 0<=byte<=255 for byte in ack['paymentId'])):
        return None
    return dict(signature=signature,packet_sha256=digest,packet_bytes=len(wire))


def receive(stream,count,deadline):
    output=bytearray()
    while len(output)<count:
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('absolute test-proxy frame deadline')
        stream.settimeout(min(remaining,1))
        try:chunk=stream.recv(count-len(output))
        except socket.timeout:continue
        if not chunk:raise ValueError('incomplete test-proxy frame')
        output.extend(chunk)
    return bytes(output)


class NativeAckGate:
    """One bounded local-only proxy per already-reviewed native endpoint.

    Root arms a fixed file; the gateway UID records a real backend ACK and exact
    packet durably, then suppresses ACKs until root removes that arm. No fake ACK,
    automatic admission, replacement packet, key loading or consensus assertion.
    """
    def __init__(self,ingress,directory=GATE):
        if Path(directory)!=GATE:raise ValueError('test gate requires its fixed LOCAL-058 directory')
        expected=identity('zolana058g')
        if os.geteuid()!=expected.pw_uid:raise PermissionError('test gate requires gateway identity')
        if not isinstance(ingress,list) or not 1<=len(ingress)<=3 or len(set(ingress))!=len(ingress):
            raise ValueError('bounded unique fixed native endpoints required')
        targets=[previous.endpoint(value) for value in ingress]
        if not GATE.exists():GATE.mkdir(mode=0o700)
        checked_directory(GATE,expected.pw_uid)
        self.directory,self.uid,self.lock=GATE,expected.pw_uid,threading.Lock()
        self.servers=[];self.threads=[];self.endpoints=[]
        owner=self
        try:
            for target in targets:
                class Handler(socketserver.BaseRequestHandler):
                    def handle(self):
                        try:
                            deadline=time.monotonic()+3
                            length=struct.unpack('<I',receive(self.request,4,deadline))[0]
                            if not 1<=length<=MAXIMUM:raise ValueError('native test frame exceeds bound')
                            wire=receive(self.request,length,deadline)
                            previous.wire_identity(wire)
                            with socket.create_connection(self.server.target,timeout=3) as backend:
                                backend.sendall(struct.pack('<I',length)+wire)
                                raw=bytearray();deadline=time.monotonic()+3
                                while not raw.endswith(b'\n') and len(raw)<=4096:
                                    raw.extend(receive(backend,1,deadline))
                            if len(raw)>4096:raise ValueError('bounded original ACK required')
                            ack=json.loads(raw)
                            if owner.suppress(wire,ack):return
                            self.request.settimeout(1);self.request.sendall(raw)
                        except (OSError,ValueError):return
                class Server(socketserver.TCPServer):allow_reuse_address=True
                server=Server(('127.0.0.1',0),Handler);server.target=target
                thread=threading.Thread(target=server.serve_forever,daemon=True)
                thread.start();self.servers.append(server);self.threads.append(thread)
                self.endpoints.append('127.0.0.1:'+str(server.server_address[1]))
        except BaseException:self.close();raise
    def arm(self):
        path=self.directory/'arm.json'
        if not os.path.lexists(path):return None
        arm=json.loads(read_owned(path,0,4096,0o640))
        now=time.time()
        if (not isinstance(arm,dict) or set(arm)!={'format','nonce','expires_at'}
                or arm['format']!='zolana-native-058-ack-arm-v1' or not isinstance(arm['nonce'],str)
                or HEX64.fullmatch(arm['nonce']) is None or type(arm['expires_at']) is not int
                or not now<arm['expires_at']<=now+300):
            raise ValueError('root test gate arm is invalid or expired')
        return arm
    def suppress(self,wire,ack):
        bound=admitted_identity(wire,ack)
        if bound is None:return False
        with self.lock:
            arm=self.arm()
            if arm is None:return False
            path=self.directory/'observed.json'
            if os.path.lexists(path):
                observed=json.loads(read_owned(path,self.uid,8192,0o600))
                retained=read_owned(self.directory/'original.packet',self.uid,MAXIMUM,0o600)
                old_signature,old_digest=previous.wire_identity(retained)
                if (observed.get('nonce')!=arm['nonce'] or observed.get('signature')!=old_signature
                        or observed.get('packet_sha256')!=old_digest or observed.get('packet_bytes')!=len(retained)):
                    raise ValueError('test fault record differs from its original durable packet')
            else:
                packet=self.directory/'original.packet'
                with os.fdopen(os.open(packet,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as output:
                    output.write(wire);output.flush();os.fsync(output.fileno())
                previous.save(path,dict(format='zolana-native-058-real-ack-v1',nonce=arm['nonce'],ack=ack,**bound))
            return True
    def close(self):
        for server in self.servers:server.shutdown();server.server_close()
        for thread in self.threads:thread.join(timeout=5)
        if any(thread.is_alive() for thread in self.threads):raise RuntimeError('test native proxy did not stop')


def proc_status(pid='self'):
    return dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)


def denied_open(path):
    """Never read secret bytes, even if the permission boundary is broken."""
    try:
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    except OSError as error:
        if error.errno not in (errno.EACCES,errno.EPERM):raise ValueError('missing/inactive path cannot prove access denial') from error
        return error.errno
    else:
        os.close(descriptor);raise ValueError('outsider unexpectedly opened protected material')


def outsider_probe(document):
    account=identity('zolana058t');status=proc_status()
    service_uids={identity(name).pw_uid for name in ACCOUNTS[:2]}
    service_gids={identity(name).pw_gid for name in ACCOUNTS[:2]}|{grp.getgrnam('zolana058link').gr_gid}
    if (os.getuid()!=account.pw_uid or os.geteuid()!=account.pw_uid or account.pw_uid in service_uids
            or service_gids.intersection(os.getgroups())
            or any(int(status[key].strip(),16)!=0 for key in ('CapEff','CapPrm','CapAmb'))
            or status['NoNewPrivs'].strip()!='1'):
        raise PermissionError('negative probe must actually run as the separate unprivileged outsider')
    if (not isinstance(document,dict) or set(document)!={'format','files','ports','service_pids','service_namespace'}
            or document['format']!='zolana-native-058-outsider-v1'
            or not 1<=len(document['files'])<=32 or not 1<=len(document['ports'])<=32
            or not 1<=len(document['service_pids'])<=16):raise ValueError('bounded fixed outsider probe required')
    host_namespace=os.readlink('/proc/self/ns/net')
    if host_namespace==document['service_namespace']:raise ValueError('outsider accidentally runs inside private service namespace')
    observations=[]
    for label,name in document['files'].items():
        path=Path(name)
        if not path.is_absolute() or not (path.is_relative_to(VALROOT) or path.is_relative_to(GWROOT)):
            raise ValueError('probe path escaped fixed protected service state')
        observations.append(dict(label=label,errno=denied_open(path),secret_bytes_read=0))
    sockets=[]
    for port in document['ports']:
        if type(port) is not int or not 1<=port<=65535 or port in TLS_PORTS:raise ValueError('invalid private-only probe port')
        for family,address in [(socket.AF_INET,('127.0.0.1',port)),(socket.AF_INET6,('::1',port))]:
            try:
                with socket.socket(family) as probe:
                    probe.settimeout(.3);result=probe.connect_ex(address)
            except OSError as error:
                if error.errno not in (errno.EAFNOSUPPORT,errno.EPROTONOSUPPORT):raise
                result=error.errno
            if result==0:raise ValueError('outsider reached a private raw/native host listener')
            sockets.append(dict(port=port,family=family,connect_errno=result))
    processes=[]
    for pid in document['service_pids']:
        if type(pid) is not int or pid<=1:raise ValueError('invalid pinned service PID')
        try:os.kill(pid,0)
        except PermissionError:pass
        except ProcessLookupError as error:raise ValueError('dead service cannot prove different-UID isolation') from error
        else:raise ValueError('outsider can signal protected service process')
        for suffix in ('environ','mem'):
            denied_open(f'/proc/{pid}/{suffix}')
        entered=subprocess.run(['/usr/bin/nsenter',f'--net=/proc/{pid}/ns/net','/usr/bin/true'],capture_output=True,timeout=3)
        if entered.returncode==0:raise ValueError('outsider entered protected network namespace')
        processes.append(dict(pid=pid,signal_denied=True,proc_secrets_denied=True,setns_denied=True))
    return dict(format='zolana-native-058-outsider-result-v1',uid=os.getuid(),gid=os.getgid(),
        host_namespace=host_namespace,private_files=observations,private_sockets=sockets,processes=processes)


def private_listeners(document):
    if os.geteuid()!=0:raise PermissionError('private listener positive control requires root in pinned namespace')
    if not isinstance(document,dict) or set(document)!={'ports'} or not isinstance(document['ports'],list) or not 1<=len(document['ports'])<=16:
        raise ValueError('bounded private listener control required')
    for port in document['ports']:
        if type(port) is not int or not 1<=port<=65535 or port in TLS_PORTS:raise ValueError('invalid private listener positive control')
        with socket.create_connection(('127.0.0.1',port),timeout=.5):pass
    return dict(ports=document['ports'],all_reachable=True,namespace=os.readlink('/proc/self/ns/net'))


RPC_METHODS={'getGenesisHash','getProgramAccounts','getSignatureStatuses','getTransaction','getSlot'}


def namespace_rpc(document):
    if os.geteuid()!=0:raise PermissionError('positive RPC control requires operator root inside the pinned namespace')
    if (not isinstance(document,dict) or set(document)!={'address','method','params'}
            or document['method'] not in RPC_METHODS or not isinstance(document['params'],list)):
        raise ValueError('bounded read-only namespace RPC operation required')
    previous.endpoint(document['address'])
    body=json.dumps(dict(jsonrpc='2.0',id=1,method=document['method'],params=document['params'])).encode()
    request=urllib.request.Request('http://'+document['address'],body,{'Content-Type':'application/json'})
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request,timeout=10) as response:raw=response.read(16*1024*1024+1)
    if len(raw)>16*1024*1024:raise ValueError('bounded canonical RPC response required')
    value=json.loads(raw)
    if value.get('id')!=1 or value.get('error') is not None or 'result' not in value:
        raise ValueError('complete positive-control RPC result required')
    return value['result']


def sandbox_probe(role):
    if role not in UNITS:raise ValueError('only fixed service sandbox roles permitted')
    account=identity('zolana058v' if role=='validator' else 'zolana058g')
    if os.getuid()!=account.pw_uid or os.geteuid()!=account.pw_uid:raise PermissionError('probe must run as actual service UID')
    directory=VALROOT if role=='validator' else GWROOT
    outside=STATE/(role+'-canary')
    try:descriptor=os.open(outside,os.O_WRONLY|os.O_NOFOLLOW)
    except OSError as error:
        if error.errno!=errno.EROFS:raise ValueError('DAC-writable external canary did not prove read-only service mount') from error
    else:os.close(descriptor);raise ValueError('service sandbox can write outside its fixed state root')
    canary=directory/'acceptance-write.canary'
    with os.fdopen(os.open(canary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb') as output:
        output.write(b'LOCAL-058 disposable mount write control\n');output.flush();os.fsync(output.fileno())
    canary.unlink()
    return dict(role=role,uid=os.getuid(),outside_write_errno=errno.EROFS,own_state_write=True,
        namespace=os.readlink('/proc/self/ns/net'))


def service_properties(role,runner=subprocess.run):
    if role not in UNITS:raise ValueError('only exact installed service units may be inspected')
    keys=('MainPID','ControlGroup','InvocationID','User','Group','Restart','NoNewPrivileges','ProtectSystem',
          'PrivateNetwork','JoinsNamespaceOf','UMask','CapabilityBoundingSet','ReadWritePaths','ActiveState','SubState')
    result=runner(['/usr/bin/systemctl','show',UNITS[role],*['--property='+key for key in keys]],
        capture_output=True,text=True,check=True,timeout=10)
    values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    expected=identity('zolana058v' if role=='validator' else 'zolana058g')
    group=values.get('ControlGroup','')
    if (set(values)!=set(keys) or values['User']!=expected.pw_name or values['Group']!=expected.pw_name
            or not values['MainPID'].isdecimal() or int(values['MainPID'])<=1
            or values['ActiveState']!='active' or values['SubState']!='running'
            or values['NoNewPrivileges']!='yes' or values['ProtectSystem']!='strict'
            or values['UMask']!='0077' or values['CapabilityBoundingSet']
            or group!='/system.slice/'+UNITS[role] or re.fullmatch('[a-f0-9]{32}',values['InvocationID']) is None):
        raise ValueError('actual fixed systemd unit lacks required active UID/cgroup/sandbox properties')
    if role=='validator' and values['PrivateNetwork']!='yes':raise ValueError('validator lacks private network namespace')
    if role=='gateway' and UNITS['validator'] not in values['JoinsNamespaceOf'].split():
        raise ValueError('gateway does not join the validator network namespace')
    pid=int(values['MainPID']);status=proc_status(pid)
    if (set(map(int,status['Uid'].split()))!={expected.pw_uid}
            or set(map(int,status['Gid'].split()))!={expected.pw_gid}
            or status['NoNewPrivs'].strip()!='1'
            or any(int(status[key].strip(),16) for key in ('CapEff','CapPrm','CapAmb','CapBnd'))):
        raise ValueError('actual service process credentials/capabilities differ from sealed unit')
    actual_group=[line.partition('::')[2] for line in Path(f'/proc/{pid}/cgroup').read_text().splitlines() if line.startswith('0::')]
    if actual_group!=[group]:raise ValueError('service process escaped its exact systemd cgroup')
    values['pid']=pid;values['namespace']=os.readlink(f'/proc/{pid}/ns/net')
    values['start_time']=Path(f'/proc/{pid}/stat').read_text().rpartition(')')[2].split()[19]
    return values


def kernel_cgroup_kill(role,main_pid):
    """Root-only fixed cgroup-v2 kernel write; no PID/name-based signal fallback."""
    if role not in UNITS or os.geteuid()!=0 or type(main_pid) is not int or main_pid<=1:
        raise PermissionError('only the pinned fixed root-managed candidate cgroup may be killed')
    mount=Path('/sys/fs/cgroup')
    if mount.resolve()!=mount:raise ValueError('cgroup kernel mount path changed')
    rows=[line.partition(' - ') for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    if not any(before.split()[4]=='/sys/fs/cgroup' and after.split()[0]=='cgroup2'
               for before,separator,after in rows if separator):
        raise ValueError('actual cgroup-v2 kernel mount required')
    descriptors=[]
    try:
        descriptor=os.open(mount,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);descriptors.append(descriptor)
        meta=os.fstat(descriptor)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0:raise ValueError('root-owned cgroup kernel mount required')
        device=meta.st_dev
        for name in ('system.slice',UNITS[role]):
            descriptor=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
            descriptors.append(descriptor)
            meta=os.fstat(descriptor)
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_dev!=device:
                raise ValueError('fixed cgroup directory is not on the root kernel mount')
        procs=os.open('cgroup.procs',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=descriptor);descriptors.append(procs)
        members=os.read(procs,4097)
        if len(members)>4096:raise ValueError('bounded candidate cgroup process list required')
        pids=members.decode('ascii').splitlines()
        if not 1<=len(pids)<=64 or any(not value.isdecimal() or int(value)<=1 for value in pids) or str(main_pid) not in pids:
            raise ValueError('pinned main process is not in the exact live cgroup')
        account=identity('zolana058v' if role=='validator' else 'zolana058g');pinned=[]
        for value in pids:
            status=proc_status(value)
            if (set(map(int,status['Uid'].split()))!={account.pw_uid}
                    or Path(f'/proc/{value}/cgroup').read_text().splitlines()!=['0::/system.slice/'+UNITS[role]]):
                raise ValueError('candidate cgroup contains a process outside its exact role UID/group')
            start=Path(f'/proc/{value}/stat').read_text().rpartition(')')[2].split()[19]
            pinned.append(dict(pid=int(value),start_time=start))
        kill=os.open('cgroup.kill',os.O_WRONLY|os.O_NOFOLLOW,dir_fd=descriptor);descriptors.append(kill)
        meta=os.fstat(kill)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or meta.st_dev!=device:
            raise ValueError('cgroup.kill is not the fixed root kernel control file')
        if os.write(kill,b'1')!=1:raise OSError('incomplete atomic cgroup.kill write')
        return pinned
    finally:
        for descriptor in reversed(descriptors):os.close(descriptor)


def kill_pinned_cgroup(role,pinned):
    if role not in UNITS or os.geteuid()!=0:raise PermissionError('fixed root operator cgroup kill required')
    current=service_properties(role)
    if any(current[key]!=pinned[key] for key in ('pid','InvocationID','ControlGroup','start_time')):
        raise ValueError('service invocation changed before atomic cgroup kill')
    return kernel_cgroup_kill(role,current['pid'])


def cgroup_sigkill_status(role,pinned,runner=subprocess.run):
    """Capture before stop: systemd clears these fields on explicit stop."""
    if role not in UNITS:raise ValueError('fixed role required for SIGKILL evidence')
    result=runner(['/usr/bin/systemctl','show',UNITS[role],'--property=ExecMainCode','--property=ExecMainStatus','--property=InvocationID'],
        capture_output=True,text=True,check=True,timeout=1)
    values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
    if values.get('InvocationID')!=pinned['InvocationID']:
        raise ValueError('service invocation changed before original SIGKILL evidence capture')
    if values.get('ExecMainCode') in ('0','') and values.get('ExecMainStatus') in ('0',''):
        return None  # The manager has not yet reaped the just-killed main PID.
    if values.get('ExecMainCode') not in ('2','killed') or values.get('ExecMainStatus')!='9':
        raise ValueError('original main process did not exit by SIGKILL')
    return dict(unit=UNITS[role],original_invocation=pinned['InvocationID'],main_code=values['ExecMainCode'],main_status=9)


def cgroup_kill_verified(role,pinned,processes,captured):
    if (role not in UNITS or captured.get('unit')!=UNITS[role]
            or captured.get('original_invocation')!=pinned['InvocationID']
            or captured.get('main_code') not in ('2','killed') or captured.get('main_status')!=9):
        raise ValueError('post-stop process audit requires its original pre-stop SIGKILL evidence')
    for process in processes:
        try:current=Path(f"/proc/{process['pid']}/stat").read_text().rpartition(')')[2].split()[19]
        except FileNotFoundError:continue
        if current==process['start_time']:return None
    path=Path('/sys/fs/cgroup/system.slice')/UNITS[role]/'cgroup.procs'
    try:
        if path.read_text().strip():return None
    except FileNotFoundError:pass
    return dict(captured,old_processes_gone=len(processes),cgroup_empty=True,kernel_control='cgroup-v2/cgroup.kill')


def fixed_systemctl(action,targets,runner=subprocess.run):
    allowed=set(UNITS.values())|set(SOCKET_UNITS)
    if action not in ('start','stop') or not targets or any(target not in allowed for target in targets):
        raise ValueError('only fixed LOCAL-058 unit lifecycle commands are permitted')
    command=['/usr/bin/systemctl',action]
    runner(command+list(targets),capture_output=True,text=True,check=True,timeout={'start':240,'stop':100}[action])


def read_ready(config,digest):
    value=json.loads(read_owned(READY,config['validator_uid'],65536,0o640))
    if (value.get('format')!='zolana-native-service-ready-v1' or value.get('config_sha256')!=digest
            or value.get('network')!=config['network'] or value.get('pool_format')!='NPOOL004'
            or value.get('mac_relay')!=config['relay_public_key']
            or not isinstance(value.get('generation'),str) or not HEX64.fullmatch(value['generation'])
            or type(value.get('namespace_inode')) is not int or value['namespace_inode']<=0
            or type(value.get('supervisor_pid')) is not int or type(value.get('child_pid')) is not int
            or not isinstance(value.get('peers'),list) or len(value['peers'])!=3):
        raise ValueError('sealed service readiness identity/configuration mismatch')
    peers=value['peers']
    if sorted(p.get('identity','') for p in peers)!=sorted(config['validator_identities']):
        raise ValueError('readiness substituted original validator identities')
    endpoints=[]
    for peer in peers:
        for key in ('rpc','native_ingress'):endpoints.append(previous.endpoint(peer[key]))
    if len(set(endpoints))!=6:raise ValueError('readiness duplicates raw endpoints')
    return value


def resolve_original(adapter,job,user_journal,original_user,original_native):
    """Same Trial recovery contract with explicit different owners at each root."""
    native=json.loads(original_native);record=adapter.faults.record
    signature,digest=record['signature'],record['packet_sha256']
    if native.get('signature')!=signature or native.get('packet_sha256')!=digest:
        raise ValueError('original native reservation differs from genuine admitted packet')
    def server_state():
        pending=job/'relay.native.json'
        if os.path.lexists(pending):
            if read_owned(pending,adapter.gateway_uid,65536,0o600)!=original_native:
                raise ValueError('native packet or gross reservation changed during recovery')
        else:
            outcome=json.loads(read_owned(job/'outcome.json',adapter.gateway_uid,65536,0o600))
            if (outcome.get('accepted') is not True or outcome.get('signature')!=signature
                    or outcome.get('packet_sha256')!=digest
                    or outcome.get('reserved_gross_debit')!=native['reserved_debit']):
                raise ValueError('native reservation vanished without original canonical outcome')
    def accepted(value):
        if (not isinstance(value,dict) or value.get('accepted') is not True
                or value.get('encrypted_checkpoint_durable') is not True
                or value.get('signature')!=signature or value.get('id')!=job.name
                or os.path.lexists(user_journal)):
            raise ValueError('original recovery requires exact durable client receipt and journal release')
        server_state();return value
    def attempt():
        server_state()
        if not os.path.lexists(user_journal):
            return accepted(json.loads(read_owned(user_journal.with_suffix('.receipt.json'),adapter.client_uid,65536,0o600)))
        if read_owned(user_journal,adapter.client_uid,20000,0o600)!=original_user:
            raise ValueError('original user proof changed during recovery')
        try:result=adapter.api('alice','resolve')
        except RuntimeError as error:
            if not previous.pending_resolution_error(error):raise
            if os.path.lexists(user_journal) and read_owned(user_journal,adapter.client_uid,20000,0o600)!=original_user:
                raise ValueError('pending recovery replaced original proof') from error
            server_state();return None
        return accepted(result)
    return adapter.wait(attempt,90)


class ServiceTrial(previous.Trial):
    """Root operator lifecycle; actual client API subprocesses remain UID058t."""
    def __init__(self,args):
        if platform.system()!='Linux' or os.geteuid()!=0:raise PermissionError('fixed Linux root operator acceptance only')
        from native_linux_service import validate_config
        raw=read_owned(CONFIG,0,65536,0o444)
        if hashlib.sha256(raw).hexdigest()!=args.config_sha256:raise ValueError('explicit sealed config digest mismatch')
        self.sealed=validate_config(json.loads(raw))
        # validate_config is deliberately also allowed to return None.
        if not isinstance(self.sealed,dict):self.sealed=json.loads(raw)
        if self.sealed.get('test_mode') is not True:raise ValueError('real ACK-loss acceptance requires sealed explicit test_mode')
        self.accounts={name:identity(name) for name in ACCOUNTS}
        if len({item.pw_uid for item in self.accounts.values()})!=3 or len({item.pw_gid for item in self.accounts.values()})!=3:
            raise ValueError('three distinct user and primary group identities required')
        for role,name in (('validator','zolana058v'),('gateway','zolana058g')):
            for suffix,actual in (('uid',self.accounts[name].pw_uid),('gid',self.accounts[name].pw_gid)):
                if self.sealed[role+'_'+suffix]!=actual:raise ValueError('sealed service account differs from installed identity')
        self.gateway_uid=self.accounts['zolana058g'].pw_uid;self.client_uid=self.accounts['zolana058t'].pw_uid
        client_groups=set(os.getgrouplist('zolana058t',self.accounts['zolana058t'].pw_gid))
        if client_groups.intersection({self.sealed['validator_gid'],self.sealed['gateway_gid'],self.sealed['link_gid']}):
            raise ValueError('outside client account shares a protected service/link group')
        checked_directory(VALROOT,self.sealed['validator_uid']);checked_directory(GWROOT,self.gateway_uid)
        checked_directory(CLIENT,self.client_uid)
        checked_directory(NETWORK,self.sealed['validator_uid'])
        self.args,self.root=args,STATE/'acceptance'
        if self.root.parent.resolve()!=STATE or os.path.lexists(self.root):raise ValueError('one fresh fixed acceptance evidence directory required; never overwrite a case')
        self.root.mkdir(mode=0o700)
        self.deadline=time.monotonic()+args.timeout
        self.children,self.logs,self.tokens={},[],{}
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.environment=dict(os.environ,RAYON_NUM_THREADS='2')
        for key in ('NATIVE_WALLET_PROGRESS','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'):
            self.environment.pop(key,None)
        self.config=json.loads(read_owned(CLIENT/'services.json',self.client_uid,65536,0o600))
        self._check_clients()
        self.password=read_owned(CLIENT/'password',self.client_uid,1024,0o600).decode()
        self.host=self.original=read_ready(self.sealed,args.config_sha256)
        self.properties={role:service_properties(role) for role in UNITS}
        self._pin_namespace()
        self.faults=argparse.Namespace(record=None,packets={})
        self.pool=json.loads(read_owned(Path('/etc/zolana-native-058/public-profile.json'),0,65536,0o444))['pool']
        self.result=dict(format='zolana-native-service-acceptance-v1',status='running',events=[],
            scope='fixed co-located Linux service sandbox, invited TLS and actual outside-UID wallet API; trusted canonical RPC',
            systemd_services_provisioned=False,genesis_created=False,mac_validators_started=False)
        self.before_ledger=self.ledger_identity()
        self.event('attached_fixed_preinstalled_service',config_sha256=args.config_sha256,
            uid_roles={name:value.pw_uid for name,value in self.accounts.items()},original_network=self.host['network'])
    def _check_clients(self):
        if (set(self.config)!={'wallet','tester','password','clients','timeout'}
                or self.config.get('wallet')!=str(PREFIX/'bin/native-wallet')
                or self.config.get('tester')!='/etc/zolana-native-058/public-profile.json'
                or self.config.get('password')!=str(CLIENT/'password')
                or set(self.config.get('clients',{}))!={'alice','bob','charlie'}
                or type(self.config.get('timeout')) is not int or not 60<=self.config['timeout']<=900):
            raise ValueError('prebootstrapped exact client paths and bounded lifetime required')
        ports=[]
        for name,item in self.config['clients'].items():
            if set(item)!={'directory','port'} or item['directory']!=str(CLIENT/name):raise ValueError('client state escaped separate fixed outsider root')
            checked_directory(CLIENT/name,self.client_uid)
            if type(item['port']) is not int or not 1024<=item['port']<=65535 or item['port'] in TLS_PORTS:
                raise ValueError('bounded loopback wallet client port required')
            ports.append(item['port'])
        if len(set(ports))!=3:raise ValueError('client API ports must differ')
    def _pin_namespace(self):
        v,g=self.properties['validator'],self.properties['gateway']
        namespace=f"net:[{self.host['namespace_inode']}]"
        if (v['namespace']!=namespace or g['namespace']!=namespace or namespace==os.readlink('/proc/self/ns/net')
                or self.host['supervisor_pid']!=v['pid'] or self.host['child_pid']<=1):
            raise ValueError('actual services/readiness do not share the pinned distinct network namespace')
        child_status=proc_status(self.host['child_pid'])
        child_group=Path(f"/proc/{self.host['child_pid']}/cgroup").read_text().splitlines()
        if (set(map(int,child_status['Uid'].split()))!={self.sealed['validator_uid']}
                or '0::'+v['ControlGroup'] not in child_group
                or os.readlink(f"/proc/{self.host['child_pid']}/ns/net")!=namespace):
            raise ValueError('ready runner child escaped the actual validator UID/cgroup/namespace')
        for role in UNITS:
            if self.properties[role]['Restart']!='on-failure':raise ValueError('fixed reviewed restart policy changed')
            value=subprocess.run(['/usr/bin/systemctl','show',UNITS[role],'--property=RestartUSec','--value'],
                capture_output=True,text=True,check=True,timeout=10).stdout.strip()
            if value not in ('10s','10sec'):raise ValueError('bounded restart delay required before actual cgroup kill')
    def rpc(self,address,method,params=()):
        if address not in {p['rpc'] for p in self.host['peers']}:raise ValueError('RPC positive control escaped fixed ready endpoints')
        pid=self.properties['validator']['pid']
        if os.readlink(f'/proc/{pid}/ns/net')!=self.properties['validator']['namespace']:
            raise ValueError('pinned namespace changed before positive control')
        result=subprocess.run(['/usr/bin/nsenter',f'--net=/proc/{pid}/ns/net','/usr/bin/python3','-B',
            str(PREFIX/'tools/native_service_acceptance.py'),'--namespace-rpc'],
            input=json.dumps(dict(address=address,method=method,params=list(params))),capture_output=True,text=True,timeout=15)
        if result.returncode:raise RuntimeError('fixed read-only namespace RPC positive control failed: '+result.stderr[-600:])
        return json.loads(result.stdout)
    def ledger_identity(self):
        raw=read_owned(NETWORK/'resume.json',self.sealed['validator_uid'],65536,0o600)
        value=json.loads(raw)
        if (value.get('original_root')!=str(NETWORK) or value.get('genesis_hash')!=self.sealed['network']['genesis_hash']
                or value.get('mac_relay')!=self.sealed['relay_public_key'] or value.get('slot_anchors') is not True
                or len(value.get('nodes',[]))!=3):raise ValueError('original exact V4 ledger resume manifest required')
        nodes=[]
        for node in value['nodes']:
            ledger=Path(node['ledger'])
            if not ledger.is_absolute():ledger=NETWORK/ledger
            if not ledger.is_relative_to(NETWORK/'ledgers') or ledger.resolve()!=ledger:raise ValueError('original ledger escaped fixed network root')
            meta=ledger.stat()
            if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=self.sealed['validator_uid']:raise ValueError('original owned ledger directory missing')
            keys=[]
            for field in ('identity_file','voter_file'):
                relative=Path(node[field])
                if relative.is_absolute() or len(relative.parts)!=1:raise ValueError('original key path escaped fixed root')
                key=NETWORK/relative;item=key.lstat()
                if (key.resolve()!=key or not stat.S_ISREG(item.st_mode) or item.st_uid!=self.sealed['validator_uid']
                        or stat.S_IMODE(item.st_mode)!=0o600):raise ValueError('original private service key ownership changed')
                keys.append(dict(name=relative.name,device=item.st_dev,inode=item.st_ino,size=item.st_size,mtime_ns=item.st_mtime_ns))
            nodes.append(dict(ledger=str(ledger),device=meta.st_dev,inode=meta.st_ino,keys=keys))
        return dict(resume_sha256=hashlib.sha256(raw).hexdigest(),nodes=nodes)
    def start(self,name):
        if name not in ('alice','bob','charlie') or name in self.children:raise ValueError('only bounded existing outside-UID wallet clients may start')
        log_path=CLIENT/(name+'-acceptance-'+str(time.time_ns())+'.log')
        descriptor=os.open(log_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        os.fchown(descriptor,self.client_uid,self.accounts['zolana058t'].pw_gid)
        log=os.fdopen(descriptor,'wb');self.logs.append(log)
        command=['/usr/sbin/runuser','-u','zolana058t','--','/usr/bin/setpriv','--no-new-privs',
            '/usr/bin/python3','-B',str(PREFIX/'tools/native_gateway_acceptance.py'),
            '--service-config',str(CLIENT/'services.json'),'--wallet-service',name]
        child=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True,env=self.environment)
        self.children[name]=child
        def ready():
            if child.poll() is not None:raise RuntimeError('outside-UID wallet process exited; retain its private log')
            with socket.socket() as probe:
                probe.settimeout(.2)
                return probe.connect_ex(('127.0.0.1',self.config['clients'][name]['port']))==0
        self.wait(ready,25)
        pidset=set()
        # The runuser parent is root; its direct python child must be UID058t.
        for candidate in Path('/proc').iterdir():
            if candidate.name.isdecimal():
                try:
                    status=proc_status(candidate.name)
                    if int(status['PPid'].strip())==child.pid:
                        if set(map(int,status['Uid'].split()))!={self.client_uid}:raise ValueError('wallet API child did not drop service privileges')
                        if os.readlink(candidate/'ns/net')==self.properties['validator']['namespace']:raise ValueError('client wrongly entered private service namespace')
                        pidset.add(int(candidate.name))
                except (FileNotFoundError,ProcessLookupError):pass
        if len(pidset)!=1:raise ValueError('exact single outside-UID wallet child required')
        with self.opener.open('http://127.0.0.1:'+str(self.config['clients'][name]['port'])+'/api/session',timeout=5) as response:
            self.tokens[name]=json.load(response)['token']
    def event(self,kind,**fields):
        return previous.Trial.event(self,kind,**fields)
    def isolate(self):
        if self.rpc(self.host['peers'][0]['rpc'],'getGenesisHash')!=self.host['network']['genesis_hash']:
            raise ValueError('private namespace RPC positive control has wrong genesis')
        protected={}
        for index in range(3):
            for kind in ('identity','voter'):
                path=NETWORK/f'{kind}-{index}.json'
                meta=path.lstat()
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=self.sealed['validator_uid'] or stat.S_IMODE(meta.st_mode)!=0o600:
                    raise ValueError('private validator key is not an active owned mode600 file')
                protected[f'{kind}-{index}']=str(path)
        for name in ('relay.key','server.key','password'):
            path=GWROOT/name;meta=path.lstat()
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=self.gateway_uid or stat.S_IMODE(meta.st_mode)!=0o600:
                raise ValueError('private gateway key is not an active owned mode600 file')
            protected[name]=str(path)
        relay=json.loads(read_owned(GWROOT/'relay/config.json',self.gateway_uid,65536,0o600))
        ports=[previous.endpoint(p[k])[1] for p in self.host['peers'] for k in ('rpc','native_ingress')]
        ports += [previous.endpoint(value)[1] for value in relay['native_ingress']]
        processes=[p['pid'] for p in self.properties.values()]+[self.host['child_pid']]
        document=dict(format='zolana-native-058-outsider-v1',files=protected,ports=sorted(set(ports)),
            service_pids=sorted(set(processes)),service_namespace=self.properties['validator']['namespace'])
        positive=subprocess.run(['/usr/bin/nsenter',f"--net=/proc/{self.properties['validator']['pid']}/ns/net",
            '/usr/bin/python3','-B',str(PREFIX/'tools/native_service_acceptance.py'),'--private-listeners'],
            input=json.dumps(dict(ports=sorted(set(ports)))),capture_output=True,text=True,timeout=15)
        if positive.returncode:raise RuntimeError('private listener positive control failed: '+positive.stderr[-600:])
        for peer in self.host['peers']:
            if self.rpc(peer['rpc'],'getGenesisHash')!=self.host['network']['genesis_hash']:
                raise ValueError('all three original raw RPC positive controls required')
        result=subprocess.run(['/usr/sbin/runuser','-u','zolana058t','--','/usr/bin/setpriv','--no-new-privs',
            '/usr/bin/python3','-B',str(PREFIX/'tools/native_service_acceptance.py'),'--outsider-probe'],
            input=json.dumps(document),capture_output=True,text=True,timeout=30)
        if result.returncode:raise RuntimeError('actual different-UID negative isolation probe failed: '+result.stderr[-600:])
        observations=json.loads(result.stdout)
        sandbox=[]
        for role,properties in self.properties.items():
            name='zolana058v' if role=='validator' else 'zolana058g';account=self.accounts[name]
            canary=STATE/(role+'-canary')
            if not os.path.lexists(canary):
                descriptor=os.open(canary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                os.fchown(descriptor,account.pw_uid,account.pw_gid);os.close(descriptor)
            meta=canary.lstat()
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=account.pw_uid or stat.S_IMODE(meta.st_mode)!=0o600:raise ValueError('mount canary ownership changed')
            command=['/usr/bin/nsenter',f"--mount=/proc/{properties['pid']}/ns/mnt",f"--net=/proc/{properties['pid']}/ns/net",
                '/usr/sbin/runuser','-u',name,'--','/usr/bin/setpriv','--no-new-privs','/usr/bin/python3','-B',
                str(PREFIX/'tools/native_service_acceptance.py'),'--sandbox-probe',role]
            control=subprocess.run(command,capture_output=True,text=True,timeout=10)
            if control.returncode:raise RuntimeError('actual mount namespace positive/negative control failed: '+control.stderr[-600:])
            sandbox.append(json.loads(control.stdout))
        self.event('actual_different_uid_fs_netns_cgroup_controls',negative_probes=observations,mount_controls=sandbox,private_listener_positive=json.loads(positive.stdout),
            private_genesis_positive_control=True,services_share_private_namespace=True)
    def tls_controls(self):
        profile=json.loads(read_owned(Path('/etc/zolana-native-058/public-profile.json'),0,65536,0o444))
        if (profile.get('private_send_transport')!='native-inline-v1' or profile.get('pool_format')!='NPOOL004'
                or profile['rpc']['url']!='https://127.0.0.1:38443' or profile['faucet']['url']!='https://127.0.0.1:38444'):
            raise ValueError('fixed invited native TLS public profile changed')
        context=ssl.create_default_context(cadata=profile['local_tls_ca_pem'])
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        for method in ('getSlot','getNativePrivateTransactionFee'):
            request=urllib.request.Request(profile['rpc']['url'],json.dumps(dict(jsonrpc='2.0',id=1,method=method,params=[])).encode(),{'Content-Type':'application/json'})
            try:opener.open(request,timeout=5).close()
            except urllib.error.HTTPError as error:
                if error.code!=403:raise ValueError('anonymous/private fee RPC isolation returned unexpected status') from error
            else:raise ValueError('anonymous client bypassed actual invited TLS gateway')
        self.event('actual_tls_gateway_anonymous_denied',local_ca_pinned=True,global_certificate_store_untouched=True)
    def capture_catalog(self):
        jobs=GWROOT/'relay/jobs';checked_directory(jobs,self.gateway_uid)
        packets={}
        for job in jobs.iterdir():
            if not HEX64.fullmatch(job.name):raise ValueError('unexpected relay job path')
            checked_directory(job,self.gateway_uid)
            path=job/'outcome.json'
            if not os.path.lexists(path):continue
            outcome=json.loads(read_owned(path,self.gateway_uid,65536,0o600))
            if outcome.get('accepted') is not True:raise ValueError('unexpected unsuccessful relay job during exact payment sequence')
            signature,digest=outcome['signature'],outcome['packet_sha256']
            if not isinstance(digest,str) or not HEX64.fullmatch(digest):raise ValueError('outcome lacks exact native packet digest')
            tx=self.rpc(self.host['peers'][0]['rpc'],'getTransaction',[signature,{'encoding':'base64','commitment':'finalized','maxSupportedTransactionVersion':0}])
            wire=base64.b64decode(tx['transaction'][0],validate=True)
            actual_signature,actual_digest=previous.wire_identity(wire)
            if (actual_signature!=signature or actual_digest!=digest or tx['slot']!=outcome['execution_slot']
                    or tx.get('meta',{}).get('err') is not None or tx['meta']['fee']!=outcome['actual_transaction_fee']
                    or outcome.get('exact_packet_canonical') is not True):raise ValueError('relay outcome differs from actual canonical full packet/fee')
            packets[signature]=dict(sha256=digest,bytes=len(wire))
        self.faults.packets=packets
    def crash_original(self):
        # Pin exact original unit/process identities immediately before mutation.
        pinned={role:service_properties(role) for role in UNITS}
        for role in UNITS:
            if any(pinned[role][key]!=self.properties[role][key] for key in ('pid','InvocationID','ControlGroup','start_time')):
                raise ValueError('service invocation changed before bounded crash')
        # Gateway Requires both sockets: stopping sockets first would stop it
        # orderly. Kill both pinned cgroups before cancelling delayed restarts.
        kill_began=time.monotonic()
        killed={};captured={}
        for role in ('gateway','validator'):
            killed[role]=kill_pinned_cgroup(role,pinned[role])
            # Capture gateway first: validator failure propagates BindsTo and
            # can clear the gateway's completed invocation status.
            remaining=min(2,7-(time.monotonic()-kill_began))
            if remaining<=0:raise TimeoutError('pre-stop SIGKILL evidence exceeded fixed restart-delay budget')
            captured[role]=self.wait(lambda role=role:cgroup_sigkill_status(role,pinned[role]),remaining)
        fixed_systemctl('stop',SOCKET_UNITS)
        fixed_systemctl('stop',[UNITS['gateway'],UNITS['validator']])
        evidence={role:self.wait(lambda role=role:cgroup_kill_verified(role,pinned[role],killed[role],captured[role]),15) for role in UNITS}
        if self.ledger_identity()!=self.before_ledger:raise ValueError('original keys/ledger inode or resume metadata changed after cgroup crash')
        self.event('actual_gateway_and_whole_validator_cgroups_sigkilled',units=list(UNITS.values()),
            old_invocations={role:value['InvocationID'] for role,value in pinned.items()},kernel_kill_evidence=evidence,original_ledger_and_keys_unchanged=True)
    def resume_original(self):
        arm=GATE/'arm.json'
        if not os.path.lexists(arm):raise ValueError('original root fault arm disappeared unexpectedly')
        arm.unlink();descriptor=os.open(GATE,os.O_RDONLY)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        fixed_systemctl('start',[UNITS['validator']])
        def ready():
            try:after=read_ready(self.sealed,self.args.config_sha256)
            except FileNotFoundError:return None
            same_original(self.original,after)
            return after if after['generation']!=self.original['generation'] else None
        self.host=self.wait(ready,180)
        fixed_systemctl('start',list(SOCKET_UNITS));fixed_systemctl('start',[UNITS['gateway']])
        old=self.properties;self.properties={role:service_properties(role) for role in UNITS};self._pin_namespace()
        if any(self.properties[role]['InvocationID']==old[role]['InvocationID'] for role in UNITS):raise ValueError('service invocation did not actually restart')
        if self.ledger_identity()!=self.before_ledger:raise ValueError('restart substituted original ledger/resume/key metadata')
        if self.rpc(self.host['peers'][0]['rpc'],'getGenesisHash')!=self.original['network']['genesis_hash']:
            raise ValueError('original resumed chain genesis changed')
        self.event('actual_original_ledger_service_resume',same_genesis_keys_ledger=True,new_ready_generation=self.host['generation'],
            no_consensus_threshold_override=True,no_new_genesis=True)
    def run(self):
        self.isolate();self.tls_controls()
        self.addresses={}
        for name in ('alice','bob','charlie'):
            self.start(name);self.addresses[name]=self.api(name,'unlock')
            if not self.api(name,'access-status')['admitted']:raise ValueError('prebootstrapped actual invite membership missing')
        expected=dict(alice=50_000_000,bob=0,charlie=0);self.balances(expected)
        self.capture_catalog()
        if self.faults.packets:raise ValueError('clean service case must not contain earlier relay jobs')
        self.audit(2,sum(expected.values()))
        for sender,recipient,amount in [('alice','bob',20_000_000),('bob','charlie',5_000_000),('alice','charlie',2_000_000)]:
            began=time.monotonic()
            receipt=self.api(sender,'send',recipient=self.addresses[recipient]['address'],amount=amount,fee_mode='shielded',max_shielded_fee=3_000_000)
            if receipt.get('accepted') is not True or receipt.get('encrypted_checkpoint_durable') is not True:
                raise ValueError('actual private send lacks accepted durable client receipt')
            expected[sender]-=amount+3_000_000;expected[recipient]+=amount;self.balances(expected)
            self.event('actual_outside_uid_invited_private_hop',sender=sender,recipient=recipient,
                action_to_all_durable_balances_ms=(time.monotonic()-began)*1000,receipt=receipt)
        self.capture_catalog()
        if len(self.faults.packets)!=3:raise ValueError('three prior exact native packet outcomes required')
        self.event('all_peer_private_state_before_crash',audit=self.audit(8,sum(expected.values())))
        checked_directory(GATE,self.gateway_uid)
        if any(os.path.lexists(GATE/name) for name in ('arm.json','observed.json','original.packet')):
            raise ValueError('fault gate must be fresh; never reset prior evidence')
        nonce=secrets.token_hex(32);arm=GATE/'arm.json'
        previous.save(arm,dict(format='zolana-native-058-ack-arm-v1',nonce=nonce,expires_at=int(time.time())+180))
        os.chown(arm,0,self.accounts['zolana058g'].pw_gid);arm.chmod(0o640)
        user=CLIENT/'alice/wallet-ui/wallet.json.shielded.json'
        with ThreadPoolExecutor(max_workers=1) as pool:
            sending=pool.submit(self.api,'alice','send',recipient=self.addresses['bob']['address'],amount=1_000_000,fee_mode='shielded',max_shielded_fee=3_000_000)
            record=self.wait(lambda:json.loads(read_owned(GATE/'observed.json',self.gateway_uid,8192,0o600)) if os.path.lexists(GATE/'observed.json') else None,90)
            wire=read_owned(GATE/'original.packet',self.gateway_uid,MAXIMUM,0o600)
            bound=admitted_identity(wire,record.get('ack'))
            if bound is None or record.get('nonce')!=nonce or any(record.get(k)!=v for k,v in bound.items()):
                raise ValueError('fault record did not bind actual admitted original packet')
            self.faults.record=record
            original_user=read_owned(user,self.client_uid,20000,0o600)
            pending=[p for p in (GWROOT/'relay/jobs').iterdir() if (p/'relay.native.json').exists()]
            if len(pending)!=1 or not HEX64.fullmatch(pending[0].name):raise ValueError('exact one pending original relay job required')
            job=pending[0];original_native=read_owned(job/'relay.native.json',self.gateway_uid,65536,0o600)
            native=json.loads(original_native)
            if (native.get('signature')!=record['signature'] or native.get('packet_sha256')!=record['packet_sha256']
                    or base64.b64decode(native['packet'],validate=True)!=wire
                    or native['reserved_debit']!=native['transaction_fee']+native['marker_rent']
                    or native['reserved_debit']>native['gross_cap']):raise ValueError('original relay packet/budget journal differs from real fault')
            previous.save(self.root/'original-fault.json',dict(job_id=job.name,record=record,
                user_proof_sha256=hashlib.sha256(original_user).hexdigest(),native_journal_sha256=hashlib.sha256(original_native).hexdigest(),
                gross_cap=native['gross_cap'],reserved_debit=native['reserved_debit']))
            self.stop('alice',crash=True);self.crash_original()
            try:sending.result(timeout=10)
            except (OSError,ValueError,RuntimeError):pass
        if read_owned(user,self.client_uid,20000,0o600)!=original_user or read_owned(job/'relay.native.json',self.gateway_uid,65536,0o600)!=original_native:
            raise ValueError('original proof/packet/budget changed while stopped')
        self.resume_original();self.start('alice')
        receipt=resolve_original(self,job,user,original_user,original_native)
        expected['alice']-=4_000_000;expected['bob']+=1_000_000;self.balances(expected)
        self.capture_catalog()
        if len(self.faults.packets)!=4:raise ValueError('fault recovery created missing or additional packet outcomes')
        self.event('original_admitted_packet_recovered_once',receipt=receipt,balances=expected,audit=self.audit(10,sum(expected.values())))
        self.isolate();self.result['status']='passed'
    def close(self):
        failures=[]
        for name in list(self.children):
            try:self.stop(name)
            except BaseException as error:failures.append(type(error).__name__)
        # Stop only these fixed candidate services, without deleting any state.
        for targets in (list(SOCKET_UNITS),[UNITS['gateway'],UNITS['validator']]):
            try:fixed_systemctl('stop',targets)
            except BaseException as error:failures.append(type(error).__name__)
        for log in self.logs:log.close()
        self.result['fixed_services_stopped']=not failures
        if failures:self.result.update(status='failed',cleanup_errors=failures)
        previous.save(self.root/'result.json',self.result)
        if failures:raise RuntimeError('fixed candidate cleanup failed; original evidence retained')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--outsider-probe',action='store_true')
    modes.add_argument('--namespace-rpc',action='store_true')
    modes.add_argument('--private-listeners',action='store_true')
    modes.add_argument('--sandbox-probe',choices=tuple(UNITS))
    modes.add_argument('--execute-isolation-recovery',action='store_true')
    parser.add_argument('--config-sha256');parser.add_argument('--timeout',type=int,default=600)
    args=parser.parse_args()
    if platform.system()!='Linux':raise ValueError('LOCAL-058 acceptance is Linux only')
    if args.outsider_probe or args.namespace_rpc or args.private_listeners:
        raw=sys.stdin.buffer.read(65537)
        if len(raw)>65536:raise ValueError('bounded internal control input required')
        result=outsider_probe(json.loads(raw)) if args.outsider_probe else (private_listeners(json.loads(raw)) if args.private_listeners else namespace_rpc(json.loads(raw)))
        print(json.dumps(result));return
    if args.sandbox_probe:print(json.dumps(sandbox_probe(args.sandbox_probe)));return
    if args.config_sha256 is None or not HEX64.fullmatch(args.config_sha256) or not 180<=args.timeout<=900:
        raise ValueError('explicit exact sealed config digest and bounded acceptance lifetime required')
    if Path(__file__).resolve()!=PREFIX/'tools/native_service_acceptance.py':
        raise ValueError('privileged acceptance must execute the fixed installed root-owned script')
    trial=None
    def interrupted(*_):raise KeyboardInterrupt('fixed service acceptance interrupted; preserving original state')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    try:trial=ServiceTrial(args);trial.run()
    except BaseException as error:
        if trial is not None:trial.result.update(status='failed',error_type=type(error).__name__,error=str(error)[:1500])
        raise
    finally:
        if trial is not None:trial.close()


if __name__=='__main__':main()
