"""Scoped HTTPS monitoring protocol. No RPC, wallet or arbitrary-file routes."""
import fcntl
import hashlib
import hmac
from http.client import HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import stat
import threading
import time
from urllib.parse import urlsplit

from operator_health import atomic, directory, read, timestamp, validate
from operator_monitor import Journal, launch_probe, public_event

HEX32=re.compile('[0-9a-f]{32}')
HEX64=re.compile('[0-9a-f]{64}')
LIMIT=8192


def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(value):return hashlib.sha256(encode(value)).hexdigest()


def decode(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate protocol key')
            result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def private(path,maximum=32768):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        meta=os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_nlink!=1 or stat.S_IMODE(meta.st_mode)!=0o600 or not 0<meta.st_size<=maximum:
            raise ValueError('unsafe bounded monitoring file')
        raw=stream.read(maximum+1)
        if len(raw)>maximum:raise ValueError('monitoring file exceeds bound')
        return raw


def capability(path,deployment,role):
    value=decode(private(path,1024))
    if (not isinstance(value,dict) or set(value)!={'format','deployment','role','token'} or
            value['format']!='native-monitor-capability-v1' or value['deployment']!=deployment or value['role']!=role or
            not isinstance(value['token'],str) or HEX64.fullmatch(value['token']) is None):
        raise ValueError('wrong monitoring capability role or deployment')
    return value['token']


def endpoint(url,allow_network=False):
    if not isinstance(url,str) or len(url)>512:raise ValueError('invalid monitoring origin')
    parsed=urlsplit(url)
    if (parsed.scheme!='https' or url!='https://'+parsed.netloc or not parsed.hostname or parsed.username or parsed.password or
            parsed.path or parsed.query or parsed.fragment or not parsed.netloc.isascii() or
            re.fullmatch('[A-Za-z0-9.:-]+',parsed.netloc) is None or not 1<=(parsed.port or 443)<=65535):
        raise ValueError('monitoring requires an exact HTTPS origin')
    if not allow_network and parsed.hostname!='127.0.0.1':raise ValueError('non-loopback monitoring requires explicit network authorization')
    return parsed


class DeadlineReader(io.RawIOBase):
    def __init__(self,owner):self.owner=owner;self.sock=owner.sock;self.deadline=owner.deadline
    def readable(self):return True
    def readinto(self,buffer):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('monitoring request deadline')
        self.sock.settimeout(remaining)
        return self.sock.recv_into(buffer)
    def close(self):
        if not self.closed:
            self.owner.readers-=1
            if self.owner.closing and not self.owner.readers:self.sock.close()
        super().close()


class DeadlineSocket:
    def __init__(self,sock,deadline):self.sock=sock;self.deadline=deadline;self.readers=0;self.closing=False
    def makefile(self,*args,**kwargs):
        self.readers+=1
        return io.BufferedReader(DeadlineReader(self))
    def close(self):
        self.closing=True
        if not self.readers:self.sock.close()
    def sendall(self,data):
        remaining=self.deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('monitoring request deadline')
        self.sock.settimeout(remaining);return self.sock.sendall(data)
    def __getattr__(self,name):return getattr(self.sock,name)


class Client:
    def __init__(self,url,ca_file,ca_sha256,key_file,deployment,role,allow_network=False,timeout=3):
        self.url=url;self.origin=endpoint(url,allow_network);self.deployment=deployment;self.role=role;self.timeout=timeout
        if not isinstance(deployment,str) or HEX32.fullmatch(deployment) is None:raise ValueError('invalid deployment identity')
        ca=private(ca_file)
        if hashlib.sha256(ca).hexdigest()!=ca_sha256:raise ValueError('monitoring CA pin changed')
        self.token=capability(key_file,deployment,role)
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cadata=ca.decode('ascii'));self.context.set_alpn_protocols(['http/1.1'])

    def request(self,path,payload):
        if path!={'health-read':'/v1/health','alert-write':'/v1/alerts','watchdog-read':'/v1/watchdog'}.get(self.role):raise ValueError('monitor capability cannot use this route')
        raw=encode(payload)
        if len(raw)>LIMIT:raise ValueError('monitoring payload exceeds bound')
        connection=HTTPSConnection(self.origin.hostname,self.origin.port or 443,timeout=self.timeout,context=self.context)
        response=None
        try:
            deadline=time.monotonic()+self.timeout
            connection.connect();connection.sock=DeadlineSocket(connection.sock,deadline)
            connection.request('POST',path,raw,{'Authorization':'Bearer '+self.token,'Content-Type':'application/json','Host':self.origin.netloc})
            response=connection.getresponse()
            if response.status in (429,500,502,503,504):raise OSError('monitoring endpoint unavailable')
            lengths=response.headers.get_all('Content-Length',[])
            if (response.status!=200 or response.headers.get('Transfer-Encoding') is not None or
                    len(lengths)!=1 or not lengths[0].isdigit() or not 0<int(lengths[0])<=LIMIT or
                    response.headers.get_content_type()!='application/json'):
                raise ValueError('monitoring response rejected')
            body=response.read(int(lengths[0]))
            if len(body)!=int(lengths[0]):raise ValueError('truncated monitoring response')
            return decode(body)
        finally:
            if response is not None:response.close()
            connection.close()

    def health(self):
        challenge=secrets.token_hex(32)
        result=self.request('/v1/health',{'deployment':self.deployment,'challenge':challenge})
        return observation(result,self.deployment,challenge)

    def alert(self,event):
        public_event(event)
        receipt=self.request('/v1/alerts',{'format':'native-monitor-alert-v1','deployment':self.deployment,'event':event})
        expected={'format':'native-alert-receipt-v1','deployment':self.deployment,'id':event['id'],'sha256':digest(event),'durable':True}
        if not isinstance(receipt,dict) or receipt.get('durable') is not True or receipt!=expected:raise ValueError('invalid durable remote alert receipt')
        return {k:receipt[k] for k in ('id','sha256','durable')}


def observation(value,deployment,challenge,now=None):
    now=time.time() if now is None else now
    if (not isinstance(value,dict) or set(value)!={'format','deployment','challenge','observed_at','job','health','error'} or
            value['format']!='native-monitor-observation-v1' or value['deployment']!=deployment or value['challenge']!=challenge or
            not timestamp(value['observed_at']) or abs(now-value['observed_at'])>10 or
            value['error'] not in (None,'monitor_probe_failed','heartbeat_missing','heartbeat_invalid')):
        raise ValueError('invalid or replayed monitoring observation')
    job=value['job']
    if job is None:
        if value['error']!='monitor_probe_failed' or value['health'] is not None:raise ValueError('invalid failed probe')
    elif (not isinstance(job,dict) or set(job)!={'loaded','pid'} or type(job['loaded']) is not bool or
            (job['pid'] is not None and (type(job['pid']) is not int or job['pid']<=0)) or
            (not job['loaded'] and (job['pid'] is not None or value['health'] is not None or value['error'] is not None))):
        raise ValueError('invalid monitored job')
    if value['health'] is not None:
        validate(value['health'])
        if value['error'] is not None:raise ValueError('conflicting health error')
    elif job is not None and job['loaded'] and value['error'] not in ('heartbeat_missing','heartbeat_invalid'):
        raise ValueError('missing loaded-service health')
    return value


class Exporter:
    def __init__(self,heartbeat,owner,deployment,probe=launch_probe):
        self.heartbeat=Path(heartbeat);self.owner=owner;self.deployment=deployment;self.probe=probe

    def handle(self,value):
        if (not isinstance(value,dict) or set(value)!={'deployment','challenge'} or value['deployment']!=self.deployment or
                not isinstance(value['challenge'],str) or HEX64.fullmatch(value['challenge']) is None):
            raise ValueError('invalid health challenge')
        error=None;health=None
        try:
            job=self.probe()
            if not isinstance(job,dict) or set(job)!={'loaded','pid'} or type(job['loaded']) is not bool:raise ValueError('invalid probe')
        except Exception:job=None;error='monitor_probe_failed'
        if job is not None and job['loaded']:
            try:health=read(self.heartbeat,self.owner)
            except FileNotFoundError:error='heartbeat_missing'
            except Exception:error='heartbeat_invalid'
        result=dict(format='native-monitor-observation-v1',deployment=self.deployment,challenge=value['challenge'],
                    observed_at=time.time(),job=job,health=health,error=error)
        return observation(result,self.deployment,value['challenge'])


class Inbox:
    def __init__(self,root,deployment,hook=None):
        self.root=Path(root);self.deployment=deployment;self.hook=hook;self.mutex=threading.Lock();self.failed=False
        if not self.root.exists():self.root.mkdir(mode=0o700)
        directory(self.root,os.getuid(),0o700)
        self.fd=os.open(self.root/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            Journal._safe(os.fstat(self.fd));fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            marker=self.root/'initialized';path=self.root/'inbox.json'
            if os.path.lexists(marker):
                if decode(private(marker))!={'format':'native-alert-inbox-marker-v1','deployment':deployment}:raise ValueError('inbox identity changed')
                self.state=decode(private(path,1048576));self.validate()
            elif os.path.lexists(path):raise ValueError('incomplete inbox; preserve evidence')
            else:
                self.state={'format':'native-alert-inbox-v1','deployment':deployment,'events':[]}
                atomic(path,self.state,0o600);atomic(marker,{'format':'native-alert-inbox-marker-v1','deployment':deployment},0o600)
        except BaseException:os.close(self.fd);raise

    def validate(self):
        s=self.state
        if not isinstance(s,dict) or set(s)!={'format','deployment','events'} or s['format']!='native-alert-inbox-v1' or s['deployment']!=self.deployment or not isinstance(s['events'],list) or len(s['events'])>1024:
            raise ValueError('invalid or full inbox')
        ids=set()
        for event in s['events']:
            public_event(event)
            if event['id'] in ids:raise ValueError('duplicate stored alert identity')
            ids.add(event['id'])

    def handle(self,value):
        if not isinstance(value,dict) or set(value)!={'format','deployment','event'} or value['format']!='native-monitor-alert-v1' or value['deployment']!=self.deployment:
            raise ValueError('invalid alert envelope')
        event=public_event(value['event'])
        with self.mutex:
            if self.failed:raise RuntimeError('inbox durability uncertain; restart against preserved state')
            old=next((e for e in self.state['events'] if e['id']==event['id']),None)
            if old is not None and digest(old)!=digest(event):raise ValueError('changed-content alert retry')
            if old is None:
                if len(self.state['events'])>=1024:raise ValueError('inbox capacity exhausted; preserve receipts')
                candidate=dict(self.state,events=self.state['events']+[event])
                if self.hook:self.hook('before_commit',event)
                try:atomic(self.root/'inbox.json',candidate,0o600)
                except Exception:self.failed=True;raise
                self.state=candidate
                if self.hook:self.hook('after_commit',event)
            return {'format':'native-alert-receipt-v1','deployment':self.deployment,'id':event['id'],'sha256':digest(event),'durable':True}

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


class Server(ThreadingHTTPServer):
    daemon_threads=False;block_on_close=True
    def __init__(self,address,app,authority,token,role,cert,key):
        self.app=app;self.authority=authority;self.token=token;self.role=role;self.slots=threading.BoundedSemaphore(4)
        private(cert);private(key)
        self.ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);self.ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        self.ctx.load_cert_chain(cert,key,password=lambda:'');self.ctx.set_alpn_protocols(['http/1.1'])
        super().__init__(address,Handler)
    def process_request(self,request,address):
        if not self.slots.acquire(blocking=False):request.close();return
        try:super().process_request(request,address)
        except BaseException:self.slots.release();raise
    def process_request_thread(self,request,address):
        secure=None
        try:
            request.settimeout(2)
            secure=self.ctx.wrap_socket(request,server_side=True)
            # Absolute read deadline covers TLS HTTP headers and body trickles.
            wrapped=DeadlineSocket(secure,time.monotonic()+3)
            self.finish_request(wrapped,address);self.shutdown_request(wrapped)
        except Exception:
            request.close()
        finally:
            if secure is not None:secure.close()
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    server_version='Monitor';sys_version=''
    def log_message(self,*_):pass
    def reply(self,status,value):
        raw=encode(value);self.send_response(status);self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(raw)
    def do_POST(self):
        expected={'health-read':'/v1/health','alert-write':'/v1/alerts','watchdog-read':'/v1/watchdog'}.get(self.server.role)
        if (self.path!=expected or self.headers.get_all('Host')!=[self.server.authority] or
                len(self.headers.get_all('Authorization',[]))!=1 or
                not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+self.server.token)):
            self.reply(403,{'error':'denied'});return
        lengths=self.headers.get_all('Content-Length',[])
        if (len(lengths)!=1 or not lengths[0].isdigit() or not 0<int(lengths[0])<=LIMIT or
                self.headers.get('Transfer-Encoding') is not None or self.headers.get('Content-Type')!='application/json'):
            self.reply(400,{'error':'invalid_request'});return
        try:
            raw=self.rfile.read(int(lengths[0]))
            if len(raw)!=int(lengths[0]):raise ValueError('truncated request')
            result=self.server.app.handle(decode(raw))
        except (ValueError,TypeError,KeyError):self.reply(409,{'error':'invalid_payload'});return
        except Exception:self.reply(503,{'error':'unavailable'});return
        self.reply(200,result)
    def do_GET(self):self.reply(404,{'error':'route_not_found'})
