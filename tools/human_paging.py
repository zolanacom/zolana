"""Durable PagerDuty Events v2 relay; local mock delivery is the default."""
from email.utils import parsedate_to_datetime
import fcntl
import hashlib
from http.client import HTTPSConnection, HTTPException
import json
import math
import os
from pathlib import Path
import signal
import ssl
import threading
import time
from urllib.parse import urlsplit

from monitor_transport import (DeadlineSocket, HEX32, HEX64, decode, digest, encode,
                               endpoint, private)
from operator_health import atomic, directory, timestamp
from operator_monitor import Journal, public_event


class PageFailure(Exception):
    def __init__(self,code,retry_at=None,blocked=False):
        super().__init__(code);self.code=code;self.retry_at=retry_at;self.blocked=blocked


def provider_url(url,allow_network=False):
    if not isinstance(url,str):raise ValueError('invalid provider endpoint')
    parsed=urlsplit(url)
    if parsed.path!='/v2/enqueue' or url!='https://'+parsed.netloc+'/v2/enqueue':raise ValueError('invalid exact provider route')
    origin=endpoint('https://'+parsed.netloc,allow_network)
    if origin.hostname!='127.0.0.1' and url!='https://events.pagerduty.com/v2/enqueue':raise ValueError('unreviewed paging provider')
    return origin


def routing_key(path,deployment):
    value=decode(private(path,2048))
    if (not isinstance(value,dict) or set(value)!={'format','deployment','routing_key'} or
            value['format']!='native-pagerduty-key-v1' or value['deployment']!=deployment or
            not isinstance(value['routing_key'],str) or HEX32.fullmatch(value['routing_key']) is None):
        raise ValueError('wrong provider integration credential')
    return value['routing_key']


def retry_after(value,now):
    if not isinstance(value,str) or len(value)>128:return None
    try:
        if value.isdigit():seconds=int(value)
        else:
            date=parsedate_to_datetime(value)
            if date.tzinfo is None:return None
            seconds=date.timestamp()-now
        if not math.isfinite(seconds):return None
        return now+min(86400,max(1,seconds))
    except (ValueError,OverflowError,TypeError):return None


class Provider:
    def __init__(self,url,ca_file,ca_sha256,key_file,deployment,allow_network=False,timeout=3):
        self.origin=provider_url(url,allow_network);self.deployment=deployment;self.timeout=timeout
        self.key=routing_key(key_file,deployment)
        ca=private(ca_file)
        if hashlib.sha256(ca).hexdigest()!=ca_sha256:raise ValueError('provider CA pin changed')
        self.context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);self.context.minimum_version=ssl.TLSVersion.TLSv1_2
        self.context.load_verify_locations(cadata=ca.decode('ascii'));self.context.set_alpn_protocols(['http/1.1'])

    def send(self,event,action,key,now):
        public_event(event)
        if action not in ('trigger','resolve') or not isinstance(key,str) or not key.startswith('nativepay:') or HEX64.fullmatch(key[10:]) is None:
            raise ValueError('invalid planned paging action')
        payload={'routing_key':self.key,'event_action':action,'dedup_key':key}
        if action=='trigger':
            payload['payload']={'summary':'Native chain: '+event['code'],'source':'native-monitor/'+self.deployment,
                'severity':'critical','component':'private-payments',
                'custom_details':{'event_id':event['id'],'code':event['code'],'kind':event['kind']}}
        connection=HTTPSConnection(self.origin.hostname,self.origin.port or 443,context=self.context,timeout=self.timeout)
        response=None
        try:
            deadline=time.monotonic()+self.timeout
            connection.connect();connection.sock=DeadlineSocket(connection.sock,deadline)
            connection.request('POST','/v2/enqueue',encode(payload),{'Content-Type':'application/json','Host':self.origin.netloc})
            response=connection.getresponse()
            if response.status==429:raise PageFailure('rate_limited',retry_after(response.headers.get('Retry-After'),now))
            if response.status in (400,401,403,404,422):raise PageFailure('provider_rejected',blocked=True)
            if response.status!=202:raise PageFailure('provider_unavailable' if response.status>=500 else 'provider_response_invalid')
            if response.headers.get_content_type()!='application/json':raise PageFailure('provider_response_invalid')
            lengths=response.headers.get_all('Content-Length',[])
            if len(lengths)>1 or (lengths and (not lengths[0].isdigit() or not 0<int(lengths[0])<=8192)):
                raise PageFailure('provider_response_invalid')
            if response.headers.get('Transfer-Encoding') not in (None,'chunked') or (lengths and response.headers.get('Transfer-Encoding')):
                raise PageFailure('provider_response_invalid')
            raw=response.read(int(lengths[0]) if lengths else 8193)
            if not 0<len(raw)<=8192 or (lengths and len(raw)!=int(lengths[0])):raise PageFailure('provider_response_invalid')
            result=decode(raw)
            if (not isinstance(result,dict) or set(result)!={'status','message','dedup_key'} or result['status']!='success' or
                    result['dedup_key']!=key or not isinstance(result['message'],str) or len(result['message'])>1024):
                raise PageFailure('provider_response_invalid')
            return {'accepted':True,'dedup_key':key}
        except (OSError,HTTPException):raise PageFailure('provider_unavailable') from None
        except ValueError:raise PageFailure('provider_response_invalid') from None
        finally:
            if response is not None:response.close()
            connection.close()


def snapshot(root,deployment):
    root=Path(root);directory(root,os.getuid(),0o700)
    if decode(private(root/'initialized'))!={'format':'native-alert-inbox-marker-v1','deployment':deployment}:
        raise ValueError('source inbox identity differs')
    value=decode(private(root/'inbox.json',1048576))
    if not isinstance(value,dict) or set(value)!={'format','deployment','events'} or value['format']!='native-alert-inbox-v1' or value['deployment']!=deployment or not isinstance(value['events'],list) or len(value['events'])>1024:
        raise ValueError('invalid source inbox snapshot')
    previous={}
    for event in value['events']:
        public_event(event);stream=event['id'].split(':')[0]
        if event['sequence']<=previous.get(stream,0):raise ValueError('source event order changed')
        previous[stream]=event['sequence']
    return value['events']


def planned(event,active,deployment):
    stream=event['id'].split(':')[0]
    if event['kind']=='incident':
        action='trigger';key=active.get(stream) or 'nativepay:'+hashlib.sha256((deployment+':'+event['id']).encode()).hexdigest()
    else:
        key=active.get(stream);action='resolve' if key is not None else 'skip'
    return {'event_id':event['id'],'event_sha256':digest(event),'action':action,'dedup_key':key}


def apply(active,event,plan):
    active=dict(active);stream=event['id'].split(':')[0]
    if plan['action']=='trigger':active[stream]=plan['dedup_key']
    else:active.pop(stream,None)
    if len(active)>128:raise ValueError('active paging capacity exhausted')
    return active


class Relay:
    def __init__(self,root,inbox,deployment,route,provider,hook=None):
        self.root=Path(root);self.inbox=Path(inbox);self.deployment=deployment;self.route=route;self.provider=provider;self.hook=hook;self.failed=False
        if self.root.resolve()==self.inbox.resolve() or self.root.resolve() in self.inbox.resolve().parents or self.inbox.resolve() in self.root.resolve().parents:
            raise ValueError('paging state and inbox must be separate')
        if not self.root.exists():self.root.mkdir(mode=0o700)
        directory(self.root,os.getuid(),0o700)
        self.fd=os.open(self.root/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            Journal._safe(os.fstat(self.fd));fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            marker=self.root/'initialized';path=self.root/'state.json'
            if os.path.lexists(marker):
                if decode(private(marker))!={'format':'native-human-pager-marker-v1','route':route}:raise ValueError('paging route changed')
                self.state=decode(private(path,1048576))
            elif os.path.lexists(path):raise ValueError('incomplete paging initialization; preserve evidence')
            else:
                self.state={'format':'native-human-pager-v1','route':route,'cursor':0,'prefix_sha256':digest([]),
                    'active':{},'pending':None,'receipts':[],'last_wall':None}
                self.save();atomic(marker,{'format':'native-human-pager-marker-v1','route':route},0o600)
            self.check(snapshot(self.inbox,self.deployment))
        except BaseException:os.close(self.fd);raise

    def save(self):
        if self.failed:raise ValueError('paging persistence uncertain; restart against retained state')
        try:atomic(self.root/'state.json',self.state,0o600)
        except Exception:self.failed=True;raise

    def check(self,events):
        s=self.state
        if (not isinstance(s,dict) or set(s)!={'format','route','cursor','prefix_sha256','active','pending','receipts','last_wall'} or
                s['format']!='native-human-pager-v1' or s['route']!=self.route or type(s['cursor']) is not int or not 0<=s['cursor']<=len(events) or
                not isinstance(s['receipts'],list) or len(s['receipts'])!=s['cursor'] or
                s['prefix_sha256']!=digest(events[:s['cursor']]) or (s['last_wall'] is not None and not timestamp(s['last_wall']))):
            raise ValueError('paging journal or source prefix changed')
        active={}
        for event,receipt in zip(events,s['receipts']):
            plan=planned(event,active,self.deployment)
            if (not isinstance(receipt,dict) or set(receipt)!={'plan','outcome','at'} or receipt['plan']!=plan or
                    receipt['outcome']!=('no_active_page' if plan['action']=='skip' else 'provider_accepted') or not timestamp(receipt['at'])):
                raise ValueError('invalid paging acceptance journal')
            active=apply(active,event,plan)
        if active!=s['active']:raise ValueError('invalid active paging incidents')
        pending=s['pending']
        if pending is not None:
            if (s['cursor']==len(events) or not isinstance(pending,dict) or set(pending)!={'plan','attempts','next_at','failure','blocked'} or
                    pending['plan']!=planned(events[s['cursor']],active,self.deployment) or type(pending['attempts']) is not int or not 0<=pending['attempts']<=1000000 or
                    not timestamp(pending['next_at']) or pending['failure'] not in (None,'rate_limited','provider_rejected','provider_unavailable','provider_response_invalid') or
                    type(pending['blocked']) is not bool or pending['blocked']!=(pending['failure']=='provider_rejected') or
                    (pending['attempts']==0 and (pending['next_at']!=0 or pending['failure'] is not None))):raise ValueError('invalid pending paging action')

    def step(self,now=None):
        if self.failed:raise ValueError('paging persistence uncertain; restart against retained state')
        now=time.time() if now is None else now
        if not timestamp(now):raise ValueError('invalid paging clock')
        events=snapshot(self.inbox,self.deployment);self.check(events);s=self.state
        if s['last_wall'] is not None and now<s['last_wall']-2:raise ValueError('paging clock moved backwards')
        s['last_wall']=now
        if s['cursor']==len(events):return self.status('idle')
        event=events[s['cursor']]
        if s['pending'] is None:
            plan=planned(event,s['active'],self.deployment);apply(s['active'],event,plan)
            s['pending']={'plan':plan,'attempts':0,'next_at':0,'failure':None,'blocked':False}
            self.save()
            if self.hook:self.hook('planned')
        p=s['pending'];plan=p['plan']
        if p['blocked']:return self.status('blocked')
        if p['next_at']>now:return self.status('waiting')
        if plan['action']!='skip':
            p['attempts']+=1;p['next_at']=now+min(300,2**min(p['attempts'],9));self.save()
            if self.hook:self.hook('before_send')
            try:
                receipt=self.provider.send(event,plan['action'],plan['dedup_key'],now)
                if receipt!={'accepted':True,'dedup_key':plan['dedup_key']} or receipt.get('accepted') is not True:
                    raise PageFailure('provider_response_invalid')
            except PageFailure as error:
                p.update(failure=error.code,blocked=error.blocked)
                if error.retry_at is not None:p['next_at']=max(p['next_at'],error.retry_at)
                self.save();return self.status('blocked' if error.blocked else 'retrying')
            if self.hook:self.hook('provider_accepted')
        s['active']=apply(s['active'],event,plan);s['cursor']+=1;s['prefix_sha256']=digest(events[:s['cursor']])
        s['receipts'].append({'plan':plan,'outcome':'no_active_page' if plan['action']=='skip' else 'provider_accepted','at':now})
        s['pending']=None;self.save()
        return self.status('accepted' if plan['action']!='skip' else 'no_active_page')

    def status(self,phase):
        return {'phase':phase,'processed':self.state['cursor'],'active_pages':len(self.state['active']),
                'failure':self.state['pending']['failure'] if self.state['pending'] else None,'human_receipt_verified':False}

    def retry_blocked(self,now=None):
        if self.failed:raise ValueError('paging persistence uncertain; restart against retained state')
        now=time.time() if now is None else now
        self.check(snapshot(self.inbox,self.deployment))
        if not timestamp(now) or (self.state['last_wall'] is not None and now<self.state['last_wall']-2):raise ValueError('invalid paging retry clock')
        pending=self.state['pending']
        if pending is None or not pending['blocked']:raise ValueError('no blocked paging action to retry')
        pending.update(blocked=False,failure=None,next_at=now);self.state['last_wall']=now;self.save()
        return self.status('retry_armed')  # Never sends a provider request.

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


def configuration(path,allow_network=False):
    path=Path(path).absolute();c=decode(private(path))
    if (not isinstance(c,dict) or set(c)!={'format','deployment','inbox','state','provider','interval_seconds'} or
            c['format']!='native-human-pager-config-v1' or not isinstance(c['deployment'],str) or HEX32.fullmatch(c['deployment']) is None or
            type(c['interval_seconds']) not in (float,int) or not 1<=c['interval_seconds']<=30):raise ValueError('invalid human paging config')
    p=c['provider']
    if not isinstance(p,dict) or set(p)!={'endpoint','ca_file','ca_sha256','routing_key_file'}:raise ValueError('invalid paging provider config')
    provider_url(p['endpoint'],allow_network)
    for item,key in ((c,'inbox'),(c,'state'),(p,'ca_file'),(p,'routing_key_file')):
        if not isinstance(item[key],str) or not item[key] or len(item[key])>1024:raise ValueError('invalid paging path')
        item[key]=str(path.parent/item[key])
    key=routing_key(p['routing_key_file'],c['deployment'])
    route={'format':'native-human-paging-route-v1','deployment':c['deployment'],'inbox':str(Path(c['inbox']).resolve()),
           'endpoint':p['endpoint'],'ca_sha256':p['ca_sha256'],'integration_sha256':hashlib.sha256(key.encode()).hexdigest()}
    provider=Provider(p['endpoint'],p['ca_file'],p['ca_sha256'],p['routing_key_file'],c['deployment'],allow_network)
    return c,route,provider


def run(path,duration=60,allow_network=False,retry_blocked=False):
    c,route,provider=configuration(path,allow_network)
    relay=Relay(c['state'],c['inbox'],c['deployment'],route,provider);stopping=threading.Event()
    if retry_blocked:
        try:print(json.dumps(relay.retry_blocked(),sort_keys=True),flush=True)
        finally:relay.close()
        return
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,lambda *_:stopping.set())
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    deadline=time.monotonic()+duration if duration else float('inf');last=None
    try:
        while not stopping.is_set() and time.monotonic()<deadline:
            status=relay.step()
            if status!=last:print(json.dumps(status,sort_keys=True),flush=True);last=status
            stopping.wait(c['interval_seconds'])
    finally:relay.close()
