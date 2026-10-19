"""Read-only progress agent and independent watchdog with its own delivery lane."""
import json
import os
from pathlib import Path
import secrets
import signal
import threading
import time
from http.client import HTTPException

from human_paging import Relay
from monitor_transport import Client, HEX32, HEX64, Inbox, Server, capability, decode, digest, endpoint, private
from operator_health import timestamp
from operator_monitor import Journal, Monitor
from watchdog_notify import Telegram
from watchdog_progress import read,validate


class Agent:
    def __init__(self,deployment,targets):self.deployment=deployment;self.targets=targets
    def handle(self,value):
        if (not isinstance(value,dict) or set(value)!={'deployment','challenge'} or value['deployment']!=self.deployment or
                not isinstance(value['challenge'],str) or HEX64.fullmatch(value['challenge']) is None):raise ValueError('invalid watchdog challenge')
        targets={}
        for role in ('monitor','pager'):
            try:pulse=read(self.targets[role]['pulse_file'],self.targets[role]['owner'],self.deployment,role);error=None
            except FileNotFoundError:pulse=None;error='missing'
            except Exception:pulse=None;error='invalid'
            targets[role]={'progress':pulse,'error':error}
        return {'format':'native-watchdog-observation-v1','deployment':self.deployment,'challenge':value['challenge'],'observed_at':time.time(),'targets':targets}


class AgentClient(Client):
    def observe(self):
        challenge=secrets.token_hex(32)
        value=self.request('/v1/watchdog',{'deployment':self.deployment,'challenge':challenge})
        return observation(value,self.deployment,challenge)


def observation(value,deployment,challenge,now=None):
    now=time.time() if now is None else now
    if (not isinstance(value,dict) or set(value)!={'format','deployment','challenge','observed_at','targets'} or
            value['format']!='native-watchdog-observation-v1' or value['deployment']!=deployment or value['challenge']!=challenge or
            not timestamp(value['observed_at']) or abs(now-value['observed_at'])>10 or
            not isinstance(value['targets'],dict) or set(value['targets'])!={'monitor','pager'}):raise ValueError('invalid watchdog observation')
    for role,item in value['targets'].items():
        if not isinstance(item,dict) or set(item)!={'progress','error'} or item['error'] not in (None,'missing','invalid'):
            raise ValueError('invalid watchdog target')
        if item['error'] is None:validate(item['progress'],deployment,role)
        elif item['progress'] is not None:raise ValueError('conflicting target error')
    return value


class Detector:
    def __init__(self,journal,source,primary_integration,stale=15,backlog=60,startup=60):
        self.journal=journal;self.source=source;self.primary=primary_integration
        self.stale=stale;self.backlog=backlog;self.startup=startup
        self.monitor=Monitor(journal,'.',os.getuid())
        self.path=journal.root/'targets.json'
        if self.path.exists():
            self.targets=decode(private(self.path))
            if not isinstance(self.targets,dict) or set(self.targets)!={'monitor','pager'}:raise ValueError('invalid watchdog restart history')
            for item in self.targets.values():
                if not isinstance(item,dict) or set(item)!={'instance','sequence','progress_at','unready_since'} or (item['instance'] is not None and (not isinstance(item['instance'],str) or HEX32.fullmatch(item['instance']) is None)) or type(item['sequence']) is not int or item['sequence']<0 or (item['progress_at'] is not None and not timestamp(item['progress_at'])) or (item['unready_since'] is not None and not timestamp(item['unready_since'])):raise ValueError('invalid watchdog progress history')
        elif self.journal.state['last_wall'] is not None:raise ValueError('initialized watchdog progress history missing')
        else:
            self.targets={role:{'instance':None,'sequence':0,'progress_at':None,'unready_since':None} for role in ('monitor','pager')}
            self.save()
    def save(self):
        from operator_health import atomic
        atomic(self.path,self.targets,0o600)
    def sample(self,now=None):
        try:value=self.source.observe()
        except (OSError,HTTPException):return self.monitor.transition('watchdog_unavailable',False,False,time.time() if now is None else now)
        except ValueError:return self.monitor.transition('watchdog_invalid',False,False,time.time() if now is None else now)
        now=time.time() if now is None else now
        if not timestamp(now) or (self.journal.state['last_wall'] is not None and now<self.journal.state['last_wall']-2):
            return self.monitor.transition('watchdog_invalid',False,False,now)
        faults=[];all_ready=True
        for role in ('monitor','pager'):
            item=value['targets'][role];history=self.targets[role]
            if history['unready_since'] is None:history['unready_since']=now
            if item['error'] is not None:faults.append(role+'_'+item['error']);continue
            pulse=item['progress'];completed=pulse['completed_at']
            if (pulse['started_at']>now+2 or (completed is not None and completed>now+2) or
                    (pulse['oldest_pending_at'] is not None and pulse['oldest_pending_at']>now+2) or
                    (role=='pager' and pulse['integration_sha256']!=self.primary)):
                faults.append(role+'_invalid');continue
            same=history['instance']==pulse['instance']
            if same and pulse['sequence']<history['sequence']:faults.append(role+'_invalid');continue
            advanced=not same or pulse['sequence']>history['sequence']
            if advanced:
                history.update(instance=pulse['instance'],sequence=pulse['sequence'],progress_at=now)
            if pulse['phase'] in ('stopped','failed'):faults.append(role+'_stopped')
            elif pulse['phase']=='starting':
                all_ready=False
                if now-min(history['unready_since'],pulse['started_at'])>self.startup:faults.append(role+'_startup_stalled')
            elif completed is None or now-completed>self.stale or (history['progress_at'] is not None and now-history['progress_at']>self.stale):faults.append(role+'_stale')
            elif pulse['failure']=='delivery_blocked':faults.append(role+'_blocked')
            elif pulse['pending'] and now-pulse['oldest_pending_at']>self.backlog:faults.append(role+'_backlog')
            else:history['unready_since']=None
        # Save progress before the journal transition. A crash can conservatively
        # re-observe it; it never resolves an incident from a new PID alone.
        self.save()
        result=self.monitor.transition(faults[0] if faults else None,all_ready and not faults,False,now)
        result['faults']=faults;return result


def config(path,allow_network=False):
    path=Path(path).absolute();c=decode(private(path));kind=c.get('format') if isinstance(c,dict) else None
    schemas={'native-watchdog-agent-v1':{'format','deployment','origin','capability_file','certificate_file','key_file','targets'},
        'native-independent-watchdog-v1':{'format','deployment','agent','provider','primary_integration_sha256','root','interval_seconds','stale_seconds','backlog_seconds','startup_seconds'}}
    if not isinstance(kind,str) or kind not in schemas or set(c)!=schemas[kind] or not isinstance(c['deployment'],str) or HEX32.fullmatch(c['deployment']) is None:raise ValueError('invalid watchdog config')
    def resolve(item,key):
        if not isinstance(item[key],str) or not item[key] or len(item[key])>1024:raise ValueError('invalid watchdog path')
        item[key]=str(path.parent/item[key])
    if kind=='native-watchdog-agent-v1':
        endpoint(c['origin'],allow_network)
        for key in ('capability_file','certificate_file','key_file'):resolve(c,key)
        if not isinstance(c['targets'],dict) or set(c['targets'])!={'monitor','pager'}:raise ValueError('invalid watchdog targets')
        for item in c['targets'].values():
            if not isinstance(item,dict) or set(item)!={'pulse_file','owner'} or type(item['owner']) is not int or item['owner']!=os.getuid():raise ValueError('invalid progress operator')
            resolve(item,'pulse_file')
    else:
        if not isinstance(c['primary_integration_sha256'],str) or HEX64.fullmatch(c['primary_integration_sha256']) is None:raise ValueError('invalid primary integration identity')
        for key,minimum,maximum in [('interval_seconds',1,30),('stale_seconds',3,300),('backlog_seconds',3,3600),('startup_seconds',3,600)]:
            if type(c[key]) not in (int,float) or not minimum<=c[key]<=maximum:raise ValueError('invalid watchdog threshold')
        for name,keys in [('agent',{'origin','capability_file','ca_file','ca_sha256'}),('provider',{'origin','key_file','ca_file','ca_sha256'})]:
            item=c[name]
            if not isinstance(item,dict) or set(item)!=keys:raise ValueError('invalid watchdog peer')
            endpoint(item['origin'],allow_network)
            for key in ('capability_file','key_file','ca_file'):
                if key in item:resolve(item,key)
        resolve(c,'root')
    return c


class Context:
    def __init__(self,c,allow_network=False):
        self.c=c;self.root=Path(c['root'])
        from operator_health import directory
        if not self.root.exists():self.root.mkdir(mode=0o700)
        directory(self.root,os.getuid(),0o700)
        a=c['agent'];p=c['provider']
        self.source=AgentClient(a['origin'],a['ca_file'],a['ca_sha256'],a['capability_file'],c['deployment'],'watchdog-read',allow_network)
        self.provider=Telegram(p['origin'],p['ca_file'],p['ca_sha256'],p['key_file'],c['deployment'],allow_network)
        route={'format':'native-watchdog-route-v1','deployment':c['deployment'],'agent_origin':a['origin'],'agent_ca':a['ca_sha256'],
            'notification_origin':p['origin'],'notification_ca':p['ca_sha256'],'notification_integration':self.provider.fingerprint,
            'primary_integration':c['primary_integration_sha256'],'thresholds':{k:c[k] for k in ('interval_seconds','stale_seconds','backlog_seconds','startup_seconds')}}
        self.journal=None;self.inbox=None;self.relay=None
        try:
            self.journal=Journal(self.root/'observations',binding=route)
            self.inbox=Inbox(self.root/'events',c['deployment'])
            self.relay=Relay(self.root/'delivery',self.root/'events',c['deployment'],route,self.provider)
            self.detector=Detector(self.journal,self.source,c['primary_integration_sha256'],c['stale_seconds'],c['backlog_seconds'],c['startup_seconds'])
        except BaseException:self.close();raise
    def step(self):
        state=self.detector.sample()
        def store(event):
            receipt=self.inbox.handle({'format':'native-monitor-alert-v1','deployment':self.c['deployment'],'event':event})
            return {k:receipt[k] for k in ('id','sha256','durable')}
        self.journal.deliver_remote(store)
        page=self.relay.step()
        return {'state':state['state'],'code':state['code'],'delivery':page['phase'],'human_receipt_verified':False}
    def close(self):
        for worker in (self.relay,self.inbox,self.journal):
            if worker is not None:worker.close()


def run(action,path,duration=60,allow_network=False,bind='127.0.0.1'):
    c=config(path,allow_network);stopping=threading.Event()
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,lambda *_:stopping.set())
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    deadline=time.monotonic()+duration if duration else float('inf')
    if action=='watchdog-agent':
        if c['format']!='native-watchdog-agent-v1':raise ValueError('wrong watchdog agent config')
        origin=endpoint(c['origin'],allow_network)
        server=Server((bind,origin.port or 443),Agent(c['deployment'],c['targets']),origin.netloc,capability(c['capability_file'],c['deployment'],'watchdog-read'),
            'watchdog-read',c['certificate_file'],c['key_file'])
        server.timeout=.2;print(json.dumps({'listening':True,'read_only':True}),flush=True)
        try:
            while not stopping.is_set() and time.monotonic()<deadline:server.handle_request()
        finally:server.server_close()
    else:
        if c['format']!='native-independent-watchdog-v1':raise ValueError('wrong independent watchdog config')
        context=Context(c,allow_network)
        try:
            if action=='watchdog-retry':print(json.dumps(context.relay.retry_blocked(),sort_keys=True),flush=True);return
            last=None
            while not stopping.is_set() and time.monotonic()<deadline:
                status=context.step()
                if status!=last:print(json.dumps(status,sort_keys=True),flush=True);last=status
                stopping.wait(c['interval_seconds'])
        finally:context.close()
