"""Standalone health exporter, independent observer and durable alert inbox."""
import argparse
from http.client import HTTPException
import json
import os
from pathlib import Path
import signal
import secrets
import ssl
import threading
import time

from monitor_transport import (Client, Exporter, HEX32, Inbox, Server, capability,
                               decode, endpoint, private)
from operator_monitor import Journal, Monitor


class DeliveryUnavailable(Exception):pass


class Watch:
    def __init__(self,journal,source,alerts,expect_running=False):
        self.journal=journal;self.source=source;self.alerts=alerts;self.current=None
        self.next_attempt=0;self.failures=0;self.delivery='idle'
        self.expect_running=expect_running
        self.monitor=Monitor(journal,'.',os.getuid(),probe=self.probe,reader=self.reader)

    def probe(self):
        if self.current['job'] is None:raise ValueError('source probe failed')
        return self.current['job']

    def reader(self):
        if self.current['error']=='heartbeat_missing':raise FileNotFoundError('source heartbeat missing')
        if self.current['error']=='heartbeat_invalid':raise ValueError('source heartbeat invalid')
        return self.current['health']

    def sample(self,now=None):
        try:self.current=self.source.health()
        except (OSError,HTTPException):return self.monitor.transition('remote_unavailable',False,False,time.time() if now is None else now)
        except ValueError:return self.monitor.transition('remote_invalid',False,False,time.time() if now is None else now)
        if self.expect_running and self.current['job'] is not None and not self.current['job']['loaded']:
            return self.monitor.transition('service_paused',False,False,time.time() if now is None else now)
        return self.monitor.sample(time.time() if now is None else now)

    def deliver(self,monotonic=None):
        now=time.monotonic() if monotonic is None else monotonic
        if now<self.next_attempt:return
        def send(event):
            try:return self.alerts.alert(event)
            except (OSError,HTTPException,ValueError):raise DeliveryUnavailable() from None
        try:
            sent=self.journal.deliver_remote(send)
            self.failures=0;self.next_attempt=0;self.delivery='delivered' if sent else 'idle'
        except DeliveryUnavailable:
            self.failures=min(self.failures+1,6);self.next_attempt=now+min(30,2**self.failures)
            self.delivery='retrying'
        # Local journal write/validation errors are fatal, not network retries.


def load_config(path,allow_network):
    path=Path(path).absolute();config=decode(private(path))
    if not isinstance(config,dict) or not isinstance(config.get('deployment'),str) or HEX32.fullmatch(config['deployment']) is None:
        raise ValueError('invalid monitor deployment config')
    schemas={
        'native-health-exporter-v1':{'format','deployment','origin','capability_file','certificate_file','key_file','heartbeat_file','heartbeat_owner'},
        'native-alert-receiver-v1':{'format','deployment','origin','capability_file','certificate_file','key_file','root'},
        'native-offhost-monitor-v1':{'format','deployment','source','alerts','journal','interval_seconds','expect_running'},
    }
    if config.get('format') not in schemas or set(config)!=schemas[config['format']]:raise ValueError('invalid exact monitor config')
    def resolved(name):
        if not isinstance(name,str) or not name or len(name)>1024:raise ValueError('invalid monitoring path')
        return str(path.parent/name)
    if config['format']=='native-offhost-monitor-v1':
        if type(config['expect_running']) is not bool:raise ValueError('expected service state must be explicit')
        if type(config['interval_seconds']) not in (int,float) or not 1<=config['interval_seconds']<=30:raise ValueError('invalid monitoring interval')
        for name in ('source','alerts'):
            item=config[name]
            if not isinstance(item,dict) or set(item)!={'origin','capability_file','ca_file','ca_sha256'}:raise ValueError('invalid monitoring peer')
            endpoint(item['origin'],allow_network)
            for key in ('capability_file','ca_file'):item[key]=resolved(item[key])
        config['journal']=resolved(config['journal'])
    else:
        endpoint(config['origin'],allow_network)
        for name in ('capability_file','certificate_file','key_file','heartbeat_file','root'):
            if name in config:config[name]=resolved(config[name])
        if config['format']=='native-health-exporter-v1' and (type(config['heartbeat_owner']) is not int or config['heartbeat_owner']<0):raise ValueError('invalid heartbeat owner')
    return config


def clients(config,allow_network):
    result=[]
    for name,role in (('source','health-read'),('alerts','alert-write')):
        item=config[name]
        result.append(Client(item['origin'],item['ca_file'],item['ca_sha256'],item['capability_file'],config['deployment'],role,allow_network))
    if result[0].token==result[1].token:raise ValueError('health and alert capabilities must be separate')
    return result


def binding(config):
    return {'format':'native-monitor-route-v1','deployment':config['deployment'],
        'source_origin':config['source']['origin'],'source_ca':config['source']['ca_sha256'],
        'alert_origin':config['alerts']['origin'],'alert_ca':config['alerts']['ca_sha256'],'expect_running':config['expect_running']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('export','receive','watch','check','keygen','page','page-retry'))
    parser.add_argument('--config',type=Path)
    parser.add_argument('--deployment');parser.add_argument('--role',choices=('health-read','alert-write'))
    parser.add_argument('--output',type=Path)
    parser.add_argument('--duration',type=int,default=60)
    parser.add_argument('--allow-network',action='store_true')
    parser.add_argument('--bind',default='127.0.0.1',choices=('127.0.0.1','0.0.0.0'))
    args=parser.parse_args()
    if args.action=='keygen':
        if not args.output or not args.role or not args.deployment or HEX32.fullmatch(args.deployment) is None:raise ValueError('keygen needs deployment, role and a new private output')
        from operator_health import atomic
        # Exclusive creation reserves the destination before atomic publication;
        # interrupted provisioning stays visibly incomplete, never overwritten.
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        atomic(args.output,{'format':'native-monitor-capability-v1','deployment':args.deployment,'role':args.role,'token':secrets.token_hex(32)},0o600)
        print(json.dumps({'created':True,'role':args.role,'spending_or_rpc_capability':False}));return
    if args.config is None:raise ValueError('monitoring role requires a private config')
    if args.action in ('page','page-retry'):
        from human_paging import run
        return run(args.config,args.duration,args.allow_network,retry_blocked=args.action=='page-retry')
    if not 0<=args.duration<=600 or (args.duration==0 and not args.allow_network):raise ValueError('local rehearsal requires a finite 1–600 second duration')
    if args.bind!='127.0.0.1' and not args.allow_network:raise ValueError('external bind requires explicit network authorization')
    config=load_config(args.config,args.allow_network)
    expected={'export':'native-health-exporter-v1','receive':'native-alert-receiver-v1','watch':'native-offhost-monitor-v1','check':'native-offhost-monitor-v1'}[args.action]
    if config['format']!=expected:raise ValueError('wrong role config')
    stopping=threading.Event()
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,lambda *_:stopping.set())
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    deadline=time.monotonic()+args.duration if args.duration else float('inf')
    if args.action in ('watch','check'):
        source,alerts=clients(config,args.allow_network)
        journal=Journal(config['journal'],binding=binding(config))
        try:
            watch=Watch(journal,source,alerts,expect_running=config['expect_running']);last=None
            while not stopping.is_set() and time.monotonic()<deadline:
                result=watch.sample();watch.deliver()
                status=dict(state=result['state'],code=result['code'],delivery=watch.delivery,
                            pending=sum(not e['delivered'] for e in journal.state['events']))
                if status!=last:print(json.dumps(status,sort_keys=True),flush=True);last=status
                if args.action=='check':return
                stopping.wait(config['interval_seconds'])
        finally:journal.close()
    else:
        role='health-read' if args.action=='export' else 'alert-write'
        token=capability(config['capability_file'],config['deployment'],role)
        app=Exporter(config['heartbeat_file'],config['heartbeat_owner'],config['deployment']) if args.action=='export' else Inbox(config['root'],config['deployment'])
        origin=endpoint(config['origin'],args.allow_network);server=None
        try:
            server=Server((args.bind,origin.port or 443),app,origin.netloc,token,role,config['certificate_file'],config['key_file'])
            server.timeout=.2;print(json.dumps({'listening':True,'role':role,'tls':True}),flush=True)
            while not stopping.is_set() and time.monotonic()<deadline:server.handle_request()
        finally:
            if server is not None:server.server_close()
            if isinstance(app,Inbox):app.close()


if __name__=='__main__':
    try:main()
    except Exception:
        # Config/TLS/transport exceptions must not echo tokens, payloads or paths.
        print(json.dumps({'error':'monitoring_failed','evidence_retained':True}),file=__import__('sys').stderr)
        raise SystemExit(1)
