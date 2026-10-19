"""Read-only local health observer with a durable, at-least-once stdout outbox."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
import threading

from operator_health import atomic, directory, read, timestamp

CODES = {'monitor_probe_failed', 'heartbeat_missing', 'heartbeat_invalid', 'heartbeat_stale',
         'clock_invalid', 'publisher_mismatch', 'startup_stalled', 'finality_stalled',
         'service_paused', 'retention_failed', 'finality_timeout', 'validator_exited',
         'ingress_exited', 'startup_failed', 'cleanup_failed', 'health_unavailable',
         'disk_low', 'test_complete', 'service_failed', 'service_not_ready'}


def launch_probe():
    result = subprocess.run(['/bin/launchctl', 'print', 'system/local.nativepay.validator'],
                            capture_output=True, text=True, timeout=5)
    if result.returncode == 113: return {'loaded': False, 'pid': None}
    if result.returncode != 0: raise ValueError('launchd probe failed')
    matches = re.findall(r'^\s*pid = (\d+)\s*$', result.stdout, re.MULTILINE)
    return {'loaded': True, 'pid': int(matches[0]) if len(matches) == 1 else None}


class Journal:
    def __init__(self, root):
        self.root = Path(root)
        if not self.root.exists(): self.root.mkdir(mode=0o700)
        directory(self.root, os.getuid(), 0o700)
        self.lock_fd = os.open(self.root/'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            self._safe(os.fstat(self.lock_fd))
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = self.root/'state.json'; marker = self.root/'initialized'
            if os.path.lexists(marker):
                if self._load(marker, 128)!={'format':'native-operator-initialized-v1'}:
                    raise ValueError('invalid monitor initialization marker')
                self.state = self._load(path)
                self._validate()
            elif os.path.lexists(path): raise ValueError('incomplete monitor initialization; preserve journal')
            else:
                self.state = dict(format='native-operator-journal-v1', journal=secrets.token_hex(16),
                    next_sequence=1, incident=None, events=[], last_wall=None, pid=None, loaded_since=None, ready_pid=None)
                self.save(); atomic(marker, {'format':'native-operator-initialized-v1'}, 0o600)
        except BaseException:
            os.close(self.lock_fd); raise

    @staticmethod
    def _safe(meta):
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_nlink != 1 or stat.S_IMODE(meta.st_mode) != 0o600:
            raise ValueError('unsafe monitor journal')

    def _load(self, path, maximum=262144):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            self._safe(os.fstat(stream.fileno()))
            raw = stream.read(maximum+1)
            if len(raw) > maximum: raise ValueError('monitor journal exceeds bound')
            return json.loads(raw)

    def _validate(self):
        s = self.state
        if not isinstance(s, dict) or set(s) != {'format', 'journal', 'next_sequence', 'incident', 'events', 'last_wall', 'pid', 'loaded_since', 'ready_pid'}:
            raise ValueError('invalid monitor journal schema')
        if s['format'] != 'native-operator-journal-v1' or not isinstance(s['journal'],str) or not re.fullmatch('[0-9a-f]{32}',s['journal']):
            raise ValueError('invalid monitor journal identity')
        if type(s['next_sequence']) is not int or s['next_sequence'] < 1: raise ValueError('invalid monitor event sequence')
        for key in ('last_wall','loaded_since'):
            if s[key] is not None and not timestamp(s[key]): raise ValueError('invalid monitor clock')
        for key in ('pid','ready_pid'):
            if s[key] is not None and (type(s[key]) is not int or s[key] <= 0): raise ValueError('invalid monitored pid')
        if not isinstance(s['events'], list) or len(s['events']) > 128: raise ValueError('monitor outbox capacity exceeded')
        previous = 0
        for event in s['events']:
            if (not isinstance(event,dict) or set(event) != {'id','sequence','kind','code','at','delivered'} or
                    type(event['sequence']) is not int or not previous < event['sequence'] < s['next_sequence'] or
                    event['id'] != s['journal']+':'+str(event['sequence']) or event['kind'] not in ('incident','recovered','operator_paused') or
                    event['code'] not in CODES or not timestamp(event['at']) or type(event['delivered']) is not bool):
                raise ValueError('invalid monitor event')
            previous = event['sequence']
        incident = s['incident']
        if incident is not None and (not isinstance(incident,dict) or set(incident) != {'code','id'} or
                incident['code'] not in CODES or not any(e['id']==incident['id'] and e['code']==incident['code'] and e['kind']=='incident' for e in s['events'])):
            raise ValueError('invalid open monitor incident')

    def save(self):
        self._validate(); atomic(self.root/'state.json', self.state, 0o600)

    def event(self, kind, code, now):
        # Keep recent delivered evidence and every pending event/open incident.
        events=self.state['events']; incident=self.state['incident']
        while len(events) >= 128:
            removable=next((i for i,e in enumerate(events) if e['delivered'] and (incident is None or e['id']!=incident['id'])),None)
            if removable is None: raise ValueError('monitor outbox full; preserve undelivered events')
            events.pop(removable)
        sequence=self.state['next_sequence']; self.state['next_sequence']+=1
        event=dict(id=self.state['journal']+':'+str(sequence),sequence=sequence,kind=kind,code=code,at=now,delivered=False)
        events.append(event)
        return event

    def deliver(self, stream):
        for event in self.state['events']:
            if not event['delivered']:
                public={k:v for k,v in event.items() if k!='delivered'}
                stream.write(json.dumps(public, sort_keys=True)+'\n'); stream.flush()
                event['delivered']=True; self.save()

    def close(self): os.close(self.lock_fd)


class Monitor:
    def __init__(self, journal, heartbeat, owner, probe=launch_probe, grace=30, stale=15, finality=60, startup=180):
        self.journal=journal; self.heartbeat=Path(heartbeat); self.owner=owner; self.probe=probe
        self.grace=grace; self.stale=stale; self.finality=finality; self.startup=startup

    def sample(self, now=None):
        now=time.time() if now is None else now
        if not timestamp(now): raise ValueError('invalid monitor time')
        state=self.journal.state; paused=False; healthy=False; code=None
        try:
            job=self.probe()
            if set(job)!={'loaded','pid'} or type(job['loaded']) is not bool or (job['pid'] is not None and (type(job['pid']) is not int or job['pid']<=0)):
                raise ValueError('invalid launchd probe')
        except Exception: job=None; code='monitor_probe_failed'
        if job is not None:
            if not job['loaded']:
                paused=True; state['loaded_since']=None; state['pid']=None; state['ready_pid']=None
            else:
                # Bound grace across a crash loop, rather than granting every
                # new PID another thirty seconds of silence.
                if state['loaded_since'] is None or (state['pid']!=job['pid'] and state['ready_pid'] is not None):
                    state['loaded_since']=now; state['ready_pid']=None
                state['pid']=job['pid']
                grace=state['ready_pid'] is None and now-state['loaded_since'] < self.grace
                try: data=read(self.heartbeat,self.owner)
                except FileNotFoundError: data=None; code=None if grace else 'heartbeat_missing'
                except Exception: data=None; code='heartbeat_invalid'
                if data is not None:
                    if data['published_at']>now+2 or (state['last_wall'] is not None and now<state['last_wall']-2): code='clock_invalid'
                    elif data['pid']!=job['pid']: code=None if grace else 'publisher_mismatch'
                    elif now-data['published_at']>self.stale: code=None if grace else 'heartbeat_stale'
                    elif data['phase'] in ('blocked','failed'): code=data['reason'] if data['reason'] in CODES else 'service_failed'
                    elif data['phase']=='paused': code='service_paused'
                    elif data['phase']=='ready':
                        if data['validator_count']!=2 or not data['ingress_ready']: code='service_not_ready'
                        elif data['sampled_at'] is None or data['finality_progress_at'] is None or now-data['sampled_at']>self.stale or now-data['finality_progress_at']>self.finality: code='finality_stalled'
                        else: healthy=True; state['ready_pid']=job['pid']
                    elif now-min(data['phase_since'],state['loaded_since'])>self.startup: code='startup_stalled'
        # A process restart alone is never a recovery. Only ready or an explicit
        # unloaded launchd job can resolve an existing incident.
        incident=state['incident']
        if code and (incident is None or incident['code']!=code):
            event=self.journal.event('incident',code,now); state['incident']={'code':code,'id':event['id']}
        elif (healthy or paused) and incident is not None:
            self.journal.event('operator_paused' if paused else 'recovered',incident['code'],now); state['incident']=None
        state['last_wall']=now; self.journal.save()
        return {'state':'paused' if paused else 'healthy' if healthy else 'unhealthy' if code else 'starting',
                'code':code,'open_incident':state['incident']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('check','watch'))
    parser.add_argument('--journal',type=Path,required=True)
    args=parser.parse_args()
    # Fixed root-owned installation; this CLI never accepts arbitrary launchd
    # targets, RPC credentials, shell commands, or a fake probe option.
    from service_account import verify_install, INSTALL
    config=verify_install(); journal=Journal(args.journal)
    stopping=threading.Event()
    for number in (signal.SIGTERM,signal.SIGINT):signal.signal(number,lambda *_:stopping.set())
    if hasattr(signal,'pthread_sigmask'):signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    try:
        monitor=Monitor(journal,INSTALL/'health/heartbeat.json',config['uid'])
        journal.deliver(sys.stdout)
        while not stopping.is_set():
            result=monitor.sample(); journal.deliver(sys.stdout)
            if args.action=='check': print(json.dumps(result,sort_keys=True)); return
            stopping.wait(2)
    finally: journal.close()


if __name__=='__main__': main()
