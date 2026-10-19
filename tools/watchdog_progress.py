"""Sanitized completed-cycle progress, published by the main loop only."""
import os
from pathlib import Path
import secrets
import time

from monitor_transport import HEX32, HEX64, decode, private
from operator_health import atomic, directory, timestamp

KEYS={'format','deployment','role','instance','pid','sequence','started_at','completed_at','phase',
      'pending','oldest_pending_at','failure','integration_sha256'}


def validate(value,deployment,role):
    if (not isinstance(value,dict) or set(value)!=KEYS or value['format']!='native-watchdog-progress-v1' or
            value['deployment']!=deployment or value['role']!=role or role not in ('monitor','pager') or
            not isinstance(value['instance'],str) or HEX32.fullmatch(value['instance']) is None or
            type(value['pid']) is not int or value['pid']<=0 or type(value['sequence']) is not int or value['sequence']<1 or
            not timestamp(value['started_at']) or (value['completed_at'] is not None and (not timestamp(value['completed_at']) or value['completed_at']<value['started_at'])) or
            value['phase'] not in ('starting','running','stopped','failed') or type(value['pending']) is not int or not 0<=value['pending']<=1024 or
            (value['oldest_pending_at'] is not None and not timestamp(value['oldest_pending_at'])) or
            (value['pending']==0)!=(value['oldest_pending_at'] is None) or
            value['failure'] not in (None,'delivery_retrying','delivery_blocked','cycle_failed')):
        raise ValueError('invalid completed-cycle status')
    integration=value['integration_sha256']
    if (role=='monitor' and integration is not None) or (role=='pager' and (not isinstance(integration,str) or HEX64.fullmatch(integration) is None)):
        raise ValueError('invalid progress integration identity')
    if value['phase']=='running' and value['completed_at'] is None:raise ValueError('running without a completed cycle')
    return value


def read(path,owner,deployment,role):
    if owner!=os.getuid():raise ValueError('progress agent requires the publishing operator identity')
    directory(Path(path).parent,owner,0o700)
    return validate(decode(private(path,4096)),deployment,role)


class Progress:
    def __init__(self,root,deployment,role,integration_sha256=None,clock=time.time):
        self.root=Path(root);self.path=self.root/'watchdog.json';self.clock=clock
        directory(self.root,os.getuid(),0o700)
        self.value=dict(format='native-watchdog-progress-v1',deployment=deployment,role=role,
            instance=secrets.token_hex(16),pid=os.getpid(),sequence=1,started_at=clock(),completed_at=None,
            phase='starting',pending=0,oldest_pending_at=None,failure=None,integration_sha256=integration_sha256)
        self.write()

    def write(self):
        validate(self.value,self.value['deployment'],self.value['role'])
        atomic(self.path,self.value,0o600)

    def complete(self,pending=0,oldest=None,failure=None):
        self.value.update(sequence=self.value['sequence']+1,completed_at=self.clock(),phase='running',pending=pending,oldest_pending_at=oldest,failure=failure)
        self.write()

    def close(self,failed=False):
        self.value.update(sequence=self.value['sequence']+1,phase='failed' if failed else 'stopped',failure='cycle_failed' if failed else self.value['failure'])
        self.write()
