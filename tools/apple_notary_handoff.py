"""Durable local-fixture model for the disabled notarization handoff.

No Apple/credential/network commands exist here. Fixture completion is never
reported as notarization, Gatekeeper approval or a release-ready artifact.
"""
import fcntl
import os
from pathlib import Path
import stat
import uuid

from wallet_release import atomic,create,decode,directory,encode,fsync_dir,hex64,read


def submission(value):
    if not isinstance(value,str) or str(uuid.UUID(value))!=value:raise ValueError('invalid submission UUID')
    return value


class Handoff:
    def __init__(self,root,artifact_sha256):
        if not hex64(artifact_sha256):raise ValueError('invalid fixture artifact digest')
        self.root=Path(root).absolute();self.failed=False;self.fd=None
        if not self.root.exists():self.root.mkdir(mode=0o700)
        directory(self.root)
        self.fd=os.open(self.root/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            meta=os.fstat(self.fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077:raise ValueError('unsafe notary fixture lock')
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            marker={'format':'native-notary-fixture-marker-v1','artifact_sha256':artifact_sha256,'evidence_kind':'local-fixture'}
            if (self.root/'initialized').exists():
                if decode(read(self.root/'initialized',4096,True))!=marker:raise ValueError('notary fixture artifact changed')
                self.state=decode(read(self.root/'state.json',8192,True));self.validate()
                if self.state['artifact_sha256']!=artifact_sha256:raise ValueError('notary fixture digest changed')
            else:
                if any(p.name!='lock' for p in self.root.iterdir()):raise ValueError('partial notary fixture retained; do not initialize again')
                self.state=dict(format='native-notary-fixture-v1',artifact_sha256=artifact_sha256,evidence_kind='local-fixture',phase='ready',submission_id=None,last_status=None,
                    stapled_sha256=None,notarized=False,release_ready=False,network_commands_executed=False)
                self.save();create(self.root/'initialized',encode(marker));fsync_dir(self.root)
        except BaseException:self.close();raise
    def validate(self):
        s=self.state
        if (not isinstance(s,dict) or set(s)!={'format','artifact_sha256','evidence_kind','phase','submission_id','last_status','stapled_sha256','notarized','release_ready','network_commands_executed'} or
                s['format']!='native-notary-fixture-v1' or not hex64(s['artifact_sha256']) or s['evidence_kind']!='local-fixture' or s['phase'] not in ('ready','submission_unknown','in_progress','accepted','rejected','staple_failed','stapled','assessment_failed','assessed') or
                s['last_status'] not in (None,'In Progress','Accepted','Invalid','Rejected') or any(s[k] is not False for k in ('notarized','release_ready','network_commands_executed'))):raise ValueError('invalid notary fixture state')
        if s['submission_id'] is not None:submission(s['submission_id'])
        if (s['phase'] in ('ready','submission_unknown'))!=(s['submission_id'] is None):raise ValueError('invalid notary fixture submission phase')
        if s['stapled_sha256'] is not None and not hex64(s['stapled_sha256']):raise ValueError('invalid stapled fixture digest')
        if (s['phase'] in ('stapled','assessment_failed','assessed'))!=(s['stapled_sha256'] is not None):raise ValueError('invalid fixture ticket phase')
        if s['phase'] in ('accepted','staple_failed','stapled','assessment_failed','assessed') and s['last_status']!='Accepted':raise ValueError('ticket without accepted fixture result')
        if s['phase']=='rejected' and s['last_status'] not in ('Invalid','Rejected'):raise ValueError('rejection without rejected fixture result')
        if s['phase'] in ('ready','submission_unknown') and s['last_status'] is not None:raise ValueError('unsubmitted fixture has a result')
        if s['phase']=='in_progress' and s['last_status']!='In Progress':raise ValueError('inconsistent progress fixture result')
    def ready(self):
        if self.failed or self.fd is None:raise ValueError('reopen original notary fixture after uncertain storage')
    def save(self):
        self.ready();self.validate()
        try:atomic(self.root/'state.json',self.state)
        except BaseException:self.failed=True;raise
    def begin_submission(self):
        self.ready()
        if self.state['phase']!='ready':raise ValueError('submission already planned; explicitly reconcile its UUID instead of resubmitting')
        self.state['phase']='submission_unknown';self.save()
        return {'execution_enabled':False,'phase':'submission_unknown'}
    def attach_submission(self,identifier,artifact_sha256):
        self.ready();submission(identifier)
        if artifact_sha256!=self.state['artifact_sha256']:raise ValueError('submission refers to another artifact')
        if self.state['submission_id']==identifier:return
        if self.state['phase']!='submission_unknown' or self.state['submission_id'] is not None:raise ValueError('original submission identity must be preserved')
        self.state.update(submission_id=identifier,phase='in_progress',last_status='In Progress');self.save()
    def result(self,identifier,artifact_sha256,status):
        self.ready()
        if identifier!=self.state['submission_id'] or artifact_sha256!=self.state['artifact_sha256'] or status not in ('In Progress','Accepted','Invalid','Rejected'):raise ValueError('invalid or mismatched notary fixture result')
        if status==self.state['last_status']:return
        if self.state['phase']!='in_progress':raise ValueError('notary fixture result cannot regress or silently retry rejection')
        self.state.update(last_status=status,phase='in_progress' if status=='In Progress' else 'accepted' if status=='Accepted' else 'rejected');self.save()
    def staple(self,identifier,artifact_sha256,ok,stapled_sha256=None):
        self.ready()
        if identifier!=self.state['submission_id'] or artifact_sha256!=self.state['artifact_sha256'] or self.state['phase'] not in ('accepted','staple_failed') or type(ok) is not bool or (ok and not hex64(stapled_sha256)) or (not ok and stapled_sha256 is not None):raise ValueError('invalid ticket fixture result')
        self.state.update(phase='stapled' if ok else 'staple_failed',stapled_sha256=stapled_sha256);self.save()
    def assess(self,stapled_sha256,ok):
        self.ready()
        if self.state['phase'] not in ('stapled','assessment_failed','assessed') or stapled_sha256!=self.state['stapled_sha256'] or type(ok) is not bool:raise ValueError('assessment refers to another fixture artifact')
        self.state['phase']='assessed' if ok else 'assessment_failed';self.save()
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
