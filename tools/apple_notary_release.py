#!/usr/bin/env python3
"""Explicit Developer ID notarization with durable, artifact-bound recovery.

No credential setup, automatic submission retry, publisher signing or distribution.
The CLI is live-only; injected test runners create permanently fixture evidence.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import uuid

from wallet_release import atomic,create,decode,directory,encode,fsync_dir,hex64,parents,read,sha

FORMAT='zolana-apple-notary-release-v1'
PHASES={'ready','submission_unknown','in_progress','awaiting_log','accepted','rejected','stapling','staple_failed','stapled','assessment_failed','assessed'}
STATUSES={None,'In Progress','Accepted','Invalid','Rejected'}


def identifier(value):
    if not isinstance(value,str):raise ValueError('explicit submission UUID required')
    try:result=str(uuid.UUID(value))
    except (ValueError,AttributeError):raise ValueError('invalid submission UUID') from None
    if result!=value.lower():raise ValueError('canonical submission UUID required')
    return result


def profile(value):
    if not isinstance(value,str) or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ -]{0,127}',value) is None:
        raise ValueError('explicit reviewed keychain profile name required; never pass credentials')
    return value


def bounded_json(raw,limit=1024*1024):
    if not isinstance(raw,bytes) or not 1<=len(raw)<=limit:raise ValueError('bounded Apple JSON response required')
    value=decode(raw)
    if not isinstance(value,dict):raise ValueError('Apple response must be an object')
    return value


def apple_command(argv,timeout=60):
    """Only fixed notary/stapler/assessment commands, no shell or credential values."""
    if (not isinstance(argv,list) or any(not isinstance(v,str) or '\0' in v for v in argv) or
            type(timeout) is not int or not 1<=timeout<=120):raise ValueError('explicit bounded Apple argument vector required')
    valid=False
    if argv[:2]==['/usr/bin/xcrun','notarytool'] and len(argv)==9:
        action=argv[2]
        valid=action in {'submit','info','log'} and argv[4:6]==['--keychain-profile',profile(argv[5])] and argv[6:]==['--output-format','json','--no-progress']
        if action=='submit':valid=valid and str(Path(argv[3]).absolute())==argv[3] and Path(argv[3]).suffix=='.dmg'
        elif action in {'info','log'}:valid=valid and identifier(argv[3])==argv[3]
    elif argv[:2]==['/usr/bin/xcrun','stapler'] and len(argv)==4:
        valid=argv[2] in {'staple','validate'} and Path(argv[3]).is_absolute() and Path(argv[3]).suffix=='.dmg'
    elif argv[:8]==['/usr/sbin/spctl','--assess','--type','open','--context','context:primary-signature','--verbose=4','--ignore-cache'] and len(argv)==9:
        valid=Path(argv[-1]).is_absolute() and Path(argv[-1]).suffix=='.dmg'
    if not valid:raise ValueError('unreviewed Apple notarization command')
    return subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=timeout,
                          env={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'})


def prepared(root,pin):
    if not hex64(pin):raise ValueError('independently reviewed preparation receipt SHA required')
    from wallet_apple_release import verify_prepared
    image,receipt=verify_prepared(Path(root),pin)
    if (receipt.get('format')!='zolana-apple-developer-id-preparation-v1' or receipt.get('mode')!='developer-id' or
            receipt.get('developer_id_used') is not True or receipt.get('notarized') is not False or
            receipt.get('release_ready') is not False or not isinstance(receipt.get('team_identifier'),str) or
            not re.fullmatch('[A-Z0-9]{10}',receipt['team_identifier']) or not isinstance(receipt.get('certificate_sha1'),str) or
            not re.fullmatch('[A-Fa-f0-9]{40}',receipt['certificate_sha1']) or
            not hex64(receipt.get('image_sha256')) or receipt.get('image_bytes')!=image.stat().st_size or
            sha(read(image,64*1024*1024))!=receipt['image_sha256']):raise ValueError('verified Developer ID artifact required; rehearsal cannot enter notarization')
    return image,receipt


class NotaryRelease:
    def __init__(self,root,runner=None,fixture_prepared=None):
        self.root=Path(root).absolute();directory(self.root);parents(self.root);self.failed=False;self.fd=None
        self.runner=runner or apple_command;self.fixture=runner is not None
        if self.fixture!=(fixture_prepared is not None):raise ValueError('test runner and test preparation must be paired')
        self.fixture_prepared=fixture_prepared
        self.fd=os.open(self.root/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            meta=os.fstat(self.fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or meta.st_mode&0o077:raise ValueError('private notary lock required')
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.config=decode(read(self.root/'initialized',16384,True));self.state=decode(read(self.root/'state.json',16384,True))
            self.validate();self.original()
        except BaseException:self.close();raise

    def validate(self):
        c=self.config;s=self.state
        keys={'format','prepared_root','preparation_sha256','image_sha256','image_bytes','team_identifier','certificate_sha1','image_identifier','keychain_profile','evidence_kind'}
        if (not isinstance(c,dict) or set(c)!=keys or c['format']!=FORMAT or not Path(c['prepared_root']).is_absolute() or
                any(not hex64(c[k]) for k in ('preparation_sha256','image_sha256')) or type(c['image_bytes']) is not int or not 0<c['image_bytes']<=64*1024*1024 or
                re.fullmatch('[A-Z0-9]{10}',c['team_identifier']) is None or re.fullmatch('[a-fA-F0-9]{40}',c['certificate_sha1']) is None or
                not isinstance(c['image_identifier'],str) or not 1<=len(c['image_identifier'])<=255 or
                c['evidence_kind']!=('local-fixture' if self.fixture else 'live-command')):raise ValueError('original explicit notary configuration required')
        profile(c['keychain_profile'])
        if (not isinstance(s,dict) or set(s)!={'format','binding_sha256','phase','submission_id','last_status','log_sha256','staple_attempt','stapled_sha256','notarized','ticket_validated','gatekeeper_local','release_ready','network_commands_executed'} or
                s['format']!=FORMAT or s['binding_sha256']!=sha(encode(c)) or s['phase'] not in PHASES or s['last_status'] not in STATUSES or s['release_ready'] is not False or
                any(type(s[k]) is not bool for k in ('notarized','ticket_validated','gatekeeper_local','network_commands_executed'))):raise ValueError('invalid artifact-bound notary state')
        if s['submission_id'] is not None:identifier(s['submission_id'])
        if (s['phase'] in {'ready','submission_unknown'})!=(s['submission_id'] is None):raise ValueError('invalid submission recovery phase')
        if s['log_sha256'] is not None and not hex64(s['log_sha256']):raise ValueError('invalid Apple log digest')
        if s['staple_attempt'] is not None and re.fullmatch('[a-f0-9]{32}',s['staple_attempt']) is None:raise ValueError('invalid staple attempt')
        if s['stapled_sha256'] is not None and not hex64(s['stapled_sha256']):raise ValueError('invalid final image digest')
        if s['phase'] in {'ready','submission_unknown'} and any(s[k] is not None for k in ('last_status','log_sha256','staple_attempt','stapled_sha256')):raise ValueError('pre-submission state cannot carry completed evidence')
        if s['phase']=='in_progress' and (s['last_status']!='In Progress' or s['log_sha256'] is not None):raise ValueError('original in-progress status required')
        if s['phase']=='awaiting_log' and (s['last_status'] not in {'Accepted','Invalid','Rejected'} or s['log_sha256'] is not None):raise ValueError('terminal info awaiting exact log required')
        attempted=s['phase'] in {'stapling','staple_failed','stapled','assessment_failed','assessed'}
        if attempted!=(s['staple_attempt'] is not None):raise ValueError('staple attempt differs from recorded phase')
        approved=s['phase'] in {'accepted','stapling','staple_failed','stapled','assessment_failed','assessed'}
        if approved and (s['last_status']!='Accepted' or s['log_sha256'] is None):raise ValueError('accepted log required before ticket operations')
        if s['phase']=='rejected' and (s['last_status'] not in {'Invalid','Rejected'} or s['log_sha256'] is None):raise ValueError('actual rejection log required')
        if s['notarized']!=(approved and not self.fixture):raise ValueError('fixture or unverified status cannot claim notarization')
        ticket=s['phase'] in {'stapled','assessment_failed','assessed'}
        if ticket!=(s['stapled_sha256'] is not None) or s['ticket_validated']!=(ticket and not self.fixture):raise ValueError('ticket validation and image digest required')
        if s['gatekeeper_local']!=(s['phase']=='assessed' and not self.fixture):raise ValueError('local assessment evidence differs')
        if self.fixture and s['network_commands_executed']:raise ValueError('fixtures cannot claim Apple commands executed')
        if s['log_sha256'] is not None:
            raw=read(self.root/'logs'/(s['log_sha256']+'.json'),1024*1024,True)
            if sha(raw)!=s['log_sha256']:raise ValueError('recorded Apple log bytes changed')
            self.checked_log(raw,s['submission_id'],s['last_status'])

    def original(self):
        if self.failed or self.fd is None:raise ValueError('reopen original notary state after uncertain storage')
        if self.fixture:
            source,receipt=self.fixture_prepared()
        else:source,receipt=prepared(Path(self.config['prepared_root']),self.config['preparation_sha256'])
        if (receipt['image_sha256']!=self.config['image_sha256'] or receipt['image_bytes']!=self.config['image_bytes'] or receipt['team_identifier']!=self.config['team_identifier'] or
                receipt['certificate_sha1']!=self.config['certificate_sha1'] or receipt['image_identifier']!=self.config['image_identifier'] or sha(read(source,64*1024*1024))!=self.config['image_sha256'] or
                sha(read(self.root/'submitted.dmg',64*1024*1024,True))!=self.config['image_sha256']):raise ValueError('prepared or frozen submission artifact changed')
        return source,receipt

    def save(self):
        self.validate()
        try:atomic(self.root/'state.json',self.state)
        except BaseException:self.failed=True;raise

    def invoke(self,argv,timeout=60):
        self.original()
        if not self.fixture and not self.state['network_commands_executed']:
            self.state['network_commands_executed']=True;self.save()
        result=self.runner(argv,timeout)
        self.original()
        if result.returncode:raise ValueError('Apple operation failed; retain original artifact, submission and private diagnostics')
        if len(result.stdout)>1024*1024 or len(result.stderr)>1024*1024:raise ValueError('Apple response exceeds private evidence limit')
        return result.stdout

    def notary(self,action,target):
        return self.invoke(['/usr/bin/xcrun','notarytool',action,str(target),'--keychain-profile',self.config['keychain_profile'],'--output-format','json','--no-progress'])

    def checked_log(self,raw,submission_id,status,require_digest=False):
        value=bounded_json(raw)
        if identifier(value.get('jobId'))!=submission_id or value.get('status')!=status or value.get('archiveFilename')!='submitted.dmg':raise ValueError('Apple log refers to another submission or file')
        digest=value.get('sha256')
        if (require_digest and digest is None) or (digest is not None and (not hex64(digest) or digest!=self.config['image_sha256'])):raise ValueError('Apple log cannot bind the exact submitted SHA256; keep unknown submission')
        return value

    def remember_log(self,raw,submission_id,status,require_digest=False):
        self.checked_log(raw,submission_id,status,require_digest);pin=sha(raw);path=self.root/'logs'/(pin+'.json')
        if path.exists():
            if read(path,1024*1024,True)!=raw:raise ValueError('immutable Apple log changed')
        else:create(path,raw);fsync_dir(path.parent)
        return pin

    def submit(self,hook=None):
        self.original()
        if self.state['phase']!='ready':raise ValueError('original submission already intended; reconcile UUID, never automatically resubmit')
        self.state['phase']='submission_unknown';self.save()
        if hook:hook('submission_intent')
        raw=self.notary('submit',self.root/'submitted.dmg');value=bounded_json(raw,65536);submission_id=identifier(value.get('id'))
        create(self.root/'submit-result.json',raw);fsync_dir(self.root)
        if hook:hook('submission_result')
        self.state.update(submission_id=submission_id,phase='in_progress',last_status='In Progress');self.save()
        return self.summary()

    def check(self):
        self.original()
        if self.state['phase'] not in {'in_progress','awaiting_log'}:raise ValueError('only the original active submission may be checked')
        ident=self.state['submission_id'];info=bounded_json(self.notary('info',ident),65536)
        if identifier(info.get('id'))!=ident or info.get('status') not in {'In Progress','Accepted','Invalid','Rejected'}:raise ValueError('Apple info identity or status differs')
        status=info['status']
        if self.state['phase']=='awaiting_log' and status!=self.state['last_status']:raise ValueError('terminal notarization result regressed')
        if status=='In Progress':return self.summary()
        self.state.update(phase='awaiting_log',last_status=status);self.save()
        raw=self.notary('log',ident);pin=self.remember_log(raw,ident,status)
        approved=status=='Accepted';self.state.update(log_sha256=pin,phase='accepted' if approved else 'rejected',notarized=approved and not self.fixture);self.save()
        return self.summary()

    def reconcile(self,ident):
        self.original();ident=identifier(ident)
        if self.state['phase']!='submission_unknown':raise ValueError('only original unknown submission permits explicit reconciliation')
        value=bounded_json(self.notary('info',ident),65536)
        if identifier(value.get('id'))!=ident or value.get('status') not in {'Accepted','Invalid','Rejected'}:raise ValueError('unknown submission requires completed Apple log with exact SHA256; do not resubmit')
        status=value['status'];raw=self.notary('log',ident);pin=self.remember_log(raw,ident,status,True)
        approved=status=='Accepted';self.state.update(submission_id=ident,last_status=status,log_sha256=pin,phase='accepted' if approved else 'rejected',notarized=approved and not self.fixture);self.save()
        return self.summary()

    def verify_image(self,path):
        if self.fixture:return
        from wallet_apple_release import signature
        signature(path,self.config['image_identifier'],self.config['team_identifier'],runtime=False,certificate=self.config['certificate_sha1'])

    def finish_staple(self,path):
        self.invoke(['/usr/bin/xcrun','stapler','validate',str(path)])
        self.verify_image(path)
        pin=sha(read(path,64*1024*1024,True));self.state.update(phase='stapled',stapled_sha256=pin,ticket_validated=not self.fixture);self.save()

    def staple(self,hook=None):
        self.original()
        if self.state['phase']=='stapling':
            path=self.root/'attempts'/self.state['staple_attempt']/'Zolana-Wallet.dmg'
            try:self.finish_staple(path)
            except (ValueError,OSError,subprocess.SubprocessError):
                self.state.update(phase='staple_failed');self.save();raise ValueError('interrupted staple retained; explicit retry uses a new copy') from None
            return self.summary()
        if self.state['phase'] not in {'accepted','staple_failed'}:raise ValueError('accepted original submission required before staple')
        attempt=secrets.token_hex(16);work=self.root/'attempts'/attempt;work.mkdir(mode=0o700);path=work/'Zolana-Wallet.dmg';create(path,read(self.root/'submitted.dmg',64*1024*1024,True));fsync_dir(work)
        self.state.update(phase='stapling',staple_attempt=attempt);self.save()
        if hook:hook('staple_intent')
        try:
            self.invoke(['/usr/bin/xcrun','stapler','staple',str(path)],120)
            if hook:hook('staple_result')
            self.finish_staple(path)
        except (ValueError,OSError,subprocess.SubprocessError):
            self.state.update(phase='staple_failed');self.save();raise
        return self.summary()

    def assess(self):
        self.original()
        if self.state['phase'] not in {'stapled','assessment_failed','assessed'}:raise ValueError('validated original stapled image required')
        path=self.root/'attempts'/self.state['staple_attempt']/'Zolana-Wallet.dmg'
        if sha(read(path,64*1024*1024,True))!=self.state['stapled_sha256']:raise ValueError('stapled image changed')
        try:
            self.invoke(['/usr/bin/xcrun','stapler','validate',str(path)]);self.verify_image(path)
            self.invoke(['/usr/sbin/spctl','--assess','--type','open','--context','context:primary-signature','--verbose=4','--ignore-cache',str(path)])
        except (ValueError,OSError,subprocess.SubprocessError):
            self.state.update(phase='assessment_failed',gatekeeper_local=False);self.save();raise
        self.state.update(phase='assessed',gatekeeper_local=not self.fixture);self.save();return self.summary()

    def summary(self):
        self.validate()
        return {**self.state,'evidence_kind':self.config['evidence_kind'],'external_device_tested':False,'publisher_final_digest_signing_required':True}

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


def initialize(root,prepared_root,preparation_sha256,keychain_profile,runner=None,fixture_prepared=None):
    root=Path(root).absolute();parents(root);profile(keychain_profile)
    if root.exists():raise ValueError('new notary workspace required; preserve original state')
    fixture=runner is not None
    if fixture!=(fixture_prepared is not None):raise ValueError('test input and runner must be paired')
    source,receipt=fixture_prepared() if fixture else prepared(prepared_root,preparation_sha256)
    if not hex64(preparation_sha256):raise ValueError('reviewed preparation receipt pin required')
    config=dict(format=FORMAT,prepared_root=str(Path(prepared_root).absolute()),preparation_sha256=preparation_sha256,image_sha256=receipt['image_sha256'],image_bytes=receipt['image_bytes'],team_identifier=receipt['team_identifier'],certificate_sha1=receipt['certificate_sha1'],image_identifier=receipt['image_identifier'],keychain_profile=keychain_profile,evidence_kind='local-fixture' if fixture else 'live-command')
    root.mkdir(mode=0o700);create(root/'submitted.dmg',read(source,64*1024*1024));(root/'logs').mkdir(mode=0o700);(root/'attempts').mkdir(mode=0o700)
    state=dict(format=FORMAT,binding_sha256=sha(encode(config)),phase='ready',submission_id=None,last_status=None,log_sha256=None,staple_attempt=None,stapled_sha256=None,notarized=False,ticket_validated=False,gatekeeper_local=False,release_ready=False,network_commands_executed=False)
    atomic(root/'state.json',state);create(root/'initialized',encode(config));fsync_dir(root)
    value=NotaryRelease(root,runner,fixture_prepared)
    try:return value.summary()
    finally:value.close()


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['init','status','submit','check','reconcile','staple','assess']);p.add_argument('--root',required=True,type=Path);p.add_argument('--prepared-root',type=Path);p.add_argument('--preparation-sha256');p.add_argument('--keychain-profile');p.add_argument('--submission-id');p.add_argument('--execute',action='store_true',help='explicitly execute this reviewed Apple operation; may contact Apple or use the selected keychain item')
    a=p.parse_args()
    if a.action=='init':
        if a.prepared_root is None or a.preparation_sha256 is None or a.keychain_profile is None:p.error('init requires explicit preparation root, receipt pin and keychain profile')
        print(json.dumps(initialize(a.root,a.prepared_root,a.preparation_sha256,a.keychain_profile),sort_keys=True));return
    if a.action!='status' and not a.execute:p.error('review exact artifact/profile then supply --execute for this single Apple operation')
    n=NotaryRelease(a.root)
    try:
        result=n.summary() if a.action=='status' else n.reconcile(a.submission_id) if a.action=='reconcile' else getattr(n,a.action)()
        print(json.dumps(result,sort_keys=True))
    finally:n.close()


if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.SubprocessError):
        print('Apple notarization operation failed; retain original artifact and workspace; never blindly resubmit.',file=__import__('sys').stderr);raise SystemExit(1)
