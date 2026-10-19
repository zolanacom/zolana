#!/usr/bin/env python3
"""All ten original pilot grants and a bounded private payment ring; no funding/reset."""
import argparse
from concurrent.futures import ThreadPoolExecutor,wait,FIRST_COMPLETED
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pilot_cohort as cohort
import pilot_funding as funding
import pilot_runtime as runtime
from pilot_runtime_localnet import PilotHost
from localnet import PROJECT,load,rpc
from fault_localnet import durable
from wallet_release import atomic,create,decode,encode,fsync_dir,read,sha
from wallet_ui import WalletApp

NAMES=tuple(f'tester-{i:02}' for i in range(1,11))
AMOUNT=50_000
EXPECTED={name:950_000 if i==0 else 1_050_000 if i==1 else 1_000_000 for i,name in enumerate(NAMES)}


def burst(folder,jobs,workers,task,pulse=lambda:None,idempotent=False):
    """Persist intent before side effects; never repeat an uncertain original job."""
    if (type(workers) is not int or not 1<=workers<=10 or len({j['id'] for j in jobs})!=len(jobs) or
            any(j['id'] not in NAMES for j in jobs)):raise ValueError('invalid bounded burst')
    folder=Path(folder);folder.mkdir(mode=0o700,exist_ok=True);cohort.directory(folder)
    def one(job):
        name=job['id']
        if name not in NAMES:raise ValueError('unknown cohort job')
        marker,done=folder/(name+'-started.json'),folder/(name+'-done.json')
        if os.path.lexists(done):
            value=decode(read(done,16384,secret=True))
            if value['job']!=job or decode(read(marker,16384,secret=True))!=job:raise ValueError('original burst identity changed')
            return value
        if os.path.lexists(marker):
            if not idempotent:raise ValueError('uncertain original job; preserve journals and resolve before retry, never repeat automatically')
            if decode(read(marker,16384,secret=True))!=job:raise ValueError('original idempotent request changed')
        else:create(marker,encode(job));fsync_dir(folder)
        began=time.monotonic()
        result=task(job)
        value=dict(job=job,result=result,started_monotonic=began,finished_monotonic=time.monotonic())
        create(done,encode(value));fsync_dir(folder);return value
    results={};errors=[]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending={pool.submit(one,j):j['id'] for j in jobs}
        while pending:
            pulse();ready,_=wait(pending,timeout=.1,return_when=FIRST_COMPLETED)
            for future in ready:
                name=pending.pop(future)
                try:results[name]=future.result()
                except BaseException as error:errors.append((name,type(error).__name__,str(error)))
    pulse()
    if errors:raise ValueError('burst preserved unfinished originals: '+str(errors))
    return results


def overlap(results):
    events=[]
    for value in results.values():events.extend(((value['started_monotonic'],1),(value['finished_monotonic'],-1)))
    active=peak=0
    for _,change in sorted(events):active+=change;peak=max(active,peak)
    return peak


class CohortRun(PilotHost):
    def event(self,kind,**fields):
        self.result['events'].append(dict(kind=kind,**fields));atomic(self.evidence/'result.json',self.result);print(kind,flush=True)
    def start_host(self):
        self.host_generation+=1
        # Observe native worker failures without changing any pinned runtime
        # source, limits, subprocess results or lifecycle decisions.
        script='''import json,subprocess,sys,time
from pathlib import Path
import pilot_runtime as runtime
from wallet_release import atomic
original=subprocess.Popen
def observed(*args,**kwargs):
 child=original(*args,**kwargs)
 command=args[0] if args else kwargs.get('args',[])
 if isinstance(command,list) and len(command)>1 and Path(command[0]).name=='native-faucet' and command[1]=='tick':
  communicate=child.communicate
  def capture(*a,**k):
   result=communicate(*a,**k)
   if child.returncode:atomic(Path(sys.argv[3]),dict(returncode=child.returncode,stderr=(result[1] or '')[-4096:],recorded_at=time.time()))
   return result
  child.communicate=capture
 return child
subprocess.Popen=observed
runtime.supervise(Path(sys.argv[1]),sys.argv[2],1800)
'''
        with (self.evidence/f'host-{self.host_generation}.log').open('xb') as log:
            self.host=subprocess.Popen([sys.executable,'-B','-c',script,str(self.root),self.binding,str(self.evidence/f'grant-worker-{self.host_generation}-error.json')],
                cwd=PROJECT/'tools',stdout=log,stderr=log,env=self.env,start_new_session=True)
        end=time.monotonic()+180
        while time.monotonic()<end:
            if self.host.poll() is not None:raise RuntimeError('owned cohort host exited; inspect original runtime diagnostics')
            status=self.host_status()
            if status['pid']==self.host.pid and status['phase']=='ready':
                if status['process_group']!=self.host.pid or any(os.getpgid(pid)!=self.host.pid for pid in status['validators']):raise ValueError('validator escaped owned process group')
                self.wait_for(self.ready_history,timeout=30);return status
            time.sleep(.15)
        raise RuntimeError('bounded cohort host startup deadline')
    def health(self):
        if self.host is None or self.host.poll() is not None:raise RuntimeError('cohort host failed; preserve original recovery state')
    def claim_progress(self):
        ledger=cohort.private_json(self.faucet_root/'claims.json')
        return {c['fee_address']:(self.claim_id(c),cohort.private_json(self.faucet_root/(self.claim_id(c)+'.json'))) for c in ledger['claims']}
    def setup(self,baseline):
        self.binding=baseline['binding_sha256'];config,_,__=runtime.static(self.root,self.binding)
        self.cr=Path(config['cohort_root']);self.digest=config['plan_sha256'];self.password_file=Path(config['password_file'])
        self.password=read(self.password_file,1024,secret=True).decode();self.faucet_root=self.cr/'faucet';self.source=self.faucet_root/'wallet.enc.json'
        self.profile=self.cr/'tester-profile.json';self.prepared=cohort.private_json(self.cr/'prepared.json')
        value=cohort.checked(self.cr,self.digest)
        if value['cohort_size']!=10 or len(cohort.issuance(self.cr,value)['slots'])!=10:raise ValueError('original ten-slot cohort required')
        self.activation=read(self.root/runtime.FILES[2],4096,secret=True)
        self.preserved={str(p):sha(read(p,16384,secret=True)) for p in self.root.glob('sponsor*.disabled')}
        self.preserved.update({str(self.cr/n):sha(read(self.cr/n,32768,secret=True)) for n in ('provision-complete.json','treasury-signed.json','funding-intent.json')})
        for i,name in enumerate(NAMES):
            directory=(PROJECT/'.local/pilot-install-046-live-a'/('alice-client' if i==0 else 'bob-client')) if i<2 else self.evidence/(name+'-client')
            self.clients[name]=WalletApp.from_profile(self.profile,directory)
            if self.clients[name].wallet.exists():self.keys[name]=self.clients[name].cli('address',self.password)
            else:self.keys[name]=self.user(name,'create');self.user(name,'ack-backup')
        if len({k['fee_address'] for k in self.keys.values()})!=10 or len({k['address'] for k in self.keys.values()})!=10:raise ValueError('ten distinct seeded identities required')
        self.original_wallets={str(p):sha(read(p,16384,secret=True)) for a in self.clients.values() for p in (a.wallet,a.backup)}
        # Native balance also updates a scan cache under the wallet lock. Never
        # race it against the automatic worker's original source wallet path.
        self.source_audit=self.evidence/'source-audit.enc.json';raw=read(self.source,16384,secret=True)
        if self.source_audit.exists():
            if read(self.source_audit,16384,secret=True)!=raw:raise ValueError('original encrypted fixture audit seed differs')
        else:create(self.source_audit,raw);fsync_dir(self.evidence)
        self.event('ten_distinct_original_seeded_wallets_ready_without_refunding')
    def audit(self,expected,label):
        # Operator-only accounting is independent of each tester's invited RPC.
        # Bounded parallel scans use actual original wallets/capability on each peer.
        answers={}
        for peer in (0,1):
            def balance(name):
                value=self.command([cohort.WALLET,'balance','--network',self.root/'network.json','--wallet',self.clients[name].wallet,
                    '--password-file',self.password_file,'--rpc',f'http://127.0.0.1:{18899+peer*1000}','--rpc-access-file',self.root/'rpc-access.key'])
                return name,value['balance']
            with ThreadPoolExecutor(max_workers=2) as pool:actual=dict(pool.map(balance,NAMES))
            if actual!=expected:raise ValueError('cohort private balances differ on validator '+str(peer))
            answers[str(peer)]=actual
        atomic(self.evidence/(label+'-balances.json'),answers);return answers
    def capture_pending(self):
        self.health()
        for name,app in self.clients.items():
            source=Path(str(app.wallet)+'.pending.json');dest=self.evidence/'payments'/(name+'-pending.json')
            if source.exists() and not dest.exists():
                try:raw=read(source,16384,secret=True)
                except FileNotFoundError:continue
                create(dest,raw);fsync_dir(dest.parent)
    def run(self,baseline,resume_admission=False,resume_grant_crash=False):
        began=time.monotonic();self.setup(baseline);self.start_host()
        if (len(durable(self.root,0))!=9 or len(self.claim_progress())!=1) and not resume_admission:
            raise ValueError('start requires original one-grant/eight-nullifier checkpoint')
        if resume_admission and (not 1<=len(self.claim_progress())<=10 or not set(self.claim_progress())<=set(k['fee_address'] for k in self.keys.values())):
            raise ValueError('admission recovery contains an unrelated claim')
        self.initial_fees={name:self.native_balance(self.keys[name]['fee_address']) if name==NAMES[0] else 0 for name in NAMES}
        self.initial_source=self.native_balance(self.prepared['fee_address'])
        oldclaim=self.claim_progress()[self.keys[NAMES[0]]['fee_address']][0]
        def join(job):
            name=job['id'];invitation=cohort.private_json(self.cr/'invitations'/(name+'.json'))['invitation']
            return self.user(name,'join',invitation=invitation)
        joined=burst(self.evidence/'admissions',[dict(id=n,binding_sha256=self.binding) for n in NAMES],10,join,self.health,idempotent=True)
        if len(self.claim_progress())!=10:raise ValueError('all ten distinct original claims were not reserved')
        self.claims={name:joined[name]['result']['claim_id'] for name in NAMES}
        if self.claims[NAMES[0]]!=oldclaim or len(set(self.claims.values()))!=10:raise ValueError('admission retry replaced or merged claims')
        self.event('all_ten_original_invitations_redeemed_concurrently',peak_client_jobs=overlap(joined))
        if not resume_grant_crash:
            end=time.monotonic()+180
            while time.monotonic()<end:
                self.health();progress=self.claim_progress();status=self.host_status()
                candidates=[(fee,p) for fee,(_,p) in progress.items() if fee!=self.keys[NAMES[0]]['fee_address'] and p['gas_done'] and not p['private_done']]
                if candidates and status.get('grant_child'):
                    snapshot=dict(progress=progress,activation_sha256=sha(self.activation),source_public=self.native_balance(self.prepared['fee_address']))
                    create(self.evidence/'interrupted-grants.json',encode(snapshot));self.stop_host(crash=True);break
                time.sleep(.1)
            else:raise RuntimeError('new grant did not reach bounded crash point')
            self.start_host()
        else:
            snapshot=decode(read(self.evidence/'interrupted-grants.json',1024*1024,secret=True))
            if snapshot['activation_sha256']!=sha(self.activation):raise ValueError('original interrupted grant activation changed')
        self.event('host_group_sigkill_with_ten_claims_and_original_grant_in_progress',recovered_cleanup_race=resume_grant_crash)
        end=time.monotonic()+900;last=-1
        while time.monotonic()<end:
            self.health();progress=self.claim_progress();complete=sum(p['private_done'] and p['gas_done'] for _,p in progress.values())
            if complete!=last:self.event('grant_recovery_progress',completed=complete,total=10);last=complete
            if complete==10:break
            time.sleep(.5)
        else:raise RuntimeError('ten original grants did not finish before bounded deadline')
        for name in NAMES:
            claim,p=progress[self.keys[name]['fee_address']]
            if claim!=self.claims[name] or p['gas_attempts']!=1 or not 1<=p['private_attempts']<=cohort.ATTEMPTS:raise ValueError('grant identity or bounded attempt changed')
            expected=self.initial_fees[name]+(0 if name==NAMES[0] else 150_000_000)
            if self.native_balance(self.keys[name]['fee_address'])!=expected:raise ValueError('gas grant missing or duplicated')
        source=self.command([cohort.WALLET,'balance','--network',self.root/'network.json','--wallet',self.source_audit,'--password-file',self.password_file,
                            '--rpc','http://127.0.0.1:18899','--rpc-access-file',self.root/'rpc-access.key'])
        if source['balance']!=0:raise ValueError('ten private grants did not exactly exhaust original reservoir')
        self.audit(EXPECTED,'after-grants');state=durable(self.root,0);self.wait_for(lambda:durable(self.root,1)==state)
        if len(state)!=27:raise ValueError('expected original pool and 26 nullifiers after ten grants')
        self.event('all_ten_original_grants_finalized_once_private_reservoir_exactly_exhausted')
        # User RPC fee quotes and sends; all work queued once, at most two local
        # proving jobs active to bound CPU use. Native source/faucet not involved.
        fee_before={name:self.native_balance(self.keys[name]['fee_address']) for name in NAMES}
        quotes={name:self.user(name,'fees',payment='send')['maximum_gross_debit'] for name in NAMES}
        self.source_after_grants=self.native_balance(self.prepared['fee_address'])
        jobs=[dict(id=name,binding_sha256=self.binding,amount=AMOUNT,recipient=self.keys[NAMES[(i+1)%10]]['address'],fee_cap=quotes[name]) for i,name in enumerate(NAMES)]
        def pay(job):
            name=job['id'];return self.user(name,'send',amount=job['amount'],recipient=job['recipient'],fee_mode='user',max_fee_debit=job['fee_cap'])
        payments=burst(self.evidence/'payments',jobs,2,pay,self.capture_pending)
        signatures={v['result']['signature'] for v in payments.values()}
        if len(signatures)!=10 or overlap(payments)!=2:raise ValueError('payment ring did not exercise two concurrent distinct sends')
        for name,value in payments.items():
            self.closed(value['result']['staging_account'])
            charged=fee_before[name]-self.native_balance(self.keys[name]['fee_address'])
            if not 0<charged<=quotes[name]:raise ValueError('user paid more than the original authorized cap')
            pending=self.evidence/'payments'/(name+'-pending.json')
            if pending.exists() and decode(read(pending,16384,secret=True))['signature']!=value['result']['signature']:raise ValueError('captured original signature differs')
        if self.native_balance(self.prepared['fee_address'])!=self.source_after_grants:raise ValueError('private sends consumed operator funding')
        self.audit(EXPECTED,'after-ring');state=durable(self.root,0);self.wait_for(lambda:durable(self.root,1)==state)
        if len(state)!=47:raise ValueError('expected exact pool and 46 permanent nullifiers after ring')
        self.event('ten_user_paid_private_sends_finalized_with_two_concurrent_client_jobs',nullifiers=46)
        barrier=max(self.slots());self.stop_host(crash=True);self.start_host()
        if min(self.slots())<=barrier or durable(self.root,0)!=state or durable(self.root,1)!=state or read(self.root/runtime.FILES[2],4096,secret=True)!=self.activation:
            raise ValueError('host restart changed original activation, pool or nullifiers')
        self.audit(EXPECTED,'after-restart')
        balances_before={name:self.native_balance(self.keys[name]['fee_address']) for name in NAMES}
        retries=burst(self.evidence/'claim-retries',[dict(id=n,claim_id=self.claims[n]) for n in NAMES],10,lambda j:self.user(j['id'],'test-coins'),self.health)
        for name in NAMES:
            if retries[name]['result']['claim_id']!=self.claims[name] or self.native_balance(self.keys[name]['fee_address'])!=balances_before[name]:raise ValueError('completed claim retry paid another grant')
        restored=WalletApp.from_profile(self.profile,self.evidence/'restored-tester-10')
        key=restored.action(dict(action='restore',password=self.password,backup=decode(read(self.clients[NAMES[-1]].backup,16384,secret=True))))
        if key['fee_address']!=self.keys[NAMES[-1]]['fee_address'] or restored.action(dict(action='balance',password=self.password))['balance']!=EXPECTED[NAMES[-1]]:
            raise ValueError('original encrypted seed failed to restore correct identity/balance')
        if restored.action(dict(action='test-coins',password=self.password))['claim_id']!=self.claims[NAMES[-1]]:raise ValueError('restore replaced original claim')
        if durable(self.root,0)!=state or durable(self.root,1)!=state or self.native_balance(self.prepared['fee_address'])!=self.source_after_grants:raise ValueError('claim retry/restore changed funding or nullifiers')
        for name,digest in {**self.preserved,**self.original_wallets}.items():
            if sha(read(Path(name),32768,secret=True))!=digest:raise ValueError('original wallet/funding/sponsor material changed')
        audit=cohort.audit(self.cr,self.digest)
        if (audit['issued'],audit['reserved_claims'])!=(10,10):raise ValueError('cohort capacity changed')
        self.stop_host();self.result.update(status='passed',seconds=round(time.monotonic()-began,2),wallets=10,original_grants=10,new_grants=9,
            payments=10,client_job_concurrency=2,admission_peak=overlap(joined),nullifiers=46,private_balances=EXPECTED,
            private_reservoir=0,host_generations=self.host_generation,original_activation=True,seed_restore=True,claims_reused=True,
            no_refill=True,source_sha256=sha(Path(__file__).read_bytes()),binding_sha256=self.binding)
        self.event('ten_wallet_cohort_restart_claim_retry_and_seed_restore_passed')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True)
    modes=p.add_mutually_exclusive_group();modes.add_argument('--resume-admission',action='store_true');modes.add_argument('--resume-grant-crash',action='store_true');modes.add_argument('--resume-after-grants',action='store_true');a=p.parse_args()
    root=a.root.absolute();evidence=a.evidence.absolute()
    baseline=decode(read(root/'pilot-install-result.json',1024*1024))
    if root!=PROJECT/'.data/p46a' or baseline.get('status')!='passed' or baseline.get('grants_exercised')!=1 or baseline.get('nullifiers')!=8:
        p.error('requires exact preserved accepted disposable one-grant checkpoint; never resets or funds')
    previous=None
    if a.resume_admission or a.resume_grant_crash or a.resume_after_grants:
        previous=decode(read(evidence/'result.json',1048576,secret=True))
        kinds=[e['kind'] for e in previous['events']]
        allowed=(a.resume_admission and previous.get('error','').startswith('burst preserved unfinished originals:') and
                    kinds==['ten_distinct_original_seeded_wallets_ready_without_refunding']) or (
                 a.resume_grant_crash and (previous.get('error')=='[Errno 1] Operation not permitted' or
                    (previous.get('error')=='unsafe or oversized release input' and
                     '[Errno 1] Operation not permitted' in previous.get('prior_failures',[]) and
                     (evidence/'grant-crash-failure-original.json').exists())) and
                    kinds==['ten_distinct_original_seeded_wallets_ready_without_refunding','all_ten_original_invitations_redeemed_concurrently'] and
                    (evidence/'interrupted-grants.json').exists()) or (
                 a.resume_after_grants and previous.get('error')=='Wallet error: No such file or directory (os error 2)\n' and
                    kinds[-1:] == ['grant_recovery_progress'] and previous['events'][-1].get('completed')==10 and
                    (evidence/'interrupted-grants.json').exists())
        if (previous.get('status')!='failed' or not allowed or (evidence/'payments').exists() or read(evidence/'baseline.json',1048576,secret=True)!=encode(baseline)):
            p.error('only exact preserved admission or grant-cleanup failure can resume; no payment replay')
        retained='after-grants-audit-failure-original.json' if a.resume_after_grants else ('admission-failure-original.json' if a.resume_admission else ('grant-crash-failure-input-bounds.json' if previous.get('error')=='unsafe or oversized release input' else 'grant-crash-failure-original.json'))
        create(evidence/retained,encode(previous))
        if a.resume_grant_crash or a.resume_after_grants:
            snapshot=decode(read(evidence/'interrupted-grants.json',1024*1024,secret=True))
            if snapshot['activation_sha256']!=sha(read(root/runtime.FILES[2],4096,secret=True)):p.error('original interrupted activation differs')
    else:evidence.mkdir(mode=0o700,parents=True,exist_ok=False);create(evidence/'baseline.json',encode(baseline))
    trial=CohortRun(root,evidence,None,None)
    if previous:
        trial.result['prior_failures']=previous.get('prior_failures',[previous['prior_admission_error']] if 'prior_admission_error' in previous else [])+[previous['error']]
        trial.host_generation=max(int(p.stem.split('-')[1]) for p in evidence.glob('host-*.log'))
    def interrupted(*_):raise KeyboardInterrupt('bounded ten-wallet rehearsal interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    with funding.native_lock(root/'cohort-rehearsal.lock'):
        try:trial.run(baseline,resume_admission=a.resume_admission or a.resume_grant_crash or a.resume_after_grants,resume_grant_crash=a.resume_grant_crash or a.resume_after_grants)
        except BaseException as error:trial.result.update(status='failed',error=str(error));raise
        finally:
            try:trial.close()
            finally:atomic(evidence/'result.json',trial.result)

if __name__=='__main__':main()
