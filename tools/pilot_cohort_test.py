"""Real native admission/configuration tests; no validator process is started."""
from contextlib import contextmanager
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import pilot_cohort as pilot
from package_wallet import public_profile
from wallet_release import create, decode, encode, read, sha


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


@contextmanager
def admission_server(root,password,port):
    # Deliberately no worker thread: these tests reserve claims but cannot send coins.
    code='''import sys
from test_faucet import BoundedServer,Faucet,Handler
app=Faucet(sys.argv[1],sys.argv[2])
app.command('access-info')
server=BoundedServer(('127.0.0.1',int(sys.argv[3])),Handler)
server.app,server.authority=app,'127.0.0.1:'+sys.argv[3]
server.serve_forever()
'''
    child=subprocess.Popen([sys.executable,'-B','-c',code,str(root),str(password),str(port)],
                           cwd=pilot.PROJECT/'tools',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if child.poll() is not None:raise RuntimeError('admission test server exited')
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.2):break
            except OSError:time.sleep(.05)
        else:raise RuntimeError('admission test server unavailable')
        yield child
    finally:
        if child.poll() is None:child.kill()
        child.wait(timeout=10)


class PilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.base.chmod(0o700)
        self.password=self.base/'password';create(self.password,b'only-disposable-test-password')
        network=dict(network=[7]*32,genesis_hash='11111111111111111111111111111111',
                     program='78kCqctsuUaj7kyV8xNVwXQrqovY3QtSytt4eCYApVUh',pool='4mJMnxFhRVMQ3aNcyn2LgW8fztTjgckUvaaWrXggdAAL',
                     pool_format='NPOOL003',recipient_withdrawals=True)
        source=public_profile(network,'Zolana pilot rehearsal','http://127.0.0.1:18899','loopback-http')
        self.port=unused_port()
        tester=public_profile(network,'Zolana pilot rehearsal','http://127.0.0.1:18898','loopback-http')
        tester.update(invite_required=True,faucet=dict(transport='loopback-http',url=f'http://127.0.0.1:{self.port}'))
        self.value=pilot.plan(source,tester,3,2)
        self.digest=sha(encode(self.value));self.root=self.base/'pilot'

    def prepare(self,**kwargs):return pilot.prepare(self.value,self.root,self.digest,self.password,**kwargs)
    def snapshot(self):
        return {p.relative_to(self.root).as_posix():sha(p.read_bytes()) for p in self.root.rglob('*') if p.is_file() and p.name!='pilot.lock'}
    def wallet(self,name):
        path=self.base/(name+'.wallet');backup=self.base/(name+'.backup')
        keys=pilot.native(pilot.WALLET,'init',extra=['--network',self.root/'tester-profile.json','--wallet',path,'--backup',backup,'--password-file','-'],password=read(self.password,1024))
        return path,backup,keys
    def command(self,command,path,**kwargs):
        extra=['--network',self.root/'tester-profile.json','--wallet',path,'--password-file','-']
        for key,value in kwargs.items():extra+=['--'+key.replace('_','-'),value]
        return pilot.native(pilot.WALLET,command,extra=extra,password=read(self.password,1024))

    def test_finite_budget_and_profile_pins_fail_before_key_generation(self):
        self.assertEqual(pilot.budget(10),dict(private_grants=10_000_000,public_gas_grants=1_500_000_000,
                         initial_working_reserve=150_000_000,gas_fee_reserve=300_000,initial_public_units=1_650_300_000,
                         conservative_public_units=6_000_300_000))
        for count in (0,101,True,2.5):
            with self.assertRaises(ValueError):pilot.budget(count)
        for change in ({'daily_admissions':4},{'rpc_per_minute':10001},{'extra':'credential'},
                       {'budget':{}},{'invitation_ttl_seconds':604801}):
            with self.assertRaises(ValueError):pilot.validate({**self.value,**change})
        bad=decode(encode(self.value));bad['tester_profile']['network']=[8]*32
        with self.assertRaises(ValueError):pilot.validate(bad)
        bad=decode(encode(self.value));bad['tester_profile']['rpc']=bad['source_profile']['rpc']
        with self.assertRaises(ValueError):pilot.validate(bad)
        with self.assertRaises(ValueError):pilot.prepare(self.value,self.root,'0'*64,self.password)
        self.assertFalse(self.root.exists())

    def test_prepare_resume_preserves_keys_claims_and_budgets(self):
        receipt=self.prepare();before=self.snapshot()
        self.assertFalse(receipt['funded']);self.assertFalse(receipt['services_started'])
        with self.assertRaises(FileExistsError):self.prepare()
        self.assertEqual(self.prepare(resume=True),receipt)
        self.assertEqual(before,self.snapshot())
        info=pilot.audit(self.root,self.digest)
        self.assertEqual((info['cohort_size'],info['issued'],info['reserved_claims']),(3,0,0))
        self.assertFalse(info['funding_verified'])

    def test_native_initialization_commit_lost_ack_resumes_same_seed(self):
        actual=pilot.native
        def lose_ack(binary,command,*args,**kwargs):
            result=actual(binary,command,*args,**kwargs)
            if command=='init':raise RuntimeError('simulated process interruption')
            return result
        with patch.object(pilot,'native',side_effect=lose_ack),self.assertRaises(RuntimeError):self.prepare()
        before=read(self.root/'faucet/wallet.enc.json',16384,secret=True)
        self.prepare(resume=True)
        self.assertEqual(before,read(self.root/'faucet/wallet.enc.json',16384,secret=True))

    def test_admission_commit_lost_ack_resumes_original_policy(self):
        actual=pilot.native
        def lose_ack(binary,command,*args,**kwargs):
            result=actual(binary,command,*args,**kwargs)
            if command=='access-init':raise RuntimeError('simulated process interruption')
            return result
        with patch.object(pilot,'native',side_effect=lose_ack),self.assertRaises(RuntimeError):self.prepare()
        before={name:read(self.root/'faucet'/name,1024*1024,secret=True) for name in ('claims.json','admission.json','wallet.enc.json')}
        self.prepare(resume=True)
        self.assertTrue(all(read(self.root/'faucet'/name,1024*1024,secret=True)==data for name,data in before.items()))

    def test_incomplete_native_setup_fails_closed_without_seed_replacement(self):
        self.prepare();original=read(self.root/'faucet/wallet.enc.json',16384,secret=True)
        # Simulate the native permanent admission marker being committed before admission data.
        (self.root/'faucet/admission.json').rename(self.root/'retained-admission.json')
        with self.assertRaises(ValueError):self.prepare(resume=True)
        self.assertEqual(original,read(self.root/'faucet/wallet.enc.json',16384,secret=True))
        self.assertFalse((self.root/'faucet/admission.json').exists())

    def test_invitation_retry_capacity_and_revocation_persist(self):
        self.prepare()
        first=pilot.issue(self.root,self.digest,'tester-01');before=self.snapshot()
        self.assertNotIn('invitation',first)
        self.assertEqual(pilot.issue(self.root,self.digest,'tester-01'),first)
        self.assertEqual(before,self.snapshot())
        pilot.native(pilot.FAUCET,'invite-revoke',self.root/'faucet',['--invite-id',first['invite_id']])
        self.assertTrue(pilot.issue(self.root,self.digest,'tester-01')['revoked'])
        for slot in ('tester-02','tester-03'):pilot.issue(self.root,self.digest,slot)
        with self.assertRaisesRegex(ValueError,'capacity'):pilot.issue(self.root,self.digest,'tester-04')
        self.assertEqual(pilot.audit(self.root,self.digest)['issued'],3)
        with self.assertRaises(ValueError):pilot.issue(self.root,self.digest,'../replacement')
        with self.assertRaises(ValueError):pilot.issue(self.root,'0'*64,'tester-04')

    def test_invitation_lost_ack_does_not_reissue_and_orphan_export_fails_closed(self):
        self.prepare();actual=pilot.native
        def lose_ack(binary,command,*args,**kwargs):
            result=actual(binary,command,*args,**kwargs)
            if command=='invite-issue':raise RuntimeError('simulated lost invitation acknowledgement')
            return result
        with patch.object(pilot,'native',side_effect=lose_ack),self.assertRaises(RuntimeError):pilot.issue(self.root,self.digest,'tester-01')
        before=self.snapshot();pilot.issue(self.root,self.digest,'tester-01');self.assertEqual(before,self.snapshot())
        # Native export persisted before its ledger commit: never mint a replacement code.
        create(self.root/'invitations/tester-02.json',encode(dict(invitation='invite1_'+'A'*43,invite_id='0'*64,redeem_by=1)))
        with self.assertRaises(ValueError):pilot.issue(self.root,self.digest,'tester-02')
        with self.assertRaises(ValueError):pilot.audit(self.root,self.digest)
        self.assertEqual(pilot.native(pilot.FAUCET,'access-info',self.root/'faucet')['issued'],1)

    def test_real_claim_and_seed_restore_survive_http_process_sigkill(self):
        self.prepare();alice,backup,keys=self.wallet('alice');bob,_,_=self.wallet('bob')
        issued=pilot.issue(self.root,self.digest,'tester-01',bind_fee=keys['fee_address'])
        invitation=self.root/'invitations/tester-01.json'
        with admission_server(self.root/'faucet',self.password,self.port) as server:
            with self.assertRaises(ValueError):self.command('join',bob,invitation_file=invitation)
            first=self.command('join',alice,invitation_file=invitation)
            self.assertTrue(first['admitted']);self.assertEqual(first['state'],'queued')
            state={n:read(self.root/'faucet'/n,1024*1024,secret=True) for n in ('claims.json','admission.json','wallet.enc.json')}
            server.kill();server.wait(timeout=10)
        restored=self.base/'restored.wallet'
        self.command('restore',restored,backup=backup)
        with admission_server(self.root/'faucet',self.password,self.port):
            self.assertTrue(self.command('access-status',restored)['admitted'])
            retry=self.command('join',restored,invitation_file=invitation)
            self.assertEqual(retry['claim_id'],first['claim_id'])
            self.assertEqual(self.command('test-coins',restored)['claim_id'],first['claim_id'])
            self.assertTrue(pilot.issue(self.root,self.digest,'tester-01',bind_fee=keys['fee_address'])['redeemed'])
            pilot.native(pilot.FAUCET,'invite-revoke',self.root/'faucet',['--invite-id',issued['invite_id']])
            self.assertFalse(self.command('access-status',restored)['admitted'])
        self.assertEqual(state['claims.json'],read(self.root/'faucet/claims.json',1024*1024,secret=True))
        self.assertEqual(state['wallet.enc.json'],read(self.root/'faucet/wallet.enc.json',16384,secret=True))
        self.assertEqual(pilot.audit(self.root,self.digest)['reserved_claims'],1)

    def test_symlink_and_changed_policy_are_rejected_without_reset(self):
        self.prepare();before=read(self.root/'faucet/wallet.enc.json',16384,secret=True)
        alias=self.base/'alias';alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError):pilot.audit(alias,self.digest)
        claims=pilot.private_json(self.root/'faucet/claims.json');claims['policy']['max_claims']=99
        from wallet_release import atomic
        atomic(self.root/'faucet/claims.json',claims)
        with self.assertRaises(ValueError):self.prepare(resume=True)
        self.assertEqual(before,read(self.root/'faucet/wallet.enc.json',16384,secret=True))

    def test_actual_preparer_and_issuer_sigkill_preserve_native_commits(self):
        script='''import os,signal,sys
import pilot_cohort as p
from unittest.mock import patch
value=p.private_json(__import__('pathlib').Path(sys.argv[1]))
original=p.native
def crash(binary,command,*args,**kwargs):
    result=original(binary,command,*args,**kwargs)
    if command==sys.argv[5]:os.kill(os.getpid(),signal.SIGKILL)
    return result
with patch.object(p,'native',side_effect=crash):
    if sys.argv[5]=='invite-issue':p.issue(sys.argv[2],sys.argv[3],'tester-01')
    else:p.prepare(value,sys.argv[2],sys.argv[3],sys.argv[4])
'''
        valuefile=self.base/'input.json';create(valuefile,encode(self.value))
        for command in ('init','access-init','invite-issue'):
            root=self.base/('crash-'+command)
            if command=='invite-issue':pilot.prepare(self.value,root,self.digest,self.password)
            result=subprocess.run([sys.executable,'-B','-c',script,str(valuefile),str(root),self.digest,str(self.password),command],
                                  cwd=pilot.PROJECT/'tools',capture_output=True,timeout=40)
            self.assertEqual(result.returncode,-9)
            source=read(root/'faucet/wallet.enc.json',16384,secret=True)
            if command=='invite-issue':
                first=read(root/'invitations/tester-01.json',1024,secret=True)
                pilot.issue(root,self.digest,'tester-01')
                self.assertEqual(first,read(root/'invitations/tester-01.json',1024,secret=True))
                self.assertEqual(pilot.audit(root,self.digest)['issued'],1)
            else:pilot.prepare(self.value,root,self.digest,self.password,resume=True)
            self.assertEqual(source,read(root/'faucet/wallet.enc.json',16384,secret=True))

    def test_missing_issuance_state_and_export_never_recreate_capacity(self):
        self.prepare();pilot.issue(self.root,self.digest,'tester-01')
        (self.root/'issuance.json').rename(self.root/'retained-issuance.json')
        with self.assertRaises(OSError):pilot.issue(self.root,self.digest,'tester-02')
        with self.assertRaises(ValueError):self.prepare(resume=True)
        self.assertFalse((self.root/'issuance.json').exists())
        (self.root/'retained-issuance.json').rename(self.root/'issuance.json')
        (self.root/'invitations/tester-01.json').rename(self.base/'retained-invitation.json')
        with self.assertRaises(ValueError):pilot.issue(self.root,self.digest,'tester-01')
        self.assertFalse((self.root/'invitations/tester-01.json').exists())

    def test_operator_rpc_capability_is_preserved_and_never_downgraded(self):
        credential=self.base/'rpc-access.key';create(credential,b'a'*64)
        self.prepare(rpc_access_file=credential)
        self.assertEqual(read(self.root/'faucet/rpc-access.key',16384,secret=True),b'a'*64)
        original=read(self.root/'faucet/wallet.enc.json',16384,secret=True)
        self.prepare(resume=True,rpc_access_file=credential)
        other=self.base/'other.key';create(other,b'b'*64)
        with self.assertRaises(ValueError):self.prepare(resume=True,rpc_access_file=other)
        self.assertEqual(original,read(self.root/'faucet/wallet.enc.json',16384,secret=True))
        (self.root/'faucet/rpc-access.key').rename(self.root/'retained-capability.key')
        with self.assertRaises(OSError):pilot.audit(self.root,self.digest)

    def test_concurrent_named_retry_cannot_consume_two_native_slots(self):
        self.prepare()
        from concurrent.futures import ThreadPoolExecutor
        def attempt(_):
            try:return pilot.issue(self.root,self.digest,'tester-01')['invite_id']
            except BlockingIOError:return None
        with ThreadPoolExecutor(max_workers=2) as workers:results=list(workers.map(attempt,range(2)))
        original=pilot.issue(self.root,self.digest,'tester-01')['invite_id']
        self.assertTrue(all(result is None or result==original for result in results))
        self.assertEqual(pilot.audit(self.root,self.digest)['issued'],1)

    def test_private_unix_rpc_material_stays_byte_identical(self):
        with tempfile.TemporaryDirectory(prefix='p42rpc-',dir='/private/tmp') as temporary:
            credential=self.base/'rpc-unix.key'
            material=encode(dict(format='native-rpc-unix-v1',token='a'*64,sockets={'18899':str(Path(temporary)/'rpc.sock')}))
            create(credential,material)
            self.prepare(rpc_access_file=credential)
            claims=pilot.private_json(self.root/'faucet/claims.json')
            self.assertTrue(claims['policy']['operator_unix'])
            self.assertEqual(read(self.root/'faucet/rpc-access.key',16384,secret=True),material)
            self.prepare(resume=True,rpc_access_file=credential)
            from wallet_release import atomic
            atomic(self.root/'faucet/rpc-access.key',{'format':'replaced'})
            with self.assertRaises(ValueError):pilot.audit(self.root,self.digest)

    def test_expired_named_slot_is_not_reissued_or_renewed(self):
        self.value['invitation_ttl_seconds']=1;self.digest=sha(encode(self.value))
        self.prepare();alice,_,_=self.wallet('alice')
        first=pilot.issue(self.root,self.digest,'tester-01')
        before=read(self.root/'invitations/tester-01.json',1024,secret=True)
        time.sleep(1.1)
        again=pilot.issue(self.root,self.digest,'tester-01')
        self.assertEqual(first,again)
        self.assertEqual(before,read(self.root/'invitations/tester-01.json',1024,secret=True))
        with admission_server(self.root/'faucet',self.password,self.port):
            with self.assertRaises(ValueError):self.command('join',alice,invitation_file=self.root/'invitations/tester-01.json')
        info=pilot.audit(self.root,self.digest)
        self.assertEqual((info['issued'],info['reserved_claims']),(1,0))


if __name__=='__main__':unittest.main()
