from pathlib import Path
import os
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import pilot_cohort as cohort
import pilot_funding as funding
import pilot_cohort_test as fixtures
from wallet_release import atomic,create,encode,read,sha


class ObservationReader:
    def __init__(self,profile,key=None):self.genesis=profile['genesis_hash'];self.calls=[]
    def rpc(self,method,params=()):
        self.calls.append(method)
        if method=='getGenesisHash':return self.genesis
        if method=='getBlock':return dict(blockhash='1'*32,blockHeight=9,parentSlot=9)
        if method=='getBalance':return dict(context=dict(slot=10),value=2_000_000_000)
        raise AssertionError('unexpected funding method')


def observation(root,value,source,password):
    p=cohort.private_json(root/'faucet/claims.json')['policy']
    return dict(balance=100_000_000,max_single_payment=100_000_000,fee_address=p['source_fee_address'],finalized_slot=10)


class FundingTests(unittest.TestCase):
    setUp=fixtures.PilotTests.setUp
    prepare=fixtures.PilotTests.prepare
    wallet=fixtures.PilotTests.wallet
    def ready(self):self.prepare();return funding.make_intent(self.root,self.digest)
    def verify(self,name='first',**kwargs):
        return funding.verify(self.root,self.digest,self.password,name,reader_factory=ObservationReader,scan_fn=observation,**kwargs)

    def test_intent_has_exact_addresses_and_conservative_budget_and_is_immutable(self):
        intent=self.ready();self.assertFalse(intent['transfer_authorized']);self.assertFalse(intent['automatic_refill'])
        self.assertEqual(intent['public_units'],self.value['budget']['conservative_public_units'])
        before=read(self.root/'funding-intent.json',16384)
        self.assertEqual(funding.make_intent(self.root,self.digest),intent)
        self.assertEqual(before,read(self.root/'funding-intent.json',16384))
        atomic(self.root/'funding-intent.json',{**intent,'fee_address':'1'*32})
        with self.assertRaises(ValueError):self.verify()

    def test_verified_receipt_retry_preserves_time_and_does_not_repeat_scan(self):
        intent=self.ready();receipt=self.verify();self.assertTrue(receipt['funding_verified']);self.assertEqual(receipt['transfers_submitted'],0)
        with patch.object(funding,'scan',side_effect=AssertionError('scan repeated')):
            again=funding.verify(self.root,self.digest,self.password,'first',reader_factory=lambda *_:(_ for _ in ()).throw(AssertionError('RPC repeated')),scan_fn=lambda *_:(_ for _ in ()).throw(AssertionError('scan repeated')))
        self.assertEqual(again,receipt);funding.validate_receipt(receipt,intent)

    def test_insufficient_or_wrong_authority_never_publishes_receipt(self):
        self.ready()
        for label,change in [('short',dict(balance=1)),('wrong',dict(fee_address='1'*32)),('badslot',dict(finalized_slot=0)),('fragmented',dict(max_single_payment=500_000)),('later-grant',dict(max_single_payment=1_500_000))]:
            def scan(*args,change=change):return {**observation(*args),**change}
            with self.assertRaises(ValueError):funding.verify(self.root,self.digest,self.password,label,reader_factory=ObservationReader,scan_fn=scan)
            self.assertFalse((self.root/'funding-checks'/(label+'.json')).exists())

    def test_missing_wrong_genesis_public_shortfall_or_changed_header_fail_closed(self):
        self.ready()
        class Bad(ObservationReader):
            mode='';count=0
            def rpc(self,method,params=()):
                value=super().rpc(method,params)
                if method=='getGenesisHash' and self.mode=='genesis':return 'wrong'
                if method=='getBlock':
                    self.count+=1
                    if self.mode=='missing':return None
                    if self.mode=='changed' and self.count==2:return {**value,'blockhash':'2'*32}
                if method=='getBalance':
                    if self.mode=='short':return dict(context=dict(slot=10),value=1)
                    if self.mode=='lag':return dict(context=dict(slot=9),value=2_000_000_000)
                return value
        for mode in ('genesis','missing','changed','short','lag'):
            Bad.mode=mode
            with self.assertRaises(ValueError):funding.verify(self.root,self.digest,self.password,mode,reader_factory=Bad,scan_fn=observation)
            self.assertFalse((self.root/'funding-checks'/(mode+'.json')).exists())

    def test_receipt_expiry_wrong_plan_and_clock_rollback_are_rejected(self):
        intent=self.ready();receipt=self.verify()
        for changed in ({'plan_sha256':'0'*64},{'private_observed':1},{'funding_verified':False},{'transfers_submitted':1},{'max_private_payment':1}):
            with self.assertRaises(ValueError):funding.validate_receipt({**receipt,**changed},intent)
        for now in (receipt['checked_at']-1,receipt['expires_at'],float('nan')):
            with self.assertRaises(ValueError):funding.validate_receipt(receipt,intent,now)
        atomic(self.root/'funding-clock.json',dict(last_time=int(time.time())+10))
        with self.assertRaisesRegex(ValueError,'backwards'):self.verify()
        with self.assertRaisesRegex(ValueError,'backwards'):funding.check(self.root,self.digest,'first')

    def test_issued_cohort_or_pending_funding_cannot_get_initial_receipt(self):
        self.ready();source=self.root/'faucet/wallet.enc.json'
        for kind in ('pending','staging'):
            path=Path(str(source)+'.'+kind+'.json');create(path,b'preserve')
            with self.assertRaises(ValueError):self.verify(kind)
            self.assertEqual(read(path,1024),b'preserve');path.unlink()
        cohort.issue(self.root,self.digest,'tester-01')
        with self.assertRaises(ValueError):self.verify()

    def test_worker_and_admission_native_locks_block_funding_check(self):
        self.ready()
        for name in ('worker.lock','claims.json.lock'):
            with funding.native_lock(self.root/'faucet'/name):
                with self.assertRaises(BlockingIOError):self.verify()
        with funding.native_lock(self.root/'faucet/worker.lock'):
            result=subprocess.run([str(cohort.FAUCET),'tick','--root',str(self.root/'faucet'),'--password-file','-'],
                                  input=read(self.password,1024),capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'lock wallet operation',result.stderr)

    def test_receipt_write_sigkill_retries_only_read_observations(self):
        self.ready()
        script='''import os,signal,sys
from unittest.mock import patch
from pathlib import Path
import pilot_funding as f
from pilot_funding_test import ObservationReader,observation
original=f.atomic
def crash(path,value):
    if path.parent.name=='funding-checks' and sys.argv[4]=='before':os.kill(os.getpid(),signal.SIGKILL)
    original(path,value)
    if path.parent.name=='funding-checks':os.kill(os.getpid(),signal.SIGKILL)
with patch.object(f,'atomic',side_effect=crash):
    f.verify(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]),sys.argv[4],reader_factory=ObservationReader,scan_fn=observation)
'''
        wallet=read(self.root/'faucet/wallet.enc.json',16384,secret=True)
        for phase in ('before','after'):
            child=subprocess.run([sys.executable,'-B','-c',script,str(self.root),self.digest,str(self.password),phase],
                                 cwd=cohort.PROJECT/'tools',capture_output=True,timeout=20)
            self.assertEqual(child.returncode,-9)
            receipt=self.verify(phase);self.assertEqual(receipt['transfers_submitted'],0)
            self.assertEqual(wallet,read(self.root/'faucet/wallet.enc.json',16384,secret=True))

    def test_public_reader_refuses_mutations_and_cross_host_redirect(self):
        from http.server import BaseHTTPRequestHandler,HTTPServer
        import threading
        class Redirect(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                self.send_response(302);self.send_header('Location','http://example.invalid/');self.end_headers()
        server=HTTPServer(('127.0.0.1',0),Redirect);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            reader=funding.Reader(dict(rpc=dict(url=f'http://127.0.0.1:{server.server_port}')))
            with self.assertRaises(ValueError):reader.rpc('sendTransaction',[])
            with self.assertRaises(ValueError):reader.rpc('getGenesisHash')
        finally:server.shutdown();server.server_close();thread.join(timeout=5)

    def test_changed_seed_or_during_scan_state_cannot_certify_funding(self):
        self.ready();source=self.root/'faucet/wallet.enc.json';original=read(source,16384,secret=True)
        atomic(source,dict(different='seed'))
        with self.assertRaises(ValueError):self.verify('changed-seed')
        from wallet_release import create as write_new
        source.unlink();write_new(source,original)
        def changed(*args):
            result=observation(*args)
            state=cohort.private_json(self.root/'faucet/claims.json');state['policy']['max_claims']=2
            atomic(self.root/'faucet/claims.json',state);return result
        with self.assertRaisesRegex(ValueError,'changed during'):
            funding.verify(self.root,self.digest,self.password,'changed-state',reader_factory=ObservationReader,scan_fn=changed)
        self.assertFalse((self.root/'funding-checks/changed-state.json').exists())


if __name__=='__main__':unittest.main()
