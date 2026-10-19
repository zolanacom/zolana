import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pilot_provision as provision
from wallet_release import create,encode,read

SIGNED=dict(format='zolana-pilot-treasury-signature-v1',genesis_hash='genesis',treasury='treasury',recipient='recipient',amount=6_000_300_000,fee=5000,last_valid_block_height=100,signature='original-signature',transaction=[1,2,3],broadcast=False)

class Transport:
    def __init__(self,final=False,ackloss=False):self.final=final;self.ackloss=ackloss;self.sent=[];self.height=50;self.genesis='genesis';self.canonical=True
    def rpc(self,method,params=()):
        if method=='getGenesisHash':return self.genesis
        if method=='getSignatureStatuses':return dict(value=[dict(confirmationStatus='finalized',err=None,slot=42) if self.final else None])
        if method=='getBlock':return dict(signatures=['original-signature'] if self.canonical else [],blockhash='original-block')
        if method=='getBlockHeight':return self.height
        if method=='sendTransaction':
            self.sent.append(params[0]);self.final=True
            if self.ackloss:raise ValueError('real reply lost in fixture')
            return 'original-signature'
        raise AssertionError(method)

class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.plan=dict(network_root=str(self.root),public_units=6_000_300_000,public_fee_cap=10_000,rpc='http://127.0.0.1:18899')
        self.calls=[]
    def native(self,args):
        self.calls.append(args[1])
        if args[1]=='pilot-treasury-check':return provision.decode(read(Path(args[-1]),16384,secret=True))
        return SIGNED.copy()
    def run_public(self,transport,hook=lambda _:None):
        with patch.object(provision,'command',side_effect=self.native):
            return provision.public_allocation(self.root,self.plan,self.root/'wallet',self.root/'password',self.root/'cold',transport,hook)
    def test_once_and_repeated_canonical_check_never_resigns_or_refills(self):
        t=Transport();first=self.run_public(t);saved=read(self.root/'treasury-signed.json',16384,secret=True)
        self.assertEqual(self.run_public(t),first);self.assertEqual(self.calls.count('pilot-treasury-sign'),1);self.assertEqual(len(t.sent),1)
        self.assertEqual(saved,read(self.root/'treasury-signed.json',16384,secret=True))
    def test_broadcast_ack_loss_recovers_original_signature_without_resend(self):
        t=Transport(ackloss=True)
        with self.assertRaises(ValueError):self.run_public(t)
        self.assertFalse((self.root/'treasury-finalized.json').exists());self.assertEqual(self.run_public(t)['signature'],'original-signature')
        self.assertEqual(len(t.sent),1);self.assertEqual(self.calls.count('pilot-treasury-sign'),1)
    def test_expired_original_signature_refuses_replacement(self):
        create(self.root/'treasury-signed.json',encode(SIGNED));t=Transport();t.height=101
        with self.assertRaisesRegex(ValueError,'never re-sign'):self.run_public(t)
        self.assertEqual(t.sent,[]);self.assertNotIn('pilot-treasury-sign',self.calls)
    def test_wrong_genesis_missing_canonical_and_changed_finality_refuse(self):
        create(self.root/'treasury-signed.json',encode(SIGNED));t=Transport(final=True);t.genesis='other'
        with self.assertRaises(ValueError):self.run_public(t)
        t.genesis='genesis';t.canonical=False
        with self.assertRaises(ValueError):self.run_public(t)
        self.assertFalse((self.root/'treasury-finalized.json').exists())
        t.canonical=True;self.run_public(t);t.final=False
        with self.assertRaises(ValueError):self.run_public(t)
        self.assertEqual(t.sent,[])
    def test_sigkill_after_durable_signature_recovers_without_signing(self):
        plan=self.root/'plan.json';create(plan,encode(self.plan))
        script='''import os,signal,sys
from pathlib import Path
from unittest.mock import patch
import pilot_provision as p
from pilot_provision_test import SIGNED,Transport
from wallet_release import read,decode
root=Path(sys.argv[1])
def kill(stage):
 if stage=='signature-durable':os.kill(os.getpid(),signal.SIGKILL)
with patch.object(p,'command',return_value=SIGNED):p.public_allocation(root,decode(read(root/'plan.json',16384)),root/'wallet',root/'password',root/'cold',Transport(),kill)
'''
        child=subprocess.run([sys.executable,'-B','-c',script,str(self.root)],cwd=provision.PROJECT/'tools',capture_output=True,timeout=15)
        self.assertEqual(child.returncode,-9);self.assertFalse((self.root/'treasury-finalized.json').exists())
        t=Transport();self.run_public(t);self.assertNotIn('pilot-treasury-sign',self.calls);self.assertEqual(len(t.sent),1)

class CeremonyTests(unittest.TestCase):
    def setUp(self):
        import pilot_runtime_test as rt
        import pilot_cohort as cohort
        from wallet_release import sha
        # Existing fixture supplies real encrypted keys, native policy and Unix
        # capability. Reprepare a separate ten-slot cohort; no validators/funds.
        rt.RuntimeTests.setUp(self)
        self.ten=self.base/'ten';self.value=cohort.plan(self.value['source_profile'],self.value['tester_profile'],10,10)
        self.digest=sha(encode(self.value));cohort.prepare(self.value,self.ten,self.digest,self.password,rpc_access_file=self.net/'rpc-access.key')
        self.receipt=provision.prepare(self.net,self.ten,self.digest)
    def test_prepare_is_idempotent_and_no_signing_occurs(self):
        with patch.object(provision,'command',side_effect=AssertionError('signer invoked')):
            self.assertEqual(provision.prepare(self.net,self.ten,self.digest),self.receipt)
        plan=provision.decode(read(self.ten/'provision-plan.json',16384,secret=True))
        self.assertEqual([v['amount'] for v in plan['private_deposits']],[5_000_000,5_000_000]);self.assertFalse(plan['automatic_refill'])
    def test_wrong_digest_changed_code_and_live_admission_refuse_before_rpc(self):
        import pilot_cohort as cohort
        with patch.object(provision,'Transport',side_effect=AssertionError('RPC constructed')):
            with self.assertRaises(ValueError):provision.run(self.ten,'0'*64,self.password,self.password,self.password)
            with patch.object(provision.cohort,'code_bytes',return_value=b'changed'):
                with self.assertRaises(ValueError):provision.run(self.ten,self.receipt['provision_sha256'],self.password,self.password,self.password)
            cohort.issue(self.ten,self.digest,'tester-01')
            with self.assertRaises(ValueError):provision.run(self.ten,self.receipt['provision_sha256'],self.password,self.password,self.password)
    def test_other_cohort_size_refused_without_signing(self):
        with self.assertRaises(ValueError):provision.prepare(self.net,self.root,provision.sha(encode(provision.cohort.checked(self.root,provision.cohort.private_json(self.root/'prepared.json')['plan_sha256']))))

if __name__=='__main__':unittest.main()
