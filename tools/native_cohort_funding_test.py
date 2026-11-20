#!/usr/bin/env python3
"""Read-only mock RPC tests; cryptographic cases use real Ed25519 signatures."""
import base64
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

import native_cohort_funding as funding
from native_pilot_cohort import hash_value

CRYPTO=importlib.util.find_spec('cryptography') is not None


class WireTests(unittest.TestCase):
    def test_exact_legacy_transfer_layout_and_canonical_base58(self):
        payer,target,blockhash=[funding.b58(bytes([x])*32) for x in (1,2,3)]
        message=funding.message(payer,target,blockhash,4_500_000_000)
        self.assertEqual(len(message),150)
        self.assertEqual(message[:4],bytes([1,0,1,3]))
        self.assertEqual(message[4:36],bytes([1])*32)
        self.assertEqual(message[36:68],bytes([2])*32)
        self.assertEqual(message[68:100],bytes(32))
        self.assertEqual(message[100:132],bytes([3])*32)
        self.assertEqual(message[132:138],bytes([1,2,2,0,1,12]))
        self.assertEqual(struct.unpack('<IQ',message[138:]),(2,4_500_000_000))
        for raw in (bytes(32),bytes([255])*32,b'\0'+bytes([5])*63):
            self.assertEqual(funding.un58(funding.b58(raw),len(raw)),raw)
        for bad in ('0','1'+payer,payer+' ',False):
            with self.assertRaises(ValueError):funding.un58(bad,32)


class PlanSizeTests(unittest.TestCase):
    """Plan-size guards that run before any signer, journal or allocation RPC."""
    def plan(self,size):
        value=dict(format='zolana-native-cohort-plan-v1',network={'network':[67]*32,
            'genesis_hash':funding.b58(bytes([9])*32)},pool_format='NPOOL004',cohort_size=size,
            private_grant=20_000_000,gas_grant=0,attempts=3,payment_cap=150_000_000,
            private_budget=size*20_000_000,public_budget=size*450_000_000,
            source_private_address='npriv1'+'A'*90,source_fee_address=funding.b58(bytes([6])*32))
        for name in ('source_wallet','password','source_profile','public_profile','relay_policy','faucet_policy','admission_policy'):
            value[name+'_sha256']='a'*64
        return value

    def test_only_the_scaled_budget_of_a_validated_cohort_size_reaches_allocation(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();root.chmod(0o700);payer=funding.b58(bytes([1])*32);calls=[]
            def rpc(method,params):
                calls.append(method);return funding.b58(bytes([1])*32)  # A foreign genesis stops before any signer.
            plan=self.plan(200);self.assertEqual(plan['public_budget'],90_000_000_000)
            message=funding.message(payer,plan['source_fee_address'],funding.b58(bytes([3])*32),plan['public_budget'])
            self.assertEqual(len(message),150);self.assertEqual(struct.unpack('<IQ',message[138:]),(2,90_000_000_000))
            invalid=[dict(plan,public_budget=4_500_000_000),dict(plan,private_budget=200_000_000),dict(plan,cohort_size=10),
                     dict(plan,cohort_size=True),self.plan(0),self.plan(501)]
            for value in invalid:
                with self.subTest(size=value['cohort_size']),self.assertRaises(ValueError):
                    funding.fund_public(root,value,rpc,root/'relay.key',payer)
            self.assertEqual(calls,[]);self.assertFalse((root/'funding').exists())
            for size in (10,200,500):
                with self.subTest(size=size),self.assertRaisesRegex(ValueError,'genesis mismatch'):
                    funding.fund_public(root,self.plan(size),rpc,root/'relay.key',payer)
            self.assertEqual(calls,['getGenesisHash']*3);self.assertFalse((root/'funding/public.json').exists())


class RPC:
    def __init__(self,plan,payer):
        self.plan=plan;self.payer=payer;self.calls=[];self.packets=[]
        self.target_balance=0;self.payer_balance=10_000_000_000
        self.height=100;self.fee=5000;self.final=False;self.drop=False
        self.genesis=plan['network']['genesis_hash'];self.packet=None
        self.bad_transaction=False;self.meta_error=None

    def __call__(self,method,params):
        self.calls.append((method,copy.deepcopy(params)))
        if method=='getGenesisHash':return self.genesis
        if method=='getBalance':return {'value':self.target_balance if params[0]==self.plan['source_fee_address'] else self.payer_balance}
        if method=='getLatestBlockhash':return {'value':{'blockhash':funding.b58(bytes([8])*32),'lastValidBlockHeight':200}}
        if method=='getFeeForMessage':
            raw=base64.b64decode(params[0],validate=True)
            assert len(raw)==150 and raw[132:138]==bytes([1,2,2,0,1,12])
            return {'value':self.fee}
        if method=='getBlockHeight':return self.height
        if method=='getSignatureStatuses':
            return {'value':[{'slot':77,'confirmationStatus':'finalized','err':None} if self.final else None]}
        if method=='getTransaction':
            return dict(slot=77,transaction=[self.packet if not self.bad_transaction else 'changed','base64'],
                        meta={'err':self.meta_error,'fee':self.fee})
        if method=='sendTransaction':
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            self.packet=params[0];self.packets.append(self.packet)
            raw=base64.b64decode(self.packet,validate=True)
            assert len(raw)==215 and raw[0]==1
            Ed25519PublicKey.from_public_bytes(raw[69:101]).verify(raw[1:65],raw[65:])
            assert raw[101:133]==funding.un58(self.plan['source_fee_address'],32)
            assert struct.unpack('<IQ',raw[-12:])==(2,self.plan['public_budget'])
            assert params[1]==dict(encoding='base64',skipPreflight=False,preflightCommitment='confirmed',maxRetries=0)
            if self.drop:self.drop=False;raise TimeoutError('deliberately lost admission response')
            return funding.b58(raw[1:65])
        raise AssertionError('unexpected RPC '+method)


@unittest.skipUnless(CRYPTO,'cryptography unavailable locally; run real Ed25519 cases on Linux')
class FundingTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        private=Ed25519PrivateKey.from_private_bytes(bytes([7])*32)
        public=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        self.payer=funding.b58(public);self.key=self.root/'relay.key'
        self.key.write_text(json.dumps(list(bytes([7])*32+public)));self.key.chmod(0o600)
        self.plan=dict(format='zolana-native-cohort-plan-v1',network={'network':[67]*32,
            'genesis_hash':funding.b58(bytes([9])*32)},pool_format='NPOOL004',cohort_size=10,
            private_grant=20_000_000,gas_grant=0,attempts=3,payment_cap=150_000_000,
            private_budget=200_000_000,public_budget=4_500_000_000,
            source_private_address='npriv1'+'A'*90,source_fee_address=funding.b58(bytes([6])*32))
        for name in ('source_wallet','password','source_profile','public_profile','relay_policy','faucet_policy','admission_policy'):
            self.plan[name+'_sha256']='a'*64
        self.rpc=RPC(self.plan,self.payer)

    def run_funding(self,**overrides):
        args=dict(root=self.root,plan=self.plan,rpc=self.rpc,payer_file=self.key,expected_payer=self.payer)
        args.update(overrides)
        return funding.fund_public(**args)

    def pending(self):
        with self.assertRaises(funding.FundingPending):self.run_funding()
        self.journal=self.root/'funding/public.json'
        return self.journal.read_bytes()

    def test_real_signed_packet_is_durable_before_submission_and_recovers_lost_ack(self):
        original_call=self.rpc.__call__
        def rpc(method,params):
            if method=='sendTransaction':
                journal=self.root/'funding/public.json'
                self.assertEqual(stat.S_IMODE(journal.stat().st_mode),0o600)
                self.assertEqual(json.loads(journal.read_bytes())['transaction'],params[0])
            return original_call(method,params)
        self.rpc.drop=True
        with self.assertRaises(funding.FundingPending):self.run_funding(rpc=rpc)
        journal=self.root/'funding/public.json';original=journal.read_bytes()
        self.rpc.final=True
        with patch.object(funding,'signer',side_effect=AssertionError('must never re-sign')):
            receipt=self.run_funding()
        self.assertEqual(receipt['amount'],4_500_000_000)
        self.assertEqual(receipt['plan_sha256'],hash_value(self.plan))
        self.assertEqual(receipt['slot'],77);self.assertEqual(receipt['fee'],5000)
        self.assertEqual(journal.read_bytes(),original);self.assertEqual(len(self.rpc.packets),1)
        self.assertTrue((self.root/'funding/public-finalized.json').exists())

    def test_pending_retry_replays_exact_packet_without_new_blockhash_or_signature(self):
        original=self.pending();first_calls=len(self.rpc.calls)
        with patch.object(funding,'signer',side_effect=AssertionError('must never re-sign')):
            with self.assertRaises(funding.FundingPending):self.run_funding()
        self.assertEqual(self.rpc.packets,[self.rpc.packets[0]]*2)
        self.assertEqual(self.journal.read_bytes(),original)
        self.assertFalse(any(method in ('getLatestBlockhash','getFeeForMessage','getBalance')
                             for method,_ in self.rpc.calls[first_calls:]))

    def test_exact_finalized_receipt_never_refills_even_after_reservoir_is_spent(self):
        self.pending();self.rpc.final=True;first=self.run_funding()
        self.rpc.target_balance=0;self.rpc.payer_balance=0
        with patch.object(funding,'signer',side_effect=AssertionError('must never re-sign')):
            self.assertEqual(self.run_funding(),first)
        self.assertEqual(len(self.rpc.packets),1)
        self.journal.unlink()
        with self.assertRaisesRegex(ValueError,'journal missing'):self.run_funding()
        self.assertEqual(len(self.rpc.packets),1)

    def test_two_hundred_wallet_plan_allocates_its_scaled_budget_exactly_once(self):
        self.plan.update(cohort_size=200,private_budget=4_000_000_000,public_budget=90_000_000_000)
        short=self.root/'short';short.mkdir(mode=0o700);rpc=RPC(self.plan,self.payer)
        rpc.payer_balance=90_000_000_000+5000+funding.RETAIN-1
        with self.assertRaises(ValueError):self.run_funding(root=short,rpc=rpc)
        self.assertEqual(rpc.packets,[]);self.assertFalse((short/'funding/public.json').exists())
        self.rpc.payer_balance=90_000_000_000+5000+funding.RETAIN
        self.pending();self.rpc.final=True;receipt=self.run_funding()
        self.assertEqual(receipt['amount'],90_000_000_000)
        self.assertEqual(receipt['plan_sha256'],hash_value(self.plan))
        ten=dict(self.plan,cohort_size=10,private_budget=200_000_000,public_budget=4_500_000_000)
        with self.assertRaises(ValueError):self.run_funding(plan=ten)
        self.assertEqual(len(self.rpc.packets),1)

    def test_tampered_plan_target_policy_signature_and_packet_fail_without_broadcast(self):
        original=self.pending()
        for key,changed in [('source_fee_address',funding.b58(bytes([3])*32)),('public_budget',4_500_000_001),
                            ('password_sha256','b'*64)]:
            plan={**self.plan,key:changed}
            with self.assertRaises(ValueError):self.run_funding(plan=plan)
        intent=json.loads(original)
        for key,changed in [('target',funding.b58(bytes([3])*32)),('signature',funding.b58(bytes([1])*64)),
                            ('fee',10_001),('transaction',base64.b64encode(bytes(215)).decode())]:
            self.journal.write_bytes(funding.canonical({**intent,key:changed}))
            with self.assertRaises(ValueError):self.run_funding()
        self.journal.write_bytes(original)
        self.assertEqual(len(self.rpc.packets),1)

    def test_existing_target_balance_and_interrupted_preparation_never_reallocate(self):
        self.rpc.target_balance=1
        with self.assertRaisesRegex(ValueError,'zero finalized'):self.run_funding()
        self.rpc.target_balance=0
        with self.assertRaisesRegex(ValueError,'journal missing'):self.run_funding()
        self.assertEqual(self.rpc.packets,[])

    def test_expired_or_uncertain_original_identity_never_resigns(self):
        original=self.pending();self.rpc.height=201
        with patch.object(funding,'signer',side_effect=AssertionError('must never re-sign')):
            with self.assertRaisesRegex(ValueError,'expired or uncertain'):self.run_funding()
        self.assertEqual(self.journal.read_bytes(),original);self.assertEqual(len(self.rpc.packets),1)
        self.rpc.final=True;self.rpc.bad_transaction=True
        with self.assertRaisesRegex(ValueError,'exact finalized'):self.run_funding()
        self.assertEqual(len(self.rpc.packets),1)

    def test_canonical_packet_failure_or_changed_fee_preserves_original_journal(self):
        original=self.pending();self.rpc.final=True
        self.rpc.meta_error={'InstructionError':[0,'Custom']}
        with self.assertRaisesRegex(ValueError,'exact finalized'):self.run_funding()
        self.rpc.meta_error=None;self.rpc.fee=5001
        with self.assertRaisesRegex(ValueError,'exact finalized'):self.run_funding()
        self.assertEqual(self.journal.read_bytes(),original)
        self.assertFalse((self.root/'funding/public-finalized.json').exists())

    def test_signer_genesis_fee_cap_and_retained_balance_are_checked_before_journal(self):
        cases=('wrong-suffix','wrong-payer','wrong-genesis','fee-cap','insufficient-retain')
        original=json.loads(self.key.read_text())
        for case in cases:
            child=self.root/case;child.mkdir(mode=0o700);rpc=RPC(self.plan,self.payer)
            expected=self.payer
            if case=='wrong-suffix':self.key.write_text(json.dumps(original[:32]+[0]*32))
            else:self.key.write_text(json.dumps(original))
            if case=='wrong-payer':expected=funding.b58(bytes([1])*32)
            if case=='wrong-genesis':rpc.genesis=funding.b58(bytes([1])*32)
            if case=='fee-cap':rpc.fee=10_001
            if case=='insufficient-retain':rpc.payer_balance=self.plan['public_budget']+5000+funding.RETAIN-1
            with self.assertRaises(ValueError):self.run_funding(root=child,rpc=rpc,expected_payer=expected)
            self.assertFalse((child/'funding/public.json').exists());self.assertEqual(rpc.packets,[])

    def test_allocation_lock_is_exclusive_and_unsafe_journal_cannot_be_reused(self):
        self.pending();lock=self.root/'funding/public.lock'
        fd=os.open(lock,os.O_RDWR)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):self.run_funding()
        finally:os.close(fd)
        self.journal.chmod(0o644)
        with self.assertRaises(ValueError):self.run_funding()
        self.assertEqual(len(self.rpc.packets),1)


if __name__=='__main__':unittest.main()
