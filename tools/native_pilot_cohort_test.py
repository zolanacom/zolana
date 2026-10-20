"""Offline helper guards with explicit native-command mocks, never chain claims.

No compiled faucet is assumed current here. The Linux acceptance exercises the
actual Rust admission and grants separately; these mocks only test orchestration.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_pilot_cohort as cohort
from explorer_model import b58
from wallet_release import atomic,create,encode


class NativeMock:
    """Simulates only the documented offline files, never signatures or funding."""
    def __init__(self):self.calls=[];self.fault=None
    def __call__(self,binary,command,root=None,extra=(),password=None):
        self.calls.append(command)
        if command=='address':
            args=list(map(str,extra));wallet=Path(args[args.index('--wallet')+1]);p=json.loads((wallet.parent/'claims.json').read_bytes())['policy']
            return dict(address=p['source_private_address'],fee_address=p['source_fee_address'])
        if command=='access-info':
            state=json.loads((Path(root)/'admission.json').read_bytes());p=state['policy']
            return dict(invite_required=True,network=p['network'],max_invites=p['max_invites'],
                issued=len(state['invitations']),rpc_audience=p['rpc_audience'],faucet_audience=p['faucet_audience'])
        if command!='invite-issue':raise AssertionError('unexpected non-offline mock command')
        state=json.loads((Path(root)/'admission.json').read_bytes());args=list(map(str,extra))
        if len(state['invitations'])>=state['policy']['max_invites']:raise ValueError('mock native lifetime capacity exhausted')
        output=Path(args[args.index('--output')+1]);bound=args[args.index('--bind-fee')+1] if '--bind-fee' in args else None
        token='invite1_'+chr(65+len(state['invitations']))*43
        invite_id=hashlib.blake2b(token.encode(),digest_size=32).hexdigest()
        export=dict(invitation=token,invite_id=invite_id,redeem_by=2_000_000_000)
        create(output,encode(export))
        if self.fault=='orphan-export':raise RuntimeError('mock crash after export before native commit')
        state['invitations'].append(dict(id=invite_id,redeem_by=export['redeem_by'],bound_fee=bound,revoked=False,member=None))
        atomic(Path(root)/'admission.json',state)
        if self.fault=='lost-ack':raise RuntimeError('mock crash after native commit')
        return dict(invite_id=invite_id,code_written=True,redeem_by=export['redeem_by'])


class Guards(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name).resolve();self.base.chmod(0o700)
        self.native=NativeMock();self.patch=patch.object(cohort,'native',side_effect=self.native)
        self.patch.start();self.addCleanup(self.patch.stop)
        self.root,self.templates,self.config=self.fixture('cohort-060')
    def private(self,path,value):create(path,encode(value))
    def template(self,path,value):self.private(path,value);path.chmod(0o444)
    def fixture(self,name):
        parent=self.base/name.replace('cohort-','case-');parent.mkdir(mode=0o700)
        root=parent/name;root.mkdir(mode=0o700)
        for sub in ('faucet','relay'):(root/sub).mkdir(mode=0o700)
        templates=parent/'templates';templates.mkdir(mode=0o700)
        config=parent/'base.json';network=dict(network=[67]*32,genesis_hash=b58(bytes([9])*32))
        self.template(config,dict(network=network))
        rpc_port,faucet_port=cohort.MODES[name]
        source=dict(format='native-wallet-profile-v1',key_mode='user-wallet-v1',label='explicit mock source',**network,
            program=b58(bytes([3])*32),pool=b58(bytes([4])*32),pool_format='NPOOL004',recipient_withdrawals=True,
            rpc=dict(transport='loopback-http',url='http://127.0.0.1:19999'))
        public=dict(source,invite_required=True,private_send_transport='native-inline-v1',
            rpc=dict(transport='https',url=f'https://127.0.0.1:{rpc_port}'),
            faucet=dict(transport='https',url=f'https://127.0.0.1:{faucet_port}'),local_tls_ca_pem='MOCK CA ONLY NO LISTENER')
        operator={key:source[key] for key in ('network','genesis_hash','program','pool','pool_format','recipient_withdrawals')}
        operator.update(format='native-gateway-operator-fixture-v1',fixture_keys_are_public=True)
        relay=dict(format='native-shielded-relay-v1',network=network,network_file=str(root/'operator.json'),
            native_profile=str(root/'public-profile.json'),payer_file=str(root.parent/'relay.key'),
            binary=str(cohort.PREFIX/'bin/native-shielded'),payer=[5]*32,fee=3_000_000,gross_cap=100_000,
            max_jobs=60,per_member=6,pool_format='NPOOL004',rpc=source['rpc']['url'],native_ingress=['127.0.0.1:20001'])
        for local,sealed,value in [('source.json','source-profile.json',source),('public-profile.json','public-profile.json',public),
                                   ('operator.json','operator.json',operator),('relay/config.json','relay.json',relay)]:
            self.private(root/local,value);self.template(templates/sealed,value)
        self.private(root/'faucet/profile.json',source)
        policy=dict(format='native-test-faucet-native-v1',network=network,source_private_address='npriv1'+'A'*100,
            source_fee_address=b58(bytes([6])*32),max_claims=10,invite_required=True,private_amount=20_000_000,
            gas_amount=0,max_attempts=3,payment_cap=150_000_000)
        admission=dict(policy=dict(format='native-invited-testnet-v1',network=network,max_invites=10,daily_admissions=10,
            rpc_per_minute=2000,rpc_audience=public['rpc']['url'],faucet_audience=public['faucet']['url']),
            invitations=[],last_time=0,admissions={},global_rpc={},global_faucet={},edge=[])
        self.private(root/'faucet/claims.json',dict(policy=policy,claims=[]))
        self.private(root/'faucet/admission.json',admission)
        create(root/'faucet/wallet.enc.json',b'explicit mock encrypted wallet, not a native seed')
        create(root/'password',b'explicit mock disposable password')
        return root,templates,config
    def build(self,root=None,templates=None,config=None):
        return cohort.build_plan(root or self.root,templates or self.templates,base_config=config or self.config)
    def prepare(self):
        plan=self.build();self.template(self.templates/'plan.json',plan);self.digest=cohort.hash_value(plan)
        cohort.initialize_issuance(self.root,self.digest,self.templates,base_config=self.config)
        return plan
    def issue(self,slot='tester-01',bound=None):
        return cohort.issue(self.root,self.digest,slot,bound,self.templates,base_config=self.config)
    def audit(self):return cohort.audit(self.root,self.digest,self.templates,base_config=self.config)
    def snapshots(self):
        return {p.relative_to(self.root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.root.rglob('*') if p.is_file() and p.name!='issuance.lock'}
    def test_hash_is_sorted_compact_no_newline_and_budget_is_exact(self):
        self.assertEqual(cohort.hash_value({'b':2,'a':1}),hashlib.sha256(b'{"a":1,"b":2}').hexdigest())
        with self.assertRaises(ValueError):cohort.hash_value({'nan':float('nan')})
        plan=self.build();self.assertEqual(set(plan),cohort.PLAN_KEYS)
        self.assertEqual((plan['private_grant'],plan['gas_grant'],plan['private_budget'],plan['public_budget']),
            (20_000_000,0,200_000_000,4_500_000_000))
        for change in (dict(public_budget=150_000_000),dict(private_grant=1_000_000),dict(cohort_size=True),dict(extra='unreviewed')):
            with self.assertRaises(ValueError):cohort.validate_plan(dict(plan,**change))
        self.assertEqual(set(self.native.calls),{'access-info','address'})
    def test_fixed_rehearsal_audiences_separate_its_plan_from_unused_pilot(self):
        pilot=self.build();root,templates,config=self.fixture('cohort-060-rehearsal')
        rehearsal=self.build(root,templates,config)
        self.assertNotEqual(cohort.hash_value(pilot),cohort.hash_value(rehearsal))
        wrong=json.loads((templates/'public-profile.json').read_bytes());wrong['rpc']['url']='https://127.0.0.1:39443'
        (templates/'public-profile.json').chmod(0o600);atomic(templates/'public-profile.json',wrong)
        with self.assertRaises(ValueError):self.build(root,templates,config)
    def test_named_slot_retry_reuses_export_and_changed_binding_never_reissues(self):
        self.prepare();first=self.issue();snapshot=self.snapshots();calls=self.native.calls.count('invite-issue')
        self.assertEqual(self.issue(),first);self.assertEqual(self.snapshots(),snapshot)
        self.assertEqual(self.native.calls.count('invite-issue'),calls)
        with self.assertRaises(ValueError):self.issue(bound=b58(bytes([7])*32))
        self.assertEqual(self.native.calls.count('invite-issue'),calls)
        self.assertNotIn('invitation',first)
    def test_reserved_slot_survives_pre_call_failure_and_same_binding_can_continue(self):
        self.prepare();actual=cohort.native
        # Explicitly mock a failure before any native commit or export exists.
        def interrupted(binary,command,*args,**kwargs):
            if command=='invite-issue':raise RuntimeError('mock interruption before native call')
            return actual(binary,command,*args,**kwargs)
        with patch.object(cohort,'native',side_effect=interrupted),self.assertRaises(RuntimeError):self.issue()
        state=cohort.private_json(self.root/'issuance.json')
        self.assertEqual(state['slots'],{'tester-01':{'bind_fee':None}})
        self.assertEqual(self.issue()['slot'],'tester-01');self.assertEqual(self.audit()['issued'],1)
    def test_lost_native_commit_ack_reuses_the_same_original_export(self):
        self.prepare();self.native.fault='lost-ack'
        with self.assertRaises(RuntimeError):self.issue()
        original=(self.root/'invitations/tester-01.json').read_bytes();snapshot=self.snapshots()
        self.native.fault=None;self.issue()
        self.assertEqual((self.root/'invitations/tester-01.json').read_bytes(),original)
        self.assertEqual(self.snapshots(),snapshot);self.assertEqual(self.native.calls.count('invite-issue'),1)
    def test_orphan_export_and_missing_committed_export_fail_without_token_replacement(self):
        self.prepare();self.native.fault='orphan-export'
        with self.assertRaises(RuntimeError):self.issue()
        before=self.snapshots();self.native.fault=None
        with self.assertRaises(ValueError):self.issue()
        with self.assertRaises(ValueError):self.audit()
        self.assertEqual(self.snapshots(),before);self.assertEqual(self.native.calls.count('invite-issue'),1)
    def test_missing_committed_export_never_refunds_or_regenerates_a_slot(self):
        self.prepare();self.issue();(self.root/'invitations/tester-01.json').unlink()
        before=self.snapshots()
        with self.assertRaises(ValueError):self.issue()
        with self.assertRaises(ValueError):self.audit()
        self.assertEqual(self.snapshots(),before);self.assertEqual(self.native.calls.count('invite-issue'),1)
    def test_missing_issuance_journal_is_not_recreated_even_before_first_invite(self):
        self.prepare();(self.root/'issuance.json').unlink()
        with self.assertRaises(ValueError):cohort.initialize_issuance(self.root,self.digest,self.templates,base_config=self.config)
        self.assertFalse((self.root/'issuance.json').exists())
        with self.assertRaises(OSError):self.issue()
        self.assertEqual(self.native.calls.count('invite-issue'),0)
    def test_only_ten_named_slots_and_revocation_does_not_restore_capacity(self):
        self.prepare()
        for slot in cohort.SLOTS:self.issue(slot)
        self.assertEqual((self.audit()['reserved_slots'],self.audit()['issued']),(10,10))
        state=cohort.private_json(self.root/'faucet/admission.json');state['invitations'][0]['revoked']=True
        atomic(self.root/'faucet/admission.json',state)
        self.assertTrue(self.issue()['revoked'])
        for name in ('tester-11','tester-1','../tester-01','new-capacity'):
            with self.assertRaises(ValueError):self.issue(name)
        self.assertEqual(self.native.calls.count('invite-issue'),10)
    def test_changed_authority_password_or_policy_fails_without_issuing(self):
        self.prepare();original=(self.root/'password').read_bytes()
        (self.root/'password').write_bytes(b'changed mock password')
        with self.assertRaises(ValueError):self.issue()
        (self.root/'password').write_bytes(original)
        state=cohort.private_json(self.root/'faucet/claims.json');state['policy']['private_amount']=1_000_000
        atomic(self.root/'faucet/claims.json',state)
        with self.assertRaises(ValueError):self.audit()
        self.assertEqual(self.native.calls.count('invite-issue'),0)
    def test_runtime_endpoint_repins_are_allowed_but_policy_changes_are_not(self):
        self.prepare()
        for name in ('source.json','faucet/profile.json'):
            value=cohort.private_json(self.root/name);value['rpc']['url']='http://127.0.0.1:29999';atomic(self.root/name,value)
        value=cohort.private_json(self.root/'relay/config.json');value['rpc']='http://127.0.0.1:29999';value['native_ingress']=['127.0.0.1:30001']
        atomic(self.root/'relay/config.json',value)
        report=self.audit();self.assertFalse(report['funding_verified']);self.assertFalse(report['network_verified'])
        value['fee']=4_000_000;atomic(self.root/'relay/config.json',value)
        with self.assertRaises(ValueError):self.audit()
    def test_symlink_private_material_and_wrong_plan_hash_fail_before_issue(self):
        self.prepare();password=self.root/'password';password.rename(self.root/'kept-password');password.symlink_to(self.root/'kept-password')
        with self.assertRaises(OSError):self.audit()
        password.unlink();(self.root/'kept-password').rename(password)
        with self.assertRaises(ValueError):cohort.issue(self.root,'0'*64,'tester-01',templates=self.templates,base_config=self.config)
        self.assertEqual(self.native.calls.count('invite-issue'),0)

    def test_durable_progress_audit_is_explicitly_not_canonical_funding_verification(self):
        # Codec-only fixture: no native signed claim or chain execution is claimed.
        fee=b58(bytes([7])*32);claims={'claims':[{'fee_address':fee}]}
        claim_id=hashlib.blake2b(fee.encode(),digest_size=32).hexdigest()
        path=self.root/'faucet'/(claim_id+'.json')
        progress=dict(gas_attempts=0,gas=None,gas_done=False,private_attempts=0,proof=None,private_done=False,submission_started=False)
        self.private(path,progress)
        self.assertEqual(cohort.progress_counts(self.root,claims)['queued'],1)
        progress.update(gas_done=True,private_attempts=1,proof=[3]*9222,submission_started=True);atomic(path,progress)
        self.assertEqual(cohort.progress_counts(self.root,claims)['funding'],1)
        progress['private_done']=True;atomic(path,progress)
        self.assertEqual(cohort.progress_counts(self.root,claims)['ready'],1)
        progress['gas_attempts']=1;atomic(path,progress);original=path.read_bytes()
        with self.assertRaises(ValueError):cohort.progress_counts(self.root,claims)
        self.assertEqual(path.read_bytes(),original)


if __name__=='__main__':unittest.main()
