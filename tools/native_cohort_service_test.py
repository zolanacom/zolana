"""LOCAL-060 pure policy, lifecycle and real-ACK matching guards; no listeners."""
import copy
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import native_linux_service as base
import native_cohort_service as service
import native_cohort_fault as fault


def key(number):return base.b58(bytes([number])*32)
def network():return dict(network=[67]*32,genesis_hash=key(4))
def config():return dict(network=network(),gateway_uid=os.getuid(),relay_public_key=key(5),test_mode=False)
def private_address():return 'npriv1'+'2'*110

def policies():
    grant=dict(format='native-test-faucet-native-v1',network=network(),source_private_address=private_address(),
        source_fee_address=key(6),max_claims=10,invite_required=True,private_amount=20_000_000,
        gas_amount=0,max_attempts=3,payment_cap=150_000_000)
    admission=dict(format='native-invited-testnet-v1',network=network(),max_invites=10,daily_admissions=3,
        rpc_per_minute=2000,rpc_audience=service.audience('rpc'),faucet_audience=service.audience('faucet'))
    return grant,admission

def plan():
    grant,admission=policies()
    return dict(format='zolana-native-cohort-plan-v1',network=network(),pool_format='NPOOL004',cohort_size=10,
        private_grant=20_000_000,gas_grant=0,attempts=3,payment_cap=150_000_000,private_budget=200_000_000,
        public_budget=4_500_000_000,source_private_address=private_address(),source_fee_address=key(6),
        source_wallet_sha256=service.digest(b'fixed encrypted source'),password_sha256=service.digest(b'fixed private password'),
        source_profile_sha256='a'*64,public_profile_sha256='b'*64,relay_policy_sha256='c'*64,
        faucet_policy_sha256=service.hash_value(grant),admission_policy_sha256=service.hash_value(admission))

def funding(value):
    return dict(format='zolana-native-cohort-funding-ready-v1',plan_sha256=service.hash_value(value),network=network(),
        source_private_address=value['source_private_address'],source_fee_address=value['source_fee_address'],
        private_observed=200_000_000,public_observed=4_500_000_000,finalized_slot=650,checked_at=1000,canonical_funding=True)

def binding(value,receipt):
    return dict(format='zolana-native-cohort-service-v1',base_config_sha256='d'*64,
        plan_sha256=service.hash_value(value),funding_ready_sha256=service.hash_value(receipt))


def save(path,value,raw=False):
    path.write_bytes(value if raw else service.encode(value));path.chmod(0o600)


class PolicyGuards(unittest.TestCase):
    def setUp(self):service.select_mode(False);self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
    def tearDown(self):service.select_mode(False);self.temp.cleanup()
    def test_canonical_hash_has_no_newline_and_is_order_independent(self):
        self.assertEqual(service.hash_value(dict(b=2,a=1)),hashlib.sha256(b'{"a":1,"b":2}').hexdigest())
        self.assertEqual(service.hash_value(dict(a=1,b=2)),service.hash_value(dict(b=2,a=1)))
    def test_exact_ten_person_native_budget_and_original_binding(self):
        value=plan();receipt=funding(value);sealed=binding(value,receipt)
        service.validate_plan(value,config(),base);service.validate_binding(sealed,value,receipt,'d'*64)
        for field,bad in [('cohort_size',11),('gas_grant',150_000_000),('private_grant',1_000_000),
                          ('attempts',4),('private_budget',400_000_000),('public_budget',4_500_000_001),('gas_grant',False)]:
            changed=dict(value);changed[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):service.validate_plan(changed,config(),base)
        for field in ('base_config_sha256','plan_sha256','funding_ready_sha256'):
            changed=dict(sealed);changed[field]='e'*64
            with self.subTest(field=field),self.assertRaises(ValueError):service.validate_binding(changed,value,receipt,'d'*64)
    def test_first_activation_is_fresh_unused_and_restart_uses_original_historical_receipt(self):
        value=plan();receipt=funding(value);sealed=binding(value,receipt)
        with mock.patch.object(service,'ROOT',self.root):
            activation=service.activate(base,config(),sealed,value,receipt,{'claims':[]},1100)
            original=(self.root/'activation.json').read_bytes()
            later=service.activate(base,config(),sealed,value,receipt,{'claims':[{}]*10},100_000)
            self.assertEqual(activation,later);self.assertEqual((self.root/'activation.json').read_bytes(),original)
            changed=dict(sealed,plan_sha256='f'*64)
            with self.assertRaises(ValueError):service.activate(base,config(),changed,value,receipt,{'claims':[]},100_000)
        self.assertEqual((self.root/'activation.json').read_bytes(),original)
    def test_stale_insufficient_future_or_used_first_cohort_cannot_activate(self):
        value=plan();receipt=funding(value);sealed=binding(value,receipt)
        with mock.patch.object(service,'ROOT',self.root):
            for changed,now,claims in [(receipt,4601,[]),(dict(receipt,private_observed=199_999_999),1100,[]),
                    (dict(receipt,public_observed=4_499_999_999),1100,[]),(receipt,999,[]),(receipt,1100,[{}])]:
                with self.subTest(now=now,claims=claims),self.assertRaises(ValueError):
                    service.activate(base,config(),sealed,value,changed,{'claims':claims},now)
            self.assertFalse((self.root/'activation.json').exists())
    def test_policy_hashes_wallet_pins_and_lifetime_limits_are_checked_without_seed_decryption(self):
        (self.root/'faucet').mkdir(mode=0o700);(self.root/'relay').mkdir(mode=0o700)
        grant,admission=policies();claims=dict(policy=grant,claims=[])
        save(self.root/'faucet/wallet.enc.json',b'fixed encrypted source',True)
        save(self.root/'password',b'fixed private password',True)
        save(self.root/'faucet/claims.json',claims);save(self.root/'faucet/admission.json',dict(policy=admission,invitations=[]))
        with mock.patch.object(service,'ROOT',self.root):
            self.assertEqual(service.authority(base,config(),plan())['claims'],[])
            altered=copy.deepcopy(claims);altered['policy']['format']='native-test-faucet-v1';save(self.root/'faucet/claims.json',altered)
            with self.assertRaises(ValueError):service.authority(base,config(),plan())
            save(self.root/'faucet/claims.json',dict(claims,claims=[{}]*11))
            with self.assertRaises(ValueError):service.authority(base,config(),plan())
            save(self.root/'faucet/claims.json',claims);save(self.root/'faucet/wallet.enc.json',b'replaced encrypted source',True)
            with self.assertRaises(ValueError):service.authority(base,config(),plan())
    def test_fixed_modes_keep_rehearsal_consumption_separate_from_pilot(self):
        pilot,rehearsal=service.fixed_mode(False),service.fixed_mode(True)
        self.assertNotEqual(pilot['root'],rehearsal['root']);self.assertNotEqual(pilot['etc'],rehearsal['etc'])
        self.assertEqual(pilot['ports'],{'rpc':39443,'faucet':39444})
        self.assertEqual(rehearsal['ports'],{'rpc':40443,'faucet':40444})
        for bad in (None,'/tmp/alternate',1):
            with self.assertRaises(ValueError):service.fixed_mode(bad)
        for rehearsal in (False,True):
            mode=service.fixed_mode(rehearsal);units=service.units(rehearsal);unit=units[mode['unit']]
            self.assertIn('ReadWritePaths='+str(mode['root'])+'\n',unit)
            self.assertNotIn('ReadWritePaths=/var/lib/zolana-native-058/gateway\n',unit)
            self.assertIn('JoinsNamespaceOf='+service.VALUNIT,unit)
            self.assertIn('BindsTo='+service.VALUNIT,unit);self.assertIn('RestartSec=10s',unit)
            self.assertIn('TemporaryFileSystem=/dev/shm:rw,nodev,nosuid,mode=1777',unit)
            self.assertEqual('--rehearsal' in unit,rehearsal)
            for name,port in mode['ports'].items():self.assertIn('ListenStream=127.0.0.1:'+str(port),units[mode['sockets'][name]])
    def test_explicit_cohort_fd_ports_do_not_change_old_default_listener_pins(self):
        class Stream:
            family=socket.AF_INET
            def __init__(self,fileno):self.fd=fileno
            def getsockopt(self,level,name):return socket.SOCK_STREAM if name==socket.SO_TYPE else 1
            def getsockname(self):return ('127.0.0.1',39443 if self.fd==3 else 39444)
            def fileno(self):return self.fd
            def close(self):pass
        env=dict(LISTEN_PID=str(os.getpid()),LISTEN_FDS='2',LISTEN_FDNAMES='rpc:faucet')
        with mock.patch.object(base.os,'set_inheritable'):
            self.assertEqual(set(base.activated_sockets(env,Stream,service.PORTS)),{'rpc','faucet'})
            with self.assertRaises(ValueError):base.activated_sockets(env,Stream)
        self.assertEqual(base.PORTS,{'rpc':38443,'faucet':38444})
        for ports in ({'rpc':39443,'faucet':39443},{'rpc':39443},{'rpc':True,'faucet':39444}):
            with self.assertRaises(ValueError):base.activated_sockets(env,Stream,ports)

    def test_ready_endpoint_repin_writes_only_new_cohort_profiles_and_keeps_budget_authority(self):
        templates=self.root/'sealed';identity=dict(**network(),program=key(7),pool=key(8),pool_format='NPOOL004',recipient_withdrawals=True)
        source=dict(format='native-wallet-profile-v1',label='Source',key_mode='user-wallet-v1',**identity,
            rpc=dict(transport='loopback-http',url='http://127.0.0.1:10000'))
        public=dict(source,label='Pilot',rpc=dict(transport='https',url=service.audience('rpc')),
            faucet=dict(transport='https',url=service.audience('faucet')),invite_required=True,
            private_send_transport='native-inline-v1')
        operator=dict(format='native-gateway-operator-fixture-v1',fixture_keys_are_public=True,**identity)
        relay=dict(format='native-shielded-relay-v1',network=network(),network_file=str(self.root/'operator.json'),
            native_profile=str(self.root/'public-profile.json'),payer=[5]*32,payer_file=str(base.GWROOT/'relay.key'),
            binary=str(service.PREFIX/'bin/native-shielded'),fee=3_000_000,gross_cap=100_000,max_jobs=60,per_member=6,
            pool_format='NPOOL004',rpc=source['rpc']['url'],native_ingress=['127.0.0.1:11000'])
        sealed={templates/'source-profile.json':service.encode(source),templates/'public-profile.json':service.encode(public),
            templates/'operator.json':service.encode(operator),templates/'relay.json':service.encode(relay),
            base.ETC/'server.crt':b'original certificate'}
        owned={self.root/'source.json':service.encode(source),self.root/'faucet/profile.json':service.encode(source),
            self.root/'public-profile.json':service.encode(public),self.root/'operator.json':service.encode(operator),
            self.root/'relay/config.json':service.encode(relay),base.GWROOT/'server.crt':b'original certificate',
            base.GWROOT/'server.key':b'private key',base.GWROOT/'relay.key':service.encode([9]*32+[5]*32)}
        value=dict(plan(),source_profile_sha256=service.hash_value(source),public_profile_sha256=service.hash_value(public),
            relay_policy_sha256=service.hash_value(relay))
        ready=dict(peers=[dict(rpc='127.0.0.1:'+str(20000+i),native_ingress='127.0.0.1:'+str(21000+i)) for i in range(3)])
        with mock.patch.object(service,'ROOT',self.root),mock.patch.object(service,'ETC',templates),\
             mock.patch.object(base,'sealed',side_effect=lambda path,*args:sealed[path]),\
             mock.patch.object(base,'owned',side_effect=lambda path,*args:owned[path]),mock.patch.object(base,'atomic') as write:
            gate,rpc=service.prepare(base,config(),value,ready)
            self.assertIsNone(gate);self.assertEqual(rpc,'http://127.0.0.1:20000')
            self.assertEqual([call.args[0] for call in write.call_args_list],
                [self.root/'source.json',self.root/'faucet/profile.json',self.root/'relay/config.json'])
            updated=write.call_args_list[-1].args[1]
            self.assertEqual(updated['gross_cap'],100_000);self.assertEqual(updated['max_jobs'],60)
            self.assertEqual(updated['payer_file'],str(base.GWROOT/'relay.key'))
            self.assertEqual(updated['native_ingress'],[p['native_ingress'] for p in ready['peers']])
            write.reset_mock();owned[self.root/'relay/config.json']=service.encode(dict(relay,gross_cap=150_000_000))
            with self.assertRaisesRegex(ValueError,'sealed policy'):service.prepare(base,config(),value,ready)
            self.assertNotIn(self.root/'relay/config.json',[call.args[0] for call in write.call_args_list])


class CohortSizeGuards(unittest.TestCase):
    """The sealed plan's cohort_size alone sets every derived lifetime limit."""
    def setUp(self):service.select_mode(False);self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
    def tearDown(self):service.select_mode(False);self.temp.cleanup()
    def sized(self,size,daily=None):
        grant,admission=policies();grant['max_claims']=size
        admission.update(max_invites=size,daily_admissions=size if daily is None else daily)
        value=dict(plan(),cohort_size=size,private_budget=size*20_000_000,public_budget=size*450_000_000,
            faucet_policy_sha256=service.hash_value(grant),admission_policy_sha256=service.hash_value(admission))
        return value,grant,admission
    def store(self,grant,admission,claims=0,invitations=0):
        for folder in ('faucet','relay'):(self.root/folder).mkdir(mode=0o700,exist_ok=True)
        save(self.root/'faucet/wallet.enc.json',b'fixed encrypted source',True)
        save(self.root/'password',b'fixed private password',True)
        save(self.root/'faucet/claims.json',dict(policy=grant,claims=[{}]*claims))
        save(self.root/'faucet/admission.json',dict(policy=admission,invitations=[{}]*invitations))
    def test_ten_wallet_plan_sealed_before_configurable_size_keeps_its_hash(self):
        # Literal document and digest as produced before the size became a plan parameter.
        import native_pilot_cohort as planner
        sealed=dict(format='zolana-native-cohort-plan-v1',network=dict(network=[67]*32,genesis_hash=key(9)),
            pool_format='NPOOL004',cohort_size=10,private_grant=20_000_000,gas_grant=0,attempts=3,payment_cap=150_000_000,
            private_budget=200_000_000,public_budget=4_500_000_000,source_private_address='npriv1'+'A'*100,
            source_fee_address=key(6),**{name+'_sha256':'a'*64 for name in
            ('source_wallet','password','source_profile','public_profile','relay_policy','faucet_policy','admission_policy')})
        accepted=service.validate_plan(copy.deepcopy(sealed),dict(config(),network=sealed['network']),base)
        self.assertEqual(accepted,sealed)
        self.assertEqual(service.hash_value(sealed),'39918ab191949f62e28ef9cb6ec63a442660c564e3fb801d345a2fb1361dfe6d')
        self.assertEqual(planner.hash_value(planner.validate_plan(copy.deepcopy(sealed))),service.hash_value(sealed))
        self.assertEqual((service.MAX_COHORT_SIZE,service.RELAY_MEMBER_JOBS),(planner.MAX_COHORT_SIZE,planner.RELAY_MEMBER_JOBS))
        from shielded_relay import MAX_JOBS
        self.assertEqual(MAX_JOBS,service.RELAY_MEMBER_JOBS*service.MAX_COHORT_SIZE)
    def test_two_hundred_wallet_plan_scales_budget_funding_and_lifetime_authority(self):
        import native_pilot_cohort as planner
        value,grant,admission=self.sized(200,daily=25)
        self.assertEqual((value['private_budget'],value['public_budget']),(4_000_000_000,90_000_000_000))
        service.validate_plan(value,config(),base);planner.validate_plan(dict(value))
        for field,bad in [('cohort_size',10),('cohort_size',201),('private_budget',200_000_000),
                          ('public_budget',4_500_000_000),('private_grant',400_000_000),('payment_cap',3_000_000_000)]:
            with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):
                service.validate_plan(dict(value,**{field:bad}),config(),base)
        receipt=dict(funding(value),private_observed=4_000_000_000,public_observed=90_000_000_000)
        service.validate_funding(receipt,value,True,1100)
        for short in (dict(private_observed=3_999_999_999),dict(public_observed=89_999_999_999),
                      dict(private_observed=200_000_000,public_observed=4_500_000_000)):
            with self.subTest(short=short),self.assertRaises(ValueError):
                service.validate_funding(dict(receipt,**short),value,True,1100)
        with mock.patch.object(service,'ROOT',self.root):
            self.store(grant,admission,claims=200,invitations=200)
            self.assertEqual(len(service.authority(base,config(),value)['claims']),200)
            self.store(grant,admission,claims=201)
            with self.assertRaises(ValueError):service.authority(base,config(),value)
            self.store(grant,admission,invitations=201)
            with self.assertRaises(ValueError):service.authority(base,config(),value)
            self.store(grant,admission)
            with self.assertRaises(ValueError):service.authority(base,config(),plan())
            for daily in (0,201,True):
                changed,grant,admission=self.sized(200,daily=daily);self.store(grant,admission)
                with self.subTest(daily=daily),self.assertRaises(ValueError):service.authority(base,config(),changed)
            # Authentic ten-wallet state is never accepted under a larger reviewed size.
            grant,admission=policies();self.store(grant,admission)
            self.assertEqual(service.authority(base,config(),plan())['claims'],[])
            with self.assertRaises(ValueError):service.authority(base,config(),value)
    def test_cohort_size_range_and_type_fail_closed(self):
        for bad in (0,-1,501,1000,True,False,'10',10.0,None,[10]):
            with self.subTest(size=bad),self.assertRaises(ValueError):
                service.validate_plan(dict(plan(),cohort_size=bad),config(),base)
        missing=plan();del missing['cohort_size']
        for value in (missing,None,[],'plan'):
            with self.assertRaises(ValueError):service.validate_plan(value,config(),base)
        for size,private,public in ((1,20_000_000,450_000_000),(500,10_000_000_000,225_000_000_000)):
            value=self.sized(size)[0]
            self.assertEqual((value['private_budget'],value['public_budget']),(private,public))
            self.assertEqual(service.validate_plan(value,config(),base)['cohort_size'],size)
        for size in (501,1000):
            with self.assertRaises(ValueError):service.validate_plan(self.sized(size)[0],config(),base)
        with self.assertRaises(ValueError):service.validate_plan(dict(self.sized(1)[0],cohort_size=True),config(),base)
    def test_relay_lifetime_jobs_are_six_per_planned_wallet(self):
        templates=self.root/'sealed';identity=dict(**network(),program=key(7),pool=key(8),pool_format='NPOOL004',recipient_withdrawals=True)
        source=dict(format='native-wallet-profile-v1',label='Source',key_mode='user-wallet-v1',**identity,
            rpc=dict(transport='loopback-http',url='http://127.0.0.1:10000'))
        public=dict(source,label='Pilot',rpc=dict(transport='https',url=service.audience('rpc')),
            faucet=dict(transport='https',url=service.audience('faucet')),invite_required=True,
            private_send_transport='native-inline-v1')
        operator=dict(format='native-gateway-operator-fixture-v1',fixture_keys_are_public=True,**identity)
        ready=dict(peers=[dict(rpc='127.0.0.1:20000',native_ingress='127.0.0.1:21000')])
        def prepare(size,jobs,per_member=6):
            relay=dict(format='native-shielded-relay-v1',network=network(),network_file=str(self.root/'operator.json'),
                native_profile=str(self.root/'public-profile.json'),payer=[5]*32,payer_file=str(base.GWROOT/'relay.key'),
                binary=str(service.PREFIX/'bin/native-shielded'),fee=3_000_000,gross_cap=100_000,max_jobs=jobs,
                per_member=per_member,pool_format='NPOOL004',rpc=source['rpc']['url'],native_ingress=['127.0.0.1:11000'])
            sealed={templates/'source-profile.json':service.encode(source),templates/'public-profile.json':service.encode(public),
                templates/'operator.json':service.encode(operator),templates/'relay.json':service.encode(relay),
                base.ETC/'server.crt':b'original certificate'}
            owned={self.root/'source.json':service.encode(source),self.root/'faucet/profile.json':service.encode(source),
                self.root/'public-profile.json':service.encode(public),self.root/'operator.json':service.encode(operator),
                self.root/'relay/config.json':service.encode(relay),base.GWROOT/'server.crt':b'original certificate',
                base.GWROOT/'server.key':b'private key',base.GWROOT/'relay.key':service.encode([9]*32+[5]*32)}
            value=dict(self.sized(size)[0],source_profile_sha256=service.hash_value(source),
                public_profile_sha256=service.hash_value(public),relay_policy_sha256=service.hash_value(relay))
            with mock.patch.object(service,'ROOT',self.root),mock.patch.object(service,'ETC',templates),\
                 mock.patch.object(base,'sealed',side_effect=lambda path,*args:sealed[path]),\
                 mock.patch.object(base,'owned',side_effect=lambda path,*args:owned[path]),mock.patch.object(base,'atomic') as write:
                service.prepare(base,config(),value,ready)
                return write.call_args_list[-1].args[1]['max_jobs']
        for size,jobs in ((1,6),(10,60),(200,1200),(500,3000)):
            with self.subTest(size=size):self.assertEqual(prepare(size,jobs),jobs)
        for size,jobs,per_member in ((200,60,6),(10,1200,6),(200,1199,6),(200,1201,6),(200,1200,8),(10,60,5)):
            with self.subTest(size=size,jobs=jobs,per_member=per_member),self.assertRaises(ValueError):prepare(size,jobs,per_member)


class WorkerGuards(unittest.TestCase):
    class Parent:
        def __init__(self):
            self.stop=threading.Event();self.child_lock=threading.Lock();self.root=Path('/fixed/cohort/faucet')
            self.binary=Path('/fixed/bin/native-faucet');self.password='private password';self.child=None
    def test_worker_failure_and_timeout_are_supervised_without_password_arguments(self):
        for timeout in (False,True):
            worker=service.supervised_faucet(self.Parent)();child=mock.Mock();child.returncode=1
            if timeout:child.communicate.side_effect=[subprocess.TimeoutExpired('tick',180),('', '')]
            else:child.communicate.return_value=('', '')
            with mock.patch('subprocess.Popen',return_value=child) as spawn:worker.work()
            self.assertTrue(worker.failed.is_set());self.assertIsNone(worker.child)
            self.assertNotIn(worker.password,spawn.call_args.args[0])
            self.assertIn('--password-file',spawn.call_args.args[0])
            self.assertEqual(child.communicate.call_args_list[0].kwargs['input'],worker.password)
            if timeout:child.kill.assert_called_once()
        worker=service.supervised_faucet(self.Parent)();worker.stop.set()
        with mock.patch('subprocess.Popen') as spawn:worker.work()
        spawn.assert_not_called()


class GrantFaultGuards(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve();(self.root/'faucet').mkdir(mode=0o700)
        self.directory=self.root/'grant-ack-gate';self.directory.mkdir(mode=0o700)
        self.gate=object.__new__(fault.GrantRpcGate);self.gate.root=self.root;self.gate.directory=self.directory
        self.gate.uid=os.getuid();self.gate.network=network();self.gate.lock=threading.Lock()
        self.arm=dict(format='zolana-native-cohort-grant-arm-v1',nonce='a'*64,expires_at=1180)
        self.signature='2'*88;self.proof=bytes([42])*9222;claim=dict(fee_address=key(8))
        self.claim_id=hashlib.blake2b(claim['fee_address'].encode(),digest_size=32).hexdigest()
        self.pending=dict(network=network(),signature=self.signature,staging_account=key(9),last_valid_block_height=900)
        self.staging=dict(network=network(),staging_account=key(9),payload_digest=list(hashlib.blake2b(self.proof,digest_size=32,person=b'NativeStageV1!!!').digest()))
        self.progress=dict(submission_started=True,private_done=False,proof=list(self.proof))
        save(self.root/'faucet/wallet.enc.json.pending.json',self.pending)
        save(self.root/'faucet/wallet.enc.json.staging.json',self.staging)
        save(self.root/'faucet/claims.json',dict(policy=dict(format='native-test-faucet-native-v1'),claims=[claim]))
        save(self.root/'faucet'/(self.claim_id+'.json'),self.progress)
        self.query=dict(jsonrpc='2.0',id=1,method='getSignatureStatuses',params=[[self.signature]])
        self.response=dict(jsonrpc='2.0',id=1,result=dict(context=dict(slot=700),value=[dict(slot=699,err=None,confirmations=None,confirmationStatus='finalized')]))
    def tearDown(self):self.temp.cleanup()
    def test_only_matching_real_finalized_response_can_hold_a_grant(self):
        status=fault.finalized_match(self.query,self.response,self.signature);self.assertEqual(status['slot'],699)
        for response in [dict(self.response,id=2),dict(self.response,error={}),dict(self.response,result=dict(value=[None])),
                         dict(self.response,result=dict(value=[dict(status,confirmationStatus='confirmed')])),
                         dict(self.response,result=dict(value=[dict(status,err='failure')]))]:
            self.assertIsNone(fault.finalized_match(self.query,response,self.signature))
        self.assertIsNone(fault.finalized_match(self.query,self.response,'3'*88))
    def test_original_pending_staging_and_proof_are_durable_before_hold(self):
        raw=service.encode(self.response)
        with mock.patch.object(self.gate,'arm',return_value=self.arm):
            self.assertTrue(self.gate.observe(self.query,self.response,raw))
            record=(self.directory/'observed.json').read_bytes()
            self.assertEqual((self.directory/'original.proof').read_bytes(),self.proof)
            self.assertEqual(json.loads(record)['proof_sha256'],hashlib.sha256(self.proof).hexdigest())
            changed=copy.deepcopy(self.response);changed['result']['context']['slot']=701
            self.assertTrue(self.gate.observe(self.query,changed,service.encode(changed)))
            self.assertEqual((self.directory/'observed.json').read_bytes(),record)
        with mock.patch.object(self.gate,'arm',return_value=dict(self.arm,nonce='b'*64)),self.assertRaises(ValueError):
            self.gate.observe(self.query,self.response,raw)
        self.assertEqual((self.directory/'observed.json').read_bytes(),record)
    def test_missing_or_changed_original_proof_never_creates_fault_evidence(self):
        changed=dict(self.progress,proof=[43]*9222);save(self.root/'faucet'/(self.claim_id+'.json'),changed)
        with mock.patch.object(self.gate,'arm',return_value=self.arm),self.assertRaises(ValueError):
            self.gate.observe(self.query,self.response,service.encode(self.response))
        self.assertFalse((self.directory/'observed.json').exists())
    def test_grant_ledger_bound_follows_the_planned_cohort_size(self):
        claims=[dict(fee_address=key(8))]+[dict(fee_address=key(20+index)) for index in range(10)]
        for claim in claims[1:]:
            claim_id=hashlib.blake2b(claim['fee_address'].encode(),digest_size=32).hexdigest()
            save(self.root/'faucet'/(claim_id+'.json'),dict(private_done=True))
        save(self.root/'faucet/claims.json',dict(policy=dict(format='native-test-faucet-native-v1'),claims=claims))
        raw=service.encode(self.response);self.assertEqual(fault.GrantRpcGate.cohort_size,10)
        with mock.patch.object(self.gate,'arm',return_value=self.arm):
            with self.assertRaises(ValueError):self.gate.observe(self.query,self.response,raw)
            self.assertFalse((self.directory/'observed.json').exists())
            self.gate.cohort_size=11
            self.assertTrue(self.gate.observe(self.query,self.response,raw))
        self.assertEqual(json.loads((self.directory/'observed.json').read_bytes())['claim_id'],self.claim_id)
        with mock.patch.object(fault,'BoundedServer') as build:
            for bad in (0,501,True,'10',None):
                with self.subTest(size=bad),self.assertRaises(ValueError):
                    fault.GrantRpcGate('127.0.0.1:5000',network(),os.geteuid(),cohort_size=bad)
            build.assert_not_called()
    def test_arm_requires_exact_root_file_policy_and_expires_after_at_most_180_seconds(self):
        def read(path,uid,maximum,mode):
            self.assertEqual(uid,0);self.assertEqual(mode,0o640);return service.encode(self.arm)
        with mock.patch.object(fault.os.path,'lexists',return_value=True),mock.patch.object(fault.base,'owned',side_effect=read):
            self.assertEqual(self.gate.arm(1000),self.arm)
            self.assertIsNone(self.gate.arm(1180))
            self.arm['expires_at']=1181
            with self.assertRaises(ValueError):self.gate.arm(1000)

    def test_single_original_status_keeps_authentic_bytes_and_batch_never_holds(self):
        raw=(json.dumps(self.response,indent=3)+'\n').encode()
        reply=fault.checked_response(fault.checked_request(json.dumps(self.query).encode()),raw)
        with mock.patch.object(self.gate,'arm',return_value=self.arm):
            self.assertTrue(self.gate.observe(self.query,reply,raw))
        record=json.loads((self.directory/'observed.json').read_bytes())
        self.assertEqual(record['authentic_response_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(record['authentic_response'],self.response)
        with mock.patch.object(self.gate,'arm',side_effect=AssertionError('a batch must not inspect ACK state')):
            self.assertFalse(self.gate.observe([self.query],[self.response],b'[]'))
        with self.assertRaises(ValueError):fault.checked_request(json.dumps([dict(self.query,id=0)]).encode())


class GrantBatchGuards(unittest.TestCase):
    def history(self,count=16):
        return [dict(jsonrpc='2.0',id=index,method='getBlock',
                     params=[100+index,dict(fault.BLOCK_CONFIG)]) for index in range(count)]
    def checked(self,query):return fault.checked_request(json.dumps(query).encode())

    def test_256_exact_history_reads_are_admitted_without_changing_their_request(self):
        self.assertEqual(fault.HISTORY_PAGE,256)
        query=self.history(fault.HISTORY_PAGE);self.assertEqual(self.checked(query),query)
        self.assertEqual(self.checked(self.history(1)),self.history(1))
        # The gate's history wire cap also accommodates the largest u64 slots;
        # the raw validator's independent HTTP body limit remains authoritative.
        for index,call in enumerate(query):call['params'][0]=2**64-fault.HISTORY_PAGE+index
        self.assertEqual(self.checked(query),query)
        # Existing source-worker writes and direct pending-status reads remain
        # single original objects; no new generic write batch is introduced.
        for method in ('sendTransaction','getSignatureStatuses'):
            single=dict(jsonrpc='2.0',id=55,method=method,params=[])
            self.assertEqual(self.checked(single),single)

    def test_batch_caps_ids_slots_and_exact_finalized_history_configuration_fail_closed(self):
        invalid=[[],self.history(fault.HISTORY_PAGE+1),[None]]
        for field,value in [('id',True),('id','0'),('id',1),('id',-1),('jsonrpc','1.0'),
                            ('method','getBlocks'),('method','sendTransaction'),('method','getSignatureStatuses')]:
            query=self.history(1);query[0][field]=value;invalid.append(query)
        for params in ([],[100],[0,dict(fault.BLOCK_CONFIG)],[True,dict(fault.BLOCK_CONFIG)],
                       [2**64,dict(fault.BLOCK_CONFIG)],[100,dict(fault.BLOCK_CONFIG),None]):
            query=self.history(1);query[0]['params']=params;invalid.append(query)
        for field,value in [('commitment','confirmed'),('encoding','json'),('transactionDetails','signatures'),
                            ('rewards',0),('rewards',True),('maxSupportedTransactionVersion',False),
                            ('maxSupportedTransactionVersion',1)]:
            query=self.history(1);query[0]['params'][1][field]=value;invalid.append(query)
        query=self.history(1);query[0]['params'][1]['extra']=False;invalid.append(query)
        query=self.history(1);query[0]['extra']='denied';invalid.append(query)
        for field,value in [('id',0),('params',[100,dict(fault.BLOCK_CONFIG)]),('params',[99,dict(fault.BLOCK_CONFIG)])]:
            query=self.history(2);query[1][field]=value;invalid.append(query)
        for query in invalid:
            with self.subTest(query=query),self.assertRaises(ValueError):self.checked(query)
        with self.assertRaises(ValueError):fault.checked_request(json.dumps(self.history(1)).encode()+b' '*65536)
        with self.assertRaises(ValueError):fault.checked_request(b' '*100001)

    def test_small_reads_use_the_existing_strict_wallet_schemas_and_cannot_mix_history_or_status(self):
        calls=[dict(method='getAccountInfo',params=[key(7),{'commitment':'confirmed','encoding':'base64'}]),
               dict(method='getBalance',params=[key(7),{'commitment':'finalized'}]),
               dict(method='getLatestBlockhash',params=[{'commitment':'confirmed'}]),
               dict(method='getSlot',params=[{'commitment':'finalized'}]),
               dict(method='getMinimumBalanceForRentExemption',params=[40]),
               dict(method='getFeeForMessage',params=['YQ==',{'commitment':'confirmed'}])]
        query=[dict(jsonrpc='2.0',id=index,**call) for index,call in enumerate(calls)]
        with mock.patch.object(fault,'read_calls',wraps=fault.read_calls) as check:
            self.assertEqual(self.checked(query),query);check.assert_called_once_with({'params':[calls]})
        for method,params in [('getSignatureStatuses',[[]]),('sendTransaction',['packet']),
                              ('getMinimumBalanceForRentExemption',[131073]),
                              ('getBalance',[key(7),{'commitment':'processed'}]),
                              ('getFeeForMessage',['invalid',{'commitment':'confirmed'}])]:
            bad=[dict(jsonrpc='2.0',id=0,method=method,params=params)]
            with self.subTest(method=method),self.assertRaises(ValueError):self.checked(bad)
        mixed=self.history(1)+[dict(query[0],id=1)]
        with self.assertRaises(ValueError):self.checked(mixed)
        sixteen=[dict(jsonrpc='2.0',id=index,method='getSlot',params=[{'commitment':'finalized'}]) for index in range(16)]
        self.assertEqual(self.checked(sixteen),sixteen)
        with self.assertRaises(ValueError):self.checked(sixteen+[dict(sixteen[0],id=16)])
        with self.assertRaises(ValueError):fault.checked_request(json.dumps(sixteen[:1]).encode()+b' '*32768)

    def test_authentic_reordered_results_nulls_and_errors_pass_without_rewriting(self):
        query=self.history(2)
        response=[dict(jsonrpc='2.0',id=1,error={'code':-32004,'message':'Block unavailable'}),
                  dict(jsonrpc='2.0',id=0,result=None)]
        raw=(json.dumps(response,indent=2)+'\n').encode();original=raw
        self.assertEqual(fault.checked_response(query,raw),response);self.assertEqual(raw,original)
        # Missing blocks and authentic upstream errors are still for the gateway
        # to reject. The test gate never fabricates a successful block result.
        query=self.history(fault.HISTORY_PAGE)
        response=[dict(jsonrpc='2.0',id=index,result={'blockhash':str(index)}) for index in reversed(range(len(query)))]
        raw=(json.dumps(response,indent=2)+'\n').encode();original=raw
        self.assertEqual(fault.checked_response(query,raw),response);self.assertEqual(raw,original)
        response[-1]['id']=fault.HISTORY_PAGE
        with self.assertRaises(ValueError):fault.checked_response(query,json.dumps(response).encode())

    def test_malformed_missing_duplicate_or_unknown_batch_responses_are_rejected(self):
        query=self.history(2);first=dict(jsonrpc='2.0',id=0,result={});second=dict(jsonrpc='2.0',id=1,result={})
        invalid=[{},[],[first],[first,first],[first,dict(second,id=2)],
                 [first,dict(second,id=True)],[first,dict(second,id='1')],
                 [first,dict(second,jsonrpc='1.0')],[first,dict(second,error={})],
                 [first,dict(jsonrpc='2.0',id=1)],[first,dict(jsonrpc='2.0',id=1,error='bad')],
                 [first,dict(second,extra=True)]]
        for response in invalid:
            with self.subTest(response=response),self.assertRaises(ValueError):
                fault.checked_response(query,json.dumps(response).encode())
        with self.assertRaises(ValueError):fault.checked_response(query,b' '*(fault.MAX_RESPONSE+1))

    def test_ambiguous_or_nonfinite_json_is_never_forwarded(self):
        for raw in (b'[{"jsonrpc":"2.0","id":0,"id":1,"method":"getBlock","params":[]}]',
                    b'[{"jsonrpc":"2.0","id":NaN,"method":"getBlock","params":[]}]',b'null',b'"object"',b'{'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):fault.checked_request(raw)
        for raw in (b'[{"jsonrpc":"2.0","id":0,"result":{},"result":{}}]',
                    b'[{"jsonrpc":"2.0","id":0,"result":Infinity}]'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):fault.checked_response(self.history(1),raw)


class GrantHistoryOverflowGuards(unittest.TestCase):
    """Exercise the real HTTP handler branch with streams, never a listener."""
    def history(self):
        return [dict(jsonrpc='2.0',id=0,method='getBlock',params=[100,dict(fault.BLOCK_CONFIG)])]

    def request(self,query,body=None,error=None):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();server=mock.Mock();server.server_address=('127.0.0.1',12345)
            with mock.patch.object(fault,'root_for',return_value=root),mock.patch.object(fault,'BoundedServer',return_value=server) as build,\
                    mock.patch.object(fault.threading,'Thread'):
                gate=fault.GrantRpcGate('127.0.0.1:5000',network(),os.geteuid())
            handler=object.__new__(build.call_args.args[1]);raw=json.dumps(query).encode()
            handler.path='/';handler.headers=Message();handler.headers['Content-Length']=str(len(raw))
            handler.rfile=io.BytesIO(raw);handler.wfile=io.BytesIO();handler.close_connection=False
            handler.send_response=mock.Mock();handler.send_header=mock.Mock();handler.end_headers=mock.Mock()
            gate.observe=mock.Mock(return_value=False);gate.hold=mock.Mock()
            upstream=mock.Mock();upstream.status=200;upstream.read.return_value=body
            upstream.__enter__=mock.Mock(return_value=upstream);upstream.__exit__=mock.Mock(return_value=False)
            opener=mock.Mock()
            if error is not None:opener.open.side_effect=error
            else:opener.open.return_value=upstream
            with mock.patch.object(fault.urllib.request,'build_opener',return_value=opener):handler.do_POST()
            return handler,gate

    def test_only_history_response_overflow_emits_bounded_internal_413(self):
        handler,gate=self.request(self.history(),body=b'x'*(fault.MAX_RESPONSE+1))
        handler.send_response.assert_called_once_with(413)
        self.assertEqual(json.loads(handler.wfile.getvalue()),{'error':'history_response_too_large'})
        self.assertTrue(handler.close_connection);gate.observe.assert_not_called();gate.hold.assert_not_called()
        with self.assertRaises(fault.HistoryResponseTooLarge):
            fault.checked_response(self.history(),b'x'*(fault.MAX_RESPONSE+1))
        for query in [dict(jsonrpc='2.0',id=0,method='getSignatureStatuses',params=[[]]),
                      [dict(jsonrpc='2.0',id=0,method='getSlot',params=[{'commitment':'finalized'}])]]:
            with self.subTest(query=query):
                handler,gate=self.request(query,body=b'x'*(fault.MAX_RESPONSE+1))
                handler.send_response.assert_not_called();self.assertEqual(handler.wfile.getvalue(),b'')
                self.assertTrue(handler.close_connection);gate.observe.assert_not_called()

    def test_only_authentic_history_upstream_413_is_propagated(self):
        for query,code,expected in [(self.history(),413,True),(self.history(),500,False),
                ([dict(jsonrpc='2.0',id=0,method='getSlot',params=[{'commitment':'finalized'}])],413,False),
                (dict(jsonrpc='2.0',id=0,method='getSignatureStatuses',params=[[]]),413,False)]:
            with self.subTest(query=query,code=code):
                error=fault.urllib.error.HTTPError('http://127.0.0.1:5000',code,'upstream',{},io.BytesIO(b'not an ACK'))
                handler,gate=self.request(query,error=error)
                error.close()
                if expected:handler.send_response.assert_called_once_with(413)
                else:handler.send_response.assert_not_called();self.assertEqual(handler.wfile.getvalue(),b'')
                gate.observe.assert_not_called();gate.hold.assert_not_called()

    def test_malformed_history_response_is_not_mislabeled_as_size_overflow(self):
        for body in [b'not JSON',b'[]',b'[{"jsonrpc":"2.0","id":1,"result":{}}]']:
            with self.subTest(body=body):
                handler,gate=self.request(self.history(),body=body)
                handler.send_response.assert_not_called();self.assertEqual(handler.wfile.getvalue(),b'')
                gate.observe.assert_not_called();gate.hold.assert_not_called()


if __name__=='__main__':unittest.main()
