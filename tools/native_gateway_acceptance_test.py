"""Guard regressions for the attached fixture; no listeners or validators start."""
import copy
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch

import native_gateway_acceptance as acceptance


class Guards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = dict(pool_format='NPOOL004', mac_relay=acceptance.b58(bytes([5])*32),
            network=dict(network=[0x43]*32,genesis_hash=acceptance.b58(bytes([9])*32)),
            peers=[dict(identity=acceptance.b58(bytes([n])*32),rpc='127.0.0.1:'+str(10000+n),
                        native_ingress='127.0.0.1:'+str(11000+n)) for n in (1,2,3)])
    def tearDown(self): self.temp.cleanup()
    def test_endpoints_are_literal_unique_authorities_not_userinfo_or_routes(self):
        self.assertEqual(acceptance.endpoint('127.0.0.1:12345'), ('127.0.0.1',12345))
        for value in ('127.0.0.1:0','127.0.0.1:65536','127.0.0.1:0123','127.0.0.1:123@outside',
                      '127.0.0.1:123/path','127.0.0.1:123\n','localhost:123','[::1]:123','127.0.0.2:123'):
            with self.subTest(value=value),self.assertRaises(ValueError): acceptance.endpoint(value)
    def test_host_evidence_accepts_only_real_three_node_v4_profile(self):
        path=self.root/'ready.json';acceptance.save(path,self.fixture)
        self.assertEqual(acceptance.host(path),self.fixture)
        for mutation in (dict(pool_format='NPOOL003'),dict(peers=self.fixture['peers'][:2]),
                         dict(peers=[self.fixture['peers'][0]]*3)):
            acceptance.save(path,dict(self.fixture,**mutation))
            with self.assertRaises(ValueError): acceptance.host(path)
        changed=copy.deepcopy(self.fixture);changed['network']['network'][0]=True
        acceptance.save(path,changed)
        with self.assertRaises(ValueError): acceptance.host(path)
    def test_resume_allows_ports_but_never_genesis_keys_or_profile_substitution(self):
        changed=copy.deepcopy(self.fixture)
        changed['peers'].reverse()
        for peer in changed['peers']:peer['rpc']='127.0.0.1:22222'
        acceptance.same_network(self.fixture,changed)
        for key,value in [('pool_format','NPOOL003'),('mac_relay',acceptance.b58(bytes([6])*32)),
                          ('network',dict(network=[0x44]*32,genesis_hash=self.fixture['network']['genesis_hash']))]:
            with self.assertRaises(ValueError): acceptance.same_network(self.fixture,dict(changed,**{key:value}))
        changed['peers'][0]['identity']=acceptance.b58(bytes([7])*32)
        with self.assertRaises(ValueError): acceptance.same_network(self.fixture,changed)
    def test_private_reads_refuse_symlinks_permissions_and_size(self):
        path=self.root/'private';path.write_bytes(b'bounded');path.chmod(0o600)
        self.assertEqual(acceptance.private(path,7),b'bounded')
        with self.assertRaises(ValueError): acceptance.private(path,6)
        path.chmod(0o644)
        with self.assertRaises(ValueError): acceptance.private(path)
        path.chmod(0o600);link=self.root/'link';link.symlink_to(path)
        with self.assertRaises(OSError): acceptance.private(link)
    def test_ack_fault_requires_real_admission_identity_and_false_finality(self):
        wire=b'\x01'+bytes([3])*64+bytes([4])*1300
        signature,_=acceptance.wire_identity(wire)
        ack=dict(status='admitted',signature=signature,slot=7,finalized=False)
        faults=acceptance.Faults(self.root);faults.armed=True
        for bad in (dict(ack,finalized=True),dict(ack,signature='other'),dict(ack,status='busy_retry_identical_bytes')):
            self.assertFalse(faults.observe(wire,bad));self.assertFalse(faults.triggered.is_set())
        self.assertTrue(faults.observe(wire,ack));self.assertTrue(faults.triggered.is_set())
        self.assertEqual(acceptance.private(self.root/'dropped-ack.packet'),wire)
        retained=json.loads(acceptance.private(self.root/'dropped-ack.json'))
        self.assertEqual(retained['packet_sha256'],acceptance.hashlib.sha256(wire).hexdigest())
        self.assertEqual(retained['signature'],signature)
        # A second dropped ACK cannot replace the original durable identity.
        second=b'\x01'+bytes([6])*64+bytes([4])*1300
        next_signature,_=acceptance.wire_identity(second)
        self.assertTrue(faults.observe(second,dict(ack,signature=next_signature)))
        self.assertEqual(acceptance.private(self.root/'dropped-ack.packet'),wire)
    def test_same_signature_cannot_hide_changed_packet_and_wire_bounds_hold(self):
        wire=b'\x01'+bytes([3])*64+bytes([4])*1300
        faults=acceptance.Faults(self.root);faults.observe(wire,{})
        with self.assertRaises(ValueError):faults.observe(wire[:-1]+b'\x05',{})
        for raw in (b'',b'\x02'+wire[1:],wire[:1232],wire+bytes(acceptance.LIMIT)):
            with self.assertRaises(ValueError):acceptance.wire_identity(raw)
    def recovery_fixture(self):
        trial=acceptance.Trial.__new__(acceptance.Trial)
        job=self.root/('a'*64);job.mkdir()
        user=self.root/'wallet.json.shielded.json';original_user=b'original authorized proof'
        user.write_bytes(original_user);user.chmod(0o600)
        signature='original-signature';digest='b'*64
        original_native=json.dumps(dict(signature=signature,packet_sha256=digest,
            gross_cap=150000000,reserved_debit=2343560)).encode()
        (job/'relay.native.json').write_bytes(original_native);(job/'relay.native.json').chmod(0o600)
        trial.faults=Mock(record=dict(signature=signature,packet_sha256=digest))
        def bounded_wait(callback,seconds):
            self.assertEqual(seconds,90)
            for _ in range(3):
                value=callback()
                if value:return value
            raise TimeoutError('still pending')
        trial.wait=bounded_wait
        receipt=dict(accepted=True,encrypted_checkpoint_durable=True,signature=signature,id=job.name)
        return trial,job,user,original_user,original_native,receipt
    def test_resolve_retries_only_explicit_pending_and_requires_original_durable_receipt(self):
        trial,job,user,old_user,old_native,receipt=self.recovery_fixture()
        pending=RuntimeError('actual wallet HTTP API: shielded payment remains unresolved; original proof retained, no new spend authorized')
        def finish(*args):
            self.assertEqual(args,('alice','resolve'))
            self.assertEqual(acceptance.private(user),old_user)
            self.assertEqual(acceptance.private(job/'relay.native.json'),old_native)
            acceptance.save(job/'outcome.json',dict(accepted=True,signature=receipt['signature'],
                packet_sha256='b'*64,reserved_gross_debit=2343560))
            (job/'relay.native.json').unlink()
            acceptance.save(user.with_suffix('.receipt.json'),receipt);user.unlink()
            return receipt
        count=0
        def real_api(*args):
            nonlocal count
            count+=1
            if count==1:raise pending
            return finish(*args)
        trial.api=Mock(side_effect=real_api)
        self.assertEqual(trial.resolve_original(job,user,old_user,old_native),receipt)
        self.assertEqual(trial.api.call_count,2)
        self.assertTrue(all(call.args==('alice','resolve') for call in trial.api.call_args_list))
    def test_resolve_never_retries_unrelated_errors_or_changed_reservations(self):
        trial,job,user,old_user,old_native,_=self.recovery_fixture()
        trial.api=Mock(side_effect=RuntimeError('actual wallet HTTP API: invalid canonical block'))
        with self.assertRaisesRegex(RuntimeError,'invalid canonical block'):
            trial.resolve_original(job,user,old_user,old_native)
        trial.api.assert_called_once_with('alice','resolve')
        self.assertEqual(acceptance.private(user),old_user)
        self.assertEqual(acceptance.private(job/'relay.native.json'),old_native)
        def altered(*_):
            acceptance.save(job/'relay.native.json',dict(signature='replacement'))
            raise RuntimeError('native outcome remains unresolved; original proof retained, no replacement authorized')
        trial.api=Mock(side_effect=altered)
        with self.assertRaisesRegex(ValueError,'reservation changed'):
            trial.resolve_original(job,user,old_user,old_native)
        self.assertEqual(trial.api.call_count,1)

    def test_process_kill_uses_only_direct_owned_group_and_refuses_changed_group(self):
        trial=acceptance.Trial.__new__(acceptance.Trial)
        child=Mock(pid=12345);child.poll.return_value=None;child.returncode=-signal.SIGKILL
        trial.children={'gateway':child}
        with patch.object(acceptance.os,'getpgid',return_value=222),patch.object(acceptance.os,'killpg') as kill:
            with self.assertRaises(ValueError):trial.stop('gateway',True)
            kill.assert_not_called()
        trial.children={'gateway':child}
        with patch.object(acceptance.os,'getpgid',return_value=12345),patch.object(acceptance.os,'killpg') as kill:
            trial.stop('gateway',True)
            kill.assert_called_once_with(12345,signal.SIGKILL);child.wait.assert_called_once_with(timeout=20)


if __name__=='__main__':unittest.main()
