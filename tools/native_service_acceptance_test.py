"""LOCAL-058 acceptance guards only: no services, validators or listeners start."""
import argparse
import errno
import json
import os
import stat
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock,patch

import native_service_acceptance as acceptance


class Guards(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()
        self.wire=b'\x01'+bytes([3])*64+bytes([4])*1300
        self.signature,self.digest=acceptance.previous.wire_identity(self.wire)
        self.ack=dict(status='admitted',signature=self.signature,paymentId=[4]*32,slot=7,finalized=False)
    def tearDown(self):self.temp.cleanup()
    def test_ack_requires_exact_real_admission_binding_and_no_finality_claim(self):
        self.assertEqual(acceptance.admitted_identity(self.wire,self.ack),dict(signature=self.signature,packet_sha256=self.digest,packet_bytes=len(self.wire)))
        for bad in (dict(self.ack,finalized=True),dict(self.ack,signature='other'),dict(self.ack,slot=True),
                    dict(self.ack,paymentId=[True]*32),dict(self.ack,extra=1),dict(self.ack,status='not_leader_retry_identical_bytes')):
            with self.subTest(bad=bad):self.assertIsNone(acceptance.admitted_identity(self.wire,bad))
    def gate(self):
        gate=acceptance.NativeAckGate.__new__(acceptance.NativeAckGate)
        gate.directory=self.root;gate.uid=os.getuid();gate.lock=threading.Lock()
        gate.arm=Mock(return_value=dict(nonce='a'*64))
        return gate
    def test_real_ack_gate_durably_preserves_first_exact_packet(self):
        gate=self.gate()
        self.assertFalse(gate.suppress(self.wire,dict(self.ack,finalized=True)))
        self.assertFalse((self.root/'observed.json').exists())
        self.assertTrue(gate.suppress(self.wire,self.ack))
        self.assertEqual(acceptance.read_owned(self.root/'original.packet',os.getuid(),16384,0o600),self.wire)
        original=acceptance.read_owned(self.root/'observed.json',os.getuid(),8192,0o600)
        other=b'\x01'+bytes([5])*64+bytes([4])*1300
        sig,_=acceptance.previous.wire_identity(other)
        self.assertTrue(gate.suppress(other,dict(self.ack,signature=sig)))
        self.assertEqual(acceptance.read_owned(self.root/'observed.json',os.getuid(),8192,0o600),original)
        self.assertEqual((self.root/'original.packet').read_bytes(),self.wire)
        gate.arm.return_value=None
        self.assertFalse(gate.suppress(self.wire,self.ack))
    def test_gate_rejects_changed_original_record_or_new_case_over_old_packet(self):
        gate=self.gate();gate.suppress(self.wire,self.ack)
        (self.root/'original.packet').write_bytes(self.wire[:-1]+b'\x05')
        with self.assertRaisesRegex(ValueError,'original durable packet'):gate.suppress(self.wire,self.ack)
        (self.root/'original.packet').write_bytes(self.wire)
        gate.arm.return_value=dict(nonce='b'*64)
        with self.assertRaisesRegex(ValueError,'original durable packet'):gate.suppress(self.wire,self.ack)
    def test_arm_is_explicit_root_owned_bounded_expiring_and_not_symlink_absence(self):
        gate=self.gate();del gate.arm
        path=self.root/'arm.json';path.write_text('placeholder')
        valid=dict(format='zolana-native-058-ack-arm-v1',nonce='a'*64,expires_at=int(time.time())+100)
        with patch.object(acceptance,'read_owned',return_value=json.dumps(valid).encode()) as read:
            self.assertEqual(gate.arm(),valid);read.assert_called_once_with(path,0,4096,0o640)
        for change in (dict(expires_at=0),dict(expires_at=int(time.time())+600),dict(expires_at=True),dict(nonce='short'),dict(extra=True)):
            with patch.object(acceptance,'read_owned',return_value=json.dumps(dict(valid,**change)).encode()),self.assertRaises(ValueError):gate.arm()
        path.unlink();path.symlink_to(self.root/'missing')
        with self.assertRaises(OSError):gate.arm()
    def test_owned_reads_refuse_wrong_owner_symlinks_mode_and_oversize(self):
        path=self.root/'private';path.write_bytes(b'private');path.chmod(0o600)
        self.assertEqual(acceptance.read_owned(path,os.getuid(),7,0o600),b'private')
        for uid,maximum,mode in ((os.getuid()+1,7,0o600),(os.getuid(),6,0o600),(os.getuid(),7,0o640)):
            with self.assertRaises(ValueError):acceptance.read_owned(path,uid,maximum,mode)
        link=self.root/'link';link.symlink_to(path)
        with self.assertRaises(OSError):acceptance.read_owned(link,os.getuid())
    def test_denied_open_never_reads_exposed_secret_or_passes_missing_file(self):
        path=self.root/'secret';path.write_bytes(b'no-read')
        with patch.object(acceptance.os,'read') as read,self.assertRaisesRegex(ValueError,'unexpectedly opened'):
            acceptance.denied_open(path)
        read.assert_not_called()
        with self.assertRaisesRegex(ValueError,'missing/inactive'):acceptance.denied_open(self.root/'absent')
        with patch.object(acceptance.os,'open',side_effect=PermissionError(errno.EACCES,'denied')):
            self.assertEqual(acceptance.denied_open(path),errno.EACCES)
    def test_lifecycle_accepts_only_exact_start_stop_and_rejects_cli_kill_route(self):
        runner=Mock()
        acceptance.fixed_systemctl('stop',[acceptance.UNITS['gateway']],runner)
        self.assertEqual(runner.call_args.args[0],['/usr/bin/systemctl','stop',acceptance.UNITS['gateway']])
        for action,targets in [('restart',[acceptance.UNITS['validator']]),('kill',[acceptance.UNITS['gateway']]),
                               ('stop',['sshd.service']),('stop',[])]:
            with self.subTest(action=action,targets=targets),self.assertRaises(ValueError):acceptance.fixed_systemctl(action,targets,runner)
        self.assertEqual(runner.call_count,1)
    def test_crash_kills_pinned_kernel_cgroups_before_required_sockets(self):
        trial=acceptance.ServiceTrial.__new__(acceptance.ServiceTrial)
        pinned={role:dict(pid=100+index,InvocationID=str(index)*32,ControlGroup='/system.slice/'+unit,start_time='123') for index,(role,unit) in enumerate(acceptance.UNITS.items(),1)}
        trial.properties=pinned;trial.before_ledger={'original':'unchanged'}
        trial.ledger_identity=Mock(return_value=trial.before_ledger);trial.event=Mock()
        trial.wait=Mock(side_effect=lambda callback,seconds:callback());operations=[]
        def kill(role,pin):
            self.assertEqual(pin,pinned[role]);operations.append(('kill',role));return [dict(pid=pin['pid'],start_time='123')]
        def lifecycle(action,units):operations.append((action,units))
        with patch.object(acceptance,'service_properties',side_effect=lambda role:pinned[role]),patch.object(acceptance,'kill_pinned_cgroup',side_effect=kill),patch.object(acceptance,'fixed_systemctl',side_effect=lifecycle),patch.object(acceptance,'cgroup_sigkill_status',side_effect=lambda role,pinned:operations.append(('capture',role)) or dict(unit=acceptance.UNITS[role],original_invocation=pinned['InvocationID'],main_code='2',main_status=9)),patch.object(acceptance,'cgroup_kill_verified',return_value=dict(verified=True)):
            trial.crash_original()
        self.assertEqual(operations,[('kill','gateway'),('capture','gateway'),('kill','validator'),('capture','validator'),('stop',acceptance.SOCKET_UNITS),('stop',[acceptance.UNITS['gateway'],acceptance.UNITS['validator']])])
        self.assertEqual(trial.wait.call_count,4)
        replaced={**pinned['gateway'],'InvocationID':'f'*32}
        with patch.object(acceptance,'service_properties',side_effect=lambda role:replaced if role=='gateway' else pinned[role]),patch.object(acceptance,'kernel_cgroup_kill') as writer,patch.object(acceptance,'fixed_systemctl') as lifecycle:
            with self.assertRaisesRegex(ValueError,'invocation changed'):trial.crash_original()
            lifecycle.assert_not_called();writer.assert_not_called()
    def test_fixed_lifecycle_timeouts_match_existing_unit_budgets(self):
        for action,timeout in [('start',240),('stop',100)]:
            runner=Mock();acceptance.fixed_systemctl(action,[acceptance.UNITS['validator']],runner)
            self.assertEqual(runner.call_args.kwargs['timeout'],timeout)
    def test_atomic_kill_revalidates_exact_pinned_unit_and_root_before_writer(self):
        pinned=dict(pid=1234,InvocationID='a'*32,ControlGroup='/system.slice/'+acceptance.UNITS['gateway'],start_time='123')
        with patch.object(acceptance.os,'geteuid',return_value=0),patch.object(acceptance,'service_properties',return_value=pinned),patch.object(acceptance,'kernel_cgroup_kill',return_value=['evidence']) as writer:
            self.assertEqual(acceptance.kill_pinned_cgroup('gateway',pinned),['evidence']);writer.assert_called_once_with('gateway',1234)
            for changed in ('pid','InvocationID','ControlGroup','start_time'):
                with patch.object(acceptance,'service_properties',return_value=dict(pinned,**{changed:'replacement'})),self.assertRaises(ValueError):acceptance.kill_pinned_cgroup('gateway',pinned)
            self.assertEqual(writer.call_count,1)
        with patch.object(acceptance.os,'geteuid',return_value=1003),patch.object(acceptance,'kernel_cgroup_kill') as writer,self.assertRaises(PermissionError):acceptance.kill_pinned_cgroup('gateway',pinned)
        writer.assert_not_called()
        with patch.object(acceptance.os,'geteuid',return_value=0),self.assertRaises(PermissionError):acceptance.kill_pinned_cgroup('sshd',pinned)
    def test_kernel_writer_only_no_follow_fixed_kernel_files_and_single_one(self):
        def text(path,*args,**kwargs):
            value=str(path)
            if value=='/proc/self/mountinfo':return '1 2 0:27 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n'
            if value.endswith('/cgroup'):return '0::/system.slice/'+acceptance.UNITS['gateway']+'\n'
            return '1234 (python name) '+' '.join(['x']*19+['123'])
        def meta(descriptor):return argparse.Namespace(st_dev=99,st_uid=0,st_mode=stat.S_IFREG if descriptor==14 else stat.S_IFDIR)
        with patch.object(acceptance.os,'geteuid',return_value=0),patch.object(acceptance.Path,'resolve',lambda path:path),patch.object(acceptance.Path,'read_text',text),patch.object(acceptance,'identity',return_value=argparse.Namespace(pw_uid=1002)),patch.object(acceptance,'proc_status',return_value=dict(Uid='1002 1002 1002 1002')),patch.object(acceptance.os,'open',side_effect=[10,11,12,13,14]) as opened,patch.object(acceptance.os,'fstat',side_effect=meta),patch.object(acceptance.os,'read',return_value=b'1234\n5678\n'),patch.object(acceptance.os,'write',return_value=1) as write,patch.object(acceptance.os,'close') as close:
            result=acceptance.kernel_cgroup_kill('gateway',1234)
            self.assertEqual([item['pid'] for item in result],[1234,5678])
            self.assertEqual([call.args[0] for call in opened.call_args_list],[Path('/sys/fs/cgroup'),'system.slice',acceptance.UNITS['gateway'],'cgroup.procs','cgroup.kill'])
            self.assertTrue(all(call.args[1]&os.O_NOFOLLOW for call in opened.call_args_list))
            self.assertEqual(opened.call_args.kwargs['dir_fd'],12)
            write.assert_called_once_with(14,b'1');self.assertEqual([call.args[0] for call in close.call_args_list],[14,13,12,11,10])
    def test_kernel_writer_refuses_missing_v2_mount_or_wrong_role_before_write(self):
        with patch.object(acceptance.os,'geteuid',return_value=0),patch.object(acceptance.Path,'resolve',lambda path:path),patch.object(acceptance.Path,'read_text',return_value='1 2 0:27 / /sys/fs/cgroup rw - tmpfs tmpfs rw'),patch.object(acceptance.os,'open') as opened,patch.object(acceptance.os,'write') as write:
            with self.assertRaisesRegex(ValueError,'cgroup-v2'):acceptance.kernel_cgroup_kill('gateway',1234)
            with self.assertRaises(PermissionError):acceptance.kernel_cgroup_kill('../sshd',1234)
            opened.assert_not_called();write.assert_not_called()
    def test_kill_verification_captures_status_before_stop_and_requires_old_processes_gone(self):
        pinned=dict(InvocationID='a'*32)
        runner=Mock(return_value=argparse.Namespace(stdout='ExecMainCode=2\nExecMainStatus=9\nInvocationID='+'a'*32))
        captured=acceptance.cgroup_sigkill_status('gateway',pinned,runner)
        self.assertEqual(runner.call_args.kwargs['timeout'],1)
        def gone(path,*args,**kwargs):raise FileNotFoundError(str(path))
        with patch.object(acceptance.Path,'read_text',gone):
            result=acceptance.cgroup_kill_verified('gateway',pinned,[dict(pid=1234,start_time='123')],captured)
            self.assertEqual(result['main_status'],9)
            for bad in (dict(captured,main_status=0),dict(captured,original_invocation='b'*32),dict(captured,unit=acceptance.UNITS['validator'])):
                with self.assertRaises(ValueError):acceptance.cgroup_kill_verified('gateway',pinned,[],bad)
        for value in ('ExecMainCode=1\nExecMainStatus=0\nInvocationID='+'a'*32,'ExecMainCode=2\nExecMainStatus=15\nInvocationID='+'a'*32,'ExecMainCode=2\nExecMainStatus=9\nInvocationID='+'b'*32):
            with self.assertRaises(ValueError):acceptance.cgroup_sigkill_status('gateway',pinned,Mock(return_value=argparse.Namespace(stdout=value)))
        pending=Mock(return_value=argparse.Namespace(stdout='ExecMainCode=0\nExecMainStatus=0\nInvocationID='+'a'*32))
        self.assertIsNone(acceptance.cgroup_sigkill_status('gateway',pinned,pending))
        with patch.object(acceptance.Path,'read_text',return_value='1234 (old) '+' '.join(['x']*19+['123'])):
            self.assertIsNone(acceptance.cgroup_kill_verified('gateway',pinned,[dict(pid=1234,start_time='123')],captured))
    def test_outsider_rejects_root_service_groups_capabilities_or_no_new_privs_missing(self):
        account=argparse.Namespace(pw_uid=1003,pw_gid=1003)
        def lookup(name):return account if name=='zolana058t' else argparse.Namespace(pw_uid=1001 if name=='zolana058v' else 1002,pw_gid=1001 if name=='zolana058v' else 1002)
        base=dict(CapEff='0',CapPrm='0',CapAmb='0',NoNewPrivs='1')
        with patch.object(acceptance,'identity',side_effect=lookup),patch.object(acceptance.grp,'getgrnam',return_value=argparse.Namespace(gr_gid=1004)),patch.object(acceptance.os,'getuid',return_value=1003),patch.object(acceptance.os,'geteuid',return_value=1003),patch.object(acceptance.os,'getgroups',return_value=[]):
            for changed in (dict(CapEff='1'),dict(CapPrm='1'),dict(CapAmb='1'),dict(NoNewPrivs='0')):
                with patch.object(acceptance,'proc_status',return_value=dict(base,**changed)),self.assertRaises(PermissionError):acceptance.outsider_probe({})
            with patch.object(acceptance,'proc_status',return_value=base),patch.object(acceptance.os,'getgroups',return_value=[1002]),self.assertRaises(PermissionError):acceptance.outsider_probe({})
    def test_namespace_positive_rpc_refuses_writes_routes_and_nonroot(self):
        valid=dict(address='127.0.0.1:1234',method='getGenesisHash',params=[])
        with patch.object(acceptance.os,'geteuid',return_value=0):
            for change in (dict(method='sendTransaction'),dict(address='http://outside/'),dict(params={}),dict(extra=1)):
                with self.assertRaises(ValueError):acceptance.namespace_rpc(dict(valid,**change))
        with patch.object(acceptance.os,'geteuid',return_value=1003),self.assertRaises(PermissionError):acceptance.namespace_rpc(valid)
    def test_service_requires_actual_credentials_cgroup_and_sandbox_not_just_unit_strings(self):
        keys=dict(MainPID='12345',ControlGroup='/system.slice/'+acceptance.UNITS['validator'],InvocationID='a'*32,
            User='zolana058v',Group='zolana058v',Restart='on-failure',NoNewPrivileges='yes',ProtectSystem='strict',
            PrivateNetwork='yes',JoinsNamespaceOf='',UMask='0077',CapabilityBoundingSet='',ReadWritePaths=str(acceptance.VALROOT),
            ActiveState='active',SubState='running')
        status=dict(Uid='1001 1001 1001 1001',Gid='1001 1001 1001 1001',NoNewPrivs='1',CapEff='0',CapPrm='0',CapAmb='0',CapBnd='0')
        def read(path,*_args,**_kwargs):
            if str(path).endswith('/cgroup'):return '0::'+keys['ControlGroup']+'\n'
            return '12345 (python weird name) '+' '.join(['x']*19+['123456'])
        def runner_for(values):return Mock(return_value=argparse.Namespace(stdout='\n'.join(k+'='+v for k,v in values.items())))
        with patch.object(acceptance,'identity',return_value=argparse.Namespace(pw_name='zolana058v',pw_uid=1001,pw_gid=1001)),patch.object(acceptance,'proc_status',return_value=status),patch.object(acceptance.Path,'read_text',read),patch.object(acceptance.os,'readlink',return_value='net:[123]'):
            self.assertEqual(acceptance.service_properties('validator',runner_for(keys))['pid'],12345)
            for changed in (dict(NoNewPrivileges='no'),dict(User='root'),dict(ControlGroup='/system.slice/sshd.service'),dict(PrivateNetwork='no')):
                with self.assertRaises(ValueError):acceptance.service_properties('validator',runner_for(dict(keys,**changed)))
            with patch.object(acceptance,'proc_status',return_value=dict(status,CapBnd='1')),self.assertRaises(ValueError):acceptance.service_properties('validator',runner_for(keys))
    def test_ready_rejects_changed_sealed_config_keys_genesis_or_duplicate_endpoints(self):
        peers=[dict(identity=acceptance.previous.b58(bytes([n])*32),rpc='127.0.0.1:'+str(10000+n),native_ingress='127.0.0.1:'+str(11000+n)) for n in (1,2,3)]
        network=dict(network=[67]*32,genesis_hash=acceptance.previous.b58(bytes([9])*32))
        relay=acceptance.previous.b58(bytes([5])*32)
        config=dict(network=network,validator_identities=[p['identity'] for p in peers],relay_public_key=relay,validator_uid=1001)
        ready=dict(format='zolana-native-service-ready-v1',network=network,pool_format='NPOOL004',mac_relay=relay,
            peers=peers,config_sha256='a'*64,generation='b'*64,namespace_inode=123,supervisor_pid=100,child_pid=101,ready_at=1)
        with patch.object(acceptance,'read_owned',return_value=json.dumps(ready).encode()):
            self.assertEqual(acceptance.read_ready(config,'a'*64),ready)
        for changed in (dict(config_sha256='c'*64),dict(pool_format='NPOOL003'),dict(namespace_inode=True),
                        dict(mac_relay=peers[0]['identity']),dict(peers=[peers[0]]*3)):
            with patch.object(acceptance,'read_owned',return_value=json.dumps(dict(ready,**changed)).encode()),self.assertRaises(ValueError):
                acceptance.read_ready(config,'a'*64)
    def recovery(self):
        job=self.root/('c'*64);job.mkdir(mode=0o700)
        user=self.root/'wallet.json.shielded.json';user.write_bytes(b'original user proof');user.chmod(0o600)
        native=json.dumps(dict(signature=self.signature,packet_sha256=self.digest,gross_cap=150000000,reserved_debit=2)).encode()
        (job/'relay.native.json').write_bytes(native);(job/'relay.native.json').chmod(0o600)
        adapter=Mock(gateway_uid=1002,client_uid=1003,faults=argparse.Namespace(record=dict(signature=self.signature,packet_sha256=self.digest)))
        def wait(callback,seconds):
            self.assertEqual(seconds,90)
            for _ in range(3):
                value=callback()
                if value:return value
            raise TimeoutError('original remains unknown')
        adapter.wait=wait
        receipt=dict(accepted=True,encrypted_checkpoint_durable=True,signature=self.signature,id=job.name)
        return adapter,job,user,user.read_bytes(),native,receipt
    def test_per_owner_recovery_only_resolves_original_and_requires_durable_receipt(self):
        adapter,job,user,old_user,old_native,receipt=self.recovery();calls=[]
        original=acceptance.read_owned
        def reader(path,uid,maximum=65536,mode=None):
            calls.append(uid);self.assertEqual(uid,1002 if Path(path).parent==job else 1003)
            return original(path,os.getuid(),maximum,mode)
        count=0
        def api(*args):
            nonlocal count
            self.assertEqual(args,('alice','resolve'));count+=1
            if count==1:raise RuntimeError('actual wallet HTTP API: native outcome remains unresolved; original proof retained, no replacement authorized')
            acceptance.previous.save(job/'outcome.json',dict(accepted=True,signature=self.signature,packet_sha256=self.digest,reserved_gross_debit=2))
            (job/'relay.native.json').unlink();user.unlink();acceptance.previous.save(user.with_suffix('.receipt.json'),receipt)
            return receipt
        adapter.api.side_effect=api
        with patch.object(acceptance,'read_owned',side_effect=reader):self.assertEqual(acceptance.resolve_original(adapter,job,user,old_user,old_native),receipt)
        self.assertEqual(adapter.api.call_count,2);self.assertEqual(set(calls),{1002,1003})
    def test_recovery_never_retries_changed_budget_or_unrelated_failure(self):
        adapter,job,user,old_user,old_native,_=self.recovery();adapter.gateway_uid=adapter.client_uid=os.getuid()
        adapter.api.side_effect=RuntimeError('canonical proof invalid')
        with self.assertRaisesRegex(RuntimeError,'canonical proof invalid'):acceptance.resolve_original(adapter,job,user,old_user,old_native)
        self.assertEqual(adapter.api.call_count,1)
        (job/'relay.native.json').write_text(json.dumps(dict(signature=self.signature,packet_sha256=self.digest,reserved_debit=3)))
        with self.assertRaisesRegex(ValueError,'gross reservation changed'):acceptance.resolve_original(adapter,job,user,old_user,old_native)
        self.assertEqual(adapter.api.call_count,1)


if __name__=='__main__':unittest.main()
