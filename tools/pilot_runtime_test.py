"""Real native keys/admission, mocked funding observations and bounded lifecycle faults."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

import pilot_cohort as cohort
import pilot_cohort_test as fixtures
import pilot_funding as funding
from pilot_funding_test import ObservationReader,observation
import pilot_runtime as runtime
from direct_tls_test import config as tls_config
from local_test_tls import create as create_tls
from wallet_release import atomic,create,decode,encode,read,sha


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        fixtures.PilotTests.setUp(self)
        short=tempfile.TemporaryDirectory(prefix='p45-',dir='/private/tmp');self.addCleanup(short.cleanup)
        self.base=Path(short.name).resolve();self.base.chmod(0o700);self.root=self.base/'pilot'
        self.password=self.base/'password';create(self.password,b'only-disposable-test-password')
        self.net=self.base/'net';self.net.mkdir(mode=0o700)
        value={k:self.value['source_profile'][k] for k in ('network','genesis_hash','program','pool','pool_format','recipient_withdrawals')}
        value.update(key_mode='local-testnet-rehearsal-v1',fixture_keys_are_public=False,raw_rpc_isolation=True,raw_rpc_host_isolation=True)
        create(self.net/'network.json',encode(value))
        key=encode(dict(format='native-rpc-unix-v1',token='a'*64,sockets={str(p):str(self.net/f'rpc-{p}.sock') for p in (18899,19899,28899,29899)}))
        create(self.net/'rpc-access.key',key)
        create(self.net/'raw-rpc-required.json',encode(dict(format='native-raw-rpc-unix-v1',credential_sha256=sha(key))))
        self.tls=self.base/'tls';create_tls(self.tls);self.listeners={}
        self.value['tester_profile'].update(local_tls_ca_pem=(self.tls/'ca.crt').read_text())
        for name in ('rpc','faucet'):
            port=fixtures.unused_port();endpoint=f'https://127.0.0.1:{port}'
            self.value['tester_profile'][name]=dict(transport='https',url=endpoint)
            config=self.base/(name+'.json');create(config,encode(tls_config(endpoint,port,self.tls/'server.crt',self.tls/'server.key')))
            self.listeners[name]=dict(config=str(config),sha256=sha(config.read_bytes()),cert=str(self.tls/'server.crt'),key=str(self.tls/'server.key'))
        self.digest=sha(encode(cohort.validate(self.value)))
        cohort.prepare(self.value,self.root,self.digest,self.password,rpc_access_file=self.net/'rpc-access.key')
        funding.make_intent(self.root,self.digest)
        self.receipt=funding.verify(self.root,self.digest,self.password,'initial',reader_factory=ObservationReader,scan_fn=observation)
    def bind(self):
        result=runtime.prepare(self.net,self.root,self.digest,'initial',self.password,self.listeners)
        self.binding=result['binding_sha256'];return result
    def wallet_bytes(self):return read(self.root/'faucet/wallet.enc.json',16384,secret=True)
    def test_binding_requires_funded_unused_pinned_private_network_and_never_reinitializes(self):
        original=self.wallet_bytes();result=self.bind()
        self.assertFalse(result['services_started']);self.assertEqual(result['phase'],'bound')
        self.assertEqual(result['transfers_submitted'],0)
        with runtime.checked(self.net,self.binding) as (_,__,state):self.assertEqual(state['phase'],'bound')
        with self.assertRaises(ValueError):self.bind()
        self.assertEqual(original,self.wallet_bytes())
    def test_stale_unused_receipt_is_not_activated_or_renewed(self):
        self.bind();before=read(self.net/runtime.FILES[2],4096)
        with patch.object(runtime.time,'time',return_value=self.receipt['expires_at']):
            with self.assertRaises(ValueError):runtime.activate(self.net,self.binding)
        self.assertEqual(before,read(self.net/runtime.FILES[2],4096))
    def test_expiry_during_unlock_cannot_commit_first_activation(self):
        self.bind();before=read(self.net/runtime.FILES[2],4096);clock=[time.time()]
        actual=cohort.native
        def unlocking(*args,**kwargs):
            result=actual(*args,**kwargs)
            if len(args)>1 and args[1]=='address':clock[0]=self.receipt['expires_at']
            return result
        with patch.object(runtime.time,'time',side_effect=lambda:clock[0]),patch.object(cohort,'native',side_effect=unlocking):
            with self.assertRaises(ValueError):runtime.activate(self.net,self.binding)
        self.assertEqual(before,read(self.net/runtime.FILES[2],4096))
    def test_partial_binding_is_preserved_and_never_recreated(self):
        actual=runtime.create
        def interrupted(path,data):
            actual(path,data)
            if path.name==runtime.FILES[0]:raise RuntimeError('interrupted binding')
        with patch.object(runtime,'create',side_effect=interrupted),self.assertRaises(RuntimeError):self.bind()
        binding=sha(read(self.net/runtime.FILES[0],32768))
        with self.assertRaises((ValueError,OSError)):runtime.activate(self.net,binding)
        with self.assertRaises(ValueError):self.bind()
        self.assertFalse((self.net/runtime.FILES[2]).exists())
    def test_active_restart_keeps_activation_after_expiry_and_issuance(self):
        self.bind();original=self.wallet_bytes();_,__,first=runtime.activate(self.net,self.binding)
        cohort.issue(self.root,self.digest,'tester-01')
        with self.assertRaises(ValueError):funding.check(self.root,self.digest,'initial')
        with patch.object(runtime.time,'time',return_value=self.receipt['expires_at']+3600):
            _,__,again=runtime.activate(self.net,self.binding)
            self.assertEqual(first,again)
            with runtime.checked(self.net,self.binding) as (_,__,state):self.assertEqual(state,first)
        self.assertEqual(original,self.wallet_bytes());self.assertEqual(cohort.audit(self.root,self.digest)['issued'],1)
    def crash_activation(self,phase):
        self.bind();before=self.wallet_bytes()
        script='''import os,signal,sys
from pathlib import Path
from unittest.mock import patch
import pilot_runtime as r
original=r.atomic
def crash(path,value):
    hit=path.name=='pilot-runtime-state.json'
    if hit and sys.argv[3]=='before':os.kill(os.getpid(),signal.SIGKILL)
    original(path,value)
    if hit:os.kill(os.getpid(),signal.SIGKILL)
with patch.object(r,'atomic',side_effect=crash):r.activate(Path(sys.argv[1]),sys.argv[2])
'''
        child=subprocess.run([sys.executable,'-B','-c',script,str(self.net),self.binding,phase],cwd=runtime.PROJECT/'tools',capture_output=True,timeout=40)
        self.assertEqual(child.returncode,-signal.SIGKILL)
        state=decode(read(self.net/runtime.FILES[2],4096))
        self.assertEqual(state['phase'],'bound' if phase=='before' else 'active')
        _,__,activated=runtime.activate(self.net,self.binding)
        if phase=='after':self.assertEqual(activated,state)
        self.assertEqual(before,self.wallet_bytes())
    def test_activation_sigkill_before_commit_retries_without_worker_or_transfer(self):self.crash_activation('before')
    def test_activation_sigkill_after_commit_reuses_original_time_and_identity(self):self.crash_activation('after')
    def test_missing_binding_activation_clock_or_marker_never_falls_back_or_recreates(self):
        self.bind();runtime.activate(self.net,self.binding);before=self.wallet_bytes()
        for name in runtime.FILES:
            p=self.net/name;saved=self.net/(name+'.retained');p.rename(saved)
            try:
                with self.assertRaises((ValueError,OSError)):runtime.activate(self.net,self.binding)
                self.assertFalse(p.exists())
            finally:saved.rename(p)
        self.assertEqual(before,self.wallet_bytes())
    def test_changed_inputs_and_legacy_faucet_are_denied(self):
        self.bind()
        for item in [self.password,self.net/'network.json',self.root/'faucet/rpc-access.key',Path(self.listeners['rpc']['config']),self.tls/'server.crt']:
            before=item.read_bytes();item.write_bytes(before+b' ')
            try:
                with self.assertRaises((ValueError,OSError)):runtime.activate(self.net,self.binding)
            finally:item.write_bytes(before)
        with patch.object(runtime,'pins',return_value={}):
            with self.assertRaises(ValueError):runtime.activate(self.net,self.binding)
        create(self.net/'ingress-setup.json',b'{}')
        with self.assertRaises(ValueError):runtime.activate(self.net,self.binding)
    def test_initial_pending_funding_blocks_but_active_pending_journals_are_preserved(self):
        self.bind();pending=Path(str(self.root/'faucet/wallet.enc.json')+'.pending.json');create(pending,b'{"original":"pending"}')
        with self.assertRaises(ValueError):runtime.activate(self.net,self.binding)
        pending.rename(pending.with_suffix('.retained'))
        runtime.activate(self.net,self.binding);create(pending,b'{"original":"active-pending"}')
        runtime.activate(self.net,self.binding);self.assertEqual(pending.read_bytes(),b'{"original":"active-pending"}')
    def test_receipt_replacement_and_clock_rollback_fail_even_for_active_cohort(self):
        self.bind();runtime.activate(self.net,self.binding)
        receipt=self.root/'funding-checks/initial.json';before=receipt.read_bytes();receipt.write_bytes(before+b' ')
        with self.assertRaises(ValueError):runtime.activate(self.net,self.binding)
        receipt.write_bytes(before)
        clock=decode(read(self.net/runtime.FILES[3],4096));atomic(self.net/runtime.FILES[3],dict(clock,last_time=int(time.time())+100))
        with self.assertRaises(ValueError):runtime.activate(self.net,self.binding)
    def test_retention_failure_prevents_activation_and_worker_start(self):
        self.bind();retention=SimpleNamespace(root=self.net,healthy=lambda:False)
        with patch.object(runtime,'activate') as activate,self.assertRaises(ValueError):runtime.Ingress(self.net,self.binding,retention)
        activate.assert_not_called()
        before=read(self.net/runtime.FILES[3],4096)
        with funding.native_lock(self.net/'pilot-runtime.lock'):
            with self.assertRaises(BlockingIOError):
                with funding.native_lock(self.net/'pilot-runtime.lock'):pass
            child=subprocess.run([sys.executable,'-B',str(runtime.PROJECT/'tools/pilot_runtime.py'),'check',
                '--network-root',str(self.net),'--binding-sha256',self.binding],capture_output=True,timeout=15)
            self.assertNotEqual(child.returncode,0)
        self.assertEqual(before,read(self.net/runtime.FILES[3],4096))
    def lifecycle(self,failure):
        self.bind();events=[];children=[Mock(pid=100,restart_tip=None),Mock(pid=101,restart_tip=None)]
        for child in children:child.poll.return_value=None
        retention=Mock();retention.healthy.return_value=True
        def retaining():
            events.append('retaining')
            if failure=='retention':raise ValueError('retention failed')
        retention.start.side_effect=retaining;retention.close.side_effect=lambda:events.append('retention-close')
        ingress=Mock();ingress.healthy.return_value=False;ingress.faucet.child=None
        ingress.close.side_effect=lambda:events.append('ingress-close')
        def opening(*args):events.append('ingress');return ingress
        def stopping(root,i):events.append('stop'+str(i));children[i].poll.return_value=0
        with patch.object(runtime.os,'getpgrp',return_value=os.getpid()),patch('localnet.load',return_value={}),\
             patch('localnet.start',side_effect=lambda root,i,**kw:children[i]),patch('localnet.wait_rpc'),patch('localnet.quiet'),\
             patch('localnet.rpc',return_value=10),patch('localnet.stop',side_effect=stopping),\
             patch('history_retention.Retention',return_value=retention),patch.object(runtime,'Ingress',side_effect=opening):
            with self.assertRaises(ValueError):runtime.supervise(self.net,self.binding,duration=30)
        self.assertEqual(decode(read(self.net/'pilot-runtime-status.json',4096))['phase'],'blocked')
        return events
    def test_retention_start_failure_stops_validators_without_opening_ingress(self):
        self.assertEqual(self.lifecycle('retention'),['retaining','retention-close','stop1','stop0'])
    def test_ingress_worker_failure_closes_ingress_retention_and_validators(self):
        self.assertEqual(self.lifecycle('worker'),['retaining','ingress','ingress-close','retention-close','stop1','stop0'])
    def test_grant_child_nonzero_is_not_mistaken_for_a_healthy_idle_worker(self):
        app=runtime.RuntimeFaucet(self.root/'faucet',self.password)
        child=Mock(returncode=1)
        with patch.object(runtime.subprocess,'Popen',return_value=child):app.work()
        self.assertTrue(app.failed.is_set());self.assertIsNone(app.child);app.close()


class ResumeGuardTests(unittest.TestCase):
    def test_resume_refuses_completed_or_unrelated_failure_without_rewriting_evidence(self):
        from pilot_runtime_localnet import checkpoint
        with tempfile.TemporaryDirectory(prefix='p45guard-',dir='/private/tmp') as folder:
            root=Path(folder);result=root/'pilot-runtime-result.json'
            for value in (dict(status='passed',events=[]),dict(status='failed',error='unrelated',events=[]),
                          dict(status='failed',error='Unknown wallet action.',events=[])):
                atomic(result,value);before=result.read_bytes()
                with self.assertRaises(ValueError):checkpoint(root,root)
                self.assertEqual(result.read_bytes(),before)
                self.assertEqual({p.name for p in root.iterdir()},{result.name})
    def test_owned_group_sigkill_and_repeated_cleanup_do_not_signal_an_empty_group(self):
        from pilot_runtime_localnet import PilotHost
        with tempfile.TemporaryDirectory(prefix='p45group-',dir='/private/tmp') as folder:
            root=Path(folder);trial=PilotHost(root/'unused',root,None,None)
            child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True)
            trial.host=child
            try:
                trial.stop_host(crash=True)
                self.assertEqual(child.returncode,-signal.SIGKILL);self.assertIsNone(trial.host)
                trial.stop_host(crash=True)
            finally:
                if child.poll() is None:child.kill();child.wait(timeout=5)


if __name__=='__main__':unittest.main()
