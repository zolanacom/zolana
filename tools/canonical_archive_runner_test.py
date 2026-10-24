"""Synthetic lifecycle, actual Capture/Reader/ArchiveRPC and gateway permits."""
from contextlib import closing
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import canonical_archive_capture as capture
from canonical_archive_capture_test import Fixture
from canonical_archive_runner import RollingCapture, MIN_FREE_BYTES
from canonical_archive_rolling import RollingArchive
from canonical_archive_store import Capture, Reader, encoded
from canonical_archive_store_test import NETWORK, page, target
import testnet_gateway


class RollingCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zolana-capture-runner-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / 'canonical.sqlite3'
        self.fixture = Fixture([1, 3, 4, 7])
        self.source = self.fixture.source(0)
        self.gateway = SimpleNamespace(info=dict(network=copy.deepcopy(NETWORK), invite_required=True,
            rpc_audience='https://fixture.invalid/'),
            forward=lambda raw,timeout:self.source(raw,timeout=min(timeout,6)))
        self.policy = dict(network=copy.deepcopy(NETWORK), max_database_bytes=16*1024**2,
            min_free_bytes=MIN_FREE_BYTES, batch_blocks=2, max_batches=1,
            timeout=1, batch_timeout=1, poll_seconds=1)
        self.disk = patch.object(capture.shutil, 'disk_usage', return_value=SimpleNamespace(free=2**50))
        self.disk.start()
        self.addCleanup(self.disk.stop)

    def worker(self, gateway=None, policy=None):
        value = RollingCapture(gateway or self.gateway, self.path, policy=policy or self.policy)
        self.addCleanup(value.close)
        return value

    def wait(self, predicate, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(.01)
        self.fail('bounded synthetic worker condition deadline')

    def test_explicit_start_bounded_windows_resume_and_concurrent_serving_never_claims_suffix(self):
        worker = self.worker()
        self.assertFalse(self.path.exists(), 'constructor does not create a database or make RPC calls')
        self.assertEqual(self.fixture.calls, [])
        self.assertEqual(worker.snapshotstatus()['phase'], 'new')
        worker.start()
        first = self.wait(lambda: (s if (s:=worker.snapshotstatus())['last_result'] is not None else None))
        self.assertEqual((first['last_result']['status'], first['last_result']['committed_slot']), ('bounded',3))
        serving = RollingArchive(self.gateway, self.path)
        with self.assertRaisesRegex(ValueError, 'committed'):
            serving.page(dict(id=1,params=[0,7,None]))
        complete = self.wait(lambda: (s if (s:=worker.snapshotstatus())['last_result'] is not None
            and s['last_result']['status']=='complete' else None))
        self.assertEqual(complete['last_result']['committed_slot'],7)
        value = json.loads(serving.page(dict(id=1,params=[0,7,None])))['result']
        self.assertTrue(value['complete'])
        self.assertEqual(value['blocks'],self.fixture.items)
        self.assertEqual(value['blocks'][0]['block']['transactions'][1]['meta']['err'],
                         {'InstructionError':[0,'Custom']})
        worker.close()
        self.assertFalse(worker.snapshotstatus()['thread_alive'])
        with self.assertRaises(ValueError): worker.start()

    def test_failure_ends_window_without_retry_then_next_window_resumes_and_status_is_copied(self):
        failed = [True]
        def change(peer, method, params, value):
            if failed[0]: raise ConnectionError('synthetic transport failure')
            return value
        self.fixture.change = change
        worker = self.worker(policy=dict(self.policy,batch_blocks=16))
        worker.start()
        status = self.wait(lambda: (s if (s:=worker.snapshotstatus())['failures']==1 else None))
        self.assertEqual(len(self.fixture.calls),1)
        time.sleep(.05)
        self.assertEqual(len(self.fixture.calls),1,'no RPC retry inside the failed capture window')
        self.assertEqual(status['last_error'],1)
        with Reader(self.path,NETWORK,NETWORK['genesis_hash']) as reader:
            self.assertEqual(reader.slot,0)
        failed[0] = False
        status = self.wait(lambda: (s if (s:=worker.snapshotstatus())['last_result'] is not None else None))
        self.assertEqual(status['last_result']['status'],'complete')
        status['last_result']['committed_slot']=999
        self.assertEqual(worker.snapshotstatus()['last_result']['committed_slot'],7)
        began=time.monotonic(); worker.close()
        self.assertLess(time.monotonic()-began,.5,'stop interrupts the poll wait')

    def test_fresh_page_wakes_capture_across_bounded_windows_before_reader_opens(self):
        self.fixture.tip=1
        worker=self.worker(policy=dict(self.policy,batch_blocks=1,poll_seconds=30))
        worker.start()
        self.wait(lambda:worker.snapshotstatus()['phase']=='idle')
        with Reader(self.path,NETWORK,NETWORK['genesis_hash'])as reader:
            self.assertEqual(reader.slot,1)
        self.fixture.tip=7
        serving=RollingArchive(self.gateway,self.path,coverage=worker.ensure_coverage)
        began=time.monotonic()
        value=json.loads(serving.page(dict(id=1,params=[0,7,None])))['result']
        self.assertLess(time.monotonic()-began,2,'fresh demand wakes a30s poll and every bounded continuation')
        self.assertTrue(value['complete'])
        self.assertEqual(value['blocks'],self.fixture.items)
        self.assertEqual(value['anchor'],target(self.fixture.items))
        self.assertGreaterEqual(worker.snapshotstatus()['windows'],4)
        # Continuation still pins the exact fresh target; catching up does not
        # weaken anchors or replace a nonzero after_slot.
        value=json.loads(serving.page(dict(id=2,params=[3,7,target(self.fixture.items)])))['result']
        self.assertEqual(value['after_slot'],3)
        self.assertEqual(value['blocks'],self.fixture.items[2:])

    def test_already_covered_pages_make_no_extra_capture_windows_but_check_fresh_primary(self):
        worker=self.worker(policy=dict(self.policy,batch_blocks=16,poll_seconds=30))
        worker.start();self.wait(lambda:worker.snapshotstatus()['phase']=='idle')
        windows=worker.snapshotstatus()['windows']
        calls=len(self.fixture.calls)
        serving=RollingArchive(self.gateway,self.path,coverage=worker.ensure_coverage)
        first=json.loads(serving.page(dict(id=1,params=[0,7,None])))['result']
        second=json.loads(serving.page(dict(id=2,params=[3,7,first['anchor']])))['result']
        time.sleep(.05)
        self.assertEqual(worker.snapshotstatus()['windows'],windows,
                         'covered history pages must not wake the30s capture poll')
        self.assertEqual(self.fixture.calls[calls:],[
            (0,'getBlock',[7,capture.HEADER]),(0,'getBlock',[7,capture.HEADER])],
            'every page still makes exactly its fresh primary header check')
        self.assertTrue(first['complete']and second['complete'])
        self.assertEqual(first['blocks'],self.fixture.items)
        self.assertEqual(second['blocks'],self.fixture.items[2:])

    def test_stalled_capture_deadline_never_reports_empty_complete_or_holds_shared_lock(self):
        self.fixture.tip=3
        worker=self.worker(policy=dict(self.policy,poll_seconds=30))
        worker.start();self.wait(lambda:worker.snapshotstatus()['phase']=='idle')
        def bounded(target,deadline):
            worker.ensure_coverage(target,min(deadline,time.monotonic()+.15))
        serving=RollingArchive(self.gateway,self.path,coverage=bounded)
        began=time.monotonic()
        with self.assertRaisesRegex(ValueError,'deadline'):
            serving.page(dict(id=1,params=[0,7,None]))
        self.assertLess(time.monotonic()-began,.7)
        self.assertLessEqual(worker.snapshotstatus()['windows'],3,'no rapid retry loop when a source makes no progress')
        with Reader(self.path,NETWORK,NETWORK['genesis_hash'])as reader:
            self.assertEqual(reader.slot,3)
        # A timed-out request left no Reader lock behind; the next captured
        # commit and exact page work without closing/restarting the service.
        self.fixture.tip=7
        value=json.loads(RollingArchive(self.gateway,self.path,coverage=worker.ensure_coverage)
                         .page(dict(id=2,params=[0,7,None])))['result']
        self.assertTrue(value['complete'])
        self.assertEqual(value['blocks'],self.fixture.items)

    def test_coverage_failure_stop_and_corrupt_store_fail_closed(self):
        worker=self.worker(policy=dict(self.policy,poll_seconds=30))
        with self.assertRaisesRegex(ValueError,'not running'):
            worker.ensure_coverage(7,time.monotonic()+1)
        self.fixture.tip=3;worker.start()
        self.wait(lambda:worker.snapshotstatus()['phase']=='idle')
        self.fixture.change=lambda *args:(_ for _ in ()).throw(ConnectionError('fixture failed'))
        with self.assertRaisesRegex(ValueError,'failed before coverage'):
            worker.ensure_coverage(7,time.monotonic()+2)
        self.fixture.change=lambda peer,method,params,value:value
        with closing(sqlite3.connect(self.path))as db,db:
            db.execute('UPDATE state SET network=?',(encoded(dict(NETWORK,network=[8]*32)),))
        with self.assertRaisesRegex(ValueError,'network'):
            worker.ensure_coverage(3,time.monotonic()+2)
        worker.close()
        with self.assertRaisesRegex(ValueError,'not running'):
            worker.ensure_coverage(3,time.monotonic()+1)
        for value in [0,True,2**64,float('nan')]:
            with self.subTest(target=value),self.assertRaises(ValueError):
                worker.ensure_coverage(value,time.monotonic()+1)

    def test_close_rejects_late_transport_result_without_further_reads_or_commit(self):
        entered, release = threading.Event(), threading.Event()
        def forward(raw, *, timeout):
            entered.set()
            if not release.wait(3): raise TimeoutError('synthetic source deadline')
            return self.source(raw,timeout=timeout)
        self.gateway.forward = forward
        worker = self.worker()
        worker.start()
        self.assertTrue(entered.wait(2))
        errors=[]
        def stop():
            try: worker.close()
            except BaseException as error: errors.append(error)
        closer=threading.Thread(target=stop); closer.start()
        self.wait(lambda:worker.snapshotstatus()['phase']=='stopping')
        release.set(); closer.join(3)
        self.assertFalse(closer.is_alive())
        self.assertEqual(errors,[])
        self.assertEqual(len(self.fixture.calls),1)
        with Reader(self.path,NETWORK,NETWORK['genesis_hash']) as reader:
            self.assertEqual(reader.slot,0)
        time.sleep(.05)
        self.assertEqual(len(self.fixture.calls),1)
        self.assertEqual(worker.snapshotstatus()['phase'],'closed')

    def test_actual_gateway_forward_permits_are_shared_with_serving_no_alternate_operator(self):
        # No Gateway constructor, key read, socket or operator is created. Use
        # its actual forward method with one existing in-process fake operator.
        gateway=object.__new__(testnet_gateway.Gateway)
        gateway.info=self.gateway.info
        class ExistingOperator:
            calls=0
            def forward(inner,raw,*,timeout):
                inner.calls+=1
                return self.source(raw,timeout=min(timeout,6))
        operator=ExistingOperator(); gateway.operator=operator
        with Capture(self.path,NETWORK,NETWORK['genesis_hash'],target(self.fixture.items)) as writer:
            writer.append(encoded(page(self.fixture.items,target(self.fixture.items),0))); writer.commit()
        semaphore=threading.BoundedSemaphore(2)
        semaphore.acquire(); semaphore.acquire()
        worker=self.worker(gateway=gateway,policy=dict(self.policy,batch_blocks=16,timeout=2,batch_timeout=2))
        serving=RollingArchive(gateway,self.path)
        results,failures=[],[]
        with patch.object(testnet_gateway,'_UPSTREAM_SLOTS',semaphore):
            worker.start()
            self.wait(lambda:worker.snapshotstatus()['phase']=='capturing')
            def read():
                try: results.append(json.loads(serving.page(dict(id=1,params=[0,7,None])))['result'])
                except BaseException as error: failures.append(error)
            thread=threading.Thread(target=read);thread.start()
            try:
                time.sleep(.05)
                self.assertEqual(operator.calls,0,'both capture and serving must wait on existing global permits')
                semaphore.release()
                self.wait(lambda:worker.snapshotstatus()['last_result'] is not None)
                thread.join(3)
            finally:
                worker.close()
                semaphore.release()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures,[])
        self.assertEqual(results[0]['blocks'],self.fixture.items)
        self.assertIs(gateway.operator,operator)

    def test_broken_transport_exceeding_close_bound_latches_failure_and_discards_late_result(self):
        entered,release=threading.Event(),threading.Event()
        def ignores_timeout(raw,*,timeout):
            entered.set()
            if not release.wait(4):raise TimeoutError('synthetic bounded fixture cleanup')
            return self.source(raw,timeout=timeout)
        self.gateway.forward=ignores_timeout
        worker=self.worker(policy=dict(self.policy,timeout=.02,batch_timeout=.02))
        worker.start()
        self.assertTrue(entered.wait(2))
        began=time.monotonic()
        try:
            with self.assertRaises(TimeoutError):worker.close()
            self.assertLess(time.monotonic()-began,2.6)
            self.assertEqual(worker.snapshotstatus()['last_error'],2)
            with self.assertRaises(ValueError):worker.start()
        finally:
            release.set()
            self.wait(lambda:not worker.snapshotstatus()['thread_alive'])
        self.assertEqual(worker.snapshotstatus()['phase'],'failed')
        self.assertEqual(len(self.fixture.calls),1)
        with Reader(self.path,NETWORK,NETWORK['genesis_hash'])as reader:
            self.assertEqual(reader.slot,0)

    def test_policy_network_private_path_and_lifecycle_guards_are_strict_and_copied(self):
        for field,value in [('min_free_bytes',MIN_FREE_BYTES-1),('batch_blocks',17),('max_batches',65),
                            ('timeout',31),('batch_timeout',7),('poll_seconds',.9),('batch_blocks',True)]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.worker(policy=dict(self.policy,**{field:value}))
        for policy in [dict(self.policy,source='http://untrusted.invalid'),dict(self.policy,network=dict(NETWORK,network=[8]*32))]:
            with self.assertRaises(ValueError): self.worker(policy=policy)
        self.root.chmod(0o755)
        try:
            with self.assertRaises(ValueError): self.worker()
        finally:self.root.chmod(0o700)
        worker=self.worker()
        self.policy['network']['network'][0]=9
        self.policy['batch_blocks']=1000
        worker.start()
        with self.assertRaises(ValueError):worker.start()
        self.wait(lambda:worker.snapshotstatus()['last_result'] is not None)
        worker.close();worker.close()
        self.assertEqual(worker.snapshotstatus()['phase'],'closed')


if __name__=='__main__':unittest.main()
