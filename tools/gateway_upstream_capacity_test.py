"""Disposable concurrency/deadline checks; no wallets, host services or network."""
import concurrent.futures
import json
import threading
import time
import types
import unittest
from unittest.mock import patch
import testnet_gateway as G


class CapacityTests(unittest.TestCase):
    def app(self, operator):
        app = object.__new__(G.Gateway)
        app.operator = operator
        return app

    def test_snapshot_and_ordinary_forward_share_two_permits(self):
        entered, release, lock = threading.Event(), threading.Event(), threading.Lock()
        active = peak = 0
        seen = []
        def forward(raw, timeout):
            nonlocal active, peak
            with lock:
                active += 1; peak = max(peak, active)
                seen.append(json.loads(raw)['params'][0])
                if active == 2: entered.set()
            try:
                if not release.wait(2): raise ValueError('fixture release timeout')
                query = json.loads(raw)
                return json.dumps(dict(jsonrpc='2.0',id=query['id'],result=query['params'][0])).encode()
            finally:
                with lock: active -= 1
        app = self.app(types.SimpleNamespace(forward=forward))
        calls = [dict(method='getMinimumBalanceForRentExemption',params=[n]) for n in range(4)]
        def snapshot():
            return app._upstream_reads(calls, time.monotonic()+3,
                single_requests=True,response_budget=[0],parallel_snapshot=True)
        ordinary = json.dumps(dict(jsonrpc='2.0',id=42,
            method='getMinimumBalanceForRentExemption',params=[99])).encode()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            futures = [pool.submit(snapshot), pool.submit(snapshot), pool.submit(app.forward,ordinary,3)]
            try:
                self.assertTrue(entered.wait(2))
                time.sleep(.02)
                with lock:self.assertEqual(peak,2)
            finally:release.set()
            self.assertEqual(futures[0].result(timeout=3),list(range(4)))
            self.assertEqual(futures[1].result(timeout=3),list(range(4)))
            self.assertEqual(json.loads(futures[2].result(timeout=3))['result'],99)
        self.assertEqual(peak,2)
        self.assertEqual(sorted(seen),sorted(list(range(4))*2+[99]))

    def test_queued_capacity_timeout_never_calls_transport_or_loses_a_permit(self):
        calls=[];app=self.app(types.SimpleNamespace(forward=lambda *a,**k:calls.append((a,k))))
        self.assertTrue(G._UPSTREAM_SLOTS.acquire(False))
        self.assertTrue(G._UPSTREAM_SLOTS.acquire(False))
        try:
            began=time.monotonic()
            with self.assertRaisesRegex(ValueError,'capacity deadline'):app.forward(b'unchanged',timeout=.02)
            self.assertLess(time.monotonic()-began,.5)
            self.assertEqual(calls,[])
        finally:
            G._UPSTREAM_SLOTS.release();G._UPSTREAM_SLOTS.release()
        self.assertTrue(G._UPSTREAM_SLOTS.acquire(False));self.assertTrue(G._UPSTREAM_SLOTS.acquire(False))
        self.assertFalse(G._UPSTREAM_SLOTS.acquire(False))
        G._UPSTREAM_SLOTS.release();G._UPSTREAM_SLOTS.release()

    def test_wait_is_subtracted_from_original_deadline_and_expired_acquire_releases(self):
        class Slots:
            def __init__(self):self.waits=[];self.released=0
            def acquire(self,timeout):self.waits.append(timeout);return True
            def release(self):self.released+=1
        for after,expected in ((102,3),(106,None)):
            slots=Slots();seen=[]
            app=self.app(types.SimpleNamespace(forward=lambda raw,timeout:seen.append((raw,timeout)) or b'exact'))
            with self.subTest(after=after),patch.object(G,'_UPSTREAM_SLOTS',slots),patch.object(G.time,'monotonic',side_effect=[100,100,after]):
                if expected is None:
                    with self.assertRaisesRegex(ValueError,'capacity deadline'):app.forward(b'exact-request',5)
                    self.assertEqual(seen,[])
                else:
                    self.assertEqual(app.forward(b'exact-request',5),b'exact')
                    self.assertEqual(seen,[(b'exact-request',expected)])
            self.assertEqual(slots.waits,[5]);self.assertEqual(slots.released,1)

    def test_operator_and_opener_failures_preserve_exception_and_release_permits(self):
        failure=OSError('fixture-private-error')
        def refuse(*a,**k):raise failure
        class Opener:
            open=staticmethod(refuse)
        for operator in (types.SimpleNamespace(forward=refuse),None):
            app=self.app(operator);app.upstream='http://127.0.0.1:1';app.opener=Opener()
            with self.subTest(operator=operator is not None),self.assertRaises(OSError) as caught:app.forward(b'exact',.2)
            self.assertIs(caught.exception,failure)
            self.assertTrue(G._UPSTREAM_SLOTS.acquire(False));self.assertTrue(G._UPSTREAM_SLOTS.acquire(False))
            self.assertFalse(G._UPSTREAM_SLOTS.acquire(False))
            G._UPSTREAM_SLOTS.release();G._UPSTREAM_SLOTS.release()


if __name__=='__main__':unittest.main()
