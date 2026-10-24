"""Disposable loopback transport regression; no pilot, wallet or authority data.

The real four-slot BoundedServer and real Operator transport are exercised with
only a temporary dummy credential. Events/barriers hold two ordinary RPC reads
while snapshot requests compete; no timing sleeps create the collision.
"""
import concurrent.futures
from http.server import BaseHTTPRequestHandler
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from operator_transport import Operator
from test_faucet import BoundedServer
import testnet_gateway as gateway
from wallet_sync_snapshot import FULL


class PrivateCapsule:
    """Actual bounded server, synthetic single-object JSON-RPC responses only."""
    def __init__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="snapshot-transport-")
        self.root = Path(self.temporary.name)
        self.key = self.root / "dummy-operator"
        self.key.write_bytes(b"0" * 64)
        self.key.chmod(0o600)
        self.background_ready = threading.Barrier(3)
        self.release_background = threading.Event()
        self.first_pair = threading.Event()
        self.release_snapshots = threading.Event()
        self.two_overflows = threading.Event()
        self.lock = threading.Lock()
        self.active = self.maximum = self.gateway_active = self.gateway_maximum = 0
        self.background_count = self.gateway_count = self.overflows = 0
        self.requests = []
        self.failures = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                entered = background = False
                try:
                    length = int(self.headers["Content-Length"])
                    if (self.path != "/" or not 1 <= length <= 32768
                            or self.headers.get("Content-Type") != "application/json"
                            or self.headers.get("X-Native-Operator") != "0" * 64):
                        raise AssertionError("synthetic operator header or request mismatch")
                    request = json.loads(self.rfile.read(length))
                    if (not isinstance(request, dict) or set(request) != {"jsonrpc", "id", "method", "params"}
                            or request["jsonrpc"] != "2.0" or request["method"] != "getBlock"
                            or request["params"][1] != FULL):
                        raise AssertionError("only fixed single-object history reads expected")
                    slot = request["params"][0]
                    if type(slot) is not int or not 0 < slot <= 1001:
                        raise AssertionError("synthetic slot bound differs")
                    background = slot >= 1000
                    with owner.lock:
                        owner.active += 1
                        entered = True
                        owner.maximum = max(owner.maximum, owner.active)
                        owner.requests.append(slot)
                        if background:
                            owner.background_count += 1
                        else:
                            owner.gateway_count += 1
                            owner.gateway_active += 1
                            owner.gateway_maximum = max(owner.gateway_maximum, owner.gateway_active)
                            if owner.gateway_count == 2:
                                owner.first_pair.set()
                    if background:
                        owner.background_ready.wait(timeout=5)
                        if not owner.release_background.wait(timeout=5):
                            raise AssertionError("background release was not signaled")
                    elif not owner.release_snapshots.wait(timeout=5):
                        raise AssertionError("snapshot release was not signaled")
                    block = dict(parentSlot=slot - 1, blockHeight=slot, blockhash="1" * 32,
                                 previousBlockhash="1" * 32, transactions=[])
                    body = json.dumps(dict(jsonrpc="2.0", id=request["id"], result=block)).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except BaseException as error:
                    with owner.lock:
                        owner.failures.append(type(error).__name__)
                    self.close_connection = True
                finally:
                    if entered:
                        with owner.lock:
                            owner.active -= 1
                            if not background:
                                owner.gateway_active -= 1

        self.server = BoundedServer(("127.0.0.1", 0), Handler)
        original_shutdown = self.server.shutdown_request

        def observed_shutdown(request):
            # No handler can finish while both release events are clear. Thus a
            # close here is the actual BoundedServer overflow/refusal path.
            if not self.release_background.is_set() and not self.release_snapshots.is_set():
                with self.lock:
                    self.overflows += 1
                    if self.overflows == 2:
                        self.two_overflows.set()
            return original_shutdown(request)

        self.server.shutdown_request = observed_shutdown
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.background_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
        self.background = [self.background_executor.submit(self.direct, slot) for slot in (1000, 1001)]
        self.background_ready.wait(timeout=5)

    def direct(self, slot):
        return Operator(self.url, self.key).forward(json.dumps(dict(jsonrpc="2.0", id=0,
            method="getBlock", params=[slot, FULL])).encode(), timeout=5)

    def app(self, barrier=None):
        app = object.__new__(gateway.Gateway)
        operator = Operator(self.url, self.key)
        if barrier is not None:
            class SynchronizedOperator:
                def forward(self, raw, timeout):
                    barrier.wait(timeout=5)
                    return operator.forward(raw, timeout=timeout)
            app.operator = SynchronizedOperator()
        else:
            app.operator = operator
        return app

    def close(self):
        self.release_snapshots.set()
        self.release_background.set()
        failures = []
        try:
            for future in self.background:
                try:
                    future.result(timeout=5)
                except BaseException as error:
                    failures.append(error)
        finally:
            self.background_executor.shutdown(wait=True)
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            self.temporary.cleanup()
        if failures:
            raise failures[0]


def snapshot_reads(app, slots):
    return app._upstream_reads([dict(method="getBlock", params=[slot, dict(FULL)]) for slot in slots],
        time.monotonic() + 5, history=True, single_requests=True,
        response_budget=[0], parallel_snapshot=True)


class SnapshotTransportTests(unittest.TestCase):
    def test_historical_four_snapshot_workers_overflow_actual_four_slot_capsule(self):
        capsule = PrivateCapsule()
        try:
            # Force all four original reads past the cancellation precheck before
            # any actual socket can return a refusal. The server itself is real.
            app = capsule.app(threading.Barrier(4))
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as reads:
                # Explicitly reproduce the former four-at-once dispatch. The
                # current implementation already dispatches smaller waves, so
                # calling it cannot reproduce the removed configuration.
                futures = [reads.submit(app.operator.forward, json.dumps(dict(jsonrpc="2.0", id=0,
                    method="getBlock", params=[slot, dict(FULL)])).encode(), 5) for slot in (1, 2, 3, 4)]
                try:
                    self.assertTrue(capsule.first_pair.wait(timeout=5))
                    self.assertTrue(capsule.two_overflows.wait(timeout=5))
                    self.assertEqual(capsule.maximum, 4)
                    self.assertEqual(capsule.gateway_count, 2)
                    self.assertEqual(capsule.overflows, 2)
                finally:
                    capsule.release_snapshots.set()
                failures, successes = [], []
                for future in futures:
                    try:
                        successes.append(json.loads(future.result(timeout=5)))
                    except OSError as error:
                        failures.append(type(error).__name__)
                self.assertEqual(len(failures), 2)
                self.assertNotIn("TimeoutError", failures)
                self.assertEqual(len(successes), 2)
            self.assertEqual(capsule.failures, [])
        finally:
            capsule.close()

    def test_shared_two_slots_allow_two_snapshot_clients_and_ordinary_gateway_read(self):
        capsule = PrivateCapsule()
        try:
            begin = threading.Barrier(4)
            def ordinary():
                app = capsule.app()
                begin.wait(timeout=5)
                return json.loads(app.forward(json.dumps(dict(jsonrpc="2.0", id=0,
                    method="getBlock", params=[99, dict(FULL)])).encode(), timeout=5))["result"]
            def client(slots):
                app = capsule.app()
                begin.wait(timeout=5)
                return snapshot_reads(app, slots)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as reads:
                with patch.object(gateway, "_SNAPSHOT_READS", reads):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as callers:
                        extra = callers.submit(ordinary)
                        first = callers.submit(client, [1, 2, 3, 4])
                        second = callers.submit(client, [11, 12, 13, 14])
                        begin.wait(timeout=5)
                        try:
                            self.assertTrue(capsule.first_pair.wait(timeout=5))
                            self.assertEqual(capsule.maximum, 4)
                            self.assertEqual(capsule.gateway_maximum, 2)
                            self.assertEqual(capsule.overflows, 0)
                        finally:
                            capsule.release_snapshots.set()
                        self.assertEqual([b["blockHeight"] for b in first.result(timeout=5)], [1, 2, 3, 4])
                        self.assertEqual([b["blockHeight"] for b in second.result(timeout=5)], [11, 12, 13, 14])
                        self.assertEqual(extra.result(timeout=5)["blockHeight"], 99)
            self.assertEqual(capsule.overflows, 0)
            self.assertEqual(capsule.background_count, 2)
            self.assertEqual(capsule.gateway_count, 9)
            self.assertEqual(sorted(capsule.requests), [1, 2, 3, 4, 11, 12, 13, 14, 99, 1000, 1001])
            self.assertEqual(capsule.failures, [])
        finally:
            capsule.close()

    def test_production_snapshot_executor_reserves_two_private_proxy_slots(self):
        self.assertEqual(gateway._SNAPSHOT_READS._max_workers, 2)


if __name__ == "__main__":
    unittest.main()
