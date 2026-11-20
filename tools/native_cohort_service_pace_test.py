"""The grant worker starts the next tick at once after a completed grant, and
the gateway starts the relay with its configured number of workers.

A real child process stands in for `native-faucet tick`: it takes one claim
from a counter file and prints the status the faucet prints, so no chain,
wallet or proof is involved. The worker's pause is recorded, not slept.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

import native_cohort_service as service
from test_faucet import Faucet

STAND_IN = r'''#!%s -IB
import json, os, sys
arguments = sys.argv[1:]
if arguments == ["warm"] or arguments[0] == "balance":
    sys.exit(0)
root = arguments[arguments.index("--root") + 1]
sys.stdin.read()
def number(name):
    try:
        return int(open(os.path.join(root, name)).read())
    except FileNotFoundError:
        return 0
def record(name, value):
    with open(os.path.join(root, name + ".new"), "w") as stream:
        stream.write(str(value))
    os.replace(os.path.join(root, name + ".new"), os.path.join(root, name))
status = dict(claim_id="0" * 64, private_amount=20000000, gas_amount=0, gas_finalized=False,
              one_grant_per_wallet=True, gas_required=False)
if number("stuck"):
    print(json.dumps(dict(status, state="needs_attention", private_finalized=False)))
elif number("queued"):
    record("queued", number("queued") - 1)
    print(json.dumps(dict(status, state="ready", private_finalized=True, grants_completed=1)))
else:
    print(json.dumps({"idle": True, "reserved_claims": 0, "max_claims": 200}))
record("ticks", number("ticks") + 1)
'''


class Recorded(threading.Event):
    """The worker's stop event; a pause is noted with the ticks finished so far."""
    def __init__(self, root):
        super().__init__()
        self.root = root
        self.pauses = []

    def wait(self, timeout=None):
        if timeout is not None:
            path = self.root / "ticks"
            self.pauses.append((timeout, int(path.read_text()) if path.exists() else 0))
        return super().wait(None if timeout is None else min(timeout, 0.02))


class GrantWorkerPace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.root = base / "cohort/faucet"
        self.root.mkdir(parents=True, mode=0o700)
        (base / "bin").mkdir()
        for name in ("native-faucet", "native-wallet"):
            path = base / "bin" / name
            path.write_text(STAND_IN % sys.executable)
            path.chmod(0o755)
            subprocess.run([str(path), "warm"], check=True, timeout=30)
        password = base / "cohort/password"
        password.write_text("stand-in worker password")
        password.chmod(0o600)
        self.worker = service.supervised_faucet(Faucet)(self.root, password, binary=base / "bin/native-faucet")
        self.worker.stop = Recorded(self.root)
        patcher = mock.patch.object(service, "print", lambda *_, **__: None, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.thread = None
        self.addCleanup(self.finish)

    def run_until(self, pauses):
        self.thread = threading.Thread(target=self.worker.work, daemon=True)
        self.thread.start()
        deadline = time.monotonic() + 20
        while len(self.worker.stop.pauses) < pauses and time.monotonic() < deadline:
            time.sleep(0.01)
        self.finish()
        self.assertGreaterEqual(len(self.worker.stop.pauses), pauses)
        return self.worker.stop.pauses

    def finish(self):
        self.worker.close()
        if self.thread is not None:
            self.thread.join(15)
            self.assertFalse(self.thread.is_alive())

    def test_completed_grant_output_is_recognised_strictly(self):
        ready = dict(claim_id="0" * 64, state="ready", private_finalized=True)
        self.assertTrue(service.paid_tick(json.dumps(ready)))
        self.assertTrue(service.paid_tick(json.dumps(dict(ready, grants_completed=3))))
        for output in ("", None, "ready", "[]", '{"idle":true}', '{"state":"ready"}', '{"private_finalized":true}',
                       json.dumps(dict(ready, state="funding")), json.dumps(dict(ready, state="needs_attention")),
                       json.dumps(dict(ready, private_finalized=False)), json.dumps(dict(ready, private_finalized=1)),
                       json.dumps([ready]), json.dumps(ready)[:-1]):
            self.assertFalse(service.paid_tick(output), output)

    def test_queued_grants_are_paid_back_to_back_and_idle_polling_keeps_its_pause(self):
        (self.root / "queued").write_text("3")
        pauses = self.run_until(3)
        # Three paying ticks and the idle tick that follows ran before the first pause.
        self.assertEqual(pauses[0], (2, 4))
        self.assertEqual([pause for pause, _ in pauses[:3]], [2, 2, 2])
        self.assertEqual([ticks for _, ticks in pauses[:3]], [4, 5, 6])  # one pause after every idle tick
        self.assertEqual((self.root / "queued").read_text(), "0")
        self.assertFalse(self.worker.failed.is_set())

    def test_claim_that_makes_no_progress_is_still_paced(self):
        (self.root / "stuck").write_text("1")
        pauses = self.run_until(3)
        self.assertEqual(pauses[:3], [(2, 1), (2, 2), (2, 3)])
        self.assertFalse(self.worker.failed.is_set())



class RelayWorkerCount(unittest.TestCase):
    """The gateway starts the relay with the configured worker count; no listener is opened."""
    def started_with(self):
        service.select_mode(False)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.addCleanup(service.select_mode, False)
        root = Path(temp.name).resolve() / "cohort"
        root.mkdir(mode=0o700)
        stop, started = threading.Event(), []

        class Parent:
            def __init__(self, *_, **__):
                self.stop, self.child_lock, self.child = threading.Event(), threading.Lock(), None
            def close(self):
                self.stop.set()

        def start(*arguments, **keywords):
            started.append((arguments, keywords))
            stop.set()  # leave before readiness is published

        class Gateway:
            def __init__(self, *_, **__):
                self.relay = types.SimpleNamespace(native_ingress="127.0.0.1:1", start=start, close=lambda: None)

        base = types.SimpleNamespace(
            sandbox=lambda config, role: 1, stop_event=lambda: stop, real_directory=lambda *a: None,
            read_ready=lambda *a: dict(generation=1, peers=[dict(rpc="127.0.0.1:1", native_ingress="127.0.0.1:2")]),
            GWROOT=root.parent)
        ingress = types.SimpleNamespace(activated_sockets=lambda: {}, listeners=lambda *a: [])
        modules = dict(test_faucet=types.SimpleNamespace(Faucet=Parent, Handler=object),
                       testnet_gateway=types.SimpleNamespace(Gateway=Gateway, Handler=object),
                       service_tls=types.SimpleNamespace(listener=None))
        with mock.patch.object(service, "ROOT", root), mock.patch.dict(sys.modules, modules), \
                mock.patch.object(service, "load_binding", return_value=({}, dict(cohort_size=200, network={}), {})), \
                mock.patch.object(service, "authority", return_value=dict(claims=[])), \
                mock.patch.object(service, "prepare", return_value=(None, "http://127.0.0.1:1")), \
                mock.patch.object(service, "activate", return_value={}), \
                mock.patch.object(service, "supervised_faucet",
                                  lambda parent: type("Worker", (parent,), dict(work=lambda self: None))):
            service.gateway(base, dict(gateway_uid=os.getuid(), test_mode=False), "d" * 64, ingress)
        return started

    def test_one_worker_is_the_default_and_uses_the_original_call(self):
        self.assertEqual(service.RELAY_WORKERS, 1)
        self.assertEqual(self.started_with(), [((), {})])

    def test_a_larger_count_is_passed_to_the_relay(self):
        with mock.patch.object(service, "RELAY_WORKERS", 2):
            self.assertEqual(self.started_with(), [((2,), {})])


if __name__ == "__main__":
    unittest.main()
