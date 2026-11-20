"""The grant worker keeps the source wallet's scan cache current while idle.

Real child processes stand in for `native-faucet tick` and `native-wallet
balance`; they only sleep, log and exit, so no chain, wallet or proof is
involved. The stand-ins refuse to run beside each other, which is how an
overlap of the idle sync and a grant would show.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import native_cohort_service as service
from test_faucet import Faucet

STAND_IN = r'''#!%s -IB
import json, os, sys, time
arguments = sys.argv[1:]
if arguments == ["warm"]:
    sys.exit(0)
kind = arguments[0]
root = os.path.dirname(arguments[arguments.index("--wallet") + 1]) if kind == "balance" else arguments[arguments.index("--root") + 1]
password = sys.stdin.read()
def log(event):
    with open(os.path.join(root, "log"), "a") as stream:
        stream.write(json.dumps([event, kind, time.time(), os.getpid()]) + "\n")
def setting(name, default):
    try:
        return open(os.path.join(root, name)).read().strip()
    except FileNotFoundError:
        return default
active = os.path.join(root, "active")
try:
    other = int(open(active).read())
    os.kill(other, 0)
    log("overlap")
    sys.exit(3)
except (FileNotFoundError, ValueError, ProcessLookupError):
    pass
with open(active, "w") as stream:
    stream.write(str(os.getpid()))
log("start")
with open(os.path.join(root, "calls"), "a") as stream:
    stream.write(json.dumps([arguments, password == "stand-in worker password", "stand-in worker password" in " ".join(arguments)]) + "\n")
code = 0
if kind == "balance":
    time.sleep(float(setting("refresh-seconds", "0")))
    code = int(setting("refresh-exit", "0"))
    if not code:
        print(json.dumps({"balance": 1, "fee_balance": 2}))
elif os.path.exists(os.path.join(root, "claim")):
    time.sleep(float(setting("claim", "0") or 0))
    os.unlink(os.path.join(root, "claim"))
    print(json.dumps({"state": "ready", "claim_id": "0" * 64}))
else:
    time.sleep(float(setting("tick-seconds", "0")))
    print(json.dumps({"idle": True, "reserved_claims": 0, "max_claims": 200}))
log("end")
os.unlink(active)
sys.exit(code)
'''


class Quick(threading.Event):
    """The worker's stop event with its two-second pause shortened for tests."""
    def wait(self, timeout=None):
        return super().wait(None if timeout is None else min(timeout, 0.02))


class GrantWorkerRefresh(unittest.TestCase):
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
            # The first execution of a new file can be slow; keep it out of the timed cases.
            subprocess.run([str(path), "warm"], check=True, timeout=30)
        password = base / "cohort/password"
        password.write_text("stand-in worker password")
        password.chmod(0o600)
        self.wallet = base / "bin/native-wallet"
        self.worker = service.supervised_faucet(Faucet)(self.root, password, binary=base / "bin/native-faucet")
        self.worker.stop = Quick()
        self.events = []
        patcher = mock.patch.object(service, "print", lambda text, **_: self.events.append(json.loads(text)), create=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.thread = None
        self.addCleanup(self.finish)

    def limits(self, **values):
        for name, value in values.items():
            patcher = mock.patch.object(service, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def start(self):
        self.thread = threading.Thread(target=self.worker.work, daemon=True)
        self.thread.start()

    def finish(self):
        self.worker.close()
        if self.thread is not None:
            self.thread.join(15)
            self.assertFalse(self.thread.is_alive())

    def set(self, name, value):
        (self.root / name).write_text(str(value))

    def log(self):
        path = self.root / "log"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def sequence(self):
        return [(event, kind) for event, kind, _, _ in self.log()]

    def until(self, condition, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if condition():
                return True
            time.sleep(0.02)
        return False

    def count(self, event, kind):
        return self.sequence().count((event, kind))

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def test_idle_tick_output_is_recognised_strictly(self):
        self.assertTrue(service.idle_tick('{"idle":true,"reserved_claims":10,"max_claims":200}'))
        for output in ("", "{}", '{"idle":false}', '{"idle":1}', '{"idle":"true"}', '[true]', "idle", None,
                       '{"state":"ready"}', '{"idle":true'):
            self.assertFalse(service.idle_tick(output), output)
        self.assertEqual((service.GRANT_TICK_LIMIT, service.SOURCE_REFRESH_SECONDS, service.SOURCE_REFRESH_LIMIT),
                         (180, 300, 3600))

    def test_first_idle_tick_refreshes_once_and_then_waits_for_the_interval(self):
        self.start()
        self.assertTrue(self.until(lambda: self.count("end", "tick") >= 6))
        self.finish()
        sequence = self.sequence()
        self.assertEqual(sequence[:4], [("start", "tick"), ("end", "tick"), ("start", "balance"), ("end", "balance")])
        self.assertEqual(self.count("start", "balance"), 1)  # the interval is 300 s
        self.assertNotIn(("overlap", "tick"), sequence)
        self.assertNotIn(("overlap", "balance"), sequence)
        calls = [json.loads(line) for line in (self.root / "calls").read_text().splitlines()]
        refresh = next(arguments for arguments, _, _ in calls if arguments[0] == "balance")
        self.assertEqual(refresh, ["balance", "--network", str(self.root.parent / "source.json"),
                                   "--wallet", str(self.root / "wallet.enc.json"), "--password-file", "-"])
        self.assertTrue(all(piped and not exposed for _, piped, exposed in calls))
        self.assertFalse(self.worker.failed.is_set())
        self.assertEqual([event["event"] for event in self.events], ["cohort_source_refreshed"])

    def test_grant_requested_during_the_idle_sync_waits_for_it_and_never_runs_beside_it(self):
        self.set("refresh-seconds", 1.0)
        self.start()
        self.assertTrue(self.until(lambda: self.count("start", "balance") == 1))
        self.set("claim", 0.3)  # a wallet joins while the sync is running
        self.assertTrue(self.until(lambda: not (self.root / "claim").exists()))
        self.assertTrue(self.until(lambda: self.count("end", "tick") >= 4))
        self.finish()
        log = self.log()
        self.assertFalse(any(event == "overlap" for event, _, _, _ in log))
        started = next(index for index, row in enumerate(log) if row[:2] == ["start", "balance"])
        self.assertEqual(log[started + 1][:2], ["end", "balance"])  # nothing started until the sync ended
        self.assertEqual(log[started + 2][:2], ["start", "tick"])   # then the grant, at once
        self.assertGreaterEqual(log[started + 1][2] - log[started][2], 0.9)
        self.assertGreaterEqual(log[started + 3][2] - log[started + 2][2], 0.25)  # that tick paid the claim
        self.assertEqual(self.count("start", "balance"), 1)
        self.assertFalse(self.worker.failed.is_set())

    def test_sync_that_becomes_due_during_a_grant_waits_for_the_next_idle_tick(self):
        self.limits(SOURCE_REFRESH_SECONDS=0.2)
        self.set("claim", 0.8)  # queued before the worker starts
        self.start()
        self.assertTrue(self.until(lambda: self.count("end", "balance") >= 2))
        self.finish()
        sequence = self.sequence()
        self.assertNotIn(("overlap", "tick"), sequence)
        self.assertNotIn(("overlap", "balance"), sequence)
        # grant tick, then an idle tick, and only then the first sync
        self.assertEqual(sequence[:6], [("start", "tick"), ("end", "tick"), ("start", "tick"), ("end", "tick"),
                                        ("start", "balance"), ("end", "balance")])
        for index, row in enumerate(sequence):
            if row == ("start", "balance"):
                self.assertEqual(sequence[index - 1], ("end", "tick"))

    def test_sync_overrun_is_killed_and_reported_without_stopping_the_gateway_or_the_grants(self):
        self.limits(SOURCE_REFRESH_LIMIT=0.4)
        self.set("refresh-seconds", 60)
        self.start()
        self.assertTrue(self.until(lambda: self.events))
        self.assertEqual(self.events, [{"event": "cohort_source_refresh_failed", "seconds": 0}])
        pid = next(row[3] for row in self.log() if row[:2] == ["start", "balance"])
        self.assertTrue(self.until(lambda: not self.alive(pid)))  # the overrunning child was killed
        self.assertFalse(self.worker.failed.is_set())
        self.assertTrue(self.thread.is_alive())
        self.set("claim", 0.1)  # grants continue; the stale marker of the killed child is not an overlap
        self.assertTrue(self.until(lambda: not (self.root / "claim").exists()))
        self.assertTrue(self.until(lambda: self.count("end", "tick") >= 4))
        self.assertEqual(self.count("start", "balance"), 1)  # retried only after the interval
        self.assertFalse(any(event == "overlap" for event, _, _, _ in self.log()))
        self.assertFalse(self.worker.failed.is_set())

    def test_failed_sync_is_reported_once_retried_after_the_interval_and_recovery_is_reported(self):
        self.limits(SOURCE_REFRESH_SECONDS=0.3)
        self.set("refresh-exit", 1)
        self.start()
        self.assertTrue(self.until(lambda: self.count("end", "balance") >= 3))
        self.assertEqual([event["event"] for event in self.events], ["cohort_source_refresh_failed"])
        self.set("refresh-exit", 0)
        self.assertTrue(self.until(lambda: len(self.events) == 2))
        self.assertEqual(self.events[1]["event"], "cohort_source_refreshed")
        self.assertFalse(self.worker.failed.is_set())
        self.assertTrue(self.thread.is_alive())

    def test_missing_wallet_binary_is_a_reported_failure_not_a_stopped_worker(self):
        self.wallet.unlink()
        self.start()
        self.assertTrue(self.until(lambda: self.events))
        self.assertEqual(self.events[0]["event"], "cohort_source_refresh_failed")
        self.assertTrue(self.until(lambda: self.count("end", "tick") >= 4))
        self.assertTrue(self.thread.is_alive())
        self.assertFalse(self.worker.failed.is_set())

    def test_grant_tick_overrun_is_still_killed_and_stops_the_gateway_without_a_sync(self):
        self.limits(GRANT_TICK_LIMIT=0.4)
        self.set("claim", 60)
        self.start()
        self.assertTrue(self.until(self.worker.failed.is_set))
        self.thread.join(15)
        self.assertFalse(self.thread.is_alive())  # the gateway's main loop sees this and exits
        pid = next(row[3] for row in self.log() if row[:2] == ["start", "tick"])
        self.assertTrue(self.until(lambda: not self.alive(pid)))
        self.assertEqual(self.sequence(), [("start", "tick")])
        self.assertTrue((self.root / "claim").exists())  # the stand-in claim was not completed
        self.assertEqual(self.events, [])

    def test_failed_grant_tick_stops_the_gateway_and_is_never_followed_by_a_sync(self):
        path = self.root.parent.parent / "bin/native-faucet"
        path.write_text("#!/bin/sh\ncat >/dev/null\necho '{\"idle\":true}'\nexit 1\n")
        self.start()
        self.assertTrue(self.until(self.worker.failed.is_set))
        self.thread.join(15)
        self.assertFalse((self.root / "log").exists())
        self.assertEqual(self.events, [])

    def test_stopping_during_the_sync_kills_it_quietly(self):
        self.set("refresh-seconds", 60)
        self.start()
        self.assertTrue(self.until(lambda: self.count("start", "balance") == 1))
        pid = next(row[3] for row in self.log() if row[:2] == ["start", "balance"])
        started = time.monotonic()
        self.finish()
        self.assertLess(time.monotonic() - started, 5)
        self.assertTrue(self.until(lambda: not self.alive(pid)))
        self.assertFalse(self.worker.failed.is_set())
        self.assertEqual(self.events, [])
        self.assertEqual(self.worker.password, "")


if __name__ == "__main__":
    unittest.main()
