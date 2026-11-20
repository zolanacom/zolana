"""Bounded relay workers: which jobs may run side by side, and what stops them.

A real child process stands in for `native-shielded relay`. It proves nothing
and contacts nothing: it marks its job and its member as busy, waits at a gate
the test opens, writes the outcome the test asked for and exits. A second child
for the same job or the same member finds the mark and reports an overlap,
which is how interference between workers would show.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from shielded_relay import MAX_WORKERS, Relay, private, save

STAND_IN = r'''#!%s -IB
import hashlib, json, os, sys, time
arguments = sys.argv[1:]
if arguments == ["warm"]:
    sys.exit(0)
job = arguments[arguments.index("--job") + 1]
root = os.path.dirname(os.path.dirname(job))
name = os.path.basename(job)
member = json.load(open(os.path.join(job, "owner.json")))
def log(event):
    line = json.dumps([event, name, member, time.time(), os.getpid(), os.environ.get("RAYON_NUM_THREADS")]) + "\n"
    descriptor = os.open(os.path.join(root, "log"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.write(descriptor, line.encode())
    os.close(descriptor)
def mark(path):
    try:
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        return True
    except FileExistsError:
        return False
marks = [os.path.join(job, "busy"), os.path.join(root, "busy-" + hashlib.sha256(member.encode()).hexdigest())]
held = []
for path, event in zip(marks, ("overlap-job", "overlap-member")):
    if not mark(path):
        log(event)
        for other in held:
            os.unlink(other)
        sys.exit(3)
    held.append(path)
log("start")
deadline = time.monotonic() + 30
while not os.path.exists(os.path.join(root, "gate")) and time.monotonic() < deadline:
    time.sleep(0.01)
code = 1 if os.path.exists(os.path.join(root, "fail-" + name)) else 0
if not code:
    descriptor = os.open(os.path.join(job, "outcome.json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(descriptor, json.dumps({"accepted": True, "signature": "stand-in " + name[:8]}).encode())
    os.close(descriptor)
for path in held:
    os.unlink(path)
log("end")
sys.exit(code)
'''


class RelayWorkers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        binary = self.root / 'stand-in'
        binary.write_text(STAND_IN % sys.executable)
        binary.chmod(0o700)
        # The first execution of a new file can be slow; keep it out of the timed cases.
        subprocess.run([str(binary), 'warm'], check=True, timeout=30)
        self.config = dict(format='native-shielded-relay-v1', network=dict(network=[7] * 32, genesis_hash='pinned'),
            network_file='/fixed/network.json', rpc='http://127.0.0.1:18899', payer=[8] * 32,
            payer_file='/fixed/key', binary=str(binary), fee=3_000_000, gross_cap=100_000,
            max_jobs=12, per_member=4)
        save(self.root / 'config.json', self.config)
        self.relay = Relay(self.root)
        self.closed = False
        self.addCleanup(self.close)
        self.nonce = 0

    def close(self):
        if not self.closed:
            self.closed = True
            (self.root / 'gate').touch()
            self.relay.close()

    def submit(self, member):
        raw = bytearray(9230)
        raw[:8] = b'NPAY0003'; raw[8:40] = bytes([7] * 32)
        raw[48:56] = (3_000_000).to_bytes(8, 'little'); raw[56:88] = bytes([8] * 32)
        raw[88:96] = raw[48:56]; raw[-1] = self.nonce
        self.nonce += 1
        value = dict(network=self.config['network'], payload=base64.b64encode(raw).decode())
        return self.relay.dispatch('submitShieldedPayment', [value], member)['id']

    def log(self):
        path = self.root / 'log'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def events(self, event):
        return [row for row in self.log() if row[0] == event]

    def until(self, condition, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if condition():
                return True
            time.sleep(0.02)
        return False

    def open_gate(self):
        (self.root / 'gate').touch()

    def running(self):
        return len(self.events('start')) - len(self.events('end'))

    def most_at_once(self):
        """Largest number of stand-ins alive together, from their own clocks."""
        edges = sorted([(row[3], 1) for row in self.events('start')] + [(row[3], -1) for row in self.events('end')])
        level = peak = 0
        for _, step in edges:
            level += step
            peak = max(peak, level)
        return peak

    def state(self, job, member):
        return self.relay.dispatch('getShieldedPaymentStatus', [job], member)['state']

    def tries(self, job):
        return json.loads(private(self.relay.jobs / job / 'tries.json'))

    def alive(self, pid):
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def assert_no_overlap(self):
        self.assertEqual([row[0] for row in self.log() if row[0].startswith('overlap')], [])

    def test_default_start_keeps_the_single_serial_worker(self):
        jobs = [self.submit(member) for member in ('alice', 'bob', 'carol')]
        self.relay.start()
        self.assertTrue(self.until(lambda: len(self.events('start')) == 1))
        time.sleep(0.4)  # the gate is closed; a second worker would have started a second job
        self.assertEqual(len(self.events('start')), 1)
        self.assertEqual(self.relay.helpers, [])
        self.open_gate()
        self.assertTrue(self.until(lambda: all((self.relay.jobs / job / 'done').exists() for job in jobs)))
        self.assertEqual(self.most_at_once(), 1)
        self.assertEqual({row[5] for row in self.events('start')}, {'2'})
        self.assertEqual([self.tries(job) for job in jobs], [1, 1, 1])
        self.assert_no_overlap()

    def test_two_workers_run_two_members_jobs_side_by_side_and_never_more(self):
        members = ('alice', 'bob', 'carol', 'dave')
        jobs = [self.submit(member) for member in members]
        self.relay.start(2)
        self.assertTrue(self.until(lambda: len(self.events('start')) == 2))
        time.sleep(0.4)  # both workers are held at the gate; nothing else may start
        self.assertEqual((len(self.events('start')), self.running()), (2, 2))
        self.assertEqual(len(self.relay.held), 2)
        self.open_gate()
        self.assertTrue(self.until(lambda: all((self.relay.jobs / job / 'done').exists() for job in jobs)))
        self.assertEqual(self.most_at_once(), 2)
        self.assert_no_overlap()
        # Every job ran exactly once, under its own member, and was accepted.
        self.assertEqual(sorted(row[1] for row in self.events('start')), sorted(jobs))
        self.assertEqual([self.tries(job) for job in jobs], [1] * 4)
        self.assertEqual([self.state(job, member) for job, member in zip(jobs, members)], ['accepted'] * 4)
        self.assertEqual({row[5] for row in self.events('start')}, {'1'})
        self.assertTrue(self.until(lambda: self.relay.held == {} and self.relay.children == {}))

    def test_jobs_of_one_member_never_run_side_by_side(self):
        mine = [self.submit('alice') for _ in range(3)]
        other = self.submit('bob')
        self.relay.start(MAX_WORKERS)
        self.assertTrue(self.until(lambda: len(self.events('start')) == 2))
        time.sleep(0.4)  # four workers, yet only one job of each member may run
        started = self.events('start')
        self.assertEqual(len(started), 2)
        self.assertEqual(len({row[2] for row in started}), 2)
        self.open_gate()
        self.assertTrue(self.until(lambda: all((self.relay.jobs / job / 'done').exists() for job in mine + [other])))
        self.assert_no_overlap()
        spans = sorted((start[3], end[3]) for start in self.events('start') for end in self.events('end')
                       if start[1] == end[1] and start[1] in mine)
        self.assertEqual(len(spans), 3)
        for earlier, later in zip(spans, spans[1:]):
            self.assertLessEqual(earlier[1], later[0])
        self.assertEqual([self.tries(job) for job in mine], [1, 1, 1])

    def test_held_job_is_refused_until_released_and_a_finished_job_is_not_run_again(self):
        job = self.relay.jobs / self.submit('alice')
        self.assertTrue(self.relay.claim(job))
        self.assertFalse(self.relay.claim(job))
        self.relay.release(job)
        self.assertTrue(self.relay.claim(job))
        self.relay.release(job)
        # A worker that claims a job another worker has just completed must not spawn.
        save(job / 'outcome.json', dict(accepted=True, signature='original'))
        save(job / 'tries.json', 1)
        save(job / 'done', True)
        with patch('shielded_relay.subprocess.Popen', side_effect=AssertionError('must not spawn')):
            self.relay.attempt(job)
        self.assertEqual(self.tries(job.name), 1)
        self.assertEqual(self.state(job.name, 'alice'), 'accepted')

    def test_failing_job_uses_only_its_own_tries_and_leaves_the_others_alone(self):
        failing = self.submit('alice')
        (self.root / ('fail-' + failing)).touch()
        good = [self.submit(member) for member in ('bob', 'carol')]
        self.open_gate()
        self.relay.start(2)
        self.assertTrue(self.until(lambda: (self.relay.jobs / failing / 'done').exists()))
        self.assertTrue(self.until(lambda: all((self.relay.jobs / job / 'done').exists() for job in good)))
        self.assertEqual(self.state(failing, 'alice'), 'aborted')
        self.assertEqual(self.tries(failing), 3)
        self.assertEqual([self.tries(job) for job in good], [1, 1])
        self.assertEqual([self.state(job, member) for job, member in zip(good, ('bob', 'carol'))], ['accepted'] * 2)
        self.assert_no_overlap()

    def test_close_kills_every_child_and_joins_every_worker_and_the_jobs_resume(self):
        members = ('alice', 'bob', 'carol')
        jobs = [self.submit(member) for member in members]
        self.relay.start(3)
        self.assertTrue(self.until(lambda: len(self.events('start')) == 3))
        pids = [row[4] for row in self.events('start')]
        threads = [self.relay.worker] + self.relay.helpers
        self.assertEqual(len(threads), 3)
        started = time.monotonic()
        self.relay.close()
        self.closed = True
        self.assertLess(time.monotonic() - started, 10)
        self.assertTrue(self.until(lambda: not any(self.alive(pid) for pid in pids)))
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual(self.events('end'), [])
        for job in jobs:
            self.assertFalse((self.relay.jobs / job / 'outcome.json').exists())
            self.assertEqual(self.tries(job), 1)
        # The killed stand-ins left their marks; a real child holds a lock the
        # kernel releases. Clear them, then a new relay resumes the same jobs.
        for mark in list(self.root.glob('busy-*')) + [self.relay.jobs / job / 'busy' for job in jobs]:
            mark.unlink()
        self.relay = Relay(self.root)
        self.closed = False
        self.open_gate()
        self.relay.start(3)
        self.assertTrue(self.until(lambda: all((self.relay.jobs / job / 'done').exists() for job in jobs)))
        self.assertEqual([self.state(job, member) for job, member in zip(jobs, members)], ['accepted'] * 3)
        self.assertEqual([self.tries(job) for job in jobs], [2, 2, 2])

    def test_a_failed_worker_ends_every_worker_so_the_supervisor_sees_it(self):
        job = self.relay.jobs / self.submit('alice')
        # A staging relay must refuse a job that claims the native transport.
        save(job / 'transport.json', dict(transport='native-inline-v1'))
        with patch('threading.excepthook', lambda *_: None):
            self.relay.start(3)
            threads = [self.relay.worker] + self.relay.helpers
            self.assertTrue(self.until(lambda: not any(thread.is_alive() for thread in threads), 10))
        self.assertTrue(self.relay.broken.is_set())
        self.assertFalse(self.relay.worker.is_alive())
        self.assertEqual(self.log(), [])

    def test_worker_count_is_bounded_and_the_relay_starts_once(self):
        self.assertEqual(MAX_WORKERS, 4)
        for workers in (0, -1, MAX_WORKERS + 1, True, 2.0, '2', None):
            with self.subTest(workers=workers), self.assertRaises(ValueError):
                self.relay.start(workers)
        self.assertIsNone(self.relay.worker)
        self.relay.start(2)
        with self.assertRaises(ValueError):
            self.relay.start(2)


if __name__ == '__main__':
    unittest.main()
