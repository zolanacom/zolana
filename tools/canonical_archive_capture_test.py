"""Disposable capture transport/SQLite tests; no sockets, ledgers or wallets."""
import copy
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import canonical_archive_capture as capture
from canonical_archive_store import Reader, encoded
from canonical_archive_store_test import NETWORK, blockhash, blocks, request, target


class Fixture:
    def __init__(self, slots=range(1, 34)):
        self.items = blocks(slots)
        self.tip = self.items[-1]['slot']
        self.calls = []
        self.change = lambda peer, method, params, value: value

    def source(self, peer):
        def forward(raw, *, timeout):
            assert 0 < timeout <= 6
            message = json.loads(raw)
            assert set(message) == {'jsonrpc', 'id', 'method', 'params'}
            assert message['jsonrpc'] == '2.0' and message['id'] == 1
            method, params = message['method'], message['params']
            self.calls.append((peer, method, copy.deepcopy(params)))
            if method == 'getGenesisHash':
                assert params == []
                value = NETWORK['genesis_hash']
            elif method == 'getSlot':
                assert params == [{'commitment': 'finalized'}]
                value = self.tip
            elif method == 'getBlocksWithLimit':
                assert params[1:] == [16, {'commitment': 'finalized'}]
                value = [item['slot'] for item in self.items if item['slot'] >= params[0]][:16]
            elif method == 'getBlock':
                assert params[1] in (capture.HEADER, capture.FULL)
                value = next(item['block'] for item in self.items if item['slot'] == params[0])
                if params[1] == capture.HEADER:
                    value = {key: value for key, value in value.items() if key != 'transactions'}
            else:
                raise AssertionError('non-read RPC')
            value = self.change(peer, method, params, copy.deepcopy(value))
            return encoded(dict(jsonrpc='2.0', id=1, result=value))
        return forward


class CanonicalArchiveCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='zolana-capture-094-')
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / 'full.sqlite3'
        self.fixture = Fixture([1, 3, 4, 7, 8, 10, 12, 20, 21, 24, 28, 30])
        self.sources = [self.fixture.source(i) for i in range(3)]

    def tearDown(self):
        self.temporary.cleanup()

    def run_capture(self, **kwargs):
        return capture.capture(self.path, NETWORK, self.sources,
                               min_free_bytes=0, timeout=10, **kwargs)

    def read_all(self):
        with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
            if not reader.slot:
                return []
            pinned = dict(slot=reader.slot, blockhash=reader.hash, block_height=reader.height)
            found, after = [], 0
            while after < reader.slot:
                page = json.loads(reader.page(request(after, pinned, first=after == 0)))['result']
                found.extend(page['blocks'])
                after = page['next_slot']
            return found

    def test_bounded_commits_resume_exact_full_prefix_and_never_claim_missing_suffix(self):
        updates = []
        first = self.run_capture(batch_blocks=3, max_batches=2, progress=updates.append)
        self.assertEqual((first['status'], first['initial_slot'], first['blocks'], first['batches']),
                         ('bounded', 0, 6, 2))
        self.assertEqual(self.read_all(), self.fixture.items[:6])
        with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
            with self.assertRaises(ValueError):
                reader.page(request(0, target(self.fixture.items), first=True))
        self.assertEqual(len(updates), 2)
        for update in updates:
            self.assertEqual(set(update), {'event', 'slot', 'height', 'target_slot', 'batches', 'blocks', 'elapsed_ms'})
            self.assertEqual(update['event'], 'canonical_capture_commit')
            self.assertTrue(all(type(v) is int for k, v in update.items() if k != 'event'))
        resumed = self.run_capture(batch_blocks=2, target=first['target'])
        self.assertEqual((resumed['status'], resumed['initial_slot'], resumed['blocks']), ('complete', 10, 6))
        self.assertEqual(self.read_all(), self.fixture.items)
        # Successful, failed and unrelated metadata and >2**53 integers remain.
        txs = self.read_all()[0]['block']['transactions']
        self.assertIsNotNone(txs[1]['meta']['err'])
        self.assertEqual(txs[2]['meta']['preBalances'], [9007199254740993])
        again = self.run_capture(target=resumed['target'])
        self.assertEqual((again['status'], again['blocks'], again['batches']), ('complete', 0, 0))

    def test_moving_head_extras_only_above_fixed_target_are_ignored_after_full_validation(self):
        fixed = target(self.fixture.items[:5])
        self.fixture.change = lambda peer, method, params, value: (
            value + [100 + peer] if method == 'getBlocksWithLimit' else value)
        result = self.run_capture(target=fixed, batch_blocks=2)
        self.assertEqual(result['committed'], fixed)
        self.assertEqual(self.read_all(), self.fixture.items[:5])
        self.fixture.change = lambda peer, method, params, value: (
            value[:-1] if peer == 1 and method == 'getBlocksWithLimit' else value)
        with self.assertRaises(ValueError):
            self.run_capture()
        self.assertEqual(self.read_all(), self.fixture.items[:5])
        self.fixture.change = lambda peer, method, params, value: (
            value + [True] if method == 'getBlocksWithLimit' else value)
        with self.assertRaises(ValueError):
            self.run_capture()
        self.assertEqual(self.read_all(), self.fixture.items[:5])

    def test_changed_fixed_anchor_genesis_gap_or_body_disagreement_never_replaces_old_prefix(self):
        self.run_capture(batch_blocks=2, max_batches=1)
        old = self.read_all()
        for corruption in ['genesis', 'anchor', 'gap', 'metadata']:
            with self.subTest(corruption=corruption):
                def change(peer, method, params, value):
                    if peer != 1:
                        return value
                    if corruption == 'genesis' and method == 'getGenesisHash':
                        return blockhash(9)
                    if corruption == 'anchor' and method == 'getBlock' and params[1] == capture.HEADER:
                        value['blockhash'] = blockhash(55)
                    if corruption == 'gap' and method == 'getBlocksWithLimit':
                        return value[1:]
                    if corruption == 'metadata' and method == 'getBlock' and params[1] == capture.FULL:
                        value['transactions'][0]['meta']['err'] = {'fixture': 'changed'}
                    return value
                self.fixture.change = change
                with self.assertRaises(ValueError):
                    self.run_capture()
                self.assertEqual(self.read_all(), old)
        self.fixture.change = lambda peer, method, params, value: value
        self.run_capture()
        self.assertEqual(self.read_all(), self.fixture.items)

    def test_mid_run_anchor_change_preserves_only_earlier_complete_batches(self):
        def progress(_):
            self.fixture.change = lambda peer, method, params, value: (
                dict(value, blockhash=blockhash(50))
                if method == 'getBlock' and params[0] == self.fixture.tip else value)
        with self.assertRaises(ValueError):
            self.run_capture(batch_blocks=2, progress=progress)
        self.assertEqual(self.read_all(), self.fixture.items[:2])

    def test_large_blocks_reduce_page_size_without_dropping_the_next_block(self):
        self.fixture = Fixture(range(1, 5))
        for item in self.fixture.items:
            item['block']['unknown_large'] = 'x' * 4000
        self.sources = [self.fixture.source(0)]
        with patch.object(capture, 'PAGE_LIMIT', 11000):
            result = self.run_capture(batch_blocks=16)
        self.assertEqual(result['batches'], 4)
        self.assertEqual(self.read_all(), self.fixture.items)

    def test_disk_database_and_shared_deadline_limits_preserve_committed_prefix(self):
        with patch.object(capture.shutil, 'disk_usage', return_value=SimpleNamespace(free=1)):
            with self.assertRaisesRegex(ValueError, 'disk floor'):
                self.run_capture()
        self.assertFalse(self.path.exists())
        self.fixture = Fixture(range(1, 4))
        for item in self.fixture.items:
            item['block']['large'] = 'x' * 700000
        self.sources = [self.fixture.source(0)]
        with self.assertRaises(sqlite3.DatabaseError):
            self.run_capture(batch_blocks=1, max_database_bytes=1024 ** 2)
        self.assertEqual(self.read_all(), self.fixture.items[:1])
        self.assertLessEqual(self.path.stat().st_size, 1024 ** 2)
        original = self.sources[0]
        def slow(raw, *, timeout):
            value = original(raw, timeout=timeout)
            time.sleep(.02)
            return value
        with self.assertRaisesRegex(ValueError, 'deadline'):
            capture.capture(self.path, NETWORK, [slow], min_free_bytes=0, timeout=.01)
        self.assertEqual(self.read_all(), self.fixture.items[:1])

    def test_held_reader_commit_busy_rolls_back_then_explicit_resume_succeeds(self):
        self.run_capture(batch_blocks=2, max_batches=1)
        with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
            self.assertEqual(reader.slot, 3)
            with self.assertRaises(sqlite3.OperationalError):
                self.run_capture(batch_blocks=2, max_batches=1)
        self.assertEqual(self.read_all(), self.fixture.items[:2])
        self.run_capture()
        self.assertEqual(self.read_all(), self.fixture.items)

    def test_callbacks_cannot_retry_or_break_commit_and_transport_failure_is_not_retried(self):
        def callback(_):
            raise RuntimeError('disposable observer failure')
        self.run_capture(batch_blocks=2, max_batches=1, progress=callback)
        prior = self.read_all()
        calls = []
        def failed(raw, *, timeout):
            calls.append(json.loads(raw)['method'])
            raise ConnectionError('disposable unavailable operator')
        with self.assertRaises(ConnectionError):
            capture.capture(self.path, NETWORK, [failed], min_free_bytes=0)
        self.assertEqual(calls, ['getGenesisHash'])
        self.assertEqual(self.read_all(), prior)
        for response in [b'[]', b'{"jsonrpc":"2.0","id":true,"result":null}',
                         b'{"jsonrpc":"2.0","id":1,"id":1,"result":null}',
                         b'{"jsonrpc":"2.0","id":1,"error":{"code":-32004}}']:
            with self.subTest(response=response):
                seen = []
                def refused(raw, *, timeout):
                    seen.append(raw)
                    return response
                with self.assertRaises(ValueError):
                    capture.capture(self.path, NETWORK, [refused], min_free_bytes=0)
                self.assertEqual(len(seen), 1)
                self.assertEqual(self.read_all(), prior)

    def test_real_sigkill_before_and_after_commit_resumes_from_recovered_sqlite_tip(self):
        child = r'''
import json,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import canonical_archive_capture as capture
from canonical_archive_capture_test import Fixture,NETWORK
data=json.loads(Path(sys.argv[2]).read_text())
fixture=Fixture(range(1,5))
for item in fixture.items:item['block']['large']='x'*(2*1024*1024)
original=capture.Capture
class Paused(original):
 def commit(self):
  self.db.execute('PRAGMA cache_size=1')
  if data['after']:super().commit()
  Path(data['marker']).write_text('committed' if data['after'] else 'uncommitted')
  while True:time.sleep(1)
capture.Capture=Paused
capture.capture(Path(data['path']),NETWORK,[fixture.source(0)],batch_blocks=1,max_batches=1,min_free_bytes=0)
'''
        for committed in [False, True]:
            with self.subTest(committed=committed):
                self.path = self.root / ('kill-' + str(committed) + '.sqlite3')
                self.fixture = Fixture(range(1, 5))
                for item in self.fixture.items:
                    item['block']['large'] = 'x' * (2 * 1024 * 1024)
                self.sources = [self.fixture.source(0)]
                self.run_capture(batch_blocks=1, max_batches=1)
                marker = self.root / ('marker-' + str(committed))
                config = self.root / ('child-' + str(committed) + '.json')
                config.write_bytes(encoded(dict(path=str(self.path), after=committed, marker=str(marker))))
                process = subprocess.Popen([sys.executable, '-B', '-c', child,
                                            str(Path(__file__).parent.resolve()), str(config)],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 8
                    while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(.01)
                    self.assertTrue(marker.exists(), process.communicate(timeout=1)
                                    if process.poll() is not None else 'child deadline')
                    process.kill()
                    process.communicate(timeout=5)
                    self.assertEqual(process.returncode, -signal.SIGKILL)
                finally:
                    if process.poll() is None:
                        process.kill(); process.communicate(timeout=5)
                resumed = self.run_capture(batch_blocks=1)
                self.assertEqual(resumed['initial_slot'], 2 if committed else 1)
                self.assertEqual(resumed['status'], 'complete')
                self.assertEqual(self.read_all(), self.fixture.items)


if __name__ == '__main__':
    unittest.main()
