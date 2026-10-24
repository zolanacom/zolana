"""Actual ArchiveRPC + R3 store integration, entirely synthetic and in-process."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import canonical_archive_backend as backend
from canonical_archive_backend import CanonicalStoreRPC, HEADER, FULL
from canonical_archive_store import Capture, encoded, number
from canonical_archive_store_test import NETWORK, blocks, blockhash, page, target
from gateway_archival import ArchiveRPC


def query(method, params):
    return encoded(dict(jsonrpc='2.0', id=1, method=method, params=params))


class CanonicalArchiveBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zolana-canonical-backend-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'canonical.sqlite3'
        self.items = blocks(range(1, 34))
        self.pinned = target(self.items)
        with Capture(self.path, NETWORK, NETWORK['genesis_hash'], self.pinned) as capture:
            after = 0
            for offset in range(0, len(self.items), 16):
                chunk = self.items[offset:offset + 16]
                capture.append(encoded(page(chunk, self.pinned, after)))
                after = chunk[-1]['slot']
            capture.commit()
        self.primary_calls, self.archive_calls = [], []
        self.primary_mutate = lambda value: value
        self.gateway = SimpleNamespace(info=dict(network=NETWORK, rpc_audience='https://fixture.invalid/'),
                                       faucet=SimpleNamespace(root=self.root))
        self.gateway.forward = self.primary
        self.source = CanonicalStoreRPC(self.path, NETWORK, NETWORK['genesis_hash'])
        self.archive = self.adapter()

    def primary(self, raw, timeout):
        request = json.loads(raw)
        self.primary_calls.append((request, timeout))
        self.assertEqual(request['method'], 'getBlock')
        self.assertEqual(request['params'][1], HEADER)
        slot = request['params'][0]
        header = dict(blockhash=blockhash(slot), previousBlockhash=blockhash(slot - 1),
                      parentSlot=slot - 1, blockHeight=slot)
        return encoded(dict(jsonrpc='2.0', id=1, result=self.primary_mutate(header)))

    def adapter(self):
        archive = ArchiveRPC(self.gateway, 'http://127.0.0.1:18899', dict(policy={}))
        def forward(raw, timeout):
            self.archive_calls.append((json.loads(raw), timeout))
            return self.source.forward(raw, timeout)
        archive.forward = forward  # Only the internal archive read transport.
        return archive

    def read(self, after=0, target_slot=33, token=None):
        return json.loads(self.archive.page(dict(id=7, params=[after, target_slot, token])))['result']

    def inventory(self):
        return {p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_size,
                         p.stat().st_mtime_ns, p.stat().st_mode) for p in self.root.iterdir()}

    def test_actual_archive_pages_preserve_all_full_bodies_and_resume_nonzero_after_restart(self):
        before = self.inventory()
        values, after, token = [], 0, None
        while after < 33:
            value = self.read(after, 33, token)
            self.assertEqual(value['anchor'], self.pinned)
            values.extend(value['blocks'])
            after, token = value['next_slot'], value['anchor']
            self.archive = self.adapter()  # No backend/session cursor state.
        self.assertEqual(values, self.items)
        self.assertEqual(len(self.primary_calls), 3)
        self.assertEqual(self.inventory(), before, 'every internal archive read must be read-only')
        for request, remaining in self.archive_calls + self.primary_calls:
            self.assertGreater(remaining, 0)
            self.assertLessEqual(remaining, 15)
            self.assertIn(request['method'], ['getGenesisHash', 'getBlock', 'getBlocksWithLimit'])
        resumed = self.read(16, 33, self.pinned)
        self.assertEqual(resumed['blocks'], self.items[16:32])
        with self.assertRaises(ValueError): self.read(16, 33, None)

    def test_fresh_primary_target_beyond_committed_tip_and_changed_anchor_refuse(self):
        with self.assertRaisesRegex(ValueError, 'committed prefix'): self.read(target_slot=34)
        for change in [dict(blockhash=blockhash(9)), dict(blockHeight=99)]:
            self.primary_mutate = lambda value, change=change: dict(value, **change)
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'differ'): self.read()
        self.primary_mutate = lambda value: value
        first = self.read()
        wrong = dict(first['anchor'], blockhash=blockhash(8))
        with self.assertRaisesRegex(ValueError, 'differ'): self.read(16, 33, wrong)

    def test_wrong_genesis_or_network_never_turns_into_canonical_history(self):
        original = self.source.forward
        def wrong_genesis(raw, timeout):
            request = json.loads(raw)
            if request['method'] == 'getGenesisHash':
                return encoded(dict(jsonrpc='2.0', id=1, result=blockhash(9)))
            return original(raw, timeout)
        with patch.object(self.source, 'forward', wrong_genesis):
            with self.assertRaisesRegex(ValueError, 'genesis mismatch'): self.read()
        self.source = CanonicalStoreRPC(self.path, dict(NETWORK, network=[8] * 32), NETWORK['genesis_hash'])
        with self.assertRaisesRegex(ValueError, 'network'): self.read()

    def test_gapped_corrupt_or_oversized_store_never_publishes_a_page(self):
        for mode in ['gap', 'body', 'index']:
            copy = self.root / (mode + '.sqlite3')
            copy.write_bytes(self.path.read_bytes()); copy.chmod(0o600)
            with closing(sqlite3.connect(copy)) as db, db:
                if mode == 'gap': db.execute('DELETE FROM blocks WHERE slot=?', (number(5),))
                if mode == 'body': db.execute('UPDATE blocks SET body=? WHERE slot=?', (b'{}', number(5)))
                if mode == 'index': db.execute('UPDATE blocks SET hash=? WHERE slot=?', ('1' * 32 + '\0' + 'x' * 4096, number(5)))
            self.source = CanonicalStoreRPC(copy, NETWORK, NETWORK['genesis_hash'])
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.read()

    def test_only_existing_fixed_read_shapes_allowed_no_writes_and_missing_file_stays_missing(self):
        before = self.inventory()
        for method, params in [('getGenesisHash', [1]), ('getBlock', [1, dict(FULL, commitment='processed')]),
                               ('getBlock', [1, dict(FULL, rewards=0)]),
                               ('getBlocksWithLimit', [1, 17, dict(commitment='finalized')]),
                               ('getBlocksWithLimit', [True, 16, dict(commitment='finalized')]),
                               ('sendTransaction', ['unused']), ('getAccountInfo', ['unused'])]:
            with self.subTest(method=method, params=params), self.assertRaises(ValueError):
                self.source.forward(query(method, params), 15)
        self.assertEqual(self.inventory(), before)
        missing = self.root / 'missing.sqlite3'
        source = CanonicalStoreRPC(missing, NETWORK, NETWORK['genesis_hash'])
        with self.assertRaises(FileNotFoundError): source.forward(query('getGenesisHash', []), 15)
        self.assertFalse(missing.exists())

    def test_shared_deadline_and_slow_reader_close_refuse_without_retry(self):
        for timeout in [0, -1, 16, True, float('nan'), float('inf')]:
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.source.forward(query('getGenesisHash', []), timeout)
        with patch.object(backend.time, 'monotonic', side_effect=[0, 0, 16]):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                self.source.forward(query('getGenesisHash', []), 15)
        original_reader = backend.Reader
        clock = [0]
        class SlowClose(original_reader):
            def close(self):
                super().close()
                clock[0] = 16
        with patch.object(backend, 'Reader', SlowClose), patch.object(backend.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                self.source.forward(query('getGenesisHash', []), 15)
        clock[0] = 0
        original_primary = self.gateway.forward
        def late_primary(raw, timeout):
            result = original_primary(raw, timeout)
            clock[0] = 16
            return result
        calls_before = len(self.archive_calls)
        with patch.object(self.gateway, 'forward', late_primary), patch.object(backend.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ValueError, 'deadline'): self.read()
        # Genesis once, fresh primary once, then the existing shared deadline
        # rejects before any archive target/block call or automatic retry.
        self.assertEqual(len(self.archive_calls) - calls_before, 1)


if __name__ == '__main__':
    unittest.main()
