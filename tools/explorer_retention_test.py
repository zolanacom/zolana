"""Durable public Explorer retention, migration, and crash regressions."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

import explorer_feed
import explorer_model
from explorer_feed import Feed, read
from explorer_model import b58, block


def encode(value):
    return json.dumps(value, sort_keys=True).encode()


def key(byte):
    return b58(bytes([byte]) * 32)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        directory = Path(temporary.name).resolve() / 'explorer'
        directory.mkdir(mode=0o755)
        self.path = directory / 'feed.json'
        self.network = dict(network=[5] * 32, genesis_hash=key(7))
        self.records = {}
        self.calls = []

    def chain(self, tip, payments):
        previous = self.network['genesis_hash']
        for slot in range(1, tip + 1):
            digest = hashlib.sha256(str(slot).encode()).digest()
            signature = hashlib.sha512(str(slot).encode()).digest()
            raw = b'\x01' + signature + b'PRIVATE WIRE RECIPIENT AND AMOUNT'
            encoded = dict(transaction=[base64.b64encode(raw).decode(), 'base64'], meta={
                'fee': 5000, 'err': None, 'logMessages': ['private log'],
                'recipient': 'private address', 'amount': 987654321,
            })
            self.records[slot] = dict(parentSlot=slot - 1, blockhash=b58(digest), previousBlockhash=previous,
                                      blockHeight=slot, transactions=[encoded] if slot in payments else [])
            previous = b58(digest)
        self.tip = tip

    def rpc(self, method, params, timeout):
        self.calls.append((method, params, timeout))
        if method == 'getGenesisHash':
            return self.network['genesis_hash']
        if method == 'getSlot':
            return self.tip
        if method == 'getBlocks':
            return list(range(params[0], params[1] + 1))
        if method == 'getBlock':
            return self.records[params[0]]
        if method == 'getVoteAccounts':
            return {'current': [], 'delinquent': []}
        self.fail(f'unexpected RPC method: {method}')

    def write_v1(self, first, last):
        value = dict(format=explorer_model.FEED_V1, network=self.network, instance='a' * 32, sequence=9,
                     published_at=time.time(), sampled_at=time.time() - 1, phase='live',
                     observed_finalized_slot=last, validators=[],
                     blocks=[block(slot, self.records[slot]) for slot in range(first, last + 1)])
        self.path.write_bytes(encode(value))
        self.path.chmod(0o644)

    def test_v1_migration_and_2048_block_rollover_keep_public_payments_after_restart(self):
        self.chain(2052, {1, 2, 3})
        self.write_v1(1, 2048)
        with self.assertRaisesRegex(ValueError, 'retained transaction capacity'):
            writer = Feed(self.path, self.network, self.rpc)
            original = self.path.read_bytes()
            try:
                with patch.object(explorer_model, 'MAX_RETAINED_TRANSACTIONS', 2):
                    writer.sample()
            finally:
                self.assertEqual(self.path.read_bytes(), original)
                writer.close(pause=False)

        writer = Feed(self.path, self.network, self.rpc)
        try:
            value = writer.sample()
        finally:
            writer.close(pause=False)
        self.assertEqual(value['format'], explorer_model.FEED_V2)
        self.assertEqual(value['retained_from_slot'], 1)
        self.assertEqual(len(value['blocks']), 2048)
        self.assertEqual(value['blocks'][0]['slot'], 5)
        self.assertEqual([item['slot'] for item in value['retained_blocks']], [1, 2, 3])
        transactions = [item['transactions'][0] for item in value['retained_blocks']]
        self.assertTrue(all(set(tx) == {'signature', 'slot', 'position', 'fee_units', 'execution', 'status'}
                            and tx['status'] == 'finalized' for tx in transactions))
        for forbidden in (b'recipient', b'amount', b'987654321', b'base64', b'logMessages', b'private address'):
            self.assertNotIn(forbidden, self.path.read_bytes())

        self.calls.clear()
        restarted = Feed(self.path, self.network, self.rpc)
        try:
            self.assertEqual(restarted.sample()['retained_blocks'], value['retained_blocks'])
            rechecked = {params[0] for method, params, _ in self.calls if method == 'getBlock'}
            self.assertTrue({1, 2, 3, 2052} <= rechecked)
        finally:
            restarted.close(pause=False)

    def test_byte_bound_keeps_payments_and_corrupt_or_changed_checkpoint_is_refused(self):
        self.chain(8, {1, 7})
        self.write_v1(1, 7)
        writer = Feed(self.path, self.network, self.rpc)
        try:
            value = writer.sample()
            limit = self.path.stat().st_size - 80
            with patch.object(explorer_feed, 'MAX_BYTES', limit):
                writer.publish(copy.deepcopy(value))
                saved = read(self.path, os.getuid(), self.network)
            self.assertLess(saved['blocks'][0]['slot'], 7)
            self.assertEqual([b['slot'] for b in saved['retained_blocks']], [1])
        finally:
            writer.close(pause=False)

        original = self.path.read_bytes()
        self.records[1]['transactions'][0]['meta']['fee'] += 1
        restarted = Feed(self.path, self.network, self.rpc)
        try:
            with self.assertRaisesRegex(ValueError, 'retained explorer block is not canonical'):
                restarted.sample()
        finally:
            restarted.close()
        self.assertEqual(self.path.read_bytes(), original)

        for field, replacement in (('recipient', 'hidden address'),
                                   ('signature', saved['blocks'][-2]['transactions'][0]['signature'])):
            malformed = copy.deepcopy(saved)
            malformed['retained_blocks'][0]['transactions'][0][field] = replacement
            self.path.write_bytes(encode(malformed))
            corrupt = self.path.read_bytes()
            with self.assertRaisesRegex(ValueError, 'invalid explorer transaction'):
                Feed(self.path, self.network, self.rpc)
            self.assertEqual(self.path.read_bytes(), corrupt)

    @unittest.skipUnless(hasattr(os, "fork"), "requires process-fork crash testing")
    def test_terminated_backfill_preserves_v1_and_retry_validates_complete_ancestry(self):
        self.chain(16, {2, 5, 9})
        self.write_v1(11, 16)
        original = self.path.read_bytes()
        reader, notifier = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(reader)

            def interrupted(method, params, timeout):
                if method == 'getBlock' and params[0] == 8:
                    os.write(notifier, b'R')
                    signal.pause()
                return self.rpc(method, params, timeout)

            try:
                Feed(self.path, self.network, interrupted).prepare(2)
            finally:
                os._exit(1)
        os.close(notifier)
        try:
            self.assertEqual(select.select([reader], [], [], 5)[0], [reader])
            self.assertEqual(os.read(reader, 1), b'R')
        finally:
            os.close(reader)
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
        self.assertEqual(self.path.read_bytes(), original)

        fork = self.records[7]['blockhash']
        self.records[7]['blockhash'] = key(89)
        writer = Feed(self.path, self.network, self.rpc)
        try:
            with self.assertRaisesRegex(ValueError, 'backfill ancestry changed'):
                writer.prepare(2)
        finally:
            writer.close()
        self.assertEqual(self.path.read_bytes(), original)

        self.records[7]['blockhash'] = fork
        writer = Feed(self.path, self.network, self.rpc)
        try:
            writer.prepare(2)
            self.assertEqual([item['slot'] for item in writer.state['retained_blocks']], [2, 5, 9])
            self.assertEqual(writer.state['retained_from_slot'], 2)
            self.assertEqual([item['slot'] for item in writer.state['blocks']], list(range(11, 17)))
            self.assertEqual(writer.state['sequence'], 10)
        finally:
            writer.close(pause=False)
        backfilled = self.path.read_bytes()
        restarted = Feed(self.path, self.network, self.rpc)
        try:
            restarted.prepare(2)
            self.assertEqual(self.path.read_bytes(), backfilled)
            self.assertEqual(restarted.sample()['phase'], 'live')
        finally:
            restarted.close(pause=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
