"""Public synthetic finalized-block reuse; no host, wallet or authority data."""
import json
import time
import unittest
from unittest.mock import patch

import testnet_gateway as gateway
import wallet_sync_snapshot as snapshot
from wallet_sync_snapshot_test import Fixture


class FinalizedCacheTests(unittest.TestCase):
    def fixture(self):
        value = Fixture()
        value.app._finalized_blocks = gateway._FinalizedBlockCache()
        return value

    def test_second_client_reuses_only_blocks_while_mutable_reads_remain_fresh(self):
        f = self.fixture()
        first = f.page()
        first['canonical_tail']['blocks'][0]['block']['transactions'].append({'not': 'cached'})
        start = len(f.calls)
        second = f.page()
        self.assertEqual([c['method'] for c in f.calls[start:]],
                         ['getGenesisHash', 'getAccountInfo', 'getBlocksWithLimit'])
        self.assertEqual(second['canonical_tail']['blocks'][0]['block']['transactions'], [])
        # A different Gateway instance never inherits the prior process state.
        other = self.fixture(); other.page()
        self.assertTrue(other.history_calls())

    def test_exact_slot_and_fixed_config_key_only(self):
        cache = gateway._FinalizedBlockCache()
        for kind, options in [('full', snapshot.FULL), ('header', snapshot.HEADER)]:
            self.assertEqual(cache.key({'method': 'getBlock', 'params': [7, options]}), (7, kind))
        for slot in (True, -1, 2**64, 7.0, '7'):
            self.assertIsNone(cache.key({'method': 'getBlock', 'params': [slot, snapshot.FULL]}))
        for method, options in [('getAccountInfo', snapshot.FULL),
                                ('getBlock', dict(snapshot.FULL, commitment='confirmed')),
                                ('getBlock', dict(snapshot.FULL, rewards=0)),
                                ('getBlock', dict(snapshot.FULL, unsupported=True))]:
            self.assertIsNone(cache.key({'method': method, 'params': [7, options]}))
        f = self.fixture(); f.page()
        start = len(f.calls)
        f.app._upstream_reads([{'method': 'getBlock', 'params': [10, dict(snapshot.HEADER)]}],
            time.monotonic() + 15, snapshot_pool=f.pool_address, single_requests=True, response_budget=[0])
        self.assertEqual([c['params'] for c in f.calls[start:]], [[10, snapshot.HEADER]])

    def test_missing_or_invalid_header_does_not_poison_cache(self):
        for value in (None, {'blockhash': 'malformed'}):
            f = self.fixture()
            f.modify = lambda call, result: value if call['method'] == 'getBlock' and call['params'][1] == snapshot.HEADER else result
            for _ in range(2):
                with self.assertRaises(ValueError): f.page()
            self.assertEqual(sum(c['method'] == 'getBlock' and c['params'][0] == f.target for c in f.calls), 2)

    def test_error_and_wrong_rpc_identity_never_cached(self):
        for response in ({'jsonrpc': '2.0', 'id': 0, 'error': {'code': -32000, 'message': 'fixture'}},
                         {'jsonrpc': '2.0', 'id': 1, 'result': {'not': 'a block'}}):
            f = self.fixture(); calls = []
            def failed(raw, timeout):
                calls.append(raw)
                return json.dumps(response).encode()
            f.app.forward = failed
            for _ in range(2):
                with self.assertRaises(ValueError):
                    f.app._upstream_reads([{'method': 'getBlock', 'params': [10, snapshot.FULL]}],
                        time.monotonic() + 15, history=True, single_requests=True, response_budget=[0])
            self.assertEqual(len(calls), 2)
            self.assertFalse(f.app._finalized_blocks._entries)

    def test_cached_blocks_still_undergo_pool_and_chain_validation(self):
        f = self.fixture(); f.page()
        # Cached blocks cannot make fresh rollback or contradictory target valid.
        f.pool['context']['slot'] = f.saved - 1
        with self.assertRaisesRegex(ValueError, 'rollback'): f.page()
        f.pool['context']['slot'] = f.target
        original = f.app._finalized_blocks.get((f.target, 'header'))
        broken = json.loads(original); broken['result']['blockhash'] = '2' * 32
        # This seam represents a syntactically valid, inconsistent finalized RPC.
        f.app._finalized_blocks.put((f.target, 'header'), json.dumps(broken).encode(), broken['result'])
        self.assertEqual(f.page()['fallback'], 'canonical-incomplete')

    def test_lru_count_bytes_and_age_are_bounded(self):
        cache = gateway._FinalizedBlockCache()
        self.assertEqual((cache.MAX_ENTRIES, cache.MAX_BYTES, cache.MAX_AGE), (512, 16 * 1024**2, 60))
        cache.MAX_ENTRIES = 2; cache.MAX_BYTES = 6
        block = Fixture().headers[7]
        with patch.object(gateway.time, 'monotonic', return_value=100):
            for slot in (1, 2): cache.put((slot, 'header'), b'abc', block)
            self.assertEqual(cache.get((1, 'header')), b'abc')
            cache.put((3, 'header'), b'def', block)
            self.assertIsNone(cache.get((2, 'header')))
            self.assertEqual(cache._bytes, 6)
            cache.put((4, 'header'), b'1234567', block)
            self.assertIsNone(cache.get((4, 'header')))
        with patch.object(gateway.time, 'monotonic', return_value=159.99):
            self.assertEqual(cache.get((1, 'header')), b'abc')
        with patch.object(gateway.time, 'monotonic', return_value=160):
            self.assertIsNone(cache.get((1, 'header')))
            self.assertEqual(cache._bytes, 0)


if __name__ == '__main__':
    unittest.main()
