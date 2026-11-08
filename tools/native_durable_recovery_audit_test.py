"""Independent disposable RPC fixtures; no sockets, keys, wallets or host calls."""
import base64
import copy
import hashlib
import io
import json
import struct
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import native_durable_recovery_audit as audit
import native_fast_cash_audit as native
from canonical_archive_store import Reader
from canonical_archive_store_test import NETWORK, blocks, target


def account(raw, lamports):
    return dict(data=[base64.b64encode(raw).decode(), 'base64'],
                owner=native.b58(native.PROGRAM), executable=False,
                lamports=lamports, rentEpoch=0, space=len(raw))


def pool_bytes(context=150):
    raw = bytearray(25_728)
    raw[:8] = b'NPOOL004'
    raw[8:40] = bytes(NETWORK['network'])
    struct.pack_into('<QQQ', raw, 40, 10_000, 994, 8)
    raw[64 + 3 * 32:64 + 4 * 32] = bytes([2]) * 32
    history = (b'ZOLANCH1' + b'\1\0' + b'ZolanaSlotRoots1' +
               bytes(NETWORK['network']) + struct.pack('<HQQ', 1, context, 8) +
               bytes([2]) * 32)
    struct.pack_into('<I', raw, 1088, len(history))
    raw[1092:1092 + len(history)] = history
    return bytes(raw)


class Fixture:
    def __init__(self):
        self.peers = [dict(identity=native.b58(bytes([i]) * 32),
                           rpc=f'127.0.0.1:{12340 + i}') for i in range(1, 4)]
        self.items = blocks(range(1, 34))
        # Public syntactic RPC fixture wires, not real signed transactions or
        # Orchard proof evidence. Preserve success/failed/unrelated metadata.
        for item in self.items:
            for index, entry in enumerate(item['block']['transactions']):
                sig = hashlib.sha512(f"{item['slot']}/{index}".encode()).digest()
                wire = b'\1' + sig + bytes(1300 - 65)
                entry['transaction'] = [base64.b64encode(wire).decode(), 'base64']
        self.payments = []
        for slot in [2, 5, 9]:
            entry = self.items[slot - 1]['block']['transactions'][0]
            wire = base64.b64decode(entry['transaction'][0])
            self.payments.append(dict(signature=native.b58(wire[1:65]), slot=slot,
                                      recorded_transaction_sha256=native.b58(hashlib.sha256(wire).digest()),
                                      recorded_transaction_bytes=len(wire)))
        self.anchor = target(self.items)
        self.calls = []
        self.genesis = NETWORK['genesis_hash']
        self.change = lambda peer, method, value: value
        self.context = 150
        self.raw_pool = pool_bytes()
        self.pruned_cutoff = None
        self.entries = []
        for i in range(1, 9):
            nullifier = bytes([i]) * 32
            raw = b'NSPENT01' + nullifier
            address = native.b58(native.pda([b'native-payment-spent-v1', native.POOL, nullifier]))
            self.entries.append(dict(pubkey=address, account=account(raw, 1)))
        self.entries.append(dict(pubkey=native.b58(native.POOL),
                                 account=account(self.raw_pool, 10_994)))
        self.expected = dict(
            accounts=[dict(address=e['pubkey'], lamports=e['account']['lamports'],
                           data_sha256=None if e['pubkey'] == native.b58(native.POOL) else
                           native.b58(hashlib.sha256(base64.b64decode(e['account']['data'][0])).digest()))
                      for e in sorted(self.entries, key=lambda e: native.un58(e['pubkey']))],
            pool=dict(note_count=8, backing=994, root=[2] * 32,
                      network=NETWORK['network'], rent_floor=10_000, slot_anchors=True),
            permanent_nullifiers=8)

    def rpc(self, url):
        peer = url.rsplit(':', 1)[1].rstrip('/')
        fixture = self

        class Rpc:
            def call(self, method, params, deadline):
                if deadline <= time.monotonic():
                    raise ValueError('fixture deadline')
                fixture.calls.append((peer, method, copy.deepcopy(params)))
                if method == 'getGenesisHash':
                    value = fixture.genesis
                elif method == 'getSlot':
                    value = fixture.anchor['slot']
                elif method == 'getFirstAvailableBlock':
                    value = 1
                elif method == 'getBlocksWithLimit':
                    start, limit = params[:2]
                    value = [item['slot'] for item in fixture.items if item['slot'] >= start][:limit]
                elif method == 'getBlock':
                    item = next((item for item in fixture.items if item['slot'] == params[0]), None)
                    value = None if item is None else copy.deepcopy(item['block'])
                    if value is not None and params[1]['transactionDetails'] == 'none':
                        value = {k: value[k] for k in
                                 ['blockhash', 'previousBlockhash', 'parentSlot', 'blockHeight']}
                    elif fixture.pruned_cutoff is not None and params[0] <= fixture.pruned_cutoff:
                        value = None
                elif method == 'getAccountInfo':
                    value = dict(context=dict(slot=fixture.context),
                                 value=account(fixture.raw_pool, 10_994))
                elif method == 'getProgramAccounts':
                    value = copy.deepcopy(fixture.entries)
                    if len(params) > 1 and params[1].get('withContext'):
                        value = dict(context=dict(slot=fixture.context), value=value)
                else:
                    raise AssertionError('unexpected read method: ' + method)
                return fixture.change(peer, method, value)

        return Rpc()


class NativeDurableRecoveryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zolana093-audit-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.fixture = Fixture()
        self.real_rpc = audit.Rpc
        self.patch = patch.object(audit, 'Rpc', side_effect=self.fixture.rpc)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def capture(self, root=None):
        return audit.capture_full_history(root or self.root, self.fixture.peers, NETWORK)

    def test_capture_uses_actual_store_and_preserves_every_full_body(self):
        meta = self.capture()
        self.assertEqual(meta['relative_path'], 'canonical/full-history.sqlite3')
        self.assertEqual(meta['anchor'], self.fixture.anchor)
        self.assertEqual(meta['produced_blocks'], len(self.fixture.items))
        path = Path(meta['path'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), meta['file_sha256'])
        values, after = [], 0
        with Reader(path, NETWORK, NETWORK['genesis_hash']) as reader:
            while after < meta['through_slot']:
                result = json.loads(reader.page(dict(id=1, params=[after, meta['through_slot'],
                                                      None if after == 0 else meta['anchor']])))['result']
                values.extend(result['blocks'])
                after = result['next_slot']
        self.assertEqual(values, self.fixture.items)
        self.assertTrue(any(tx['meta']['err'] is not None
                            for item in values for tx in item['block']['transactions']))

    def test_wrong_genesis_or_changed_fresh_anchor_never_becomes_a_capture(self):
        genesis_root = self.root / 'genesis'
        genesis_root.mkdir(mode=0o700)
        self.fixture.genesis = native.b58(bytes([9]) * 32)
        with self.assertRaises(ValueError):
            self.capture(genesis_root)
        self.fixture.genesis = NETWORK['genesis_hash']
        anchor_root = self.root / 'anchor'
        anchor_root.mkdir(mode=0o700)
        self.fixture.change = lambda peer, method, value: (
            dict(value, blockhash=native.b58(bytes([8]) * 32))
            if method == 'getBlock' and peer == '12342' else value)
        with self.assertRaises(ValueError):
            self.capture(anchor_root)

    def test_capture_ignores_peer_range_progress_only_above_fixed_target(self):
        def progress_above_target(peer, method, value):
            if method == 'getBlocksWithLimit' and len(value) < 16:
                return value + list(range(34, 34 + int(peer[-1])))
            return value
        self.fixture.change = progress_above_target
        meta = self.capture()
        self.assertEqual(meta['through_slot'], 33)
        self.assertEqual(meta['produced_blocks'], 33)

        # A disagreement inside the immutable target remains a refusal, even
        # when both raw lists independently have valid ordering and bounds.
        other = self.root / 'inside-target'
        other.mkdir(mode=0o700)
        self.fixture.change = lambda peer, method, value: (
            value[1:] if method == 'getBlocksWithLimit' and peer == '12342' else value)
        with self.assertRaises(ValueError):
            self.capture(other)

    def test_native_stable_state_and_prefix_survive_rolling_checkpoint_progress(self):
        before = audit.audit_native(self.fixture.peers, self.fixture.expected, NETWORK)
        prefix = hashlib.sha256(self.fixture.raw_pool[:1088]).hexdigest()
        self.fixture.context += 1
        self.fixture.raw_pool = pool_bytes(self.fixture.context)
        after = audit.audit_native(self.fixture.peers, self.fixture.expected, NETWORK,
                                   expected_pool_prefix_sha256=prefix)
        self.assertIsInstance(before, dict)
        self.assertIsInstance(after, dict)

    def test_native_missing_marker_wrong_account_or_stale_checkpoint_refuse(self):
        original = copy.deepcopy(self.fixture.entries)
        self.fixture.entries = self.fixture.entries[1:]
        with self.assertRaises(ValueError):
            audit.audit_native(self.fixture.peers, self.fixture.expected, NETWORK)
        self.fixture.entries = copy.deepcopy(original)
        self.fixture.entries[0]['account']['owner'] = native.b58(bytes([9]) * 32)
        with self.assertRaises(ValueError):
            audit.audit_native(self.fixture.peers, self.fixture.expected, NETWORK)
        self.fixture.entries = original
        self.fixture.context += 1
        with self.assertRaises(ValueError):
            audit.audit_native(self.fixture.peers, self.fixture.expected, NETWORK)

    def test_actual_archive_adapter_recovers_exact_old_payment_wires_without_primary_bodies(self):
        meta = self.capture()
        self.fixture.pruned_cutoff = 10
        self.fixture.calls.clear()
        cutoffs = {p['identity']: 10 for p in self.fixture.peers}
        result = audit.verify_archived_payments(meta, self.fixture.peers,
                                                self.fixture.payments, cutoffs)
        self.assertEqual(set(result['payments']), {p['signature'] for p in self.fixture.payments})
        self.assertTrue(result['full_canonical_pages_equal_all_three'])
        self.assertTrue(result['primary_old_blocks_unavailable'])
        full_reads = [params[0] for _, method, params in self.fixture.calls
                      if method == 'getBlock' and params[1]['transactionDetails'] == 'full']
        self.assertCountEqual(full_reads, [2, 5, 9] * 3,
                              'only explicit absence probes may request old primary full bodies')

    def test_archived_acceptance_refuses_unpruned_boundary_wrong_wire_and_bad_rpc_reason(self):
        meta = self.capture()
        self.fixture.pruned_cutoff = 10
        cutoffs = {p['identity']: 10 for p in self.fixture.peers}
        too_short = dict(cutoffs)
        too_short[self.fixture.peers[1]['identity']] = 8
        with self.assertRaisesRegex(ValueError, 'pruned prefix'):
            audit.verify_archived_payments(meta, self.fixture.peers,
                                            self.fixture.payments, too_short)
        wrong_wire = copy.deepcopy(self.fixture.payments)
        wrong_wire[0]['recorded_transaction_sha256'] = native.b58(bytes([9]) * 32)
        with self.assertRaises(ValueError):
            audit.verify_archived_payments(meta, self.fixture.peers, wrong_wire, cutoffs)
        wrong_size = copy.deepcopy(self.fixture.payments)
        wrong_size[0]['recorded_transaction_bytes'] += 1
        with self.assertRaisesRegex(ValueError, 'wire/metadata'):
            audit.verify_archived_payments(meta, self.fixture.peers, wrong_size, cutoffs)

        def reject_for_other_reason(peer, method, value):
            if method == 'getBlock' and value is None:
                raise audit.RpcRefusal(-32602)
            return value
        self.fixture.change = reject_for_other_reason
        with self.assertRaisesRegex(ValueError, 'non-pruning reason'):
            audit.verify_archived_payments(meta, self.fixture.peers,
                                            self.fixture.payments, cutoffs)

    def test_real_rpc_constructor_and_dispatch_refuse_nonfixed_or_writing_requests(self):
        for url in ['https://127.0.0.1:1234', 'http://localhost:1234',
                    'http://127.0.0.1:1234/path', 'http://user@127.0.0.1:1234']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.real_rpc(url)
        rpc = self.real_rpc('http://127.0.0.1:1234')
        rpc.opener = Mock()
        rpc.opener.open.side_effect = AssertionError('refused input must never reach transport')
        signature = native.b58(bytes(range(64)))
        transaction_options = dict(encoding='base64', commitment='finalized', maxSupportedTransactionVersion=1)
        for method, params in [('sendTransaction', ['unused']), ('getGenesisHash', [1]),
                               ('sendTransaction', [signature, transaction_options]),
                               ('getTransaction', [native.b58(bytes(63)), transaction_options]),
                               ('getTransaction', ['1' + signature, transaction_options]),
                               ('getTransaction', [signature, dict(transaction_options, commitment='confirmed')]),
                               ('getTransaction', [signature, dict(transaction_options, maxSupportedTransactionVersion=True)]),
                               ('getTransaction', [signature, dict(transaction_options, minContextSlot=1)]),
                               ('getBlock', [True, audit.FULL]),
                               ('getBlock', [1, dict(audit.FULL, rewards=0)]),
                               ('getBlock', [1, dict(audit.FULL, maxSupportedTransactionVersion=False)]),
                               ('getProgramAccounts', [native.b58(native.PROGRAM),
                                  dict(encoding='base64', commitment='finalized', withContext=1)]),
                               ('getBlocksWithLimit', [1, 17, {'commitment': 'finalized'}])]:
            with self.subTest(method=method, params=params), self.assertRaises(ValueError):
                rpc.call(method, params, time.monotonic() + 1)
        rpc.opener.open.assert_not_called()

    def test_real_rpc_reads_exact_finalized_transaction(self):
        rpc = self.real_rpc('http://127.0.0.1:1234')
        rpc.opener = Mock()
        result = dict(slot=1, transaction=['AA==', 'base64'])
        rpc.opener.open.return_value = io.BytesIO(audit.encoded(dict(jsonrpc='2.0', id=1, result=result)))
        params = [native.b58(bytes(range(64))),
                  dict(encoding='base64', commitment='finalized', maxSupportedTransactionVersion=1)]
        self.assertEqual(rpc.call('getTransaction', params, time.monotonic() + 1), result)
        rpc.opener.open.assert_called_once()
        request, = rpc.opener.open.call_args.args
        self.assertEqual(json.loads(request.data), dict(jsonrpc='2.0', id=1, method='getTransaction', params=params))


if __name__ == '__main__':
    unittest.main()
