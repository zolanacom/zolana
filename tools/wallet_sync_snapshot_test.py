"""Synthetic RPC/authorization boundaries; no validator, wallet or network calls."""
import ast
import base64
import copy
import concurrent.futures
import json
import hashlib
import io
from email.message import Message
from pathlib import Path
import types
import threading
import time
import urllib.request
import unittest
from unittest.mock import patch

import testnet_gateway as gateway
import testnet_gateway_test as existing
import wallet_sync_snapshot as snapshot


def wire_queries(raw):
    value = json.loads(raw)
    return [value] if isinstance(value, dict) else value


def block_hash(value):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    return '1' * 30 + alphabet[value // 58 % 58] + alphabet[value % 58]


class Fixture:
    def __init__(self, saved=7, slots=(10, 12, 17)):
        self.saved, self.slots = saved, list(slots)
        self.target = self.slots[-1] if self.slots else saved
        self.network = {'network': [67] * 32, 'genesis_hash': '1' * 32}
        self.pool_address = block_hash(99)
        self.pool = {'context': {'slot': self.target}, 'value': {
            'lamports': 5000, 'owner': block_hash(98), 'data': ['', 'base64']}}
        self.blocks = {}
        self.headers = {saved: {'parentSlot': max(0, saved - 1), 'blockHeight': 100,
                               'blockhash': block_hash(saved), 'previousBlockhash': block_hash(saved - 1)}}
        previous, height = saved, 100
        for slot in self.slots:
            # Skipped slots AND nonconsecutive block heights are preserved.
            height += 3
            header = {'parentSlot': previous, 'blockHeight': height,
                      'blockhash': block_hash(slot), 'previousBlockhash': block_hash(previous)}
            self.headers[slot] = header
            self.blocks[slot] = dict(header, transactions=[])
            previous = slot
        self.calls, self.raw_batches = [], []
        self.modify = lambda call, result: result
        self.app = object.__new__(gateway.Gateway)
        self.app.pool = self.pool_address
        self.app.info = {'network': self.network}
        self.app.forward = self.forward

    def forward(self, raw, timeout):
        if not 0 < timeout <= 15:
            raise ValueError('fixture received unbounded timeout')
        query = json.loads(raw)
        self.raw_batches.append(query)
        batch = [query] if isinstance(query, dict) else query
        result = []
        for query in batch:
            self.calls.append(copy.deepcopy(query))
            method, params = query['method'], query['params']
            if method == 'getGenesisHash':
                value = self.network['genesis_hash']
            elif method == 'getAccountInfo':
                if params != [self.pool_address, snapshot.POOL]:
                    raise ValueError('caller substituted pool or configuration')
                value = self.pool
            elif method == 'getBlocksWithLimit':
                if params != [self.saved + 1, 257, snapshot.RANGE]:
                    raise ValueError('range was not fixed and bounded')
                value = self.slots
            elif method == 'getBlock':
                value = (self.blocks if params[1] == snapshot.FULL else self.headers).get(params[0])
            elif method == 'getSlot':
                value = self.target
            elif method == 'getMinimumBalanceForRentExemption':
                value = 100 + params[0]
            else:
                raise ValueError('unexpected method')
            value = self.modify(query, copy.deepcopy(value))
            result.append({'jsonrpc': '2.0', 'id': query['id'], 'result': value})
        # Correlation must use IDs, not response arrival order.
        return json.dumps(result[0] if isinstance(query, dict) else list(reversed(result))).encode()

    def page(self, slot=None):
        return json.loads(self.app.sync_snapshot({'id': 'request-id', 'params': [self.saved if slot is None else slot]},
                                                snapshot.time.monotonic() + 15))['result']

    def history_calls(self):
        return [c for c in self.calls if c['method'] == 'getBlock' and c['params'][1] == snapshot.FULL]


def actual_capsule_forward(upstream):
    """Execute the exact live058 do_POST with only its upstream I/O replaced."""
    raw = (Path(__file__).parent / 'fixtures/native_cohort_fault_058_single_v1.py').read_bytes()
    if hashlib.sha256(raw).hexdigest() != '4855ae70151cf3853d35f658c9b8236a173bb542cd7c77e95333eace84f918e7':
        raise ValueError('actual058 public capsule fixture changed')
    tree = ast.parse(raw)
    gate = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'GrantRpcGate')
    init = next(n for n in gate.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
    handler = next(n for n in init.body if isinstance(n, ast.ClassDef) and n.name == 'Handler')
    method = next(n for n in handler.body if isinstance(n, ast.FunctionDef) and n.name == 'do_POST')
    owner = types.SimpleNamespace(upstream='127.0.0.1:1', observe=lambda *_: False,
                                  hold=lambda: (_ for _ in ()).throw(AssertionError('no grant observation')))
    namespace = {'json': json, 'urllib': urllib, 'owner': owner, 'MAX_RESPONSE': 16 * 1024 * 1024,
                 'base': types.SimpleNamespace(NoRedirect=gateway.NoRedirect)}
    exec(compile(ast.Module(body=[method], type_ignores=[]), '<exact058-capsule>', 'exec'), namespace)

    class Response:
        status = 200
        def __init__(self, body): self.body = body
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, maximum): return self.body[:maximum]

    def forward(raw, timeout):
        h = types.SimpleNamespace(path='/', headers=Message(), rfile=io.BytesIO(raw),
                                  wfile=io.BytesIO(), close_connection=False)
        h.headers['Content-Length'] = str(len(raw)); codes = []
        h.send_response = codes.append; h.send_header = lambda *_: None; h.end_headers = lambda: None
        namespace['do_POST'](h)
        if codes != [200]:
            raise urllib.error.URLError('actual058 capsule closed the rejected RPC envelope')
        return h.wfile.getvalue()
    # This exact captured handler is now called concurrently. Give its globals
    # a fixed fake transport instead of racing process-wide mock patch scopes.
    class Opener:
        def open(self, request, timeout):
            return Response(upstream(request.data, timeout))
    namespace['urllib'] = types.SimpleNamespace(request=types.SimpleNamespace(
        build_opener=lambda *_: Opener(), ProxyHandler=urllib.request.ProxyHandler,
        Request=urllib.request.Request))
    return forward


class SnapshotTests(unittest.TestCase):
    def test_actual058_capsule_rejects_every_batch_but_accepts_complete_snapshot_as_objects(self):
        f = Fixture(); capsule = actual_capsule_forward(f.forward)
        for batch in ([{'jsonrpc': '2.0', 'id': 0, 'method': 'getGenesisHash', 'params': []}],
                      [{'jsonrpc': '2.0', 'id': 0, 'method': 'getBlock', 'params': [10, snapshot.FULL]}]):
            with self.assertRaises(urllib.error.URLError): capsule(json.dumps(batch).encode(), 15)
        self.assertEqual(f.calls, [])
        f.app.forward = capsule
        result = f.page()
        self.assertIsNone(result['fallback'])
        self.assertEqual(len(result['canonical_tail']['blocks']), 3)
        self.assertEqual(len(f.raw_batches), 8)
        self.assertTrue(all(isinstance(q, dict) and q['id'] == 0 for q in f.raw_batches))

    def test_single_snapshot_responses_still_require_exact_original_object_identity(self):
        for raw in (b'[{"jsonrpc":"2.0","id":0,"result":"x"}]',
                    b'{"jsonrpc":"2.0","id":1,"result":"x"}',
                    b'{"jsonrpc":"2.0","id":false,"result":"x"}',
                    b'{"jsonrpc":"2.0","id":0,"id":0,"result":"x"}'):
            f = Fixture(); f.app.forward = lambda *_args, **_kw: raw
            with self.subTest(raw=raw), self.assertRaises(ValueError): f.page()

    def test_single_snapshot_response_budget_is_shared_across_metadata_and_history(self):
        f = Fixture(); count = [0]; original = f.forward
        def measured(raw, timeout):
            result = original(raw, timeout); count[0] += len(result); return result
        f.app.forward = measured
        with patch.object(gateway, 'RESPONSE_LIMIT', 1000):
            result = f.page()
        self.assertGreater(count[0], 1000)
        self.assertEqual(result['fallback'], 'response-too-large')
        self.assertIsNone(result['canonical_tail'])
        # Up to two reads may already be in flight when the shared byte limit
        # is crossed. The whole tail is discarded; no replacement read occurs.
        self.assertLessEqual(len(f.history_calls()), 3)

    def test_single_request_mode_is_explicit_and_preserves_public_read_validation(self):
        f = Fixture(); call = [{'method': 'getSlot', 'params': [{'commitment': 'processed'}]}]
        for flag, budget in ((1, [0]), (None, [0]), (True, None), (True, [True]), (True, [0])):
            with self.subTest(flag=flag, budget=budget), self.assertRaises(ValueError):
                f.app._upstream_reads(call, 1e20, single_requests=flag, response_budget=budget)
        self.assertEqual(f.calls, [])

    def test_actual058_capsule_accepts_bounded_public_reads_with_same_outer_shape(self):
        f = Fixture(); f.app.forward = actual_capsule_forward(f.forward)
        calls = [{'method': 'getSlot', 'params': [{'commitment': 'finalized'}]},
                 {'method': 'getMinimumBalanceForRentExemption', 'params': [4]}]
        result = json.loads(f.app.read_batch({'id': 'same'}, calls))
        self.assertEqual(result, {'jsonrpc': '2.0', 'id': 'same', 'result': [
            {'request': calls[0], 'result': 17}, {'request': calls[1], 'result': 104}]})
        self.assertTrue(all(isinstance(q, dict) and q['id'] == 0 for q in f.raw_batches))

    def test_snapshot257_fallback_can_continue_through_existing_history_capsule_route(self):
        f = Fixture(saved=7, slots=tuple(range(8, 265)))
        f.app.forward = actual_capsule_forward(f.forward)
        result = f.page()
        self.assertEqual(result['fallback'], 'tail-too-large')
        self.assertEqual(f.history_calls(), [])
        slots = f.slots[:256]
        result = json.loads(f.app.history_blocks({'id': 'legacy'}, slots))
        self.assertEqual(result['id'], 'legacy')
        self.assertEqual([item['slot'] for item in result['result']], slots)
        self.assertEqual([item['block'] for item in result['result']], [f.blocks[slot] for slot in slots])
        self.assertTrue(all(isinstance(q, dict) and q['id'] == 0 for q in f.raw_batches))

    def test_complete_tail_preserves_exact_headers_full_blocks_and_nonconsecutive_heights(self):
        f = Fixture()
        value = f.page()
        self.assertEqual(set(value), {'format', 'network', 'genesis', 'pool', 'target_header',
                                     'saved_header', 'canonical_tail', 'fallback'})
        self.assertEqual(value['format'], snapshot.FORMAT)
        self.assertIsNone(value['fallback'])
        self.assertEqual(value['pool'], f.pool)
        self.assertEqual(value['target_header'], f.headers[17])
        self.assertEqual(value['saved_header'], f.headers[7])
        self.assertEqual(value['canonical_tail'], {'after_slot': 7, 'target_slot': 17, 'next_slot': 17,
                         'complete': True, 'blocks': [{'slot': s, 'block': f.blocks[s]} for s in f.slots]})
        self.assertEqual(len(f.raw_batches), 8)
        self.assertTrue(all(isinstance(query, dict) and query['id'] == 0 for query in f.raw_batches))

    def test_one_pool_target_stays_pinned_when_rpc_head_advances(self):
        f = Fixture()
        f.slots.append(19)  # The range may advance beyond the original pool Bank.
        result = f.page()
        self.assertEqual(result['pool']['context']['slot'], 17)
        self.assertEqual(result['canonical_tail']['target_slot'], 17)
        self.assertEqual([b['slot'] for b in result['canonical_tail']['blocks']], [10, 12, 17])
        self.assertNotIn(19, [c['params'][0] for c in f.history_calls()])

    def test_257th_produced_block_returns_metadata_only_before_full_history_io(self):
        f = Fixture(saved=0, slots=tuple(range(1, 258)))
        result = f.page()
        self.assertEqual(result['fallback'], 'tail-too-large')
        self.assertIsNone(result['canonical_tail'])
        self.assertIsNone(result['saved_header'])
        self.assertEqual(f.history_calls(), [])

    def test_exactly256_produced_blocks_are_complete(self):
        f = Fixture(saved=0, slots=tuple(range(1, 257)))
        self.assertEqual(len(f.page()['canonical_tail']['blocks']), 256)

    def test_equal_cursor_uses_one_header_and_empty_complete_tail(self):
        f = Fixture(saved=7, slots=())
        result = f.page()
        self.assertEqual(result['saved_header'], result['target_header'])
        self.assertEqual(result['canonical_tail']['blocks'], [])
        self.assertFalse(any(c['method'] == 'getBlocksWithLimit' for c in f.calls))
        self.assertEqual(len([c for c in f.calls if c['method'] == 'getBlock']), 1)

    def test_pruned_cached_header_falls_back_without_reading_full_history(self):
        f = Fixture()
        del f.headers[7]
        result = f.page()
        self.assertEqual(result['fallback'], 'checkpoint-unavailable')
        self.assertIsNone(result['saved_header'])
        self.assertIsNone(result['canonical_tail'])
        self.assertEqual(f.history_calls(), [])

    def test_missing_target_genesis_mismatch_and_rollback_fail_closed(self):
        for mutate, requested, message in [
                (lambda f: f.headers.pop(17), None, 'target'),
                (lambda f: setattr(f, 'modify', lambda c, v: block_hash(4) if c['method'] == 'getGenesisHash' else v), None, 'genesis'),
                (lambda f: None, 18, 'rollback')]:
            f = Fixture();mutate(f)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                f.page(requested)
            self.assertEqual(f.history_calls(), [])

    def test_pruned_gap_parent_hash_height_and_final_target_mismatch_never_publish_partial_tail(self):
        changes = [lambda f: f.slots.remove(12),
                   lambda f: f.blocks[12].update(parentSlot=9),
                   lambda f: f.blocks[12].update(previousBlockhash=block_hash(9)),
                   lambda f: f.blocks[12].update(blockHeight=100),
                   lambda f: f.blocks[17].update(blockhash=block_hash(19)),
                   lambda f: f.blocks.update({12: 'not-a-block'})]
        for change in changes:
            f = Fixture();change(f)
            with self.subTest(change=change):
                result = f.page()
                self.assertEqual(result['fallback'], 'canonical-incomplete')
                self.assertIsNone(result['canonical_tail'])

    def test_malformed_range_cannot_be_silently_sorted_deduplicated_or_truncated(self):
        for slots in ([12, 10, 17], [10, 10, 17], [True, 17], [7, 17], [2**64], list(range(1, 259))):
            f = Fixture();f.slots = slots
            with self.subTest(slots=slots[:4]), self.assertRaisesRegex(ValueError, 'range malformed'):
                f.page()
            self.assertEqual(f.history_calls(), [])

    def test_upstream_history_byte_limit_returns_metadata_only_fallback(self):
        f = Fixture();forward = f.forward
        def bounded(raw, timeout):
            if any(q['method'] == 'getBlock' and q['params'][1] == snapshot.FULL for q in wire_queries(raw)):
                raise gateway._UpstreamResponseTooLarge('fixture byte bound')
            return forward(raw, timeout)
        f.app.forward = bounded
        result = f.page()
        self.assertEqual(result['fallback'], 'response-too-large')
        self.assertIsNone(result['canonical_tail'])

    def test_combined_response_bound_removes_whole_tail_not_trailing_blocks(self):
        f = Fixture();f.blocks[10]['transactions'] = [{'transaction': ['x' * 2000, 'base64']}]
        with patch.object(snapshot, 'LIMIT', 1400):
            result = f.page()
        self.assertEqual(result['fallback'], 'response-too-large')
        self.assertIsNone(result['canonical_tail'])

    def test_same_deadline_covers_metadata_history_and_final_encoding(self):
        f = Fixture();forward = f.forward;clock = [0]
        def delayed(raw, timeout):
            result = forward(raw, timeout)
            if any(q['method'] == 'getBlock' and q['params'][1] == snapshot.FULL for q in wire_queries(raw)):
                clock[0] = 16
            return result
        f.app.forward = delayed
        with patch('time.monotonic', side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                f.app.sync_snapshot({'id': 1, 'params': [7]}, 15)

    def test_internal_metadata_construction_never_broadens_caller_read_batch(self):
        f = Fixture()
        for calls in [[{'method': 'sendTransaction', 'params': ['wire']}],
                      [{'method': 'getAccountInfo', 'params': [block_hash(3), snapshot.POOL]}],
                      [{'method': 'getBlock', 'params': [3, snapshot.FULL]}],
                      [{'method': 'getBlocksWithLimit', 'params': [1, 258, snapshot.RANGE]}]]:
            with self.subTest(calls=calls), self.assertRaises(ValueError):
                f.app._upstream_reads(calls, snapshot.time.monotonic() + 15, snapshot_pool=f.pool_address)
        with self.assertRaises(ValueError):
            gateway.read_calls({'params': [[{'method': 'getGenesisHash', 'params': []}]]})
        self.assertNotIn('getBlocksWithLimit', gateway.METHODS)
        self.assertEqual(f.calls, [])

    def test_metadata_identity_null_and_explicit_pruning_semantics(self):
        calls = [{'method': 'getBlock', 'params': [7, snapshot.HEADER]}]
        good = {'jsonrpc': '2.0', 'id': 0, 'result': None}
        self.assertEqual(snapshot.metadata_results(json.dumps([good]).encode(), calls), [None])
        pruning = {'jsonrpc': '2.0', 'id': 0, 'error': {'code': -32001, 'message': 'cleaned'}}
        self.assertEqual(snapshot.metadata_results(json.dumps([pruning]).encode(), calls), [None])
        bad = [[dict(good, id=True)], [good, good], [dict(good, id=1)],
               [dict(pruning, error={'code': -32603, 'message': 'unavailable'})],
               [dict(good, extra=1)], [dict(good, jsonrpc='1.0')]]
        for response in bad:
            with self.subTest(response=response), self.assertRaises(ValueError):
                snapshot.metadata_results(json.dumps(response).encode(), calls)
        with self.assertRaises(ValueError):
            snapshot.metadata_results(b'[{"jsonrpc":"2.0","id":0,"id":0,"result":null}]', calls)
        with self.assertRaises(ValueError):
            snapshot.metadata_results(json.dumps([good]).encode(), [{'method': 'getGenesisHash', 'params': []}])


class SnapshotConcurrencyTests(unittest.TestCase):
    def test_two_snapshot_requests_share_two_upstream_workers_and_preserve_order(self):
        fixtures = [Fixture(saved=7, slots=tuple(range(8, 24))) for _ in range(2)]
        lock, entered, release = threading.Lock(), threading.Event(), threading.Event()
        active = peak = 0
        def wrapped(original):
            def forward(raw, timeout):
                nonlocal active, peak
                with lock:
                    active += 1; peak = max(peak, active)
                    if active == 2: entered.set()
                try:
                    if not release.wait(2): raise ValueError('fixture release timeout')
                    return original(raw, timeout)
                finally:
                    with lock: active -= 1
            return forward
        for f in fixtures: f.app.forward = wrapped(f.forward)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as callers:
            futures = [callers.submit(f.page) for f in fixtures]
            try:
                self.assertTrue(entered.wait(2), 'two independent reads must overlap')
                with lock: self.assertEqual(peak, 2)
            finally: release.set()
            values = [future.result(timeout=3) for future in futures]
        self.assertEqual(peak, 2)
        for f, value in zip(fixtures, values):
            self.assertEqual([item['slot'] for item in value['canonical_tail']['blocks']], f.slots)
            unique = [(call['method'], json.dumps(call['params'], sort_keys=True)) for call in f.calls]
            self.assertEqual(len(unique), len(set(unique)), 'one original call per requested read')
            self.assertEqual(len(f.calls), 2 + 3 + len(f.slots))

    def test_history_reply_arrival_does_not_reorder_the_canonical_tail(self):
        f = Fixture(slots=(10, 12, 17, 18)); original = f.forward
        release, lock = threading.Event(), threading.Lock(); completed = []
        def forward(raw, timeout):
            query = json.loads(raw)
            if query['method'] != 'getBlock' or query['params'][1] != snapshot.FULL:
                return original(raw, timeout)
            slot = query['params'][0]
            if slot == 10 and not release.wait(2): raise ValueError('fixture out-of-order timeout')
            result = original(raw, timeout)
            with lock: completed.append(slot)
            if slot == 12: release.set()
            return result
        f.app.forward = forward; value = f.page()
        self.assertEqual(completed[0], 12)
        self.assertEqual([item['slot'] for item in value['canonical_tail']['blocks']], f.slots)
        self.assertEqual(sorted(completed), f.slots)

    def test_failure_cancels_queued_reads_and_never_schedules_another_wave(self):
        f = Fixture(slots=tuple(range(8, 24))); seen = []; lock = threading.Lock()
        def forward(raw, timeout):
            query = json.loads(raw)
            with lock: seen.append(query['params'][0])
            raise ValueError('fixture upstream refusal')
        f.app.forward = forward
        calls = [{'method': 'getBlock', 'params': [slot, snapshot.FULL]} for slot in f.slots]
        with self.assertRaisesRegex(ValueError, 'fixture upstream refusal'):
            f.app._upstream_reads(calls, time.monotonic() + 2, history=True,
                single_requests=True, response_budget=[0], parallel_snapshot=True)
        self.assertTrue(1 <= len(seen) <= 2)
        self.assertTrue(set(seen) <= set(f.slots[:2]))
        self.assertEqual(len(seen), len(set(seen)))

    def test_concurrent_responses_charge_one_shared_budget_without_lost_bytes(self):
        f = Fixture(slots=(10, 12, 17, 18)); barrier = threading.Barrier(2); original = f.forward
        expected = sum(len(json.dumps({'jsonrpc': '2.0', 'id': 0, 'result': f.blocks[slot]}).encode()) for slot in f.slots)
        def forward(raw, timeout):
            result = original(raw, timeout); barrier.wait(timeout=2); return result
        f.app.forward = forward; budget = [0]
        calls = [{'method': 'getBlock', 'params': [slot, snapshot.FULL]} for slot in f.slots]
        with patch.object(gateway, 'RESPONSE_LIMIT', expected - 1):
            with self.assertRaises(gateway.HistoryTooLarge):
                f.app._upstream_reads(calls, time.monotonic() + 2, history=True,
                    single_requests=True, response_budget=budget, parallel_snapshot=True)
        self.assertEqual(budget[0], expected)
        self.assertEqual(len(f.calls), 4)

    def test_size_fallback_cannot_hide_a_parallel_authorization_failure(self):
        f = Fixture(slots=(10, 12, 17, 18)); barrier = threading.Barrier(2); original = f.forward
        def forward(raw, timeout):
            query = json.loads(raw); barrier.wait(timeout=2)
            if query['params'][0] == 10: raise gateway._UpstreamResponseTooLarge('fixture size')
            if query['params'][0] == 12: raise urllib.error.HTTPError('http://127.0.0.1/', 403, 'fixture denied', {}, io.BytesIO())
            return original(raw, timeout)
        f.app.forward = forward
        calls = [{'method': 'getBlock', 'params': [slot, snapshot.FULL]} for slot in f.slots]
        with self.assertRaises(urllib.error.HTTPError) as error:
            f.app._upstream_reads(calls, time.monotonic() + 2, history=True,
                single_requests=True, response_budget=[0], parallel_snapshot=True)
        self.assertEqual(error.exception.code, 403)

    def test_expired_queued_request_never_reaches_upstream_or_gets_a_new_deadline(self):
        release, entered = threading.Event(), threading.Barrier(3)
        def occupy(): entered.wait(timeout=2); release.wait(2)
        occupied = [gateway._SNAPSHOT_READS.submit(occupy) for _ in range(2)]
        entered.wait(timeout=2)
        f = Fixture(); calls = [{'method': 'getBlock', 'params': [slot, snapshot.FULL]} for slot in f.slots]
        began = time.monotonic()
        try:
            with self.assertRaisesRegex(ValueError, 'deadline'):
                f.app._upstream_reads(calls, began + .03, history=True,
                    single_requests=True, response_budget=[0], parallel_snapshot=True)
            self.assertLess(time.monotonic() - began, 1)
            self.assertEqual(f.calls, [])
        finally:
            release.set()
            for future in occupied: future.result(timeout=2)
        self.assertEqual(f.calls, [], 'cancelled queued calls must not run after capacity returns')


class AuthorizationTests(unittest.TestCase):
    def test_fresh_full_precharge_precedes_any_snapshot_io_even_for_empty_or_fallback_tail(self):
        helper = existing.GatewayTests()
        header = base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'getWalletSyncSnapshot', 'params': [0]}
        for bulk in (False, True):
            for result in (b'{"result":{"fallback":"tail-too-large"}}', b'{"result":{"canonical_tail":{"blocks":[]}}}'):
                code, _, calls = helper.request(request, header, authorize_many=bulk, app_body=result)
                self.assertEqual(code, 200)
                expected = ['ingress', 'authorize-many', 'snapshot'] if bulk else ['ingress'] + ['authorize'] * 21 + ['snapshot']
                self.assertEqual([c[0] for c in calls], expected)
                if bulk:
                    self.assertEqual(calls[1][2], ['--units', '21'])
                code, _, calls = helper.request(request, header, authorize_many=bulk, authorize_limit=20)
                self.assertEqual(code, 429)
                self.assertFalse(any(c[0] in ('snapshot', 'forward') for c in calls))
        for access, headers in [(None, {}), (header, {'Origin': 'https://untrusted.example'})]:
            code, _, calls = helper.request(request, access, headers=headers)
            self.assertEqual(code, 403)
            self.assertFalse(any(c[0] in ('snapshot', 'forward') for c in calls))

    def test_bad_cursor_or_ambiguous_rpc_batch_refused_before_debit(self):
        helper = existing.GatewayTests();header = base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        request = {'jsonrpc': '2.0', 'id': 1, 'method': 'getWalletSyncSnapshot', 'params': [0]}
        for params in (None, [], [True], [-1], [2**64], [1.0], [0, 1], [{'slot': 0}], ['0']):
            code, _, calls = helper.request(dict(request, params=params), header)
            self.assertEqual(code, 403)
            self.assertEqual([c[0] for c in calls], ['ingress'])
        code, _, calls = helper.request([request], header)
        self.assertEqual(code, 403)
        self.assertFalse(any(c[0] in ('authorize', 'snapshot', 'forward') for c in calls))


if __name__ == '__main__':
    unittest.main()
