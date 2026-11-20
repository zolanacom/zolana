"""The first-sync mirror collector program, on loopback, with no chain and no wallet binary.

The program under test is used unchanged, and so are the modules it pins: history_retention
(capture and the store rules), gateway_history (the reader the gateway serves pages with) and
its codec. Two things are stand-ins:

  - the node: a loopback server in this file that answers the finalized reads of a fixed
    public chain whose headers follow a rule (no consensus, no ledger, no write method);
  - the collector binary: fixtures/first_sync_collector_stand_in.py, which has the command
    line, store layout and result line of `native-wallet archive` and none of its
    verification of signatures, proofs, the note tree, nullifiers or the pool.

So these cases cover what the program itself decides: its configuration and pinned files, the
read-only paced forwarder, publishing, reading the mirror back, adopting an earlier store,
setting the manifest aside and restoring it, and leaving when the chain is down. They do not
cover the wallet engine's verification, which has its own Rust tests.

Pinned files cannot be root-owned in a test: the program's reader is built for the user
running the test, exactly as its --rehearsal-root switch does. Nothing else differs.
"""
import base64
import concurrent.futures
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

import first_sync_mirror as program

TOOLS = Path(__file__).resolve().parent
PINNED = ('history_retention.py', 'gateway_history_codec.py', 'gateway_history.py')
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
mine = program.reader(os.geteuid())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def base58(raw):
    zeros = len(raw) - len(raw.lstrip(b'\0'))
    value, output = int.from_bytes(raw, 'big'), ''
    while value:
        value, digit = divmod(value, 58)
        output = ALPHABET[digit] + output
    return '1' * zeros + output


class Chain:
    """A fixed public chain. Headers follow a rule, because nothing here recomputes a block hash
    from block contents; every slot that is a multiple of `skip` was not produced."""

    def __init__(self, target=1300, skip=97, carrying=(5, 700, 1290), rule=b'first-sync-test'):
        self.target, self.skip, self.carrying, self.rule = target, skip, frozenset(carrying), rule
        self.blocks = target - target // skip
        self.network = {'network': [7] * 32, 'genesis_hash': self.hash(0)}
        self.pool = base58(hashlib.blake2b(b'pool', digest_size=32, person=rule).digest())

    def hash(self, slot):
        return base58(hashlib.blake2b(slot.to_bytes(8, 'little'), digest_size=32, person=self.rule).digest())

    def produced(self, slot):
        return 1 <= slot <= self.target and slot % self.skip != 0

    def parent(self, slot):
        return slot - 1 if slot == 1 or (slot - 1) % self.skip else slot - 2

    def slots(self, start, end):
        return [slot for slot in range(max(start, 1), min(end, self.target) + 1) if slot % self.skip]

    def block(self, slot, full):
        """As a node's getBlock answers; the transactions are opaque public bytes, not payments."""
        block = {'blockHeight': slot - slot // self.skip, 'blockTime': None, 'blockhash': self.hash(slot),
                 'parentSlot': self.parent(slot), 'previousBlockhash': self.hash(self.parent(slot))}
        if full:
            block['transactions'] = [] if slot not in self.carrying else [
                {'transaction': [base64.b64encode(b'public stand-in bytes %d' % slot).decode(), 'base64'],
                 'version': 'legacy', 'meta': {'err': None}}]
        return block


class NodeHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    disable_nagle_algorithm = True

    def log_message(self, *_):
        pass

    def answer(self, method, params):
        node, chain = self.server.node, self.server.node.chain
        if method == 'getGenesisHash':
            return chain.network['genesis_hash']
        if method == 'getSlot':
            return chain.target
        if method == 'getBlockHeight':
            return chain.blocks + node.advanced()
        if method == 'getFirstAvailableBlock':
            return 0
        if method == 'getAccountInfo':
            return {'context': {'slot': chain.target},
                    'value': None if params[0] != chain.pool else {
                        'lamports': 1, 'owner': '1' * 32, 'data': ['', 'base64'], 'executable': False,
                        'rentEpoch': 0, 'space': 0}}
        if method == 'getBlocks':
            return chain.slots(params[0], params[1] if len(params) > 1 and type(params[1]) is int else chain.target)
        if method == 'getBlocksWithLimit':
            return chain.slots(params[0], chain.target)[:params[1]]
        if method == 'getBlock':
            if not chain.produced(params[0]):
                raise LookupError
            if node.latency:
                time.sleep(node.latency)
            return chain.block(params[0], (params[1] if len(params) > 1 else {}).get('transactionDetails', 'full') == 'full')
        raise ValueError('method outside the read-only stand-in')

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        try:
            with self.server.node.lock:
                self.server.node.calls[request.get('method')] = self.server.node.calls.get(request.get('method'), 0) + 1
            body = {'jsonrpc': '2.0', 'id': request.get('id'), 'result': self.answer(request.get('method'), request.get('params') or [])}
        except LookupError:
            body = {'jsonrpc': '2.0', 'id': request.get('id'),
                    'error': {'code': -32009, 'message': 'Slot was skipped, or missing in long-term storage'}}
        except (ValueError, IndexError, TypeError, AttributeError):
            body = {'jsonrpc': '2.0', 'id': request.get('id'), 'error': {'code': -32601, 'message': 'Method not found'}}
        data = json.dumps(body, separators=(',', ':')).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Node:
    """Loopback stand-in for a node's read-only JSON-RPC. `latency` delays every getBlock; `rate`
    is the finalized blocks a second that getBlockHeight reports on top of the fixed chain."""

    def __init__(self, chain, latency=0.0, rate=5.0):
        self.chain, self.latency, self.rate = chain, latency, rate
        self.calls, self.lock = {}, threading.Lock()
        self.gain, self.at = 0.0, time.monotonic()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), NodeHandler)
        self.server.daemon_threads, self.server.node = True, self
        self.peer = '127.0.0.1:%d' % self.server.server_port
        self.url = 'http://' + self.peer
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        self.thread.start()

    def advanced(self):
        with self.lock:
            now = time.monotonic()
            self.gain += (now - self.at) * self.rate
            self.at = now
            return int(self.gain)

    def stop(self):
        if self.thread is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=10)
            self.thread = None
        return dict(self.calls)


class Quick(threading.Event):
    """Waits that give a time are cut short; rates are still measured against the real clock."""

    def wait(self, timeout=None):
        return super().wait(None if timeout is None else min(timeout, 0.05))


class Installation:
    """What the program is configured with, laid out in one temporary directory: copies of the
    pinned modules and of the cohort service, a public profile, a ready record, the stand-in
    collector behind a launcher, and the empty store root. The store sits under var/lib/... of
    that directory because the cohort service names one fixed absolute directory, and
    serve-check compares the two (with the temporary directory as --rehearsal-root)."""

    def __init__(self, base, chain, node):
        self.base, self.chain = Path(base).resolve(), chain
        self.tools = self.base / 'tools'
        self.tools.mkdir()
        for name in PINNED + ('native_cohort_service.py',):
            shutil.copyfile(TOOLS / name, self.tools / name)
            os.chmod(self.tools / name, 0o644)
        self.wired = self.tools / 'native_cohort_service.py'
        self.profile = self.base / 'operator.json'
        self.profile.write_text(json.dumps({
            'format': 'native-gateway-operator-fixture-v1', 'fixture_keys_are_public': True,
            'network': chain.network['network'], 'genesis_hash': chain.network['genesis_hash'],
            'pool': chain.pool, 'pool_format': 'NPOOL004', 'recipient_withdrawals': True}))
        self.ready = self.base / 'ready.json'
        self.attach(node, 'one')
        self.root = self.base / 'var/lib/zolana-first-sync-mirror'
        self.fresh_root()
        self.collector = self.launcher('collector', 'exec "%s" -B "%s" "$@"' % (
            sys.executable, TOOLS / 'fixtures/first_sync_collector_stand_in.py'))
        self.failing = self.launcher('failing-collector', 'echo refused >&2\nexit 1')
        self.published = self.root / 'recovery-history-mirror'

    def launcher(self, name, body):
        path = self.base / name
        path.write_text('#!/bin/sh\n' + body + '\n')
        path.chmod(0o755)
        return path

    def attach(self, node, generation):
        self.ready.write_text(json.dumps({'network': self.chain.network, 'pool_format': 'NPOOL004',
                                          'generation': generation, 'peers': [{'rpc': node.peer}]}))

    def fresh_root(self):
        self.root.mkdir(parents=True, mode=0o700)
        os.chmod(self.root, 0o700)

    def config(self, collector=None, **changes):
        collector = collector or self.collector
        value = {'format': program.FORMAT, 'root': str(self.root), 'collector': str(collector), 'collector_sha256': sha(collector),
                 'retention_module': str(self.tools / 'history_retention.py'),
                 'retention_module_sha256': sha(self.tools / 'history_retention.py'),
                 'codec_module': str(self.tools / 'gateway_history_codec.py'),
                 'codec_module_sha256': sha(self.tools / 'gateway_history_codec.py'),
                 'history_module': str(self.tools / 'gateway_history.py'),
                 'history_module_sha256': sha(self.tools / 'gateway_history.py'),
                 'profile': str(self.profile), 'profile_sha256': sha(self.profile), 'ready': str(self.ready),
                 'interval_seconds': 30, 'collection_timeout_seconds': 120, 'minimum_free_bytes': 2 * 1024 ** 3,
                 'store_budget_bytes': 256 * 1024 ** 2, 'withdraw_after_failures': 2, 'collector_threads': 2,
                 'pace_percent': 100, 'paced_above_slots': 10 ** 9, 'sample_seconds': 1}
        value.update(changes)
        path = self.base / ('config-%d.json' % time.monotonic_ns())
        path.write_text(json.dumps(value))
        return path

    def mirror(self, **changes):
        """The program's own object. It loads the pinned modules under their real names, so the
        caller keeps sys.modules as it was (see CollectionTests.setUp)."""
        path = self.config(**changes)
        config = program.load_config(path, sha(path), mine)
        return program.Mirror(config, program.load_modules(config, mine), mine)

    def status(self):
        return json.loads((self.root / 'status.json').read_bytes())


def good_config():
    value = {'format': program.FORMAT, 'root': '/var/lib/x', 'collector': '/opt/x/bin/native-wallet', 'ready': '/run/x/ready.json',
             'retention_module': '/opt/x/tools/history_retention.py', 'codec_module': '/opt/x/tools/gateway_history_codec.py',
             'history_module': '/opt/x/tools/gateway_history.py', 'profile': '/etc/x/operator.json',
             'interval_seconds': 300, 'collection_timeout_seconds': 7200, 'minimum_free_bytes': 4 * 1024 ** 3,
             'store_budget_bytes': 256 * 1024 ** 2, 'withdraw_after_failures': 5, 'collector_threads': 2,
             'pace_percent': 50, 'paced_above_slots': 5000, 'sample_seconds': 10}
    value.update({key: 'a' * 64 for key in program.PINS})
    return value


class ConfigurationTests(unittest.TestCase):
    def test_only_the_exact_bounded_configuration_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'config.json'

            def load(value):
                path.write_text(json.dumps(value))
                return program.load_config(path, sha(path), mine)
            good = good_config()
            self.assertEqual(load(good), good)
            for key, value in (('interval_seconds', 5), ('collection_timeout_seconds', 10), ('root', 'relative'),
                               ('collector_sha256', 'A' * 64), ('store_budget_bytes', 1024), ('minimum_free_bytes', 1),
                               ('withdraw_after_failures', 1), ('collector_threads', 0), ('format', 'other'),
                               ('pace_percent', 1), ('pace_percent', 101), ('pace_percent', 50.0), ('sample_seconds', 0),
                               ('paced_above_slots', 1)):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    load(dict(good, **{key: value}))
            with self.assertRaises(ValueError):
                load(dict(good, extra=1))
            path.write_text(json.dumps(good))
            with self.assertRaises(ValueError):
                program.load_config(path, 'd' * 64, mine)

    def test_pinned_reader_refuses_files_another_user_could_write_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'config.json'
            path.write_text('{}')
            self.assertEqual(mine(path, 100), b'{}')
            if os.geteuid() != 0:
                with self.assertRaises(ValueError):
                    program.reader(0)(path, 100)             # as installed: only root-owned files are read
            with self.assertRaises(ValueError):
                mine(path, 1)                                # larger than its bound
            with self.assertRaises(ValueError):
                mine(path, 100, 'd' * 64)                    # not the pinned content
            os.chmod(path, 0o664)
            with self.assertRaises(ValueError):
                mine(path, 100)
            os.chmod(path, 0o644)
            link = path.with_name('link.json')
            link.symlink_to(path)
            with self.assertRaises((ValueError, OSError)):
                mine(link, 100)

    def test_ready_record_must_name_this_network_and_a_loopback_peer(self):
        network = {'network': [7] * 32, 'genesis_hash': '1' * 32}
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / 'ready.json'
            with self.assertRaises(program.Blocked) as missing:
                program.node_endpoint(ready, network)
            self.assertEqual((missing.exception.code, missing.exception.refuted), ('chain_not_running', False))
            good = {'network': network, 'pool_format': 'NPOOL004', 'generation': 'g', 'peers': [{'rpc': '127.0.0.1:4113'}]}
            ready.write_text(json.dumps(good))
            self.assertEqual(program.node_endpoint(ready, network), ('127.0.0.1:4113', 'g'))
            for change in ({'peers': [{'rpc': '10.0.0.1:4113'}]}, {'peers': [{'rpc': '127.0.0.1:4113/x'}]}, {'peers': []},
                           {'pool_format': 'NPOOL003'}, {'network': dict(network, genesis_hash='2' * 32)}):
                ready.write_text(json.dumps(dict(good, **change)))
                with self.subTest(change=change), self.assertRaises(program.Blocked) as differs:
                    program.node_endpoint(ready, network)
                self.assertEqual((differs.exception.code, differs.exception.refuted), ('ready_record_differs', False))


class ForwarderTests(unittest.TestCase):
    def setUp(self):
        self.node = Node(Chain(), latency=0.040)
        self.addCleanup(self.node.stop)
        self.forwarder = program.Forwarder(self.node.peer, 50)
        self.addCleanup(lambda: self.forwarder.connection and self.forwarder.connection.close())
        self.addCleanup(self.forwarder.server_close)
        self.addCleanup(self.forwarder.shutdown)
        threading.Thread(target=self.forwarder.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True).start()

    def post(self, body):
        connection = http.client.HTTPConnection('127.0.0.1', self.forwarder.server_port, timeout=20)
        try:
            connection.request('POST', '/', json.dumps(body), {'Content-Type': 'application/json'})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def block(self, slot):
        return self.post({'jsonrpc': '2.0', 'id': slot, 'method': 'getBlock', 'params': [slot, {'transactionDetails': 'full'}]})

    def test_only_reads_reach_the_node_and_everything_else_is_answered_here(self):
        for method in ('sendTransaction', 'requestAirdrop', 'simulateTransaction', 'getProgramAccounts', 'getTransaction'):
            status, reply = self.post({'jsonrpc': '2.0', 'id': 7, 'method': method, 'params': []})
            self.assertEqual((status, reply['id'], reply['error']['code']), (200, 7, -32601))
        status, reply = self.post([{'jsonrpc': '2.0', 'id': 1, 'method': 'getSlot'}])      # a batch is not a read
        self.assertEqual(reply['error']['code'], -32601)
        status, reply = self.post({'jsonrpc': '2.0', 'id': 3, 'method': 'getSlot', 'params': []})
        self.assertEqual((status, reply['id'], type(reply['result'])), (200, 3, int))
        self.assertEqual(self.block(5)[1]['result']['parentSlot'], 4)
        self.assertEqual(self.forwarder.refused, {'sendTransaction': 1, 'requestAirdrop': 1, 'simulateTransaction': 1,
                                                  'getProgramAccounts': 1, 'getTransaction': 1, 'other': 1})
        self.assertEqual((self.forwarder.requests, self.forwarder.blocks), (2, 1))
        self.assertEqual(self.node.stop(), {'getSlot': 1, 'getBlock': 1})

    def test_one_request_at_a_time_and_a_rest_after_each_when_paced(self):
        began = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            replies = list(pool.map(self.block, (1, 2, 3, 4)))
        unpaced = time.monotonic() - began
        self.assertTrue(all(status == 200 for status, _ in replies))
        self.assertGreaterEqual(unpaced, 4 * 0.040)            # four reads of 40 ms each, never side by side
        self.forwarder.paced = True
        began = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(4) as pool:
            list(pool.map(self.block, (5, 6, 7, 8)))
        paced = time.monotonic() - began
        self.assertGreaterEqual(paced, 7 * 0.040)              # at 50 %: a rest as long as each read (the last rest is not waited for)
        self.forwarder.pace_percent = 10
        began = time.monotonic()
        self.block(9), self.block(10)
        self.assertGreaterEqual(time.monotonic() - began, 0.040 * 10)


class CollectionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        # The program loads its pinned modules under their real names; other suites in the same
        # run must find the modules they imported, so the table is put back after every case.
        modules = mock.patch.dict(sys.modules)
        modules.start()
        self.addCleanup(modules.stop)
        self.chain = Chain()
        self.node = Node(self.chain)
        self.addCleanup(lambda: self.node.stop())
        self.site = Installation(temporary.name, self.chain, self.node)
        self.base, self.root, self.published = self.site.base, self.site.root, self.site.published
        self.target, self.blocks = self.chain.target, self.chain.blocks

    def rewrite_segment(self, index, change):
        """Replace one published segment by a changed one with a correct checksum and manifest."""
        manifest = json.loads((self.published / 'manifest.json').read_bytes())
        descriptor = manifest['segments'][index]
        blocks = json.loads((self.published / ('segment-%08d-%s.json' % (index, descriptor['digest']))).read_bytes())
        change(blocks)
        data = json.dumps(blocks, separators=(',', ':')).encode()
        descriptor['digest'] = hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest()
        target = self.published / ('segment-%08d-%s.json' % (index, descriptor['digest']))
        target.write_bytes(data)
        os.chmod(target, 0o600)
        (self.published / 'manifest.json').write_bytes(json.dumps(manifest, separators=(',', ':')).encode())

    def test_collection_publishes_verifies_and_repeats_without_change(self):
        mirror = self.site.mirror()
        first = mirror.attempt()
        self.assertEqual((first['phase'], first['retained_tip'], first['lag_slots'], first['blocks_read']),
                         ('ready', self.target, 0, self.blocks))
        self.assertEqual((first['refused_methods'], first['withdrawn'], first['segments']), ({}, False, 2))
        published = (self.published / 'manifest.json').read_bytes()
        self.assertEqual(published, (self.root / 'recovery-history/manifest.json').read_bytes())
        for entry in self.root.rglob('*'):
            self.assertEqual(entry.lstat().st_mode & 0o077, 0, entry.name)
        seen = mirror.verify(True)
        self.assertEqual((seen['blocks'], seen['tip_slot'], seen['tip_matches_node']), (self.blocks, self.target, True))
        self.assertEqual(seen['payment_transactions'], len(self.chain.carrying))
        self.assertGreaterEqual(seen['sampled_blocks_match_node'], 60)
        second = self.site.mirror().attempt()
        self.assertEqual((second['phase'], second['new_blocks'], second['retained_tip']), ('ready', 0, self.target))
        self.assertEqual((self.published / 'manifest.json').read_bytes(), published)
        self.assertEqual(set(self.node.stop()), {'getGenesisHash', 'getBlocks', 'getBlock', 'getSlot',
                                                 'getFirstAvailableBlock', 'getBlockHeight'})

    def test_gateway_reader_and_the_wired_class_serve_first_and_last_page(self):
        mirror = self.site.mirror()
        self.assertIsNotNone(mirror.attempt())
        plain = mirror.serve_check(None, mine, '')
        self.assertEqual((plain['wired'], plain['reader'], plain['retained_tip']), (False, 'gateway_history.History', self.target))
        with self.assertRaises(ValueError):
            mirror.serve_check(self.site.wired, mine, '')       # wired to its fixed directory, not to this copy
        prefix = str(self.base)
        wired = mirror.serve_check(self.site.wired, mine, prefix)
        self.assertEqual((wired['wired'], wired['reader'], wired['first_page_blocks']), (True, 'RetainedFirstSync', self.blocks))
        self.assertEqual(wired['wiring_sha256'], sha(self.site.wired))
        with self.assertRaises(ValueError):
            mirror.serve_check(self.site.tools / 'history_retention.py', mine, prefix)      # a file without the class
        (self.published / 'manifest.json').rename(self.published / 'withdrawn-manifest-1.json')
        with self.assertRaises(ValueError):
            mirror.serve_check(self.site.wired, mine, prefix)
        with self.assertRaises(ValueError):
            mirror.verify(False)

    def test_an_earlier_store_is_copied_unpublished_and_verified_by_the_next_collection(self):
        self.assertIsNotNone(self.site.mirror().attempt())
        earlier = self.base / 'earlier'
        os.rename(self.root, earlier)
        self.site.fresh_root()
        kept = (earlier / 'recovery-history/manifest.json').read_bytes()
        mirror = self.site.mirror()
        adopted = mirror.adopt(str(earlier / 'recovery-history'))
        self.assertEqual((adopted['blocks'], adopted['tip_slot'], adopted['published']), (self.blocks, self.target, False))
        self.assertFalse((self.published / 'manifest.json').exists())
        with self.assertRaises(ValueError):
            mirror.adopt(str(earlier / 'recovery-history'))                     # never over existing history
        status = mirror.attempt()
        self.assertEqual((status['phase'], status['new_blocks'], status['blocks_read'], status['retained_tip']),
                         ('ready', 0, 0, self.target))
        seen = mirror.verify(True)
        self.assertTrue(seen['tip_matches_node'])
        self.assertGreaterEqual(seen['sampled_blocks_match_node'], 60)
        self.assertEqual((earlier / 'recovery-history/manifest.json').read_bytes(), kept)
        segment = sorted((earlier / 'recovery-history').glob('segment-*'))[1]
        data = bytearray(segment.read_bytes())
        data[100] ^= 1
        segment.write_bytes(bytes(data))
        os.rename(self.root, self.base / 'second')
        self.site.fresh_root()
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.site.mirror().adopt(str(earlier / 'recovery-history'))
        self.assertFalse((self.root / 'recovery-history/manifest.json').exists())

    def test_a_retained_block_that_differs_from_the_node_is_found_by_the_spread_comparison(self):
        mirror = self.site.mirror()
        self.assertIsNotNone(mirror.attempt())
        index = (self.blocks // 64) * 5                       # one of the compared positions

        def change(blocks):
            blocks[index]['blockhash'] = blocks[index + 1]['previous_blockhash'] = blocks[0]['blockhash']
        self.rewrite_segment(0, change)
        self.assertEqual(mirror.verify(False)['blocks'], self.blocks)           # links and checksums still hold
        with self.assertRaisesRegex(ValueError, 'differs from the node'):
            mirror.verify(True)

    def test_a_mirror_that_ends_on_another_block_than_the_node_is_not_verified(self):
        mirror = self.site.mirror()
        self.assertIsNotNone(mirror.attempt())

        def change(blocks):
            blocks[-1]['blockhash'] = blocks[-2]['blockhash']
        self.rewrite_segment(1, change)
        self.assertEqual(mirror.verify(False)['blocks'], self.blocks)           # self-consistent offline
        with self.assertRaisesRegex(ValueError, 'the node does not have'):
            mirror.verify(True)

    def test_stopped_chain_or_unreachable_node_waits_and_keeps_the_mirror(self):
        mirror = self.site.mirror()
        self.assertIsNotNone(mirror.attempt())
        published = (self.published / 'manifest.json').read_bytes()
        self.site.ready.rename(self.site.ready.with_name('ready.gone'))
        for _ in range(4):
            self.assertIsNone(mirror.attempt())
        self.assertEqual((self.site.status()['phase'], self.site.status()['error']), ('waiting', 'chain_not_running'))
        self.site.ready.with_name('ready.gone').rename(self.site.ready)
        self.node.stop()
        for _ in range(4):
            self.assertIsNone(mirror.attempt())
        status = self.site.status()
        self.assertEqual((status['phase'], status['error'], status['consecutive_failures']), ('waiting', 'node_unavailable', 0))
        self.assertFalse(status['withdrawn'])
        self.assertEqual((self.published / 'manifest.json').read_bytes(), published)

    def test_a_store_at_its_budget_stops_growing_and_stays_published(self):
        self.assertIsNotNone(self.site.mirror().attempt())
        published = (self.published / 'manifest.json').read_bytes()
        full = self.site.mirror(store_budget_bytes=32 * 1024 * 1024)            # no room left for one more segment
        for _ in range(3):
            self.assertIsNone(full.attempt())
        status = self.site.status()
        self.assertEqual((status['phase'], status['error'], status['consecutive_failures']), ('waiting', 'store_budget', 0))
        self.assertEqual((status['withdrawn'], status['retained_tip']), (False, self.target))
        self.assertEqual((self.published / 'manifest.json').read_bytes(), published)

    @unittest.skipIf(os.geteuid() == 0, 'the program refuses to collect as root')
    def test_run_leaves_with_status_75_when_the_chain_is_not_there(self):
        path = self.site.config()
        self.site.ready.unlink()
        for number in (signal.SIGTERM, signal.SIGINT):                          # main() installs its own handlers
            self.addCleanup(signal.signal, number, signal.getsignal(number) or signal.SIG_DFL)
        with mock.patch.object(threading, 'Event', Quick):
            code = program.main(['run', '--config', str(path), '--config-sha256', sha(path), '--rehearsal-root', str(self.base)])
        self.assertEqual(code, program.EXIT_CHAIN_DOWN)
        self.assertEqual((self.site.status()['phase'], self.site.status()['error']), ('stopped', 'chain_not_running'))
        self.assertFalse((self.published / 'manifest.json').exists())

    def test_repeated_refuted_collections_set_the_manifest_aside_and_a_verified_one_restores_it(self):
        self.assertIsNotNone(self.site.mirror().attempt())
        published = (self.published / 'manifest.json').read_bytes()
        segments = sorted(p.name for p in self.published.glob('segment-*'))
        failing = self.site.mirror(collector=self.site.failing)
        self.assertIsNone(failing.attempt())
        self.assertTrue((self.published / 'manifest.json').exists())
        self.assertEqual((self.site.status()['phase'], self.site.status()['error']), ('blocked', 'collection_failed'))
        self.assertIsNone(failing.attempt())
        self.assertFalse((self.published / 'manifest.json').exists())
        aside = list(self.published.glob('withdrawn-manifest-*.json'))
        self.assertEqual([p.read_bytes() for p in aside], [published])
        self.assertEqual(sorted(p.name for p in self.published.glob('segment-*')), segments)
        self.assertTrue(self.site.status()['withdrawn'])
        self.assertIn('refused', json.loads((self.root / 'collector-error.json').read_bytes())['stderr'])
        restored = self.site.mirror().attempt()
        self.assertEqual((restored['phase'], restored['withdrawn']), ('ready', False))
        self.assertEqual((self.published / 'manifest.json').read_bytes(), published)

    def test_a_node_that_is_behind_or_on_another_chain_than_the_store_gets_the_manifest_set_aside(self):
        self.assertIsNotNone(self.site.mirror().attempt())
        published = (self.published / 'manifest.json').read_bytes()
        for name, other in (('behind', Chain(target=600)), ('another', Chain(rule=b'restored-chain'))):
            with self.subTest(node=name):
                # Same network identity in the ready record; only the node's history differs.
                other.network = self.chain.network
                self.node.stop()
                self.node = Node(other)
                self.site.attach(self.node, name)
                mirror = self.site.mirror()
                self.assertIsNone(mirror.attempt())
                self.assertEqual(self.site.status()['phase'], 'blocked')
                self.assertTrue((self.published / 'manifest.json').exists())
                self.assertIsNone(mirror.attempt())
                self.assertFalse((self.published / 'manifest.json').exists())
                self.assertTrue(self.site.status()['withdrawn'])
                # Back on the chain the store was made from: verified again and published again.
                self.node.stop()
                self.node = Node(self.chain)
                self.site.attach(self.node, 'original')
                restored = self.site.mirror().attempt()
                self.assertEqual((restored['phase'], restored['withdrawn']), ('ready', False))
                self.assertEqual((self.published / 'manifest.json').read_bytes(), published)

    def test_catch_up_is_paced_watched_and_given_up_when_the_chain_stays_slow(self):
        self.node.stop()
        self.node = Node(self.chain, latency=0.002, rate=2000.0)
        self.site.attach(self.node, 'two')
        seen = []

        def announce(status):
            seen.append(status['phase'])
            if status['phase'] == 'collecting':
                self.node.rate = 100.0                       # one twentieth of the rate measured before
        # sample_seconds is 60 so that one slow sample at the smallest pace is the full minute the
        # program waits for; every wait is cut to 50 ms and rates use the real clock.
        with mock.patch.object(threading, 'Event', Quick):
            mirror = self.site.mirror(pace_percent=50, paced_above_slots=256, sample_seconds=60)
            mirror.announce = announce
            self.assertIsNone(mirror.attempt())
        status = self.site.status()
        self.assertEqual((status['phase'], status['error'], status['pace_percent']),
                         ('waiting', 'chain_slow', program.SMALLEST_PACE))
        self.assertGreaterEqual(status['pace_reductions'], 4)
        self.assertLess(status['blocks_read'], self.blocks)
        self.assertEqual(seen[0], 'measuring-chain')
        self.assertFalse((self.published / 'manifest.json').exists())
        self.assertEqual((status['withdrawn'], status['consecutive_failures']), (False, 0))


if __name__ == '__main__':
    unittest.main()
