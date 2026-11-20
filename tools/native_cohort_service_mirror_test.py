"""The optional first-sync mirror behind the cohort gateway. Loopback only.

Every request goes through the real request handler and the real Gateway class, built with
the arguments gateway() gives it (bulk authorization and the compact page charge) and given
the service's RetainedFirstSync over a directory in a temporary folder. Stand-ins: the node
(a fixed public chain, see first_sync_mirror_test), the admission ledger (one known member,
every debit recorded) and the collector binary that fills the small store (see
fixtures/first_sync_collector_stand_in.py). The store is published by the real
history_retention.capture() and read by the real gateway_history.History.

What is shown: with no store the gateway answers and charges every read as it did before
the mirror was wired; a first retained page then answers "no mirror" (a null result), which
sends a wallet down the block-by-block path; a small valid store is served and charged at
the compact rate; a store that appears, is set aside or comes back is followed without a
restart; a store that cannot be read is answered as no mirror; and a page that continues a
sync already under way is refused rather than answered from anything else.
"""
import base64
import http.client
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from first_sync_mirror_test import Chain, Node
from gateway_history import History
from gateway_history_codec import unpack_blocks
from history_retention import capture
import native_cohort_service as service
import testnet_gateway

COLLECTOR = Path(__file__).resolve().parent / 'fixtures/first_sync_collector_stand_in.py'
PROOF = {'signature': 'stand-in member'}
ACCESS = base64.urlsafe_b64encode(json.dumps(PROOF).encode()).decode().rstrip('=')
FINALIZED = {'commitment': 'finalized'}
HEADER = {'transactionDetails': 'none', 'rewards': False, 'commitment': 'finalized'}


class Admission:
    """Stand-in for the admission ledger: one known member, every debit recorded."""

    def __init__(self, root, network):
        self.root, self.network = root, network
        self.debits, self.lock = [], threading.Lock()

    def ingress(self, channel, peer, units=1):
        pass

    def command(self, command, proof=None, extra=()):
        if command == 'access-info':
            return {'invite_required': True, 'rpc_audience': 'https://127.0.0.1:1', 'network': self.network}
        if proof != PROOF:
            raise ValueError('invitation required')
        if command == 'authorize':
            units = 1
        elif command == 'authorize-many' and len(extra) == 2 and extra[0] == '--units':
            units = int(extra[1])
        else:
            raise ValueError('command outside the stand-in')
        with self.lock:
            self.debits.append(units)
        return {'authorized': True, 'units': units} if command == 'authorize-many' else {'authorized': True}


class MirrorWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name).resolve()          # the store reader insists on real paths
        os.chmod(cls.work, 0o700)
        cls.chain = Chain()
        cls.target, cls.network = cls.chain.target, cls.chain.network
        cls.node = Node(cls.chain, rate=0.0)               # a height that stands still: answers can be compared
        cls.addClassCleanup(cls.node.stop)
        profile = cls.work / 'network.json'
        profile.write_text(json.dumps(cls.network))
        cls.primary = cls.work / 'recovery-history'
        cls.primary.mkdir(mode=0o700)
        done = subprocess.run([sys.executable, '-B', str(COLLECTOR), 'archive', '--network', str(profile),
                               '--rpc', cls.node.url, '--history', str(cls.primary)],
                              capture_output=True, text=True, timeout=120)
        assert done.returncode == 0, done.stderr[-600:]
        cls.store = cls.publish('present')
        cls.number = 0

    @classmethod
    def publish(cls, name):
        """A store as the collector program publishes it: one captured manifest and its segments."""
        target = cls.work / name / 'recovery-history-mirror'
        target.parent.mkdir(mode=0o700, exist_ok=True)
        capture(cls.primary, target, cls.network)
        return target

    def gateway(self, history=None, per_unit=256):
        """The real Gateway behind the real handler; `history` None is the gateway before the wiring."""
        type(self).number += 1
        root = self.work / ('gateway-%d' % self.number)
        root.mkdir()
        (root / 'profile.json').write_text(json.dumps({'pool': self.chain.pool, 'rpc': {'url': self.node.url}}))
        (root / 'claims.json').write_text(json.dumps({'policy': {}}))
        ledger = Admission(root, self.network)
        app = testnet_gateway.Gateway(ledger, authorize_many=True, compact_headers_per_unit=per_unit)
        if history is not None:
            app.history = history
        server = ThreadingHTTPServer(('127.0.0.1', 0), testnet_gateway.Handler)
        server.daemon_threads = True
        server.authority, server.app = '127.0.0.1:%d' % server.server_port, app
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 10)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def wired(self, directory, retry=30):
        """As gateway() wires it, over `directory` instead of the service's fixed one."""
        server = self.gateway()
        server.app.history = service.RetainedFirstSync(directory, server.app.info['network'], retry=retry)
        return server

    def call(self, server, method, params=None, proof=True, identifier=7):
        body = json.dumps({'jsonrpc': '2.0', 'id': identifier, 'method': method,
                           **({} if params is None else {'params': params})}).encode()
        headers = {'Host': server.authority, 'Content-Type': 'application/json', 'Content-Length': str(len(body))}
        if proof:
            headers['X-Testnet-Access'] = ACCESS
        connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=60)
        try:
            connection.request('POST', '/', body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def result(self, server, method, params):
        status, body = self.call(server, method, params)
        self.assertEqual(status, 200, body[:200])
        return json.loads(body)['result']

    def refused(self, server, method, params):
        status, body = self.call(server, method, params)
        self.assertEqual((status, json.loads(body)), (403, {'error': 'access_denied'}))

    def canonical(self):
        """Every kind of read a wallet makes that is answered from the node."""
        chain = self.chain
        pool = [chain.pool, {'commitment': 'finalized', 'encoding': 'base64'}]
        return [('getGenesisHash', None, False), ('getGenesisHash', [], True),
                ('getSlot', [FINALIZED], True), ('getBlockHeight', [FINALIZED], True),
                ('getAccountInfo', pool, True), ('getBlocks', [1, 400, FINALIZED], True),
                ('getBlock', [self.target, HEADER], True),
                ('getWalletReadBatch', [[{'method': 'getSlot', 'params': [FINALIZED]},
                                         {'method': 'getAccountInfo', 'params': [chain.pool, {'commitment': 'confirmed', 'encoding': 'base64'}]}]], True),
                ('getWalletHistoryBlocks', [chain.slots(1, 16)], True),
                ('getWalletHistoryBlocks', [chain.slots(17, 272)], True),
                ('getWalletHistoryBlocks', [chain.slots(self.target - 30, self.target)], True),
                ('getWalletSyncSnapshot', [0], True),
                ('getWalletSyncSnapshot', [chain.slots(1, self.target - 30)[-1]], True),
                ('getWalletCanonicalHistory', [0, self.target, None], True),
                ('getSlot', [FINALIZED], False)]

    def retained(self, token=None):
        return [('getWalletRetainedHistory', [0, self.target, token]), ('getWalletRetainedHistoryV2', [0, self.target, token]),
                ('getWalletRetainedHistoryV3', [0, self.target, token]), ('getWalletRetainedHistoryV3', [0, self.target, token, 32768])]

    def test_with_no_store_every_read_is_answered_and_charged_as_before_the_wiring(self):
        before = self.gateway(per_unit=16)                 # no retained source and the default charge
        absent = self.work / 'absent' / 'recovery-history-mirror'
        wired = self.wired(absent)
        answered, snapshots = 0, []
        for method, params, proof in self.canonical():
            first, second = self.call(before, method, params, proof), self.call(wired, method, params, proof)
            self.assertEqual(first, second, method)
            answered += first[0] == 200 and b'"result"' in first[1]
            if method == 'getWalletSyncSnapshot':
                snapshots.append(json.loads(second[1])['result'])
        self.assertEqual(answered, len(self.canonical()) - 1)   # all but the read without a proof
        self.assertEqual((snapshots[0]['fallback'], snapshots[0]['canonical_tail']), ('tail-too-large', None))
        self.assertEqual((snapshots[1]['canonical_tail']['complete'], len(snapshots[1]['canonical_tail']['blocks'])), (True, 30))
        for method, params in self.retained():
            first, second = self.call(before, method, params), self.call(wired, method, params)
            self.assertEqual(first, second, method)
        self.assertEqual(before.app.faucet.debits, wired.app.faucet.debits)       # the same charge for every request
        self.assertGreater(sum(wired.app.faucet.debits), 60)
        self.assertIsNone(wired.app.history.inner)
        self.assertFalse(absent.parent.exists())           # nothing is created where a store would be

    def test_a_first_retained_page_without_a_store_answers_no_mirror(self):
        wired = self.wired(self.work / 'none' / 'recovery-history-mirror')
        for method, params in self.retained():
            status, body = self.call(wired, method, params)
            self.assertEqual((status, json.loads(body)), (200, {'jsonrpc': '2.0', 'id': 7, 'result': None}), method)
        self.assertEqual(wired.app.faucet.debits, [1, 1, 1, 1])
        # Without a proof nothing is said about a mirror at all.
        self.assertEqual(self.call(wired, 'getWalletRetainedHistoryV3', [0, self.target, None], proof=False)[0], 403)
        # A page that continues a sync has no mirror to continue from: refused, never answered as "no mirror".
        token = {'segments': 1, 'sha256': '0' * 64}
        for method, params in self.retained(token):
            self.refused(wired, method, params)
        self.assertIsNone(self.result(wired, 'getWalletRetainedHistoryV3', [0, self.target, None]))    # and the gateway goes on

    def test_a_small_valid_store_is_served_and_charged_at_the_compact_rate(self):
        wired = self.wired(self.store)
        plain = self.gateway(History(self.store, self.network))                 # the reader without the class
        default = self.gateway(History(self.store, self.network), per_unit=16)  # and at the default charge
        request = ('getWalletRetainedHistoryV3', [0, self.target, None, 32768])
        status, body = self.call(wired, *request)
        self.assertEqual(status, 200)
        page = json.loads(body)['result']
        self.assertEqual((page['retained_tip'], page['after_slot'], page['next_slot'], page['complete']),
                         (self.target, 0, self.target, True))
        blocks = unpack_blocks(page['compact_headers'], page['transactions'])
        self.assertEqual(len(blocks), self.chain.blocks)
        self.assertEqual([block['slot'] for block in blocks], self.chain.slots(1, self.target))
        self.assertEqual(sum(len(block['transactions']) for block in blocks), len(self.chain.carrying))
        self.assertEqual(blocks[-1]['blockhash'], self.chain.hash(self.target))
        self.assertEqual((status, body), self.call(plain, *request))            # byte for byte the reader's own page
        units = max(1, (self.chain.blocks + 255) // 256, (len(body) + 65535) // 65536)
        self.assertEqual(wired.app.faucet.debits, [1, units - 1])
        self.assertEqual(sum(wired.app.faucet.debits), sum(plain.app.faucet.debits))
        self.call(default, *request)
        self.assertEqual(sum(default.app.faucet.debits), (self.chain.blocks + 15) // 16)
        self.assertLess(units * 8, sum(default.app.faucet.debits))
        # The same sync goes on with the checkpoint it was given.
        partial = self.result(wired, 'getWalletRetainedHistory', [0, self.target, None])
        self.assertEqual((len(partial['blocks']), partial['complete'], partial['checkpoint']), (16, False, page['checkpoint']))
        rest = self.result(wired, 'getWalletRetainedHistoryV3', [partial['next_slot'], self.target, partial['checkpoint'], 32768])
        self.assertEqual((rest['after_slot'], rest['next_slot'], rest['complete']), (partial['next_slot'], self.target, True))
        self.assertEqual(rest['compact_headers']['count'], self.chain.blocks - 16)
        self.assertEqual(len(self.result(wired, 'getWalletRetainedHistoryV2', [0, self.target, None])['blocks']), self.chain.blocks)
        # A checkpoint the store never issued is refused, with or without the class.
        bogus = {'segments': page['checkpoint']['segments'], 'sha256': '0' * 64}
        for server in (wired, plain):
            self.refused(server, 'getWalletRetainedHistoryV3', [0, self.target, bogus])
        # Reads answered from the node are the same beside a store.
        for method, params, proof in self.canonical():
            self.assertEqual(self.call(wired, method, params, proof), self.call(plain, method, params, proof), method)

    def test_a_store_that_appears_after_the_gateway_started_is_served_without_a_restart(self):
        wired = self.wired(self.work / 'late' / 'recovery-history-mirror', retry=0.2)
        first = [0, self.target, None, 32768]
        self.assertIsNone(self.result(wired, 'getWalletRetainedHistoryV3', first))
        self.publish('late')
        deadline, page = time.monotonic() + 20, None
        while page is None and time.monotonic() < deadline:
            time.sleep(0.1)
            page = self.result(wired, 'getWalletRetainedHistoryV3', first)
        self.assertIsInstance(page, dict)
        self.assertEqual((page['retained_tip'], page['complete']), (self.target, True))

    def test_an_absent_store_is_looked_for_again_only_after_the_retry_interval(self):
        directory = self.work / 'interval' / 'recovery-history-mirror'
        history = service.RetainedFirstSync(directory, self.network)
        self.assertEqual(history.retry, 30)
        request = {'jsonrpc': '2.0', 'id': 1, 'params': [0, self.target, None]}
        null = json.dumps({'jsonrpc': '2.0', 'id': 1, 'result': None}).encode()
        self.assertEqual(history.page_compact_counted(request, max_blocks=32768), (null, 0))
        self.publish('interval')
        self.assertEqual(history.page_compact_counted(request, max_blocks=32768), (null, 0))    # inside the interval
        self.assertGreater(history.after, time.monotonic() + 25)
        history.after = time.monotonic()                   # the interval has passed
        raw, count = history.page_compact_counted(request, max_blocks=32768)
        self.assertEqual((count, json.loads(raw)['result']['retained_tip']), (self.chain.blocks, self.target))
        self.assertEqual(history.page(request), History(directory, self.network).page(request))
        self.assertEqual(history.page_counted(request, max_blocks=4096), History(directory, self.network).page_counted(request, max_blocks=4096))

    def test_a_store_that_cannot_be_read_is_answered_as_no_mirror_and_other_reads_go_on(self):
        def garbage(store):
            (store / 'manifest.json').write_text('{not a manifest')

        def another_network(store):
            value = json.loads((store / 'manifest.json').read_bytes())
            value['network'] = dict(value['network'], genesis_hash=self.chain.hash(1))
            (store / 'manifest.json').write_text(json.dumps(value))

        def missing_segment(store):
            sorted(store.glob('segment-*'))[0].unlink()

        def damaged_segment(store):
            segment = sorted(store.glob('segment-*'))[0]
            data = bytearray(segment.read_bytes())
            data[100] ^= 1
            segment.write_bytes(bytes(data))

        def readable_by_others(store):
            os.chmod(store, 0o750)

        def linked_manifest(store):
            (store / 'manifest.json').rename(store / 'kept.json')
            (store / 'manifest.json').symlink_to(store / 'kept.json')

        first = [0, self.target, None, 32768]
        for change in (garbage, another_network, missing_segment, damaged_segment, readable_by_others, linked_manifest):
            with self.subTest(store=change.__name__):
                store = self.publish(change.__name__)
                token = History(store, self.network).page_counted({'id': 1, 'params': [0, self.target, None]})[0]
                token = json.loads(token)['result']['checkpoint']
                change(store)
                wired = self.wired(store)
                for method, params in self.retained():
                    status, body = self.call(wired, method, params)
                    self.assertEqual((status, json.loads(body)), (200, {'jsonrpc': '2.0', 'id': 7, 'result': None}), method)
                self.refused(wired, 'getWalletRetainedHistoryV3', [1024, self.target, token, 32768])
                self.assertEqual(len(self.result(wired, 'getWalletHistoryBlocks', [self.chain.slots(1, 16)])), 16)

    def test_a_store_set_aside_or_damaged_while_open_answers_no_mirror_until_it_is_whole_again(self):
        store = self.publish('open')
        wired = self.wired(store)
        first = [0, self.target, None, 32768]
        page = self.result(wired, 'getWalletRetainedHistoryV3', first)
        self.assertEqual(page['retained_tip'], self.target)
        # What the collector does when it can no longer verify its store against the node.
        (store / 'manifest.json').rename(store / 'withdrawn-manifest-1.json')
        self.assertIsNone(self.result(wired, 'getWalletRetainedHistoryV3', first))
        self.refused(wired, 'getWalletRetainedHistoryV3', [1024, self.target, page['checkpoint'], 32768])
        (store / 'withdrawn-manifest-1.json').rename(store / 'manifest.json')
        self.assertEqual(self.result(wired, 'getWalletRetainedHistoryV3', first), page)
        segment = sorted(store.glob('segment-*'))[1]
        data = segment.read_bytes()
        segment.write_bytes(data[:-1])
        self.assertIsNone(self.result(wired, 'getWalletRetainedHistoryV3', first))
        segment.write_bytes(data)
        self.assertEqual(self.result(wired, 'getWalletRetainedHistoryV3', first), page)

    def test_the_service_names_one_fixed_directory_and_a_charge_the_gateway_accepts(self):
        self.assertEqual(service.RETAINED, Path('/var/lib/zolana-first-sync-mirror/recovery-history-mirror'))
        self.assertEqual(testnet_gateway.COMPACT_AUTH_HEADERS, 256)
        source = Path(service.__file__).read_text()
        self.assertEqual(source.count("authorize_many=True,compact_headers_per_unit=256)"), 1)
        self.assertEqual(source.count("app.history=RetainedFirstSync(RETAINED,app.info['network'])"), 1)
        # Nothing is opened or looked for while the gateway is being built, even where a store exists.
        idle = service.RetainedFirstSync(self.store, self.network)
        self.assertEqual((idle.inner, idle.after, idle.root, idle.network), (None, 0.0, self.store, self.network))
        # The compact charge exists only together with bulk authorization.
        with self.assertRaises(ValueError):
            testnet_gateway.Gateway(Admission(self.work, self.network), compact_headers_per_unit=256)


if __name__ == '__main__':
    unittest.main()
