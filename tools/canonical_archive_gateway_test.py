"""Gateway's normal private archive selection and unchanged invited HTTP lane."""
import base64
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from canonical_archive_store import Capture, encoded
from canonical_archive_store_test import NETWORK, blocks, page, target
from canonical_archive_backend import HEADER
from testnet_gateway import Gateway
import testnet_gateway_test as gateway_fixtures
import testnet_gateway


class CanonicalGatewayTests(unittest.TestCase):
    def test_source_conflict_refuses_before_reading_faucet_or_network(self):
        with self.assertRaisesRegex(ValueError, 'one fixed canonical'):
            Gateway(object(), archive_rpc='http://127.0.0.1:1', archive_store=Path('/not-opened'))

    def test_real_constructor_selects_store_and_pages_exact_body(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            store = root / 'canonical.sqlite3'
            items = blocks([1, 2])
            pinned = target(items)
            with Capture(store, NETWORK, NETWORK['genesis_hash'], pinned) as writer:
                writer.append(encoded(page(items, pinned, 0)))
                writer.commit()
            (root / 'profile.json').write_text(json.dumps(dict(rpc=dict(url='http://127.0.0.1:18899'))))
            (root / 'claims.json').write_text(json.dumps(dict(policy={})))
            class Faucet:
                def command(self, name):
                    assert name == 'access-info'
                    return dict(invite_required=True, network=NETWORK, rpc_audience='https://fixture.invalid/')
            faucet = Faucet()
            faucet.root = root
            calls = []
            def forward(_self, raw, timeout=15):
                query = json.loads(raw)
                calls.append(query)
                if query['method'] == 'getGenesisHash':
                    result = NETWORK['genesis_hash']
                else:
                    self.assertEqual(query['method'], 'getBlock')
                    self.assertEqual(query['params'], [2, HEADER])
                    result = {k: v for k, v in items[-1]['block'].items() if k != 'transactions'}
                return encoded(dict(jsonrpc='2.0', id=1, result=result))
            with patch.object(Gateway, 'forward', forward):
                gateway = Gateway(faucet, archive_store=store)
                value = json.loads(gateway.canonical_history(dict(jsonrpc='2.0', id=9,
                    method='getWalletCanonicalHistory', params=[0, 2, None])))['result']
                self.assertEqual(value['blocks'], items)
                self.assertTrue(value['complete'])
                self.assertEqual(value['anchor'], pinned)
            self.assertEqual([q['method'] for q in calls], ['getGenesisHash', 'getBlock'])

    def test_existing_http_lane_denies_before_archive_and_charges_invitation(self):
        fixture = gateway_fixtures.GatewayTests()
        query = dict(jsonrpc='2.0', id=1, method='getWalletCanonicalHistory', params=[0, 2, None])
        code, _, calls = fixture.request(query)
        self.assertEqual(code, 403)
        self.assertFalse(any(c[0] == 'canonical' for c in calls))
        access = base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        code, _, calls = fixture.request(query, access)
        self.assertEqual(code, 200)
        self.assertEqual([c[0] for c in calls], ['ingress', 'authorize', 'canonical'])
        code, _, calls = fixture.request(query, access, authorize_limit=0)
        self.assertEqual(code, 429)
        self.assertFalse(any(c[0] == 'canonical' for c in calls))

    def test_capture_constructor_pins_policy_but_never_starts_worker(self):
        with self.assertRaisesRegex(ValueError, 'fixed private archive store'):
            Gateway(object(), archive_capture_policy={})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            store = root / 'not-yet-created.sqlite3'
            (root / 'profile.json').write_text(json.dumps(dict(rpc=dict(url='http://127.0.0.1:18899'))))
            (root / 'claims.json').write_text(json.dumps(dict(policy={})))
            class Faucet:
                def command(self, name):
                    assert name == 'access-info'
                    return dict(invite_required=True, network=NETWORK, rpc_audience='https://fixture.invalid/')
            faucet = Faucet(); faucet.root = root
            policy = dict(network=NETWORK, max_database_bytes=16*1024**2, min_free_bytes=28*1024**3,
                          batch_blocks=2, max_batches=1, timeout=1, batch_timeout=1, poll_seconds=1)
            def forward(_self, raw, timeout=15):
                self.assertEqual(json.loads(raw)['method'], 'getGenesisHash')
                return encoded(dict(jsonrpc='2.0', id=1, result=NETWORK['genesis_hash']))
            from canonical_archive_runner import RollingCapture
            with patch.object(Gateway, 'forward', forward), patch.object(RollingCapture, 'start') as start:
                gateway = Gateway(faucet, archive_store=store, archive_capture_policy=policy)
                try:
                    self.assertIsInstance(gateway.archive_capture, RollingCapture)
                    status = gateway.archive_capture.snapshotstatus()
                    self.assertEqual(status['phase'], 'new')
                    self.assertFalse(status['thread_alive'])
                    self.assertEqual(status['windows'], 0)
                    self.assertFalse(store.exists())
                    start.assert_not_called()
                finally:
                    gateway.archive_capture.close()

    def test_cli_requires_store_before_faucet_and_no_capture_starts_implicitly(self):
        argv = ['gateway', '--root', '/disposable', '--password-file', '/disposable/no-password', '--archive-capture']
        with patch.object(sys, 'argv', argv), patch.object(testnet_gateway, 'Faucet') as faucet, \
                patch.object(sys, 'stderr', io.StringIO()), self.assertRaises(SystemExit):
            testnet_gateway.main()
        faucet.assert_not_called()

    def test_cli_listener_and_serve_or_capture_close_failure_always_release_faucet(self):
        for mode in ['listener-failure', 'serve-failure', 'capture-close-failure']:
            with self.subTest(mode=mode):
                events = []
                class Resource:
                    def __init__(self, name): self.name = name
                    def start(self): events.append(self.name + '.start')
                    def close(self):
                        events.append(self.name + '.close')
                        if self.name == 'capture' and mode == 'capture-close-failure':
                            raise TimeoutError('disposable capture close')
                class Server:
                    def serve_forever(self):
                        events.append('serve')
                        raise RuntimeError('disposable server failure')
                    def server_close(self): events.append('server.close')
                faucet = Resource('faucet')
                faucet.command = lambda name: dict(network=NETWORK) if name == 'access-info' else None
                app = SimpleNamespace(info=dict(rpc_audience='https://fixture.invalid/'),
                                      relay=Resource('relay'), archive_capture=Resource('capture'))
                def listener(*_args):
                    events.append('listener')
                    if mode == 'listener-failure': raise OSError('disposable listener failure')
                    return Server()
                argv = ['gateway', '--root', '/disposable', '--password-file', '/disposable/no-password',
                        '--archive-store', '/disposable/new.sqlite3', '--archive-capture']
                expected = OSError if mode == 'listener-failure' else TimeoutError if mode == 'capture-close-failure' else RuntimeError
                with patch.object(sys, 'argv', argv), patch.object(testnet_gateway, 'Faucet', return_value=faucet), \
                        patch.object(testnet_gateway, 'Gateway', return_value=app) as constructor, \
                        patch('service_tls.listener', side_effect=listener), self.assertRaises(expected):
                    testnet_gateway.main()
                self.assertEqual(constructor.call_args.kwargs['archive_capture_policy'],
                    dict(network=NETWORK, max_database_bytes=8*1024**3,min_free_bytes=28*1024**3,
                         batch_blocks=16,max_batches=64,timeout=30,batch_timeout=6,poll_seconds=1))
                self.assertEqual(events[-1], 'faucet.close')
                self.assertIn('capture.close', events)
                self.assertIn('relay.close', events)
                if mode == 'listener-failure':
                    self.assertNotIn('relay.start', events)
                    self.assertNotIn('capture.start', events)
                    self.assertNotIn('server.close', events)
                else:
                    self.assertEqual(events[:4], ['listener', 'relay.start', 'capture.start', 'serve'])
                    self.assertEqual(events[-4:], ['capture.close', 'server.close', 'relay.close', 'faucet.close'])


if __name__ == '__main__':
    unittest.main()
