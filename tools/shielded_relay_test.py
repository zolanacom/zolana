import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from shielded_relay import Relay, packet, private, save


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = dict(format='native-shielded-relay-v1', network=dict(network=[7]*32, genesis_hash='pinned'),
            network_file='/fixed/network.json', rpc='http://127.0.0.1:18899', payer=[8]*32,
            payer_file='/fixed/key', binary='/fixed/binary', fee=3_000_000, gross_cap=150_000_000,
            max_jobs=4, per_member=2)
        save(self.root / 'config.json', self.config)
        self.relay = Relay(self.root)

    def tearDown(self):
        self.relay.close()
        self.temp.cleanup()

    def value(self, nonce=0):
        raw = bytearray(9230)
        raw[:8] = b'NPAY0003'; raw[8:40] = bytes([7]*32)
        raw[48:56] = (3_000_000).to_bytes(8, 'little'); raw[56:88] = bytes([8]*32)
        raw[88:96] = raw[48:56]; raw[-1] = nonce
        return dict(network=self.config['network'], payload=base64.b64encode(raw).decode())

    def test_packet_shape_fee_payee_network_and_encoding_are_bounded(self):
        good = self.value()
        self.assertEqual(len(packet(good, self.config['network'], [8]*32, 3_000_000)), 64)
        for offset in [0, 8, 48, 56, 88]:
            changed = copy.deepcopy(good); raw = bytearray(base64.b64decode(changed['payload']))
            raw[offset] ^= 1; changed['payload'] = base64.b64encode(raw).decode()
            with self.assertRaises(ValueError): packet(changed, self.config['network'], [8]*32, 3_000_000)
        for changed in [dict(good, extra=True), dict(good, payload='?'), dict(good, payload=good['payload']+'='),
                        dict(good, network={}), dict(good, payload=[]), None]:
            with self.assertRaises(ValueError): packet(changed, self.config['network'], [8]*32, 3_000_000)

    def test_duplicates_concurrency_ownership_and_restart_preserve_lifetime_quota(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            replies = list(pool.map(lambda _: self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice'), range(8)))
        self.assertTrue(all(r == replies[0] for r in replies))
        job_id = replies[0]['id']
        self.assertEqual(len(list(self.relay.jobs.iterdir())), 1)
        for method, params in [('submitShieldedPayment', [self.value()]), ('getShieldedPaymentStatus', [job_id])]:
            with self.assertRaises(ValueError): self.relay.dispatch(method, params, 'bob')
        self.relay.dispatch('submitShieldedPayment', [self.value(1)], 'alice')
        with self.assertRaisesRegex(ValueError, 'quota'): self.relay.dispatch('submitShieldedPayment', [self.value(2)], 'alice')
        save(self.relay.jobs / job_id / 'outcome.json', dict(accepted=True, signature='original'))
        self.relay.close(); self.relay = Relay(self.root)
        self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [job_id], 'alice')['signature'], 'original')
        self.assertEqual(self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice'), replies[0])
        with self.assertRaisesRegex(ValueError, 'quota'): self.relay.dispatch('submitShieldedPayment', [self.value(2)], 'alice')
        self.relay.dispatch('submitShieldedPayment', [self.value(2)], 'bob')
        self.relay.dispatch('submitShieldedPayment', [self.value(3)], 'bob')
        with self.assertRaisesRegex(ValueError, 'quota'): self.relay.dispatch('submitShieldedPayment', [self.value(4)], 'carol')

    def test_partial_publication_is_invisible_and_second_worker_cannot_start(self):
        orphan = self.root / '.relay-orphan'; orphan.mkdir(mode=0o700)
        save(orphan / 'packet.json', self.value())
        self.assertEqual(list(self.relay.jobs.iterdir()), [])
        with self.assertRaises(BlockingIOError): Relay(self.root)
        value = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')
        self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [value['id']], 'alice')['state'], 'pending')

    def test_failed_worker_is_bounded_and_does_not_overwrite_unknown_payment(self):
        job_id = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')['id']
        path = self.relay.jobs / job_id
        save(path / 'tries.json', 3)
        with patch('shielded_relay.subprocess.Popen', side_effect=AssertionError('must not spawn')):
            self.relay.work_once()
        self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [job_id], 'alice')['state'], 'aborted')
        second = self.relay.dispatch('submitShieldedPayment', [self.value(1)], 'alice')['id']
        path = self.relay.jobs / second
        save(path / 'tries.json', 3); save(path / 'relay.pending.json', dict(signature='unknown'))
        class Child:
            returncode = 1
            def wait(self, timeout): pass
        with patch('shielded_relay.subprocess.Popen', return_value=Child()): self.relay.work_once()
        self.assertEqual(json.loads(private(path / 'relay.pending.json')), dict(signature='unknown'))
        self.assertFalse((path / 'outcome.json').exists())

    def test_a_completed_marker_cannot_hide_a_reappearing_pending_journal(self):
        job_id = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')['id']
        path = self.relay.jobs / job_id
        save(path / 'done', True)
        save(path / 'outcome.json', dict(accepted=True, signature='original'))
        save(path / 'relay.pending.json', dict(signature='original'))
        class Child:
            returncode = 0
            def wait(self, timeout):
                (path / 'relay.pending.json').unlink()
        with patch('shielded_relay.subprocess.Popen', return_value=Child()) as spawn:
            self.relay.work_once()
            spawn.assert_called_once()
        self.assertEqual(json.loads(private(path / 'outcome.json'))['signature'], 'original')
        with patch('shielded_relay.subprocess.Popen', side_effect=AssertionError('must stay idle')):
            self.relay.work_once()


if __name__ == '__main__': unittest.main()
