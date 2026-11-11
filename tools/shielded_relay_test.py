import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from shielded_relay import Relay, RelayCapacityError, native_options, packet, private, save, sync_dir


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

    def test_failed_initialization_releases_lock_with_a_retained_exception(self):
        for failure in ('missing', 'malformed', 'invalid-config', 'invalid-jobs', 'invalid-native'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = root / 'config.json'
                if failure != 'missing':
                    value = dict(self.config)
                    if failure == 'invalid-config':
                        value['fee'] = 0
                    if failure == 'invalid-native':
                        value['native_ingress'] = ['127.0.0.1:19001']
                    save(config, value)
                if failure == 'malformed':
                    config.write_text('{')
                if failure == 'invalid-jobs':
                    (root / 'jobs').write_text('disposable invalid directory')
                retained = None
                try:
                    Relay(root)
                except (ValueError, OSError) as error:
                    retained = error
                self.assertIsNotNone(retained)
                # A caller may retain this traceback for diagnostics while it
                # corrects configuration. The failed instance must own no lock.
                save(config, self.config)
                if failure == 'invalid-jobs':
                    (root / 'jobs').rename(root / 'original-invalid-jobs')
                replacement = Relay(root)
                try:
                    self.assertEqual(replacement.quote()['fee'], self.config['fee'])
                    with self.assertRaises(BlockingIOError):
                        Relay(root)
                finally:
                    replacement.close()
                self.assertIsNotNone(retained.__traceback__)

    def test_new_publication_wakes_only_after_directory_fsync_and_duplicate_does_not(self):
        fsynced = []
        def durable(path):
            if path == self.relay.jobs:
                self.assertFalse(self.relay.wake.is_set())
                jobs = list(path.iterdir())
                self.assertEqual(len(jobs), 1)
                self.assertEqual(json.loads(private(jobs[0] / 'packet.json')), self.value())
                self.assertTrue((jobs[0] / 'owner.json').is_file())
                fsynced.append(True)
            sync_dir(path)
        with patch('shielded_relay.sync_dir', side_effect=durable):
            first = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')
        self.assertEqual(fsynced, [True])
        self.assertTrue(self.relay.wake.is_set())
        self.relay.wake.clear()
        self.assertEqual(self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice'), first)
        self.assertFalse(self.relay.wake.is_set())

    def test_failed_publication_fsync_does_not_signal_a_durable_job(self):
        def failed(path):
            if path == self.relay.jobs: raise OSError('disposable fsync failure')
            sync_dir(path)
        with patch('shielded_relay.sync_dir', side_effect=failed):
            with self.assertRaises(OSError):
                self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')
        self.assertFalse(self.relay.wake.is_set())
        # The published original is retained for the ordinary periodic/restart
        # scan; failed acknowledgement never creates a replacement packet.
        self.assertEqual(len(list(self.relay.jobs.iterdir())), 1)

    def test_durable_publication_wakes_an_actually_idle_worker(self):
        waiting, rescanned = threading.Event(), threading.Event()
        class Wake(threading.Event):
            def wait(inner, timeout=None):
                self.assertEqual(timeout, 1)
                waiting.set()
                # A long test-only deadline makes a real event, rather than
                # the periodic production timeout, the reason for this wake.
                result = super().wait(5)
                self.assertTrue(result)
                return result
        self.relay.wake = Wake()
        scans = []
        def scan():
            scans.append(list(self.relay.jobs.iterdir()))
            if len(scans) == 2:
                self.relay.stop.set(); rescanned.set()
        with patch.object(self.relay, 'work_once', side_effect=scan):
            self.relay.start()
            self.assertTrue(waiting.wait(1))
            self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')
            self.assertTrue(rescanned.wait(1))
            self.relay.worker.join(timeout=1)
        self.assertEqual([len(paths) for paths in scans], [0, 1])
        self.assertFalse(self.relay.worker.is_alive())

    def test_publication_during_scan_is_not_cleared_before_wait(self):
        scans, waits = [], []
        def scan():
            scans.append(True)
            if len(scans) == 1:
                self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')
            else: self.relay.stop.set()
        def wait(timeout):
            waits.append(timeout)
            self.assertTrue(self.relay.wake.is_set())
            return True
        with patch.object(self.relay, 'work_once', side_effect=scan), patch.object(self.relay.wake, 'wait', side_effect=wait):
            self.relay.work()
        self.assertEqual(len(scans), 2)
        self.assertEqual(waits, [1])

    def test_periodic_fallback_rescans_without_an_event(self):
        scans, waits = [], []
        def scan():
            scans.append(True)
            if len(scans) == 2: self.relay.stop.set()
        def timeout(value):
            self.assertFalse(self.relay.wake.is_set())
            waits.append(value)
            return False
        with patch.object(self.relay, 'work_once', side_effect=scan), patch.object(self.relay.wake, 'wait', side_effect=timeout):
            self.relay.work()
        self.assertEqual(len(scans), 2)
        self.assertEqual(waits, [1])

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

    def test_quote_refuses_member_capacity_and_restart_preserves_original_jobs(self):
        self.assertEqual(self.relay.dispatch('getShieldedFeeQuote', [], 'alice')['fee'], 3_000_000)
        self.assertEqual(list(self.relay.jobs.iterdir()), [])
        first = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')
        second = self.relay.dispatch('submitShieldedPayment', [self.value(1)], 'alice')
        save(self.relay.jobs / first['id'] / 'outcome.json', dict(accepted=True, signature='original'))
        before = sorted(path.name for path in self.relay.jobs.iterdir())
        for restart in (False, True):
            if restart:
                self.relay.close()
                self.relay = Relay(self.root)
            for method, params in [('getShieldedFeeQuote', []), ('submitShieldedPayment', [self.value(2)])]:
                with self.assertRaises(RelayCapacityError) as refusal:
                    self.relay.dispatch(method, params, 'alice')
                self.assertEqual(refusal.exception.scope, 'member')
                self.assertEqual(str(refusal.exception), 'relay lifetime quota exhausted')
            self.assertEqual(sorted(path.name for path in self.relay.jobs.iterdir()), before)
            self.assertEqual(self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice'), first)
            self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [first['id']], 'alice')['signature'], 'original')
            self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [second['id']], 'alice')['state'], 'pending')
            self.assertEqual(self.relay.dispatch('getShieldedFeeQuote', [], 'bob')['fee'], 3_000_000)

    def test_network_capacity_refuses_quotes_and_new_jobs_but_keeps_existing_access(self):
        first = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')
        self.relay.dispatch('submitShieldedPayment', [self.value(1)], 'alice')
        self.relay.dispatch('submitShieldedPayment', [self.value(2)], 'bob')
        self.relay.dispatch('submitShieldedPayment', [self.value(3)], 'bob')
        for member in ('alice', 'carol'):
            for method, params in [('getShieldedFeeQuote', []), ('submitShieldedPayment', [self.value(4)])]:
                with self.assertRaises(RelayCapacityError) as refusal:
                    self.relay.dispatch(method, params, member)
                self.assertEqual(refusal.exception.scope, 'network')
        self.assertEqual(len(list(self.relay.jobs.iterdir())), 4)
        self.assertEqual(self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice'), first)
        self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [first['id']], 'alice')['state'], 'pending')
        self.relay.close()
        self.relay = Relay(self.root)
        with self.assertRaises(RelayCapacityError) as refusal:
            self.relay.dispatch('getShieldedFeeQuote', [], 'carol')
        self.assertEqual(refusal.exception.scope, 'network')
        self.assertEqual(len(list(self.relay.jobs.iterdir())), 4)
        self.assertEqual(self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice'), first)

    def test_quote_does_not_reserve_capacity_and_submit_rechecks_after_a_race(self):
        self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')
        self.relay.dispatch('getShieldedFeeQuote', [], 'alice')
        self.relay.dispatch('submitShieldedPayment', [self.value(1)], 'alice')
        with self.assertRaises(RelayCapacityError) as refusal:
            self.relay.dispatch('submitShieldedPayment', [self.value(2)], 'alice')
        self.assertEqual(refusal.exception.scope, 'member')
        self.assertEqual(len(list(self.relay.jobs.iterdir())), 2)

    def test_capacity_error_accepts_only_public_scopes_and_invalid_quotes_stay_invalid(self):
        for scope in ('member', 'network'):
            self.assertIsInstance(RelayCapacityError(scope), ValueError)
        with self.assertRaises(ValueError):
            RelayCapacityError('private-detail')
        with self.assertRaisesRegex(ValueError, 'quote accepts no parameters') as refusal:
            self.relay.dispatch('getShieldedFeeQuote', [1], 'alice')
        self.assertNotIsInstance(refusal.exception, RelayCapacityError)

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


class NativeRelayTests(unittest.TestCase):
    """Transport/lifecycle evidence only; synthetic payloads are not valid proofs."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = dict(format='native-shielded-relay-v1',
            network=dict(network=[67] * 32, genesis_hash='1' * 32),
            network_file='/fixed/v4-profile.json', rpc='http://127.0.0.1:18899', payer=[8] * 32,
            payer_file='/fixed/shared-relay-key', binary='/fixed/binary', fee=2,
            gross_cap=150_000_000, max_jobs=4, per_member=2,
            pool_format='NPOOL004', native_profile='/fixed/public-tester.json', native_ingress=['127.0.0.1:19001', '127.0.0.1:19002'])
        save(self.root / 'config.json', self.config)
        self.relay = Relay(self.root)

    def tearDown(self):
        self.relay.close()
        self.temp.cleanup()

    def value(self, nonce=0):
        raw = bytearray(9230)
        raw[:8] = b'NPAY0003'; raw[8:40] = bytes([67] * 32)
        raw[48:56] = (2).to_bytes(8, 'little'); raw[56:88] = bytes([8] * 32)
        raw[88:96] = raw[48:56]; raw[-1] = nonce
        return dict(network=self.config['network'], payload=base64.b64encode(raw).decode())

    def test_opt_in_is_explicit_loopback_bounded_and_quote_preserves_network_fee_and_payer(self):
        self.assertEqual(native_options(self.config), '127.0.0.1:19001,127.0.0.1:19002')
        quote = self.relay.quote()
        self.assertEqual(quote['transport'], 'native-inline-v1')
        self.assertEqual(quote['pool_format'], 'NPOOL004')
        self.assertEqual(quote['network'], self.config['network'])
        self.assertEqual(quote['fee'], 2)
        self.assertNotIn('native_ingress', quote)
        for endpoints in [[], ['127.0.0.1:0'], ['127.0.0.1:65536'], ['localhost:19001'],
                          ['[::1]:19001'], ['http://127.0.0.1:19001'], ['127.0.0.1:019001'],
                          ['127.0.0.2:19001'], ['127.0.0.1:19001'] * 2, self.config['native_ingress'] * 2,
                          '127.0.0.1:19001', [True]]:
            with self.subTest(endpoints=endpoints), self.assertRaises(ValueError):
                native_options(dict(self.config, native_ingress=endpoints))
        for changed in [dict(self.config, pool_format='NPOOL003'),
                        {k:v for k,v in self.config.items() if k != 'pool_format'},
                        {k:v for k,v in self.config.items() if k != 'native_ingress'},
                        dict(self.config, payer=[False]*32),
                        dict(self.config, network=dict(network=[0]*32, genesis_hash='1'*32))]:
            with self.assertRaises(ValueError): native_options(changed)

    def test_pending_native_packet_survives_restart_attempt_budget_and_transport_ack(self):
        job = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')['id']
        path = self.relay.jobs / job
        original = dict(signature='original-packet', packet='exact-signed-bytes', last_valid_block_height=77)
        save(path / 'relay.native.json', original)
        journal = private(path / 'relay.native.json')
        save(path / 'tries.json', 9)
        self.relay.close(); self.relay = Relay(self.root)
        class Child:
            returncode = 0  # A successful admission command alone is not acceptance.
            def wait(self, timeout): pass
        with patch('shielded_relay.subprocess.Popen', return_value=Child()) as spawn:
            self.relay.work_once()
        args = spawn.call_args.args[0]
        self.assertEqual(args[args.index('--native-ingress') + 1], '127.0.0.1:19001,127.0.0.1:19002')
        self.assertEqual(args[args.index('--pool-format') + 1], 'NPOOL004')
        self.assertEqual(private(path / 'relay.native.json'), journal)
        self.assertFalse((path / 'outcome.json').exists())
        self.assertFalse((path / 'done').exists())
        self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [job], 'alice')['state'], 'pending')
        self.assertEqual(self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')['id'], job)
        with self.assertRaisesRegex(ValueError, 'ownership'):
            self.relay.dispatch('getShieldedPaymentStatus', [job], 'bob')

    def test_native_binding_prevents_staging_downgrade_and_changed_authority_or_state(self):
        job = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')['id']
        path = self.relay.jobs / job
        original = private(path / 'transport.json')
        for field, replacement in [('payer', [9]*32), ('fee', 3), ('network', dict(network=[68]*32,genesis_hash='1'*32))]:
            changed = json.loads(original); changed[field] = replacement
            save(path / 'transport.json', changed)
            with self.assertRaisesRegex(ValueError, 'binding'):
                self.relay.dispatch('getShieldedPaymentStatus', [job], 'alice')
            with patch('shielded_relay.subprocess.Popen') as spawn:
                with self.assertRaisesRegex(ValueError, 'binding'): self.relay.work_once()
                spawn.assert_not_called()
            (path / 'transport.json').write_bytes(original)
        self.relay.close()
        staging = {k:v for k,v in self.config.items() if k not in ('native_ingress','pool_format','native_profile')}
        save(self.root / 'config.json', staging)
        with self.assertRaisesRegex(ValueError, 'fall back'): Relay(self.root)
        save(self.root / 'config.json', self.config)
        self.relay = Relay(self.root)
        self.assertEqual(private(path / 'transport.json'), original)
        self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [job], 'alice')['state'], 'pending')

    def test_done_marker_cannot_hide_unknown_native_journal_and_quota_remains_durable(self):
        job = self.relay.dispatch('submitShieldedPayment', [self.value()], 'alice')['id']
        path = self.relay.jobs / job
        save(path / 'done', True); save(path / 'relay.native.json', dict(signature='original'))
        class Child:
            returncode = 1
            def wait(self, timeout): pass
        with patch('shielded_relay.subprocess.Popen', return_value=Child()) as spawn:
            self.relay.work_once(); spawn.assert_called_once()
        self.assertEqual(self.relay.dispatch('getShieldedPaymentStatus', [job], 'alice')['state'], 'pending')
        self.relay.dispatch('submitShieldedPayment', [self.value(1)], 'alice')
        self.relay.close(); self.relay = Relay(self.root)
        with self.assertRaisesRegex(ValueError, 'quota'):
            self.relay.dispatch('submitShieldedPayment', [self.value(2)], 'alice')


if __name__ == '__main__': unittest.main()
