import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from history_retention import Retention, capture, manifest, MIN_FREE, MAX_SEGMENT, MAX_LAG

NETWORK = {'network': [7] * 32, 'genesis_hash': '11111111111111111111111111111111'}
H = '11111111111111111111111111111111'


def write(path, data):
    path.write_bytes(data); path.chmod(0o600)


def segment(root, blocks, index=0):
    data = json.dumps(blocks).encode()
    digest = hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest()
    name = 'segment-%08d-%s.json' % (index, digest)
    write(root / name, data)
    return {'first_slot': blocks[0]['slot'], 'last_slot': blocks[-1]['slot'], 'count': len(blocks), 'digest': digest}


def block(slot, parent=None):
    return {'slot': slot, 'parent_slot': slot - 1 if parent is None else parent,
            'blockhash': H, 'previous_blockhash': H, 'block_height': slot, 'transactions': []}


def archive(root, descriptors=None):
    root.mkdir(mode=0o700, exist_ok=True)
    if descriptors is None: descriptors = [segment(root, [block(1)])]
    write(root / 'manifest.json', json.dumps({'format': 'native-payment-history-v1', 'network': NETWORK, 'segments': descriptors}).encode())


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.source = self.root / 'source'; self.mirror = self.root / 'mirror'
        archive(self.source)

    def test_captured_manifest_is_exact_and_excludes_keys_locks_and_uncommitted_payloads(self):
        write(self.source / 'operator.password', b'not-public-history')
        write(self.source / '.uncommitted.tmp', b'partial')
        result = capture(self.source, self.mirror, NETWORK)
        self.assertEqual(result['finalized_slot'], 1)
        self.assertEqual((self.source / 'manifest.json').read_bytes(), (self.mirror / 'manifest.json').read_bytes())
        self.assertFalse((self.mirror / 'operator.password').exists()); self.assertFalse((self.mirror / '.uncommitted.tmp').exists())
        self.assertEqual(capture(self.source, self.mirror, NETWORK), result)

    def test_interrupted_copy_keeps_old_manifest_and_recovers_identical_orphans(self):
        capture(self.source, self.mirror, NETWORK)
        old = (self.mirror / 'manifest.json').read_bytes()
        descriptors = json.loads((self.source / 'manifest.json').read_bytes())['segments']
        descriptors.append(segment(self.source, [block(2)], 1)); archive(self.source, descriptors)
        with patch('history_retention.atomic', side_effect=OSError('simulated power loss before manifest publication')):
            with self.assertRaises(OSError): capture(self.source, self.mirror, NETWORK)
        self.assertEqual((self.mirror / 'manifest.json').read_bytes(), old)
        self.assertEqual(capture(self.source, self.mirror, NETWORK)['finalized_slot'], 2)
        self.assertEqual((self.source / 'manifest.json').read_bytes(), (self.mirror / 'manifest.json').read_bytes())

    def test_missing_corrupt_rehashed_gap_and_wrong_network_never_publish(self):
        for mode in ['missing', 'checksum', 'gap', 'network', 'permissions', 'path']:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as name:
                source = Path(name).resolve() / 'source'; dest = Path(name).resolve() / 'dest'; archive(source)
                data = json.loads((source / 'manifest.json').read_bytes()); descriptor = data['segments'][0]
                payload = source / ('segment-00000000-%s.json' % descriptor['digest'])
                if mode == 'missing': payload.unlink()
                if mode == 'checksum': write(payload, b'changed')
                if mode == 'permissions': payload.chmod(0o644)
                if mode == 'gap': data['segments'] = [segment(source, [block(1, parent=99)])]
                if mode == 'network': data['network']['network'][0] = 99
                if mode == 'path': data['segments'][0]['digest'] = '../outside'
                write(source / 'manifest.json', json.dumps(data).encode())
                with self.assertRaises((ValueError, OSError)): capture(source, dest, NETWORK)
                self.assertFalse((dest / 'manifest.json').exists())

    def test_rollback_repartition_and_symlink_cannot_replace_a_verified_backup(self):
        capture(self.source, self.mirror, NETWORK); old = (self.mirror / 'manifest.json').read_bytes()
        archive(self.source, [])
        with self.assertRaisesRegex(ValueError, 'rollback'): capture(self.source, self.mirror, NETWORK)
        self.assertEqual((self.mirror / 'manifest.json').read_bytes(), old)
        archive(self.source, [segment(self.source, [dict(block(1), transactions=[{'changed': True}])])])
        with self.assertRaisesRegex(ValueError, 'prefix change'): capture(self.source, self.mirror, NETWORK)
        archive(self.source)
        name = next(self.mirror.glob('segment-*.json')); name.unlink(); name.symlink_to(self.source / name.name)
        with self.assertRaises(OSError): capture(self.source, self.mirror, NETWORK)
        self.assertEqual((self.mirror / 'manifest.json').read_bytes(), old)

    def test_capacity_and_concurrent_writer_refuse_without_manifest_publication(self):
        with self.assertRaisesRegex(ValueError, 'capacity'): capture(self.source, self.mirror, NETWORK, budget=16)
        self.assertFalse((self.mirror / 'manifest.json').exists())
        with (self.mirror / '.mirror.lock').open('r+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): capture(self.source, self.mirror, NETWORK)
        link = self.root / 'link'; link.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError): capture(link, self.mirror, NETWORK)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(); self.root.chmod(0o700)
        write(self.root / 'network.json', json.dumps(NETWORK).encode())
        archive(self.root / 'recovery-history')
        self.calls = []
        def query(method, params):
            self.calls.append(method); return 0 if method == 'getFirstAvailableBlock' else 1
        self.worker = Retention(self.root, self.root / 'native-wallet', 'http://127.0.0.1:18899', query, credential=self.root / 'rpc-access.key')
        self.worker.resources = lambda: None

    def child(self, success=True):
        class Child:
            pid = 321; returncode = 0 if success else 1
            def poll(self): return self.returncode
            def communicate(self, **kwargs): return json.dumps({'manifest_committed': True, 'finalized_slot': 1}), ''
        return Child()

    def test_collection_uses_no_wallet_password_sponsor_or_write_rpc_and_commits_mirror_before_ready(self):
        with patch('history_retention.subprocess.Popen', return_value=self.child()) as launch:
            result = self.worker.collect()
        self.assertEqual(result['phase'], 'ready'); self.assertTrue(self.worker.healthy())
        args = launch.call_args.args[0]
        self.assertEqual(args[1], 'archive')
        self.assertFalse(set(args) & {'--wallet', '--password-file', '--sponsor', '--sponsor-password-file'})
        self.assertEqual(args[-2:], ['--rpc-access-file', str(self.root / 'rpc-access.key')])
        self.assertEqual(self.calls, ['getSlot', 'getFirstAvailableBlock', 'getSlot'])
        self.assertEqual(manifest(self.worker.mirror, NETWORK)[2], 1)
        self.worker.close(); self.assertFalse(self.worker.healthy())
        self.assertEqual(json.loads(self.worker.path.read_bytes())['phase'], 'paused')

    def test_failure_preserves_last_committed_mirror_and_never_refills_or_reinitializes(self):
        capture(self.worker.primary, self.worker.mirror, NETWORK)
        original = (self.worker.mirror / 'manifest.json').read_bytes()
        with patch('history_retention.subprocess.Popen', return_value=self.child(False)):
            with self.assertRaisesRegex(ValueError, 'collection_failed'): self.worker.collect()
        self.assertEqual(self.worker.info['phase'], 'blocked'); self.assertFalse(self.worker.healthy())
        self.assertEqual((self.worker.mirror / 'manifest.json').read_bytes(), original)
        diagnostic=json.loads((self.root/'history-collector-error.json').read_text())
        self.assertEqual(diagnostic['returncode'],1)
        self.assertEqual((self.root/'history-collector-error.json').stat().st_mode&0o777,0o600)

    def test_pruning_gap_blocks_before_starting_collector(self):
        self.worker.query = lambda method, params: 5
        with patch('history_retention.subprocess.Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'history_gap'): self.worker.collect()
        launch.assert_not_called(); self.assertFalse(self.worker.healthy())

    def test_lag_stale_success_and_clock_rollback_cannot_report_healthy(self):
        values = iter([1, 0, MAX_LAG + 2]); self.worker.query = lambda *args: next(values)
        with patch('history_retention.subprocess.Popen', return_value=self.child()):
            with self.assertRaisesRegex(ValueError, 'checkpoint_lag'): self.worker.collect()
        self.assertFalse(self.worker.healthy())
        for ago in [181, -1]:
            self.worker.info.update(phase='ready', last_success=time.time() - ago)
            self.assertFalse(self.worker.healthy())

    def test_live_disk_guard_kills_owned_child_and_preserves_original_manifest(self):
        original = (self.worker.primary / 'manifest.json').read_bytes()
        class Child:
            pid = 322; killed = False; returncode = None
            def poll(self): return self.returncode
            def kill(self): self.killed = True; self.returncode = -9
            def communicate(self, **kwargs):
                if self.killed: return '', ''
                raise subprocess.TimeoutExpired('owned collector', .25)
        child = Child()
        with patch.object(self.worker, 'resources', side_effect=[None, ValueError('retention_disk_guard')]), patch('history_retention.subprocess.Popen', return_value=child):
            with self.assertRaisesRegex(ValueError, 'disk_guard'): self.worker.collect()
        self.assertTrue(child.killed); self.assertIsNone(self.worker.child)
        self.assertEqual((self.worker.primary / 'manifest.json').read_bytes(), original)
        self.assertFalse(self.worker.healthy())

    def test_real_resource_checks_block_low_free_space_and_over_budget_stores(self):
        from types import SimpleNamespace
        with patch('history_retention.shutil.disk_usage', return_value=SimpleNamespace(free=MIN_FREE)):
            with self.assertRaisesRegex(ValueError, 'retention_disk_guard'):
                Retention.resources(self.worker)
        with patch('history_retention.shutil.disk_usage', return_value=SimpleNamespace(free=MIN_FREE + MAX_SEGMENT)), patch('history_retention.usage', side_effect=ValueError('history storage budget exceeded')):
            with self.assertRaisesRegex(ValueError, 'retention_storage_guard'):
                Retention.resources(self.worker)

    def test_disk_capacity_policies_cannot_be_silently_weakened(self):
        for kwargs in [{'minimum_free': MIN_FREE - 1}, {'interval': 0}, {'interval': 61}, {'budget': MAX_SEGMENT - 1}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                Retention(self.root, self.root / 'binary', 'http://127.0.0.1:18899', lambda *args: 1, **kwargs)

    def replica_policy(self):
        write(self.root/'history-replica.json',json.dumps({'format':'native-history-replication-v1',
            'url':'https://127.0.0.1:12345','ca_sha256':'a'*64}).encode())

    def test_configured_replica_ack_precedes_ready_and_uses_no_wallet_keys(self):
        self.replica_policy()
        receipt={'durable':True,'manifest_sha256':'verified-remote-checkpoint'}
        with patch('history_retention.subprocess.Popen',return_value=self.child()), patch('history_replica.replicate',return_value=receipt) as transfer:
            result=self.worker.collect()
        self.assertEqual(result['phase'],'ready');self.assertEqual(result['replica'],receipt)
        self.assertEqual(transfer.call_args.args[:2],(self.worker.mirror,NETWORK))
        self.assertEqual(transfer.call_args.args[3:5],(self.root/'history-replica.key',self.root/'history-replica-ca.crt'))
        self.assertIs(transfer.call_args.args[-1],self.worker.stop)

    def test_configured_replica_outage_fails_closed_without_erasing_local_history(self):
        self.replica_policy();capture(self.worker.primary,self.worker.mirror,NETWORK)
        original=(self.worker.mirror/'manifest.json').read_bytes()
        with patch('history_retention.subprocess.Popen',return_value=self.child()), patch('history_replica.replicate',side_effect=OSError('receiver unavailable')):
            with self.assertRaisesRegex(ValueError,'replica_unavailable'):self.worker.collect()
        self.assertFalse(self.worker.healthy());self.assertEqual(self.worker.info['phase'],'blocked')
        self.assertEqual((self.worker.mirror/'manifest.json').read_bytes(),original)

    def test_removing_required_replica_policy_cannot_silently_disable_replication(self):
        self.replica_policy()
        with patch('history_retention.subprocess.Popen',return_value=self.child()), patch('history_replica.replicate',return_value={'durable':True}):self.worker.collect()
        (self.root/'history-replica.json').unlink()
        with patch('history_retention.subprocess.Popen',return_value=self.child()):
            with self.assertRaises(FileNotFoundError):self.worker.collect()
        self.assertFalse(self.worker.healthy())

    def test_invalid_replica_policy_never_calls_transport_or_reports_ready(self):
        self.replica_policy();value=json.loads((self.root/'history-replica.json').read_bytes());value['ca_sha256']='not-a-pin'
        write(self.root/'history-replica.json',json.dumps(value).encode())
        with patch('history_retention.subprocess.Popen',return_value=self.child()), patch('history_replica.replicate') as transfer:
            with self.assertRaisesRegex(ValueError,'replica_policy_invalid'):self.worker.collect()
        transfer.assert_not_called();self.assertFalse(self.worker.healthy())

    def test_restart_preserves_required_replica_even_if_configuration_disappears(self):
        self.replica_policy()
        with patch('history_retention.subprocess.Popen',return_value=self.child()), patch('history_replica.replicate',return_value={'durable':True}):self.worker.collect()
        (self.root/'history-replica.json').unlink()
        restarted=Retention(self.root,self.root/'binary','http://127.0.0.1:18899',lambda method,params:0 if method=='getFirstAvailableBlock' else 1)
        restarted.resources=lambda:None
        with patch('history_retention.subprocess.Popen',return_value=self.child()):
            with self.assertRaises(FileNotFoundError):restarted.collect()
        self.assertFalse(restarted.healthy());self.assertTrue(restarted.replica_required)


if __name__ == '__main__': unittest.main()
