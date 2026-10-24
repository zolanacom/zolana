"""Actual ArchiveRPC/SQLite synthetic fixtures; no host, listener or wallet."""
from contextlib import closing
import hashlib
import json
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import canonical_archive_rolling as rolling
from canonical_archive_rolling import RollingArchive
from canonical_archive_backend import HEADER
from canonical_archive_store import Capture, Reader, BLOCK_LIMIT, encoded, number
from canonical_archive_store_test import NETWORK, blocks, blockhash, page, target


class RollingArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zolana-canonical-rolling-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'canonical.sqlite3'
        self.items = blocks(range(1, 34))
        self.append(self.items)
        self.calls = []
        self.transform = lambda value: value
        self.primary_hook = None
        self.gateway = SimpleNamespace(info=dict(network=NETWORK, invite_required=True,
            rpc_audience='https://fixture.invalid/'), forward=self.primary)
        self.archive = RollingArchive(self.gateway, self.path)

    def append(self, items, after=0):
        pinned = target(items)
        with Capture(self.path, NETWORK, NETWORK['genesis_hash'], pinned) as writer:
            for offset in range(0, len(items), 16):
                chunk = items[offset:offset + 16]
                writer.append(encoded(page(chunk, pinned, after)))
                after = chunk[-1]['slot']
            writer.commit()

    def primary(self, raw, timeout):
        value = json.loads(raw)
        self.calls.append(value)
        self.assertEqual(value['method'], 'getBlock')
        self.assertEqual(value['params'][1], HEADER)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 15)
        if self.primary_hook:
            self.primary_hook()
        slot = value['params'][0]
        header = dict(blockhash=blockhash(slot), blockHeight=slot,
                      parentSlot=slot - 1, previousBlockhash=blockhash(slot - 1))
        return encoded(dict(jsonrpc='2.0', id=1, result=self.transform(header)))

    def read(self, after=0, through=33, token=None):
        return json.loads(self.archive.page(dict(jsonrpc='2.0', id='fixture',
            method='getWalletCanonicalHistory', params=[after, through, token])))['result']

    def inventory(self):
        return {p.name:(hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns,
                        p.stat().st_size, p.stat().st_mode) for p in self.root.iterdir()}

    def test_actual_protocol_preserves_every_full_body_and_old_continuation_across_commits(self):
        original = self.inventory()
        first = self.read()
        self.assertEqual(first['blocks'], self.items[:16])
        self.assertEqual(self.inventory(), original)
        extra = blocks(range(34, 50), after=33, height=33)
        self.append(extra, after=33)
        tail = self.read(16, 33, first['anchor'])
        last = self.read(32, 33, first['anchor'])
        self.assertEqual(first['blocks'] + tail['blocks'] + last['blocks'], self.items)
        self.assertTrue(last['complete'])
        self.assertEqual(self.read(33, 49, target(extra))['blocks'], extra)
        self.assertFalse(self.read(33, 33, first['anchor'])['blocks'])
        self.assertEqual(len(self.calls), 5, 'every page still checks a fresh primary target')

    def test_one_readonly_snapshot_per_page_and_fixed_private_gateway_configuration(self):
        opened, closed = [], []
        class CountedReader(Reader):
            def __init__(inner, *args):
                super().__init__(*args)
                opened.append(inner)
            def close(inner):
                closed.append(inner)
                super().close()
        before = self.inventory()
        with patch.object(rolling, 'Reader', CountedReader):
            self.read()
        self.assertEqual(len(opened), 1)
        self.assertEqual(closed, opened)
        self.assertEqual(self.inventory(), before)
        with self.assertRaises(ValueError):
            RollingArchive(SimpleNamespace(info=dict(self.gateway.info, invite_required=False)), self.path)
        for count in [True, 0, 5]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                RollingArchive(self.gateway, self.path, max_readers=count)
        for field in ['source', 'path', 'url', 'network']:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.archive.page(dict(id=1, params=[0, 33, None], **{field:'untrusted'}))

    def test_uncommitted_extension_never_becomes_absence_success_and_thread_commit_waits_for_page(self):
        entered, release, staged, writer_done = (threading.Event() for _ in range(4))
        values, failures = [], []
        def pause():
            entered.set()
            if not release.wait(4):
                raise TimeoutError('synthetic page release deadline')
        self.primary_hook = pause
        def read():
            try: values.append(self.read())
            except BaseException as error: failures.append(error)
        reader = threading.Thread(target=read)
        reader.start()
        self.assertTrue(entered.wait(2))
        extra = blocks(range(34, 50), after=33, height=33)
        def write():
            try:
                with Capture(self.path, NETWORK, NETWORK['genesis_hash'], target(extra)) as writer:
                    writer.append(encoded(page(extra, target(extra), 33)))
                    staged.set()
                    writer.commit()
            except BaseException as error: failures.append(error)
            finally: writer_done.set()
        writer = threading.Thread(target=write)
        writer.start()
        try:
            self.assertTrue(staged.wait(2))
            self.assertFalse(writer_done.wait(.05), 'commit must respect the active pinned read transaction')
        finally:
            release.set()
            reader.join(4); writer.join(4)
        self.assertFalse(reader.is_alive() or writer.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(values[0]['blocks'], self.items[:16])
        self.primary_hook = None
        self.assertEqual(self.read(33, 49, target(extra))['blocks'], extra)

    def test_reader_budget_has_no_wait_queue_and_writer_busy_keeps_old_prefix(self):
        self.archive = RollingArchive(self.gateway, self.path, max_readers=1)
        entered, release = threading.Event(), threading.Event()
        failures = []
        def pause():
            entered.set()
            if not release.wait(4): raise TimeoutError('synthetic page deadline')
        self.primary_hook = pause
        def read():
            try: self.read()
            except BaseException as error: failures.append(error)
        thread = threading.Thread(target=read)
        thread.start()
        self.assertTrue(entered.wait(2))
        try:
            with self.assertRaisesRegex(ValueError, 'busy'): self.read()
            extra = blocks([34], after=33, height=33)
            with self.assertRaises(sqlite3.OperationalError):
                self.append(extra, after=33)
        finally:
            release.set(); thread.join(4)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.primary_hook = None
        self.assertEqual(self.read()['anchor']['slot'], 33)
        with self.assertRaisesRegex(ValueError, 'committed'): self.read(through=34)

    def test_optional_coverage_precedes_reader_and_shares_deadline_and_reader_budget(self):
        events=[]
        class OrderedReader(Reader):
            def __init__(inner,*args):
                events.append('reader')
                super().__init__(*args)
        def coverage(slot,deadline):
            self.assertEqual(slot,33)
            self.assertGreater(deadline,time.monotonic())
            self.assertLessEqual(deadline-time.monotonic(),15)
            self.assertEqual(events,[])
            events.append('coverage')
        self.archive=RollingArchive(self.gateway,self.path,coverage=coverage)
        with patch.object(rolling,'Reader',OrderedReader):self.read()
        self.assertEqual(events,['coverage','reader'])
        calls=len(self.calls)
        def fails(slot,deadline):raise TimeoutError('coverage unavailable')
        self.archive=RollingArchive(self.gateway,self.path,max_readers=1,coverage=fails)
        with patch.object(rolling,'Reader',side_effect=AssertionError('must not open Reader')):
            for _ in range(2):
                with self.assertRaisesRegex(TimeoutError,'coverage unavailable'):self.read()
        self.assertEqual(len(self.calls),calls,'failed coverage makes no primary request')
        entered,release=threading.Event(),threading.Event()
        failures=[]
        def waiting(slot,deadline):
            entered.set()
            if not release.wait(2):raise TimeoutError('fixture wait exceeded')
        self.archive=RollingArchive(self.gateway,self.path,max_readers=1,coverage=waiting)
        def read():
            try:self.read()
            except BaseException as error:failures.append(error)
        thread=threading.Thread(target=read);thread.start()
        self.assertTrue(entered.wait(1))
        try:
            with self.assertRaisesRegex(ValueError,'busy'):self.read()
        finally:release.set();thread.join(3)
        self.assertEqual(failures,[])
        clock=[0]
        self.archive=RollingArchive(self.gateway,self.path,coverage=lambda *args:clock.__setitem__(0,16))
        with patch.object(rolling.time,'monotonic',side_effect=lambda:clock[0]),\
             patch.object(rolling,'Reader',side_effect=AssertionError('expired coverage cannot open Reader')):
            with self.assertRaisesRegex(ValueError,'deadline'):self.read()
        with self.assertRaises(ValueError):RollingArchive(self.gateway,self.path,coverage=True)

    def test_failed_primary_changed_anchor_missing_gap_corruption_and_deadline_never_fallback(self):
        calls_before = len(self.calls)
        def fail(): raise ConnectionError('synthetic primary failure')
        self.primary_hook = fail
        with self.assertRaises(ConnectionError): self.read()
        self.assertEqual(len(self.calls), calls_before + 1)
        self.primary_hook = None
        self.transform = lambda value:dict(value, blockhash=blockhash(5))
        with self.assertRaisesRegex(ValueError, 'differ'): self.read()
        self.transform = lambda value:value
        with self.assertRaises(ValueError): self.read(16, 33, dict(target(self.items), block_height=99))
        self.assertEqual(self.read()['blocks'], self.items[:16], 'all failed paths release their reader budget')
        clock = [0]
        self.primary_hook = lambda: clock.__setitem__(0, 16)
        with patch.object(rolling.time, 'monotonic', side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(ValueError, 'deadline'): self.read()
        self.primary_hook = None
        for mode in ['gap', 'body', 'oversized', 'index', 'wrong-network', 'missing']:
            copy = self.root / (mode + '.sqlite3')
            if mode != 'missing':
                copy.write_bytes(self.path.read_bytes()); copy.chmod(0o600)
            if mode in ('gap', 'body', 'oversized', 'index'):
                with closing(sqlite3.connect(copy)) as db, db:
                    if mode == 'gap': db.execute('DELETE FROM blocks WHERE slot=?', (number(5),))
                    elif mode == 'body': db.execute('UPDATE blocks SET body=? WHERE slot=?', (b'{}', number(5)))
                    elif mode == 'oversized': db.execute('UPDATE blocks SET body=zeroblob(?) WHERE slot=?', (BLOCK_LIMIT+1, number(5)))
                    else: db.execute('UPDATE blocks SET hash=? WHERE slot=?', ('1'*32+'\0'+'x'*4096, number(5)))
            gateway = self.gateway if mode != 'wrong-network' else SimpleNamespace(
                info=dict(self.gateway.info, network=dict(NETWORK, network=[8]*32)), forward=self.primary)
            self.archive = RollingArchive(gateway, copy)
            with self.subTest(mode=mode), self.assertRaises((ValueError, FileNotFoundError)): self.read()
            if mode == 'missing': self.assertFalse(copy.exists())

    def test_process_crash_before_and_after_commit_serves_only_complete_prefix(self):
        child = r'''
import json,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from canonical_archive_store import Capture,encoded
data=json.loads(Path(sys.argv[2]).read_bytes())
with Capture(Path(data['path']),data['network'],data['network']['genesis_hash'],data['target']) as writer:
    writer.db.execute('PRAGMA cache_size=1')
    writer.append(encoded(data['page']))
    if data['commit']:writer.commit()
    Path(data['marker']).write_text('ready')
    while True:time.sleep(1)
'''
        original_path = self.path
        for committed in [False, True]:
            self.path = self.root / ('killed-' + str(committed) + '.sqlite3')
            self.path.write_bytes(original_path.read_bytes()); self.path.chmod(0o600)
            self.archive = RollingArchive(self.gateway, self.path)
            extra = blocks([34], after=33, height=33)
            extra[0]['block']['large_unknown_field'] = 'x' * (2*1024**2)
            pinned = target(extra)
            marker = self.root / ('ready-' + str(committed))
            config = self.root / ('process-' + str(committed) + '.json')
            config.write_bytes(encoded(dict(path=str(self.path), network=NETWORK, target=pinned,
                page=page(extra,pinned,33), commit=committed, marker=str(marker))))
            process = subprocess.Popen([sys.executable,'-B','-c',child,str(Path(__file__).parent),str(config)],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(marker.exists(), 'synthetic owned writer failed to reach kill boundary')
                process.kill(); process.communicate(timeout=5)
                self.assertEqual(process.returncode, -signal.SIGKILL)
            finally:
                if process.poll() is None: process.kill(); process.communicate(timeout=5)
            if committed:
                self.assertEqual(self.read(33,34,pinned)['blocks'],extra)
            else:
                # A read-only hot journal must refuse, never expose uncommitted
                # rows. An owned writer open may perform SQLite recovery only.
                journal = self.path.with_name(self.path.name+'-journal')
                self.assertTrue(journal.exists())
                with journal.open('rb') as source: self.assertNotEqual(source.read(8),bytes(8))
                with self.assertRaises(sqlite3.OperationalError): self.read()
                with self.assertRaises((ValueError,sqlite3.OperationalError)): self.read(33,34,pinned)
                with Capture(self.path,NETWORK,NETWORK['genesis_hash'],pinned): pass
                self.assertEqual(self.read()['blocks'],self.items[:16])
                with self.assertRaisesRegex(ValueError,'committed'): self.read(through=34)


if __name__ == '__main__':
    unittest.main()
