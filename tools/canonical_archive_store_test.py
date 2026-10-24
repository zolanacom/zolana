"""Disposable full-RPC fixtures only; no host, wallet, key or network access."""
import base64
import copy
from contextlib import closing
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import canonical_archive_store as archive
from canonical_archive_store import Capture, Reader, BLOCK_LIMIT, PAGE_LIMIT, encoded, number

NETWORK = dict(network=[7] * 32, genesis_hash='1' * 32)
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def blockhash(slot):
    return '1' * 31 + ALPHABET[slot % len(ALPHABET)]


def blocks(slots, after=0, height=0):
    result = []
    for slot in slots:
        height += 1
        # Deliberately include successful, failed and unrelated full bodies;
        # storage must not inspect their program or discard their metadata.
        txs = [dict(transaction=[base64.b64encode(label.encode()).decode(), 'base64'],
                    meta=dict(err=None if label != 'failed' else {'InstructionError': [0, 'Custom']},
                              status={'Ok': None} if label != 'failed' else {'Err': 'fixture'},
                              fee=5000, preBalances=[9007199254740993], postBalances=[1],
                              loadedAddresses=dict(writable=[], readonly=[]), unknown_meta={'kept': label}),
                    version='legacy', unknown_entry=[label, 0, False])
               for label in ['native', 'failed', 'unrelated']]
        body = dict(blockhash=blockhash(slot), previousBlockhash=blockhash(after),
                    parentSlot=after, blockHeight=height, transactions=txs,
                    blockTime=None, rewards=[], unknown_block={'preserve': ['all', 'fields']})
        result.append(dict(slot=slot, block=body))
        after = slot
    return result


def target(items):
    return dict(slot=items[-1]['slot'], blockhash=items[-1]['block']['blockhash'],
                block_height=items[-1]['block']['blockHeight'])


def page(items, pinned, after):
    return dict(network=NETWORK, anchor=pinned, after_slot=after,
                next_slot=items[-1]['slot'], complete=items[-1]['slot'] == pinned['slot'], blocks=items)


def request(after, pinned, first=False):
    return dict(id=1, params=[after, pinned['slot'], None if first else pinned])


class CanonicalArchiveStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zolana-canonical-prototype-')
        self.root = Path(self.temp.name).resolve()
        self.path = self.root / 'canonical.sqlite3'
        self.addCleanup(self.temp.cleanup)

    def capture(self, items, after=0):
        pinned = target(items)
        with Capture(self.path, NETWORK, NETWORK['genesis_hash'], pinned) as writer:
            for offset in range(0, len(items), 16):
                chunk = items[offset:offset + 16]
                writer.append(encoded(page(chunk, pinned, after)))
                after = chunk[-1]['slot']
            writer.commit()
        return pinned

    def read_all(self, pinned):
        result, after = [], 0
        with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
            while after < pinned['slot']:
                value = json.loads(reader.page(request(after, pinned, first=after == 0)))['result']
                self.assertEqual(value['anchor'], pinned)
                self.assertLessEqual(len(value['blocks']), 16)
                result.extend(value['blocks'])
                after = value['next_slot']
        return result

    def test_full_unfiltered_bodies_failed_metadata_unknown_fields_and_u64_preserved(self):
        items = blocks(range(1, 35))
        pinned = self.capture(items)
        self.assertEqual(self.read_all(pinned), items)
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)
        # SQLite INTEGER cannot hold these valid u64 slots; ordered BLOB keys can.
        other = self.root / 'upper-half.sqlite3'
        self.path = other
        items = blocks([2**63 + 3, 2**64 - 1])
        pinned = self.capture(items)
        self.assertEqual(self.read_all(pinned), items)

    def test_append_old_targets_restart_cursor_and_readonly_reader(self):
        first = blocks([2, 4])
        old = self.capture(first)
        rest = blocks([8, 11], after=4, height=2)
        final = self.capture(rest, after=4)
        self.assertEqual(self.read_all(final), first + rest)
        self.assertEqual(self.read_all(old), first)
        with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
            saved = json.loads(reader.page(request(0, final, first=True)))['result']['anchor']
            with self.assertRaises(sqlite3.OperationalError):
                reader.db.execute('DELETE FROM blocks')
        with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
            resumed = json.loads(reader.page(request(4, saved)))['result']
            self.assertEqual(resumed['blocks'], rest)
            self.assertTrue(resumed['complete'])
            empty = json.loads(reader.page(request(11, saved)))['result']
            self.assertEqual(empty['blocks'], [])
            self.assertTrue(empty['complete'])

    def test_failed_or_incomplete_extension_never_publishes_or_replaces_old_prefix(self):
        old_items = blocks([1, 2])
        old = self.capture(old_items)
        extra = blocks([3, 4], after=2, height=2)
        pinned = target(extra)
        for mode in ['gap', 'hash', 'height', 'network', 'anchor', 'next', 'complete', 'missing-meta',
                     'missing-err', 'missing-body', 'not-base64', 'duplicate-slot', 'replay', 'extra-field', 'bool-anchor']:
            value = page(copy.deepcopy(extra), pinned, 2)
            if mode == 'gap': value['blocks'][1]['block']['parentSlot'] = 1
            if mode == 'hash': value['blocks'][1]['block']['previousBlockhash'] = blockhash(1)
            if mode == 'height': value['blocks'][1]['block']['blockHeight'] = 9
            if mode == 'network': value['network'] = dict(NETWORK, network=[8] * 32)
            if mode == 'anchor': value['anchor'] = dict(pinned, blockhash=blockhash(9))
            if mode == 'next': value['next_slot'] = 3
            if mode == 'complete': value['complete'] = False
            if mode == 'missing-meta': del value['blocks'][1]['block']['transactions'][0]['meta']
            if mode == 'missing-err': del value['blocks'][1]['block']['transactions'][0]['meta']['err']
            if mode == 'missing-body': del value['blocks'][1]['block']['transactions']
            if mode == 'not-base64': value['blocks'][1]['block']['transactions'][0]['transaction'][0] = 'bad'
            if mode == 'duplicate-slot': value['blocks'][1] = copy.deepcopy(value['blocks'][0])
            if mode == 'replay': value['after_slot'] = 1
            if mode == 'extra-field': value['checkpoint'] = {'retained': True}
            if mode == 'bool-anchor': value['anchor'] = dict(pinned, block_height=True)
            with self.subTest(mode=mode):
                writer = Capture(self.path, NETWORK, NETWORK['genesis_hash'], pinned)
                with self.assertRaises((ValueError, KeyError)):
                    writer.append(encoded(value))
                self.assertTrue(writer.closed)
                with self.assertRaises(ValueError): writer.commit()
                self.assertEqual(self.read_all(old), old_items)
        with Capture(self.path, NETWORK, NETWORK['genesis_hash'], pinned) as writer:
            writer.append(encoded(page(extra[:1], pinned, 2)))
            with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
                self.assertEqual(reader.slot, 2)
                with self.assertRaises(ValueError): reader.page(request(0, pinned, first=True))
            with self.assertRaises(ValueError): writer.commit()
        self.assertEqual(self.read_all(old), old_items)
        for pinned_again in [old, dict(old, slot=1, blockhash=blockhash(1), block_height=1)]:
            with self.assertRaises(ValueError):
                Capture(self.path, NETWORK, NETWORK['genesis_hash'], pinned_again)

    def test_genesis_anchor_limits_duplicates_and_unsafe_files_refuse(self):
        items = blocks([1])
        pinned = self.capture(items)
        with self.assertRaises(ValueError): Reader(self.path, NETWORK, blockhash(2))
        with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
            for query in [request(0, dict(pinned, blockhash=blockhash(2))),
                          dict(id=1, params=[1, 2, dict(pinned, slot=2)]),
                          dict(id=True, params=[0, 1, None]),
                          dict(id=1, params=[1, 1, None])]:
                with self.subTest(query=query), self.assertRaises(ValueError): reader.page(query)
        extra = blocks([2], after=1, height=1)
        next_target = target(extra)
        for raw in [b'{"network":{},"network":{}}', b'x' * (PAGE_LIMIT + 1),
                    encoded(page(extra * 17, next_target, 1)),
                    encoded(page([dict(extra[0], block=dict(extra[0]['block'], padding='x' * BLOCK_LIMIT))], next_target, 1))]:
            with Capture(self.path, NETWORK, NETWORK['genesis_hash'], next_target) as writer:
                with self.assertRaises(ValueError): writer.append(raw)
        link = self.root / 'link.sqlite3'
        link.symlink_to(self.path)
        with self.assertRaises(ValueError): Reader(link, NETWORK, NETWORK['genesis_hash'])
        os.chmod(self.path, 0o644)
        with self.assertRaises(ValueError): Reader(self.path, NETWORK, NETWORK['genesis_hash'])
        os.chmod(self.path, 0o600)

    def test_corrupt_body_index_or_missing_produced_block_refuses(self):
        for mode in ['checksum', 'index', 'gap', 'tip']:
            self.path = self.root / (mode + '.sqlite3')
            items = blocks([1, 2, 3])
            pinned = self.capture(items)
            with closing(sqlite3.connect(self.path)) as db, db:
                if mode == 'checksum': db.execute('UPDATE blocks SET body=? WHERE slot=?', (b'{}', number(1)))
                if mode == 'index': db.execute('UPDATE blocks SET parent=? WHERE slot=?', (number(0), number(2)))
                if mode == 'gap': db.execute('DELETE FROM blocks WHERE slot=?', (number(2),))
                if mode == 'tip': db.execute('DELETE FROM blocks WHERE slot=?', (number(3),))
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.read_all(pinned)

    def test_sqlite_rejects_oversized_stored_values_before_python_row_materialization(self):
        # Tiny injected limits exercise the real SQLite engine rejection. No
        # giant corrupt fixture or post-fetch Python allocation is needed.
        cap = 4096
        for column, query in [('body', 'SELECT body FROM blocks'),
                              ('network', 'SELECT network FROM state'),
                              ('hash', 'SELECT hash FROM blocks'),
                              ('slot', 'SELECT slot FROM state'),
                              ('aggregate-row', 'SELECT * FROM blocks')]:
            self.path = self.root / ('oversized-' + column + '.sqlite3')
            self.capture(blocks([1]))
            with closing(sqlite3.connect(self.path)) as db, db:
                if column == 'body': db.execute('UPDATE blocks SET body=?', (b'x' * (cap + 1),))
                if column == 'network': db.execute('UPDATE state SET network=?', (b'x' * (cap + 1),))
                if column == 'hash': db.execute('UPDATE blocks SET hash=?', ('x' * (cap + 1),))
                if column == 'slot': db.execute('UPDATE state SET slot=?', (b'x' * (cap + 1),))
                if column == 'aggregate-row':
                    # Neither individual field exceeds the cap, but the full
                    # record does. SQLite must bound the combined row too.
                    db.execute('UPDATE blocks SET body=?,hash=?',
                               (b'x' * (cap // 2 + 1), 'x' * (cap // 2 + 1)))
            with self.subTest(column=column), patch.object(archive, 'SQLITE_ROW_LIMIT', cap):
                with closing(archive.open_db(self.path, NETWORK)) as db:
                    self.assertEqual(db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH), cap)
                    materialized = []
                    db.row_factory = lambda _cursor, row: materialized.append(row) or row
                    if column == 'aggregate-row':
                        # SQLite's scalar limit alone does not reject this
                        # read. The real fixed projection must NULL the bad
                        # index field before Python receives the result row.
                        row = db.execute('SELECT ' + archive.BLOCK_ROW + ' FROM blocks').fetchone()
                        self.assertIsNone(row[2])
                        self.assertLess(sum(len(v) for v in row if isinstance(v, (bytes, str))), cap)
                    else:
                        with self.assertRaises(sqlite3.DataError): db.execute(query).fetchone()
                        self.assertEqual(materialized, [], 'oversized values must not reach a Python row')
                with self.assertRaises((ValueError, sqlite3.DataError)): Reader(self.path, NETWORK, NETWORK['genesis_hash'])
                with self.assertRaises((ValueError, sqlite3.DataError)):
                    Capture(self.path, NETWORK, NETWORK['genesis_hash'], target(blocks([2], after=1, height=1)))

    def test_sql_projections_bound_body_network_and_index_columns_before_python(self):
        for column, table, value, projection, position in [
            ('body', 'blocks', b'x' * (BLOCK_LIMIT + 1), archive.BLOCK_ROW, 5),
            ('network', 'state', b'x' * 4097, archive.STATE_ROW, 1),
            ('hash', 'blocks', 'x' * 45, archive.BLOCK_ROW, 2),
            ('previous', 'blocks', 'x' * 45, archive.BLOCK_ROW, 3),
            ('height', 'blocks', b'x' * 9, archive.BLOCK_ROW, 4),
            ('digest', 'blocks', b'x' * 33, archive.BLOCK_ROW, 6),
        ]:
            self.path = self.root / ('projected-' + column + '.sqlite3')
            self.capture(blocks([1]))
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute('UPDATE ' + table + ' SET ' + column + '=?', (value,))
            with self.subTest(column=column):
                with closing(archive.open_db(self.path, NETWORK)) as db:
                    materialized = []
                    db.row_factory = lambda _cursor, row: materialized.append(row) or row
                    row = db.execute('SELECT ' + projection + ' FROM ' + table).fetchone()
                    self.assertIsNone(row[position])
                    self.assertEqual(len(materialized), 1)
                    # The corrupt value was discarded inside SQLite; only
                    # bounded values and NULL reach Python's row factory.
                    self.assertNotIn(value, row)
                with self.assertRaises(ValueError): Reader(self.path, NETWORK, NETWORK['genesis_hash'])

    def test_missing_connection_length_limit_support_refuses_before_creating_a_file(self):
        with patch.object(archive.sqlite3, 'Connection', object):
            with self.assertRaisesRegex(ValueError, 'Python 3.11'):
                Capture(self.path, NETWORK, NETWORK['genesis_hash'], target(blocks([1])))
        self.assertFalse(self.path.exists())

    def test_text_projection_limits_use_bytes_including_nul_and_multibyte_suffixes(self):
        for index, (column, table, projection, position, limit) in enumerate([
            ('hash', 'blocks', archive.BLOCK_ROW, 2, 44),
            ('previous', 'blocks', archive.BLOCK_ROW, 3, 44),
            ('format', 'state', archive.STATE_ROW, 0, 128),
            ('hash', 'state', archive.STATE_ROW, 3, 44),
        ]):
            for case, value, expected in [
                ('nul', '1' * 32 + '\0' + 'x' * 4096, None),
                ('utf8-at-limit', 'é' * (limit // 2), 'é' * (limit // 2)),
                ('utf8-over-limit', 'é' * (limit // 2 + 1), None),
            ]:
                self.path = self.root / ('text-' + str(index) + '-' + case + '.sqlite3')
                self.capture(blocks([1]))
                with closing(sqlite3.connect(self.path)) as db, db:
                    db.execute('UPDATE ' + table + ' SET ' + column + '=?', (value,))
                with self.subTest(column=column, table=table, case=case):
                    with closing(archive.open_db(self.path, NETWORK)) as db:
                        row = db.execute('SELECT ' + projection + ' FROM ' + table).fetchone()
                        self.assertEqual(row[position], expected)
                    # Byte-bounded but invalid values must still fail the
                    # unchanged format/hash/index validation, never a page.
                    with self.assertRaises(ValueError): Reader(self.path, NETWORK, NETWORK['genesis_hash'])
        with closing(sqlite3.connect(':memory:')) as db:
            for position, limit in [(0, 64), (1, 1024)]:
                for value, expected in [('n\0' + 'x' * 4096, None),
                                        ('é' * (limit // 2), 'é' * (limit // 2)),
                                        ('é' * (limit // 2 + 1), None)]:
                    values = ['blocks', archive.SCHEMA['blocks']]
                    values[position] = value
                    row = db.execute('SELECT ' + archive.SCHEMA_ROW +
                                     ' FROM (SELECT ? AS name,? AS sql)', values).fetchone()
                    self.assertEqual(row[position], expected)

    def test_real_process_sigkill_before_and_after_sqlite_commit(self):
        child = r'''
import json,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from canonical_archive_store import Capture,encoded
data=json.loads(Path(sys.argv[2]).read_text())
with Capture(Path(data['path']),data['network'],data['network']['genesis_hash'],data['target']) as writer:
    writer.db.execute('PRAGMA cache_size=1')
    writer.append(encoded(data['page']))
    if data['commit']:writer.commit()
    Path(data['marker']).write_text('after-commit' if data['commit'] else 'before-commit')
    while True:time.sleep(1)
'''
        for committed in [False, True]:
            self.path = self.root / ('crash-' + str(committed) + '.sqlite3')
            first = blocks([1])
            old = self.capture(first)
            extra = blocks([2], after=1, height=1)
            extra[0]['block']['large_unknown_field'] = 'x' * (2 * 1024 * 1024)
            pinned = target(extra)
            marker, config = self.root / ('ready-' + str(committed)), self.root / ('child-' + str(committed) + '.json')
            config.write_bytes(encoded(dict(path=str(self.path), network=NETWORK, target=pinned,
                                           page=page(extra, pinned, 1), commit=committed, marker=str(marker))))
            process = subprocess.Popen([sys.executable, '-B', '-c', child, str(Path(__file__).parent), str(config)],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(marker.exists(), process.communicate(timeout=1) if process.poll() is not None else 'child deadline')
                process.kill()
                process.communicate(timeout=5)
                self.assertEqual(process.returncode, -signal.SIGKILL)
            finally:
                if process.poll() is None:
                    process.kill(); process.communicate(timeout=5)
            if committed:
                self.assertEqual(self.read_all(pinned), first + extra)
            else:
                # Read-only hot-journal recovery may refuse. An owned writer
                # open recovers SQLite, without resuming or publishing pages.
                try: self.assertEqual(self.read_all(old), first)
                except sqlite3.OperationalError: pass
                with Capture(self.path, NETWORK, NETWORK['genesis_hash'], pinned): pass
                self.assertEqual(self.read_all(old), first)
                with Reader(self.path, NETWORK, NETWORK['genesis_hash']) as reader:
                    self.assertEqual(reader.slot, 1)
                    with self.assertRaises(ValueError): reader.page(request(0, pinned, first=True))


if __name__ == '__main__':
    unittest.main()
