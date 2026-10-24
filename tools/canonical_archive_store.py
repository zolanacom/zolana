"""Preparation prototype: distinct, unfiltered full canonical RPC block storage.

Nothing here captures a host, configures ArchiveRPC, serves HTTP or prunes data.
The caller must independently obtain the trusted RPC genesis and exact finalized
target header, then stream existing getWalletCanonicalHistory *result* pages.
This preserves the operator-RPC trust model; checksums are not consensus proofs.

One capture is one SQLite transaction. Only a complete contiguous extension to
the pinned target is published. A failed capture rolls back; a killed writer's
hot journal can make a read-only open refuse until the next owned writer open
lets SQLite recover. No partial rows are usable as an absence result. Existing
committed readers keep their original snapshot. Blocks retain all parsed JSON
fields and transaction/metadata values, not original whitespace/escape spelling.
Python 3.11+ SQLite connection limits are required: corrupt stored rows must be
bounded by SQLite before they can become Python bytes, strings or tuples.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import urllib.parse

from gateway_archival import anchor, parameters
from history_retention import block_hash, natural

FORMAT = 'zolana-full-canonical-archive-prototype-v1'
PAGE_LIMIT = 16 * 1024 * 1024
BLOCK_LIMIT = 8 * 1024 * 1024
# Covers one maximum block body plus its bounded index/digest/record overhead.
# Applies to every stored value before Python materialization. Fixed projections
# below also bound each field: SQLite SELECTs do not always enforce a cumulative
# record limit when several individually valid values are fetched together.
SQLITE_ROW_LIMIT = BLOCK_LIMIT + 4096
APPLICATION_ID = 0x5A43414E
SCHEMA = {
    'state': 'CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL, network BLOB NOT NULL, slot BLOB NOT NULL, hash TEXT, height BLOB NOT NULL)',
    'blocks': 'CREATE TABLE blocks (slot BLOB PRIMARY KEY, parent BLOB NOT NULL, hash TEXT NOT NULL, previous TEXT NOT NULL, height BLOB NOT NULL, body BLOB NOT NULL, digest BLOB NOT NULL) WITHOUT ROWID',
}
# CASE keeps a malformed oversized column out of the Python result tuple. Keep
# its row (with NULL), so validation refuses corruption rather than skipping it.
BLOCK_ROW = ','.join([
    "CASE WHEN typeof(slot)='blob' AND length(slot)=8 THEN slot END",
    "CASE WHEN typeof(parent)='blob' AND length(parent)=8 THEN parent END",
    "CASE WHEN typeof(hash)='text' AND length(CAST(hash AS BLOB)) BETWEEN 32 AND 44 THEN hash END",
    "CASE WHEN typeof(previous)='text' AND length(CAST(previous AS BLOB)) BETWEEN 32 AND 44 THEN previous END",
    "CASE WHEN typeof(height)='blob' AND length(height)=8 THEN height END",
    "CASE WHEN typeof(body)='blob' AND length(body) BETWEEN 1 AND " + str(BLOCK_LIMIT) + " THEN body END",
    "CASE WHEN typeof(digest)='blob' AND length(digest)=32 THEN digest END",
])
STATE_ROW = ','.join([
    "CASE WHEN typeof(format)='text' AND length(CAST(format AS BLOB))<=128 THEN format END",
    "CASE WHEN typeof(network)='blob' AND length(network) BETWEEN 1 AND 4096 THEN network END",
    "CASE WHEN typeof(slot)='blob' AND length(slot)=8 THEN slot END",
    "CASE WHEN hash IS NULL OR (typeof(hash)='text' AND length(CAST(hash AS BLOB)) BETWEEN 32 AND 44) THEN hash END",
    "CASE WHEN typeof(height)='blob' AND length(height)=8 THEN height END",
])
SCHEMA_ROW = ("CASE WHEN length(CAST(name AS BLOB))<=64 THEN name END,"
              "CASE WHEN length(CAST(sql AS BLOB))<=1024 THEN sql END")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def decoded(raw, limit):
    check(type(raw) is bytes and 0 < len(raw) <= limit, 'bounded JSON bytes required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            check(key not in result, 'duplicate JSON field')
            result[key] = value
        return result
    def nonfinite(_):
        raise ValueError('nonfinite archive JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def number(value):
    check(natural(value), 'unsigned archive number required')
    return value.to_bytes(8, 'big')


def integer(value):
    check(type(value) is bytes and len(value) == 8, 'invalid stored unsigned number')
    return int.from_bytes(value, 'big')


def identity(network, genesis):
    check(type(network) is dict and set(network) == {'network', 'genesis_hash'} and
          type(network['network']) is list and len(network['network']) == 32 and
          all(type(v) is int and 0 <= v <= 255 for v in network['network']) and
          block_hash(genesis) and network['genesis_hash'] == genesis,
          'archive network and trusted RPC genesis must match')
    return decoded(encoded(network), 4096)


def local_file(path, create):
    path = Path(path)
    check(path.is_absolute() and path.resolve() == path, 'fixed real absolute archive path required')
    parent = path.parent
    meta = parent.lstat()
    check(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.geteuid() and
          stat.S_IMODE(meta.st_mode) == 0o700, 'archive parent must be owner-only')
    new = False
    if create and not os.path.lexists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        new = True
    meta = path.lstat()
    check(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid() and
          stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1,
          'archive file must be regular, single-link and owner-only')
    return path, new, (meta.st_dev, meta.st_ino)


def open_db(path, network, create=False):
    check(callable(getattr(sqlite3.Connection, 'setlimit', None)) and
          callable(getattr(sqlite3.Connection, 'getlimit', None)) and
          type(getattr(sqlite3, 'SQLITE_LIMIT_LENGTH', None)) is int,
          'Python 3.11+ SQLite stored-row limits required')
    path, new, file_id = local_file(path, create)
    uri = 'file:' + urllib.parse.quote(str(path), safe='/') + '?mode=' + ('rw' if create else 'ro')
    db = sqlite3.connect(uri, uri=True, isolation_level=None, timeout=1)
    try:
        # Set before the first SQL statement, including schema/state reads.
        # A post-fetch len() check alone would allocate a corrupt giant BLOB.
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, SQLITE_ROW_LIMIT)
        check(db.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == SQLITE_ROW_LIMIT,
              'exact SQLite stored-row limit unavailable')
        check((path.stat().st_dev, path.stat().st_ino) == file_id, 'archive file changed while opening')
        db.execute('PRAGMA trusted_schema=OFF')
        if new:
            db.execute('PRAGMA journal_mode=DELETE')
            db.execute('PRAGMA synchronous=FULL')
            db.execute('BEGIN IMMEDIATE')
            for sql in SCHEMA.values():
                db.execute(sql)
            db.execute('INSERT INTO state VALUES (1,?,?,?,?,?)',
                       (FORMAT, encoded(network), number(0), None, number(0)))
            db.execute('PRAGMA application_id=' + str(APPLICATION_ID))
            db.execute('PRAGMA user_version=1')
            db.execute('COMMIT')
            fd = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
        check(db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID and
              db.execute('PRAGMA user_version').fetchone()[0] == 1 and
              dict(db.execute("SELECT " + SCHEMA_ROW + " FROM sqlite_schema "
                              "WHERE name NOT LIKE 'sqlite_%' LIMIT 3")) == SCHEMA,
              'distinct canonical archive schema required')
        if create:
            check(db.execute('PRAGMA journal_mode').fetchone()[0] == 'delete', 'rollback journal required')
            db.execute('PRAGMA synchronous=FULL')
        else:
            db.execute('PRAGMA query_only=ON')
        return db
    except BaseException:
        db.close()
        raise


def block_body(slot, block, previous_slot, previous_hash, previous_height):
    check(type(block) is dict and natural(slot) and slot > previous_slot and
          block.get('parentSlot') == previous_slot and type(block.get('parentSlot')) is int and
          block_hash(block.get('blockhash')) and block_hash(block.get('previousBlockhash')) and
          (previous_hash is None or block['previousBlockhash'] == previous_hash) and
          natural(block.get('blockHeight')) and block['blockHeight'] == previous_height + 1 and
          type(block.get('transactions')) is list, 'incomplete canonical block link or body')
    raw = encoded(block)
    check(len(raw) <= BLOCK_LIMIT, 'canonical block exceeds bound')
    for item in block['transactions']:
        check(type(item) is dict and type(item.get('transaction')) is list and
              len(item['transaction']) == 2 and item['transaction'][1] == 'base64' and
              type(item['transaction'][0]) is str and item['transaction'][0] and
              type(item.get('meta')) is dict and 'err' in item['meta'],
              'full transaction and execution metadata required')
        payload = base64.b64decode(item['transaction'][0], validate=True)
        check(base64.b64encode(payload).decode() == item['transaction'][0], 'canonical base64 transaction required')
    return raw


def row_block(row):
    check(row is not None and len(row) == 7, 'committed canonical block unavailable')
    slot, parent, blockhash, previous, height, raw, digest = row
    check(type(raw) is bytes and type(digest) is bytes and len(digest) == 32 and
          hashlib.sha256(raw).digest() == digest, 'stored canonical body checksum mismatch')
    body = decoded(raw, BLOCK_LIMIT)
    check(type(body) is dict, 'stored canonical body must be an object')
    slot, parent, height = integer(slot), integer(parent), integer(height)
    check(body.get('parentSlot') == parent and body.get('blockHeight') == height and
          body.get('blockhash') == blockhash and body.get('previousBlockhash') == previous,
          'stored canonical index differs from body')
    block_body(slot, body, parent, previous, height - 1)
    return slot, body


def state(db, network):
    rows = db.execute('SELECT ' + STATE_ROW + ' FROM state LIMIT 2').fetchall()
    check(len(rows) == 1 and rows[0][0] == FORMAT and decoded(rows[0][1], 4096) == network,
          'archive network or committed state differs')
    _, _, slot, blockhash, height = rows[0]
    slot, height = integer(slot), integer(height)
    last = db.execute('SELECT ' + BLOCK_ROW + ' FROM blocks ORDER BY slot DESC LIMIT 1').fetchone()
    if slot == 0:
        check(last is None and blockhash is None and height == 0, 'invalid empty canonical prefix')
    else:
        actual_slot, body = row_block(last)
        check(actual_slot == slot and body['blockhash'] == blockhash and body['blockHeight'] == height,
              'committed canonical tip differs')
    return slot, blockhash, height


class Capture:
    """Owned append transaction; caller must explicitly commit a complete target."""
    def __init__(self, path, network, genesis, target):
        self.network = identity(network, genesis)
        self.target = decoded(encoded(anchor(target, target['slot'])), 4096)
        check(block_hash(self.target['blockhash']), 'exact finalized target hash required')
        self.db = open_db(path, self.network, create=True)
        self.closed = False
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.slot, self.hash, self.height = state(self.db, self.network)
            check(self.target['slot'] > self.slot and self.target['block_height'] > self.height,
                  'capture must extend the committed prefix; replay refused')
            self.complete, self.pages = False, 0
        except BaseException:
            self.close()
            raise

    def append(self, raw_page):
        try:
            self._append(raw_page)
        except BaseException:
            self.close()
            raise

    def _append(self, raw_page):
        check(not self.closed and not self.complete and self.pages < 65536, 'capture already complete or bounded run exhausted')
        page = decoded(raw_page, PAGE_LIMIT)
        check(type(page) is dict and set(page) == {'network', 'anchor', 'after_slot', 'next_slot', 'complete', 'blocks'} and
              identity(page['network'], self.network['genesis_hash']) == self.network and
              anchor(page['anchor'], self.target['slot']) == self.target and
              type(page['after_slot']) is int and page['after_slot'] == self.slot and
              type(page['complete']) is bool and type(page['blocks']) is list and
              1 <= len(page['blocks']) <= 16, 'changed or incomplete canonical capture page')
        for item in page['blocks']:
            check(type(item) is dict and set(item) == {'slot', 'block'} and
                  natural(item['slot']) and item['slot'] <= self.target['slot'], 'invalid canonical page block')
            check(len(encoded(item)) <= BLOCK_LIMIT, 'canonical block envelope exceeds bound')
            slot, block = item['slot'], item['block']
            body = block_body(slot, block, self.slot, self.hash, self.height)
            self.db.execute('INSERT INTO blocks VALUES (?,?,?,?,?,?,?)', (number(slot), number(self.slot),
                block['blockhash'], block['previousBlockhash'], number(block['blockHeight']), body, hashlib.sha256(body).digest()))
            self.slot, self.hash, self.height = slot, block['blockhash'], block['blockHeight']
        check(type(page['next_slot']) is int and page['next_slot'] == self.slot and
              page['complete'] == (self.slot == self.target['slot']), 'incomplete canonical page cursor')
        self.complete, self.pages = page['complete'], self.pages + 1
        if self.complete:
            check(self.hash == self.target['blockhash'] and self.height == self.target['block_height'],
                  'capture does not reach the exact finalized target')

    def commit(self):
        try:
            check(not self.closed and self.complete, 'cannot publish incomplete canonical capture')
            self.db.execute('UPDATE state SET slot=?,hash=?,height=? WHERE id=1',
                            (number(self.slot), self.hash, number(self.height)))
            self.db.execute('COMMIT')
        finally:
            self.close()

    def close(self):
        if not self.closed:
            self.db.close()  # SQLite rolls back any uncommitted capture.
            self.closed = True

    def __enter__(self): return self
    def __exit__(self, *_): self.close()


class Reader:
    """Read-only pinned committed snapshot; no upstream or network transport."""
    def __init__(self, path, network, genesis):
        self.network = identity(network, genesis)
        self.db = open_db(path, self.network)
        try:
            self.db.execute('BEGIN')
            self.slot, self.hash, self.height = state(self.db, self.network)
        except BaseException:
            self.db.close()
            raise

    def page(self, request):
        after, target, token = parameters(request)
        check(type(request.get('id')) in (int, str) and len(str(request['id'])) <= 64,
              'bounded canonical request identity required')
        check(target <= self.slot, 'target exceeds complete committed canonical prefix')
        _, end = row_block(self.db.execute('SELECT ' + BLOCK_ROW + ' FROM blocks WHERE slot=?', (number(target),)).fetchone())
        pinned = dict(slot=target, blockhash=end['blockhash'], block_height=end['blockHeight'])
        check(token is None or token == pinned, 'canonical target anchor changed')
        previous_hash, previous_height = None, 0
        if after:
            _, previous = row_block(self.db.execute('SELECT ' + BLOCK_ROW + ' FROM blocks WHERE slot=?', (number(after),)).fetchone())
            previous_hash, previous_height = previous['blockhash'], previous['blockHeight']
        page = dict(network=self.network, anchor=pinned, after_slot=after, next_slot=after,
                    complete=after == target, blocks=[])
        rows = self.db.execute('SELECT ' + BLOCK_ROW + ' FROM blocks WHERE slot>? AND slot<=? ORDER BY slot LIMIT 16',
                               (number(after), number(target)))
        cursor = after
        for row in rows:
            slot, block = row_block(row)
            block_body(slot, block, cursor, previous_hash, previous_height)
            item = dict(slot=slot, block=block)
            check(len(encoded(item)) <= BLOCK_LIMIT, 'canonical block envelope exceeds bound')
            candidate = dict(page, blocks=page['blocks'] + [item], next_slot=slot, complete=slot == target)
            if len(encoded(dict(jsonrpc='2.0', id=request['id'], result=candidate))) > PAGE_LIMIT:
                break
            page = candidate
            cursor, previous_hash, previous_height = slot, block['blockhash'], block['blockHeight']
        check(after == target or page['blocks'], 'complete canonical history is unavailable')
        return encoded(dict(jsonrpc='2.0', id=request['id'], result=page))

    def close(self): self.db.close()
    def __enter__(self): return self
    def __exit__(self, *_): self.close()
