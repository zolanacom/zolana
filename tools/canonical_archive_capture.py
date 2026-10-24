"""Bounded incremental full-canonical capture from operator-owned RPC transports.

Sources are fixed callables with the Operator.forward(raw, timeout=...) contract;
they are configured by the operator, never by an archive client or stored row.
Only four finalized read methods are emitted. No RPC is retried. Each invocation
pins one target, and each <=16-block extension commits its own complete target
through the existing Capture transaction. A result short of the invocation target
is explicitly bounded progress, never evidence of absence past the committed tip.
This retains operator-RPC trust, not independent cryptographic finality proof.
The caller must schedule capture within the shared RPC capacity budget, supply
timeout-honoring transports and keep progress observers bounded. There is no
background daemon, activation, pruning or caller-selected source endpoint here.
"""
import math
import json
import os
from pathlib import Path
import shutil
import stat
import time

from canonical_archive_store import (BLOCK_LIMIT, PAGE_LIMIT, Capture, decoded,
                                     encoded, identity, local_file, open_db, state)
from canonical_archive_backend import HEADER, FULL
from gateway_archival import anchor
from history_retention import block_hash, natural

MAX_DATABASE_BYTES = 1024 ** 4
MAX_BATCHES = 65536


def check(value, reason):
    if not value:
        raise ValueError(reason)


def remaining(deadline):
    left = deadline - time.monotonic()
    check(left > 0, 'canonical capture deadline exceeded')
    return left


def seconds(value, maximum):
    check(type(value) in (int, float) and math.isfinite(value) and
          0 < value <= maximum, 'positive bounded capture deadline required')
    return value


def same_json(left, right):
    # JSON spelling distinguishes bool/int values unlike Python dict equality.
    options = dict(sort_keys=True, separators=(',', ':'), allow_nan=False)
    return json.dumps(left, **options) == json.dumps(right, **options)


def read(source, method, params, deadline):
    """One fixed read and one shared remaining deadline; never a retry."""
    request = encoded(dict(jsonrpc='2.0', id=1, method=method, params=params))
    raw = source(request, timeout=min(6, remaining(deadline)))
    remaining(deadline)
    value = decoded(raw, PAGE_LIMIT)
    check(type(value) is dict and value.get('jsonrpc') == '2.0' and
          type(value.get('id')) is int and value['id'] == 1 and
          value.get('error') is None and 'result' in value,
          'canonical capture RPC unavailable')
    return value['result']


def all_reads(sources, method, params, deadline):
    return [read(source, method, params, deadline) for source in sources]


def header(sources, slot, deadline):
    values = all_reads(sources, 'getBlock', [slot, HEADER], deadline)
    pins = []
    for value in values:
        check(type(value) is dict and natural(value.get('parentSlot')) and
              value['parentSlot'] < slot and block_hash(value.get('previousBlockhash')) and
              natural(value.get('blockHeight')) and value['blockHeight'] > 0 and
              block_hash(value.get('blockhash')), 'finalized capture header unavailable')
        pins.append(dict(slot=slot, blockhash=value['blockhash'],
                         block_height=value['blockHeight']))
    check(all(same_json(pin, pins[0]) for pin in pins), 'operator finalized anchors differ')
    return anchor(pins[0], slot)


def ranges(sources, after, target, deadline):
    values = all_reads(sources, 'getBlocksWithLimit',
                       [after + 1, 16, {'commitment': 'finalized'}], deadline)
    prefixes = []
    for value in values:
        check(type(value) is list and len(value) <= 16 and
              all(natural(slot) and slot > after for slot in value) and
              all(a < b for a, b in zip(value, value[1:])),
              'invalid produced-slot capture range')
        prefixes.append([slot for slot in value if slot <= target])
    check(all(same_json(value, prefixes[0]) for value in prefixes),
          'operator produced-slot prefixes differ')
    check(prefixes[0], 'fixed canonical capture target is incomplete')
    return prefixes[0]


def file_bound(path, maximum):
    if os.path.lexists(path):
        local_file(path, False)
        check(path.stat().st_size <= maximum, 'canonical database exceeds byte cap')


def disk_budget(path, minimum, batch_blocks):
    # Reserve worst-case bounded block bodies, rollback/index overhead and the
    # explicit operator floor. Never infer that a free-space check reserves it.
    reserve = batch_blocks * (BLOCK_LIMIT + 4096) + 4 * 1024 * 1024
    check(shutil.disk_usage(path.parent).free >= minimum + reserve,
          'canonical capture disk floor or batch reserve unavailable')


def database_budget(db, maximum, deadline):
    remaining(deadline)
    db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
    size = db.execute('PRAGMA page_size').fetchone()[0]
    pages = db.execute('PRAGMA page_count').fetchone()[0]
    cap = maximum // size
    check(cap > 0 and pages <= cap and
          db.execute('PRAGMA max_page_count=' + str(cap)).fetchone()[0] == cap,
          'canonical database page cap unavailable')
    remaining(deadline)


def sync_closed(path):
    # Capture uses DELETE/FULL and closes before this extra file/parent fsync.
    checked, _, expected = local_file(path, False)
    fd = os.open(checked, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        check(stat.S_ISREG(meta.st_mode) and (meta.st_dev, meta.st_ino) == expected,
              'canonical database changed before fsync')
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def capture(path, network, sources, *, target=None, batch_blocks=16,
            max_batches=64, timeout=120, batch_timeout=15,
            max_database_bytes=8 * 1024 ** 3, min_free_bytes=1024 ** 3,
            progress=None):
    """Append bounded complete prefixes; safely resume from SQLite's committed tip.

    ``target`` is either None (pin the minimum finalized root across sources) or
    an exact {slot,blockhash,block_height} anchor. A new invocation may pin a newer
    target; an already selected target never moves within an invocation. Returns
    status ``complete`` only at that target, otherwise ``bounded``. Exceptions can
    leave earlier complete batches committed, but never commit the failed batch.
    The optional callback receives only fixed event/numeric progress after fsync;
    callback failures do not change capture or cause retries.
    """
    started = time.monotonic()
    deadline = started + seconds(timeout, 300)
    seconds(batch_timeout, 15)
    check(type(batch_blocks) is int and 1 <= batch_blocks <= 16 and
          type(max_batches) is int and 1 <= max_batches <= MAX_BATCHES,
          'bounded canonical batch size/count required')
    check(type(max_database_bytes) is int and 1024 ** 2 <= max_database_bytes <= MAX_DATABASE_BYTES and
          type(min_free_bytes) is int and 0 <= min_free_bytes <= MAX_DATABASE_BYTES,
          'bounded database size and disk floor required')
    check(type(sources) in (list, tuple) and 1 <= len(sources) <= 3 and
          all(callable(source) for source in sources), 'one to three fixed operator transports required')
    check(progress is None or callable(progress), 'numeric progress callback required')
    network = identity(network, network['genesis_hash'])
    path = Path(path)
    check(path.is_absolute() and path.resolve() == path, 'fixed real absolute capture path required')
    initial = min(deadline, time.monotonic() + batch_timeout)
    file_bound(path, max_database_bytes)
    disk_budget(path, min_free_bytes, batch_blocks)
    # An owned rw open lets SQLite recover an interrupted writer's hot journal.
    # A read-only observer is never allowed to reinterpret partial journal state.
    db = open_db(path, network, create=True)
    try:
        database_budget(db, max_database_bytes, initial)
        slot, blockhash, height = state(db, network)
    finally:
        db.close()
    remaining(deadline)
    initial_slot = slot
    check(all(value == network['genesis_hash'] for value in
              all_reads(sources, 'getGenesisHash', [], initial)), 'operator genesis differs')
    roots = all_reads(sources, 'getSlot', [{'commitment': 'finalized'}], initial)
    check(all(natural(root) and root > 0 for root in roots), 'positive finalized roots required')
    if target is not None:
        check(type(target) is dict and natural(target.get('slot')) and target['slot'] > 0,
              'exact positive fixed target required')
        target = decoded(encoded(anchor(target, target['slot'])), 4096)
        check(block_hash(target['blockhash']), 'exact fixed target hash required')
        check(target['slot'] <= min(roots), 'fixed target is not finalized on every source')
    observed = header(sources, min(roots) if target is None else target['slot'], initial)
    check(target is None or same_json(target, observed), 'fixed target anchor differs')
    target = observed
    check(target['slot'] >= slot, 'capture target rolls back committed prefix')
    batches = blocks = 0
    while slot < target['slot'] and batches < max_batches:
        batch_deadline = min(deadline, time.monotonic() + batch_timeout)
        file_bound(path, max_database_bytes)
        disk_budget(path, min_free_bytes, batch_blocks)
        check(all(value == network['genesis_hash'] for value in
                  all_reads(sources, 'getGenesisHash', [], batch_deadline)), 'operator genesis differs')
        check(same_json(header(sources, target['slot'], batch_deadline), target),
              'fixed finalized target changed during capture')
        if slot:
            check(same_json(header(sources, slot, batch_deadline),
                            dict(slot=slot, blockhash=blockhash, block_height=height)),
                  'committed canonical tip differs from operator')
        selected = ranges(sources, slot, target['slot'], batch_deadline)[:batch_blocks]
        items = []
        for current in selected:
            bodies = all_reads(sources, 'getBlock', [current, FULL], batch_deadline)
            check(type(bodies[0]) is dict and
                  all(same_json(body, bodies[0]) for body in bodies),
                  'operator full canonical block/metadata differs')
            item = dict(slot=current, block=bodies[0])
            check(len(encoded(item)) <= BLOCK_LIMIT, 'full canonical block exceeds bound')
            # Leave room for the bounded page envelope/anchor. A large full
            # block reduces this transaction's count, never drops a body.
            if len(encoded(items + [item])) + 4096 > PAGE_LIMIT:
                break
            items.append(item)
        check(items, 'canonical capture page cannot fit a complete block')
        endpoint = header(sources, items[-1]['slot'], batch_deadline)
        with Capture(path, network, network['genesis_hash'], endpoint) as writer:
            database_budget(writer.db, max_database_bytes, batch_deadline)
            check((writer.slot, writer.hash, writer.height) == (slot, blockhash, height),
                  'concurrent canonical writer changed committed prefix')
            raw_page = encoded(dict(network=network, anchor=endpoint, after_slot=slot,
                                    next_slot=endpoint['slot'], complete=True, blocks=items))
            check(len(raw_page) <= PAGE_LIMIT, 'canonical capture batch exceeds page bound')
            writer.append(raw_page)
            remaining(batch_deadline)
            file_bound(path, max_database_bytes)
            disk_budget(path, min_free_bytes, batch_blocks)
            writer.commit()
        sync_closed(path)
        remaining(batch_deadline)
        file_bound(path, max_database_bytes)
        slot, blockhash, height = endpoint['slot'], endpoint['blockhash'], endpoint['block_height']
        batches += 1
        blocks += len(items)
        if progress is not None:
            try:
                progress(dict(event='canonical_capture_commit', slot=slot, height=height,
                              target_slot=target['slot'], batches=batches, blocks=blocks,
                              elapsed_ms=round((time.monotonic() - started) * 1000)))
            except Exception:
                pass
    remaining(deadline)
    check(slot != target['slot'] or (blockhash == target['blockhash'] and
                                   height == target['block_height']),
          'complete committed target differs')
    return dict(status='complete' if slot == target['slot'] else 'bounded',
                network=network, target=target, initial_slot=initial_slot,
                committed=(None if slot == 0 else dict(slot=slot, blockhash=blockhash, block_height=height)),
                batches=batches, blocks=blocks, database_bytes=path.stat().st_size,
                elapsed_ms=round((time.monotonic() - started) * 1000))
