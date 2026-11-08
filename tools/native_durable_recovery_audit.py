"""Bounded read-only acceptance helpers for a NEW disposable LOCAL-093 fixture.

Trusted operator RPC evidence, not a light-client/Orchard proof implementation.
No SSH, wallet/key reads, submissions, service actions, retries or listeners.
"""
import base64
import hashlib
import math
import json
import os
from pathlib import Path
import stat
import struct
import time
from types import SimpleNamespace
import urllib.parse
import urllib.request

from canonical_archive_store import (Capture, Reader, decoded, encoded, identity,
                                     PAGE_LIMIT, BLOCK_LIMIT)
from canonical_archive_backend import CanonicalStoreRPC, HEADER, FULL, configuration
from gateway_archival import ArchiveRPC, anchor
from history_retention import natural
from native_fast_cash_audit import (PROGRAM, POOL, PALLAS_BASE, ALPHABET, b58,
                                   un58, pda, Cursor)

MAX_BLOCKS = 4096
MAX_FILE = 64 * 1024 * 1024
POOL_BYTES = 25728


def check(value, reason):
    if not value:
        raise ValueError(reason)


def same_json(left, right):
    options = dict(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    return json.dumps(left, **options) == json.dumps(right, **options)


def deadline_after(timeout):
    check(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 180,
          'positive bounded audit timeout required')
    return time.monotonic() + timeout


def remaining(deadline):
    value = deadline - time.monotonic()
    check(value > 0, 'native durable audit deadline exceeded')
    return value


def public_bytes(value, size):
    check(type(value) is str and 1 <= len(value) <= 100 and
          all(c in ALPHABET for c in value), 'invalid public base58 identity')
    raw = un58(value)
    check(len(raw) == size and b58(raw) == value, 'noncanonical public base58 identity')
    return raw


class RpcRefusal(ValueError):
    def __init__(self, code):
        super().__init__('read-only RPC refused')
        self.code = code


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('audit RPC redirect refused')


class Rpc:
    def __init__(self, url):
        p = urllib.parse.urlsplit(url)
        check(p.scheme == 'http' and p.hostname == '127.0.0.1' and p.port and
              not p.username and not p.password and p.path in ('', '/') and
              not p.query and not p.fragment, 'fixed loopback audit RPC required')
        self.url = url
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, params, deadline):
        check(type(params) is list, 'fixed read-only parameters required')
        allowed = ((method == 'getGenesisHash' and params == []) or
                   (method == 'getSlot' and same_json(params, [{'commitment': 'finalized'}])) or
                   (method == 'getBlocksWithLimit' and len(params) == 3 and
                    natural(params[0]) and params[0] > 0 and type(params[1]) is int and
                    params[1] == 16 and configuration(params[2], {'commitment': 'finalized'})) or
                   (method == 'getBlock' and len(params) == 2 and natural(params[0]) and
                    params[0] > 0 and (configuration(params[1], HEADER) or configuration(params[1], FULL))) or
                   (method == 'getTransaction' and len(params) == 2 and
                    configuration(params[1], {'encoding': 'base64', 'commitment': 'finalized',
                                              'maxSupportedTransactionVersion': 1})) or
                   (method == 'getAccountInfo' and same_json(params, [b58(POOL), {'encoding': 'base64', 'commitment': 'finalized'}])) or
                   (method == 'getProgramAccounts' and same_json(params, [b58(PROGRAM), {'encoding': 'base64', 'commitment': 'finalized', 'withContext': True}])))
        check(allowed, 'non-fixed or non-read audit RPC denied')
        if method == 'getTransaction':
            public_bytes(params[0], 64)
        request = urllib.request.Request(self.url, encoded(dict(jsonrpc='2.0', id=1, method=method, params=params)),
                                         {'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=min(6, remaining(deadline))) as response:
            body = bytearray()
            while True:
                remaining(deadline)
                chunk = response.read1(min(65536, PAGE_LIMIT + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                check(len(body) <= PAGE_LIMIT, 'audit RPC body exceeds bound')
        remaining(deadline)
        value = decoded(bytes(body), PAGE_LIMIT)
        check(type(value) is dict and value.get('jsonrpc') == '2.0' and
              type(value.get('id')) is int and value['id'] == 1, 'audit RPC envelope differs')
        if value.get('error') is not None:
            error = value['error']
            check(type(error) is dict and type(error.get('code')) is int, 'malformed RPC refusal')
            raise RpcRefusal(error['code'])
        check('result' in value, 'audit RPC result missing')
        return value['result']


def peers_rpc(peers, network, deadline):
    network = identity(network, network['genesis_hash'])
    check(type(peers) is list and len(peers) == 3, 'exact three pinned peers required')
    result, seen = [], set()
    for peer in peers:
        check(type(peer) is dict, 'pinned peer object required')
        key = peer.get('identity')
        public_bytes(key, 32)
        check(key not in seen and type(peer.get('rpc')) is str, 'distinct fixed peer required')
        seen.add(key)
        url = peer['rpc'] if peer['rpc'].startswith('http://') else 'http://' + peer['rpc']
        rpc = Rpc(url)
        check(rpc.call('getGenesisHash', [], deadline) == network['genesis_hash'], 'peer genesis differs')
        result.append((key, rpc))
    return result


def private_directory(path, create=False):
    check(path.is_absolute() and path.resolve() == path, 'real absolute audit directory required')
    if create:
        path.mkdir(mode=0o700)
    m = path.lstat()
    check(stat.S_ISDIR(m.st_mode) and m.st_uid == os.geteuid() and
          stat.S_IMODE(m.st_mode) == 0o700, 'private owned audit directory required')


def file_sha(path, maximum=MAX_FILE):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        m = os.fstat(source.fileno())
        check(stat.S_ISREG(m.st_mode) and m.st_uid == os.geteuid() and m.st_nlink == 1 and
              stat.S_IMODE(m.st_mode) == 0o600 and 0 < m.st_size <= maximum, 'unsafe audit file')
        digest, total = hashlib.sha256(), 0
        while True:
            raw = source.read(65536)
            if not raw:
                break
            total += len(raw)
            check(total <= maximum, 'audit file exceeds bound')
            digest.update(raw)
        check(total == m.st_size == os.fstat(source.fileno()).st_size, 'audit file changed')
        return digest.hexdigest()


def add_block_digest(digest, item):
    raw = encoded(item)
    check(len(raw) <= BLOCK_LIMIT, 'full canonical block exceeds bound')
    digest.update(len(raw).to_bytes(8, 'little'))
    digest.update(raw)


def capture_full_history(root, peers, network, timeout=120):
    """Capture all produced blocks 1..fixed finalized E; do not append/retry."""
    deadline = deadline_after(timeout)
    root = Path(root)
    private_directory(root)
    directory = root / 'canonical'
    if not os.path.lexists(directory):
        private_directory(directory, create=True)
    private_directory(directory)
    path = directory / 'full-history.sqlite3'
    check(not os.path.lexists(path), 'canonical capture must be fresh; no append/retry')
    network = identity(network, network['genesis_hash'])
    sources = peers_rpc(peers, network, deadline)
    roots = [rpc.call('getSlot', [{'commitment': 'finalized'}], deadline) for _, rpc in sources]
    check(all(natural(s) and s > 0 for s in roots), 'positive finalized roots required')
    target = min(roots)
    headers = [rpc.call('getBlock', [target, HEADER], deadline) for _, rpc in sources]
    check(all(type(h) is dict for h in headers), 'fixed finalized capture header unavailable')
    pinned = anchor(dict(slot=target, blockhash=headers[0].get('blockhash'), block_height=headers[0].get('blockHeight')), target)
    check(all(h.get('blockhash') == pinned['blockhash'] and h.get('blockHeight') == pinned['block_height'] for h in headers), 'peer finalized capture anchors differ')
    digest, count, after = hashlib.sha256(), 0, 0
    with Capture(path, network, network['genesis_hash'], pinned) as capture:
        page_size = capture.db.execute('PRAGMA page_size').fetchone()[0]
        maximum = MAX_FILE // page_size
        check(capture.db.execute('PRAGMA max_page_count=' + str(maximum)).fetchone()[0] <= maximum, 'SQLite file cap could not be installed')
        while after < target:
            remaining(deadline)
            ranges = [rpc.call('getBlocksWithLimit', [after + 1, 16, {'commitment': 'finalized'}], deadline) for _, rpc in sources]
            for slots in ranges:
                check(type(slots) is list and len(slots) <= 16 and
                      all(natural(s) and s > after for s in slots) and
                      all(a < b for a, b in zip(slots, slots[1:])), 'peer produced-slot ranges differ')
            prefixes = [[s for s in slots if s <= target] for slots in ranges]
            slots = prefixes[0]
            check(all(same_json(prefix, slots) for prefix in prefixes), 'peer produced-slot ranges differ')
            check(slots and count + len(slots) <= MAX_BLOCKS, 'canonical capture is incomplete or exceeds produced-block bound')
            items = []
            for slot in slots:
                bodies = [rpc.call('getBlock', [slot, FULL], deadline) for _, rpc in sources]
                check(type(bodies[0]) is dict and all(same_json(b, bodies[0]) for b in bodies), 'peer full canonical block/metadata differs')
                item = dict(slot=slot, block=bodies[0])
                add_block_digest(digest, item)
                items.append(item)
            capture.append(encoded(dict(network=network, anchor=pinned, after_slot=after,
                                        next_slot=slots[-1], complete=slots[-1] == target, blocks=items)))
            count += len(slots)
            after = slots[-1]
            check(path.stat().st_size <= MAX_FILE, 'canonical file exceeds bound')
        remaining(deadline)
        capture.commit()
    # R3 commit is closed/FULL-synchronous; also explicitly fsync file and its
    # parent before returning the independent digest for Rust policy binding.
    with path.open('rb') as source:
        os.fsync(source.fileno())
    for parent in [directory, root]:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    remaining(deadline)
    closed_sha = file_sha(path)
    remaining(deadline)
    return dict(path=str(path), relative_path='canonical/full-history.sqlite3', file_sha256=closed_sha,
                through_slot=target, through_blockhash=pinned['blockhash'], anchor=pinned,
                network=network, produced_blocks=count, canonical_blocks_sha256=digest.hexdigest())


def account_bytes(account):
    check(type(account) is dict and account.get('owner') == b58(PROGRAM) and
          account.get('executable') is False and natural(account.get('lamports')) and
          type(account.get('data')) is list and len(account['data']) == 2 and
          account['data'][1] == 'base64' and type(account['data'][0]) is str and
          len(account['data'][0]) <= 2 * POOL_BYTES, 'invalid native account envelope')
    raw = base64.b64decode(account['data'][0], validate=True)
    check(base64.b64encode(raw).decode() == account['data'][0], 'noncanonical native account base64')
    return raw


def stable_pool(raw, context, expected):
    check(len(raw) == POOL_BYTES and raw[:8] == b'NPOOL004' and
          raw[8:40] == bytes(expected['network']), 'native V4 pool domain differs')
    floor, backing, count = struct.unpack_from('<QQQ', raw, 40)
    check(count < 2**32 and count % 2 == 0, 'invalid native note count')
    for level in range(32):
        node = raw[64 + level * 32:96 + level * 32]
        check((int.from_bytes(node, 'little') < PALLAS_BASE) if count & (1 << level) else node == bytes(32), 'noncanonical native frontier')
    length = int.from_bytes(raw[1088:1092], 'little')
    check(60 <= length <= 24636 and raw[1092 + length:] == bytes(POOL_BYTES - 1092 - length), 'native checkpoint length/padding differs')
    history = raw[1092:1092 + length]
    check(history[:8] == b'ZOLANCH1' and history[8:10] == b'\1\0' and
          history[10:26] == b'ZolanaSlotRoots1' and history[26:58] == bytes(expected['network']), 'native checkpoint domain differs')
    entries = int.from_bytes(history[58:60], 'little')
    check(0 < entries <= 512 and length == 60 + entries * 48, 'native checkpoint count differs')
    previous = None
    for offset in range(60, length, 48):
        slot, notes = struct.unpack_from('<QQ', history, offset)
        root = history[offset + 16:offset + 48]
        check(notes % 2 == 0 and notes <= count and root != bytes(32) and
              int.from_bytes(root, 'little') < PALLAS_BASE, 'invalid native checkpoint')
        if previous:
            old_slot, old_notes, old_root = previous
            check(slot > old_slot and notes >= old_notes and ((notes == old_notes) == (root == old_root)), 'native checkpoints do not progress')
        previous = (slot, notes, root)
    check(previous[0] == context and previous[1] == count and
          previous[0] - struct.unpack_from('<Q', history, 60)[0] < 512, 'native checkpoint does not bind finalized context')
    observed = dict(note_count=count, backing=backing, root=list(previous[2]), network=list(raw[8:40]), rent_floor=floor, slot_anchors=True)
    check(same_json(observed, expected), 'stable native pool fields differ from initial main audit')
    return hashlib.sha256(raw[:1088]).hexdigest()


def audit_native(peers, expected_native_state, network, timeout=60, *, expected_pool_prefix_sha256=None):
    deadline = deadline_after(timeout)
    expected = decoded(encoded(expected_native_state), PAGE_LIMIT)
    check(type(expected) is dict and set(expected) == {'accounts', 'pool', 'permanent_nullifiers'} and
          type(expected['accounts']) is list and type(expected['pool']) is dict and
          expected['permanent_nullifiers'] == 8 and expected['pool'].get('slot_anchors') is True and
          expected['pool'].get('network') == network['network'], 'exact main V4 native state required')
    sources = peers_rpc(peers, network, deadline)
    reports, prefixes = [], []
    for key, rpc in sources:
        scanned = rpc.call('getProgramAccounts', [b58(PROGRAM), {'encoding': 'base64', 'commitment': 'finalized', 'withContext': True}], deadline)
        check(type(scanned) is dict and type(scanned.get('value')) is list and len(scanned['value']) == 9, 'exact native pool plus eight permanent markers required')
        response = rpc.call('getAccountInfo', [b58(POOL), {'encoding': 'base64', 'commitment': 'finalized'}], deadline)
        check(type(response) is dict and type(response.get('context')) is dict and natural(response['context'].get('slot')) and response.get('value') is not None, 'finalized pool context missing')
        context = response['context']['slot']
        accounts, seen, pool_digest, markers = [], set(), None, 0
        for item in scanned['value']:
            check(type(item) is dict and type(item.get('pubkey')) is str and item['pubkey'] not in seen, 'duplicate native account')
            address = item['pubkey']; public_bytes(address, 32); seen.add(address)
            account = response['value'] if address == b58(POOL) else item.get('account')
            raw = account_bytes(account)
            if address == b58(POOL):
                pool_digest = stable_pool(raw, context, expected['pool'])
                check(account['lamports'] >= expected['pool']['rent_floor'] + expected['pool']['backing'], 'native pool backing is underfunded')
                data_hash = None
            else:
                check(len(raw) == 40 and raw[:8] == b'NSPENT01' and b58(pda([b'native-payment-spent-v1', POOL, raw[8:]])) == address, 'permanent marker data/address differs')
                markers += 1
                data_hash = b58(hashlib.sha256(raw).digest())
            accounts.append(dict(address=address, lamports=account['lamports'], data_sha256=data_hash))
        accounts.sort(key=lambda a: public_bytes(a['address'], 32))
        observed = dict(accounts=accounts, pool=expected['pool'], permanent_nullifiers=markers)
        check(pool_digest is not None and same_json(observed, expected), 'exact native account/marker state differs')
        check(expected_pool_prefix_sha256 is None or pool_digest == expected_pool_prefix_sha256, 'nonrolling native pool prefix changed')
        prefixes.append(pool_digest)
        reports.append(dict(identity=key, pool_finalized_context_slot=context))
    check(len(set(prefixes)) == 1, 'peers disagree on nonrolling native pool bytes')
    remaining(deadline)
    return dict(status='passed', native_state=expected, pool_prefix_sha256=prefixes[0], peers=reports,
                pool_root_evidence='Finalized on-chain V4 checkpoint matched initial native Rust root; no independent Orchard hashing claim')


def verify_archived_payments(capturemeta, peers, original_payments, pruned_cutoffs, timeout=120):
    deadline = deadline_after(timeout)
    meta = capturemeta
    check(type(meta) is dict and meta.get('relative_path') == 'canonical/full-history.sqlite3', 'fixed capture metadata required')
    path = Path(meta['path'])
    check(path.is_absolute() and path.resolve() == path and path.name == 'full-history.sqlite3' and path.parent.name == 'canonical', 'fixed canonical source path required')
    check(file_sha(path) == meta['file_sha256'], 'closed canonical capture digest differs')
    network = identity(meta['network'], meta['network']['genesis_hash'])
    target = meta['through_slot']; pinned = anchor(meta['anchor'], target)
    check(meta['through_blockhash'] == pinned['blockhash'] and type(original_payments) is list and len(original_payments) == 3, 'fixed complete capture/three original payments required')
    sources = peers_rpc(peers, network, deadline)
    check(type(pruned_cutoffs) is dict and set(pruned_cutoffs) == {key for key, _ in sources}, 'exact peer prune cutoff pins required')
    expected, found = {}, {}
    for payment in original_payments:
        signature, slot = payment.get('signature'), payment.get('slot')
        public_bytes(signature, 64)
        check(signature not in expected and natural(slot) and slot > 0 and
              all(natural(c) and slot <= c < target for c in pruned_cutoffs.values()), 'original payment is not in every explicitly pruned prefix')
        tx_hash = public_bytes(payment.get('recorded_transaction_sha256'), 32)
        size = payment.get('recorded_transaction_bytes')
        check(type(size) is int and 1232 < size <= 16384, 'full original proof transaction byte count required')
        expected[signature] = (slot, tx_hash, size)
    for _, rpc in sources:
        for slot in {p[0] for p in expected.values()}:
            try:
                unavailable = rpc.call('getBlock', [slot, FULL], deadline) is None
            except RpcRefusal as error:
                check(error.code in (-32001, -32004, -32007, -32009), 'old block RPC refused for a non-pruning reason')
                unavailable = True
            check(unavailable, 'original payment block is still available on primary after purge')
    backend = CanonicalStoreRPC(path, network, network['genesis_hash'])
    adapters = []
    for _, rpc in sources:
        gateway = SimpleNamespace(info=dict(network=network, rpc_audience='https://fixed-primary.invalid/'), faucet=SimpleNamespace(root=path.parent))
        def primary(raw, timeout, rpc=rpc):
            request = decoded(raw, 4096)
            check(request == dict(jsonrpc='2.0', id=1, method='getBlock', params=[target, HEADER]), 'archive primary may read only fresh fixed-E header')
            value = rpc.call('getBlock', [target, HEADER], min(deadline, time.monotonic() + timeout))
            return encoded(dict(jsonrpc='2.0', id=1, result=value))
        gateway.forward = primary
        # This address is never contacted: source is replaced with a fixed
        # in-process read-only backend. Request clients cannot choose a source.
        adapter = ArchiveRPC(gateway, 'http://127.0.0.1:1', dict(policy={}))
        adapter.forward = backend.forward
        adapters.append(adapter)
    after, token, count, digest = 0, None, 0, hashlib.sha256()
    with Reader(path, network, network['genesis_hash']) as reader:
        check(reader.slot == target and reader.hash == pinned['blockhash'] and reader.height == pinned['block_height'], 'complete captured tip differs')
        while after < target:
            remaining(deadline)
            request = dict(id=1, params=[after, target, token])
            baseline = decoded(reader.page(request), PAGE_LIMIT)['result']
            pages = [decoded(a.page(request), PAGE_LIMIT)['result'] for a in adapters]
            check(all(page == baseline for page in pages) and baseline['anchor'] == pinned, 'canonical archive pages/full metadata differ')
            for item in baseline['blocks']:
                count += 1; check(count <= MAX_BLOCKS, 'archived history exceeds block bound')
                add_block_digest(digest, item)
                for transaction in item['block']['transactions']:
                    wire = base64.b64decode(transaction['transaction'][0], validate=True)
                    wire_hash = hashlib.sha256(wire).digest()
                    for signature, (slot, tx_hash, size) in expected.items():
                        if wire_hash == tx_hash:
                            cursor = Cursor(wire)
                            check(cursor.short() == 1 and b58(cursor.take(64)) == signature,
                                  'original accepted transaction signature differs')
                            check(signature not in found and item['slot'] == slot and len(wire) == size and
                                  transaction['meta']['err'] is None,
                                  'original accepted transaction slot/wire/metadata differs')
                            found[signature] = dict(slot=slot, metadata_sha256=hashlib.sha256(encoded(transaction['meta'])).hexdigest())
            check(baseline['next_slot'] > after, 'canonical archive cursor stalled')
            after, token = baseline['next_slot'], baseline['anchor']
    check(after == target and count == meta['produced_blocks'] and digest.hexdigest() == meta['canonical_blocks_sha256'], 'complete archived capture differs')
    check(set(found) == set(expected), 'original accepted payment set wire/metadata missing')
    remaining(deadline)
    check(file_sha(path) == meta['file_sha256'], 'read-only archive changed during verification')
    remaining(deadline)
    return dict(status='passed', through_slot=target, produced_blocks=count, payments=found,
                full_canonical_pages_equal_all_three=True, primary_old_blocks_unavailable=True)
