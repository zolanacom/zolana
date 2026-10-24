"""Bounded public-ciphertext pages; never canonical transaction-status evidence."""
import bisect
from collections import OrderedDict
import hashlib
import json
import threading
import time

from history_retention import (directory, manifest, read, usage, natural, block_hash,
                               MAX_SEGMENT, MAX_SEGMENTS, STORE_BUDGET)

LIMIT = 16 * 1024 * 1024
PAGE_BLOCKS = 16
PAGE_BLOCKS_V2 = 4096
PAGE_BLOCKS_WIDE = 16384
PAGE_BLOCKS_LARGE = 32768
CACHE_BYTES = 32 * 1024 * 1024
CACHE_SEGMENTS = 64
CACHE_HEADERS = 65536


def parameters(request):
    params = request.get('params')
    if not isinstance(params, list) or len(params) != 3 or not all(natural(n) for n in params[:2]):
        raise ValueError('invalid retained history request')
    token = params[2]
    if token is not None and (not isinstance(token, dict) or set(token) != {'segments', 'sha256'}
            or type(token['segments']) is not int or not 1 <= token['segments'] <= MAX_SEGMENTS
            or not isinstance(token['sha256'], str) or len(token['sha256']) != 64
            or any(c not in '0123456789abcdef' for c in token['sha256'])):
        raise ValueError('invalid retained history checkpoint')
    return params


def encode(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


class History:
    def __init__(self, root, network):
        self.root = directory(root)
        self.network = network
        _, files, _ = manifest(self.root, network)
        usage(self.root, STORE_BUDGET)
        self._cache = OrderedDict()
        self._cache_lock = threading.Lock()
        self._cache_bytes = self._cache_headers = 0
        # Only public immutable bytes are prepared before ingress. Limit both
        # startup source work and resident payload/metadata independently.
        deadline = time.monotonic() + 15
        remaining = CACHE_BYTES
        for position, (name, descriptor) in enumerate(files[:CACHE_SEGMENTS]):
            if remaining <= 0:
                break
            if (self.root / name).lstat().st_size > remaining:
                continue
            _, used = self._encoded_segment(name, descriptor,
                files[position-1][1]['last_slot'] if position else 0,
                deadline, maximum=min(MAX_SEGMENT, remaining))
            remaining -= used

    def _remember(self, key, entry):
        slots, encoded, size = entry
        if size > CACHE_BYTES or len(slots) > CACHE_HEADERS:
            return entry  # Dense segments keep the original uncached path.
        with self._cache_lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            while self._cache and (len(self._cache) >= CACHE_SEGMENTS or
                    self._cache_bytes + size > CACHE_BYTES or
                    self._cache_headers + len(slots) > CACHE_HEADERS):
                _, removed = self._cache.popitem(last=False)
                self._cache_bytes -= removed[2]
                self._cache_headers -= len(removed[0])
            self._cache[key] = entry
            self._cache_bytes += size
            self._cache_headers += len(slots)
        return entry

    def _validate_segment(self, data, descriptor, previous):
        # Resolve the owned codec only after the sealed loader publishes it.
        from gateway_history_codec import hash_bytes

        def valid_hash(value):
            try:
                hash_bytes(value)
            except ValueError:
                return False
            return True

        records = json.loads(data)
        if not isinstance(records, list) or len(records) != descriptor['count'] or not records:
            raise ValueError('retained segment size mismatch')
        previous_hash = self.network['genesis_hash'] if previous == 0 else None
        height = None
        slots, encoded = [], []
        for block in records:
            if (not isinstance(block, dict) or set(block) != {'slot','parent_slot','blockhash','previous_blockhash','block_height','transactions'}
                    or not natural(block['slot']) or block['slot'] <= previous
                    or not natural(block['parent_slot']) or block['parent_slot'] != previous
                    or not valid_hash(block['blockhash']) or not valid_hash(block['previous_blockhash'])
                    or (previous_hash is not None and block['previous_blockhash'] != previous_hash)
                    or not natural(block['block_height']) or (height is not None and block['block_height'] != height+1)
                    or not isinstance(block['transactions'], list)):
                raise ValueError('retained segment continuity mismatch')
            raw = encode(block)
            if len(raw) > 8*1024*1024:
                raise ValueError('retained segment continuity mismatch')
            slots.append(block['slot']); encoded.append(raw)
            previous, previous_hash, height = block['slot'], block['blockhash'], block['block_height']
        if slots[0] != descriptor['first_slot'] or slots[-1] != descriptor['last_slot']:
            raise ValueError('retained segment boundaries mismatch')
        return tuple(slots), tuple(encoded), sum(map(len, encoded))

    def _encoded_segment(self, name, descriptor, previous, deadline, maximum=MAX_SEGMENT):
        if time.monotonic() >= deadline:
            raise ValueError('retained history deadline exceeded')
        # Every cache hit still securely reads and hashes the complete source.
        # A stat match alone never authorizes reuse after corruption or mutation.
        data = read(self.root / name, maximum)
        if hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest() != descriptor['digest']:
            raise ValueError('retained history checksum mismatch')
        key = (name, descriptor['digest'], descriptor['first_slot'],
               descriptor['last_slot'], descriptor['count'], previous)
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is not None:
                self._cache.move_to_end(key)
        if entry is None:
            entry = self._remember(key, self._validate_segment(data, descriptor, previous))
        if time.monotonic() >= deadline:
            raise ValueError('retained history deadline exceeded')
        return entry, len(data)

    def page(self, request):
        return self.page_counted(request)[0]

    def page_compact_counted(self, request, *, max_blocks=PAGE_BLOCKS_V2, deadline=None):
        """Opt-in lossless transport; same pinned page and durable header charge."""
        from gateway_history_codec import pack_blocks
        if deadline is None:
            deadline = time.monotonic() + 15
        raw, count = self.page_counted(request, max_blocks=max_blocks, deadline=deadline)
        value = json.loads(raw)
        if value['result'] is not None:
            result = value['result']
            headers, transactions = pack_blocks(result.pop('blocks'))
            result['compact_headers'], result['transactions'] = headers, transactions
        raw = encode(value)
        if len(raw) > LIMIT or time.monotonic() >= deadline:
            raise ValueError('retained response bound exceeded')
        return raw, count

    def page_counted(self, request, *, max_blocks=PAGE_BLOCKS, deadline=None):
        """Return public bytes and their actual header count for durable billing."""
        if type(max_blocks) is not int or max_blocks not in (PAGE_BLOCKS, PAGE_BLOCKS_V2, PAGE_BLOCKS_WIDE, PAGE_BLOCKS_LARGE):
            raise ValueError('invalid retained page bound')
        after, target, token = parameters(request)
        if deadline is None:
            deadline = time.monotonic() + 15
        if time.monotonic() >= deadline:
            raise ValueError('retained history deadline exceeded')
        directory(self.root)
        _, files, _ = manifest(self.root, self.network)
        usage(self.root, STORE_BUDGET)
        if not files and token is None:
            return encode({'jsonrpc':'2.0','id':request['id'],'result':None}), 0
        count = len(files) if token is None else token['segments']
        if not 0 < count <= len(files):
            raise ValueError('retained checkpoint unavailable')
        files = files[:count]
        checkpoint = {'segments': count, 'sha256': hashlib.sha256(json.dumps({'network': self.network,
            'segments': [descriptor for _, descriptor in files]},sort_keys=True,separators=(',', ':')).encode()).hexdigest()}
        if token is not None and token != checkpoint:
            raise ValueError('retained immutable checkpoint changed')
        tip = files[-1][1]['last_slot']; through = min(target, tip)
        blocks = []
        cursor = after
        index = bisect.bisect_right([d['last_slot'] for _, d in files], after)
        budget = len(encode({'jsonrpc':'2.0','id':request['id']})) + 1024
        for position in range(index, len(files)):
            if after >= through: break
            name, descriptor = files[position]
            if descriptor['first_slot'] > through: break
            entry, _ = self._encoded_segment(name, descriptor,
                files[position-1][1]['last_slot'] if position else 0, deadline)
            slots, encoded, _ = entry
            for slot, raw in zip(slots, encoded):
                if not after < slot <= through: continue
                if time.monotonic() >= deadline: raise ValueError('retained history deadline exceeded')
                size = len(raw) + 1
                if len(blocks) == max_blocks or budget + size > LIMIT:
                    break
                blocks.append(raw); budget += size; cursor = slot
            if len(blocks) == max_blocks or (blocks and cursor < min(through, slots[-1])): break
        if cursor < through and not blocks:
            raise ValueError('retained prefix is incomplete')
        result = {'network': self.network, 'checkpoint': checkpoint, 'retained_tip': tip,
                  'after_slot': after, 'through_slot': through, 'next_slot': cursor,
                  'complete': cursor >= through}
        prefix = encode({'jsonrpc':'2.0','id':request['id'],'result':result})
        raw = prefix[:-2] + b',"blocks":[' + b','.join(blocks) + b']}}'
        if len(raw) > LIMIT or time.monotonic() >= deadline:
            raise ValueError('retained response bound exceeded')
        return raw, len(blocks)
