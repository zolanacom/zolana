"""Bounded public-ciphertext pages; never canonical transaction-status evidence."""
import bisect
import hashlib
import json
import time

from history_retention import (directory, manifest, read, usage, natural, block_hash,
                               MAX_SEGMENT, MAX_SEGMENTS, STORE_BUDGET)

LIMIT = 16 * 1024 * 1024


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
        manifest(self.root, network)
        usage(self.root, STORE_BUDGET)

    def page(self, request):
        after, target, token = parameters(request)
        deadline = time.monotonic() + 15
        directory(self.root)
        _, files, _ = manifest(self.root, self.network)
        usage(self.root, STORE_BUDGET)
        if not files and token is None:
            return encode({'jsonrpc':'2.0','id':request['id'],'result':None})
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
        index = bisect.bisect_right([d['last_slot'] for _, d in files], after)
        budget = len(encode({'jsonrpc':'2.0','id':request['id']})) + 1024
        for position in range(index, len(files)):
            if after >= through: break
            name, descriptor = files[position]
            if descriptor['first_slot'] > through: break
            if time.monotonic() >= deadline: raise ValueError('retained history deadline exceeded')
            data = read(self.root / name, MAX_SEGMENT)
            if hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest() != descriptor['digest']:
                raise ValueError('retained history checksum mismatch')
            records = json.loads(data)
            if not isinstance(records, list) or len(records) != descriptor['count'] or not records:
                raise ValueError('retained segment size mismatch')
            previous = files[position-1][1]['last_slot'] if position else 0
            previous_hash = None if position else self.network['genesis_hash']
            height = None
            for block in records:
                if (not isinstance(block, dict) or set(block) != {'slot','parent_slot','blockhash','previous_blockhash','block_height','transactions'}
                        or not natural(block['slot']) or block['slot'] <= previous
                        or not natural(block['parent_slot']) or block['parent_slot'] != previous
                        or not block_hash(block['blockhash']) or not block_hash(block['previous_blockhash'])
                        or (previous_hash is not None and block['previous_blockhash'] != previous_hash)
                        or not natural(block['block_height']) or (height is not None and block['block_height'] != height+1)
                        or not isinstance(block['transactions'], list) or len(encode(block)) > 8*1024*1024):
                    raise ValueError('retained segment continuity mismatch')
                previous, previous_hash, height = block['slot'], block['blockhash'], block['block_height']
            if records[0]['slot'] != descriptor['first_slot'] or records[-1]['slot'] != descriptor['last_slot']:
                raise ValueError('retained segment boundaries mismatch')
            for block in records:
                if not after < block['slot'] <= through: continue
                if time.monotonic() >= deadline: raise ValueError('retained history deadline exceeded')
                size = len(encode(block)) + 1
                if len(blocks) == 16 or budget + size > LIMIT:
                    break
                blocks.append(block); budget += size
            if len(blocks) == 16 or (blocks and blocks[-1]['slot'] < min(through, records[-1]['slot'])): break
        cursor = blocks[-1]['slot'] if blocks else after
        if cursor < through and not blocks:
            raise ValueError('retained prefix is incomplete')
        result = {'network': self.network, 'checkpoint': checkpoint, 'retained_tip': tip,
                  'after_slot': after, 'through_slot': through, 'next_slot': cursor,
                  'complete': cursor >= through, 'blocks': blocks}
        raw = encode({'jsonrpc':'2.0','id':request['id'],'result':result})
        if len(raw) > LIMIT or time.monotonic() >= deadline:
            raise ValueError('retained response bound exceeded')
        return raw
