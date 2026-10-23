"""Fixed, prepaid canonical sync reads. This is ordinary operator RPC trust.

No wallet balance, key, payment-status hint, endpoint or caller-selected RPC is
accepted here. The wallet still verifies the checkpoint, every canonical block,
the finalized pool and its original pending packet with its existing Rust core.
Every request prepays 21 units (five metadata reads plus sixteen history groups),
even when its actual tail is empty or requires an older bounded scan fallback.
"""
import json
import time

FORMAT = 'zolana-wallet-sync-snapshot-v1'
MAX_BLOCKS = 256
PREPAID_UNITS = 5 + (MAX_BLOCKS + 15) // 16
LIMIT = 16 * 1024 * 1024
HEADER = {'transactionDetails': 'none', 'rewards': False, 'commitment': 'finalized'}
POOL = {'commitment': 'finalized', 'encoding': 'base64'}
RANGE = {'commitment': 'finalized'}
FULL = {'encoding': 'base64', 'transactionDetails': 'full', 'rewards': False,
        'commitment': 'finalized', 'maxSupportedTransactionVersion': 0}


def natural(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


def parameters(request):
    values = request.get('params')
    if not isinstance(values, list) or len(values) != 1 or not natural(values[0]):
        raise ValueError('invalid fixed sync snapshot cursor')
    return values[0]


def metadata_calls(calls, pool):
    """Internal construction gate; this is not another caller batch method."""
    if not isinstance(calls, list) or not 1 <= len(calls) <= 5:
        raise ValueError('invalid fixed sync metadata batch')
    for call in calls:
        if not isinstance(call, dict) or set(call) != {'method', 'params'}:
            raise ValueError('invalid fixed sync metadata call')
        method, args = call['method'], call['params']
        if method == 'getGenesisHash' and args == []:
            continue
        if method == 'getAccountInfo' and args == [pool, POOL]:
            continue
        if (method == 'getBlock' and isinstance(args, list) and len(args) == 2
                and natural(args[0]) and args[1] == HEADER):
            continue
        if (method == 'getBlocksWithLimit' and isinstance(args, list) and len(args) == 3
                and natural(args[0]) and args[0] > 0
                and type(args[1]) is int and args[1] == MAX_BLOCKS + 1 and args[2] == RANGE):
            continue
        raise ValueError('only fixed sync metadata reads may be aggregated')
    return calls


def metadata_results(raw, calls):
    """Same strict batch identity rules; only missing getBlock is nullable."""
    if not isinstance(raw, bytes) or len(raw) > LIMIT:
        raise ValueError('sync metadata response exceeds byte limit')

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('ambiguous sync metadata object')
            value[key] = item
        return value

    def invalid(_):
        raise ValueError('nonfinite sync metadata value')

    response = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    if not isinstance(response, list) or len(response) != len(calls):
        raise ValueError('complete sync metadata batch unavailable')
    values = {}
    for item in response:
        if (not isinstance(item, dict) or item.get('jsonrpc') != '2.0'
                or type(item.get('id')) is not int or not 0 <= item['id'] < len(calls)
                or item['id'] in values):
            raise ValueError('sync metadata response identity differs')
        index = item['id']
        if set(item) == {'jsonrpc', 'id', 'result'}:
            result = item['result']
            if result is None and calls[index]['method'] != 'getBlock':
                raise ValueError('required sync metadata unavailable')
        elif set(item) == {'jsonrpc', 'id', 'error'} and calls[index]['method'] == 'getBlock':
            error = item['error']
            # Ordinary finalized-block absence/pruning only. Other upstream
            # failures do not become a successful snapshot or implicit retry.
            if (not isinstance(error, dict) or set(error) - {'code', 'message', 'data'}
                    or type(error.get('code')) is not int
                    or error['code'] not in (-32001, -32004, -32007, -32009)
                    or not isinstance(error.get('message'), str)
                    or len(error['message']) > 4096):
                raise ValueError('sync metadata RPC failed')
            result = None
        else:
            raise ValueError('sync metadata RPC failed')
        values[index] = result
    return [values[index] for index in range(len(calls))]


def _deadline(deadline):
    if time.monotonic() >= deadline:
        raise ValueError('wallet sync snapshot deadline exceeded')


def _hash(value):
    return (isinstance(value, str) and 32 <= len(value) <= 44
            and all(c in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in value))


def _header(value):
    return (isinstance(value, dict) and natural(value.get('parentSlot'))
            and natural(value.get('blockHeight')) and _hash(value.get('blockhash'))
            and _hash(value.get('previousBlockhash'))
            and len(json.dumps(value, separators=(',', ':')).encode()) <= 16384)


def page(request, network, pool_address, reads, deadline, size_error):
    """reads(calls, deadline, history=False) is the gateway's fixed private batch."""
    saved = parameters(request)
    if not _hash(pool_address):
        raise ValueError('fixed sync pool address unavailable')
    _deadline(deadline)
    genesis, pool = reads([{'method': 'getGenesisHash', 'params': []},
                           {'method': 'getAccountInfo', 'params': [pool_address, dict(POOL)]}], deadline)
    if genesis != network['genesis_hash']:
        raise ValueError('sync snapshot genesis mismatch')
    if (not isinstance(pool, dict) or not isinstance(pool.get('context'), dict)
            or not natural(pool['context'].get('slot')) or not isinstance(pool.get('value'), dict)
            or not natural(pool['value'].get('lamports'))):
        raise ValueError('sync snapshot finalized pool unavailable')
    target = pool['context']['slot']
    if saved > target:
        raise ValueError('sync snapshot refuses saved checkpoint rollback')

    calls = [{'method': 'getBlock', 'params': [target, dict(HEADER)]}]
    cached_index = None
    if saved != 0 and saved != target:
        cached_index = len(calls)
        calls.append({'method': 'getBlock', 'params': [saved, dict(HEADER)]})
    range_index = None
    if saved < target:
        range_index = len(calls)
        calls.append({'method': 'getBlocksWithLimit',
                      'params': [saved + 1, MAX_BLOCKS + 1, dict(RANGE)]})
    values = reads(calls, deadline)
    target_header = values[0]
    if not _header(target_header):
        raise ValueError('sync snapshot exact finalized target unavailable')
    cached = (target_header if saved == target else values[cached_index]) if saved else None
    if cached is not None and not _header(cached):
        raise ValueError('sync snapshot saved header malformed')
    result = {'format': FORMAT, 'network': network, 'genesis': genesis, 'pool': pool,
              'target_header': target_header, 'saved_header': cached,
              'canonical_tail': None, 'fallback': None}

    def encoded():
        _deadline(deadline)
        raw = json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result},
                         separators=(',', ':'), allow_nan=False).encode()
        if len(raw) > LIMIT:
            raise size_error('Wallet history response exceeds byte limit')
        _deadline(deadline)
        return raw

    if saved and cached is None:
        result['fallback'] = 'checkpoint-unavailable'
        return encoded()
    slots = [] if range_index is None else values[range_index]
    if (not isinstance(slots, list) or len(slots) > MAX_BLOCKS + 1
            or any(not natural(s) or s <= saved for s in slots)
            or any(a >= b for a, b in zip(slots, slots[1:]))):
        raise ValueError('sync snapshot canonical range malformed')
    slots = [slot for slot in slots if slot <= target]
    if len(slots) > MAX_BLOCKS:
        result['fallback'] = 'tail-too-large'
        return encoded()
    if saved < target and (not slots or slots[-1] != target):
        result['fallback'] = 'canonical-incomplete'
        return encoded()
    calls = [{'method': 'getBlock', 'params': [slot, dict(FULL)]} for slot in slots]
    try:
        blocks = reads(calls, deadline, history=True) if calls else []
    except size_error:
        result['fallback'] = 'response-too-large'
        return encoded()
    if not isinstance(blocks, list) or len(blocks) != len(slots):
        result['fallback'] = 'canonical-incomplete'
        return encoded()
    previous_slot, previous_hash = saved, cached['blockhash'] if cached else None
    previous_height = cached['blockHeight'] if cached else None
    items = []
    for slot, block in zip(slots, blocks):
        _deadline(deadline)
        if (not isinstance(block, dict)
                or not _header({k: v for k, v in block.items() if k != 'transactions'})
                or not isinstance(block.get('transactions'), list)
                or block['parentSlot'] != previous_slot
                or (previous_hash is not None and block['previousBlockhash'] != previous_hash)
                or (previous_height is not None and block['blockHeight'] <= previous_height)):
            result['fallback'] = 'canonical-incomplete'
            return encoded()
        items.append({'slot': slot, 'block': block})
        previous_slot, previous_hash, previous_height = slot, block['blockhash'], block['blockHeight']
    if (len(blocks) != len(slots) or previous_slot != target
            or (slots and (previous_hash != target_header['blockhash']
                           or previous_height != target_header['blockHeight']))):
        result['fallback'] = 'canonical-incomplete'
        return encoded()
    result['canonical_tail'] = {'after_slot': saved, 'target_slot': target,
                                'next_slot': target, 'complete': True, 'blocks': items}
    try:
        return encoded()
    except size_error:
        result['canonical_tail'] = None
        result['fallback'] = 'response-too-large'
        return encoded()
