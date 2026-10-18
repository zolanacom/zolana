"""Bounded full canonical history from one operator-pinned RPC, never a mirror.

Like ordinary RPC this trusts the operator's validator for transaction metadata.
The primary finalized header/genesis pins the chain; it is not a light-client proof.
No caller-selected endpoint, transaction encoding, finality, or upstream method.
"""
import json
import time
import urllib.parse
import urllib.request

LIMIT = 16 * 1024 * 1024


def natural(value):
    return type(value) is int and 0 <= value <= 2**64 - 1


def anchor(value, target):
    if not isinstance(value, dict) or set(value) != {'slot', 'blockhash', 'block_height'} or not natural(value['slot']) or value['slot'] != target or not natural(value['block_height']) or not isinstance(value['blockhash'], str) or not 32 <= len(value['blockhash']) <= 44 or any(c not in '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz' for c in value['blockhash']):
        raise ValueError('invalid canonical history anchor')
    return value


def parameters(request):
    values = request.get('params')
    if not isinstance(values, list) or len(values) != 3:
        raise ValueError('invalid canonical history parameters')
    after, target, token = values
    if not natural(after) or not natural(target) or target == 0 or after > target:
        raise ValueError('invalid canonical history range')
    if token is not None:
        anchor(token, target)
    elif after != 0:
        raise ValueError('canonical continuation requires an anchor')
    return after, target, token


class ArchiveRPC:
    def __init__(self, gateway, url, ledger):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or url == gateway.info['rpc_audience']:
            raise ValueError('archive requires an operator-pinned loopback validator RPC')
        self.gateway, self.url = gateway, url
        self.operator = None
        if ledger['policy'].get('operator_rpc'):
            from operator_transport import Operator
            self.operator = Operator(url, gateway.faucet.root / 'rpc-access.key')
            if ledger['policy'].get('operator_unix') and self.operator.path is None:
                raise ValueError('archive private RPC transport cannot be downgraded')

    def forward(self, raw, timeout):
        if self.operator is not None:
            return self.operator.forward(raw, timeout=timeout)
        request = urllib.request.Request(self.url, raw, {'Content-Type': 'application/json'})
        with self.gateway.opener.open(request, timeout=timeout) as response:
            body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ValueError('archive response exceeds gateway limit')
        return body

    def page(self, request):
        after, target, token = parameters(request)
        deadline = time.monotonic() + 15

        def read(method, params, primary=False):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('canonical history deadline exceeded')
            raw = json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode()
            body = (self.gateway.forward if primary else self.forward)(raw, timeout=remaining)
            value = json.loads(body)
            if not isinstance(value, dict) or value.get('id') != 1 or value.get('error') is not None or 'result' not in value:
                raise ValueError('canonical archival RPC is unavailable')
            return value['result']

        if read('getGenesisHash', []) != self.gateway.info['network']['genesis_hash']:
            raise ValueError('canonical archive genesis mismatch')
        config = dict(transactionDetails='none', rewards=False, commitment='finalized')
        primary = read('getBlock', [target, config], primary=True)
        archived = read('getBlock', [target, config])
        if not isinstance(primary, dict) or not isinstance(archived, dict):
            raise ValueError('canonical checkpoint unavailable')
        pinned = anchor(dict(slot=target, blockhash=primary.get('blockhash'), block_height=primary.get('blockHeight')), target)
        if archived.get('blockhash') != pinned['blockhash'] or archived.get('blockHeight') != pinned['block_height'] or (token is not None and token != pinned):
            raise ValueError('archive and primary finalized checkpoints differ')
        slots = [] if after == target else read('getBlocksWithLimit', [after + 1, 16, {'commitment': 'finalized'}])
        if not isinstance(slots, list) or len(slots) > 16 or any(not natural(s) or s <= after for s in slots) or any(a >= b for a, b in zip(slots, slots[1:])):
            raise ValueError('invalid canonical archive block range')
        page = dict(network=self.gateway.info['network'], anchor=pinned, after_slot=after,
                    next_slot=after, complete=after == target, blocks=[])
        for slot in slots:
            if slot > target:
                break
            block = read('getBlock', [slot, dict(encoding='base64', transactionDetails='full', rewards=False,
                                               commitment='finalized', maxSupportedTransactionVersion=0)])
            if not isinstance(block, dict) or not isinstance(block.get('transactions'), list) or not natural(block.get('parentSlot')) or not natural(block.get('blockHeight')):
                raise ValueError('full canonical archival block unavailable')
            item = dict(slot=slot, block=block)
            # Reserve enough space for the exact outer envelope and escaped id.
            size = len(json.dumps(item, separators=(',', ':')).encode())
            if size > 8 * 1024 * 1024:
                raise ValueError('canonical archival block exceeds limit')
            candidate = dict(page, blocks=page['blocks'] + [item], next_slot=slot, complete=slot == target)
            encoded = json.dumps(dict(jsonrpc='2.0', id=request['id'], result=candidate), separators=(',', ':')).encode()
            if len(encoded) > LIMIT:
                break
            page = candidate
        if after < target and not page['blocks']:
            raise ValueError('canonical archival history is incomplete')
        if time.monotonic() > deadline:
            raise ValueError('canonical history deadline exceeded')
        return json.dumps(dict(jsonrpc='2.0', id=request['id'], result=page), separators=(',', ':')).encode()
