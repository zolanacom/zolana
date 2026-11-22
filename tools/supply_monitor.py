#!/usr/bin/env python3
"""Read-only supply and pool-backing monitor for one RPC endpoint.

`check` reads the shielded pool account and the total supply at one slot,
evaluates the invariants below and writes a result document, optionally
signed with an operator key. `verify` authenticates a published result and
recomputes its verdict from the numbers it contains.

The tool sends no transaction, holds no wallet capability and creates no key.
It is standalone: Python 3.9+ and /usr/bin/openssl, no other project module.
See docs/supply-monitor-runbook.md for what a green result does and does not
establish.
"""
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

FORMAT = 'native-supply-monitor-v1'
DOMAIN = b'native-supply-monitor-signature-v1\x00'
ALGORITHM = 'ecdsa-p256-sha256'
OPENSSL = '/usr/bin/openssl'
P256 = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004')

GREEN, RED, UNKNOWN = 'green', 'red', 'unknown'
EXIT = {GREEN: 0, RED: 1, UNKNOWN: 3}
EXIT_USAGE = 2
EXIT_SIGNATURE = 4

ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
# protocol/payments/src/native_accounts.rs: PROGRAM_ID and the pool seed.
PROGRAM_ID = bytes([
    91, 34, 9, 203, 140, 74, 92, 11, 167, 20, 210, 73, 64, 155, 3, 220, 25, 87, 194, 52, 122, 28,
    170, 241, 29, 131, 42, 88, 76, 107, 13, 190,
])
POOL_SEED = b'native-payment-pool-v1'
EPOCH_REWARDS = 'SysvarEpochRewards1111111111111111111111111'
# protocol/payments/src/state.rs: STATE_BYTES and SLOT_STATE_BYTES.
POOL_FORMATS = {b'NPOOL003': 3137, b'NPOOL004': 25728}
MAX_COMMITMENTS = (1 << 32) - 2
U64 = (1 << 64) - 1
I64 = (1 << 63) - 1
PPB = 10**9
# The validator's default: 31,557,600 seconds at 2.5 slots per second.
SLOTS_PER_YEAR = 78_894_000
MAX_EPOCHS = 100_000
RESPONSE_LIMIT = 4 * 1024 * 1024
RESULT_LIMIT = 64 * 1024
CHECKS = ('pool_account', 'pool_backing', 'pool_rent_floor', 'supply_identity',
          'pool_within_supply', 'supply_ceiling', 'continuity', 'supply_issuance')
REASONS = ('rpc_unavailable', 'rpc_error', 'malformed_response', 'inconsistent_slots',
           'wrong_network', 'stale_endpoint')
HEX64 = re.compile('[0-9a-f]{64}')
AMOUNT = re.compile('0|[1-9][0-9]{0,19}')
SIGNED = re.compile('-?(0|[1-9][0-9]{0,19})')


class Indeterminate(Exception):
    """No trustworthy observation was obtained; neither green nor red."""

    def __init__(self, reason, detail):
        super().__init__(detail)
        self.reason = reason


class SignatureError(Exception):
    """Signing or authentication failed. Never carries key material."""


class Usage(Exception):
    """The invocation or a local input file is unusable."""


def b58encode(raw):
    number = int.from_bytes(raw, 'big')
    result = ''
    while number:
        number, index = divmod(number, 58)
        result = ALPHABET[index] + result
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + result


def public_key(value):
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        return False
    number = 0
    for character in value:
        if character not in ALPHABET:
            return False
        number = number * 58 + ALPHABET.index(character)
    return len(value) - len(value.lstrip('1')) + (number.bit_length() + 7) // 8 == 32


def on_curve(raw):
    p = (1 << 255) - 19
    y = int.from_bytes(raw, 'little') & ((1 << 255) - 1)
    if y >= p:
        return False
    y2 = y * y % p
    d = -121665 * pow(121666, p - 2, p) % p
    denominator = (d * y2 + 1) % p
    if denominator == 0:
        return False
    x2 = (y2 - 1) * pow(denominator, p - 2, p) % p
    return pow(x2, (p - 1) // 2, p) in (0, 1)


def program_address(seeds, program):
    for bump in range(255, -1, -1):
        raw = hashlib.sha256(b''.join(seeds) + bytes([bump]) + program + b'ProgramDerivedAddress').digest()
        if not on_curve(raw):
            return raw
    raise ValueError('no program address')


PROGRAM = b58encode(PROGRAM_ID)
POOL = b58encode(program_address([POOL_SEED], PROGRAM_ID))


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def hex64(value):
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def natural(value, limit=2**53 - 1):
    return type(value) is int and 0 <= value <= limit


def amount(value):
    return isinstance(value, str) and AMOUNT.fullmatch(value) is not None and int(value) <= U64


def ceil_div(numerator, denominator):
    return -(-numerator // denominator)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('duplicate JSON field')
            value[key] = item
        return value

    def refuse(_):
        raise ValueError('nonfinite JSON number')

    return json.loads(raw, object_pairs_hook=unique, parse_constant=refuse)


# Pool account ---------------------------------------------------------------

def decode_pool(data):
    """The header shared by both pool formats. Mirrors PoolState::decode's
    header rules; the note-tree frontier and anchors are not re-verified."""
    tag = bytes(data[:8])
    if tag not in POOL_FORMATS or len(data) != POOL_FORMATS[tag]:
        raise ValueError('unknown pool format or length')
    domain = bytes(data[8:40])
    rent_floor, backing, note_count = struct.unpack_from('<QQQ', data, 40)
    if domain == bytes(32):
        raise ValueError('pool has no network domain')
    if backing > I64 or note_count > MAX_COMMITMENTS or note_count % 2:
        raise ValueError('pool header is out of range')
    return {'format': tag.decode(), 'domain': domain.hex(), 'rent_floor': rent_floor,
            'backing': backing, 'note_count': note_count}


def pool_record(account, rent_exempt_minimum):
    """The public description of the pool account as one RPC response gave it."""
    record = dict.fromkeys(('owner', 'executable', 'lamports', 'data_bytes', 'data_sha256', 'format', 'domain',
                            'rent_floor', 'backing', 'note_count', 'rent_exempt_minimum', 'surplus'))
    record['present'] = account is not None
    if account is None:
        return record
    data = account['data']
    record.update(owner=account['owner'], executable=account['executable'], lamports=str(account['lamports']),
                  data_bytes=len(data), data_sha256=sha(data), rent_exempt_minimum=str(rent_exempt_minimum))
    try:
        header = decode_pool(data)
    except ValueError:
        return record
    record.update(format=header['format'], domain=header['domain'], rent_floor=str(header['rent_floor']),
                  backing=str(header['backing']), note_count=header['note_count'],
                  surplus=str(account['lamports'] - header['rent_floor'] - header['backing']))
    return record


# Invariants -------------------------------------------------------------------

def issuance_allowance(baseline, supply, epoch, policy):
    """The most the total supply may have grown since the baseline: rewards the
    baseline had computed but not yet credited, plus one bounded epoch of
    validator inflation for every epoch boundary crossed since."""
    crossed = epoch - baseline['epoch']
    if not 0 <= crossed <= MAX_EPOCHS:
        return None
    rate = max(baseline['validator_rate_ppb'], supply['validator_rate_ppb'])
    span = max(baseline['slots_in_epoch'], supply['slots_in_epoch'])
    total = int(baseline['total'])
    allowance = int(baseline['rewards_pending'])
    for _ in range(crossed):
        allowance += ceil_div((total + allowance) * rate * span, PPB * policy['slots_per_year'])
    return allowance + int(policy['issuance_slack'])


def evaluate(pool, supply, epoch, baseline, policy):
    """Every verdict is a function of published numbers, so `verify` and any
    reader can recompute it. `ok` is None when a check could not be evaluated."""
    checks = []

    def add(name, ok, detail):
        checks.append({'id': name, 'ok': ok, 'detail': detail})

    decoded = pool['present'] and pool['format'] is not None
    if not pool['present']:
        add('pool_account', False, 'pool account does not exist')
    elif pool['owner'] != PROGRAM or pool['executable']:
        add('pool_account', False, 'pool account is not a data account of the payment program')
    elif not decoded:
        add('pool_account', False, 'pool account data is not a valid pool header')
    else:
        add('pool_account', True, f"{pool['format']} pool of {pool['data_bytes']} bytes owned by the payment program")

    if decoded:
        lamports, floor, backing = int(pool['lamports']), int(pool['rent_floor']), int(pool['backing'])
        minimum = int(pool['rent_exempt_minimum'])
        add('pool_backing', lamports >= floor + backing,
            f'lamports {lamports} - rent_floor {floor} - backing {backing} = surplus {lamports - floor - backing}')
        add('pool_rent_floor', floor >= minimum, f'rent_floor {floor} against rent-exempt minimum {minimum}')
    else:
        add('pool_backing', None, 'pool header unavailable')
        add('pool_rent_floor', None, 'pool header unavailable')

    total, circulating, idle = int(supply['total']), int(supply['circulating']), int(supply['non_circulating'])
    add('supply_identity', total == circulating + idle,
        f'total {total} against circulating {circulating} + non_circulating {idle}')
    if pool['present']:
        add('pool_within_supply', int(pool['lamports']) <= total, f"pool lamports {pool['lamports']} against total {total}")
    else:
        add('pool_within_supply', None, 'pool account unavailable')
    if policy['supply_ceiling'] is None:
        add('supply_ceiling', None, 'no ceiling configured')
    else:
        add('supply_ceiling', total <= int(policy['supply_ceiling']), f"total {total} against ceiling {policy['supply_ceiling']}")

    if baseline is None:
        add('continuity', None, 'no baseline')
        add('supply_issuance', None, 'no baseline')
        return checks
    if not decoded:
        add('continuity', None, 'pool header unavailable')
    else:
        problems = []
        for field in ('format', 'domain', 'rent_floor'):
            if pool[field] != baseline[field]:
                problems.append(f'{field} changed')
        if pool['note_count'] < baseline['note_count']:
            problems.append(f"note_count fell from {baseline['note_count']} to {pool['note_count']}")
        elif pool['note_count'] == baseline['note_count'] and pool['backing'] != baseline['backing']:
            problems.append(f"backing moved from {baseline['backing']} to {pool['backing']} without a payment")
        add('continuity', not problems,
            '; '.join(problems) or f"note_count {baseline['note_count']} -> {pool['note_count']}, backing {baseline['backing']} -> {pool['backing']}")
    allowance = issuance_allowance(baseline, supply, epoch, policy)
    if allowance is None:
        add('supply_issuance', None, 'baseline is too many epochs old')
    else:
        growth = total - int(baseline['total'])
        add('supply_issuance', growth <= allowance,
            f"total moved {growth} since slot {baseline['slot']}; at most {allowance} may be issued over {epoch - baseline['epoch']} epoch boundaries")
    return checks


def verdict(checks):
    failed = [item['id'] for item in checks if item['ok'] is False]
    return (RED if failed else GREEN), failed


# Result document --------------------------------------------------------------

def baseline_summary(raw, value):
    return {'sha256': sha(raw), 'slot': value['slot'], 'epoch': value['epoch'],
            **{key: value['supply'][key] for key in ('total', 'rewards_pending', 'validator_rate_ppb', 'slots_in_epoch')},
            **{key: value['pool'][key] for key in ('format', 'domain', 'rent_floor', 'backing', 'note_count')}}


def validate(value):
    """Exact shape of a result document. Raises ValueError."""
    def need(condition, what):
        if not condition:
            raise ValueError(f'invalid supply monitor result: {what}')

    keys = {'format', 'status', 'reason', 'failed', 'observed_at', 'commitment', 'read_mode', 'genesis_hash', 'program',
            'pool_address', 'slot', 'epoch', 'block_time', 'pool', 'supply', 'policy', 'baseline', 'checks', 'signer'}
    need(isinstance(value, dict) and set(value) == keys and value['format'] == FORMAT, 'fields')
    need(value['status'] in EXIT and natural(value['observed_at']) and value['commitment'] in ('finalized', 'confirmed'), 'status')
    need(value['program'] == PROGRAM and value['pool_address'] == POOL, 'program identity')
    need(value['genesis_hash'] is None or public_key(value['genesis_hash']), 'genesis hash')
    signer = value['signer']
    need(signer is None or (isinstance(signer, dict) and set(signer) == {'algorithm', 'key_sha256'}
                            and signer['algorithm'] == ALGORITHM and hex64(signer['key_sha256'])), 'signer')
    policy = value['policy']
    need(isinstance(policy, dict) and set(policy) == {'supply_ceiling', 'slots_per_year', 'issuance_slack'}
         and (policy['supply_ceiling'] is None or amount(policy['supply_ceiling']))
         and natural(policy['slots_per_year']) and policy['slots_per_year'] > 0 and amount(policy['issuance_slack']), 'policy')
    baseline = value['baseline']
    if baseline is not None:
        need(isinstance(baseline, dict) and set(baseline) == {'sha256', 'slot', 'epoch', 'total', 'rewards_pending',
             'validator_rate_ppb', 'slots_in_epoch', 'format', 'domain', 'rent_floor', 'backing', 'note_count'}, 'baseline fields')
        need(hex64(baseline['sha256']) and natural(baseline['slot']) and natural(baseline['epoch'])
             and amount(baseline['total']) and amount(baseline['rewards_pending']) and natural(baseline['validator_rate_ppb'], PPB)
             and natural(baseline['slots_in_epoch']) and baseline['slots_in_epoch'] > 0
             and isinstance(baseline['format'], str) and baseline['format'].encode() in POOL_FORMATS and hex64(baseline['domain'])
             and amount(baseline['rent_floor']) and amount(baseline['backing']) and natural(baseline['note_count'], MAX_COMMITMENTS), 'baseline')
    if value['status'] == UNKNOWN:
        need(value['reason'] in REASONS and value['failed'] == [] and value['checks'] == [] and value['pool'] is None
             and value['supply'] is None and value['slot'] is None and value['epoch'] is None and value['block_time'] is None
             and value['read_mode'] is None, 'unknown result')
        return value
    need(value['reason'] is None and value['read_mode'] in ('batch', 'sequential') and public_key(value['genesis_hash'])
         and natural(value['slot']) and natural(value['epoch']) and (value['block_time'] is None or natural(value['block_time'])), 'observation')
    pool = value['pool']
    pool_keys = {'present', 'owner', 'executable', 'lamports', 'data_bytes', 'data_sha256', 'format', 'domain', 'rent_floor',
                 'backing', 'note_count', 'rent_exempt_minimum', 'surplus'}
    need(isinstance(pool, dict) and set(pool) == pool_keys and type(pool['present']) is bool, 'pool fields')
    account = ('owner', 'executable', 'lamports', 'data_bytes', 'data_sha256', 'rent_exempt_minimum')
    header = ('format', 'domain', 'rent_floor', 'backing', 'note_count', 'surplus')
    if pool['present']:
        need(public_key(pool['owner']) and type(pool['executable']) is bool and amount(pool['lamports'])
             and natural(pool['data_bytes']) and hex64(pool['data_sha256']) and amount(pool['rent_exempt_minimum']), 'pool account')
    else:
        need(all(pool[key] is None for key in account + header), 'absent pool')
    if pool['format'] is None:
        need(all(pool[key] is None for key in header), 'undecoded pool')
    else:
        need(pool['present'] and isinstance(pool['format'], str) and pool['format'].encode() in POOL_FORMATS
             and pool['data_bytes'] == POOL_FORMATS[pool['format'].encode()] and hex64(pool['domain'])
             and amount(pool['rent_floor']) and amount(pool['backing']) and natural(pool['note_count'], MAX_COMMITMENTS)
             and isinstance(pool['surplus'], str) and SIGNED.fullmatch(pool['surplus']) is not None
             and int(pool['surplus']) == int(pool['lamports']) - int(pool['rent_floor']) - int(pool['backing']), 'pool header')
    supply = value['supply']
    need(isinstance(supply, dict) and set(supply) == {'total', 'circulating', 'non_circulating', 'validator_rate_ppb',
         'slots_in_epoch', 'block_height', 'rewards_pending'}, 'supply fields')
    need(all(amount(supply[key]) for key in ('total', 'circulating', 'non_circulating', 'rewards_pending'))
         and natural(supply['validator_rate_ppb'], PPB) and natural(supply['slots_in_epoch']) and supply['slots_in_epoch'] > 0
         and natural(supply['block_height']), 'supply')
    if baseline is not None:
        need(baseline['slot'] <= value['slot'] and baseline['epoch'] <= value['epoch'], 'baseline order')
    checks = value['checks']
    need(isinstance(checks, list) and [item.get('id') if isinstance(item, dict) else None for item in checks] == list(CHECKS), 'checks')
    for item in checks:
        need(set(item) == {'id', 'ok', 'detail'} and item['ok'] in (True, False, None)
             and isinstance(item['detail'], str) and len(item['detail']) <= 400, 'check')
    need(checks == evaluate(pool, supply, value['epoch'], baseline, policy), 'checks do not follow from the published numbers')
    need((value['status'], value['failed']) == verdict(checks), 'status does not follow from the checks')
    return value


# RPC --------------------------------------------------------------------------

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def loopback(host):
    if host == 'localhost':
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Rpc:
    """Direct JSON-RPC reads: no proxy, no redirect, bounded responses."""

    def __init__(self, url, timeout=10, insecure_http=False):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
            raise Usage('--rpc must be an http or https URL without credentials')
        if parts.scheme == 'http' and not loopback(parts.hostname) and not insecure_http:
            raise Usage('plain http is only read from loopback; use https or pass --insecure-http')
        self.url = url
        self.timeout = timeout
        self.batching = 'untested'
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def post(self, payload):
        request = urllib.request.Request(self.url, json.dumps(payload).encode(), {'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(RESPONSE_LIMIT + 1)
        except (OSError, ValueError, http.client.HTTPException) as error:
            raise Indeterminate('rpc_unavailable', f'endpoint did not answer: {type(error).__name__}') from None
        if len(raw) > RESPONSE_LIMIT:
            raise Indeterminate('malformed_response', 'response exceeds the size bound')
        try:
            return decode(raw)
        except (ValueError, RecursionError):
            raise Indeterminate('malformed_response', 'response is not JSON') from None

    @staticmethod
    def result(entry, method):
        if not isinstance(entry, dict):
            raise Indeterminate('malformed_response', f'{method} returned no object')
        if 'error' in entry or 'result' not in entry:
            code = entry['error'].get('code') if isinstance(entry.get('error'), dict) else None
            raise Indeterminate('rpc_error', f'{method} was refused with code {code if type(code) is int else "unknown"}')
        return entry['result']

    def call(self, method, params):
        return self.result(self.post({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}), method)

    def read(self, calls):
        """One batch when the endpoint accepts it, so the reads share a slot."""
        if self.batching != 'no':
            payload = [{'jsonrpc': '2.0', 'id': index, 'method': method, 'params': params}
                       for index, (method, params) in enumerate(calls)]
            try:
                answer = self.post(payload)
            except Indeterminate:
                if self.batching == 'yes':
                    raise
                answer = None
            ordered = None
            if isinstance(answer, list) and len(answer) == len(calls) and all(isinstance(item, dict) for item in answer):
                by_id = {item.get('id'): item for item in answer if type(item.get('id')) is int}
                if set(by_id) == set(range(len(calls))):
                    ordered = [by_id[index] for index in range(len(calls))]
            if ordered is not None:
                self.batching = 'yes'
                return [self.result(item, calls[index][0]) for index, item in enumerate(ordered)]
            if self.batching == 'yes':
                raise Indeterminate('malformed_response', 'incomplete batch response')
            # The endpoint does not take batches: ask one call at a time. The
            # caller still requires every answer to name the same slot.
            self.batching = 'no'
        return [self.call(method, params) for method, params in calls]

    @property
    def mode(self):
        return 'sequential' if self.batching == 'no' else 'batch'


def malformed(what):
    return Indeterminate('malformed_response', f'unexpected {what}')


def context(value, what):
    if (not isinstance(value, dict) or not isinstance(value.get('context'), dict)
            or not natural(value['context'].get('slot')) or 'value' not in value):
        raise malformed(what)
    return value['context']['slot'], value['value']


def account(value, what):
    if value is None:
        return None
    data = value.get('data') if isinstance(value, dict) else None
    if (not isinstance(data, list) or len(data) != 2 or data[1] != 'base64' or not isinstance(data[0], str)
            or not natural(value.get('lamports'), U64) or not public_key(value.get('owner'))
            or type(value.get('executable')) is not bool):
        raise malformed(what)
    try:
        raw = base64.b64decode(data[0], validate=True)
    except ValueError:
        raise malformed(what) from None
    return {'lamports': value['lamports'], 'owner': value['owner'], 'executable': value['executable'], 'data': raw}


def observe(rpc, commitment, attempts=8, pause=0.1):
    """One pool account, one supply and the reward state, from responses that
    all name the same slot. Reads that straddle a slot are repeated.

    The supply, epoch and block height come from the node's bank for that
    slot. Account contents can be newer: a node serves an account from its
    latest root, which may be ahead of the slot it reports as finalized. So
    backing is only ever compared with the balance of the same account record,
    and the reward state is read in a way that a newer copy cannot understate."""
    config = {'commitment': commitment}
    calls = [('getAccountInfo', [POOL, dict(config, encoding='base64')]),
             ('getSupply', [dict(config, excludeNonCirculatingAccountsList=True)]),
             ('getAccountInfo', [EPOCH_REWARDS, dict(config, encoding='base64')]),
             ('getEpochInfo', [config]),
             ('getInflationRate', [])]
    for attempt in range(attempts):
        if attempt:
            time.sleep(pause)
        pool, supply, rewards, epoch, inflation = rpc.read(calls)
        pool_slot, pool_value = context(pool, 'pool account')
        supply_slot, supply_value = context(supply, 'supply')
        rewards_slot, rewards_value = context(rewards, 'reward state')
        if (not isinstance(epoch, dict) or not all(natural(epoch.get(key)) for key in ('absoluteSlot', 'blockHeight', 'epoch', 'slotsInEpoch'))
                or not epoch['slotsInEpoch']):
            raise malformed('epoch')
        if (not isinstance(inflation, dict) or not natural(inflation.get('epoch')) or type(inflation.get('validator')) not in (int, float)
                or not math.isfinite(inflation['validator']) or not 0 <= inflation['validator'] <= 1):
            raise malformed('inflation rate')
        # The inflation rate has no commitment parameter. One epoch earlier is
        # accepted because the schedule only falls: it is an upper bound.
        if (pool_slot == supply_slot == rewards_slot == epoch['absoluteSlot']
                and epoch['epoch'] - 1 <= inflation['epoch'] <= epoch['epoch']):
            break
    else:
        raise Indeterminate('inconsistent_slots', f'reads did not share one slot in {attempts} attempts')
    if (not isinstance(supply_value, dict)
            or not all(natural(supply_value.get(key), U64) for key in ('total', 'circulating', 'nonCirculating'))):
        raise malformed('supply')
    genesis = rpc.call('getGenesisHash', [])
    if not public_key(genesis):
        raise malformed('genesis hash')
    pool_account = account(pool_value, 'pool account')
    minimum = 0
    if pool_account is not None:
        minimum = rpc.call('getMinimumBalanceForRentExemption', [len(pool_account['data'])])
        if not natural(minimum, U64):
            raise malformed('rent-exempt minimum')
    try:
        block_time = rpc.call('getBlockTime', [pool_slot])
    except Indeterminate as error:
        if error.reason != 'rpc_error':
            raise
        block_time = None
    rate = min(PPB, math.ceil(inflation['validator'] * PPB))
    record = {'total': str(supply_value['total']), 'circulating': str(supply_value['circulating']),
              'non_circulating': str(supply_value['nonCirculating']), 'validator_rate_ppb': rate,
              'slots_in_epoch': epoch['slotsInEpoch'], 'block_height': epoch['blockHeight']}
    # EpochRewards holds the first block height of the current distribution, its
    # number of blocks and, at byte 64, the rewards computed for the epoch. They
    # are credited in those blocks. Until this bank has passed the last of them
    # the whole amount counts as pending; the account's own progress counter is
    # not used because the account may be newer than the supply beside it.
    state = account(rewards_value, 'reward state')
    if state is not None and len(state['data']) >= 81:
        first, blocks = struct.unpack_from('<QQ', state['data'], 0)
        computed = struct.unpack_from('<Q', state['data'], 64)[0]
        record['rewards_pending'] = str(0 if epoch['blockHeight'] + 1 >= first + blocks else computed)
    else:
        record['rewards_pending'] = None
    return {'genesis_hash': genesis, 'slot': pool_slot, 'epoch': epoch['epoch'],
            'block_time': block_time if natural(block_time) else None, 'read_mode': rpc.mode,
            'pool': pool_record(pool_account, minimum), 'supply': record}


# Signature --------------------------------------------------------------------

def openssl(args, data=b''):
    try:
        result = subprocess.run([OPENSSL, *args], input=data, capture_output=True, timeout=15,
                                env={'PATH': '/usr/bin:/bin', 'OPENSSL_CONF': '/dev/null'})
    except (OSError, subprocess.TimeoutExpired):
        raise SignatureError('the cryptographic tool is unavailable') from None
    if result.returncode:
        # Its diagnostics are withheld: they may describe the key.
        raise SignatureError('cryptographic operation failed')
    return result.stdout


def private_file(path, limit):
    """An existing, bounded, owner-only regular file. Its bytes are not read here."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise Usage(f'cannot open {path}') from None
    try:
        meta = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077 or not 1 <= meta.st_size <= limit:
        raise Usage(f'{path} must be a bounded regular file readable only by its owner')
    return str(path)


def public_pem(der):
    if len(der) != len(P256) + 64 or not der.startswith(P256):
        raise SignatureError('the key is not a named-curve P-256 key')
    text = base64.b64encode(der)
    return (b'-----BEGIN PUBLIC KEY-----\n' + b'\n'.join(text[i:i + 64] for i in range(0, len(text), 64))
            + b'\n-----END PUBLIC KEY-----\n')


def public_der(pem):
    if b'PRIVATE' in pem:
        raise SignatureError('a public key is required')
    der = openssl(['pkey', '-pubin', '-outform', 'DER'], pem)
    public_pem(der)
    return der


class Signer:
    """Signs with a key file supplied by the operator. The key is handed to
    the system OpenSSL by path; this process never reads, copies or prints it."""

    def __init__(self, key, password=None):
        self.key = private_file(key, 16384)
        self.passin = ['-passin', 'file:' + private_file(password, 1024)] if password else ['-passin', 'pass:']
        self.der = openssl(['pkey', '-in', self.key, *self.passin, '-pubout', '-outform', 'DER'])
        public_pem(self.der)
        self.identity = {'algorithm': ALGORITHM, 'key_sha256': sha(self.der)}

    def sign(self, raw):
        signature = openssl(['dgst', '-sha256', '-sign', self.key, *self.passin], DOMAIN + raw)
        authenticate(raw, signature, self.der)
        return signature


def authenticate(raw, signature, der):
    if not 8 <= len(signature) <= 80:
        raise SignatureError('malformed signature')
    with tempfile.TemporaryDirectory(prefix='supply-monitor-verify-') as directory:
        key, detached = Path(directory, 'public.pem'), Path(directory, 'signature')
        key.write_bytes(public_pem(der))
        detached.write_bytes(signature)
        openssl(['dgst', '-sha256', '-verify', str(key), '-signature', str(detached)], DOMAIN + raw)


# Commands ---------------------------------------------------------------------

def read_public(path, limit):
    try:
        with open(path, 'rb') as stream:
            raw = stream.read(limit + 1)
    except OSError:
        raise Usage(f'cannot read {path}') from None
    if not 1 <= len(raw) <= limit:
        raise Usage(f'{path} is empty or exceeds its size bound')
    return raw


def write_atomic(path, raw):
    path = Path(path)
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(8))
    try:
        with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644), 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise Usage(f'cannot write {path}') from None


def load_baseline(path, commitment):
    if path is None or not os.path.lexists(path):
        return None
    raw = read_public(path, RESULT_LIMIT)
    try:
        value = validate(decode(raw))
    except (ValueError, RecursionError):
        raise Usage('the baseline is not a supply monitor result') from None
    if raw != encode(value) or value['status'] != GREEN or value['pool']['format'] is None:
        raise Usage('the baseline must be an unmodified green result')
    if value['commitment'] != commitment:
        raise Usage('the baseline was read at another commitment level')
    return value['genesis_hash'], baseline_summary(raw, value)


def document(args, signer):
    """Observe and evaluate. Returns the result and, when nothing was
    observed, a note for the operator's console."""
    policy = {'supply_ceiling': None if args.supply_ceiling is None else str(args.supply_ceiling),
              'slots_per_year': args.slots_per_year, 'issuance_slack': str(args.issuance_slack)}
    value = {'format': FORMAT, 'observed_at': int(time.time()), 'commitment': args.commitment,
             'program': PROGRAM, 'pool_address': POOL, 'policy': policy, 'baseline': None,
             'signer': signer.identity if signer else None}
    loaded = load_baseline(args.baseline, args.commitment)
    try:
        rpc = Rpc(args.rpc, args.timeout, args.insecure_http)
        seen = observe(rpc, args.commitment, args.attempts)
        expected = [args.expect_genesis] if args.expect_genesis else []
        if loaded:
            expected.append(loaded[0])
        if any(seen['genesis_hash'] != item for item in expected):
            raise Indeterminate('wrong_network', 'the endpoint serves another genesis')
        baseline = loaded[1] if loaded else None
        if baseline and (seen['slot'] < baseline['slot'] or seen['epoch'] < baseline['epoch']):
            raise Indeterminate('stale_endpoint', 'the endpoint is behind the baseline')
        supply = seen['supply']
        if supply['rewards_pending'] is None:
            # No reward state to read: allow one whole epoch of issuance instead.
            supply['rewards_pending'] = str(ceil_div(int(supply['total']) * supply['validator_rate_ppb'] * supply['slots_in_epoch'],
                                                     PPB * policy['slots_per_year']))
        checks = evaluate(seen['pool'], supply, seen['epoch'], baseline, policy)
        status, failed = verdict(checks)
        value.update(seen, baseline=baseline, checks=checks, status=status, failed=failed, reason=None)
    except Indeterminate as error:
        value.update(status=UNKNOWN, reason=error.reason, failed=[], checks=[], pool=None, supply=None, slot=None, epoch=None,
                     block_time=None, read_mode=None, genesis_hash=None)
        return validate(value), str(error)
    return validate(value), None


def check(args):
    if args.signing_key and not args.output:
        raise Usage('--signing-key needs --output: the signature is written next to the result')
    if args.password_file and not args.signing_key:
        raise Usage('--password-file needs --signing-key')
    signature_path = str(args.output) + '.sig' if args.output else None
    if args.output and not args.signing_key and os.path.lexists(signature_path):
        raise Usage(f'{signature_path} exists; an unsigned result would be published beside a stale signature')
    signer = Signer(args.signing_key, args.password_file) if args.signing_key else None
    value, note = document(args, signer)
    raw = encode(value)
    signature = signer.sign(raw) if signer else None
    if args.output:
        if signature:
            write_atomic(signature_path, signature)
        write_atomic(args.output, raw)
        summary = {'status': value['status'], 'reason': value['reason'], 'failed': value['failed'], 'slot': value['slot'],
                   'signed': signature is not None, 'result_sha256': sha(raw)}
        print(json.dumps(summary, sort_keys=True))
    else:
        sys.stdout.write(raw.decode())
    if note:
        print(f'supply monitor: no observation: {note}', file=sys.stderr)
    if args.baseline and value['status'] == GREEN:
        write_atomic(args.baseline, raw)
    return EXIT[value['status']]


def verify(args):
    raw = read_public(args.result, RESULT_LIMIT)
    signature = read_public(str(args.result) + '.sig', 80)
    der = public_der(read_public(args.public_key, 4096))
    if not hex64(args.key_sha256) or sha(der) != args.key_sha256:
        raise SignatureError('the public key differs from the independent pin')
    authenticate(raw, signature, der)
    try:
        value = validate(decode(raw))
    except (ValueError, RecursionError) as error:
        raise SignatureError(str(error)) from None
    if raw != encode(value) or value['signer'] != {'algorithm': ALGORITHM, 'key_sha256': args.key_sha256}:
        raise SignatureError('the result is not in canonical form or names another key')
    if args.expect_genesis and value['genesis_hash'] != args.expect_genesis:
        raise SignatureError('the result describes another network')
    if args.max_age is not None and not -300 <= time.time() - value['observed_at'] <= args.max_age:
        raise SignatureError('the result is older than --max-age')
    if args.min_slot is not None and (value['slot'] is None or value['slot'] < args.min_slot):
        raise SignatureError('the result is older than --min-slot')
    print(json.dumps({'authentic': True, 'status': value['status'], 'reason': value['reason'], 'failed': value['failed'],
                      'slot': value['slot'], 'observed_at': value['observed_at'], 'result_sha256': sha(raw)}, sort_keys=True))
    return EXIT[value['status']]


def whole(text):
    if AMOUNT.fullmatch(text) is None or int(text) > U64:
        raise argparse.ArgumentTypeError('expected a whole number of base units')
    return int(text)


def positive(text):
    value = whole(text)
    if not 0 < value <= 2**53 - 1:
        raise argparse.ArgumentTypeError('expected a positive whole number')
    return value


def parser():
    top = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = top.add_subparsers(dest='command', required=True)
    run = commands.add_parser('check', help='observe one endpoint and write a result')
    run.add_argument('--rpc', required=True, help='JSON-RPC endpoint of a validator')
    run.add_argument('--commitment', choices=('finalized', 'confirmed'), default='finalized')
    run.add_argument('--expect-genesis', help='refuse any other network')
    run.add_argument('--baseline', type=Path, help='last green result; read if present, replaced when this run is green')
    run.add_argument('--output', type=Path, help='result path; the signature goes to PATH.sig')
    run.add_argument('--signing-key', type=Path, help='owner-only P-256 private key in PEM; omit for an unsigned result')
    run.add_argument('--password-file', type=Path, help='owner-only file holding the key password')
    run.add_argument('--supply-ceiling', type=whole, help='declared maximum total supply in base units')
    run.add_argument('--slots-per-year', type=positive, default=SLOTS_PER_YEAR)
    run.add_argument('--issuance-slack', type=whole, default=0, help='extra base units of growth tolerated since the baseline')
    run.add_argument('--attempts', type=positive, default=8, help='tries for reads that share one slot')
    run.add_argument('--timeout', type=positive, default=10, help='seconds per request')
    run.add_argument('--insecure-http', action='store_true', help='read plain http from a host that is not loopback')
    seal = commands.add_parser('verify', help='authenticate a signed result and recompute its verdict')
    seal.add_argument('--result', required=True, type=Path)
    seal.add_argument('--public-key', required=True, type=Path)
    seal.add_argument('--key-sha256', required=True, help='SHA-256 of the public key DER, obtained independently')
    seal.add_argument('--expect-genesis')
    seal.add_argument('--max-age', type=whole, help='seconds')
    seal.add_argument('--min-slot', type=whole)
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    if getattr(args, 'expect_genesis', None) and not public_key(args.expect_genesis):
        print('supply monitor: --expect-genesis is not a genesis hash', file=sys.stderr)
        return EXIT_USAGE
    try:
        return check(args) if args.command == 'check' else verify(args)
    except Usage as error:
        print(f'supply monitor: {error}', file=sys.stderr)
        return EXIT_USAGE
    except SignatureError as error:
        print(f'supply monitor: {error}', file=sys.stderr)
        return EXIT_SIGNATURE


if __name__ == '__main__':
    sys.exit(main())
