"""LOCAL-092 preparation prototype: private in-process full archive RPC reads.

This is an inert transport seam for the existing ArchiveRPC, not a listener,
service configuration, capture daemon or independent proof of canonicality.
The operator fixes one local R3 full-store path/network/genesis at construction.
The existing ArchiveRPC must retain its separate fresh primary transport and
genesis/target/continuation/deadline checks. No request can select another source.
"""
import math
from pathlib import Path
import time

from canonical_archive_store import (Reader, BLOCK_ROW, PAGE_LIMIT, block_body,
                                     decoded, encoded, identity, number, row_block)
from history_retention import natural

HEADER = dict(transactionDetails='none', rewards=False, commitment='finalized')
FULL = dict(encoding='base64', transactionDetails='full', rewards=False,
            commitment='finalized', maxSupportedTransactionVersion=0)


def check(value, message):
    if not value:
        raise ValueError(message)


def configuration(value, expected):
    return (type(value) is dict and value == expected and
            all(type(value[key]) is type(item) for key, item in expected.items()))


class CanonicalStoreRPC:
    """Read-only fixed local source; inject only as an ArchiveRPC transport."""
    def __init__(self, path, network, genesis):
        self.path = Path(path)
        self.network = identity(network, genesis)
        self.genesis = genesis

    @staticmethod
    def _block(reader, slot):
        check(slot <= reader.slot, 'canonical target exceeds complete committed prefix')
        actual, body = row_block(reader.db.execute('SELECT ' + BLOCK_ROW +
            ' FROM blocks WHERE slot=?', (number(slot),)).fetchone())
        check(actual == slot, 'canonical block index changed')
        return body

    @staticmethod
    def _slots(reader, start):
        previous = reader.db.execute('SELECT ' + BLOCK_ROW +
            ' FROM blocks WHERE slot<? ORDER BY slot DESC LIMIT 1', (number(start),)).fetchone()
        after, blockhash, height = 0, None, 0
        if previous is not None:
            after, body = row_block(previous)
            blockhash, height = body['blockhash'], body['blockHeight']
        slots = []
        rows = reader.db.execute('SELECT ' + BLOCK_ROW +
            ' FROM blocks WHERE slot>=? ORDER BY slot LIMIT 16', (number(start),))
        for row in rows:
            slot, body = row_block(row)
            check(start <= slot <= reader.slot, 'canonical block range exceeds committed prefix')
            block_body(slot, body, after, blockhash, height)
            slots.append(slot)
            after, blockhash, height = slot, body['blockhash'], body['blockHeight']
        return slots

    def forward(self, raw, timeout):
        # SQLite/file IO is not preemptible here. A slow read must fail rather
        # than publish after the caller's shared deadline; no retry is made.
        check(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 15,
              'positive bounded remaining canonical deadline required')
        deadline = time.monotonic() + timeout
        request = decoded(raw, 4096)
        check(type(request) is dict and set(request) == {'jsonrpc', 'id', 'method', 'params'} and
              request['jsonrpc'] == '2.0' and type(request['id']) is int and request['id'] == 1 and
              type(request['params']) is list, 'fixed internal canonical request required')
        method, params = request['method'], request['params']
        check(method in ('getGenesisHash', 'getBlock', 'getBlocksWithLimit'), 'canonical source method denied')
        if method == 'getGenesisHash':
            check(params == [], 'genesis parameters denied')
        elif method == 'getBlock':
            check(len(params) == 2 and natural(params[0]) and params[0] > 0 and
                  (configuration(params[1], HEADER) or configuration(params[1], FULL)),
                  'only fixed finalized header or full base64 block reads permitted')
        else:
            check(len(params) == 3 and natural(params[0]) and params[0] > 0 and
                  type(params[1]) is int and params[1] == 16 and
                  configuration(params[2], dict(commitment='finalized')),
                  'only bounded finalized produced-slot reads permitted')
        check(time.monotonic() < deadline, 'canonical source deadline exceeded')
        with Reader(self.path, self.network, self.genesis) as reader:
            if method == 'getGenesisHash':
                result = reader.network['genesis_hash']
            elif method == 'getBlock':
                result = self._block(reader, params[0])
                if configuration(params[1], HEADER):
                    result = {key: value for key, value in result.items() if key != 'transactions'}
            else:
                result = self._slots(reader, params[0])
        check(time.monotonic() < deadline, 'canonical source deadline exceeded')
        response = encoded(dict(jsonrpc='2.0', id=1, result=result))
        check(len(response) <= PAGE_LIMIT and time.monotonic() < deadline,
              'canonical source response bound or deadline exceeded')
        return response
