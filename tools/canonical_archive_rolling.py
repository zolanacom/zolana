"""Private in-process serving of complete, rolling canonical SQLite prefixes.

Gateway's existing invited HTTP handler must authorize each call before .page().
This module creates no listener, credentials, admission cache or writer. The
owner fixes one local store and the existing primary RPC transport at startup.
Each page pins ONE read-only SQLite transaction while existing ArchiveRPC checks
the fresh primary target, genesis and continuation. Commits become visible only
to subsequent pages; a failed/busy/hot-journal read is never an absence result.
Trust remains operator RPC data, not an independent consensus/light proof.
"""
import math
from pathlib import Path
import threading
import time
from types import SimpleNamespace

from canonical_archive_backend import CanonicalStoreRPC, HEADER, FULL, configuration
from canonical_archive_store import Reader, PAGE_LIMIT, decoded, encoded, identity
from gateway_archival import ArchiveRPC, parameters
from history_retention import natural


def check(value, reason):
    if not value:
        raise ValueError(reason)


def remaining(deadline, timeout=15):
    check(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 15,
          'positive bounded canonical page deadline required')
    value = deadline - time.monotonic()
    check(value > 0, 'rolling canonical page deadline exceeded')
    return min(value, timeout)


class _PinnedSource:
    """Only the three existing fixed internal read shapes, on one snapshot."""
    def __init__(self, reader, deadline):
        self.reader, self.deadline, self.calls = reader, deadline, 0

    def forward(self, raw, timeout):
        remaining(self.deadline, timeout)
        self.calls += 1
        check(self.calls <= 19, 'bounded canonical page call count exceeded')
        request = decoded(raw, 4096)
        check(type(request) is dict and set(request) == {'jsonrpc', 'id', 'method', 'params'}
              and request['jsonrpc'] == '2.0' and type(request['id']) is int and request['id'] == 1
              and type(request['params']) is list, 'fixed internal canonical request required')
        method, params = request['method'], request['params']
        if method == 'getGenesisHash':
            check(params == [], 'genesis parameters denied')
            result = self.reader.network['genesis_hash']
        elif method == 'getBlock':
            check(len(params) == 2 and natural(params[0]) and params[0] > 0 and
                  (configuration(params[1], HEADER) or configuration(params[1], FULL)),
                  'only fixed finalized header or full block reads permitted')
            result = CanonicalStoreRPC._block(self.reader, params[0])
            if configuration(params[1], HEADER):
                result = {key: value for key, value in result.items() if key != 'transactions'}
        elif method == 'getBlocksWithLimit':
            check(len(params) == 3 and natural(params[0]) and params[0] > 0
                  and type(params[1]) is int and params[1] == 16
                  and configuration(params[2], dict(commitment='finalized')),
                  'only bounded finalized produced-slot reads permitted')
            result = CanonicalStoreRPC._slots(self.reader, params[0])
        else:
            raise ValueError('canonical source method denied')
        response = encoded(dict(jsonrpc='2.0', id=1, result=result))
        check(len(response) <= PAGE_LIMIT, 'rolling canonical source response bound exceeded')
        remaining(self.deadline, timeout)
        return response


class RollingArchive:
    """Drop-in private Gateway.archive .page interface; no access is activated.

    Construct only after Gateway's normal invite-required/network/primary
    transport checks. Existing HTTP authorization/quota handling stays in place.
    Busy readers fail immediately rather than creating an unbounded wait queue.
    """
    def __init__(self, gateway, path, *, max_readers=2, coverage=None):
        check(type(max_readers) is int and 1 <= max_readers <= 4, 'one to four bounded archive readers required')
        check(gateway.info.get('invite_required') is True, 'rolling archive requires the existing invited gateway')
        self.path = Path(path)
        check(self.path.is_absolute() and self.path.resolve() == self.path, 'fixed real absolute canonical store required')
        network = gateway.info['network']
        self.network = identity(network, network['genesis_hash'])
        self.primary = gateway.forward
        check(callable(self.primary) and type(gateway.info.get('rpc_audience')) is str,
              'existing fixed gateway primary transport required')
        self.audience = gateway.info['rpc_audience']
        self.readers = threading.BoundedSemaphore(max_readers)
        check(coverage is None or callable(coverage), 'optional bounded coverage callback required')
        self._coverage = coverage

    def page(self, request):
        # Copy and bound before touching the store or primary transport. No
        # request field can name a path/source or change the pinned network.
        value = decoded(encoded(request), 4096)
        check(type(value) is dict and not set(value) - {'jsonrpc', 'id', 'method', 'params'}
              and type(value.get('id')) in (int, str) and len(str(value['id'])) <= 64
              and value.get('jsonrpc', '2.0') == '2.0'
              and value.get('method', 'getWalletCanonicalHistory') == 'getWalletCanonicalHistory',
              'fixed bounded canonical history request required')
        _, target, _ = parameters(value)
        deadline = time.monotonic() + 15
        check(self.readers.acquire(blocking=False), 'rolling canonical readers busy')
        try:
            if self._coverage is not None:
                # Capture must commit before this page opens its pinned read
                # transaction. Waiting with a Reader open would block SQLite
                # publication. This shares the page's unchanged15s deadline.
                self._coverage(target, deadline)
                remaining(deadline)
            with Reader(self.path, self.network, self.network['genesis_hash']) as reader:
                remaining(deadline)
                # Keep slow SQL from publishing after this page's unchanged
                # overall deadline. Existing SQLite row/value limits stay set.
                reader.db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                check(target <= reader.slot, 'target exceeds complete committed canonical prefix')
                source = _PinnedSource(reader, deadline)

                def primary(raw, timeout):
                    query = decoded(raw, 4096)
                    check(query == dict(jsonrpc='2.0', id=1, method='getBlock', params=[target, HEADER]),
                          'canonical primary transport is fixed to this fresh finalized target')
                    body = self.primary(raw, timeout=remaining(deadline, timeout))
                    check(type(body) is bytes and 0 < len(body) <= PAGE_LIMIT,
                          'bounded primary canonical response required')
                    decoded(body, PAGE_LIMIT)  # Reject duplicate/nonfinite JSON before ArchiveRPC.
                    remaining(deadline)
                    return body

                gateway = SimpleNamespace(info=dict(network=self.network, rpc_audience=self.audience), forward=primary)
                # Never contacted: .forward is bound immediately to the fixed
                # private Reader. Reuse ArchiveRPC without a second listener.
                archive = ArchiveRPC(gateway, 'http://127.0.0.1:1', dict(policy={}))
                archive.forward = source.forward
                result = archive.page(value)
                remaining(deadline)
            remaining(deadline)
            return result
        finally:
            self.readers.release()
