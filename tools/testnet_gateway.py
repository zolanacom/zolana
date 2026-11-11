#!/usr/bin/env python3
"""Loopback invited-wallet RPC ingress. Raw validator RPC remains operator-local."""
import argparse
import base64
import concurrent.futures
from collections import OrderedDict
import gzip
from http.server import BaseHTTPRequestHandler
import json
import re
import subprocess
import threading
import time
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request
from test_faucet import BoundedServer, Faucet

METHODS = {
    "getShieldedFeeQuote", "submitShieldedPayment", "getShieldedPaymentStatus",
    "getWalletReadBatch",
    "getWalletSyncSnapshot",
    "getWalletHistoryBlocks", "getWalletRetainedHistory", "getWalletRetainedHistoryV2", "getWalletRetainedHistoryV3", "getWalletCanonicalHistory",
    "getGenesisHash", "getHealth", "getVersion", "getAccountInfo", "getMultipleAccounts",
    "getBlocks", "getBlock", "getBlockHeight", "getSlot", "getEpochInfo", "getBalance",
    "getSignaturesForAddress", "getSignatureStatuses", "getTransaction", "getLatestBlockhash",
    "getMinimumBalanceForRentExemption", "getFeeForMessage", "sendTransaction", "getProgramAccounts",
}

# Small reads only. No write, history scan, caller URL or arbitrary RPC batch.
READ_METHODS = {'getAccountInfo', 'getBalance', 'getLatestBlockhash', 'getSlot',
                'getMinimumBalanceForRentExemption', 'getFeeForMessage'}


def read_calls(request):
    params = request.get('params')
    if not isinstance(params, list) or len(params) != 1 or not isinstance(params[0], list) or not 1 <= len(params[0]) <= 16:
        raise ValueError('invalid bounded read request')
    for call in params[0]:
        if (not isinstance(call, dict) or set(call) != {'method', 'params'} or
                not isinstance(call['method'], str) or call['method'] not in READ_METHODS or
                not isinstance(call['params'], list)):
            raise ValueError('only bounded wallet reads may be aggregated')
        method, args = call['method'], call['params']
        if method == 'getMinimumBalanceForRentExemption':
            if len(args) != 1 or type(args[0]) is not int or not 0 <= args[0] <= 131072:
                raise ValueError('invalid rent read')
            continue
        count = 1 if method in {'getLatestBlockhash', 'getSlot'} else 2
        if len(args) != count or args[-1] not in ({'commitment': 'confirmed'}, {'commitment': 'finalized'},
                {'commitment': 'confirmed', 'encoding': 'base64'}):
            raise ValueError('invalid bounded read configuration')
        if method in {'getAccountInfo', 'getBalance'}:
            if not isinstance(args[0], str) or re.fullmatch('[1-9A-HJ-NP-Za-km-z]{32,44}', args[0]) is None:
                raise ValueError('invalid public read address')
        elif method == 'getFeeForMessage':
            if not isinstance(args[0], str) or not 1 <= len(args[0]) <= 1644:
                raise ValueError('invalid fee message size')
            message = base64.b64decode(args[0], validate=True)
            if not 1 <= len(message) <= 1232 or base64.b64encode(message).decode() != args[0]:
                raise ValueError('invalid fee message encoding')
    return params[0]


RESPONSE_LIMIT = 16 * 1024 * 1024
UPSTREAM_REQUEST_LIMIT = 51200
HISTORY_REQUEST_LIMIT = 48 * 1024
HISTORY_PAGE = 256
HISTORY_AUTH_BLOCKS = 16
COMPACT_AUTH_HEADERS = 256
COMPACT_AUTH_BYTES = 64 * 1024
HISTORY_SIZE_CODE = -32062
HISTORY_SIZE_MESSAGE = 'Wallet history response exceeds byte limit'
RELAY_CAPACITY_CODE = -32040
RELAY_CAPACITY_MESSAGE = 'Testnet private payment capacity reached'
# A process-wide snapshot pool; construction does not start any worker thread.
# The original private RPC capsule has four slots. Leave two slots for its
# existing single grant/relay reads; public TLS capacity is a separate bound.
SNAPSHOT_WORKERS = 2
_SNAPSHOT_READS = concurrent.futures.ThreadPoolExecutor(max_workers=SNAPSHOT_WORKERS,
    thread_name_prefix='wallet-snapshot')
# Ordinary gateway reads share the same two permits as snapshot reads. Grant
# and relay children use their existing separate single-request transports.
_UPSTREAM_SLOTS = threading.BoundedSemaphore(2)


def _observe_failure(observer, stage, error):
    try:
        if observer is not None:
            observer(stage, error)
    except Exception:
        pass  # Optional operator diagnostics cannot change request decisions.


class HistoryTooLarge(ValueError):
    pass


class _UpstreamResponseTooLarge(ValueError):
    pass


class _SnapshotReadCancelled(ValueError):
    pass


class _FinalizedBlockCache:
    """Bounded public finalized blocks only; never admission or mutable state."""
    MAX_ENTRIES = 512
    MAX_BYTES = 16 * 1024 * 1024
    MAX_AGE = 60

    def __init__(self):
        self._entries = OrderedDict()
        self._bytes = 0
        self._lock = threading.Lock()

    @staticmethod
    def key(call):
        from wallet_sync_snapshot import FULL, HEADER, natural
        if not isinstance(call, dict) or call.get('method') != 'getBlock':
            return None
        args = call.get('params')
        if not isinstance(args, list) or len(args) != 2 or not natural(args[0]) or not isinstance(args[1], dict):
            return None
        for kind, options in (('full', FULL), ('header', HEADER)):
            if args[1] == options and all(type(args[1][k]) is type(v) for k, v in options.items()):
                return args[0], kind
        return None

    def _prune(self, now):
        for key, (created, raw) in list(self._entries.items()):
            if now - created >= self.MAX_AGE:
                del self._entries[key]
                self._bytes -= len(raw)

    def get(self, key):
        if key is None:
            return None
        with self._lock:
            self._prune(time.monotonic())
            value = self._entries.get(key)
            if value is None:
                return None
            self._entries.move_to_end(key)
            return value[1]  # bytes remain immutable; every hit is parsed anew.

    def put(self, key, raw, result):
        from wallet_sync_snapshot import _header
        if (key is None or not isinstance(raw, bytes) or len(raw) > self.MAX_BYTES
                or not isinstance(result, dict)
                or not _header({k: v for k, v in result.items() if k != 'transactions'})
                or (key[1] == 'full' and not isinstance(result.get('transactions'), list))
                or (key[1] == 'header' and 'transactions' in result)):
            return
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            previous = self._entries.pop(key, None)
            if previous is not None:
                self._bytes -= len(previous[1])
            self._entries[key] = (now, raw)
            self._bytes += len(raw)
            while len(self._entries) > self.MAX_ENTRIES or self._bytes > self.MAX_BYTES:
                _, (_, removed) = self._entries.popitem(last=False)
                self._bytes -= len(removed)


def accepts_history_gzip(values):
    """Optional explicit gzip only; ambiguous negotiation stays identity."""
    if (len(values) != 1 or not isinstance(values[0], str) or
            not 1 <= len(values[0]) <= 1024 or not values[0].isascii()):
        return False
    codings = {}
    for item in values[0].split(','):
        match = re.fullmatch(r"([!#$%&'*+\-.^_`|~0-9A-Za-z]+)(?:[ \t]*;[ \t]*q[ \t]*=[ \t]*(0(?:\.[0-9]{0,3})?|1(?:\.0{0,3})?))?",
                             item.strip(' \t'), re.IGNORECASE)
        if match is None or match[1].lower() in codings:
            return False
        codings[match[1].lower()] = float(match[2]) if match[2] is not None else 1.0
    return codings.get('gzip', 0) > 0


def history_encoding(raw, accepted, deadline):
    """Keep the uncompressed history bound and original response deadline."""
    if not isinstance(raw, bytes):
        raise ValueError('invalid history response bytes')
    if len(raw) > RESPONSE_LIMIT:
        raise HistoryTooLarge(HISTORY_SIZE_MESSAGE)
    if time.monotonic() >= deadline:
        raise ValueError('wallet history/read deadline exceeded')
    encoded = gzip.compress(raw, compresslevel=1, mtime=0) if accepted and len(raw) >= 1024 else None
    if time.monotonic() >= deadline:
        raise ValueError('wallet history/read deadline exceeded')
    return (encoded, 'gzip') if encoded is not None and len(encoded) < len(raw) else (raw, None)


def retained_window(request):
    from gateway_history import parameters, PAGE_BLOCKS_V2, PAGE_BLOCKS_WIDE, PAGE_BLOCKS_LARGE
    params = request.get('params')
    maximum = PAGE_BLOCKS_V2
    if isinstance(params, list) and len(params) == 4:
        if type(params[3]) is not int or params[3] not in (PAGE_BLOCKS_WIDE, PAGE_BLOCKS_LARGE):
            raise ValueError('invalid explicit retained page bound')
        maximum = params[3]
        request = dict(request, params=params[:3])
    parameters(request)
    return request, maximum


def batch_results(raw, count, max_count=16):
    """Correlate a complete bounded upstream response, never its arrival order."""
    if (type(max_count) is not int or max_count not in (16, HISTORY_PAGE) or
            type(count) is not int or not 1 <= count <= max_count):
        raise ValueError('bounded upstream read batch required')
    if not isinstance(raw, bytes):
        raise ValueError('invalid upstream response bytes')
    if len(raw) > RESPONSE_LIMIT:
        raise _UpstreamResponseTooLarge('RPC response exceeds gateway limit')
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('ambiguous upstream JSON object')
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError('nonfinite upstream JSON value')
    response = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if not isinstance(response, list) or len(response) != count:
        raise ValueError('complete upstream read batch unavailable')
    results = {}
    for item in response:
        if (not isinstance(item, dict) or set(item) != {'jsonrpc', 'id', 'result'} or
                item['jsonrpc'] != '2.0' or type(item['id']) is not int or
                not 0 <= item['id'] < count or item['id'] in results or item['result'] is None):
            raise ValueError('complete upstream read result unavailable')
        results[item['id']] = item['result']
    if len(results) != count:
        raise ValueError('complete upstream read batch unavailable')
    return [results[index] for index in range(count)]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


class Gateway:
    def __init__(self, faucet, history_root=None, archive_rpc=None, relay_root=None, *, authorize_many=False,
                 compact_headers_per_unit=HISTORY_AUTH_BLOCKS, archive_store=None, archive_capture_policy=None):
        if archive_rpc is not None and archive_store is not None:
            raise ValueError('choose one fixed canonical archive source')
        if archive_capture_policy is not None and archive_store is None:
            raise ValueError('canonical capture requires a fixed private archive store')
        if type(authorize_many) is not bool:
            raise ValueError('explicit bulk authorization capability required')
        if (type(compact_headers_per_unit) is not int or
                compact_headers_per_unit not in (HISTORY_AUTH_BLOCKS, COMPACT_AUTH_HEADERS) or
                (compact_headers_per_unit != HISTORY_AUTH_BLOCKS and not authorize_many)):
            raise ValueError('explicit supported compact authorization policy required')
        self.authorize_many = authorize_many
        self.compact_headers_per_unit = compact_headers_per_unit
        self.relay = None
        self.faucet = faucet
        self.info = faucet.command("access-info")
        if self.info.get("invite_required") is not True:
            raise ValueError("RPC gateway requires durable invitation admission")
        profile = json.loads((faucet.root / "profile.json").read_bytes())
        self.pool = profile.get('pool')
        self.upstream = profile["rpc"]["url"]
        parsed = urllib.parse.urlsplit(self.upstream)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or self.upstream == self.info["rpc_audience"]:
            raise ValueError("gateway needs a separate pinned loopback validator RPC")
        self.operator=None
        ledger=json.loads((faucet.root/'claims.json').read_bytes())
        if ledger['policy'].get('operator_rpc'):
            from operator_transport import Operator
            self.operator=Operator(self.upstream,faucet.root/'rpc-access.key')
            if ledger['policy'].get('operator_unix') and self.operator.path is None:raise ValueError('faucet private RPC transport cannot be downgraded')
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self._finalized_blocks = _FinalizedBlockCache()
        result = self.forward(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getGenesisHash"}).encode())
        if json.loads(result).get("result") != self.info["network"]["genesis_hash"]:
            raise ValueError("upstream genesis mismatch")

        self.history = None
        if history_root is not None:
            from gateway_history import History
            self.history = History(history_root, self.info['network'])
        self.archive = None
        self.archive_capture = None
        if archive_rpc is not None:
            from gateway_archival import ArchiveRPC
            self.archive = ArchiveRPC(self, archive_rpc, ledger)
        elif archive_store is not None:
            from canonical_archive_rolling import RollingArchive
            if archive_capture_policy is not None:
                from canonical_archive_runner import RollingCapture
                self.archive_capture = RollingCapture(self, archive_store, policy=archive_capture_policy)
            self.archive = RollingArchive(self, archive_store,
                coverage=self.archive_capture.ensure_coverage if self.archive_capture is not None else None)

        if relay_root is not None:
            from shielded_relay import Relay
            self.relay = Relay(relay_root)
            if self.relay.config['network'] != self.info['network']:
                self.relay.close()
                raise ValueError('relay gateway network mismatch')
            if self.relay.native_ingress is not None:
                try:
                    from shielded_relay import private
                    public = json.loads(private(Path(self.relay.config['native_profile']), 8192))
                    if not isinstance(public, dict):
                        raise ValueError('native public profile must be an object')
                    if (public.get('format') != 'native-wallet-profile-v1' or
                            public.get('key_mode') != 'user-wallet-v1' or
                            profile.get('pool_format') != 'NPOOL004' or
                            public.get('pool_format') != 'NPOOL004' or
                            any(public.get(k) != profile.get(k) for k in ('program', 'pool')) or
                            public.get('private_send_transport') != 'native-inline-v1' or
                            public.get('invite_required') is not True or
                            public.get('rpc', {}).get('transport') != 'https' or
                            public.get('rpc', {}).get('url') != self.info['rpc_audience'] or
                            {k:public.get(k) for k in ('network', 'genesis_hash')} != self.info['network'] or
                            self.relay.config['rpc'] != self.upstream):
                        raise ValueError('native relay requires the explicit invited V4 public profile and its pinned private RPC')
                except (ValueError, OSError, KeyError, TypeError):
                    self.relay.close()
                    raise

    def shielded(self, request, proof):
        from shielded_relay import RelayCapacityError
        if self.relay is None: raise ValueError('shielded relay is unavailable')
        try:
            value = self.relay.dispatch(request['method'], request.get('params'), proof['fee_address'])
        except RelayCapacityError as error:
            return json.dumps(dict(jsonrpc='2.0', id=request['id'], error=dict(
                code=RELAY_CAPACITY_CODE, message=RELAY_CAPACITY_MESSAGE,
                data=dict(scope=error.scope)))).encode()
        return json.dumps(dict(jsonrpc='2.0', id=request['id'], result=value)).encode()

    def canonical_history(self, request):
        if self.archive is None:
            return json.dumps({'jsonrpc':'2.0','id':request['id'],'result':None}).encode()
        return self.archive.page(request)

    def diagnostic_failure(self, stage, error):
        pass  # The optional operator-only diagnostics view supplies this hook.

    def sync_snapshot(self, request, deadline):
        from wallet_sync_snapshot import page
        response_budget = [0]
        read_failed = threading.Event()
        def reads(calls, shared_deadline, *, history=False):
            prefix = 'snapshot_history_' if history else 'snapshot_metadata_'
            def failure(stage, error):
                read_failed.set()
                _observe_failure(self.diagnostic_failure, prefix + stage, error)
            try:
                return self._upstream_reads(calls, shared_deadline, history=history,
                    snapshot_pool=None if history else self.pool, single_requests=True,
                    response_budget=response_budget, parallel_snapshot=True,
                    diagnostic_failure=failure)
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                if not read_failed.is_set():
                    failure('request', error)
                raise
        try:
            return page(request, self.info['network'], self.pool, reads, deadline, HistoryTooLarge)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            if not read_failed.is_set():
                _observe_failure(self.diagnostic_failure, 'snapshot_shape', error)
            raise

    def retained_history(self, request):
        if self.history is None:
            return json.dumps({'jsonrpc':'2.0','id':request['id'],'result':None}).encode()
        return self.history.page(request)

    def retained_history_v2(self, request, deadline):
        if self.history is None:
            return json.dumps({'jsonrpc':'2.0','id':request['id'],'result':None}).encode(), 0
        request, maximum = retained_window(request)
        return self.history.page_counted(request, max_blocks=maximum, deadline=deadline)

    def retained_history_v3(self, request, deadline):
        if self.history is None:
            return json.dumps({'jsonrpc':'2.0','id':request['id'],'result':None}).encode(), 0
        request, maximum = retained_window(request)
        return self.history.page_compact_counted(request, max_blocks=maximum, deadline=deadline)

    def forward(self, raw, timeout=15):
        deadline = time.monotonic() + timeout
        if not _UPSTREAM_SLOTS.acquire(timeout=max(0, deadline - time.monotonic())):
            raise ValueError('upstream RPC capacity deadline exceeded')
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('upstream RPC capacity deadline exceeded')
            if self.operator is not None:
                return self.operator.forward(raw, timeout=remaining)
            request = urllib.request.Request(self.upstream, raw, {"Content-Type": "application/json"})
            with self.opener.open(request, timeout=remaining) as response:
                body = response.read(16 * 1024 * 1024 + 1)
                if len(body) > 16 * 1024 * 1024:
                    raise _UpstreamResponseTooLarge("RPC response exceeds gateway limit")
                return body
        finally:
            _UPSTREAM_SLOTS.release()

    def _upstream_reads(self, calls, deadline, *, history=False, snapshot_pool=None,
                        single_requests=False, response_budget=None, parallel_snapshot=False,
                        diagnostic_failure=None):
        # Constructed only from validated read aggregators. Never accept
        # caller-supplied JSON-RPC batches or aggregate any write/status method.
        maximum = HISTORY_PAGE if history else 16
        methods = {'getBlock'} if history else READ_METHODS
        if type(single_requests) is not bool:
            raise ValueError('explicit single request policy required')
        if type(parallel_snapshot) is not bool or parallel_snapshot and not single_requests:
            raise ValueError('explicit single-request snapshot concurrency required')
        if single_requests and (not isinstance(response_budget, list) or len(response_budget) != 1 or
                type(response_budget[0]) is not int or not 0 <= response_budget[0] <= RESPONSE_LIMIT):
            raise ValueError('bounded read response budget required')
        if single_requests and not history and snapshot_pool is None:
            read_calls({'params': [calls]})
        if snapshot_pool is not None:
            if history:
                raise ValueError('fixed sync metadata cannot be a history batch')
            from wallet_sync_snapshot import metadata_calls
            metadata_calls(calls, snapshot_pool)
        if (type(history) is not bool or not 1 <= len(calls) <= maximum or
                (snapshot_pool is None and any(call['method'] not in methods for call in calls))):
            raise ValueError('only bounded upstream reads may be aggregated')
        received = 0
        budget_lock, stopped = threading.Lock(), threading.Event()
        def send(part, phase=None):
            nonlocal received
            queries = [dict(jsonrpc='2.0', id=index, **call) for index, call in enumerate(part)]
            # The sealed058 GrantRpcGate accepts only original RPC objects.
            # Aggregators preserve their public JSON/quotas while using the
            # existing single-object transport inside the private capsule.
            encoded = json.dumps(queries[0] if single_requests else queries,
                                 separators=(',', ':')).encode()
            if history and len(encoded) > HISTORY_REQUEST_LIMIT and len(part) > 1:
                middle = len(part) // 2
                return send(part[:middle]) + send(part[middle:])
            if len(encoded) > UPSTREAM_REQUEST_LIMIT:
                raise ValueError('upstream read request exceeds limit')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('wallet history/read deadline exceeded')
            if parallel_snapshot and stopped.is_set():
                raise _SnapshotReadCancelled('snapshot read cancelled before upstream I/O')
            if phase is not None:
                phase[0] = 'upstream'
            cache = getattr(self, '_finalized_blocks', None) if single_requests else None
            cache_key = cache.key(part[0]) if cache is not None else None
            cached = cache.get(cache_key) if cache is not None else None
            try:
                raw = cached if cached is not None else self.forward(encoded, timeout=remaining)
            except (_UpstreamResponseTooLarge, urllib.error.HTTPError) as error:
                if isinstance(error, urllib.error.HTTPError):
                    error.close()
                if time.monotonic() >= deadline:
                    raise ValueError('wallet history/read deadline exceeded') from error
                if history and (isinstance(error, _UpstreamResponseTooLarge) or error.code == 413):
                    raise HistoryTooLarge(HISTORY_SIZE_MESSAGE) from error
                raise
            if phase is not None:
                phase[0] = 'response'
            if time.monotonic() >= deadline:
                raise ValueError('wallet history/read deadline exceeded')
            if not isinstance(raw, bytes):
                raise ValueError('invalid upstream response bytes')
            response_raw = raw
            if single_requests:
                with budget_lock:
                    response_budget[0] += len(raw)
                    if response_budget[0] > RESPONSE_LIMIT:
                        if history:
                            raise HistoryTooLarge(HISTORY_SIZE_MESSAGE)
                        raise _UpstreamResponseTooLarge('read response exceeds gateway limit')
                # Preserve the exact received object and the existing strict
                # ID/error/duplicate-field parser, without decoding/reencoding.
                raw = b'[' + raw + b']'
            elif history:
                received += len(raw)
                if received > RESPONSE_LIMIT:
                    raise HistoryTooLarge(HISTORY_SIZE_MESSAGE)
            if snapshot_pool is not None:
                from wallet_sync_snapshot import metadata_results
                results = metadata_results(raw, part)
            else:
                results = batch_results(raw, len(part), max_count=maximum)
            if time.monotonic() >= deadline:
                raise ValueError('wallet history/read deadline exceeded')
            if cache is not None and cached is None:
                cache.put(cache_key, response_raw, results[0])
            return results
        if not parallel_snapshot:
            return [send([call])[0] for call in calls] if single_requests else send(calls)

        def single(call):
            # The observer receives only a fixed leaf label and the exception;
            # it cannot see the call, response, access proof or payment content.
            phase = ['request']
            try:
                return send([call], phase)[0]
            except BaseException as error:
                stopped.set()
                if not isinstance(error, _SnapshotReadCancelled):
                    _observe_failure(diagnostic_failure, phase[0], error)
                raise

        results = []
        for start in range(0, len(calls), SNAPSHOT_WORKERS):
            if time.monotonic() >= deadline:
                raise ValueError('wallet history/read deadline exceeded')
            # Keep replies in input order, not completion order. Do not queue
            # the entire256-block tail or create another request's worker pool.
            futures = [_SNAPSHOT_READS.submit(single, call)
                       for call in calls[start:start + SNAPSHOT_WORKERS]]
            try:
                _, pending = concurrent.futures.wait(futures,
                    timeout=max(0, deadline - time.monotonic()),
                    return_when=concurrent.futures.FIRST_EXCEPTION)
                if pending:
                    stopped.set()
                    for future in pending:
                        future.cancel()
                    # Running reads retain the original deadline. Inspect their
                    # errors too: a size-only fallback must not mask a separate
                    # authorization or transport failure in the same wave.
                    running = [future for future in pending if not future.cancelled()]
                    if running:
                        concurrent.futures.wait(running, timeout=max(0, deadline - time.monotonic()))
                if time.monotonic() >= deadline or any(not future.done() for future in futures):
                    raise ValueError('wallet history/read deadline exceeded')
                errors = [future.exception() for future in futures if not future.cancelled()]
                errors = [error for error in errors if error is not None and not isinstance(error, _SnapshotReadCancelled)]
                if errors:
                    raise next((error for error in errors if not isinstance(error, HistoryTooLarge)), errors[0])
                if any(future.cancelled() or isinstance(future.exception(), _SnapshotReadCancelled) for future in futures):
                    raise ValueError('snapshot reads cancelled without complete results')
                results.extend(future.result() for future in futures)
            except BaseException:
                stopped.set()
                for future in futures:
                    future.cancel()
                raise
        return results

    def history_blocks(self, request, slots):
        # One bounded read-only aggregate; return every full finalized block.
        # Clients still authenticate continuity and replay every payment proof.
        slots = history_slots({'params': [slots]})
        calls = [dict(method='getBlock', params=[slot, {
            'encoding': 'base64', 'transactionDetails': 'full', 'rewards': False,
            'commitment': 'finalized', 'maxSupportedTransactionVersion': 0}]) for slot in slots]
        deadline = time.monotonic() + 15
        blocks = self._upstream_reads(calls, deadline, history=True,
                                     single_requests=True, response_budget=[0])
        prefix = json.dumps({'jsonrpc': '2.0', 'id': request['id']}).encode()[:-1] + b',"result":['
        items, total = [], len(prefix) + 2
        for slot, block in zip(slots, blocks):
            if not isinstance(block, dict):
                raise ValueError('complete finalized history is unavailable')
            item = json.dumps({'slot': slot, 'block': block}, separators=(',', ':')).encode()
            if time.monotonic() >= deadline:
                raise ValueError('wallet history/read deadline exceeded')
            total += len(item) + (1 if items else 0)
            if total > RESPONSE_LIMIT:
                raise HistoryTooLarge(HISTORY_SIZE_MESSAGE)
            items.append(item)
        if time.monotonic() >= deadline:
            raise ValueError('wallet history/read deadline exceeded')
        body = prefix + b','.join(items) + b']}'
        if time.monotonic() >= deadline:
            raise ValueError('wallet history/read deadline exceeded')
        return body

    def read_batch(self, request, calls):
        calls = read_calls({'params': [calls]})
        deadline = time.monotonic() + 15
        values = self._upstream_reads(calls, deadline, single_requests=True, response_budget=[0])
        results, total = [], 0
        for call, value in zip(calls, values):
            # Preserve each exact request/message/configuration binding.
            item = dict(request=call, result=value)
            total += len(json.dumps(item).encode())
            if total > 1024 * 1024:
                raise ValueError('wallet read result exceeds limit')
            results.append(item)
        if time.monotonic() >= deadline:
            raise ValueError('wallet history/read deadline exceeded')
        body = json.dumps(dict(jsonrpc='2.0', id=request['id'], result=results)).encode()
        if len(body) > 1024 * 1024:
            raise ValueError('wallet read result exceeds limit')
        if time.monotonic() >= deadline:
            raise ValueError('wallet history/read deadline exceeded')
        return body


def history_slots(request):
    params = request.get("params")
    if not isinstance(params, list) or len(params) != 1 or not isinstance(params[0], list):
        raise ValueError("invalid history request")
    slots = params[0]
    if not 1 <= len(slots) <= HISTORY_PAGE or any(type(slot) is not int or not 1 <= slot <= 2**64 - 1 for slot in slots) or any(a >= b for a, b in zip(slots, slots[1:])):
        raise ValueError("invalid history block range")
    return slots


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    disable_nagle_algorithm = True
    max_connection_requests = 64
    max_connection_seconds = 30

    def setup(self):
        super().setup()
        self.connection_started = time.monotonic()
        self.connection_requests = 0

    def handle_one_request(self):
        self.connection_requests += 1
        self.connection.settimeout(5)
        super().handle_one_request()

    def end_headers(self):
        if (self.connection_requests >= self.max_connection_requests or
                time.monotonic() - self.connection_started >= self.max_connection_seconds):
            self.close_connection = True
        if self.close_connection:
            self.send_header('Connection', 'close')
        super().end_headers()

    def log_message(self, *_):
        pass  # No access proofs, requests, addresses or invitation codes in logs.

    def diagnostic_refusal(self, stage, error, status):
        pass  # Optional fixed-label diagnostics; never part of authorization.

    def retained_v2(self, request, proof, deadline):
        # The initial authorization is already durable. Only charge work that
        # this bounded page actually returns, before exposing any public bytes.
        if request['method'] == 'getWalletRetainedHistoryV3':
            data, count = self.server.app.retained_history_v3(request, deadline)
        else:
            data, count = self.server.app.retained_history_v2(request, deadline)
        _, maximum = retained_window(request)
        if type(count) is not int or not 0 <= count <= maximum:
            raise ValueError('invalid retained header count')
        if time.monotonic() >= deadline:
            raise ValueError('retained history deadline exceeded')
        headers_per_unit = getattr(self.server.app, 'compact_headers_per_unit', HISTORY_AUTH_BLOCKS)
        if (type(headers_per_unit) is not int or
                headers_per_unit not in (HISTORY_AUTH_BLOCKS, COMPACT_AUTH_HEADERS) or
                (headers_per_unit != HISTORY_AUTH_BLOCKS and getattr(self.server.app, 'authorize_many', False) is not True)):
            raise ValueError('explicit supported compact authorization policy required')
        units = max(1, (count + headers_per_unit - 1) // headers_per_unit)
        if headers_per_unit == COMPACT_AUTH_HEADERS:
            # Resource pricing is explicit and uses uncompressed encoded bytes,
            # so dense proof pages cannot become cheap through gzip or low counts.
            if not isinstance(data, bytes):
                raise ValueError('invalid history response bytes')
            if len(data) > RESPONSE_LIMIT:
                raise HistoryTooLarge(HISTORY_SIZE_MESSAGE)
            units = max(units, (len(data) + COMPACT_AUTH_BYTES - 1) // COMPACT_AUTH_BYTES)
        additional = units - 1
        if additional:
            accepted = self.server.app.faucet.command('authorize-many', proof,
                extra=['--units', str(additional)])
            if (not isinstance(accepted, dict) or accepted.get('authorized') is not True or
                    type(accepted.get('units')) is not int or accepted['units'] != additional):
                raise ValueError('retained authorization acknowledgment mismatch')
        if time.monotonic() >= deadline:
            raise ValueError('retained history deadline exceeded')
        return history_encoding(data,
            accepts_history_gzip(self.headers.get_all('Accept-Encoding', [])), deadline)

    def _read_rpc_request(self):
        """Validate ingress and read one bounded RPC envelope."""
        if (self.path != "/" or self.headers.get("Host") != self.server.authority
                or self.headers.get("Origin") is not None):
            raise ValueError("access denied")
        if any(len(self.headers.get_all(name, [])) > 1 for name in ('Host', 'Content-Length', 'Content-Type', 'X-Testnet-Access')):
            raise ValueError('ambiguous persistent framing')
        self._request_stage = 'ingress'
        self.server.app.faucet.ingress("rpc", self.client_address[0])
        self._request_stage = 'body'
        if self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding") is not None:
            raise ValueError("invalid RPC body")
        length = self.headers.get('Content-Length', '')
        if re.fullmatch('[0-9]{1,5}', length) is None:
            raise ValueError('invalid RPC length')
        size = int(length)
        if not 1 <= size <= 32768:
            raise ValueError("RPC body exceeds limit")
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise ValueError('incomplete RPC body')
        self._request_stage = 'envelope'
        request = json.loads(raw)
        if (not isinstance(request, dict)
                or set(request) - {"jsonrpc", "id", "method", "params"}
                or request.get("jsonrpc") != "2.0"
                or not isinstance(request.get("method"), str)
                or request["method"] not in METHODS
                or type(request.get("id")) not in (str, int)
                or len(str(request["id"])) > 64
                or (request.get("params") is not None and not isinstance(request["params"], list))):
            raise ValueError("RPC method or envelope denied")
        return raw, request

    def _authorize_rpc_request(self, request):
        """Charge the original request before any upstream work."""
        if request["method"] == "getGenesisHash":
            return None, None, None, None
        self._request_stage = 'parameters'
        calls = read_calls(request) if request['method'] == 'getWalletReadBatch' else None
        if request['method'] in ('getWalletRetainedHistoryV2', 'getWalletRetainedHistoryV3'):
            retained_window(request)
        if request['method'] == 'getWalletRetainedHistory':
            from gateway_history import parameters
            parameters(request)
        if request['method'] == 'getWalletCanonicalHistory':
            from gateway_archival import parameters
            parameters(request)
        if request['method'] == 'getWalletSyncSnapshot':
            from wallet_sync_snapshot import parameters
            parameters(request)
        slots = history_slots(request) if request["method"] == "getWalletHistoryBlocks" else None
        self._request_stage = 'proof'
        header = self.headers.get("X-Testnet-Access", "")
        if not 1 <= len(header) <= 3072:
            raise ValueError("invitation required")
        proof = json.loads(base64.b64decode(header + "=" * (-len(header) % 4), altchars=b"-_", validate=True))
        # Each group of up to 16 history slots or individual bounded read costs
        # one durable unit. A reviewed bulk-capable faucet may debit all units
        # in one fresh authorization. Admission is checked for every request.
        self._request_stage = 'authorization'
        authorization_deadline = time.monotonic() + 15
        if slots is not None:
            charges = (len(slots) + HISTORY_AUTH_BLOCKS - 1) // HISTORY_AUTH_BLOCKS
        elif calls is not None:
            charges = len(calls)
        else:
            charges = 1
        if request['method'] == 'getWalletSyncSnapshot':
            # All 21 durable units are paid before metadata/history upstream IO.
            from wallet_sync_snapshot import PREPAID_UNITS
            charges = PREPAID_UNITS
        if charges > 1 and getattr(self.server.app, 'authorize_many', False) is True:
            if time.monotonic() >= authorization_deadline:
                raise ValueError('wallet authorization deadline exceeded')
            accepted = self.server.app.faucet.command('authorize-many', proof,
                extra=['--units', str(charges)])
            if (not isinstance(accepted, dict) or accepted.get('authorized') is not True or
                    type(accepted.get('units')) is not int or accepted['units'] != charges):
                raise ValueError('authorization acknowledgment mismatch')
            if time.monotonic() >= authorization_deadline:
                raise ValueError('wallet authorization deadline exceeded')
        else:
            for _ in range(charges):
                if time.monotonic() >= authorization_deadline:
                    raise ValueError('wallet authorization deadline exceeded')
                self.server.app.faucet.command("authorize", proof)
        return proof, calls, slots, authorization_deadline

    def _dispatch_rpc_request(self, raw, request, proof, calls, slots, authorization_deadline):
        """Route an authorized request with its original deadline and encoding."""
        history_success, encoding = False, None
        if request['method'] in {'getShieldedFeeQuote', 'submitShieldedPayment', 'getShieldedPaymentStatus'}:
            self._request_stage = 'shielded'
            data = self.server.app.shielded(request, proof)
        elif request['method'] == 'getWalletReadBatch':
            self._request_stage = 'read_batch'
            data = self.server.app.read_batch(request, calls)
        elif request['method'] == 'getWalletRetainedHistory':
            self._request_stage = 'retained'
            data = self.server.app.retained_history(request)
        elif request['method'] in ('getWalletRetainedHistoryV2', 'getWalletRetainedHistoryV3'):
            self._request_stage = 'retained'
            data, encoding = self.retained_v2(request, proof, authorization_deadline)
            history_success = True
        elif request['method'] == 'getWalletCanonicalHistory':
            self._request_stage = 'canonical'
            data = self.server.app.canonical_history(request)
        elif request['method'] == 'getWalletSyncSnapshot':
            self._request_stage = 'snapshot'
            data = self.server.app.sync_snapshot(request, authorization_deadline)
            self._request_stage = 'snapshot_encoding'
            data, encoding = history_encoding(data,
                accepts_history_gzip(self.headers.get_all('Accept-Encoding', [])), authorization_deadline)
            history_success = True
        elif request['method'] == 'getWalletHistoryBlocks':
            self._request_stage = 'history'
            deadline = time.monotonic() + 15
            data = self.server.app.history_blocks(request, slots)
            data, encoding = history_encoding(data, accepts_history_gzip(self.headers.get_all('Accept-Encoding', [])), deadline)
            history_success = True
        else:
            self._request_stage = 'forward'
            data = self.server.app.forward(raw)
        return data, history_success, encoding

    def _write_rpc_response(self, code, data, history_success, encoding):
        """Emit the existing response headers and bounded result bytes."""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if history_success:
            self.send_header('Vary', 'Accept-Encoding')
            if encoding is not None:
                self.send_header('Content-Encoding', encoding)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if code == 429:
            # The native HTTP sender honors this bounded delay. Retrying a
            # read does not reset durable quotas or spin against the gateway.
            self.send_header("Retry-After", str(61 - int(time.time()) % 60))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        code, data = 200, b""
        history_authorized = False
        history_success, encoding = False, None
        self._request_stage = 'framing'
        try:
            raw, request = self._read_rpc_request()
            proof, calls, slots, authorization_deadline = self._authorize_rpc_request(request)
            history_authorized = slots is not None or request['method'] == 'getWalletSyncSnapshot'
            data, history_success, encoding = self._dispatch_rpc_request(
                raw, request, proof, calls, slots, authorization_deadline)
        except (ValueError, RecursionError, OSError, urllib.error.URLError, subprocess.SubprocessError) as error:
            self.close_connection = True  # An unread/rejected body cannot become another request.
            if isinstance(error, HistoryTooLarge) and history_authorized:
                data = json.dumps(dict(jsonrpc='2.0', id=request['id'], error=dict(code=HISTORY_SIZE_CODE, message=HISTORY_SIZE_MESSAGE))).encode()
            else:
                code = 429 if "quota exhausted" in str(error) else 403
                data = json.dumps({"error": "request_limit" if code == 429 else "access_denied"}).encode()
                _observe_failure(lambda label, failure: self.diagnostic_refusal(label, failure, code), self._request_stage, error)
        self._write_rpc_response(code, data, history_success, encoding)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18898)
    parser.add_argument("--history",type=Path,help="operator-configured retained mirror; never supplied by a client")
    canonical = parser.add_mutually_exclusive_group()
    canonical.add_argument("--archive-rpc",help="fixed operator-only canonical archive RPC; never supplied by a client")
    canonical.add_argument("--archive-store",type=Path,help="fixed owner-only rolling canonical store; never supplied by a client")
    parser.add_argument("--archive-capture",action="store_true",help="explicitly run bounded capture into --archive-store using existing shared RPC capacity")
    parser.add_argument("--archive-capture-max-bytes",type=int,default=8*1024**3,help="private archive byte cap; capture always retains at least 28GiB free")
    parser.add_argument("--tls-cert",type=Path)
    parser.add_argument("--tls-key",type=Path)
    parser.add_argument("--listener-config",type=Path,help="reviewed direct HTTPS binding; default remains loopback-only")
    parser.add_argument("--listener-sha256",help="independently reviewed exact configuration file digest")
    parser.add_argument("--shielded-relay", type=Path, help="fixed owner-only relay configuration; opt-in")
    parser.add_argument("--authorize-many", action="store_true", help="reviewed faucet supports exact authorize-many debits; opt-in")
    parser.add_argument("--compact-headers-per-unit", type=int, choices=(HISTORY_AUTH_BLOCKS, COMPACT_AUTH_HEADERS),
                        default=HISTORY_AUTH_BLOCKS, help="explicit compact resource pricing; 256 requires --authorize-many")
    args = parser.parse_args()
    if args.archive_capture and args.archive_store is None:
        parser.error('--archive-capture requires --archive-store')
    # Reuse the bounded, owner-only operator service interface; no worker starts here.
    faucet = Faucet(args.root, args.password_file)
    app = server = None
    try:
        policy = None
        if args.archive_capture:
            policy = dict(network=faucet.command('access-info')['network'],
                max_database_bytes=args.archive_capture_max_bytes,min_free_bytes=28*1024**3,
                batch_blocks=16,max_batches=64,timeout=30,batch_timeout=6,poll_seconds=1)
        app = Gateway(faucet,history_root=args.history,archive_rpc=args.archive_rpc,relay_root=args.shielded_relay,
                      authorize_many=args.authorize_many,compact_headers_per_unit=args.compact_headers_per_unit,
                      archive_store=args.archive_store,archive_capture_policy=policy)
        from service_tls import listener
        server=listener(app.info['rpc_audience'],args.port,Handler,app,args.tls_cert,args.tls_key,args.listener_config,args.listener_sha256)
        if app.relay is not None: app.relay.start()
        if app.archive_capture is not None: app.archive_capture.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if app is not None and app.archive_capture is not None: app.archive_capture.close()
        finally:
            try:
                if server is not None: server.server_close()
            finally:
                try:
                    if app is not None and app.relay is not None: app.relay.close()
                finally:
                    faucet.close()


if __name__ == "__main__":
    main()
