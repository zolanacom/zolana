#!/usr/bin/env python3
"""Retained-history collector for wallet first sync, run beside the sealed runtime.

It keeps a mirror of public finalized history (block headers plus the successful signed
payment transactions) that the gateway can serve to a new wallet in a few compact pages.
It holds no wallet, password, signer or admission state and sends nothing to the chain.

The work is the installed collector's: `native-wallet archive` replays the whole retained
store and the new finalized blocks, checks every payment's signatures and proof, reconciles
the result with the finalized pool and only then publishes its manifest. This program runs
that binary on a schedule, copies each verified manifest to the mirror with the installed
history_retention.capture(), and records what happened. It never deletes or rewrites a
retained segment. A collection that fails leaves the last published mirror in place.

The binary never talks to the node directly. It is given a loopback forwarder inside this
program, which
  - passes on a fixed list of read-only methods and answers anything else itself;
  - lets exactly one request be in flight at a time;
  - while catching up, rests after every request so that the node spends at most the
    configured share of one request lane on this collector, watches the chain's own rate of
    finalized blocks, halves that share whenever the rate falls below four fifths of what it
    was just before the collection started, and gives the collection up if the rate stays
    below half at the smallest share;
  - counts the blocks read, so that progress can be reported.

After a configured number of consecutive collections in which the node answered but the
retained store could not be verified against it, the mirror's manifest is set aside
(renamed, kept) so that the gateway answers "no mirror" and wallets read canonical blocks
as before; the next verified collection publishes it again.

Commands:
  check        validate the configuration and every pinned file; start nothing
  once         one collection, then exit (status 0 only if verified and published);
               with --verify also read the whole mirror back through the gateway's own
               reader and compare its last block with the node
  run          collect at the configured interval; exits with status 75 when the chain is
               not running, so that the service manager decides whether to start it again
  verify       read the whole published mirror back through the gateway's own reader
  adopt        copy an earlier retained store (--from, a directory holding manifest.json and
               its segments) into the empty store with the installed capture(), which checks
               every checksum, the continuity of every block and every bound. Nothing is
               published by this: the next collection replays every adopted block, checks
               every payment's signatures and proof and reconciles with the finalized pool
               before it publishes, exactly as for blocks it read itself
  serve-check  ask the gateway's installed retained-history class (from --wiring, or the
               plain reader without it) for the first and the last page of the mirror
"""
import argparse
import collections
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import types
import urllib.parse

FORMAT = 'zolana-first-sync-mirror-config-v2'
PATHS = ('root', 'collector', 'retention_module', 'codec_module', 'history_module', 'profile', 'ready')
PINS = ('collector_sha256', 'retention_module_sha256', 'codec_module_sha256', 'history_module_sha256', 'profile_sha256')
BOUNDS = {'interval_seconds': (30, 3600), 'collection_timeout_seconds': (60, 14400),
          'minimum_free_bytes': (2 * 1024 ** 3, 1 << 50), 'store_budget_bytes': (32 * 1024 * 1024, 64 * 1024 ** 3),
          'withdraw_after_failures': (2, 100), 'collector_threads': (1, 8), 'pace_percent': (2, 100),
          'paced_above_slots': (256, 10 ** 9), 'sample_seconds': (1, 60)}
KEYS = {'format', *PATHS, *PINS, *BOUNDS}
HEX = re.compile('[a-f0-9]{64}')
ENDPOINT = re.compile(r'127\.0\.0\.1:[1-9][0-9]{0,4}')
MAX_SEGMENT = 32 * 1024 * 1024
HEADER = {'transactionDetails': 'none', 'rewards': False, 'commitment': 'finalized'}
FINALIZED = [{'commitment': 'finalized'}]
# Everything the collector binary may ask the node. All are reads.
READ_METHODS = frozenset(('getGenesisHash', 'getAccountInfo', 'getMultipleAccounts', 'getBlocks', 'getBlocksWithLimit',
                          'getBlock', 'getSlot', 'getBlockHeight', 'getFirstAvailableBlock', 'getVersion', 'getHealth',
                          'getEpochInfo'))
SMALLEST_PACE = 2
EXIT_CHAIN_DOWN = 75


class Blocked(Exception):
    """A collection that could not be completed.

    `refuted` is True when the node answered and the retained store could not be verified
    against it or extended from it; only such failures count toward setting the mirror aside.
    An unreachable node, a stopped chain, a full budget, a slow chain or a timeout leave a
    mirror that is behind, not wrong.
    """

    def __init__(self, code, refuted=True):
        super().__init__(code)
        self.code, self.refuted = code, refuted


def reader(owner):
    """Pinned-file reader: a file only `owner` (root when installed) can write, by its hash."""
    def sealed(path, maximum, expected=None):
        path = Path(path)
        if not path.is_absolute() or path.resolve() != path:
            raise ValueError('absolute real path required: ' + path.name)
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022
                    or not 0 < info.st_size <= maximum):
                raise ValueError('owner-sealed bounded file required: ' + path.name)
            raw = source.read(maximum + 1)
        if len(raw) > maximum or (expected is not None and hashlib.sha256(raw).hexdigest() != expected):
            raise ValueError('pinned file differs: ' + path.name)
        return raw
    return sealed


def load_config(path, expected, trusted):
    value = json.loads(trusted(path, 16384, expected))
    if (not isinstance(value, dict) or set(value) != KEYS or value['format'] != FORMAT
            or any(not isinstance(value[key], str) or not Path(value[key]).is_absolute() for key in PATHS)
            or any(not isinstance(value[key], str) or HEX.fullmatch(value[key]) is None for key in PINS)
            or any(type(value[key]) is not int or not low <= value[key] <= high for key, (low, high) in BOUNDS.items())):
        raise ValueError('invalid first-sync mirror configuration')
    return value


def load_modules(config, trusted):
    """The installed retention, codec and reader modules, each by its pinned hash, used unchanged."""
    loaded = {}
    for name, key in (('history_retention', 'retention_module'), ('gateway_history_codec', 'codec_module'),
                      ('gateway_history', 'history_module')):
        raw = trusted(config[key], 1024 * 1024, config[key + '_sha256'])
        module = types.ModuleType(name)
        module.__file__ = config[key]
        sys.modules[name] = module
        exec(compile(raw, config[key], 'exec'), module.__dict__)
        loaded[name] = module
    return loaded


def node_endpoint(ready_path, network):
    """The first peer's loopback RPC of the running generation, from the runtime's ready record."""
    try:
        with open(ready_path, 'rb') as source:
            raw = source.read(65537)
    except OSError:
        raise Blocked('chain_not_running', refuted=False) from None
    try:
        ready = json.loads(raw)
        peer = ready['peers'][0]['rpc']
        if ready.get('network') != network or ready.get('pool_format') != 'NPOOL004' or ENDPOINT.fullmatch(peer) is None:
            raise ValueError
        return peer, ready.get('generation')
    except (ValueError, KeyError, IndexError, TypeError):
        raise Blocked('ready_record_differs', refuted=False) from None


def node_read(peer, method, slot=None):
    """The four fixed finalized reads this program sends by itself."""
    params = {'getSlot': FINALIZED, 'getBlockHeight': FINALIZED, 'getFirstAvailableBlock': [],
              'getBlock': [slot, HEADER]}[method]
    host, port = peer.split(':')
    connection = http.client.HTTPConnection(host, int(port), timeout=5)
    try:
        connection.request('POST', '/', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
                           {'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read(16385)
        value = json.loads(raw)
        result = value['result']
        if response.status != 200 or len(raw) > 16384:
            raise ValueError
        if method == 'getBlock':
            if not isinstance(result, dict) or not isinstance(result.get('blockhash'), str) or type(result.get('blockHeight')) is not int:
                raise ValueError
        elif type(result) is not int or not 0 <= result <= 2 ** 64 - 1:
            raise ValueError
        return result
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        raise Blocked('node_unavailable', refuted=False) from None
    finally:
        connection.close()


class Forwarder(ThreadingHTTPServer):
    """Loopback forwarder between the collector binary and the node: read-only, one at a time, paced."""
    daemon_threads = True

    def __init__(self, peer, pace_percent):
        super().__init__(('127.0.0.1', 0), ForwardHandler)
        host, port = peer.split(':')
        self.peer = (host, int(port))
        self.gate = threading.Lock()
        self.connection = None
        self.pace_percent, self.paced = pace_percent, False
        self.blocks = self.requests = self.failures = 0
        self.busy = 0.0
        self.refused = {}

    def upstream(self, raw):
        for attempt in (0, 1):
            try:
                if self.connection is None:
                    self.connection = http.client.HTTPConnection(*self.peer, timeout=14)
                self.connection.request('POST', '/', raw, {'Content-Type': 'application/json'})
                response = self.connection.getresponse()
                body = response.read(16 * 1024 * 1024 + 1)
                if len(body) > 16 * 1024 * 1024:
                    raise ValueError('node response exceeds bound')
                return response.status, body
            except (OSError, http.client.HTTPException):
                # A kept-alive connection the node closed: every forwarded method is a read.
                if self.connection is not None:
                    self.connection.close()
                self.connection = None
                if attempt:
                    raise


class ForwardHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    disable_nagle_algorithm = True

    def log_message(self, *_):
        pass

    def reply(self, status, body):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        server = self.server
        length = self.headers.get('Content-Length', '')
        if not length.isdigit() or not 0 < int(length) <= 65536:
            self.close_connection = True
            return self.reply(400, b'{}')
        raw = self.rfile.read(int(length))
        try:
            request = json.loads(raw)
            method = request['method'] if isinstance(request, dict) else None
        except (ValueError, KeyError):
            request, method = {}, None
        if method not in READ_METHODS:
            name = method if isinstance(method, str) and re.fullmatch('[A-Za-z]{1,40}', method) else 'other'
            with server.gate:
                server.refused[name] = server.refused.get(name, 0) + 1
            return self.reply(200, json.dumps({'jsonrpc': '2.0', 'id': request.get('id') if isinstance(request, dict) else None,
                                               'error': {'code': -32601, 'message': 'Method not found'}}).encode())
        with server.gate:
            began = time.monotonic()
            try:
                status, body = server.upstream(raw)
            except (OSError, ValueError, http.client.HTTPException):
                server.failures += 1
                self.close_connection = True
                return self.reply(502, b'{}')
            took = time.monotonic() - began
            server.requests += 1
            server.busy += took
            params = request.get('params')
            if (method == 'getBlock' and isinstance(params, list) and len(params) == 2 and isinstance(params[1], dict)
                    and params[1].get('transactionDetails', 'full') == 'full'):
                server.blocks += 1
            self.reply(status, body)
            if server.paced:
                # The reply is already with the binary; the next request waits here.
                time.sleep(min(took * (100.0 / server.pace_percent - 1), 5.0))


class Mirror:
    def __init__(self, config, modules, trusted, announce=None):
        self.config, self.retention, self.modules = config, modules['history_retention'], modules
        self.announce = announce
        profile_raw = trusted(config['profile'], 32768, config['profile_sha256'])
        profile = json.loads(profile_raw)
        if profile.get('pool_format') != 'NPOOL004' or profile.get('fixture_keys_are_public') is not True \
                or profile.get('invite_required', False) or profile.get('key_mode') == 'user-wallet-v1':
            raise ValueError('public operator profile required')
        self.network = {key: profile[key] for key in ('network', 'genesis_hash')}
        trusted(config['collector'], 256 * 1024 * 1024, config['collector_sha256'])
        self.root = self.retention.directory(config['root'])
        self.primary = self.retention.directory(self.root / 'recovery-history', create=True)
        self.mirror = self.retention.directory(self.root / 'recovery-history-mirror', create=True)
        profile_copy = self.root / 'network.json'
        if os.path.lexists(profile_copy):
            if self.retention.read(profile_copy, 32768) != profile_raw:
                raise ValueError('collector profile changed; the retained store belongs to another profile')
        else:
            self.retention.atomic(profile_copy, profile_raw)
        self.status_path = self.root / 'status.json'
        self.stop = threading.Event()
        self.child = None
        self.lock = threading.RLock()   # re-entrant: the stop signal may arrive while a record is being written
        self.failures = 0
        self.forwarder = None
        self.give_up = None
        self.sample_every, self.sampled = 1 << 62, []
        # What is published now stays in every record while a collection is still running.
        try:
            published = self.store(self.mirror)[0]
        except (ValueError, OSError):
            published = 0
        self.status = {'format': 'zolana-first-sync-mirror-status-v2', 'phase': 'starting', 'error': None,
                       'last_success': None, 'retained_tip': published, 'withdrawn': False}

    def record(self, **fields):
        with self.lock:
            self.status.update(fields, recorded_at=int(time.time()))
            self.retention.atomic(self.status_path, json.dumps(self.status, sort_keys=True).encode())
        if self.announce is not None:
            self.announce(dict(self.status))

    def store(self, directory):
        if not (directory / 'manifest.json').exists():
            return 0, 0
        _, files, tip = self.retention.manifest(directory, self.network)
        return tip, sum(descriptor['count'] for _, descriptor in files)

    def guard(self):
        budget = self.config['store_budget_bytes']
        if shutil.disk_usage(self.root).free < self.config['minimum_free_bytes'] + MAX_SEGMENT:
            raise Blocked('free_space_reserve', refuted=False)
        try:
            # Leave room for the largest segment one collection may add.
            if self.retention.usage(self.primary, budget) + MAX_SEGMENT > budget:
                raise ValueError
            self.retention.usage(self.mirror, budget)
        except ValueError:
            raise Blocked('store_budget', refuted=False) from None

    def watch(self, peer, forwarder, baseline, expected, began):
        """Progress, and the chain's own rate of finalized blocks while a catch-up runs."""
        sample, configured = self.config['sample_seconds'], self.config['pace_percent']
        heights = collections.deque(maxlen=4)
        marks = collections.deque(maxlen=4)
        slow = missed = events = 0
        while not self.done.wait(sample):
            now, rate = time.monotonic(), None
            try:
                heights.append((now, node_read(peer, 'getBlockHeight')))
                missed = 0
            except Blocked:
                missed += 1
                if missed >= 6:
                    self.give_up = 'node_unavailable'
            if len(heights) >= 2 and heights[-1][0] > heights[0][0]:
                rate = (heights[-1][1] - heights[0][1]) / (heights[-1][0] - heights[0][0])
            if rate is not None and forwarder.paced and baseline:
                if rate < 0.8 * baseline and forwarder.pace_percent > SMALLEST_PACE:
                    forwarder.pace_percent = max(SMALLEST_PACE, forwarder.pace_percent // 2)
                    events += 1
                    heights.clear()
                elif rate >= 0.9 * baseline and forwarder.pace_percent < configured:
                    forwarder.pace_percent = min(configured, forwarder.pace_percent * 2)
                slow = slow + 1 if rate < 0.5 * baseline and forwarder.pace_percent == SMALLEST_PACE else 0
                if slow * sample >= 60:
                    self.give_up = 'chain_slow'
            marks.append((now, forwarder.blocks))
            recent = ((marks[-1][1] - marks[0][1]) / (marks[-1][0] - marks[0][0])) if len(marks) >= 2 else 0.0
            self.record(phase='collecting', blocks_read=forwarder.blocks, expected_blocks=expected,
                        blocks_per_second=round(recent, 1), elapsed_seconds=int(now - began),
                        pace_percent=forwarder.pace_percent if forwarder.paced else 100,
                        node_busy_seconds=round(forwarder.busy, 1), pace_reductions=events,
                        chain_blocks_per_second=None if rate is None else round(rate, 2),
                        chain_blocks_per_second_before=None if baseline is None else round(baseline, 2))

    def run_collector(self, rpc):
        args = [self.config['collector'], 'archive', '--network', str(self.root / 'network.json'),
                '--rpc', rpc, '--history', str(self.primary)]
        with self.lock:
            if self.stop.is_set():
                raise Blocked('stopped', refuted=False)
            self.child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          text=True, env={'PATH': '/usr/bin:/bin', 'SOLANA_METRICS_CONFIG': '',
                                                          'RAYON_NUM_THREADS': str(self.config['collector_threads'])})
            child = self.child
        end = time.monotonic() + self.config['collection_timeout_seconds']
        try:
            while True:
                try:
                    stdout, stderr = child.communicate(timeout=1)
                    break
                except subprocess.TimeoutExpired:
                    if self.stop.is_set():
                        raise Blocked('stopped', refuted=False) from None
                    if self.give_up is not None:
                        raise Blocked(self.give_up, refuted=False) from None
                    if time.monotonic() > end:
                        raise Blocked('collection_timeout', refuted=False) from None
                    self.guard()
            if child.returncode and self.forwarder is not None and self.forwarder.failures:
                # The node did not answer a read; the store was not shown to be wrong.
                raise Blocked('node_unavailable', refuted=False)
            if child.returncode or len(stdout) > 4096:
                # Bounded diagnostics stay inside the private root.
                self.retention.atomic(self.root / 'collector-error.json', json.dumps({
                    'returncode': child.returncode, 'stderr': stderr[-4096:], 'recorded_at': int(time.time())},
                    sort_keys=True).encode())
                raise Blocked('collection_failed')
            result = json.loads(stdout)
            if not isinstance(result, dict) or result.get('manifest_committed') is not True \
                    or type(result.get('finalized_slot')) is not int:
                raise Blocked('collection_unverified')
            return result
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=10)
            with self.lock:
                self.child = None

    def collect(self):
        began = time.monotonic()
        peer, generation = node_endpoint(self.config['ready'], self.network)
        self.guard()
        current = node_read(peer, 'getSlot')
        first = node_read(peer, 'getFirstAvailableBlock')
        height = node_read(peer, 'getBlockHeight')
        tip, held = self.store(self.primary)
        if first > tip + 1:
            # History before the retained tip is gone from this node: it cannot be extended.
            raise Blocked('history_gap')
        if current < tip:
            raise Blocked('node_behind_retained_history')
        catching_up = current - tip > self.config['paced_above_slots']
        baseline = None
        if catching_up:
            # The chain's own pace just before this collection puts any load on the node.
            self.record(phase='measuring-chain', error=None, first_available_block=first)
            marks = [(time.monotonic(), height)]
            for _ in range(2):
                if self.stop.wait(self.config['sample_seconds']):
                    raise Blocked('stopped', refuted=False)
                marks.append((time.monotonic(), node_read(peer, 'getBlockHeight')))
            baseline = (marks[-1][1] - marks[0][1]) / (marks[-1][0] - marks[0][0])
            if baseline <= 0:
                raise Blocked('chain_not_advancing', refuted=False)
        forwarder = Forwarder(peer, self.config['pace_percent'])
        forwarder.paced = catching_up or self.config['pace_percent'] < 100
        self.forwarder = forwarder
        self.give_up, self.done = None, threading.Event()
        serving = threading.Thread(target=forwarder.serve_forever, kwargs={'poll_interval': 0.2}, daemon=True)
        watching = threading.Thread(target=self.watch, daemon=True,
                                    args=(peer, forwarder, baseline, max(0, height - held), began))
        serving.start()
        self.record(phase='collecting', error=None, first_available_block=first, blocks_read=0,
                    expected_blocks=max(0, height - held))
        watching.start()
        try:
            result = self.run_collector('http://127.0.0.1:%d' % forwarder.server_port)
        finally:
            self.done.set()
            watching.join(timeout=15)
            forwarder.shutdown()
            forwarder.server_close()
            if forwarder.connection is not None:
                forwarder.connection.close()
        if result['finalized_slot'] < current:
            raise Blocked('collection_unverified')
        collected = time.monotonic()
        self.guard()
        self.record(phase='publishing')
        copied = self.retention.capture(self.primary, self.mirror, self.network, self.config['store_budget_bytes'])
        if copied['finalized_slot'] != result['finalized_slot']:
            raise Blocked('publication_differs')
        live = node_read(peer, 'getSlot')
        self.failures = 0
        seconds = collected - began
        self.record(phase='ready', error=None, last_success=int(time.time()), retained_tip=copied['finalized_slot'],
                    live_slot=live, lag_slots=max(0, live - copied['finalized_slot']), generation=generation,
                    segments=copied['segments'], referenced_bytes=copied['referenced_bytes'],
                    new_blocks=result.get('new_blocks'), payments_verified=result.get('payments_verified'),
                    blocks_read=forwarder.blocks, node_requests=forwarder.requests,
                    node_busy_seconds=round(forwarder.busy, 1), refused_methods=forwarder.refused,
                    blocks_per_second=round(forwarder.blocks / seconds, 1) if seconds > 0 else None,
                    collection_seconds=round(seconds, 1), publication_seconds=round(time.monotonic() - collected, 1),
                    first_available_block=first, consecutive_failures=0, withdrawn=False)
        return dict(self.status)

    def withdraw(self):
        """Set the published manifest aside, keeping every file; the gateway then reports no mirror."""
        manifest = self.mirror / 'manifest.json'
        if os.path.lexists(manifest):
            os.rename(manifest, self.mirror / ('withdrawn-manifest-%d.json' % int(time.time())))
            self.retention.sync_directory(self.mirror)
        self.record(withdrawn=True)

    def attempt(self):
        try:
            return self.collect()
        except Blocked as error:
            if error.refuted and not self.stop.is_set():
                self.failures += 1
                if self.failures >= self.config['withdraw_after_failures'] and not self.status['withdrawn']:
                    self.withdraw()
            self.record(phase='stopped' if self.stop.is_set() else 'blocked' if error.refuted else 'waiting',
                        error=error.code, consecutive_failures=self.failures)
            return None
        except (ValueError, OSError, subprocess.SubprocessError):
            # A check inside the installed retention functions refused the store or the copy.
            self.failures += 1
            if self.failures >= self.config['withdraw_after_failures'] and not self.status['withdrawn']:
                self.withdraw()
            self.record(phase='blocked', error='verification_failed', consecutive_failures=self.failures)
            return None

    def pages(self, source, after=0):
        """Read retained pages as a wallet would be given them and decode each one."""
        unpack = self.modules['gateway_history_codec'].unpack_blocks
        token, pages, blocks, payments, last = None, 0, 0, 0, None
        self.sampled = []
        while True:
            raw, count = source.page_compact_counted({'jsonrpc': '2.0', 'id': 1, 'params': [after, 2 ** 64 - 1, token]},
                                                     max_blocks=32768, deadline=time.monotonic() + 60)
            result = json.loads(raw)['result']
            if result is None:
                raise ValueError('the reader reports no mirror')
            decoded = unpack(result['compact_headers'], result['transactions'])
            if len(decoded) != count or not decoded or decoded[0]['parent_slot'] != after:
                raise ValueError('page does not continue the cursor')
            for index in range(-(blocks % self.sample_every) % self.sample_every, len(decoded), self.sample_every):
                self.sampled.append({key: decoded[index][key] for key in ('slot', 'parent_slot', 'blockhash', 'block_height')})
            pages, blocks, last = pages + 1, blocks + len(decoded), decoded[-1]
            payments += sum(len(block['transactions']) for block in decoded)
            after, token = result['next_slot'], result['checkpoint']
            if after != last['slot']:
                raise ValueError('page cursor differs from its last block')
            if result['complete']:
                return {'pages': pages, 'blocks': blocks, 'payment_transactions': payments, 'tip_slot': last['slot'],
                        'tip_blockhash': last['blockhash'], 'tip_block_height': last['block_height'],
                        'retained_tip': result['retained_tip']}

    def verify(self, online):
        """The whole published mirror, read back through the gateway's own reader class."""
        began = time.monotonic()
        tip, held = self.store(self.mirror)
        if tip == 0:
            raise ValueError('no published mirror')
        self.sample_every = max(1, held // 64)
        seen = self.pages(self.modules['gateway_history'].History(self.mirror, self.network))
        if seen['tip_slot'] != tip or seen['retained_tip'] != tip or seen['blocks'] != held:
            raise ValueError('pages do not cover the published manifest')
        seen['tip_matches_node'] = seen['sampled_blocks_match_node'] = None
        if online:
            peer, _ = node_endpoint(self.config['ready'], self.network)
            header = node_read(peer, 'getBlock', tip)
            if header['blockhash'] != seen['tip_blockhash'] or header['blockHeight'] != seen['tip_block_height']:
                raise ValueError('the mirror ends on a block the node does not have')
            seen['tip_matches_node'] = True
            # About sixty-four blocks spread over the whole store, each compared with the node's own.
            for block in self.sampled:
                header = node_read(peer, 'getBlock', block['slot'])
                if (header['blockhash'] != block['blockhash'] or header['blockHeight'] != block['block_height']
                        or header.get('parentSlot') != block['parent_slot']):
                    raise ValueError('a retained block differs from the node at the same slot')
            seen['sampled_blocks_match_node'] = len(self.sampled)
        del seen['tip_blockhash']
        seen['seconds'] = round(time.monotonic() - began, 1)
        return seen

    def adopt(self, source):
        """Copy an earlier retained store into the empty one. Publishes nothing."""
        if not source or not Path(source).is_absolute():
            raise ValueError('absolute path of the earlier store required')
        if self.store(self.primary)[0] or self.store(self.mirror)[0] or any(self.mirror.iterdir()):
            raise ValueError('the store is not empty; nothing is adopted over existing history')
        copied = self.retention.capture(Path(source), self.primary, self.network, self.config['store_budget_bytes'])
        tip, held = self.store(self.primary)
        if tip != copied['finalized_slot']:
            raise ValueError('adopted manifest differs from the copy')
        self.record(phase='adopted', error=None, adopted_tip=tip, adopted_blocks=held)
        return {'adopted': True, 'tip_slot': tip, 'blocks': held, 'segments': copied['segments'],
                'bytes': copied['referenced_bytes'], 'published': False}

    def serve_check(self, wiring, trusted, prefix):
        """First and last page from the class the gateway itself uses for retained pages."""
        tip, held = self.store(self.mirror)
        if tip == 0:
            raise ValueError('no published mirror')
        report = {'wired': False, 'reader': 'gateway_history.History'}
        source = self.modules['gateway_history'].History(self.mirror, self.network)
        if wiring is not None:
            raw = trusted(wiring, 1024 * 1024)
            module = types.ModuleType('installed_cohort_service')
            module.__file__ = str(wiring)
            exec(compile(raw, str(wiring), 'exec'), module.__dict__)
            if not hasattr(module, 'RetainedFirstSync') or not hasattr(module, 'RETAINED'):
                raise ValueError('the installed cohort service has no retained first-sync class')
            if Path(prefix + str(module.RETAINED)) != self.mirror:
                raise ValueError('the gateway is wired to another directory than this mirror')
            source = module.RetainedFirstSync(self.mirror, self.network)
            report = {'wired': True, 'reader': 'RetainedFirstSync', 'wiring_sha256': hashlib.sha256(raw).hexdigest()}
        raw, count = source.page_compact_counted({'jsonrpc': '2.0', 'id': 1, 'params': [0, 2 ** 64 - 1, None]},
                                                 max_blocks=32768, deadline=time.monotonic() + 60)
        first = json.loads(raw)['result']
        if first is None or count < 1 or first['after_slot'] != 0 or first['retained_tip'] != tip:
            raise ValueError('the first page was not served')
        _, files, _ = self.retention.manifest(self.mirror, self.network)
        after = files[-2][1]['last_slot'] if len(files) > 1 else 0
        last = self.pages(source, after)
        if last['tip_slot'] != tip:
            raise ValueError('the last page does not reach the retained tip')
        report.update(first_page_blocks=count, first_page_bytes=len(raw), last_page_blocks=last['blocks'],
                      retained_tip=tip, retained_blocks=held)
        return report

    def close(self):
        self.stop.set()
        with self.lock:
            if self.child is not None and self.child.poll() is None:
                self.child.kill()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('check', 'once', 'run', 'verify', 'serve-check', 'adopt'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--config-sha256', required=True)
    parser.add_argument('--verify', action='store_true', help='once: also read the mirror back and compare its tip with the node')
    parser.add_argument('--wiring', help='serve-check: the installed tools/native_cohort_service.py')
    parser.add_argument('--from', dest='source', help='adopt: directory of the earlier retained store')
    parser.add_argument('--rehearsal-root', default='',
                        help='rehearsal on a copy only, never on the server: pinned files are owned by the caller '
                             'instead of root, and the gateway class is given the copy of its directory')
    args = parser.parse_args(argv)
    if HEX.fullmatch(args.config_sha256) is None:
        parser.error('--config-sha256 must be 64 lower-case hex characters')
    trusted = reader(os.geteuid() if args.rehearsal_root else 0)
    config = load_config(args.config, args.config_sha256, trusted)
    modules = load_modules(config, trusted)
    if args.command == 'check':
        for key in ('collector', 'profile'):
            trusted(config[key], 256 * 1024 * 1024, config[key + '_sha256'])
        print(json.dumps({'configuration': 'valid', 'services_started': 0, 'interval_seconds': config['interval_seconds'],
                          'pace_percent': config['pace_percent'], 'store_budget_bytes': config['store_budget_bytes']}))
        return 0
    if os.geteuid() == 0:
        raise ValueError('the collector runs as the gateway service identity, never as root')
    progress = (lambda status: print(json.dumps(status, sort_keys=True), flush=True)) if args.command == 'once' else None
    mirror = Mirror(config, modules, trusted, progress)
    if args.command == 'verify':
        print(json.dumps(dict(mirror.verify(False), verified=True), sort_keys=True))
        return 0
    if args.command == 'serve-check':
        print(json.dumps(mirror.serve_check(args.wiring, trusted, args.rehearsal_root), sort_keys=True))
        return 0
    if args.command == 'adopt':
        try:
            print(json.dumps(mirror.adopt(args.source), sort_keys=True))
        except (ValueError, OSError) as error:
            # One line for the runner's log; the earlier store was only read.
            print('not adopted: ' + str(error)[:200], file=sys.stderr)
            return 1
        return 0
    signal.signal(signal.SIGTERM, lambda *_: mirror.close())
    signal.signal(signal.SIGINT, lambda *_: mirror.close())
    if args.command == 'once':
        status = mirror.attempt()
        if status is None:
            return 1
        if args.verify:
            try:
                mirror.record(verification=dict(mirror.verify(True), verified=True))
            except (ValueError, OSError, Blocked) as error:
                mirror.record(phase='blocked', error='mirror_verification_failed',
                              verification={'verified': False, 'reason': str(error)[:200]})
                return 1
        return 0
    down = 0
    while not mirror.stop.is_set():
        status = mirror.attempt()
        if status is None and mirror.status.get('error') in ('chain_not_running', 'node_unavailable', 'ready_record_differs'):
            down += 1
            if down >= 3:
                # The chain is not there. Leave; this unit may only run while the validators do.
                mirror.record(phase='stopped', error='chain_not_running')
                return EXIT_CHAIN_DOWN
            mirror.stop.wait(20)
            continue
        down = 0
        mirror.stop.wait(config['interval_seconds'])
    mirror.record(phase='stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
