"""Tests for explorer_feed_v0.

Run from this folder:

    python3 -m unittest -v test_explorer_feed_v0

Every test talks to a fake JSON-RPC node served by http.server on 127.0.0.1;
nothing outside the loopback interface and a temporary directory is touched.
"""

import hashlib
import hmac
import http.client
import http.server
import io
import ipaddress
import json
import os
import re
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import explorer_feed_v0 as feed  # noqa: E402

SCRIPT = os.path.join(HERE, "explorer_feed_v0.py")
UNIT = os.path.join(HERE, "zolana-explorer-feed-v0.service")

NETWORK_FIELDS = {"status", "tip_slot", "finalized_slot", "block_height", "slot_time_ms",
                  "last_block_at", "validators"}
VALIDATOR_FIELDS = {"identity", "vote_account", "last_vote", "active"}
BLOCK_FIELDS = {"slot", "parent_slot", "blockhash", "block_time", "block_height", "tx_count",
                "non_vote_tx_count"}
TRANSACTION_FIELDS = {"signature", "slot", "block_time", "ok", "fee", "kind"}
STAT_FIELDS = {"since", "blocks_seen", "transactions_seen", "non_vote_transactions_seen"}
ALLOWED_METHODS = {"getGenesisHash", "getSlot", "getBlockHeight", "getBlocks", "getBlock",
                   "getVoteAccounts", "getHealth"}


def name(kind, number):
    """A deterministic 44-character stand-in for a base58 hash or address."""
    return (kind + hashlib.sha256(("%s:%d" % (kind, number)).encode()).hexdigest())[:44]


def signature(slot, position):
    digest = hashlib.sha256(("signature:%d:%d" % (slot, position)).encode()).hexdigest()
    return (digest + digest)[:88]


class FakeClock:
    def __init__(self):
        self.now = 1800000000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeRpcError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class FakeChain:
    """A scriptable chain answering the JSON-RPC methods the feed service uses."""

    def __init__(self, clock):
        self.lock = threading.RLock()
        self.genesis = name("G", 1)
        self.epoch = int(clock()) - 200000
        self.tip = 0
        self.finality_lag = 32
        self.blocks = {}
        self.parent = 0
        self.height = 0
        self.votes_per_block = 1
        self.program_per_block = 0
        self.fail_every = 0
        self.program_counter = 0
        self.phantom = {}               # slot -> error code getBlock gives although getBlocks lists it
        self.full_broken = set()        # slots whose block the node fails to return with full details
        self.missing = set()            # methods answered with "Method not found"
        self.reject_commitments = set() # getBlock commitments answered with "Invalid params"
        self.reject_details = set()     # getBlock transactionDetails answered with "Invalid params"
        self.plain_slot_only = False    # getSlot refuses a config object
        self.validators = 1
        self.delinquent = 1
        self.delay = 0.0
        self.calls = []
        self.http_requests = []

    # -- scripting ---------------------------------------------------------

    def advance(self, count, skip_every=0):
        with self.lock:
            for _ in range(count):
                self.tip += 1
                if skip_every and self.tip % skip_every == 0:
                    continue
                self._produce(self.tip)

    def jump(self, slots, produce=300):
        """Move the tip far ahead, producing blocks only for the last stretch."""
        with self.lock:
            self.tip += slots - produce
            self.advance(produce)

    def reset_ledger(self):
        with self.lock:
            self.blocks = {}
            self.tip = self.parent = self.height = 0

    def _produce(self, slot):
        entries = []
        for index in range(self.votes_per_block):
            keys = [name("N", index), name("V", index), feed.VOTE_PROGRAM]
            if slot % 2 == 0:           # the jsonParsed shape: objects carrying "pubkey"
                keys = [{"pubkey": key, "signer": i == 0, "writable": i < 2} for i, key in enumerate(keys)]
            entries.append({"transaction": {"signatures": [signature(slot, len(entries))],
                                            "message": {"accountKeys": keys}},
                            "meta": {"err": None, "fee": 5000}, "version": "legacy"})
        for _ in range(self.program_per_block):
            self.program_counter += 1
            failed = bool(self.fail_every) and self.program_counter % self.fail_every == 0
            keys = [name("W", self.program_counter), name("P", 1)]
            entries.append({"transaction": {"signatures": [signature(slot, len(entries))],
                                            "message": {"accountKeys": keys}},
                            "meta": {"err": {"InstructionError": [0, "Custom"]} if failed else None, "fee": 5000},
                            "version": "legacy"})
        self.height += 1
        self.blocks[slot] = {"blockhash": name("B", slot), "previousBlockhash": name("B", self.parent),
                             "parentSlot": self.parent, "blockTime": self.epoch + slot * 2 // 5,
                             "blockHeight": self.height, "transactions": entries}
        self.parent = slot

    def expected_ok(self, slot, tx_signature):
        for entry in self.blocks[slot]["transactions"]:
            if entry["transaction"]["signatures"][0] == tx_signature:
                return entry["meta"]["err"] is None
        raise AssertionError("signature not in block %d" % slot)

    def calls_to(self, method):
        with self.lock:
            return [params for called, params in self.calls if called == method]

    # -- JSON-RPC ----------------------------------------------------------

    def handle(self, method, params):
        with self.lock:
            self.calls.append((method, params))
            handler = getattr(self, "rpc_" + method, None)
            if handler is None or method in self.missing:
                raise FakeRpcError(-32601, "Method not found")
            return handler(*params)

    def ceiling(self, config):
        commitment = (config or {}).get("commitment", "finalized")
        return max(0, self.tip - self.finality_lag) if commitment == "finalized" else self.tip

    def rpc_getGenesisHash(self):
        return self.genesis

    def rpc_getHealth(self):
        return "ok"

    def rpc_getSlot(self, config=None):
        if self.plain_slot_only and config is not None:
            raise FakeRpcError(-32602, "Invalid params")
        return self.ceiling(config)

    def rpc_getBlockHeight(self, config=None):
        ceiling = self.ceiling(config)
        return max((block["blockHeight"] for slot, block in self.blocks.items() if slot <= ceiling), default=0)

    def rpc_getBlocks(self, start, end, config=None):
        top = min(end, self.ceiling(config))
        return sorted(slot for slot in set(self.blocks) | set(self.phantom) if start <= slot <= top)

    def rpc_getBlock(self, slot, config=None):
        config = config or {}
        details = config.get("transactionDetails", "full")
        if config.get("commitment", "finalized") in self.reject_commitments or details in self.reject_details:
            raise FakeRpcError(-32602, "Invalid params")
        if slot > self.ceiling(config):
            raise FakeRpcError(-32004, "Block not available for slot %d" % slot)
        if details == "full" and slot in self.full_broken:
            raise FakeRpcError(-32603, "Internal error")
        if slot in self.phantom:
            raise FakeRpcError(self.phantom[slot], "Slot %d is not here" % slot)
        if slot not in self.blocks:
            raise FakeRpcError(-32007, "Slot %d was skipped, or missing due to ledger jump to recent snapshot" % slot)
        block = self.blocks[slot]
        if details == "signatures":
            reply = {key: value for key, value in block.items() if key != "transactions"}
            reply["signatures"] = [entry["transaction"]["signatures"][0] for entry in block["transactions"]]
            return reply
        return block

    def rpc_getVoteAccounts(self, config=None):
        def account(number):
            return {"votePubkey": name("V", number), "nodePubkey": name("N", number), "activatedStake": 1000000,
                    "epochVoteAccount": True, "commission": 0, "lastVote": self.tip, "rootSlot": self.ceiling(None)}
        return {"current": [account(i) for i in range(self.validators)],
                "delinquent": [account(1000 + i) for i in range(self.delinquent)]}

    def rpc_sendTransaction(self, *params):
        return signature(0, 0)

    def rpc_requestAirdrop(self, *params):
        return signature(0, 1)


class RpcHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        chain = self.server.chain
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        chain.http_requests.append((self.command, self.path))
        if chain.delay:
            time.sleep(chain.delay)
        request = json.loads(body)
        reply = {"jsonrpc": "2.0", "id": request.get("id")}
        try:
            reply["result"] = chain.handle(request["method"], request.get("params") or [])
        except FakeRpcError as exc:
            reply["error"] = {"code": exc.code, "message": exc.message}
        data = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        pass


class RpcServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def handle_error(self, request, client_address):
        pass


class FakeNode:
    """The fake chain behind a real HTTP listener that can go away and come back."""

    def __init__(self, chain):
        self.chain = chain
        self.port = 0
        self.server = None
        self.start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def start(self):
        self.server = RpcServer(("127.0.0.1", self.port), RpcHandler)
        self.server.chain = self.chain
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join()
            self.server = None


class FeedTestCase(unittest.TestCase):
    def setUp(self):
        self.log = io.StringIO()
        feed.log_stream = self.log
        self.addCleanup(setattr, feed, "log_stream", None)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state_dir = os.path.join(self.tmp.name, "state")
        os.mkdir(self.state_dir)
        self.key = hashlib.sha256(b"explorer feed test key").digest()
        self.clock = FakeClock()
        self.chain = FakeChain(self.clock)
        self.node = FakeNode(self.chain)
        self.addCleanup(self.node.stop)

    def poller(self, timeout=2.0, **options):
        rpc = feed.RpcClient(self.node.url, timeout=timeout)
        poller = feed.FeedPoller(rpc, self.state_dir, self.key, clock=self.clock, monotonic=self.clock, **options)
        poller.start()
        return poller

    def cycle(self, poller, slots=5, seconds=2.0, **produce):
        self.chain.advance(slots, **produce)
        self.clock.advance(seconds)
        return poller.poll_once()

    def events(self):
        return [line.split()[1] for line in self.log.getvalue().splitlines()]

    def state_file(self, filename):
        with open(os.path.join(self.state_dir, filename), "rb") as stream:
            return stream.read()

    def assert_optional_int(self, value):
        self.assertTrue(value is None or (type(value) is int and value >= 0), value)

    def check_contract(self, poller):
        """Assert the published payload follows the shared feed contract; return it parsed."""
        payload, sig = poller.store.current()
        self.assertLessEqual(len(payload), 400 * 1000)
        self.assertEqual(sig, hmac.new(self.key, payload, hashlib.sha256).hexdigest().encode() + b"\n")
        self.assertRegex(sig.decode(), r"\A[0-9a-f]{64}\n\Z")
        doc = json.loads(payload.decode("utf-8"))
        self.assertEqual(json.dumps(doc, separators=(",", ":")).encode(), payload, "compact separators")
        self.assertEqual(list(doc), ["format", "generated_at", "genesis_hash", "network", "blocks",
                                     "transactions", "stats"])
        self.assertEqual(doc["format"], "zolana-explorer-feed-v0")
        self.assertIs(type(doc["generated_at"]), int)
        self.assertTrue(doc["genesis_hash"] is None or isinstance(doc["genesis_hash"], str))

        network = doc["network"]
        self.assertEqual(set(network), NETWORK_FIELDS)
        self.assertIn(network["status"], ("live", "unavailable"))
        for field in ("tip_slot", "finalized_slot", "block_height", "last_block_at"):
            self.assert_optional_int(network[field])
        self.assertTrue(network["slot_time_ms"] is None or type(network["slot_time_ms"]) in (int, float))
        if network["last_block_at"] is not None:
            self.assertLessEqual(network["last_block_at"], doc["generated_at"])
        self.assertIsInstance(network["validators"], list)
        for row in network["validators"]:
            self.assertEqual(set(row), VALIDATOR_FIELDS)
            self.assertIsInstance(row["identity"], str)
            self.assertTrue(row["vote_account"] is None or isinstance(row["vote_account"], str))
            self.assert_optional_int(row["last_vote"])
            self.assertIs(type(row["active"]), bool)

        self.assertLessEqual(len(doc["blocks"]), 120)
        for row in doc["blocks"]:
            self.assertEqual(set(row), BLOCK_FIELDS)
            self.assertIs(type(row["slot"]), int)
            self.assertIsInstance(row["blockhash"], str)
            for field in ("parent_slot", "block_time", "block_height"):
                self.assert_optional_int(row[field])
            self.assertIs(type(row["tx_count"]), int)
            self.assertIs(type(row["non_vote_tx_count"]), int)
            self.assertLessEqual(row["non_vote_tx_count"], row["tx_count"])
        slots = [row["slot"] for row in doc["blocks"]]
        self.assertEqual(slots, sorted(set(slots), reverse=True), "blocks newest first, no duplicates")

        self.assertLessEqual(len(doc["transactions"]), 200)
        for row in doc["transactions"]:
            self.assertEqual(set(row), TRANSACTION_FIELDS)
            self.assertIsInstance(row["signature"], str)
            self.assertIs(type(row["slot"]), int)
            self.assert_optional_int(row["block_time"])
            self.assertIs(type(row["ok"]), bool)
            self.assertIs(type(row["fee"]), int)
            self.assertIn(row["kind"], ("vote", "program"))
        tx_slots = [row["slot"] for row in doc["transactions"]]
        self.assertEqual(tx_slots, sorted(tx_slots, reverse=True), "transactions newest first")
        self.assertEqual(len({row["signature"] for row in doc["transactions"]}), len(doc["transactions"]))

        self.assertEqual(set(doc["stats"]), STAT_FIELDS)
        for value in doc["stats"].values():
            self.assertIs(type(value), int)
        return doc


class RpcClientTests(FeedTestCase):
    def test_allowlist_is_exactly_the_seven_read_only_methods(self):
        self.assertEqual(set(feed.RPC_ALLOWLIST), ALLOWED_METHODS)

    def test_methods_outside_the_allowlist_raise_before_anything_is_sent(self):
        rpc = feed.RpcClient(self.node.url)
        for method in ("sendTransaction", "requestAirdrop", "getAccountInfo", "getBalance", "getTransaction",
                       "getProgramAccounts", "simulateTransaction", "getslot", "getSlot ", ""):
            with self.assertRaises(feed.RpcMethodNotAllowed, msg=method):
                rpc.call(method, [])
        self.assertEqual(self.chain.http_requests, [])
        self.assertEqual(self.chain.calls, [])

    def test_allowlisted_call_is_a_post_to_the_root_path(self):
        self.chain.advance(40)
        rpc = feed.RpcClient(self.node.url)
        self.assertEqual(rpc.call("getSlot", [{"commitment": "confirmed"}]), 40)
        self.assertEqual(rpc.call("getGenesisHash"), self.chain.genesis)
        self.assertEqual(self.chain.http_requests, [("POST", "/"), ("POST", "/")])

    def test_json_rpc_error_and_unreachable_node_are_told_apart(self):
        rpc = feed.RpcClient(self.node.url)
        self.chain.missing.add("getHealth")
        with self.assertRaises(feed.RpcResponseError) as caught:
            rpc.call("getHealth")
        self.assertEqual(caught.exception.code, -32601)
        self.node.stop()
        with self.assertRaises(feed.RpcUnavailable):
            rpc.call("getSlot")

    def test_slow_node_times_out(self):
        self.chain.delay = 1.0
        rpc = feed.RpcClient(self.node.url, timeout=0.2)
        started = time.monotonic()
        with self.assertRaises(feed.RpcUnavailable):
            rpc.call("getSlot")
        self.assertLess(time.monotonic() - started, 0.9)
        self.assertEqual(feed.RPC_TIMEOUT_SECONDS, 4.0)
        self.assertEqual(feed.RpcClient(self.node.url).timeout, 4.0)

    def test_rpc_url_must_be_plain_http_to_the_root(self):
        self.assertEqual(feed.normalize_rpc_url("http://127.0.0.1:49643"), "http://127.0.0.1:49643/")
        self.assertEqual(feed.normalize_rpc_url("http://[::1]:8899/"), "http://[::1]:8899/")
        for url in ("file:///etc/hostname", "ftp://127.0.0.1/", "http://user:secret@127.0.0.1:1/",
                    "http://127.0.0.1:1/other", "http://127.0.0.1:1/?a=1", "127.0.0.1:1", "http://"):
            with self.assertRaises(feed.ConfigError, msg=url):
                feed.normalize_rpc_url(url)


class PollerTests(FeedTestCase):
    def test_normal_advancing_chain(self):
        self.chain.program_per_block = 2
        self.chain.fail_every = 3
        self.chain.advance(200)
        poller = self.poller()
        first = self.check_contract(poller)
        self.assertEqual(first["network"]["status"], "unavailable")
        self.assertEqual(first["blocks"], [])

        for _ in range(8):
            self.assertEqual(self.cycle(poller), "live")
        doc = self.check_contract(poller)
        network = doc["network"]
        self.assertEqual(doc["genesis_hash"], self.chain.genesis)
        self.assertEqual(doc["generated_at"], int(self.clock()))
        self.assertEqual(network["status"], "live")
        self.assertEqual(network["tip_slot"], 240)
        self.assertEqual(network["finalized_slot"], 208)
        self.assertEqual(network["block_height"], 240)
        self.assertEqual(network["slot_time_ms"], 400.0)
        self.assertEqual(network["last_block_at"], int(self.clock()))
        self.assertEqual(network["validators"], [
            {"identity": name("N", 0), "vote_account": name("V", 0), "last_vote": 240, "active": True},
            {"identity": name("N", 1000), "vote_account": name("V", 1000), "last_vote": 240, "active": False},
        ])

        # First start began 120 slots behind the tip (slot 85); the window keeps the newest 120 blocks.
        self.assertEqual([row["slot"] for row in doc["blocks"]], list(range(208, 88, -1)))
        newest = doc["blocks"][0]
        self.assertEqual(newest, {"slot": 208, "parent_slot": 207, "blockhash": name("B", 208),
                                  "block_time": self.chain.blocks[208]["blockTime"], "block_height": 208,
                                  "tx_count": 3, "non_vote_tx_count": 2})
        self.assertEqual(doc["stats"], {"since": doc["stats"]["since"], "blocks_seen": 124,
                                        "transactions_seen": 372, "non_vote_transactions_seen": 248})

        # 248 non-vote transactions were seen: the list holds the newest 200 and no votes.
        self.assertEqual(len(doc["transactions"]), 200)
        self.assertEqual({row["kind"] for row in doc["transactions"]}, {"program"})
        self.assertEqual([row["signature"] for row in doc["transactions"][:3]],
                         [signature(208, 2), signature(208, 1), signature(207, 2)])
        for row in doc["transactions"]:
            self.assertEqual(row["ok"], self.chain.expected_ok(row["slot"], row["signature"]))
            self.assertEqual(row["fee"], 5000)
            self.assertEqual(row["block_time"], self.chain.blocks[row["slot"]]["blockTime"])
        self.assertIn(False, {row["ok"] for row in doc["transactions"]})

        self.assertEqual(poller.block_variant, feed.BlockVariant("full", "finalized"))
        self.assertEqual(self.chain.calls_to("getBlock")[0][1], {
            "encoding": "json", "transactionDetails": "full", "rewards": False,
            "maxSupportedTransactionVersion": 0, "commitment": "finalized"})
        self.assertLessEqual({method for method, _ in self.chain.calls}, ALLOWED_METHODS)
        self.assertEqual(set(self.chain.http_requests), {("POST", "/")})

    def test_files_are_written_atomically_with_a_valid_signature(self):
        self.chain.advance(150)
        poller = self.poller()
        self.cycle(poller)
        payload, sig = poller.store.current()
        self.assertEqual(self.state_file("feed.json"), payload)
        self.assertEqual(self.state_file("feed.sig"), sig)
        self.assertEqual(sig.strip().decode(), hmac.new(self.key, payload, hashlib.sha256).hexdigest())
        self.assertEqual(sig.count(b"\n"), 1)
        for filename in ("feed.json", "feed.sig"):
            mode = stat.S_IMODE(os.stat(os.path.join(self.state_dir, filename)).st_mode)
            self.assertEqual(mode, 0o644, filename)
        self.assertEqual(sorted(os.listdir(self.state_dir)), ["feed.json", "feed.sig", "window.json"])

    def test_votes_only_fill_while_fewer_than_twenty_non_vote_exist(self):
        self.chain.finality_lag = 0
        self.chain.advance(60)
        poller = self.poller()
        self.cycle(poller)
        self.cycle(poller)
        doc = self.check_contract(poller)
        self.assertEqual(len(doc["transactions"]), 20)
        self.assertEqual({row["kind"] for row in doc["transactions"]}, {"vote"})
        self.assertEqual(doc["transactions"][0]["slot"], doc["blocks"][0]["slot"])
        self.assertEqual(doc["stats"]["non_vote_transactions_seen"], 0)

        self.chain.program_per_block = 3
        self.cycle(poller, slots=1)
        self.chain.program_per_block = 0
        self.cycle(poller)
        kinds = [row["kind"] for row in self.check_contract(poller)["transactions"]]
        self.assertEqual((kinds.count("program"), kinds.count("vote")), (3, 17))

        self.chain.program_per_block = 4
        self.cycle(poller)
        doc = self.check_contract(poller)
        self.assertEqual({row["kind"] for row in doc["transactions"]}, {"program"})
        self.assertEqual(len(doc["transactions"]), 23)

    def test_limits_hold_on_a_busy_chain(self):
        self.chain.finality_lag = 0
        self.chain.program_per_block = 6
        self.chain.validators = 300
        self.chain.advance(400)
        poller = self.poller()
        for _ in range(8):
            self.cycle(poller)
        doc = self.check_contract(poller)
        self.assertEqual(len(doc["blocks"]), 120)
        self.assertEqual(len(doc["transactions"]), 200)
        self.assertEqual(len(doc["network"]["validators"]), feed.MAX_VALIDATORS)
        self.assertGreater(doc["stats"]["blocks_seen"], 120)
        self.assertGreater(doc["stats"]["non_vote_transactions_seen"], 200)
        self.assertLessEqual(len(poller.store.current()[0]), 400 * 1000)
        self.assertLessEqual(max(len(params) for params in self.chain.calls_to("getBlock")), 2)

    def test_at_most_max_blocks_per_cycle_are_fetched(self):
        self.chain.finality_lag = 0
        self.chain.advance(300)
        poller = self.poller(max_blocks_per_cycle=7)
        self.cycle(poller)
        self.assertEqual(len(self.chain.calls_to("getBlock")), 7)
        self.assertEqual(len(self.check_contract(poller)["blocks"]), 7)

    def test_skipped_slots_are_passed_over_silently(self):
        self.chain.finality_lag = 0
        self.chain.advance(80, skip_every=4)
        self.chain.phantom[41] = -32007     # listed by getBlocks, then reported as skipped
        self.chain.phantom[43] = -32009
        poller = self.poller()
        for _ in range(4):
            self.assertEqual(self.cycle(poller, slots=4, skip_every=4), "live")
        doc = self.check_contract(poller)
        slots = [row["slot"] for row in doc["blocks"]]
        self.assertEqual(slots, sorted((s for s in range(1, 97) if s % 4 and s not in (41, 43)), reverse=True))
        parents = {row["slot"]: row["parent_slot"] for row in doc["blocks"]}
        self.assertEqual((parents[5], parents[6], parents[93]), (3, 5, 91))     # slots 4 and 92 hold no block
        self.assertEqual(doc["stats"]["blocks_seen"], len(slots))
        self.assertLessEqual(set(self.events()), {"rpc-ok", "rpc-health", "block-variant"})

    def test_block_the_node_never_returns_is_given_up_after_retries(self):
        self.chain.finality_lag = 0
        self.chain.advance(50)
        self.chain.phantom[40] = -32004     # "not available" for good
        poller = self.poller()
        for _ in range(6):
            self.cycle(poller, slots=1)
        slots = [row["slot"] for row in self.check_contract(poller)["blocks"]]
        self.assertNotIn(40, slots)
        self.assertIn(39, slots)
        self.assertEqual(slots[0], self.chain.tip)
        self.assertEqual(len([p for p in self.chain.calls_to("getBlock") if p[0] == 40]), 2 * feed.PENDING_RETRIES)

    def test_node_without_getblock_still_publishes_network_status(self):
        self.chain.missing.add("getBlock")
        self.chain.advance(200)
        poller = self.poller()
        for _ in range(3):
            self.assertEqual(self.cycle(poller), "live")
        doc = self.check_contract(poller)
        self.assertEqual(doc["network"]["status"], "live")
        self.assertEqual(doc["network"]["tip_slot"], self.chain.tip)
        self.assertEqual(doc["network"]["block_height"], self.chain.height)
        self.assertEqual(doc["blocks"], [])
        self.assertEqual(doc["transactions"], [])
        self.assertEqual(doc["stats"]["blocks_seen"], 0)
        self.assertEqual(self.events().count("blocks-unavailable"), 1)
        probes = len(self.chain.calls_to("getBlock"))
        self.assertEqual(probes, len(feed.BLOCK_VARIANTS))

        # Support is looked for again later, without restarting the service.
        self.chain.missing.clear()
        self.cycle(poller, seconds=feed.BLOCK_REPROBE_SECONDS + 1)
        self.assertGreater(len(self.check_contract(poller)["blocks"]), 0)

    def test_node_without_getblocks_still_publishes_network_status(self):
        self.chain.missing.add("getBlocks")
        self.chain.advance(200)
        poller = self.poller()
        for _ in range(3):
            self.assertEqual(self.cycle(poller), "live")
        doc = self.check_contract(poller)
        self.assertEqual((doc["network"]["status"], doc["network"]["tip_slot"]), ("live", self.chain.tip))
        self.assertEqual(doc["blocks"], [])
        self.assertEqual(self.chain.calls_to("getBlock"), [])
        self.assertEqual(self.events().count("blocks-unavailable"), 1)

    def test_bare_node_with_only_getslot(self):
        self.chain.missing.update(ALLOWED_METHODS - {"getSlot"})
        self.chain.plain_slot_only = True
        self.chain.advance(100)
        poller = self.poller()
        self.assertEqual(self.cycle(poller), "live")
        self.assertEqual(self.cycle(poller), "live")
        doc = self.check_contract(poller)
        self.assertIsNone(doc["genesis_hash"])
        self.assertEqual(doc["network"]["tip_slot"], self.chain.tip - self.chain.finality_lag)
        self.assertEqual(doc["network"]["status"], "live")
        for field in ("finalized_slot", "block_height"):
            self.assertIsNone(doc["network"][field])
        self.assertEqual(doc["network"]["validators"], [])
        self.assertEqual(doc["blocks"], [])

    def test_falls_back_to_confirmed_commitment_and_remembers_it(self):
        self.chain.reject_commitments.add("finalized")
        self.chain.advance(200)
        poller = self.poller()
        self.cycle(poller)
        self.assertEqual(poller.block_variant, feed.BlockVariant("full", "confirmed"))
        del self.chain.calls[:]
        for _ in range(6):
            self.cycle(poller)
        configs = [params[1] for params in self.chain.calls_to("getBlock")]
        self.assertTrue(configs)
        for config in configs:
            self.assertEqual((config["commitment"], config["transactionDetails"]), ("confirmed", "full"))
        doc = self.check_contract(poller)
        self.assertEqual(doc["blocks"][0]["slot"], self.chain.tip)
        self.assertEqual(self.events().count("block-variant"), 1)

    def test_falls_back_to_signatures_and_classifies_as_program(self):
        self.chain.reject_details.add("full")
        self.chain.program_per_block = 2
        self.chain.advance(200)
        poller = self.poller()
        for _ in range(3):
            self.cycle(poller)
        self.assertEqual(poller.block_variant, feed.BlockVariant("signatures", "finalized"))
        doc = self.check_contract(poller)
        self.assertGreater(len(doc["blocks"]), 0)
        for row in doc["blocks"]:
            self.assertEqual((row["tx_count"], row["non_vote_tx_count"]), (3, 3))
        self.assertEqual({(row["kind"], row["ok"], row["fee"]) for row in doc["transactions"]}, {("program", True, 0)})
        self.assertEqual(doc["transactions"][0]["signature"], signature(doc["blocks"][0]["slot"], 2))

    def test_one_block_the_node_cannot_return_in_full_is_listed_from_its_signatures(self):
        self.chain.finality_lag = 0
        self.chain.program_per_block = 1
        self.chain.advance(60)
        self.chain.full_broken.add(50)
        poller = self.poller()
        for _ in range(3):
            self.cycle(poller)
        rows = {row["slot"]: row for row in self.check_contract(poller)["blocks"]}
        self.assertEqual((rows[50]["tx_count"], rows[50]["non_vote_tx_count"]), (2, 2))
        self.assertEqual((rows[51]["tx_count"], rows[51]["non_vote_tx_count"]), (2, 1))
        self.assertEqual(poller.block_variant, feed.BlockVariant("full", "finalized"))

    def test_passing_genesis_error_does_not_discard_the_window(self):
        self.chain.finality_lag = 0
        self.chain.advance(150)
        poller = self.poller()
        for _ in range(3):
            self.cycle(poller)
        before = self.check_contract(poller)
        poller.genesis_recheck_at = 0           # the periodic re-check is due
        self.chain.missing.add("getGenesisHash")
        self.assertEqual(self.cycle(poller), "live")
        self.chain.missing.clear()
        self.assertEqual(self.cycle(poller), "live")
        after = self.check_contract(poller)
        self.assertEqual(after["genesis_hash"], self.chain.genesis)
        self.assertEqual(after["stats"]["since"], before["stats"]["since"])
        self.assertGreater(after["stats"]["blocks_seen"], before["stats"]["blocks_seen"])
        self.assertNotIn("genesis-changed", self.events())

        # A node that really stopped naming its genesis is taken at its word after repeated failures.
        poller.genesis_recheck_at = 0
        self.chain.missing.add("getGenesisHash")
        for _ in range(feed.GENESIS_ERROR_LIMIT):
            self.cycle(poller)
        final = self.check_contract(poller)
        self.assertIsNone(final["genesis_hash"])
        self.assertEqual(final["network"]["status"], "live")
        self.assertIn("genesis-changed", self.events())
        self.assertEqual(final["stats"]["blocks_seen"], len(final["blocks"]))

    def test_first_start_begins_120_slots_behind_a_far_ahead_tip(self):
        self.chain.jump(100000)
        poller = self.poller()
        self.cycle(poller, slots=0)
        self.assertEqual(min(params[0] for params in self.chain.calls_to("getBlock")), 100000 - 120)
        self.assertEqual(min(params[0] for params in self.chain.calls_to("getBlocks")), 100000 - 120)
        self.assertEqual(poller.gaps, 0)
        self.assertEqual(self.check_contract(poller)["blocks"][-1]["slot"], 100000 - 120)

    def test_falling_more_than_500_slots_behind_jumps_forward_and_counts_a_gap(self):
        self.chain.finality_lag = 0
        self.chain.advance(200)
        poller = self.poller()
        for _ in range(5):
            self.cycle(poller)
        before = self.chain.tip
        self.assertEqual(self.check_contract(poller)["blocks"][0]["slot"], before)
        self.chain.jump(2000)
        del self.chain.calls[:]
        self.assertEqual(self.cycle(poller, slots=0), "live")
        self.assertEqual(poller.gaps, 1)
        self.assertEqual(min(params[0] for params in self.chain.calls_to("getBlock")), self.chain.tip - 120)
        self.cycle(poller)
        self.assertEqual(poller.gaps, 1)
        self.assertEqual(self.events().count("gap"), 1)
        doc = self.check_contract(poller)
        slots = [row["slot"] for row in doc["blocks"]]
        self.assertFalse([slot for slot in slots if before < slot < before + 2000 - 120])
        self.assertNotIn(b"gap", poller.store.current()[0])

    def test_node_going_away_flips_status_once_and_recovers(self):
        self.chain.finality_lag = 0
        self.chain.program_per_block = 1
        self.chain.advance(150)
        poller = self.poller()
        for _ in range(6):
            self.cycle(poller)
        live = self.check_contract(poller)
        live_bytes = poller.store.current()[0]
        self.assertEqual(live["network"]["status"], "live")
        self.assertEqual((len(live["blocks"]), live["blocks"][0]["slot"]), (120, self.chain.tip))

        self.node.stop()
        self.clock.advance(2)
        self.assertEqual(poller.poll_once(), "live")            # inside the 15 s allowance
        self.assertEqual(poller.store.current()[0], live_bytes) # and not refreshed while failing
        self.clock.advance(14)
        self.assertEqual(poller.poll_once(), "unavailable")
        down = self.check_contract(poller)
        down_bytes = poller.store.current()[0]
        self.assertEqual(down["network"]["status"], "unavailable")
        self.assertEqual(down["generated_at"], int(self.clock()))
        self.assertEqual(down["blocks"], live["blocks"])
        self.assertEqual(down["transactions"], live["transactions"])
        self.assertEqual(down["network"]["tip_slot"], live["network"]["tip_slot"])
        self.assertEqual(down["network"]["last_block_at"], live["network"]["last_block_at"])
        self.assertEqual(self.state_file("feed.json"), down_bytes)

        for _ in range(3):                                      # generated_at stops advancing
            self.clock.advance(20)
            self.assertEqual(poller.poll_once(), "unavailable")
        self.assertEqual(poller.store.current()[0], down_bytes)
        self.assertEqual(self.state_file("feed.json"), down_bytes)

        self.node.start()
        self.assertEqual(self.cycle(poller), "live")
        back = self.check_contract(poller)
        self.assertEqual(back["network"]["status"], "live")
        self.assertEqual(back["generated_at"], int(self.clock()))
        self.assertEqual(back["blocks"][0]["slot"], self.chain.tip)
        self.assertEqual(back["blocks"][5:], live["blocks"][:-5])       # the old window, five new blocks on top
        events = self.events()
        self.assertEqual((events.count("rpc-unavailable"), events.count("status-unavailable")), (1, 1))
        self.assertEqual(events.count("rpc-ok"), 2)

    def test_unresponsive_node_is_treated_as_unavailable(self):
        self.chain.advance(150)
        poller = self.poller(timeout=0.2)
        self.assertEqual(self.cycle(poller), "live")
        self.chain.delay = 0.6
        self.clock.advance(16)
        self.assertEqual(poller.poll_once(), "unavailable")
        self.assertEqual(self.check_contract(poller)["network"]["status"], "unavailable")

    def test_restart_reloads_the_window(self):
        self.chain.finality_lag = 0
        self.chain.program_per_block = 1
        self.chain.advance(150)
        first = self.poller()
        for _ in range(6):
            self.cycle(first)
        before = self.check_contract(first)
        first.close()
        top = before["blocks"][0]["slot"]

        del self.chain.calls[:]
        self.clock.advance(30)
        second = self.poller()
        self.assertIn("window-loaded", self.events())
        reloaded = self.check_contract(second)
        self.assertEqual(reloaded["network"]["status"], "unavailable")   # nothing polled yet
        self.assertEqual(reloaded["generated_at"], int(self.clock()))
        self.assertEqual(reloaded["genesis_hash"], self.chain.genesis)
        self.assertEqual(reloaded["blocks"], before["blocks"])
        self.assertEqual(reloaded["transactions"], before["transactions"])
        self.assertEqual(reloaded["stats"], before["stats"])
        self.assertEqual(reloaded["network"]["tip_slot"], before["network"]["tip_slot"])

        self.assertEqual(self.cycle(second), "live")
        after = self.check_contract(second)
        slots = [row["slot"] for row in after["blocks"]]
        self.assertEqual(slots, list(range(top + 5, top + 5 - len(slots), -1)))
        self.assertEqual(after["stats"]["blocks_seen"], before["stats"]["blocks_seen"] + 5)
        self.assertEqual(after["stats"]["since"], before["stats"]["since"])
        self.assertEqual(min(params[0] for params in self.chain.calls_to("getBlock")), top + 1)
        self.assertEqual(second.gaps, 0)

    def test_restart_with_another_genesis_starts_clean(self):
        self.chain.finality_lag = 0
        self.chain.advance(150)
        first = self.poller()
        for _ in range(6):
            self.cycle(first)
        before = self.check_contract(first)
        first.close()

        self.chain.genesis = name("G", 2)
        self.clock.advance(500)
        second = self.poller()
        self.assertEqual(self.cycle(second), "live")
        after = self.check_contract(second)
        self.assertIn("genesis-changed", self.events())
        self.assertEqual(after["genesis_hash"], name("G", 2))
        self.assertEqual(len(after["blocks"]), 30)
        self.assertEqual(after["stats"]["blocks_seen"], 30)
        self.assertEqual(after["stats"]["since"], int(self.clock()))
        self.assertGreater(after["stats"]["since"], before["stats"]["since"])
        self.assertEqual(after["blocks"][-1]["slot"], self.chain.tip - 120)

    def test_unreadable_window_file_starts_clean(self):
        with open(os.path.join(self.state_dir, "window.json"), "wb") as stream:
            stream.write(b'{"format":"zolana-explorer-window-v0","blocks":[{"slot":"x"}]')
        self.chain.advance(150)
        poller = self.poller()
        self.assertIn("window-ignored", self.events())
        self.assertEqual(self.cycle(poller), "live")
        self.assertEqual(len(self.check_contract(poller)["blocks"]), 30)

    def test_window_is_persisted_at_most_every_ten_seconds(self):
        self.chain.finality_lag = 0
        self.chain.advance(150)
        poller = self.poller()
        self.cycle(poller)
        saved = self.state_file("window.json")
        self.assertEqual(json.loads(saved)["genesis_hash"], self.chain.genesis)
        for _ in range(4):                  # 8 s later: not yet rewritten
            self.cycle(poller)
        self.assertEqual(self.state_file("window.json"), saved)
        self.cycle(poller)                  # 10 s after the last save
        later = self.state_file("window.json")
        self.assertNotEqual(later, saved)
        self.assertGreater(len(json.loads(later)["blocks"]), len(json.loads(saved)["blocks"]))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.state_dir, "window.json")).st_mode), 0o600)

    def test_restart_while_stopped_keeps_the_last_feed_untouched(self):
        self.chain.finality_lag = 0
        self.chain.advance(150)
        first = self.poller()
        for _ in range(3):
            self.cycle(first)
        self.node.stop()
        self.clock.advance(16)
        self.assertEqual(first.poll_once(), "unavailable")
        stopped = first.store.current()
        first.close()

        self.clock.advance(3600)
        second = self.poller()
        self.assertEqual(second.store.current(), stopped)       # generated_at did not move
        self.assertEqual(second.poll_once(), "unavailable")
        self.assertEqual(second.store.current(), stopped)
        self.assertEqual(self.state_file("feed.json"), stopped[0])
        self.node.start()
        self.assertEqual(self.cycle(second), "live")
        self.assertEqual(self.check_contract(second)["generated_at"], int(self.clock()))

    def test_ledger_reset_with_the_same_genesis_drops_the_old_window(self):
        self.chain.finality_lag = 0
        self.chain.advance(300)
        poller = self.poller()
        for _ in range(4):
            self.cycle(poller)
        self.chain.reset_ledger()
        self.chain.advance(60)
        self.clock.advance(2)
        self.assertEqual(poller.poll_once(), "live")
        doc = self.check_contract(poller)
        self.assertIn("tip-regressed", self.events())
        self.assertEqual(doc["network"]["tip_slot"], 60)
        self.assertEqual([row["slot"] for row in doc["blocks"]], list(range(30, 0, -1)))

    def test_slot_time_is_measured_from_observed_progress(self):
        self.chain.finality_lag = 0
        self.chain.advance(150)
        poller = self.poller()
        self.cycle(poller)
        self.assertIsNone(self.check_contract(poller)["network"]["slot_time_ms"])
        for _ in range(4):
            self.cycle(poller, slots=4, seconds=2.0)
        self.assertEqual(self.check_contract(poller)["network"]["slot_time_ms"], 500.0)
        for _ in range(40):                 # the tip stands still for longer than the window
            self.cycle(poller, slots=0)
        doc = self.check_contract(poller)
        self.assertIsNone(doc["network"]["slot_time_ms"])
        self.assertEqual(doc["network"]["status"], "live")
        self.assertLess(doc["network"]["last_block_at"], doc["generated_at"] - 60)


class PureFunctionTests(unittest.TestCase):
    def entry(self, keys, loaded=None):
        meta = {"err": None, "fee": 5000}
        if loaded is not None:
            meta["loadedAddresses"] = loaded
        return {"transaction": {"signatures": [signature(1, 0)], "message": {"accountKeys": keys}}, "meta": meta}

    def test_vote_detection(self):
        vote = feed.VOTE_PROGRAM
        self.assertEqual(vote, "Vote111111111111111111111111111111111111111")
        self.assertEqual(feed.transaction_kind(self.entry([name("A", 1), vote])), "vote")
        self.assertEqual(feed.transaction_kind(self.entry([{"pubkey": name("A", 1)}, {"pubkey": vote}])), "vote")
        self.assertEqual(feed.transaction_kind(self.entry([name("A", 1)], {"writable": [], "readonly": [vote]})), "vote")
        self.assertEqual(feed.transaction_kind(self.entry([name("A", 1), name("P", 1)])), "program")
        self.assertEqual(feed.transaction_kind(self.entry([{"pubkey": name("A", 1)}, {"other": vote}])), "program")
        for unreadable in ({}, {"transaction": ["AQID", "base64"], "meta": None}, {"transaction": {"message": None}},
                           {"transaction": {"message": {"accountKeys": "Vote"}}}, None, "text", 7):
            self.assertEqual(feed.transaction_kind(unreadable), "program")

    def test_parse_block_rejects_what_is_not_a_block(self):
        for reply in (None, [], "block", {}, {"blockhash": name("B", 1)}, {"blockhash": 5, "transactions": []},
                      {"blockhash": "<script>", "transactions": []}):
            self.assertIsNone(feed.parse_block(1, reply))
        parsed = feed.parse_block(9, {"blockhash": name("B", 9), "transactions": [
            self.entry([name("A", 1)]), "garbage", {"transaction": {"signatures": ["bad sig!"]}}]})
        self.assertEqual(parsed.row, {"slot": 9, "parent_slot": None, "blockhash": name("B", 9), "block_time": None,
                                      "block_height": None, "tx_count": 3, "non_vote_tx_count": 3})
        self.assertEqual([row["signature"] for row in parsed.program], [signature(1, 0)])

    def test_untrusted_values_are_filtered(self):
        self.assertEqual(feed.as_count(12), 12)
        self.assertEqual(feed.as_count(2 ** 53 - 1), 2 ** 53 - 1)
        for value in (True, -1, 1.5, "3", None, 2 ** 53, 2 ** 63):
            self.assertIsNone(feed.as_count(value))
        self.assertEqual(feed.as_text("Abc123"), "Abc123")
        self.assertEqual(feed.as_text("x" * 127), "x" * 127)
        for value in ("", "a b", "<b>", "x" * 128, "x" * 129, "café", 5, None):
            self.assertIsNone(feed.as_text(value))

    def test_oversized_feed_is_trimmed_below_the_limit(self):
        def big(count):
            return [{"slot": i, "blockhash": "h" * 120} for i in range(count, 0, -1)]
        document = {"network": {"validators": big(3000)}, "transactions": big(3000), "blocks": big(3000)}
        payload = feed.encode_feed(document)
        self.assertLessEqual(len(payload), 400 * 1000)
        trimmed = json.loads(payload)
        self.assertEqual(trimmed["blocks"][0]["slot"], 3000)    # the newest rows survive
        self.assertGreater(len(trimmed["blocks"]), 0)
        self.assertEqual(feed.MAX_FEED_BYTES, 400000)

    def test_signature_is_hmac_sha256_of_the_exact_bytes(self):
        key = bytes(range(32))
        payload = b'{"format":"zolana-explorer-feed-v0"}'
        self.assertEqual(feed.sign_feed(key, payload),
                         hmac.new(key, payload, hashlib.sha256).hexdigest().encode() + b"\n")
        self.assertNotEqual(feed.sign_feed(key, payload), feed.sign_feed(key, payload + b"\n"))


class KeyFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def key_file(self, content, mode):
        self.count = getattr(self, "count", 0) + 1
        path = os.path.join(self.tmp.name, "hmac-%d.key" % self.count)
        with open(path, "wb") as stream:
            stream.write(content)
        os.chmod(path, mode)
        return path

    def test_exact_bytes_are_used_for_owner_only_and_credential_modes(self):
        key = os.urandom(31) + b"\n"        # a trailing newline is part of the key
        for mode in (0o600, 0o400, 0o440):
            self.assertEqual(feed.load_hmac_key(self.key_file(key, mode)), key, oct(mode))
        self.assertEqual(len(feed.load_hmac_key(self.key_file(os.urandom(64), 0o400))), 64)

    def test_refuses_missing_short_or_exposed_keys(self):
        with self.assertRaisesRegex(feed.ConfigError, "cannot be opened"):
            feed.load_hmac_key(os.path.join(self.tmp.name, "absent.key"))
        with self.assertRaisesRegex(feed.ConfigError, "shorter than 32"):
            feed.load_hmac_key(self.key_file(os.urandom(31), 0o600))
        with self.assertRaisesRegex(feed.ConfigError, "shorter than 32"):
            feed.load_hmac_key(self.key_file(b"", 0o600))
        for mode in (0o644, 0o604, 0o444, 0o666, 0o601):
            with self.assertRaisesRegex(feed.ConfigError, "other users", msg=oct(mode)):
                feed.load_hmac_key(self.key_file(os.urandom(32), mode))
        for mode in (0o640, 0o660, 0o460, 0o650):
            with self.assertRaisesRegex(feed.ConfigError, "its group", msg=oct(mode)):
                feed.load_hmac_key(self.key_file(os.urandom(32), mode))
        with self.assertRaisesRegex(feed.ConfigError, "not a regular file"):
            feed.load_hmac_key(self.tmp.name)

    def test_ownership_rules(self):
        regular = stat.S_IFREG
        self.assertIsNone(feed.key_file_problem(regular | 0o400, 1000, 1000))
        self.assertIsNone(feed.key_file_problem(regular | 0o440, 1000, 1000))   # LoadCredential, service user
        self.assertIsNone(feed.key_file_problem(regular | 0o440, 0, 1000))      # LoadCredential, root-owned
        self.assertIsNone(feed.key_file_problem(regular | 0o400, 0, 1000))
        self.assertIsNotNone(feed.key_file_problem(regular | 0o444, 0, 1000))   # world readable
        self.assertIsNotNone(feed.key_file_problem(regular | 0o640, 0, 1000))
        self.assertIsNotNone(feed.key_file_problem(regular | 0o400, 1001, 1000))  # someone else's file
        self.assertIsNotNone(feed.key_file_problem(stat.S_IFIFO | 0o600, 1000, 1000))


class HttpServerTests(unittest.TestCase):
    FEED_A, SIG_A = b'{"format":"zolana-explorer-feed-v0","generated_at":1}', b"a" * 64 + b"\n"
    FEED_B, SIG_B = b'{"format":"zolana-explorer-feed-v0","generated_at":2}', b"b" * 64 + b"\n"

    def setUp(self):
        self.log = io.StringIO()
        feed.log_stream = self.log
        self.addCleanup(setattr, feed, "log_stream", None)
        self.store = feed.PayloadStore()
        self.store.publish(self.FEED_A, self.SIG_A)

    def serve(self, allowed=(), store=None):
        server = feed.FeedHTTPServer(("127.0.0.1", 0), self.store if store is None else store,
                                     [ipaddress.ip_address(ip) for ip in allowed])
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join()
        self.addCleanup(stop)
        return server

    def request(self, server, method, path):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        try:
            connection.request(method, path)
            response = connection.getresponse()
            return response.status, {k.lower(): v for k, v in response.getheaders()}, response.read()
        finally:
            connection.close()

    def test_serves_the_two_payloads(self):
        server = self.serve()
        status, headers, body = self.request(server, "GET", "/feed.json")
        self.assertEqual((status, body), (200, self.FEED_A))
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(headers["content-length"], str(len(self.FEED_A)))
        self.assertNotIn("Python", headers["server"])
        status, headers, body = self.request(server, "GET", "/feed.sig")
        self.assertEqual((status, body), (200, self.SIG_A))
        self.assertEqual(headers["content-type"], "text/plain")
        self.assertEqual(headers["cache-control"], "no-store")

    def test_head_sends_headers_only(self):
        server = self.serve()
        for path, payload in (("/feed.json", self.FEED_A), ("/feed.sig", self.SIG_A)):
            status, headers, body = self.request(server, "HEAD", path)
            self.assertEqual((status, body), (200, b""))
            self.assertEqual(headers["content-length"], str(len(payload)))
            self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(self.request(server, "HEAD", "/nothing")[0], 404)

    def test_every_other_path_is_404(self):
        server = self.serve()
        for path in ("/", "/feed", "/feed.json?x=1", "/feed.json?", "/feed.sig?download", "/feed.json/",
                     "//feed.json", "/../feed.json", "/./feed.json", "/FEED.JSON", "/feed.json#a", "/window.json",
                     "/.feed.json.tmp", "/explorer/feed.json", "/feed.json%00", "http://127.0.0.1/feed.json", "*"):
            status, headers, body = self.request(server, "GET", path)
            self.assertEqual(status, 404, path)
            self.assertEqual(body, b"Not Found\n", path)
            self.assertEqual(headers["cache-control"], "no-store")

    def test_only_get_and_head(self):
        server = self.serve()
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            status, headers, body = self.request(server, method, "/feed.json")
            self.assertEqual(status, 405, method)
            self.assertEqual(headers["allow"], "GET, HEAD")
            self.assertNotIn(b"zolana", body)
        status, _, body = self.request(server, "BREW", "/feed.json")
        self.assertEqual(status, 501)
        self.assertNotIn(b"BREW", body)

    def test_other_client_addresses_get_403(self):
        closed = self.serve(allowed=["192.0.2.10"])
        for method, path in (("GET", "/feed.json"), ("GET", "/feed.sig"), ("HEAD", "/feed.json"),
                             ("GET", "/nothing"), ("POST", "/feed.json")):
            status, _, body = self.request(closed, method, path)
            self.assertEqual(status, 403, (method, path))
            self.assertNotIn(b"zolana", body)
        self.assertEqual(closed.snapshot()["forbidden"], 5)
        opened = self.serve(allowed=["192.0.2.10", "127.0.0.1"])
        self.assertEqual(self.request(opened, "GET", "/feed.json")[::2], (200, self.FEED_A))

    def test_address_matching(self):
        server = self.serve(allowed=["192.0.2.10", "2001:db8::1"])
        self.assertTrue(server.client_allowed("192.0.2.10"))
        self.assertTrue(server.client_allowed("::ffff:192.0.2.10"))     # IPv4 client on a dual-stack socket
        self.assertTrue(server.client_allowed("2001:db8:0::1"))
        for other in ("192.0.2.11", "127.0.0.1", "::1", "not-an-address", ""):
            self.assertFalse(server.client_allowed(other), other)
        self.assertTrue(self.serve().client_allowed("203.0.113.9"))      # no list: everyone

    def test_signature_matches_the_feed_a_client_just_fetched(self):
        server = self.serve()
        self.assertEqual(self.request(server, "GET", "/feed.json")[2], self.FEED_A)
        self.store.publish(self.FEED_B, self.SIG_B)                      # rewritten between the two requests
        self.assertEqual(self.request(server, "GET", "/feed.sig")[2], self.SIG_A)
        self.assertEqual(self.request(server, "GET", "/feed.sig")[2], self.SIG_B)
        self.assertEqual(self.request(server, "GET", "/feed.json")[2], self.FEED_B)
        self.assertEqual(self.request(server, "GET", "/feed.json")[2], self.FEED_B)

    def test_pairing_expires(self):
        clock = FakeClock()
        store = feed.PayloadStore(monotonic=clock)
        store.publish(self.FEED_A, self.SIG_A)
        self.assertEqual(store.fetch("192.0.2.1", 0), self.FEED_A)
        store.publish(self.FEED_B, self.SIG_B)
        self.assertEqual(store.fetch("192.0.2.2", 1), self.SIG_B)        # another client: current data
        clock.advance(feed.PAIR_SECONDS + 0.1)
        self.assertEqual(store.fetch("192.0.2.1", 1), self.SIG_B)        # too late to pair
        for number in range(500):                                        # remembered pairs stay bounded
            store.fetch("198.51.100.%d" % (number % 250), 0)
        self.assertLessEqual(len(store._pairs), feed.MAX_PAIRS)

    def test_nothing_published_yet_is_503(self):
        server = self.serve(store=feed.PayloadStore())
        self.assertEqual(self.request(server, "GET", "/feed.json")[0], 503)
        self.assertEqual(self.request(server, "HEAD", "/feed.sig")[0], 503)

    def test_requests_are_counted_not_logged(self):
        server = self.serve()
        self.request(server, "GET", "/feed.json")
        self.request(server, "GET", "/secret-looking-path")
        self.assertEqual(self.log.getvalue(), "")
        counters = server.snapshot()
        self.assertEqual((counters["requests"], counters["ok"], counters["not_found"]), (2, 1, 1))

    def test_idle_connection_is_dropped_after_two_seconds(self):
        self.assertEqual(feed.FeedRequestHandler.timeout, 2.0)
        server = self.serve()
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=6)
        self.addCleanup(connection.close)
        connection.connect()
        started = time.monotonic()
        self.assertEqual(connection.sock.recv(1), b"")                   # closed by the server, nothing sent
        self.assertLess(time.monotonic() - started, 4.0)

    def raw(self, server, data=b""):
        connection = socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=6)
        self.addCleanup(connection.close)
        connection.sendall(data)
        return connection

    def read_all(self, connection):
        chunks = []
        try:
            while True:
                chunk = connection.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        except ConnectionError:
            pass                                                         # a reset also means: closed
        return b"".join(chunks)

    def wait_for_count(self, server, name, value):
        deadline = time.monotonic() + 5
        while server.snapshot().get(name, 0) != value and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertEqual(server.snapshot().get(name, 0), value, name)

    def test_request_sent_in_pieces_is_served(self):
        server = self.serve()
        connection = self.raw(server, b"GET /feed.json HTT")
        time.sleep(0.2)
        connection.sendall(b"P/1.0\r\nHost: x\r\n")
        time.sleep(0.2)
        connection.sendall(b"\r\n")
        reply = self.read_all(connection)
        self.assertTrue(reply.startswith(b"HTTP/1.0 200 "), reply[:40])
        self.assertTrue(reply.endswith(b"\r\n\r\n" + self.FEED_A))
        bare = self.read_all(self.raw(server, b"GET /feed.sig HTTP/1.0\n\n"))   # bare line feeds
        self.assertTrue(bare.endswith(b"\r\n\r\n" + self.SIG_A), bare[:40])
        self.assertNotIn("aborted", server.snapshot())

    def test_slowly_sent_request_is_cut_off(self):
        self.assertEqual(feed.HTTP_REQUEST_SECONDS, 5.0)
        self.addCleanup(setattr, feed, "HTTP_REQUEST_SECONDS", feed.HTTP_REQUEST_SECONDS)
        feed.HTTP_REQUEST_SECONDS = 1.0
        server = self.serve()
        connection = self.raw(server, b"GET /feed.json HTTP/1.0\r\n")
        started = time.monotonic()
        closed = False
        while time.monotonic() - started < 4.0 and not closed:
            time.sleep(0.25)                                             # well inside the 2 s idle timeout
            try:
                connection.sendall(b"X")
            except OSError:
                closed = True
        self.assertTrue(closed, "a client that keeps trickling bytes must still be cut off")
        self.assertEqual(self.read_all(connection), b"")                 # and it gets no reply
        self.wait_for_count(server, "aborted", 1)

    def test_oversized_request_is_dropped_without_being_buffered(self):
        self.assertEqual(feed.HTTP_MAX_REQUEST_BYTES, 8192)
        server = self.serve()
        connection = self.raw(server)
        try:
            connection.sendall(b"GET /feed.json HTTP/1.0\r\nX-Filler: " + b"a" * 200000)
        except OSError:
            pass                                                         # cut off while still sending
        self.assertEqual(self.read_all(connection), b"")
        self.wait_for_count(server, "aborted", 1)
        self.assertEqual(self.request(server, "GET", "/feed.json")[::2], (200, self.FEED_A))

    def test_other_addresses_cannot_use_up_the_connection_limit(self):
        self.assertEqual((feed.HTTP_MAX_CONNECTIONS, feed.HTTP_MAX_STRANGER_CONNECTIONS), (32, 8))
        server = self.serve(allowed=["192.0.2.10"])                      # 127.0.0.1 is not on the list
        held = [self.raw(server, b"GET /feed.json HTTP/1.0\r\n") for _ in range(8)]
        self.assertEqual(self.read_all(self.raw(server, b"GET /feed.json HTTP/1.0\r\n\r\n")), b"")
        self.wait_for_count(server, "dropped", 1)
        # The allowed address still has every remaining connection to itself.
        for _ in range(24):
            self.assertTrue(server._acquire_slot(False))
        self.assertFalse(server._acquire_slot(False))
        for _ in range(24):
            server._release_slot(False)
        for connection in held:
            connection.sendall(b"\r\n")
            self.assertTrue(self.read_all(connection).startswith(b"HTTP/1.0 403 "))
        self.wait_for_count(server, "forbidden", 8)
        # All slots were handed back: a full set of connections fits again.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            taken = [server._acquire_slot(True) for _ in range(8)]
            for _ in range(sum(taken)):
                server._release_slot(True)
            if all(taken):
                break
            time.sleep(0.02)
        self.assertTrue(all(taken))

    def test_without_an_allowlist_every_client_shares_the_full_limit(self):
        server = self.serve()
        for _ in range(32):
            self.assertTrue(server._acquire_slot(not server.client_allowed("203.0.113.9")))
        self.assertFalse(server._acquire_slot(False))
        for _ in range(32):
            server._release_slot(False)


class ProcessTests(FeedTestCase):
    def launch(self, *arguments):
        process = subprocess.Popen([sys.executable, "-I", "-B", SCRIPT] + list(arguments), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        lines = []
        reader = threading.Thread(target=lambda: lines.extend(iter(process.stderr.readline, "")), daemon=True)
        reader.start()

        def finish():
            if process.poll() is None:
                process.kill()
            process.wait()
            reader.join(5)
            process.stderr.close()
        self.addCleanup(finish)
        return process, lines, reader

    def key_file(self, mode=0o600):
        path = os.path.join(self.tmp.name, "hmac.key")
        with open(path, "wb") as stream:
            stream.write(self.key)
        os.chmod(path, mode)
        return path

    def fetch(self, port, path):
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            connection.request("GET", path)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_runs_serves_and_stops_cleanly_on_sigterm(self):
        self.chain.program_per_block = 1
        self.chain.advance(200)
        state_dir = os.path.join(self.tmp.name, "created-by-service")
        process, lines, reader = self.launch(
            "--rpc-url", self.node.url, "--state-dir", state_dir, "--hmac-key-file", self.key_file(0o400),
            "--listen", "127.0.0.1:0", "--allow-ip", "127.0.0.1", "--poll-seconds", "0.2")
        deadline = time.monotonic() + 20
        port = None
        while port is None and time.monotonic() < deadline and process.poll() is None:
            for line in list(lines):
                found = re.search(r" started .* port=(\d+)", line)
                if found:
                    port = int(found.group(1))
            time.sleep(0.05)
        self.assertIsNotNone(port, "".join(lines))

        document = None
        while time.monotonic() < deadline:
            self.chain.advance(2)
            status, payload = self.fetch(port, "/feed.json")
            self.assertEqual(status, 200)
            sig_status, sig = self.fetch(port, "/feed.sig")
            self.assertEqual(sig_status, 200)
            self.assertEqual(sig.decode().strip(), hmac.new(self.key, payload, hashlib.sha256).hexdigest())
            document = json.loads(payload)
            if document["network"]["status"] == "live" and len(document["blocks"]) >= 60:
                break
            time.sleep(0.1)
        self.assertEqual(document["network"]["status"], "live")
        self.assertGreaterEqual(len(document["blocks"]), 60)
        self.assertEqual(document["genesis_hash"], self.chain.genesis)
        self.assertEqual(self.fetch(port, "/window.json")[0], 404)

        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=20), 0)
        reader.join(5)
        output = "".join(lines)
        self.assertIn(" stopped ", output)
        self.assertEqual(sorted(os.listdir(state_dir)), ["feed.json", "feed.sig", "window.json"])
        saved = {}
        for filename in os.listdir(state_dir):
            with open(os.path.join(state_dir, filename), "rb") as stream:
                saved[filename] = stream.read()
        self.assertEqual(saved["feed.sig"].decode().strip(),
                         hmac.new(self.key, saved["feed.json"], hashlib.sha256).hexdigest())
        self.assertEqual(len(json.loads(saved["window.json"])["blocks"]), len(json.loads(saved["feed.json"])["blocks"]))
        for secret in (self.key.hex(), repr(self.key), "hmac.key"):
            self.assertNotIn(secret, output)
        self.assertNotIn("GET /", output)
        self.assertNotIn("Traceback", output)
        self.assertLessEqual({method for method, _ in self.chain.calls}, ALLOWED_METHODS)
        self.assertEqual(set(self.chain.http_requests), {("POST", "/")})

    def refused(self, *arguments):
        process, lines, reader = self.launch("--rpc-url", self.node.url, "--state-dir", self.state_dir,
                                             "--listen", "127.0.0.1:0", *arguments)
        self.assertEqual(process.wait(timeout=20), 2)
        reader.join(5)
        output = "".join(lines)
        self.assertIn("refusing-to-start", output)
        self.assertEqual(os.listdir(self.state_dir), [])
        self.assertEqual(self.chain.http_requests, [])
        return output

    def test_refuses_to_start_without_a_usable_key(self):
        self.assertIn("cannot be opened", self.refused("--hmac-key-file", os.path.join(self.tmp.name, "absent")))
        self.assertIn("other users", self.refused("--hmac-key-file", self.key_file(0o644)))
        self.assertIn("its group", self.refused("--hmac-key-file", self.key_file(0o640)))
        short = os.path.join(self.tmp.name, "short.key")
        with open(short, "wb") as stream:
            stream.write(b"k" * 31)
        os.chmod(short, 0o600)
        self.assertIn("shorter than 32", self.refused("--hmac-key-file", short))

    def test_refuses_an_unsubstituted_allow_ip_placeholder(self):
        output = self.refused("--hmac-key-file", self.key_file(), "--allow-ip", "ALLOW_IP")
        self.assertIn("--allow-ip", output)

    def test_key_file_flag_is_required(self):
        process, lines, reader = self.launch("--rpc-url", self.node.url, "--state-dir", self.state_dir)
        self.assertEqual(process.wait(timeout=20), 2)
        reader.join(5)
        self.assertIn("--hmac-key-file", "".join(lines))


class UnitFileTests(unittest.TestCase):
    def setUp(self):
        with open(UNIT, "r", encoding="utf-8") as stream:
            text = stream.read()
        self.text = text
        joined = text.replace("\\\n", " ")
        self.settings = {}
        for line in joined.splitlines():
            if "=" in line and not line.lstrip().startswith(("#", ";")):
                key, _, value = line.partition("=")
                self.settings.setdefault(key.strip(), []).append(" ".join(value.split()))

    def test_required_settings(self):
        expected = {
            "DynamicUser": "yes", "StateDirectory": "zolana-explorer-feed-v0", "NoNewPrivileges": "yes",
            "LoadCredential": "hmac:/etc/zolana-explorer-feed-v0/hmac.key", "ProtectSystem": "strict",
            "ProtectHome": "yes", "PrivateTmp": "yes", "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
            "MemoryMax": "128M", "CPUQuota": "20%", "Restart": "always", "RestartSec": "3",
        }
        for key, value in expected.items():
            self.assertEqual(self.settings.get(key), [value], key)

    def test_command_line(self):
        (command,) = self.settings["ExecStart"]
        self.assertTrue(command.startswith(
            "/usr/bin/python3 -I -B /opt/zolana-explorer-feed-v0/explorer_feed_v0.py "), command)
        self.assertIn("--hmac-key-file %d/hmac", command)
        self.assertIn("--allow-ip ALLOW_IP", command)
        self.assertEqual(self.text.count("--allow-ip ALLOW_IP"), 1)
        arguments = feed.build_parser().parse_args(command.replace("%d/hmac", "/run/credentials/hmac").split()[4:])
        self.assertEqual(arguments.state_dir, "/var/lib/zolana-explorer-feed-v0")
        self.assertEqual(arguments.listen, "0.0.0.0:18080")
        self.assertEqual(arguments.allow_ip, ["ALLOW_IP"])

    def test_unit_name_and_write_scope(self):
        self.assertFalse(os.path.basename(UNIT).startswith("zolana-invited-pilot-20261113-"))
        for key in ("ReadWritePaths", "LogsDirectory", "CacheDirectory", "RuntimeDirectory", "ConfigurationDirectory"):
            self.assertNotIn(key, self.settings)


class CommandLineTests(unittest.TestCase):
    def test_defaults(self):
        arguments = feed.build_parser().parse_args(["--hmac-key-file", "/k"])
        self.assertEqual(arguments.rpc_url, "http://127.0.0.1:49643")
        self.assertEqual(arguments.state_dir, "/var/lib/zolana-explorer-feed-v0")
        self.assertEqual(arguments.listen, "0.0.0.0:18080")
        self.assertEqual(arguments.allow_ip, [])
        self.assertEqual(arguments.poll_seconds, 2.0)
        self.assertEqual(arguments.max_blocks_per_cycle, 30)

    def test_listen_and_allow_ip_parsing(self):
        self.assertEqual(feed.parse_listen("0.0.0.0:18080"), ("0.0.0.0", 18080))
        self.assertEqual(feed.parse_listen("[::]:18080"), ("::", 18080))
        for value in ("18080", "localhost:18080", "0.0.0.0:99999", "0.0.0.0:", ":18080", "0.0.0.0:http"):
            with self.assertRaises(feed.ConfigError, msg=value):
                feed.parse_listen(value)
        self.assertEqual(feed.parse_allowed(["192.0.2.10", "2001:db8::1"]),
                         {ipaddress.ip_address("192.0.2.10"), ipaddress.ip_address("2001:db8::1")})
        for value in ("ALLOW_IP", "192.0.2.0/24", "example.org", ""):
            with self.assertRaises(feed.ConfigError, msg=value):
                feed.parse_allowed([value])


if __name__ == "__main__":
    unittest.main()
