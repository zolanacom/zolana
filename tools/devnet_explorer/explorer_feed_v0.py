#!/usr/bin/python3
"""Chain-side feed service for the Zolana devnet explorer (feed format v0).

One process that

  * polls a Solana-compatible JSON-RPC endpoint, read-only and limited to a
    fixed method allowlist, and keeps a rolling in-memory window of recent
    blocks and transactions;
  * writes feed.json and feed.sig (HMAC-SHA256 over the exact feed.json bytes)
    atomically into a state directory;
  * serves exactly GET/HEAD /feed.json and /feed.sig over plain HTTP from a
    background thread, always from memory.

The feed marks which transactions invoke the native payment program and names
the instructions they carry (see payment_instructions). It reads the first
byte of an instruction's data and nothing after it.

Standard library only.
"""

import argparse
import collections
import hashlib
import hmac
import http
import http.client
import http.server
import io
import ipaddress
import json
import os
import signal
import socket
import socketserver
import stat
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request

FEED_FORMAT = "zolana-explorer-feed-v0"
WINDOW_FORMAT = "zolana-explorer-window-v0"
VOTE_PROGRAM = "Vote111111111111111111111111111111111111111"

# The only JSON-RPC methods this service may ever send. All are read-only.
RPC_ALLOWLIST = frozenset((
    "getGenesisHash", "getSlot", "getBlockHeight", "getBlocks", "getBlock",
    "getVoteAccounts", "getHealth",
))
RPC_TIMEOUT_SECONDS = 4.0
RPC_MAX_RESPONSE_BYTES = 4 * 1024 * 1024

MAX_BLOCKS = 120                # blocks published, newest first
MAX_TRANSACTIONS = 200          # transactions published, newest first
VOTE_FILL_TARGET = 20           # votes are listed only while fewer non-vote rows exist
MAX_VALIDATORS = 64
MAX_FEED_BYTES = 400 * 1000
MAX_TEXT = 127                  # longest hash, signature or address accepted from the node;
                                # the web-side puller refuses a feed holding a longer string
MAX_COUNT = 2 ** 53             # integers must stay below this; the puller and the page refuse larger ones

LIVE_SECONDS = 15               # "live" needs a successful poll within this many seconds
START_BACKLOG_SLOTS = 120       # first start and gap recovery begin this far behind the tip
MAX_LAG_SLOTS = 500             # further behind than this: jump forward instead of catching up
PERSIST_SECONDS = 10            # window.json is rewritten at most this often
HEALTH_POLL_SECONDS = 10        # how often getHealth is asked (process log only)
GENESIS_RECHECK_SECONDS = 60
GENESIS_ERROR_LIMIT = 3
BLOCK_REPROBE_SECONDS = 60      # how often to look again for block support on a node without it
PENDING_RETRIES = 3             # attempts at a listed block the node cannot return yet
CYCLE_BUDGET_SECONDS = 6.0      # stop fetching blocks in a cycle that has run this long
SLOT_TIME_WINDOW_SECONDS = 60.0
SLOT_TIME_MIN_SECONDS = 4.0
SUMMARY_SECONDS = 60

HTTP_SOCKET_TIMEOUT_SECONDS = 2.0
HTTP_REQUEST_SECONDS = 5.0      # a request line and its headers must arrive within this long
HTTP_MAX_REQUEST_BYTES = 8192   # ... and be no larger than this
HTTP_MAX_CONNECTIONS = 32
HTTP_MAX_STRANGER_CONNECTIONS = 8   # of those, for addresses that are not on the allowlist
HTTP_SEND_BUFFER_BYTES = 512 * 1024
PAIR_SECONDS = 3.0              # a client's /feed.json and /feed.sig come from one snapshot
MAX_PAIRS = 64

MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 4096
MAX_WINDOW_BYTES = 2 * 1024 * 1024

SKIPPED_SLOT_CODES = frozenset((-32001, -32007, -32009))
PENDING_BLOCK_CODES = frozenset((-32004, -32014))

TRANSACTION_FIELDS = ("signature", "slot", "block_time", "ok", "fee", "kind", "payment_instructions")
STAT_FIELDS = ("since", "blocks_seen", "transactions_seen", "non_vote_transactions_seen")
# Counted from payments_since on, which is later than "since" in a window that
# was saved before payments were counted.
PAYMENT_STAT_FIELDS = ("payments_since", "payment_transactions_seen", "executed_payments_seen")

# The native payment program (PROGRAM_ID in protocol/payments/src/native_accounts.rs).
# It is a built-in of the validator at the same address on every network.
PAYMENT_PROGRAM = "78kCqctsuUaj7kyV8xNVwXQrqovY3QtSytt4eCYApVUh"
# Its instructions, by the first byte of the instruction data (docs/protocol-spec.md,
# section 13.3). Any other first byte, or no data, is listed as "unknown".
PAYMENT_INSTRUCTIONS = ("initialize", "write", "seal", "finalize", "close", "inline")
UNKNOWN_INSTRUCTION = "unknown"
PAYMENT_INSTRUCTION_ORDER = PAYMENT_INSTRUCTIONS + (UNKNOWN_INSTRUCTION,)
# The two instructions that execute a payment; the others stage its bytes or
# return the rent of a staging account.
EXECUTING_INSTRUCTIONS = frozenset(("finalize", "inline"))
MAX_INSTRUCTION_TEXT = 24000    # longest base58 instruction data read: above the largest inline frame
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_DIGITS = {character: digit for digit, character in enumerate(BASE58_ALPHABET)}

BlockVariant = collections.namedtuple("BlockVariant", "details commitment")
# getBlock request shapes in order of preference; the first one that works is remembered.
BLOCK_VARIANTS = (
    BlockVariant("full", "finalized"),
    BlockVariant("full", "confirmed"),
    BlockVariant("signatures", "finalized"),
    BlockVariant("signatures", "confirmed"),
)
ParsedBlock = collections.namedtuple("ParsedBlock", "row program votes")

SKIPPED = object()
PENDING = object()


class ConfigError(Exception):
    """The service was started with settings it must refuse."""


class RpcMethodNotAllowed(ValueError):
    """A method outside RPC_ALLOWLIST was requested."""


class RpcUnavailable(Exception):
    """The node gave no usable JSON-RPC reply (refused, timed out, garbled)."""


class RpcResponseError(Exception):
    """The node answered, but with a JSON-RPC error for this request."""

    def __init__(self, method, code, message):
        super().__init__("%s failed with code %s" % (method, code))
        self.method = method
        self.code = code
        self.message = message


class BlockDataUnsupported(Exception):
    """The node offers no usable getBlocks or getBlock."""


# --------------------------------------------------------------------------
# Logging: one line per event on stderr. Key material is never passed in.

log_stream = None
_log_lock = threading.Lock()


def _log_text(value):
    text = "".join(ch if 32 <= ord(ch) < 127 and ch != '"' else "_" for ch in str(value))[:160]
    return '"%s"' % text if " " in text or not text else text


def log(event, **fields):
    parts = [time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), event]
    parts.extend("%s=%s" % (name, _log_text(value)) for name, value in fields.items())
    with _log_lock:
        stream = log_stream if log_stream is not None else sys.stderr
        try:
            stream.write(" ".join(parts) + "\n")
            stream.flush()
        except (OSError, ValueError):
            pass


# --------------------------------------------------------------------------
# Values taken from the node are validated before they reach the feed.

def as_count(value):
    """A non-negative integer, or None."""
    if type(value) is int and 0 <= value < MAX_COUNT:
        return value
    return None


def as_text(value):
    """A short ASCII alphanumeric string (hash, signature, address), or None."""
    if isinstance(value, str) and 0 < len(value) <= MAX_TEXT and value.isascii() and value.isalnum():
        return value
    return None


# --------------------------------------------------------------------------
# JSON-RPC client

def normalize_rpc_url(url):
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        raise ConfigError("--rpc-url is not a valid URL") from None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ConfigError("--rpc-url must be an http or https URL")
    if parts.username is not None or parts.password is not None:
        raise ConfigError("--rpc-url must not contain credentials")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ConfigError('--rpc-url must not carry a path, query or fragment; requests go to "/"')
    host = "[%s]" % parts.hostname if ":" in parts.hostname else parts.hostname
    return "%s://%s%s/" % (parts.scheme, host, "" if port is None else ":%d" % port)


def _read_bounded(response, deadline):
    chunks = []
    size = 0
    while True:
        chunk = response.read(65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > RPC_MAX_RESPONSE_BYTES:
            return None
        if time.monotonic() > deadline:
            raise RpcUnavailable("reply took too long")
        chunks.append(chunk)


class RpcClient:
    """JSON-RPC over HTTP POST to "/". `call` is the only place a request is built."""

    def __init__(self, url, timeout=RPC_TIMEOUT_SECONDS):
        self.url = normalize_rpc_url(url)
        self.timeout = timeout
        # A bare opener: no proxy lookup, no redirects, no non-HTTP schemes.
        self._opener = urllib.request.OpenerDirector()
        self._opener.add_handler(urllib.request.HTTPHandler())
        if hasattr(urllib.request, "HTTPSHandler"):
            self._opener.add_handler(urllib.request.HTTPSHandler())

    def call(self, method, params=()):
        """Send one allowlisted request and return its result.

        Raises RpcMethodNotAllowed before anything is sent for any method that
        is not on RPC_ALLOWLIST, RpcResponseError when the node answers with a
        JSON-RPC error, and RpcUnavailable when there is no usable answer.
        """
        if method not in RPC_ALLOWLIST:
            raise RpcMethodNotAllowed("RPC method is not on the read-only allowlist: %r" % (method,))
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": list(params)},
                          separators=(",", ":")).encode("ascii")
        request = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "zolana-explorer-feed/0",
        })
        deadline = time.monotonic() + 2 * self.timeout
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status = response.status
                raw = _read_bounded(response, deadline)
        except (OSError, http.client.HTTPException) as exc:
            reason = getattr(exc, "reason", exc)
            raise RpcUnavailable(type(reason).__name__ if isinstance(reason, BaseException) else str(reason)) from None
        if raw is None:
            raise RpcResponseError(method, None, "reply larger than %d bytes" % RPC_MAX_RESPONSE_BYTES)
        try:
            reply = json.loads(raw)
        except (ValueError, RecursionError):
            reply = None
        if not isinstance(reply, dict):
            raise RpcUnavailable("HTTP %d without a JSON-RPC reply" % status)
        error = reply.get("error")
        if error is not None:
            code = error.get("code") if isinstance(error, dict) else None
            message = error.get("message") if isinstance(error, dict) else error
            raise RpcResponseError(method, code if type(code) is int else None, str(message)[:200])
        if "result" not in reply:
            raise RpcUnavailable("HTTP %d reply without a result" % status)
        return reply["result"]


# --------------------------------------------------------------------------
# Blocks and transactions

def block_config(variant):
    return {"encoding": "json", "transactionDetails": variant.details, "rewards": False,
            "maxSupportedTransactionVersion": 0, "commitment": variant.commitment}


def is_skipped_slot(error):
    return error.code in SKIPPED_SLOT_CODES or "skipped" in error.message.lower()


def _meta(entry):
    meta = entry.get("meta") if isinstance(entry, dict) else None
    return meta if isinstance(meta, dict) else {}


def _message(entry):
    transaction = entry.get("transaction") if isinstance(entry, dict) else None
    message = transaction.get("message") if isinstance(transaction, dict) else None
    return message if isinstance(message, dict) else None


def account_key_table(entry):
    """The account addresses of a getBlock transaction entry by index.

    The message's own keys come first, then the addresses loaded from lookup
    tables, writable before read-only: the order an instruction's program
    index counts in. A key that cannot be read is None, so later ones keep
    their index.
    """
    table = []
    message = _message(entry)
    keys = message.get("accountKeys") if message is not None else None
    for key in keys if isinstance(keys, list) else ():
        if isinstance(key, str):
            table.append(key)
        elif isinstance(key, dict) and isinstance(key.get("pubkey"), str):
            table.append(key["pubkey"])
        else:
            table.append(None)
    loaded = _meta(entry).get("loadedAddresses")
    if isinstance(loaded, dict):
        for group in ("writable", "readonly"):
            addresses = loaded.get(group)
            for key in addresses if isinstance(addresses, list) else ():
                table.append(key if isinstance(key, str) else None)
    return table


def account_keys(entry):
    """Yield every account address a getBlock transaction entry names."""
    for key in account_key_table(entry):
        if key is not None:
            yield key


def transaction_kind(entry):
    """"vote" if any account key is the vote program, otherwise "program".

    Entries without readable account keys are classified as "program".
    """
    for key in account_keys(entry):
        if key == VOTE_PROGRAM:
            return "vote"
    return "program"


def first_data_byte(data):
    """The first byte of base58-encoded instruction data, or None if it cannot be read.

    The whole text has to be decoded to find that byte; nothing else of the
    result is kept or returned.
    """
    if not isinstance(data, str) or not 0 < len(data) <= MAX_INSTRUCTION_TEXT:
        return None
    number = 0
    for start in range(0, len(data), 10):
        part = 0
        for character in data[start:start + 10]:
            digit = BASE58_DIGITS.get(character)
            if digit is None:
                return None
            part = part * 58 + digit
        number = number * 58 ** len(data[start:start + 10]) + part
    if data[0] == "1":
        return 0                    # each leading "1" stands for one leading zero byte
    return number >> (8 * ((number.bit_length() - 1) // 8))


def payment_instructions(entry):
    """Names of the payment-program instructions a getBlock transaction entry carries.

    Only the top level of the transaction is read: the program refuses to be
    invoked by another program. Each name appears once, in the order of
    PAYMENT_INSTRUCTION_ORDER. The list is empty when the entry carries no such
    instruction or its instructions cannot be read.

    This is what the ledger shows to anyone who reads the block: the program
    an instruction is addressed to and the first byte of its data. Nothing
    after that byte is looked at, so no amount, account, nullifier, note
    commitment or ciphertext reaches the feed from here.
    """
    message = _message(entry)
    instructions = message.get("instructions") if message is not None else None
    if not isinstance(instructions, list):
        return []
    table = account_key_table(entry)
    found = set()
    for instruction in instructions:
        if not isinstance(instruction, dict):
            continue
        program = instruction.get("programId")
        if not isinstance(program, str):
            index = instruction.get("programIdIndex")
            program = table[index] if type(index) is int and 0 <= index < len(table) else None
        if program != PAYMENT_PROGRAM:
            continue
        opcode = first_data_byte(instruction.get("data"))
        known = opcode is not None and opcode < len(PAYMENT_INSTRUCTIONS)
        found.add(PAYMENT_INSTRUCTIONS[opcode] if known else UNKNOWN_INSTRUCTION)
    return [name for name in PAYMENT_INSTRUCTION_ORDER if name in found]


def executes_payment(instructions, ok):
    """True for a transaction that succeeded and carries a finalize or inline instruction."""
    return bool(ok) and any(name in EXECUTING_INSTRUCTIONS for name in instructions or ())


def _transaction_row(entry, slot, block_time, position, kind, instructions):
    transaction = entry.get("transaction") if isinstance(entry, dict) else None
    signatures = transaction.get("signatures") if isinstance(transaction, dict) else None
    signature = as_text(signatures[0]) if isinstance(signatures, list) and signatures else None
    if signature is None:
        return None
    meta = _meta(entry)
    return {"signature": signature, "slot": slot, "block_time": block_time,
            "ok": meta.get("err") is None, "fee": as_count(meta.get("fee")) or 0,
            "kind": kind, "payment_instructions": instructions, "position": position}


def parse_block(slot, data):
    """Turn a getBlock result into a feed block row and its listable transactions.

    Accepts both the "full" shape (a "transactions" list) and the "signatures"
    shape. Returns None when the reply does not look like a block.

    The payment counts of a block cover every transaction in it, listed or
    not. In the "signatures" shape they are None, and so is the
    payment_instructions of each of its transactions: not known.
    """
    if not isinstance(data, dict):
        return None
    blockhash = as_text(data.get("blockhash"))
    if blockhash is None:
        return None
    block_time = as_count(data.get("blockTime"))
    program = collections.deque(maxlen=MAX_TRANSACTIONS)
    votes = collections.deque(maxlen=VOTE_FILL_TARGET)
    entries = data.get("transactions")
    signatures = data.get("signatures")
    if isinstance(entries, list):
        tx_count = len(entries)
        non_vote = payment = executed = 0
        for position, entry in enumerate(entries):
            kind = transaction_kind(entry)
            if kind != "vote":
                non_vote += 1
            instructions = payment_instructions(entry)
            if instructions:
                payment += 1
                # The same "ok" as the transaction's row: no error recorded.
                if executes_payment(instructions, _meta(entry).get("err") is None):
                    executed += 1
            row = _transaction_row(entry, slot, block_time, position, kind, instructions)
            if row is not None:
                (votes if kind == "vote" else program).append(row)
    elif isinstance(signatures, list):
        # No account keys and no execution metadata in this shape: every
        # transaction is listed as "program" with no error and no fee reported.
        tx_count = non_vote = len(signatures)
        payment = executed = None
        for position, signature in enumerate(signatures):
            signature = as_text(signature)
            if signature is not None:
                program.append({"signature": signature, "slot": slot, "block_time": block_time,
                                "ok": True, "fee": 0, "kind": "program", "payment_instructions": None,
                                "position": position})
    else:
        return None
    row = {"slot": slot, "parent_slot": as_count(data.get("parentSlot")), "blockhash": blockhash,
           "block_time": block_time, "block_height": as_count(data.get("blockHeight")),
           "tx_count": tx_count, "non_vote_tx_count": non_vote,
           "payment_tx_count": payment, "executed_payment_count": executed}
    return ParsedBlock(row, list(program), list(votes))


def parse_validators(result):
    rows = []
    if not isinstance(result, dict):
        return rows
    for group, active in (("current", True), ("delinquent", False)):
        entries = result.get(group)
        for entry in entries if isinstance(entries, list) else ():
            identity = as_text(entry.get("nodePubkey")) if isinstance(entry, dict) else None
            if identity is not None:
                rows.append({"identity": identity, "vote_account": as_text(entry.get("votePubkey")),
                             "last_vote": as_count(entry.get("lastVote")),
                             "root_slot": as_count(entry.get("rootSlot")), "active": active})
    rows.sort(key=lambda row: (not row["active"], row["identity"]))
    return rows[:MAX_VALIDATORS]


def select_transactions(program, votes):
    """Newest first; votes only top the list up while fewer than 20 non-vote rows exist."""
    listed = list(program)[-MAX_TRANSACTIONS:]
    if len(listed) < VOTE_FILL_TARGET:
        listed.extend(list(votes)[len(listed) - VOTE_FILL_TARGET:])
    listed.sort(key=lambda row: (row["slot"], row["position"]), reverse=True)
    return [{name: row[name] for name in TRANSACTION_FIELDS} for row in listed]


# --------------------------------------------------------------------------
# Feed encoding, signing and files

def encode_feed(feed):
    """Compact JSON bytes of at most MAX_FEED_BYTES, dropping the oldest rows if needed."""
    while True:
        payload = json.dumps(feed, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(payload) <= MAX_FEED_BYTES:
            return payload
        for rows in (feed["network"]["validators"], feed["transactions"], feed["blocks"]):
            if rows:
                del rows[len(rows) // 2:]
                break
        else:
            raise ValueError("feed cannot be reduced below the size limit")


def sign_feed(key, payload):
    """feed.sig content: lowercase hex HMAC-SHA256 of the feed bytes, one line."""
    return hmac.new(key, payload, hashlib.sha256).hexdigest().encode("ascii") + b"\n"


def write_atomic(path, data, mode, durable=False):
    """Replace `path` with `data` through a temporary file in the same directory."""
    directory, name = os.path.split(path)
    temporary = os.path.join(directory, "." + name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        with open(os.open(temporary, flags, mode), "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def read_bounded_file(path, limit):
    with open(path, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("file is larger than %d bytes" % limit)
    return data


def key_file_problem(mode, owner, euid):
    """Say why a key file's type, owner or mode is unacceptable, or return None.

    Accepted: access for the owner only (0400, 0600), or a read-only file that
    also grants group read (0440), which is how systemd can present a
    LoadCredential file. The owner must be the running user or root. Any
    access for other users is refused.
    """
    if not stat.S_ISREG(mode):
        return "is not a regular file"
    permissions = stat.S_IMODE(mode)
    if owner not in (0, euid):
        return "is owned by another user"
    if permissions & 0o007:
        return "is accessible to other users"
    if permissions & 0o070 and permissions != 0o440:
        return "is accessible to its group"
    return None


def load_hmac_key(path):
    """Read the shared key: the exact bytes of the file, nothing trimmed or decoded."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise ConfigError("HMAC key file cannot be opened (%s)" % (exc.strerror or "error")) from None
    try:
        info = os.fstat(descriptor)
        problem = key_file_problem(info.st_mode, info.st_uid, os.geteuid())
        if problem is not None:
            raise ConfigError("HMAC key file " + problem)
        key = b""
        while len(key) <= MAX_KEY_BYTES:
            chunk = os.read(descriptor, MAX_KEY_BYTES + 1 - len(key))
            if not chunk:
                break
            key += chunk
    except OSError as exc:
        raise ConfigError("HMAC key file cannot be read (%s)" % (exc.strerror or "error")) from None
    finally:
        os.close(descriptor)
    if len(key) < MIN_KEY_BYTES:
        raise ConfigError("HMAC key file is shorter than %d bytes" % MIN_KEY_BYTES)
    if len(key) > MAX_KEY_BYTES:
        raise ConfigError("HMAC key file is longer than %d bytes" % MAX_KEY_BYTES)
    return key


# --------------------------------------------------------------------------
# The two payloads the HTTP server may hand out

class PayloadStore:
    """Holds the current (feed.json, feed.sig) bytes.

    The two are fetched with separate requests while the feed is rewritten
    every poll, so a client's second request, if it follows within
    PAIR_SECONDS and asks for the other half, is answered from the same
    snapshot as its first. A puller therefore never sees a signature that
    belongs to a newer feed than the one it just downloaded.
    """

    def __init__(self, monotonic=time.monotonic):
        self._lock = threading.Lock()
        self._monotonic = monotonic
        self._current = None
        self._pairs = collections.OrderedDict()

    def publish(self, feed, signature):
        with self._lock:
            self._current = (feed, signature)

    def current(self):
        with self._lock:
            return self._current

    def fetch(self, client, index):
        """Payload `index` (0 feed.json, 1 feed.sig) for `client`, or None before the first publish."""
        now = self._monotonic()
        with self._lock:
            if self._current is None:
                return None
            pair = self._pairs.pop(client, None)
            if pair is not None and pair[1] != index and now - pair[0] <= PAIR_SECONDS:
                return pair[2][index]
            for stale in [key for key, value in self._pairs.items() if now - value[0] > PAIR_SECONDS]:
                del self._pairs[stale]
            while len(self._pairs) >= MAX_PAIRS:
                self._pairs.popitem(last=False)
            self._pairs[client] = (now, index, self._current)
            return self._current[index]


# --------------------------------------------------------------------------
# Poller

class FeedPoller:
    """Polls the node, maintains the rolling window and publishes the feed."""

    def __init__(self, rpc, state_dir, key, max_blocks_per_cycle=30,
                 clock=time.time, monotonic=time.monotonic):
        self.rpc = rpc
        self.key = key
        self.max_blocks_per_cycle = max_blocks_per_cycle
        self.clock = clock
        self.monotonic = monotonic
        self.feed_path = os.path.join(state_dir, "feed.json")
        self.sig_path = os.path.join(state_dir, "feed.sig")
        self.window_path = os.path.join(state_dir, "window.json")
        self.store = PayloadStore()
        self.stopping = threading.Event()

        self.genesis_hash = None
        self.genesis_known = False      # a hash (or its absence) has been recorded
        self.genesis_checked = False    # ... and confirmed against the node since the last outage
        self.genesis_recheck_at = 0.0
        self.genesis_errors = 0
        self.block_variant = None
        self.blocks_unsupported_until = None
        self.blocks_unsupported_logged = False
        self.pending_slot = None
        self.pending_tries = 0
        self.gaps = 0
        self.health = None
        self.health_poll_at = None
        self.samples = collections.deque(maxlen=128)
        self.last_ok = None
        self.failing = False
        self.fetch_failing = False
        self.disk_failing = False
        self.published_status = None
        self.dirty = False
        self.saved_at = None
        self._start_clean(self.clock())

    # -- window state ------------------------------------------------------

    def _start_clean(self, now):
        self.blocks = collections.deque(maxlen=MAX_BLOCKS)                 # oldest first
        self.program_txs = collections.deque(maxlen=MAX_TRANSACTIONS)      # oldest first
        self.vote_txs = collections.deque(maxlen=VOTE_FILL_TARGET)         # oldest first
        self.stats = {"since": int(now), "blocks_seen": 0, "transactions_seen": 0,
                      "non_vote_transactions_seen": 0, "payments_since": int(now),
                      "payment_transactions_seen": 0, "executed_payments_seen": 0}
        self.network = {"tip_slot": None, "finalized_slot": None, "block_height": None,
                        "slot_time_ms": None, "last_block_at": None, "validators": []}
        self.next_slot = None
        self.samples.clear()
        self.dirty = True

    def _drop_blocks(self):
        self.blocks.clear()
        self.program_txs.clear()
        self.vote_txs.clear()
        self.next_slot = None
        self.samples.clear()

    def _add_block(self, parsed):
        row = parsed.row
        if self.blocks and row["slot"] <= self.blocks[-1]["slot"]:
            return
        self.blocks.append(row)
        self.program_txs.extend(parsed.program)
        self.vote_txs.extend(parsed.votes)
        self.stats["blocks_seen"] += 1
        self.stats["transactions_seen"] += row["tx_count"]
        self.stats["non_vote_transactions_seen"] += row["non_vote_tx_count"]
        if row["payment_tx_count"] is not None:
            self.stats["payment_transactions_seen"] += row["payment_tx_count"]
            self.stats["executed_payments_seen"] += row["executed_payment_count"]

    # -- start and stop ----------------------------------------------------

    def start(self):
        """Reload the saved window and make the first payload available."""
        now = self.clock()
        loaded = self._load_window(now)
        if loaded and self._adopt_published_feed():
            log("feed-kept", blocks=len(self.blocks))
        else:
            self._publish("unavailable", now)

    def close(self):
        self._save_window(self.monotonic(), force=True)

    def _load_window(self, now):
        try:
            raw = read_bounded_file(self.window_path, MAX_WINDOW_BYTES)
        except FileNotFoundError:
            return False
        except (OSError, ValueError) as exc:
            log("window-ignored", reason=type(exc).__name__)
            return False
        try:
            self._restore(json.loads(raw), now)
        except (ValueError, TypeError, KeyError, RecursionError):
            log("window-ignored", reason="not a valid window file")
            self._start_clean(now)
            return False
        self.dirty = False
        log("window-loaded", blocks=len(self.blocks), genesis=self.genesis_hash)
        return True

    def _restore(self, data, now):
        if not isinstance(data, dict) or data.get("format") != WINDOW_FORMAT:
            raise ValueError("unknown window format")
        genesis = data["genesis_hash"]
        if genesis is not None and as_text(genesis) is None:
            raise ValueError("bad genesis hash")
        blocks = [_restore_block(row) for row in data["blocks"]][-MAX_BLOCKS:]
        slots = [row["slot"] for row in blocks]
        if slots != sorted(set(slots)):
            raise ValueError("blocks out of order")
        program = [_restore_transaction(row) for row in data["transactions"]][-MAX_TRANSACTIONS:]
        votes = [_restore_transaction(row) for row in data["votes"]][-VOTE_FILL_TARGET:]
        stats = {name: as_count(data["stats"][name]) for name in STAT_FIELDS}
        if any(name in data["stats"] for name in PAYMENT_STAT_FIELDS):
            stats.update((name, as_count(data["stats"][name])) for name in PAYMENT_STAT_FIELDS)
        else:
            # Saved before payments were counted: the counters start now, and the
            # saved blocks and transactions stay marked "not known".
            stats.update(payments_since=int(now), payment_transactions_seen=0, executed_payments_seen=0)
        if None in stats.values() or stats["executed_payments_seen"] > stats["payment_transactions_seen"]:
            raise ValueError("bad stats")
        saved = data["network"]
        slot_time = saved["slot_time_ms"]
        if slot_time is not None and (type(slot_time) not in (int, float) or not 0 < slot_time < 1e9):
            raise ValueError("bad slot time")
        network = {"tip_slot": as_count(saved["tip_slot"]), "finalized_slot": as_count(saved["finalized_slot"]),
                   "block_height": as_count(saved["block_height"]), "slot_time_ms": slot_time,
                   "last_block_at": as_count(saved["last_block_at"]),
                   "validators": [_restore_validator(row) for row in saved["validators"]][:MAX_VALIDATORS]}
        next_slot = as_count(data["next_slot"])
        if next_slot is None and blocks:
            next_slot = blocks[-1]["slot"] + 1

        self.blocks = collections.deque(blocks, maxlen=MAX_BLOCKS)
        self.program_txs = collections.deque(program, maxlen=MAX_TRANSACTIONS)
        self.vote_txs = collections.deque(votes, maxlen=VOTE_FILL_TARGET)
        self.stats = stats
        self.network = network
        self.next_slot = next_slot
        self.genesis_hash = genesis
        self.genesis_known = True

    def _adopt_published_feed(self):
        """Keep serving the previous feed untouched if it already said "unavailable".

        A restart while the chain is stopped then leaves generated_at where it
        was instead of moving it to the restart time.
        """
        try:
            payload = read_bounded_file(self.feed_path, MAX_FEED_BYTES)
            signature = read_bounded_file(self.sig_path, 256)
            feed = json.loads(payload)
        except (OSError, ValueError, RecursionError):
            return False
        if not hmac.compare_digest(signature, sign_feed(self.key, payload)):
            return False
        network = feed.get("network") if isinstance(feed, dict) else None
        if (not isinstance(network, dict) or feed.get("format") != FEED_FORMAT
                or network.get("status") != "unavailable" or feed.get("genesis_hash") != self.genesis_hash):
            return False
        self.store.publish(payload, signature)
        self.published_status = "unavailable"
        return True

    def _save_window(self, mono, force=False):
        if not self.dirty:
            return
        if not force and self.saved_at is not None and mono - self.saved_at < PERSIST_SECONDS:
            return
        data = {"format": WINDOW_FORMAT, "saved_at": int(self.clock()), "genesis_hash": self.genesis_hash,
                "next_slot": self.next_slot, "network": self.network, "blocks": list(self.blocks),
                "transactions": list(self.program_txs), "votes": list(self.vote_txs), "stats": self.stats}
        self.saved_at = mono
        try:
            write_atomic(self.window_path, json.dumps(data, separators=(",", ":")).encode("ascii"),
                         0o600, durable=True)
        except OSError as exc:
            self._disk_error(exc)
        else:
            self.dirty = False

    def _disk_error(self, exc):
        if not self.disk_failing:
            log("state-write-failed", error=exc.strerror or type(exc).__name__)
        self.disk_failing = True

    # -- one polling cycle -------------------------------------------------

    def poll_once(self):
        """Run one cycle and return the status of the feed now being served."""
        now = self.clock()
        mono = self.monotonic()
        try:
            self._poll(now, mono)
        except RpcUnavailable as exc:
            self._poll_failed(str(exc), now, mono)
        except Exception as exc:  # an unforeseen reply shape must not stop the service
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            self._poll_failed("unexpected %s at line %d" % (type(exc).__name__, frame.lineno), now, mono)
        self._save_window(mono)
        return self.published_status

    def _poll(self, now, mono):
        tip = self._slot("confirmed")
        if tip is None:
            raise RpcUnavailable("getSlot returned no slot")
        regressed = bool(self.blocks) and tip < self.blocks[-1]["slot"]
        if not self.genesis_checked or regressed or mono >= self.genesis_recheck_at:
            self._check_genesis(now, mono)
        previous_tip = self.network["tip_slot"]
        if self.blocks and tip < self.blocks[-1]["slot"]:
            # Same genesis, lower tip: the ledger was reset, so the window is from another history.
            log("tip-regressed", tip=tip, window_top=self.blocks[-1]["slot"])
            self._drop_blocks()
        elif previous_tip is not None and tip < previous_tip:
            self.samples.clear()

        finalized = self._slot("finalized")
        if finalized is not None and finalized > tip:
            finalized = tip
        self.network["tip_slot"] = tip
        self.network["finalized_slot"] = finalized
        self.network["block_height"] = as_count(self._optional("getBlockHeight", "confirmed"))

        observed_recently = self.last_ok is not None and mono - self.last_ok <= LIVE_SECONDS
        if observed_recently and previous_tip is not None and tip > previous_tip:
            self.network["last_block_at"] = int(now)
        self.samples.append((mono, tip))
        self.network["slot_time_ms"] = self._slot_time(mono)

        # The node answered: from here on the cycle counts as a successful poll.
        self.last_ok = mono
        if self.failing or self.published_status != "live":
            log("rpc-ok", tip=tip, finalized=finalized, genesis=self.genesis_hash)
        self.failing = False
        try:
            accounts = self._optional("getVoteAccounts", "confirmed")
            if accounts is not None:
                self.network["validators"] = parse_validators(accounts)
            if self.health_poll_at is None or mono >= self.health_poll_at:
                self.health_poll_at = mono + HEALTH_POLL_SECONDS
                self._poll_health()
            self._ingest(tip, finalized, mono)
            self.fetch_failing = False
        except RpcUnavailable as exc:
            if not self.fetch_failing:
                log("poll-interrupted", reason=exc)
            self.fetch_failing = True
        if self.blocks:
            newest = self.blocks[-1]["block_time"]
            if newest is not None and newest > (self.network["last_block_at"] or 0):
                self.network["last_block_at"] = min(newest, int(now))
        self.dirty = True
        self._publish("live", now)

    def _poll_failed(self, reason, now, mono):
        if not self.failing:
            log("rpc-unavailable", reason=reason)
        self.failing = True
        self.genesis_checked = False
        expired = self.last_ok is None or mono - self.last_ok > LIVE_SECONDS
        if self.published_status == "live" and expired:
            # Written once: generated_at then stops advancing until the node is back.
            self._publish("unavailable", now)
            log("status-unavailable", last_tip=self.network["tip_slot"])

    def _slot(self, commitment):
        forms = [[{"commitment": commitment}]]
        if commitment != "finalized":
            forms.append([])
        for params in forms:
            try:
                return as_count(self.rpc.call("getSlot", params))
            except RpcResponseError:
                continue
        return None

    def _optional(self, method, commitment=None):
        """Result of a method the node may lack; None when it answers with an error."""
        forms = [[]] if commitment is None else [[{"commitment": commitment}], []]
        for params in forms:
            try:
                return self.rpc.call(method, params)
            except RpcResponseError:
                continue
        return None

    def _check_genesis(self, now, mono):
        try:
            found = as_text(self.rpc.call("getGenesisHash", []))
        except RpcResponseError:
            found = None
        if found is None and self.genesis_hash is not None:
            # Do not discard a window over a passing error: only accept that the
            # node cannot name its genesis after several consecutive failures.
            self.genesis_errors += 1
            if self.genesis_errors < GENESIS_ERROR_LIMIT:
                raise RpcUnavailable("genesis hash not available")
        self.genesis_errors = 0
        if self.genesis_known and found != self.genesis_hash:
            log("genesis-changed", previous=self.genesis_hash, current=found)
            self._start_clean(now)
        self.genesis_hash = found
        self.genesis_known = True
        self.genesis_checked = True
        self.genesis_recheck_at = mono + GENESIS_RECHECK_SECONDS

    def _poll_health(self):
        """Node health goes to the process log only; it does not decide the feed status."""
        try:
            health = "ok" if self.rpc.call("getHealth", []) == "ok" else "not-ok"
        except RpcResponseError as exc:
            health = "unsupported" if exc.code == -32601 else "not-ok"
        if health != self.health:
            log("rpc-health", state=health)
            self.health = health

    def _slot_time(self, mono):
        while self.samples and mono - self.samples[0][0] > SLOT_TIME_WINDOW_SECONDS:
            self.samples.popleft()
        if len(self.samples) >= 2:
            elapsed = self.samples[-1][0] - self.samples[0][0]
            slots = self.samples[-1][1] - self.samples[0][1]
            if elapsed >= SLOT_TIME_MIN_SECONDS:
                return round(elapsed * 1000.0 / slots, 1) if slots > 0 else None
        return self.network["slot_time_ms"]

    # -- blocks ------------------------------------------------------------

    def _ingest(self, tip, finalized, mono):
        if self.blocks_unsupported_until is not None:
            if mono < self.blocks_unsupported_until:
                return
            self.blocks_unsupported_until = None
        if self.next_slot is None:
            self.next_slot = max(0, tip - START_BACKLOG_SLOTS)
        elif tip - self.next_slot > MAX_LAG_SLOTS:
            self.gaps += 1
            log("gap", behind_at=self.next_slot, resumed_at=tip - START_BACKLOG_SLOTS, gaps=self.gaps)
            self.next_slot = tip - START_BACKLOG_SLOTS
        try:
            slots, commitment = self._list_slots(tip, finalized)
            for slot in slots[:self.max_blocks_per_cycle]:
                if self.stopping.is_set() or self.monotonic() - mono > CYCLE_BUDGET_SECONDS:
                    break
                block = self._fetch_block(slot, commitment)
                if block is PENDING:
                    if self._retry_later(slot):
                        break
                elif block is not SKIPPED:
                    self._add_block(block)
                self.next_slot = slot + 1
        except BlockDataUnsupported as exc:
            self.next_slot = None
            self.blocks_unsupported_until = mono + BLOCK_REPROBE_SECONDS
            if not self.blocks_unsupported_logged:
                log("blocks-unavailable", method=exc, note="publishing network status only")
            self.blocks_unsupported_logged = True

    def _retry_later(self, slot):
        """Count a failed attempt; True while the slot gets another try next cycle."""
        if self.pending_slot != slot:
            self.pending_slot = slot
            self.pending_tries = 0
        self.pending_tries += 1
        return self.pending_tries < PENDING_RETRIES

    def _list_slots(self, tip, finalized):
        """Slots holding blocks from next_slot on, and the commitment they were listed at."""
        start = self.next_slot
        if self.block_variant is not None:
            commitments = (self.block_variant.commitment,)
        else:
            commitments = ("finalized", "confirmed")
        asked = answered = False
        for commitment in commitments:
            ceiling = finalized if commitment == "finalized" else tip
            if ceiling is None or ceiling < start:
                continue
            asked = True
            slots = self._get_blocks(start, min(ceiling, start + MAX_LAG_SLOTS), commitment)
            if slots is None:
                continue
            answered = True
            if slots:
                return slots, commitment
        if asked and not answered and self.block_variant is None:
            raise BlockDataUnsupported("getBlocks")
        return [], None

    def _get_blocks(self, start, end, commitment):
        forms = [[start, end, {"commitment": commitment}]]
        if commitment == "finalized":
            forms.append([start, end])      # nodes without the config object default to finalized
        for params in forms:
            try:
                result = self.rpc.call("getBlocks", params)
            except RpcResponseError:
                continue
            if isinstance(result, list):
                return sorted({slot for slot in result if as_count(slot) is not None and start <= slot <= end})
        return None

    def _fetch_block(self, slot, commitment):
        """A ParsedBlock, SKIPPED or PENDING. Raises BlockDataUnsupported if no request shape works."""
        if self.block_variant is None:
            variants = [v for v in BLOCK_VARIANTS if commitment == "finalized" or v.commitment == "confirmed"]
        else:
            variants = [self.block_variant]
            if self.block_variant.details == "full":
                # For one block the node cannot return in full, settle for its signatures.
                variants.append(BlockVariant("signatures", self.block_variant.commitment))
        pending = False
        for variant in variants:
            try:
                result = self.rpc.call("getBlock", [slot, block_config(variant)])
            except RpcResponseError as exc:
                if is_skipped_slot(exc):
                    return SKIPPED
                pending = pending or exc.code in PENDING_BLOCK_CODES
                continue
            if result is None:
                pending = True
                continue
            block = parse_block(slot, result)
            if block is None:
                continue
            if self.block_variant is None:
                self.block_variant = variant
                self.blocks_unsupported_logged = False
                log("block-variant", details=variant.details, commitment=variant.commitment)
            return block
        if pending or self.block_variant is not None:
            return PENDING
        raise BlockDataUnsupported("getBlock")

    # -- publishing --------------------------------------------------------

    def build_feed(self, status, now):
        network = {"status": status}
        network.update(self.network)
        network["validators"] = list(self.network["validators"])
        return {
            "format": FEED_FORMAT,
            "generated_at": int(now),
            "genesis_hash": self.genesis_hash,
            "network": network,
            "blocks": [dict(row) for row in reversed(self.blocks)],
            "transactions": select_transactions(self.program_txs, self.vote_txs),
            "stats": dict(self.stats),
        }

    def _publish(self, status, now):
        payload = encode_feed(self.build_feed(status, now))
        signature = sign_feed(self.key, payload)
        self.store.publish(payload, signature)
        self.published_status = status
        try:
            write_atomic(self.feed_path, payload, 0o644)
            write_atomic(self.sig_path, signature, 0o644)
        except OSError as exc:
            self._disk_error(exc)
        else:
            self.disk_failing = False


def _restore_block(row):
    slot = as_count(row["slot"])
    blockhash = as_text(row["blockhash"])
    tx_count = as_count(row["tx_count"])
    non_vote = as_count(row["non_vote_tx_count"])
    if None in (slot, blockhash, tx_count, non_vote):
        raise ValueError("bad block row")
    # Both payment counts or neither: a row saved before payments were counted has neither.
    payment = row.get("payment_tx_count")
    executed = row.get("executed_payment_count")
    if (payment is None) != (executed is None):
        raise ValueError("bad block row")
    if payment is not None and (as_count(payment) is None or as_count(executed) is None
                                or not executed <= payment <= tx_count):
        raise ValueError("bad block row")
    return {"slot": slot, "parent_slot": as_count(row["parent_slot"]), "blockhash": blockhash,
            "block_time": as_count(row["block_time"]), "block_height": as_count(row["block_height"]),
            "tx_count": tx_count, "non_vote_tx_count": non_vote,
            "payment_tx_count": payment, "executed_payment_count": executed}


def _restore_instructions(value):
    """None (not known), or instruction names, each once, in the order the feed lists them."""
    if value is None:
        return None
    if (not isinstance(value, list) or any(name not in PAYMENT_INSTRUCTION_ORDER for name in value)
            or value != [name for name in PAYMENT_INSTRUCTION_ORDER if name in value]):
        raise ValueError("bad payment instructions")
    return list(value)


def _restore_transaction(row):
    signature = as_text(row["signature"])
    slot = as_count(row["slot"])
    fee = as_count(row["fee"])
    position = as_count(row["position"])
    if None in (signature, slot, fee, position) or type(row["ok"]) is not bool or row["kind"] not in ("vote", "program"):
        raise ValueError("bad transaction row")
    return {"signature": signature, "slot": slot, "block_time": as_count(row["block_time"]),
            "ok": row["ok"], "fee": fee, "kind": row["kind"],
            "payment_instructions": _restore_instructions(row.get("payment_instructions")),
            "position": position}


def _restore_validator(row):
    identity = as_text(row["identity"])
    if identity is None or type(row["active"]) is not bool:
        raise ValueError("bad validator row")
    return {"identity": identity, "vote_account": as_text(row["vote_account"]),
            "last_vote": as_count(row["last_vote"]), "root_slot": as_count(row.get("root_slot")),
            "active": row["active"]}


# --------------------------------------------------------------------------
# HTTP server: two fixed paths, GET and HEAD, served from memory

ROUTES = {"/feed.json": (0, "application/json"), "/feed.sig": (1, "text/plain")}


def normalize_ip(text):
    address = ipaddress.ip_address(text.split("%", 1)[0])
    mapped = getattr(address, "ipv4_mapped", None)
    return address if mapped is None else mapped


class FeedRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "zolana-explorer-feed"
    sys_version = ""
    timeout = HTTP_SOCKET_TIMEOUT_SECONDS

    def setup(self):
        super().setup()
        try:
            # Lets a whole payload be queued at once, so a slow link is not cut off by the timeout.
            self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, HTTP_SEND_BUFFER_BYTES)
        except OSError:
            pass

    def version_string(self):
        return self.server_version

    def handle(self):
        # The request line and headers are read here, within fixed size and time
        # limits, and then parsed from memory. The stock reader accepts megabytes
        # of header lines per connection and has no limit on a slowly sent request.
        head = self._read_head()
        if head is None:
            self.server.count_event("aborted")
            return
        self.rfile.close()
        self.rfile = io.BytesIO(head)
        super().handle()

    def _read_head(self):
        """The request up to its blank line, or None if it is too slow or too large."""
        deadline = time.monotonic() + HTTP_REQUEST_SECONDS
        head = b""
        try:
            while b"\n\r\n" not in head and b"\n\n" not in head:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or len(head) >= HTTP_MAX_REQUEST_BYTES:
                    return None
                self.connection.settimeout(min(remaining, HTTP_SOCKET_TIMEOUT_SECONDS))
                chunk = self.connection.recv(HTTP_MAX_REQUEST_BYTES - len(head))
                if not chunk:
                    break                   # the client stopped sending: answer what arrived
                head += chunk
            self.connection.settimeout(HTTP_SOCKET_TIMEOUT_SECONDS)
        except OSError:
            return None
        return head

    def do_GET(self):
        self._serve(True)

    def do_HEAD(self):
        self._serve(False)

    def _refuse_method(self):
        self._reply(403 if not self._allowed() else 405)

    do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = do_CONNECT = _refuse_method

    def _allowed(self):
        return self.server.client_allowed(self.client_address[0])

    def _serve(self, with_body):
        if not self._allowed():
            return self._reply(403, with_body=with_body)
        # Match the request target exactly as sent (self.path is normalised by the
        # standard library): no query strings, no alternative spellings.
        words = self.requestline.split()
        route = ROUTES.get(words[1]) if len(words) >= 2 else None
        if route is None:
            return self._reply(404, with_body=with_body)
        index, content_type = route
        if with_body:
            body = self.server.store.fetch(self.client_address[0], index)
        else:
            current = self.server.store.current()
            body = None if current is None else current[index]
        if body is None:
            return self._reply(503, with_body=with_body)
        self._reply(200, body, content_type, with_body)

    def _reply(self, status, body=None, content_type="text/plain", with_body=True):
        if body is None:
            body = (http.HTTPStatus(status).phrase + "\n").encode("ascii")
        self.server.count(status)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 405:
            self.send_header("Allow", "GET, HEAD")
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        # Replaces the stock HTML error page so that nothing from the request is echoed.
        self.close_connection = True
        try:
            self._reply(int(code) if self._allowed() else 403, with_body=self.command != "HEAD")
        except OSError:
            pass

    def log_message(self, format, *args):
        pass                                # requests are counted, never logged


class FeedHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, address, store, allowed=()):
        self.address_family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
        self.store = store
        self.allowed = frozenset(allowed)
        self.counters = collections.Counter()
        self._counter_lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(HTTP_MAX_CONNECTIONS)
        self._stranger_slots = threading.BoundedSemaphore(HTTP_MAX_STRANGER_CONNECTIONS)
        super().__init__(address, FeedRequestHandler)

    def server_bind(self):
        # Like HTTPServer.server_bind, minus the reverse DNS lookup for the host name.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def client_allowed(self, host):
        if not self.allowed:
            return True
        try:
            return normalize_ip(host) in self.allowed
        except ValueError:
            return False

    def count(self, status):
        name = {200: "ok", 403: "forbidden", 404: "not_found"}.get(status, "other")
        with self._counter_lock:
            self.counters["requests"] += 1
            self.counters[name] += 1

    def count_event(self, name):
        with self._counter_lock:
            self.counters[name] += 1

    def snapshot(self):
        with self._counter_lock:
            return dict(self.counters)

    # Addresses that are not on the allowlist only ever receive a 403. They share a
    # small part of the connection limit, so they cannot use up the connections
    # that the allowed clients need.

    def _acquire_slot(self, stranger):
        if stranger and not self._stranger_slots.acquire(blocking=False):
            return False
        if self._slots.acquire(blocking=False):
            return True
        if stranger:
            self._stranger_slots.release()
        return False

    def _release_slot(self, stranger):
        self._slots.release()
        if stranger:
            self._stranger_slots.release()

    def process_request(self, request, client_address):
        stranger = not self.client_allowed(client_address[0])
        if not self._acquire_slot(stranger):
            self.count_event("dropped")
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._release_slot(stranger)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release_slot(not self.client_allowed(client_address[0]))

    def handle_error(self, request, client_address):
        self.count_event("handler_errors")


# --------------------------------------------------------------------------
# Command line

def parse_listen(value):
    host, separator, port = value.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        if not separator:
            raise ValueError
        ipaddress.ip_address(host)
        port = int(port)
        if not 0 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ConfigError("--listen must be ADDRESS:PORT with a literal IP address") from None
    return host, port


def parse_allowed(values):
    allowed = set()
    for value in values or ():
        try:
            allowed.add(normalize_ip(value))
        except ValueError:
            raise ConfigError("--allow-ip is not an IP address: %s" % _log_text(value)) from None
    return allowed


def prepare_state_dir(path):
    try:
        os.makedirs(path, mode=0o750, exist_ok=True)
    except OSError as exc:
        raise ConfigError("state directory cannot be created (%s)" % (exc.strerror or "error")) from None
    if not os.access(path, os.W_OK | os.X_OK):
        raise ConfigError("state directory is not writable")
    return path


def build_parser():
    parser = argparse.ArgumentParser(
        description="Zolana devnet explorer feed: polls a JSON-RPC node read-only and serves "
                    "/feed.json and /feed.sig.", allow_abbrev=False)
    parser.add_argument("--rpc-url", default="http://127.0.0.1:49643",
                        help="JSON-RPC endpoint (default %(default)s)")
    parser.add_argument("--state-dir", default="/var/lib/zolana-explorer-feed-v0",
                        help="directory for feed.json, feed.sig and window.json (default %(default)s)")
    parser.add_argument("--hmac-key-file", required=True,
                        help="file holding the shared key: 32 or more random bytes, not readable by other users")
    parser.add_argument("--listen", default="0.0.0.0:18080", help="ADDRESS:PORT to serve on (default %(default)s)")
    parser.add_argument("--allow-ip", action="append", default=[], metavar="IP",
                        help="client address allowed to fetch the feed; repeatable; if given, all others get 403")
    parser.add_argument("--poll-seconds", type=float, default=2.0, help="pause between polls (default %(default)s)")
    parser.add_argument("--max-blocks-per-cycle", type=int, default=30,
                        help="most blocks fetched per poll (default %(default)s)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if not 0.1 <= args.poll_seconds <= 10:
            raise ConfigError("--poll-seconds must be between 0.1 and 10")
        if not 1 <= args.max_blocks_per_cycle <= MAX_BLOCKS:
            raise ConfigError("--max-blocks-per-cycle must be between 1 and %d" % MAX_BLOCKS)
        key = load_hmac_key(args.hmac_key_file)
        address = parse_listen(args.listen)
        allowed = parse_allowed(args.allow_ip)
        rpc = RpcClient(args.rpc_url)
        state_dir = prepare_state_dir(args.state_dir)
    except ConfigError as exc:
        log("refusing-to-start", reason=exc)
        return 2

    poller = FeedPoller(rpc, state_dir, key, max_blocks_per_cycle=args.max_blocks_per_cycle)
    stop = threading.Event()

    def request_stop(signum, frame):
        poller.stopping.set()
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    # Poll once before listening, so a restart on a running chain answers "live" from its first request.
    poller.start()
    started = time.monotonic()
    poller.poll_once()
    try:
        server = FeedHTTPServer(address, poller.store, allowed)
    except OSError as exc:
        log("listen-failed", listen=args.listen, error=exc.strerror or type(exc).__name__)
        return 1
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.25},
                              name="feed-http", daemon=True)
    thread.start()
    log("started", rpc=rpc.url, address=server.server_address[0], port=server.server_address[1],
        allow=",".join(sorted(str(ip) for ip in allowed)) or "any")
    summary_at = time.monotonic() + SUMMARY_SECONDS
    try:
        while not stop.wait(max(0.05, args.poll_seconds - (time.monotonic() - started))):
            started = time.monotonic()
            status = poller.poll_once()
            if started >= summary_at:
                summary_at = started + SUMMARY_SECONDS
                log("summary", status=status, tip=poller.network["tip_slot"], blocks=len(poller.blocks),
                    blocks_seen=poller.stats["blocks_seen"], gaps=poller.gaps, **{
                        "http_" + name: value for name, value in sorted(server.snapshot().items())})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        poller.close()
    log("stopped", gaps=poller.gaps)
    return 0


if __name__ == "__main__":
    sys.exit(main())
