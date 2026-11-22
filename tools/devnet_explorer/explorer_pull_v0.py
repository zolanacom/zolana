#!/usr/bin/env python3
"""Web-side puller for the Zolana explorer feed (zolana-explorer-feed-v0).

Every interval it fetches feed.json and feed.sig from the chain host over plain
HTTP, checks the HMAC-SHA256 signature with the shared key, validates the
document against the feed contract and only then publishes the exact verified
bytes with an atomic rename. Any failure leaves the published file untouched.

The contract has two shapes under the one format name: the base shape, and the
shape that also marks payment-program transactions (see validate_feed). Both
are accepted, so this puller can be installed before or after the feed service
that writes the second shape.

Standard library only. Exit codes with --once: 0 published, 3 no change,
1 error. Exit code 2 means the arguments or the key file were rejected.
"""
import argparse
import hashlib
import hmac
import http.client
import json
import math
import os
import re
import signal
import stat
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

FEED_FORMAT = "zolana-explorer-feed-v0"
DEFAULT_OUTPUT = "/var/lib/zolana-explorer-pull-v0/feed.json"
DEFAULT_INTERVAL = 3.0
MIN_INTERVAL = 1.0
MAX_INTERVAL = 3600.0
HTTP_TIMEOUT = 4.0
MAX_READ_BYTES = 500 * 1000       # transport cap for one response body
MAX_FEED_BYTES = 400 * 1024       # contract cap for feed.json
MAX_SIGNATURE_BYTES = 128
MIN_KEY_BYTES = 32
MAX_KEY_BYTES = 4096
MAX_BLOCKS = 120
MAX_TRANSACTIONS = 200
MAX_STRING_LENGTH = 127           # strings must be shorter than 128 characters
INTEGER_LIMIT = 2 ** 53           # integers must be below this
MAX_FUTURE_SECONDS = 120
LOG_INTERVAL = 30.0
STALE_TEMP_SECONDS = 60.0

PUBLISHED = "published"
UNCHANGED = "unchanged"

EXIT_PUBLISHED = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_UNCHANGED = 3

_SOURCE_RE = re.compile(
    r"http://((?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}):([1-9][0-9]{0,4})")
_SIGNATURE_RE = re.compile(rb"[0-9a-f]{64}")
_CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,12}")
# Every string in the contract is a base58 identifier or hash, so only ASCII
# letters and digits are accepted; nothing that reaches the page can carry markup.
_TEXT_RE = re.compile(r"[0-9A-Za-z]*")

_TOP_KEYS = ("format", "generated_at", "genesis_hash", "network", "blocks",
             "transactions", "stats")
_NETWORK_KEYS = ("status", "tip_slot", "finalized_slot", "block_height",
                 "slot_time_ms", "last_block_at", "validators")
_VALIDATOR_KEYS = ("identity", "vote_account", "last_vote", "active")
_BLOCK_KEYS = ("slot", "parent_slot", "blockhash", "block_time", "block_height",
               "tx_count", "non_vote_tx_count")
_TRANSACTION_KEYS = ("signature", "slot", "block_time", "ok", "fee", "kind")
_STATS_KEYS = ("since", "blocks_seen", "transactions_seen",
               "non_vote_transactions_seen")
# The fields a feed that marks payment-program transactions adds. A feed
# carries all of them, in every row, or none of them.
_VALIDATOR_PAYMENT_KEYS = ("root_slot",)
_BLOCK_PAYMENT_KEYS = ("payment_tx_count", "executed_payment_count")
_TRANSACTION_PAYMENT_KEYS = ("payment_instructions",)
_STATS_PAYMENT_KEYS = ("payments_since", "payment_transactions_seen",
                       "executed_payments_seen")
# Names of the payment program's instructions, in the order a feed lists them.
PAYMENT_INSTRUCTIONS = ("initialize", "write", "seal", "finalize", "close",
                        "inline", "unknown")

_REQUEST_HEADERS = {
    "User-Agent": "zolana-explorer-pull/0",
    "Accept": "*/*",
    "Accept-Encoding": "identity",
    "Cache-Control": "no-cache",
}


class ConfigError(Exception):
    """The command line or the key file was rejected."""


class PullError(Exception):
    """One pull attempt failed; kind groups log lines for rate limiting."""

    def __init__(self, kind, detail):
        super().__init__("%s: %s" % (kind, detail))
        self.kind = kind
        self.detail = detail


def _clip(value, limit=96):
    text = "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in str(value))
    return text[:limit]


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def parse_source(value):
    """Return the normalised source base URL or raise ConfigError.

    Only http://<literal IPv4>:<port> is accepted: no other scheme, no host
    names, no implicit port, no path, query, fragment or credentials.
    """
    match = _SOURCE_RE.fullmatch(value) if isinstance(value, str) else None
    if match is not None:
        host, port = match.group(1), int(match.group(2))
        if all(int(part) <= 255 for part in host.split(".")) and port <= 65535:
            return "http://%s:%d" % (host, port)
    raise ConfigError("--source must be http://<IPv4 address>:<port> with no path, "
                      "for example http://203.0.113.10:18080")


def key_file_problem(mode, owner, euid):
    """Say why a key file's type, owner or mode is unacceptable, or return None.

    Accepted: access for the owner only (0400, 0600), or a read-only file that
    also shows group read (0440), which is how systemd presents a
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


def load_key(path):
    """Read the shared HMAC key: the exact bytes of the file.

    Nothing is trimmed or decoded, so the web host and the chain host must
    hold byte-identical copies of the file. The key is 32 bytes; a longer
    file (up to 4096 bytes) is used as it is.
    """
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise ConfigError("HMAC key file cannot be opened (%s)"
                          % _clip(exc.strerror or "error")) from None
    try:
        info = os.fstat(fd)
        problem = key_file_problem(info.st_mode, info.st_uid, os.geteuid())
        if problem is not None:
            raise ConfigError("HMAC key file " + problem)
        key = os.read(fd, MAX_KEY_BYTES + 1)
    except OSError as exc:
        raise ConfigError("HMAC key file cannot be read (%s)"
                          % _clip(exc.strerror or "error")) from None
    finally:
        os.close(fd)
    if len(key) < MIN_KEY_BYTES:
        raise ConfigError("HMAC key file is shorter than %d bytes" % MIN_KEY_BYTES)
    if len(key) > MAX_KEY_BYTES:
        raise ConfigError("HMAC key file is longer than %d bytes" % MAX_KEY_BYTES)
    return key


def resolve_output(value):
    path = os.path.abspath(value)
    directory, name = os.path.split(path)
    if not name:
        raise ConfigError("--output must name a file")
    if not os.path.isdir(directory):
        raise ConfigError("--output directory does not exist: %s" % _clip(directory, 200))
    return path


# --------------------------------------------------------------------------
# Feed contract
# --------------------------------------------------------------------------

def _invalid(path, problem):
    raise PullError("invalid", "%s %s" % (path, problem))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def _reject_constant(_name):
    raise ValueError("non-finite number")


def parse_feed(body):
    """Decode feed.json bytes as strict JSON (UTF-8, unique keys, finite numbers)."""
    if len(body) > MAX_FEED_BYTES:
        raise PullError("oversized", "feed.json is %d bytes; the contract allows at most %d"
                        % (len(body), MAX_FEED_BYTES))
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise PullError("invalid", "feed.json is not valid UTF-8") from None
    try:
        return json.loads(text, object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    except RecursionError:
        raise PullError("invalid", "feed.json is nested too deeply") from None
    except ValueError as exc:
        raise PullError("invalid", "feed.json is not strict JSON: %s" % _clip(exc)) from None


def _object(value, path, keys):
    if type(value) is not dict:
        _invalid(path, "must be an object")
    for key in value:
        if key not in keys:
            _invalid(path, "has unexpected key %s" % _clip(ascii(key), 48))
    for key in keys:
        if key not in value:
            _invalid(path, "is missing key %s" % key)
    return value


def _array(value, path, cap=None):
    if type(value) is not list:
        _invalid(path, "must be an array")
    if cap is not None and len(value) > cap:
        _invalid(path, "has %d entries; at most %d are allowed" % (len(value), cap))
    return value


def _integer(value, path, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not int or not 0 <= value < INTEGER_LIMIT:
        _invalid(path, "must be an integer from 0 to 2**53 - 1")
    return value


def _number(value, path, nullable=False):
    if value is None and nullable:
        return
    if type(value) is int:
        valid = 0 <= value < INTEGER_LIMIT
    elif type(value) is float:
        valid = math.isfinite(value) and 0 <= value < INTEGER_LIMIT
    else:
        valid = False
    if not valid:
        _invalid(path, "must be a finite number from 0 to below 2**53")


def _string(value, path, nullable=False):
    if value is None and nullable:
        return
    if (type(value) is not str or len(value) > MAX_STRING_LENGTH
            or _TEXT_RE.fullmatch(value) is None):
        _invalid(path, "must be a string of ASCII letters and digits shorter than 128 characters")


def _boolean(value, path):
    if type(value) is not bool:
        _invalid(path, "must be true or false")


def _enum(value, path, allowed):
    if type(value) is not str or value not in allowed:
        _invalid(path, "must be one of %s" % ", ".join(allowed))


def _payment_instructions(value, path):
    """null (not known), or instruction names, each once, in the listed order."""
    if value is None:
        return
    position = -1
    for index, name in enumerate(_array(value, path, len(PAYMENT_INSTRUCTIONS))):
        _enum(name, "%s[%d]" % (path, index), PAYMENT_INSTRUCTIONS)
        if PAYMENT_INSTRUCTIONS.index(name) <= position:
            _invalid(path, "must name each instruction once, in the order %s"
                     % ", ".join(PAYMENT_INSTRUCTIONS))
        position = PAYMENT_INSTRUCTIONS.index(name)


def validate_feed(document):
    """Check a parsed feed against the shared contract; return generated_at.

    A feed whose stats carry a payment counter is held to the shape that
    marks payment-program transactions: every validator, block, transaction
    and the stats must then carry their payment fields. A feed whose stats
    carry none must carry none anywhere.
    """
    feed = _object(document, "feed", _TOP_KEYS)
    marked = type(feed["stats"]) is dict and any(key in feed["stats"] for key in _STATS_PAYMENT_KEYS)
    validator_keys = _VALIDATOR_KEYS + (_VALIDATOR_PAYMENT_KEYS if marked else ())
    block_keys = _BLOCK_KEYS + (_BLOCK_PAYMENT_KEYS if marked else ())
    transaction_keys = _TRANSACTION_KEYS + (_TRANSACTION_PAYMENT_KEYS if marked else ())
    stats_keys = _STATS_KEYS + (_STATS_PAYMENT_KEYS if marked else ())
    if type(feed["format"]) is not str or feed["format"] != FEED_FORMAT:
        _invalid("format", "must be exactly %s" % FEED_FORMAT)
    generated_at = _integer(feed["generated_at"], "generated_at")
    _string(feed["genesis_hash"], "genesis_hash", nullable=True)

    network = _object(feed["network"], "network", _NETWORK_KEYS)
    _enum(network["status"], "network.status", ("live", "unavailable"))
    _integer(network["tip_slot"], "network.tip_slot", nullable=True)
    _integer(network["finalized_slot"], "network.finalized_slot", nullable=True)
    _integer(network["block_height"], "network.block_height", nullable=True)
    _number(network["slot_time_ms"], "network.slot_time_ms", nullable=True)
    _integer(network["last_block_at"], "network.last_block_at", nullable=True)
    for index, item in enumerate(_array(network["validators"], "network.validators")):
        path = "network.validators[%d]" % index
        _object(item, path, validator_keys)
        _string(item["identity"], path + ".identity")
        _string(item["vote_account"], path + ".vote_account", nullable=True)
        _integer(item["last_vote"], path + ".last_vote", nullable=True)
        _boolean(item["active"], path + ".active")
        if marked:
            _integer(item["root_slot"], path + ".root_slot", nullable=True)

    for index, item in enumerate(_array(feed["blocks"], "blocks", MAX_BLOCKS)):
        path = "blocks[%d]" % index
        _object(item, path, block_keys)
        _integer(item["slot"], path + ".slot")
        _integer(item["parent_slot"], path + ".parent_slot", nullable=True)
        _string(item["blockhash"], path + ".blockhash")
        _integer(item["block_time"], path + ".block_time", nullable=True)
        _integer(item["block_height"], path + ".block_height", nullable=True)
        _integer(item["tx_count"], path + ".tx_count")
        _integer(item["non_vote_tx_count"], path + ".non_vote_tx_count")
        if marked:
            # Both counts, or null for both: the block was read without its instructions.
            payment = _integer(item["payment_tx_count"], path + ".payment_tx_count", nullable=True)
            executed = _integer(item["executed_payment_count"],
                                path + ".executed_payment_count", nullable=True)
            if (payment is None) != (executed is None):
                _invalid(path, "must give both payment counts or null for both")
            if payment is not None and not executed <= payment <= item["tx_count"]:
                _invalid(path, "must have executed_payment_count <= payment_tx_count <= tx_count")

    for index, item in enumerate(_array(feed["transactions"], "transactions",
                                        MAX_TRANSACTIONS)):
        path = "transactions[%d]" % index
        _object(item, path, transaction_keys)
        _string(item["signature"], path + ".signature")
        _integer(item["slot"], path + ".slot")
        _integer(item["block_time"], path + ".block_time", nullable=True)
        _boolean(item["ok"], path + ".ok")
        _integer(item["fee"], path + ".fee")
        _enum(item["kind"], path + ".kind", ("vote", "program"))
        if marked:
            _payment_instructions(item["payment_instructions"], path + ".payment_instructions")

    stats = _object(feed["stats"], "stats", stats_keys)
    for key in stats_keys:
        _integer(stats[key], "stats." + key)
    if marked and stats["executed_payments_seen"] > stats["payment_transactions_seen"]:
        _invalid("stats", "must have executed_payments_seen <= payment_transactions_seen")
    return generated_at


# --------------------------------------------------------------------------
# Publishing
# --------------------------------------------------------------------------

def write_atomic(path, data):
    """Replace path with data so readers only ever see a complete file."""
    directory, name = os.path.split(path)
    fd, temporary = tempfile.mkstemp(prefix="." + name + ".", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    try:
        directory_fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(directory_fd)
    except OSError:
        pass
    finally:
        os.close(directory_fd)


def remove_stale_temp_files(output, max_age=STALE_TEMP_SECONDS):
    """Delete temporary files an interrupted earlier run left next to output."""
    directory, name = os.path.split(output)
    prefix = "." + name + "."
    cutoff = time.time() - max_age
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return
    for entry in entries:
        if not (entry.name.startswith(prefix) and entry.name.endswith(".tmp")):
            continue
        try:
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISREG(info.st_mode) and info.st_mtime < cutoff:
                os.unlink(entry.path)
        except OSError:
            pass


def _published_generated_at(body):
    """Best-effort generated_at of an already published file, or -1."""
    try:
        document = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
        return -1
    value = document.get("generated_at") if type(document) is dict else None
    if type(value) is int and 0 <= value < INTEGER_LIMIT:
        return value
    return -1


class RateLimitedLog:
    """Writes log lines; limited() emits at most one line per interval per kind."""

    def __init__(self, emit=None, interval=LOG_INTERVAL, clock=time.monotonic):
        self._emit = emit if emit is not None else self._stderr
        self._interval = interval
        self._clock = clock
        self._last = {}
        self._suppressed = {}

    @staticmethod
    def _stderr(line):
        try:
            print(line, file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass

    def write(self, line):
        self._emit(line)

    def limited(self, kind, line):
        now = self._clock()
        last = self._last.get(kind)
        if last is not None and now - last < self._interval:
            self._suppressed[kind] = self._suppressed.get(kind, 0) + 1
            return False
        skipped = self._suppressed.pop(kind, 0)
        self._last[kind] = now
        if skipped:
            line += " (%d similar suppressed)" % skipped
        self._emit(line)
        return True


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Puller:
    def __init__(self, source, key, output, clock=time.time, log=None, timeout=HTTP_TIMEOUT):
        self._source = source
        self._key = key
        self._output = os.path.abspath(output)
        self._clock = clock
        self._log = log if log is not None else RateLimitedLog()
        self._timeout = timeout
        # No proxies and no redirects: the only peer is the configured address.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())
        self._high_water = -1
        self._known_body = None
        self._known_generated_at = -1
        self._healthy = None
        self.last_generated_at = None
        self.last_size = None

    # ---- transport -------------------------------------------------------

    def _fetch(self, name, limit):
        request = urllib.request.Request(self._source + "/" + name,
                                         headers=_REQUEST_HEADERS, method="GET")
        deadline = time.monotonic() + self._timeout
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                if response.status != 200:
                    raise PullError("http", "%s returned HTTP %d" % (name, response.status))
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    if _CONTENT_LENGTH_RE.fullmatch(declared) is None:
                        raise PullError("fetch", "%s has an invalid Content-Length" % name)
                    declared = int(declared)
                    if declared > limit:
                        raise PullError("oversized", "%s is %d bytes; at most %d are read"
                                        % (name, declared, limit))
                chunks = []
                size = 0
                while True:
                    chunk = response.read1(min(65536, limit + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > limit:
                        raise PullError("oversized", "%s is larger than %d bytes"
                                        % (name, limit))
                    chunks.append(chunk)
                    if time.monotonic() > deadline:
                        raise PullError("fetch", "%s timed out" % name)
                if declared is not None and size != declared:
                    raise PullError("fetch", "%s ended before its declared length" % name)
                return b"".join(chunks)
        except PullError:
            raise
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise PullError("http", "%s returned HTTP %d" % (name, code)) from None
        except urllib.error.URLError as exc:
            raise PullError("fetch", "%s: %s" % (name, _clip(exc.reason))) from None
        except (OSError, http.client.HTTPException) as exc:
            raise PullError("fetch", "%s: %s" % (name, _clip(exc) or type(exc).__name__)) from None

    def _signature_problem(self, body, raw_signature):
        candidate = raw_signature.rstrip(b"\r\n")
        if _SIGNATURE_RE.fullmatch(candidate) is None:
            return "feed.sig is not one line of 64 lowercase hex characters"
        expected = hmac.new(self._key, body, hashlib.sha256).hexdigest().encode("ascii")
        if not hmac.compare_digest(expected, candidate):
            return "feed.sig does not match feed.json"
        return None

    def _fetch_verified(self):
        body = self._fetch("feed.json", MAX_READ_BYTES)
        signature = self._fetch("feed.sig", MAX_SIGNATURE_BYTES)
        problem = self._signature_problem(body, signature)
        if problem is None:
            return body
        # The publisher may have replaced the pair between the two requests,
        # so each half is read once more before the mismatch is reported.
        signature = self._fetch("feed.sig", MAX_SIGNATURE_BYTES)
        if self._signature_problem(body, signature) is None:
            return body
        body = self._fetch("feed.json", MAX_READ_BYTES)
        problem = self._signature_problem(body, signature)
        if problem is None:
            return body
        raise PullError("signature", problem)

    # ---- published state -------------------------------------------------

    def _read_published(self):
        flags = (os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(self._output, flags)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PullError("write", "cannot read the published feed (it must be a "
                            "regular file): %s" % _clip(exc.strerror)) from None
        try:
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise PullError("write", "the output path is not a regular file")
                return stream.read(MAX_READ_BYTES + 1)
        except OSError as exc:
            raise PullError("write", "cannot read the published feed: %s"
                            % _clip(exc.strerror)) from None

    def _published_floor(self, previous):
        if previous is None:
            return self._high_water
        if previous != self._known_body:
            self._known_body = previous
            self._known_generated_at = _published_generated_at(previous)
        return max(self._high_water, self._known_generated_at)

    # ---- one attempt -----------------------------------------------------

    def pull_once(self):
        """Fetch, verify, validate and publish. Returns PUBLISHED or UNCHANGED.

        Raises PullError and leaves the published file untouched otherwise.
        """
        body = self._fetch_verified()
        generated_at = validate_feed(parse_feed(body))
        ahead = generated_at - self._clock()
        if ahead > MAX_FUTURE_SECONDS:
            raise PullError("future", "generated_at is %d s ahead of this host's clock; "
                            "at most %d s is accepted" % (ahead, MAX_FUTURE_SECONDS))
        previous = self._read_published()
        floor = self._published_floor(previous)
        self.last_generated_at = generated_at
        self.last_size = len(body)
        if previous == body:
            self._high_water = max(self._high_water, generated_at)
            return UNCHANGED
        if generated_at < floor:
            raise PullError("rollback", "generated_at %d is older than the published %d"
                            % (generated_at, floor))
        try:
            write_atomic(self._output, body)
        except OSError as exc:
            raise PullError("write", "cannot publish the feed: %s"
                            % _clip(exc.strerror or exc)) from None
        self._high_water = generated_at
        self._known_body = body
        self._known_generated_at = generated_at
        return PUBLISHED

    def attempt(self):
        """Run pull_once, log the outcome concisely and return an exit code."""
        try:
            outcome = self.pull_once()
        except PullError as exc:
            self._healthy = False
            self._log.limited(exc.kind, "error %s: %s" % (exc.kind, exc.detail))
            return EXIT_ERROR
        except Exception as exc:  # keep the loop alive on anything unforeseen
            self._healthy = False
            self._log.limited("internal", "error internal: %s" % type(exc).__name__)
            return EXIT_ERROR
        if self._healthy is not True:
            self._healthy = True
            self._log.limited("ok", "ok: feed %s (generated_at=%d, %d bytes)"
                              % (outcome, self.last_generated_at, self.last_size))
        return EXIT_PUBLISHED if outcome == PUBLISHED else EXIT_UNCHANGED


def run_loop(puller, interval, stop):
    """Call puller.attempt() every interval seconds until stop is set."""
    pause = min(1.0, interval)
    next_at = time.monotonic()
    while not stop.is_set():
        puller.attempt()
        next_at += interval
        now = time.monotonic()
        if next_at < now + pause:   # a slow attempt never causes a burst
            next_at = now + pause
        stop.wait(next_at - now)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="explorer_pull_v0.py", allow_abbrev=False,
        description="Pull, verify and publish the signed Zolana explorer feed.")
    parser.add_argument("--source", required=True,
                        help="feed origin, for example http://203.0.113.10:18080 "
                             "(http scheme, literal IPv4 address, explicit port, no path)")
    parser.add_argument("--hmac-key-file", required=True,
                        help="file holding the shared 32-byte HMAC key, used byte for byte; "
                             "must be owned by this user or root and not be accessible "
                             "to other users")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help="published feed path (default: %(default)s)")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL,
                        help="seconds between pulls (default: %(default)s)")
    parser.add_argument("--once", action="store_true",
                        help="make a single attempt; exit 0 on publish, 3 on no change, "
                             "1 on error")
    args = parser.parse_args(argv)

    log = RateLimitedLog()
    try:
        source = parse_source(args.source)
        if not MIN_INTERVAL <= args.interval <= MAX_INTERVAL:
            raise ConfigError("--interval must be between %g and %g seconds"
                              % (MIN_INTERVAL, MAX_INTERVAL))
        key = load_key(args.hmac_key_file)
        output = resolve_output(args.output)
    except ConfigError as exc:
        log.write("configuration error: %s" % exc)
        return EXIT_CONFIG

    remove_stale_temp_files(output)
    puller = Puller(source, key, output, log=log)
    if args.once:
        return puller.attempt()

    stop = threading.Event()

    def request_stop(_signum, _frame):
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    log.write("pulling %s every %g s into %s" % (source, args.interval, _clip(output, 200)))
    run_loop(puller, args.interval, stop)
    log.write("stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
