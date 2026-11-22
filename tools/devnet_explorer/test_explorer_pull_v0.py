"""Tests for explorer_pull_v0. Standard library only.

Run from any directory:

    python3 -B test_explorer_pull_v0.py
"""
import copy
import hashlib
import hmac
import http.server
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import explorer_pull_v0 as pull  # noqa: E402

SCRIPT = os.path.join(HERE, "explorer_pull_v0.py")
KEY = bytes(range(32))
NOW = 1800000000
_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58(label, length=44):
    digest = hashlib.sha512(label.encode("ascii")).digest()
    while len(digest) < length:
        digest += hashlib.sha512(digest).digest()
    return "".join(_BASE58[byte % 58] for byte in digest[:length])


def make_feed(generated_at=NOW, blocks=3, transactions=4, validators=1, status="live"):
    tip = 250000
    return {
        "format": "zolana-explorer-feed-v0",
        "generated_at": generated_at,
        "genesis_hash": base58("genesis"),
        "network": {
            "status": status,
            "tip_slot": tip,
            "finalized_slot": tip - 32,
            "block_height": tip - 10,
            "slot_time_ms": 412.5,
            "last_block_at": generated_at - 1,
            "validators": [
                {"identity": base58("identity%d" % index),
                 "vote_account": base58("vote%d" % index),
                 "last_vote": tip - 1,
                 "active": True}
                for index in range(validators)],
        },
        "blocks": [
            {"slot": tip - index,
             "parent_slot": tip - index - 1,
             "blockhash": base58("block%d" % (tip - index)),
             "block_time": generated_at - index,
             "block_height": tip - 10 - index,
             "tx_count": 3,
             "non_vote_tx_count": 1}
            for index in range(blocks)],
        "transactions": [
            {"signature": base58("signature%d" % index, 88),
             "slot": tip - index // 2,
             "block_time": generated_at - index,
             "ok": index % 5 != 0,
             "fee": 5000,
             "kind": "program"}
            for index in range(transactions)],
        "stats": {"since": generated_at - 3600, "blocks_seen": 9000,
                  "transactions_seen": 27000, "non_vote_transactions_seen": 40},
    }


def make_marked_feed(generated_at=NOW, **sizes):
    """The same feed in the shape that marks payment-program transactions."""
    feed = make_feed(generated_at, **sizes)
    steps = (["finalize", "close"], [], ["initialize", "write"], None, ["inline"], ["unknown"])
    for row in feed["network"]["validators"]:
        row["root_slot"] = row["last_vote"] - 31
    for index, row in enumerate(feed["blocks"]):
        row["payment_tx_count"] = None if index % 7 == 3 else 1
        row["executed_payment_count"] = None if index % 7 == 3 else index % 2
    for index, row in enumerate(feed["transactions"]):
        row["payment_instructions"] = steps[index % len(steps)]
    feed["stats"].update(payments_since=generated_at - 600, payment_transactions_seen=31,
                         executed_payments_seen=4)
    return feed


def encode(feed):
    return json.dumps(feed, separators=(",", ":")).encode("utf-8")


def sign(body, key=KEY):
    return hmac.new(key, body, hashlib.sha256).hexdigest().encode("ascii") + b"\n"


def read_bytes(path):
    with open(path, "rb") as stream:
        return stream.read()


def fingerprint(path):
    info = os.stat(path)
    return (read_bytes(path), info.st_ino, info.st_mtime_ns, stat.S_IMODE(info.st_mode))


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        route = self.server.routes.get(self.path)
        if route is None:
            self.send_error(404)
        elif callable(route):
            route(self)
        else:
            status, body, headers = route
            self.send_response(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *_args):
        pass


class _QuietServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class FeedServer:
    """A local stand-in for the chain host feed endpoint."""

    def __init__(self):
        self.httpd = _QuietServer(("127.0.0.1", 0), _Handler)
        self.httpd.routes = {}
        self.httpd.hits = []
        self.release = threading.Event()
        self._thread = threading.Thread(target=self.httpd.serve_forever,
                                        kwargs={"poll_interval": 0.01}, daemon=True)
        self._thread.start()

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.httpd.server_address[1]

    @property
    def routes(self):
        return self.httpd.routes

    @property
    def hits(self):
        return self.httpd.hits

    def serve(self, body, signature=None):
        self.routes["/feed.json"] = (200, body, [])
        self.routes["/feed.sig"] = (200, sign(body) if signature is None else signature, [])

    def close(self):
        self.release.set()
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


class PullerCase(unittest.TestCase):
    def setUp(self):
        self.server = FeedServer()
        self.addCleanup(self.server.close)
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.directory = os.path.join(scratch.name, "state")
        os.mkdir(self.directory, 0o755)
        self.output = os.path.join(self.directory, "feed.json")
        self.now = NOW
        self.monotonic = 1000.0
        self.lines = []
        self.puller = self.make_puller()

    def make_puller(self, source=None, **options):
        log = pull.RateLimitedLog(emit=self.lines.append, clock=lambda: self.monotonic)
        return pull.Puller(source or self.server.url, KEY, self.output,
                           clock=lambda: self.now, log=log, **options)

    def publish_baseline(self, generated_at=NOW - 10):
        body = encode(make_feed(generated_at))
        self.server.serve(body)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), body)
        return body

    def assert_refused(self, kind, puller=None):
        """The attempt fails with the given kind and the published file is untouched."""
        before = fingerprint(self.output)
        with self.assertRaises(pull.PullError) as caught:
            (puller or self.puller).pull_once()
        self.assertEqual(caught.exception.kind, kind, caught.exception.detail)
        self.assertEqual(fingerprint(self.output), before)
        self.assertEqual(os.listdir(self.directory), ["feed.json"])
        return caught.exception


class PublishTest(PullerCase):
    def test_valid_feed_is_published_byte_for_byte(self):
        body = encode(make_feed(NOW, blocks=120, transactions=200, validators=3))
        self.server.serve(body)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), body)
        self.assertEqual(stat.S_IMODE(os.stat(self.output).st_mode), 0o644)
        self.assertEqual(os.listdir(self.directory), ["feed.json"])
        self.assertEqual(self.server.hits, ["/feed.json", "/feed.sig"])

    def test_feed_that_marks_payments_is_published_byte_for_byte(self):
        body = encode(make_marked_feed(NOW, blocks=120, transactions=200, validators=3))
        self.server.serve(body)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), body)
        # The shape may change from one pull to the next, in either direction.
        base = encode(make_feed(NOW + 5))
        self.server.serve(base)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), base)
        marked = encode(make_marked_feed(NOW + 10))
        self.server.serve(marked)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), marked)

    def test_published_mode_is_0644_under_a_restrictive_umask(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        self.publish_baseline()
        self.assertEqual(stat.S_IMODE(os.stat(self.output).st_mode), 0o644)

    def test_signature_without_trailing_newline_is_accepted(self):
        body = encode(make_feed(NOW))
        self.server.serve(body, signature=sign(body).rstrip(b"\n"))
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)

    def test_identical_feed_is_no_change_and_is_not_rewritten(self):
        self.publish_baseline()
        before = fingerprint(self.output)
        self.assertEqual(self.puller.pull_once(), pull.UNCHANGED)
        self.assertEqual(fingerprint(self.output), before)

    def test_newer_feed_replaces_the_previous_one(self):
        self.publish_baseline(NOW - 10)
        newer = encode(make_feed(NOW - 7, status="unavailable"))
        self.server.serve(newer)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), newer)

    def test_stale_but_newer_feed_is_still_published(self):
        self.publish_baseline(NOW - 7200)
        newer = encode(make_feed(NOW - 3600, status="unavailable"))
        self.server.serve(newer)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), newer)

    def test_pair_replaced_between_the_two_requests_still_publishes(self):
        old = encode(make_feed(NOW - 10))
        new = encode(make_feed(NOW - 7))

        def swap(handler):
            # The publisher replaces both files after feed.json was read and
            # before feed.sig is answered.
            self.server.serve(new)
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(sign(new))))
            handler.end_headers()
            handler.wfile.write(sign(new))

        self.server.routes["/feed.json"] = (200, old, [])
        self.server.routes["/feed.sig"] = swap
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), new)

    def test_signature_lagging_behind_the_feed_still_publishes(self):
        old = encode(make_feed(NOW - 10))
        new = encode(make_feed(NOW - 7))
        self.server.routes["/feed.json"] = (200, new, [])
        answers = [sign(old), sign(new)]

        def lagging(handler):
            answer = answers.pop(0) if len(answers) > 1 else answers[0]
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(answer)))
            handler.end_headers()
            handler.wfile.write(answer)

        self.server.routes["/feed.sig"] = lagging
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), new)

    def test_corrupt_previous_output_is_replaced_by_a_verified_feed(self):
        with open(self.output, "wb") as stream:
            stream.write(b"{not json")
        body = encode(make_feed(NOW))
        self.server.serve(body)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), body)


class RefusalTest(PullerCase):
    def setUp(self):
        super().setUp()
        self.baseline = self.publish_baseline()

    def serve_document(self, document):
        self.server.serve(encode(document))

    def test_bad_signature(self):
        newer = encode(make_feed(NOW))
        self.server.serve(newer, signature=sign(newer, key=b"\x01" * 32))
        self.assert_refused("signature")

    def test_signature_of_a_different_body(self):
        newer = encode(make_feed(NOW))
        self.server.serve(newer, signature=sign(self.baseline))
        self.assert_refused("signature")

    def test_malformed_signatures(self):
        newer = encode(make_feed(NOW))
        good = sign(newer).strip()
        for signature in (b"", b"\n", good.upper(), good[:-1], good + b"0",
                          b" " + good, good + b" extra", b"\x00" * 64):
            with self.subTest(signature=signature):
                self.server.serve(newer, signature=signature)
                self.assert_refused("signature")

    def test_oversized_signature(self):
        newer = encode(make_feed(NOW))
        self.server.serve(newer, signature=b"a" * 4096)
        self.assert_refused("oversized")

    def test_oversized_body_with_declared_length(self):
        huge = encode(make_feed(NOW, validators=4500))
        self.assertGreater(len(huge), pull.MAX_READ_BYTES)
        self.server.serve(huge)
        self.assert_refused("oversized")

    def test_oversized_body_without_declared_length(self):
        huge = encode(make_feed(NOW, validators=4500))

        def stream(handler):
            handler.send_response(200)
            handler.end_headers()
            handler.wfile.write(huge)

        self.server.serve(huge)
        self.server.routes["/feed.json"] = stream
        self.assert_refused("oversized")

    def test_body_over_the_contract_size_is_refused(self):
        validators = 3200
        large = encode(make_feed(NOW, validators=validators))
        self.assertGreater(len(large), pull.MAX_FEED_BYTES)
        self.assertLessEqual(len(large), pull.MAX_READ_BYTES)
        self.server.serve(large)
        self.assert_refused("oversized")

    def test_wrong_format_string(self):
        document = make_feed(NOW)
        document["format"] = "zolana-explorer-feed-v1"
        self.serve_document(document)
        self.assert_refused("invalid")

    def test_extra_top_level_key(self):
        document = make_feed(NOW)
        document["notice"] = "x"
        self.serve_document(document)
        self.assert_refused("invalid")

    def test_too_many_blocks(self):
        self.serve_document(make_feed(NOW, blocks=121))
        self.assert_refused("invalid")

    def test_too_many_transactions(self):
        self.serve_document(make_feed(NOW, transactions=201))
        self.assert_refused("invalid")

    def test_signed_body_that_is_not_json(self):
        self.server.serve(b"<html>maintenance</html>")
        self.assert_refused("invalid")

    def test_older_generated_at(self):
        self.serve_document(make_feed(NOW - 11))
        error = self.assert_refused("rollback")
        self.assertIn(str(NOW - 10), error.detail)

    def test_older_generated_at_after_a_restart(self):
        self.serve_document(make_feed(NOW - 11))
        self.assert_refused("rollback", puller=self.make_puller())

    def test_rollback_is_refused_even_if_the_published_file_disappears(self):
        os.unlink(self.output)
        self.serve_document(make_feed(NOW - 11))
        with self.assertRaises(pull.PullError) as caught:
            self.puller.pull_once()
        self.assertEqual(caught.exception.kind, "rollback")
        self.assertEqual(os.listdir(self.directory), [])

    def test_same_generated_at_with_new_content_is_not_a_rollback(self):
        sibling = encode(make_feed(NOW - 10, status="unavailable"))
        self.server.serve(sibling)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), sibling)

    def test_far_future_generated_at(self):
        self.serve_document(make_feed(NOW + 121))
        self.assert_refused("future")

    def test_generated_at_up_to_120_seconds_ahead_is_accepted(self):
        body = encode(make_feed(NOW + 120))
        self.server.serve(body)
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(read_bytes(self.output), body)

    def test_unreachable_source(self):
        puller = self.make_puller(source="http://127.0.0.1:%d" % free_port())
        self.assert_refused("fetch", puller=puller)

    def test_missing_signature_file(self):
        self.serve_document(make_feed(NOW))
        del self.server.routes["/feed.sig"]
        self.assert_refused("http")

    def test_server_error(self):
        self.server.routes["/feed.json"] = (500, b"busy", [])
        self.assert_refused("http")

    def test_partial_content_status_is_refused(self):
        newer = encode(make_feed(NOW))
        self.server.serve(newer)
        self.server.routes["/feed.json"] = (206, newer, [])
        self.assert_refused("http")

    def test_redirect_is_not_followed(self):
        newer = encode(make_feed(NOW))
        self.server.serve(newer)
        self.server.routes["/moved.json"] = (200, newer, [])
        self.server.routes["/feed.json"] = (302, b"", [("Location", "/moved.json")])
        del self.server.hits[:]
        self.assert_refused("http")
        self.assertNotIn("/moved.json", self.server.hits)

    def test_truncated_body(self):
        newer = encode(make_feed(NOW))

        def truncated(handler):
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(newer)))
            handler.end_headers()
            handler.wfile.write(newer[:len(newer) // 2])

        self.server.serve(newer)
        self.server.routes["/feed.json"] = truncated
        self.assert_refused("fetch")

    def test_stalled_source_times_out(self):
        newer = encode(make_feed(NOW))

        def stalled(handler):
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(newer)))
            handler.end_headers()
            handler.wfile.write(newer[:10])
            handler.wfile.flush()
            self.server.release.wait(10)

        self.server.serve(newer)
        self.server.routes["/feed.json"] = stalled
        started = time.monotonic()
        self.assert_refused("fetch", puller=self.make_puller(timeout=0.3))
        self.assertLess(time.monotonic() - started, 5)

    def test_output_that_is_a_symlink_is_refused(self):
        real = os.path.join(self.directory, "real.json")
        os.replace(self.output, real)
        os.symlink(real, self.output)
        self.serve_document(make_feed(NOW))
        with self.assertRaises(pull.PullError) as caught:
            self.make_puller().pull_once()
        self.assertEqual(caught.exception.kind, "write")
        self.assertTrue(os.path.islink(self.output))
        self.assertEqual(read_bytes(real), self.baseline)


class AtomicityTest(PullerCase):
    def test_replacement_is_a_complete_fsynced_file_in_the_same_directory(self):
        old = self.publish_baseline()
        new = encode(make_feed(NOW, blocks=120, transactions=200))
        self.server.serve(new)
        events = []
        real_replace, real_fsync = os.replace, os.fsync

        def checked_fsync(fd):
            events.append("fsync")
            return real_fsync(fd)

        def checked_replace(source, target):
            events.append("replace")
            self.assertEqual(target, self.output)
            self.assertEqual(os.path.dirname(source), self.directory)
            self.assertNotEqual(source, target)
            self.assertEqual(read_bytes(source), new)
            self.assertEqual(stat.S_IMODE(os.stat(source).st_mode), 0o644)
            self.assertEqual(read_bytes(target), old)
            return real_replace(source, target)

        with mock.patch.object(pull.os, "fsync", checked_fsync), \
                mock.patch.object(pull.os, "replace", checked_replace):
            self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        self.assertEqual(events[:2], ["fsync", "replace"])
        self.assertEqual(read_bytes(self.output), new)
        self.assertEqual(os.listdir(self.directory), ["feed.json"])

    def test_failed_write_keeps_the_previous_file_and_leaves_no_temp_file(self):
        self.publish_baseline()
        self.server.serve(encode(make_feed(NOW)))
        for name in ("replace", "fsync"):
            with self.subTest(failing=name):
                with mock.patch.object(pull.os, name, side_effect=OSError(28, "No space left")):
                    self.assert_refused("write")

    def test_concurrent_reader_never_sees_a_partial_file(self):
        bodies = [encode(make_feed(NOW - 100 + index, blocks=120, transactions=200))
                  for index in range(60)]
        valid = set(bodies)
        self.server.serve(bodies[0])
        self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        stop = threading.Event()
        observed = {"reads": 0, "bad": []}

        def reader():
            while not stop.is_set():
                try:
                    data = read_bytes(self.output)
                except OSError as exc:
                    observed["bad"].append(repr(exc))
                    continue
                observed["reads"] += 1
                if data not in valid:
                    observed["bad"].append("%d unexpected bytes" % len(data))

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        try:
            for body in bodies[1:]:
                self.server.serve(body)
                self.assertEqual(self.puller.pull_once(), pull.PUBLISHED)
        finally:
            stop.set()
            thread.join(10)
        self.assertEqual(observed["bad"], [])
        self.assertGreater(observed["reads"], 0)
        self.assertEqual(read_bytes(self.output), bodies[-1])
        self.assertEqual(os.listdir(self.directory), ["feed.json"])

    def test_stale_temp_files_are_removed_and_fresh_ones_kept(self):
        stale = os.path.join(self.directory, ".feed.json.abc123.tmp")
        fresh = os.path.join(self.directory, ".feed.json.def456.tmp")
        other = os.path.join(self.directory, "notes.tmp")
        for path in (stale, fresh, other):
            with open(path, "wb") as stream:
                stream.write(b"partial")
        long_ago = time.time() - 3600
        os.utime(stale, (long_ago, long_ago))
        os.utime(other, (long_ago, long_ago))
        pull.remove_stale_temp_files(self.output)
        self.assertEqual(sorted(os.listdir(self.directory)),
                         [".feed.json.def456.tmp", "notes.tmp"])


class ContractTest(unittest.TestCase):
    def check(self, document):
        return pull.validate_feed(pull.parse_feed(encode(document)))

    def assert_invalid(self, document):
        with self.assertRaises(pull.PullError) as caught:
            self.check(document)
        self.assertEqual(caught.exception.kind, "invalid")

    def test_full_feed_is_valid_and_returns_generated_at(self):
        self.assertEqual(self.check(make_feed(NOW, blocks=120, transactions=200)), NOW)

    def test_feed_that_marks_payments_is_valid(self):
        self.assertEqual(self.check(make_marked_feed(NOW, blocks=120, transactions=200, validators=3)), NOW)
        document = make_marked_feed(NOW, blocks=2, transactions=7)
        document["network"]["validators"][0]["root_slot"] = None
        document["blocks"][0].update(tx_count=5, payment_tx_count=5, executed_payment_count=5)
        document["blocks"][1].update(payment_tx_count=0, executed_payment_count=0)
        document["transactions"][0]["payment_instructions"] = list(pull.PAYMENT_INSTRUCTIONS)
        document["stats"].update(payment_transactions_seen=0, executed_payments_seen=0, payments_since=0)
        self.assertEqual(self.check(document), NOW)
        document["blocks"] = []
        document["transactions"] = []
        document["network"]["validators"] = []
        self.assertEqual(self.check(document), NOW)

    def test_a_feed_marks_payments_everywhere_or_nowhere(self):
        places = {
            "validator": (lambda d: d["network"]["validators"][0], {"root_slot": 5}),
            "block": (lambda d: d["blocks"][1], {"payment_tx_count": 0, "executed_payment_count": 0}),
            "transaction": (lambda d: d["transactions"][2], {"payment_instructions": []}),
            "stats": (lambda d: d["stats"], {"payments_since": NOW, "payment_transactions_seen": 0,
                                             "executed_payments_seen": 0}),
        }
        for label, (locate, fields) in places.items():
            for key, value in fields.items():
                with self.subTest(place=label, base_feed_with=key):
                    document = make_feed(NOW)
                    locate(document)[key] = value
                    self.assert_invalid(document)
                with self.subTest(place=label, marked_feed_without=key):
                    document = make_marked_feed(NOW)
                    del locate(document)[key]
                    self.assert_invalid(document)
        # One counter alone in the stats is enough to hold the whole feed to the marked shape.
        document = make_feed(NOW)
        document["stats"].update(places["stats"][1])
        self.assert_invalid(document)

    def test_malformed_payment_fields_are_rejected(self):
        def at(locate, key, value):
            return lambda d: locate(d).__setitem__(key, value)

        validator = lambda d: d["network"]["validators"][0]    # noqa: E731
        block = lambda d: d["blocks"][0]                       # noqa: E731
        transaction = lambda d: d["transactions"][0]           # noqa: E731
        stats = lambda d: d["stats"]                           # noqa: E731
        mutations = {
            "root_slot negative": at(validator, "root_slot", -1),
            "root_slot string": at(validator, "root_slot", "12"),
            "root_slot bool": at(validator, "root_slot", True),
            "root_slot 2**53": at(validator, "root_slot", 2 ** 53),
            "payment_tx_count string": at(block, "payment_tx_count", "1"),
            "payment_tx_count float": at(block, "payment_tx_count", 1.0),
            "payment_tx_count negative": at(block, "payment_tx_count", -1),
            "payment_tx_count above tx_count": at(block, "payment_tx_count", 4),
            "payment_tx_count null alone": at(block, "payment_tx_count", None),
            "executed_payment_count bool": at(block, "executed_payment_count", False),
            "executed_payment_count null alone": at(block, "executed_payment_count", None),
            "executed_payment_count above payment_tx_count": at(block, "executed_payment_count", 2),
            "payment_instructions string": at(transaction, "payment_instructions", "finalize"),
            "payment_instructions object": at(transaction, "payment_instructions", {"finalize": True}),
            "payment_instructions number": at(transaction, "payment_instructions", 3),
            "payment_instructions false": at(transaction, "payment_instructions", False),
            "payment_instructions unknown name": at(transaction, "payment_instructions", ["deposit"]),
            "payment_instructions opcode number": at(transaction, "payment_instructions", [3]),
            "payment_instructions null entry": at(transaction, "payment_instructions", [None]),
            "payment_instructions wrong case": at(transaction, "payment_instructions", ["Finalize"]),
            "payment_instructions repeated": at(transaction, "payment_instructions", ["write", "write"]),
            "payment_instructions out of order": at(transaction, "payment_instructions", ["close", "finalize"]),
            "payment_instructions too many": at(transaction, "payment_instructions",
                                                list(pull.PAYMENT_INSTRUCTIONS) + ["unknown"]),
            "payment_instructions nested": at(transaction, "payment_instructions", [["finalize"]]),
            "payments_since null": at(stats, "payments_since", None),
            "payments_since float": at(stats, "payments_since", 1.5),
            "payment_transactions_seen negative": at(stats, "payment_transactions_seen", -1),
            "payment_transactions_seen string": at(stats, "payment_transactions_seen", "3"),
            "executed_payments_seen bool": at(stats, "executed_payments_seen", True),
            "executed_payments_seen above payment_transactions_seen": at(stats, "executed_payments_seen", 32),
        }
        self.assertEqual(self.check(make_marked_feed(NOW)), NOW)
        for label, mutate in mutations.items():
            with self.subTest(case=label):
                document = make_marked_feed(NOW)
                mutate(document)
                self.assert_invalid(document)

    def test_empty_and_null_variants_are_valid(self):
        document = make_feed(NOW, blocks=1, transactions=1)
        document["genesis_hash"] = None
        network = document["network"]
        network.update(status="unavailable", tip_slot=None, finalized_slot=None,
                       block_height=None, slot_time_ms=None, last_block_at=None)
        network["validators"][0].update(vote_account=None, last_vote=None, active=False)
        document["blocks"][0].update(parent_slot=None, block_time=None, block_height=None)
        document["transactions"][0].update(block_time=None, kind="vote", ok=False, fee=0)
        self.assertEqual(self.check(document), NOW)
        document["network"]["validators"] = []
        document["blocks"] = []
        document["transactions"] = []
        self.assertEqual(self.check(document), NOW)

    def test_boundary_values_are_valid(self):
        document = make_feed(NOW)
        document["genesis_hash"] = "A" * 127
        document["network"]["tip_slot"] = 2 ** 53 - 1
        document["network"]["slot_time_ms"] = 400
        document["transactions"][0]["fee"] = 0
        self.assertEqual(self.check(document), NOW)

    def test_every_key_is_required_and_no_other_key_is_allowed(self):
        places = {
            "top level": lambda d: d,
            "network": lambda d: d["network"],
            "validator": lambda d: d["network"]["validators"][0],
            "block": lambda d: d["blocks"][0],
            "transaction": lambda d: d["transactions"][0],
            "stats": lambda d: d["stats"],
        }
        for make in (make_feed, make_marked_feed):
            for label, locate in places.items():
                for key in list(locate(make(NOW))):
                    with self.subTest(shape=make.__name__, place=label, missing=key):
                        document = make(NOW)
                        del locate(document)[key]
                        self.assert_invalid(document)
                with self.subTest(shape=make.__name__, place=label, extra=True):
                    document = make(NOW)
                    locate(document)["extra"] = 1
                    self.assert_invalid(document)

    def test_wrong_types_ranges_and_enums_are_rejected(self):
        def top(key, value):
            return lambda d: d.__setitem__(key, value)

        def at(locate, key, value):
            return lambda d: locate(d).__setitem__(key, value)

        network = lambda d: d["network"]                       # noqa: E731
        validator = lambda d: d["network"]["validators"][0]    # noqa: E731
        block = lambda d: d["blocks"][0]                       # noqa: E731
        transaction = lambda d: d["transactions"][-1]          # noqa: E731
        stats = lambda d: d["stats"]                           # noqa: E731
        mutations = {
            "format other version": top("format", "zolana-explorer-feed-v1"),
            "format with suffix": top("format", "zolana-explorer-feed-v0 "),
            "format not a string": top("format", 0),
            "generated_at negative": top("generated_at", -1),
            "generated_at 2**53": top("generated_at", 2 ** 53),
            "generated_at float": top("generated_at", 1800000000.5),
            "generated_at string": top("generated_at", "1800000000"),
            "generated_at bool": top("generated_at", True),
            "generated_at null": top("generated_at", None),
            "genesis_hash 128 chars": top("genesis_hash", "A" * 128),
            "genesis_hash markup": top("genesis_hash", "<script>alert(1)</script>"),
            "genesis_hash non-ASCII": top("genesis_hash", "häsh"),
            "genesis_hash number": top("genesis_hash", 7),
            "network not an object": top("network", []),
            "blocks not an array": top("blocks", {}),
            "transactions not an array": top("transactions", "none"),
            "stats not an object": top("stats", None),
            "status unknown": at(network, "status", "paused"),
            "status wrong case": at(network, "status", "Live"),
            "status null": at(network, "status", None),
            "tip_slot bool": at(network, "tip_slot", True),
            "tip_slot negative": at(network, "tip_slot", -1),
            "finalized_slot string": at(network, "finalized_slot", "12"),
            "block_height float": at(network, "block_height", 12.0),
            "slot_time_ms negative": at(network, "slot_time_ms", -0.5),
            "slot_time_ms string": at(network, "slot_time_ms", "412.5"),
            "slot_time_ms bool": at(network, "slot_time_ms", False),
            "slot_time_ms too large": at(network, "slot_time_ms", 1e300),
            "last_block_at 2**53": at(network, "last_block_at", 2 ** 53),
            "validators not an array": at(network, "validators", {}),
            "validator not an object": at(network, "validators", ["x"]),
            "identity null": at(validator, "identity", None),
            "identity 128 chars": at(validator, "identity", "B" * 128),
            "vote_account number": at(validator, "vote_account", 5),
            "last_vote negative": at(validator, "last_vote", -3),
            "active number": at(validator, "active", 1),
            "active null": at(validator, "active", None),
            "block not an object": top("blocks", [7]),
            "slot null": at(block, "slot", None),
            "slot string": at(block, "slot", "250000"),
            "parent_slot bool": at(block, "parent_slot", False),
            "blockhash null": at(block, "blockhash", None),
            "blockhash with space": at(block, "blockhash", "abc def"),
            "block_time negative": at(block, "block_time", -1),
            "block_height 2**53": at(block, "block_height", 2 ** 53),
            "tx_count null": at(block, "tx_count", None),
            "non_vote_tx_count float": at(block, "non_vote_tx_count", 1.5),
            "transaction not an object": top("transactions", [None]),
            "signature null": at(transaction, "signature", None),
            "signature 128 chars": at(transaction, "signature", "C" * 128),
            "tx slot null": at(transaction, "slot", None),
            "ok string": at(transaction, "ok", "true"),
            "ok number": at(transaction, "ok", 0),
            "fee negative": at(transaction, "fee", -1),
            "fee null": at(transaction, "fee", None),
            "fee 2**53": at(transaction, "fee", 2 ** 53),
            "kind unknown": at(transaction, "kind", "transfer"),
            "kind null": at(transaction, "kind", None),
            "since null": at(stats, "since", None),
            "blocks_seen negative": at(stats, "blocks_seen", -1),
            "transactions_seen string": at(stats, "transactions_seen", "9"),
            "non_vote_transactions_seen bool": at(stats, "non_vote_transactions_seen", True),
        }
        for make in (make_feed, make_marked_feed):
            for label, mutate in mutations.items():
                with self.subTest(shape=make.__name__, case=label):
                    document = make(NOW)
                    mutate(document)
                    self.assert_invalid(document)

    def test_array_caps(self):
        self.assertEqual(self.check(make_feed(NOW, blocks=120, transactions=0)), NOW)
        self.assertEqual(self.check(make_feed(NOW, blocks=0, transactions=200)), NOW)
        self.assert_invalid(make_feed(NOW, blocks=121))
        self.assert_invalid(make_feed(NOW, transactions=201))
        self.assertEqual(self.check(make_marked_feed(NOW, blocks=120, transactions=200)), NOW)
        self.assert_invalid(make_marked_feed(NOW, blocks=121))
        self.assert_invalid(make_marked_feed(NOW, transactions=201))

    def test_top_level_must_be_an_object(self):
        for value in ([], "feed", 1, None, True):
            with self.subTest(value=value):
                self.assert_invalid(value)

    def test_strict_json_parsing(self):
        good = encode(make_feed(NOW))
        self.assertEqual(pull.parse_feed(good), make_feed(NOW))
        nested = b"[" * 200000 + b"]" * 200000
        cases = {
            "not json": b"feed",
            "empty": b"",
            "trailing data": good + b"{}",
            "byte order mark": b"\xef\xbb\xbf" + good,
            "invalid UTF-8": good.replace(b"live", b"l\xffve"),
            "duplicate key": good[:-1] + b',"format":"zolana-explorer-feed-v0"}',
            "NaN": good.replace(b"412.5", b"NaN"),
            "Infinity": good.replace(b"412.5", b"Infinity"),
            "negative infinity": good.replace(b"412.5", b"-Infinity"),
            "deep nesting": nested,
        }
        for label, body in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(pull.PullError) as caught:
                    pull.parse_feed(body)
                self.assertEqual(caught.exception.kind, "invalid")

    def test_overflowing_number_is_rejected(self):
        body = encode(make_feed(NOW)).replace(b"412.5", b"1e999")
        with self.assertRaises(pull.PullError) as caught:
            pull.validate_feed(pull.parse_feed(body))
        self.assertEqual(caught.exception.kind, "invalid")

    def test_validation_does_not_modify_the_document(self):
        for make in (make_feed, make_marked_feed):
            document = make(NOW)
            snapshot = copy.deepcopy(document)
            pull.validate_feed(document)
            self.assertEqual(document, snapshot)


class SourceUrlTest(unittest.TestCase):
    def test_accepts_http_ipv4_with_port(self):
        self.assertEqual(pull.parse_source("http://203.0.113.10:18080"),
                         "http://203.0.113.10:18080")
        self.assertEqual(pull.parse_source("http://127.0.0.1:1"), "http://127.0.0.1:1")
        self.assertEqual(pull.parse_source("http://10.0.0.255:65535"),
                         "http://10.0.0.255:65535")

    def test_rejects_everything_else(self):
        rejected = [
            "https://203.0.113.10:18080",          # https
            "HTTP://203.0.113.10:18080",
            "ftp://203.0.113.10:18080",
            "file:///etc/hostname",
            "203.0.113.10:18080",                  # no scheme
            "http://explorer.example:18080",       # host names
            "http://localhost:18080",
            "http://203.0.113.10",                 # missing port
            "http://203.0.113.10:",
            "http://203.0.113.10:18080/",          # paths
            "http://203.0.113.10:18080/feed.json",
            "http://203.0.113.10:18080/a/../b",
            "http://203.0.113.10:18080?x=1",       # query and fragment
            "http://203.0.113.10:18080#top",
            "http://user@203.0.113.10:18080",      # credentials
            "http://user:pw@203.0.113.10:18080",
            "http://[::1]:18080",                  # IPv6
            "http://203.0.113:18080",              # not dotted quad
            "http://203.0.113.10.5:18080",
            "http://203.0.113.256:18080",          # octet out of range
            "http://203.0.113.010:18080",          # leading zero
            "http://0x7f.0.0.1:18080",
            "http://2130706433:18080",
            "http://203.0.113.10:0",               # port out of range
            "http://203.0.113.10:65536",
            "http://203.0.113.10:018080",
            "http://203.0.113.10:18080 ",
            " http://203.0.113.10:18080",
            "http://203.0.113.10:18080\n",
            "http://203.0.113.10:18080\r\nHost: x",
            "http://١٢٣.0.0.1:18080",   # non-ASCII digits
            "SOURCE_URL",
            "",
        ]
        for value in rejected:
            with self.subTest(source=value):
                with self.assertRaises(pull.ConfigError):
                    pull.parse_source(value)
        with self.assertRaises(pull.ConfigError):
            pull.parse_source(None)


class KeyFileTest(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.path = os.path.join(scratch.name, "hmac.key")

    def write(self, content, mode):
        if os.path.lexists(self.path):
            os.unlink(self.path)
        with open(self.path, "wb") as stream:
            stream.write(content)
        os.chmod(self.path, mode)

    def test_owner_only_key_is_accepted(self):
        for mode in (0o600, 0o400):
            with self.subTest(mode=oct(mode)):
                self.write(KEY, mode)
                self.assertEqual(pull.load_key(self.path), KEY)

    def test_group_readable_key_is_accepted_like_a_systemd_credential(self):
        # systemd credential files are mode 0400 plus an access-control entry
        # for the service user, which stat reports as 0440.
        self.write(KEY, 0o440)
        self.assertEqual(pull.load_key(self.path), KEY)

    def test_key_is_the_exact_file_content(self):
        # Nothing is trimmed or decoded: the publisher signs with the raw bytes.
        for content in (KEY.hex().encode("ascii") + b"\n", b" " + KEY + b"\r\n",
                        bytes(range(256)) * 16):
            with self.subTest(size=len(content)):
                self.write(content, 0o600)
                self.assertEqual(pull.load_key(self.path), content)

    def test_world_accessible_key_is_refused(self):
        for mode in (0o644, 0o604, 0o444, 0o666, 0o602, 0o601, 0o647):
            with self.subTest(mode=oct(mode)):
                self.write(KEY, mode)
                with self.assertRaises(pull.ConfigError) as caught:
                    pull.load_key(self.path)
                self.assertIn("other users", str(caught.exception))

    def test_group_access_other_than_a_credential_file_is_refused(self):
        for mode in (0o640, 0o660, 0o460, 0o420, 0o410, 0o450):
            with self.subTest(mode=oct(mode)):
                self.write(KEY, mode)
                with self.assertRaises(pull.ConfigError) as caught:
                    pull.load_key(self.path)
                self.assertIn("group", str(caught.exception))

    def test_key_length_limits(self):
        for content in (b"", KEY[:31], KEY * 128 + b"\x00"):
            with self.subTest(size=len(content)):
                self.write(content, 0o600)
                with self.assertRaises(pull.ConfigError):
                    pull.load_key(self.path)
        for content in (KEY, KEY + b"\x00", KEY * 128):
            with self.subTest(size=len(content)):
                self.write(content, 0o600)
                self.assertEqual(pull.load_key(self.path), content)

    def test_missing_key_and_non_regular_key_are_refused(self):
        with self.assertRaises(pull.ConfigError):
            pull.load_key(self.path)
        with self.assertRaises(pull.ConfigError):
            pull.load_key(os.path.dirname(self.path))

    def test_owner_and_file_type_rules(self):
        regular = stat.S_IFREG
        self.assertIsNone(pull.key_file_problem(regular | 0o600, 1000, 1000))
        self.assertIsNone(pull.key_file_problem(regular | 0o400, 0, 1000))
        self.assertIsNone(pull.key_file_problem(regular | 0o440, 0, 1000))
        self.assertIsNone(pull.key_file_problem(regular | 0o440, 1000, 1000))
        self.assertIn("another user", pull.key_file_problem(regular | 0o600, 1001, 1000))
        self.assertIn("another user", pull.key_file_problem(regular | 0o400, 1000, 0))
        for kind in (stat.S_IFDIR, stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR):
            with self.subTest(kind=oct(kind)):
                self.assertIn("regular", pull.key_file_problem(kind | 0o600, 1000, 1000))

    def test_error_messages_never_contain_key_material(self):
        secret = b"s3cr3t-material-" * 4
        self.write(secret, 0o644)
        with self.assertRaises(pull.ConfigError) as caught:
            pull.load_key(self.path)
        self.assertNotIn("s3cr3t", str(caught.exception))
        self.write(secret[:20], 0o600)
        with self.assertRaises(pull.ConfigError) as caught:
            pull.load_key(self.path)
        self.assertNotIn("s3cr3t", str(caught.exception))


class LoggingTest(PullerCase):
    def test_one_line_per_kind_per_30_seconds(self):
        self.puller = self.make_puller(source="http://127.0.0.1:%d" % free_port())
        for _ in range(5):
            self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
            self.monotonic += 3
        self.assertEqual(len(self.lines), 1)
        self.assertTrue(self.lines[0].startswith("error fetch: "), self.lines)
        self.assertNotIn("\n", self.lines[0])
        self.monotonic = 1000.0 + 30
        self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
        self.assertEqual(len(self.lines), 2)
        self.assertIn("(4 similar suppressed)", self.lines[1])

    def test_kinds_are_limited_independently(self):
        body = encode(make_feed(NOW))
        self.server.serve(body, signature=b"0" * 64 + b"\n")
        self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
        self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
        document = make_feed(NOW)
        document["format"] = "other"
        self.server.serve(encode(document))
        self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
        self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
        self.assertEqual([line.split(":")[0] for line in self.lines],
                         ["error signature", "error invalid"])

    def test_success_is_logged_once_and_again_after_recovery(self):
        self.server.serve(encode(make_feed(NOW - 10)))
        self.assertEqual(self.puller.attempt(), pull.EXIT_PUBLISHED)
        self.assertEqual(self.puller.attempt(), pull.EXIT_UNCHANGED)
        self.server.serve(encode(make_feed(NOW - 7)))
        self.assertEqual(self.puller.attempt(), pull.EXIT_PUBLISHED)
        self.assertEqual(len(self.lines), 1)
        self.assertTrue(self.lines[0].startswith("ok: feed published"), self.lines)
        self.server.routes["/feed.json"] = (503, b"", [])
        self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
        self.monotonic += 60
        self.server.serve(encode(make_feed(NOW - 4)))
        self.assertEqual(self.puller.attempt(), pull.EXIT_PUBLISHED)
        self.assertEqual([line.split(":")[0] for line in self.lines],
                         ["ok", "error http", "ok"])

    def test_log_lines_are_single_line_printable_and_bounded(self):
        document = make_feed(NOW)
        document["<img src=x onerror=alert(1)>\n"] = 1
        self.server.serve(encode(document))
        self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
        self.assertEqual(len(self.lines), 1)
        line = self.lines[0]
        self.assertNotIn("\n", line)
        self.assertNotIn(KEY.hex(), line)
        self.assertLess(len(line), 200)
        self.assertTrue(all(32 <= ord(ch) < 127 for ch in line), line)

    def test_unexpected_exception_does_not_escape_attempt(self):
        with mock.patch.object(self.puller, "pull_once", side_effect=RuntimeError("boom")):
            self.assertEqual(self.puller.attempt(), pull.EXIT_ERROR)
        self.assertEqual(self.lines, ["error internal: RuntimeError"])


class LoopTest(PullerCase):
    def test_loop_publishes_updates_survives_failures_and_stops(self):
        first = encode(make_feed(NOW - 10))
        self.server.serve(first)
        stop = threading.Event()
        thread = threading.Thread(target=pull.run_loop, args=(self.puller, 0.02, stop),
                                  daemon=True)
        thread.start()
        try:
            self.wait_for(first)
            broken = encode(make_feed(NOW - 8))
            self.server.serve(broken, signature=b"f" * 64 + b"\n")
            time.sleep(0.15)
            self.assertEqual(read_bytes(self.output), first)
            second = encode(make_feed(NOW - 5))
            self.server.serve(second)
            self.wait_for(second)
        finally:
            stop.set()
            thread.join(10)
        self.assertFalse(thread.is_alive())

    def wait_for(self, expected):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if os.path.exists(self.output) and read_bytes(self.output) == expected:
                return
            time.sleep(0.01)
        self.fail("the expected feed was not published in time")


class CommandLineTest(unittest.TestCase):
    def setUp(self):
        self.server = FeedServer()
        self.addCleanup(self.server.close)
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.directory = os.path.join(scratch.name, "state")
        os.mkdir(self.directory, 0o755)
        self.output = os.path.join(self.directory, "feed.json")
        self.key_file = os.path.join(scratch.name, "hmac.key")
        with open(self.key_file, "wb") as stream:
            stream.write(KEY)
        os.chmod(self.key_file, 0o600)

    def command(self, *extra, source=None, key_file=None, output=None):
        return [sys.executable, "-I", "-B", SCRIPT,
                "--source", source or self.server.url,
                "--hmac-key-file", key_file or self.key_file,
                "--output", output or self.output] + list(extra)

    def run_once(self, **options):
        environment = dict(os.environ, http_proxy="http://127.0.0.1:9",
                           HTTP_PROXY="http://127.0.0.1:9", all_proxy="http://127.0.0.1:9")
        return subprocess.run(self.command("--once", **options), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=60, env=environment)

    def test_once_exit_codes(self):
        current = int(time.time())
        first = encode(make_feed(current - 5))
        self.server.serve(first)

        result = self.run_once()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(read_bytes(self.output), first)
        self.assertEqual(stat.S_IMODE(os.stat(self.output).st_mode), 0o644)
        self.assertIn(b"ok: feed published", result.stderr)

        result = self.run_once()
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn(b"ok: feed unchanged", result.stderr)

        newer = encode(make_feed(current - 2))
        self.server.serve(newer, signature=b"0" * 64 + b"\n")
        result = self.run_once()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stderr.count(b"\n"), 1)
        self.assertIn(b"error signature", result.stderr)
        self.assertEqual(read_bytes(self.output), first)

        self.server.serve(encode(make_feed(current - 60)))
        result = self.run_once()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"error rollback", result.stderr)
        self.assertEqual(read_bytes(self.output), first)

        self.server.serve(encode(make_feed(current + 3600)))
        result = self.run_once()
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"error future", result.stderr)
        self.assertEqual(read_bytes(self.output), first)

        self.server.serve(newer)
        result = self.run_once()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(read_bytes(self.output), newer)
        self.assertEqual(os.listdir(self.directory), ["feed.json"])

    def test_text_key_file_is_used_byte_for_byte(self):
        text_key = KEY.hex().encode("ascii") + b"\n"
        path = self.key_file + ".text"
        with open(path, "wb") as stream:
            stream.write(text_key)
        os.chmod(path, 0o600)
        body = encode(make_feed(int(time.time())))
        self.server.serve(body, signature=sign(body, key=text_key))
        result = self.run_once(key_file=path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(read_bytes(self.output), body)

    def test_once_exits_1_when_the_source_is_unreachable(self):
        result = self.run_once(source="http://127.0.0.1:%d" % free_port())
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(b"error fetch", result.stderr)
        self.assertEqual(os.listdir(self.directory), [])

    def test_rejected_arguments_exit_2_without_contacting_the_source(self):
        port = self.server.httpd.server_address[1]
        world_readable = self.key_file + ".open"
        with open(world_readable, "wb") as stream:
            stream.write(KEY)
        os.chmod(world_readable, 0o644)
        cases = {
            "https": {"source": "https://127.0.0.1:%d" % port},
            "host name": {"source": "http://localhost:%d" % port},
            "missing port": {"source": "http://127.0.0.1"},
            "path": {"source": "http://127.0.0.1:%d/feed.json" % port},
            "unit placeholder": {"source": "SOURCE_URL"},
            "world-readable key": {"key_file": world_readable},
            "missing key": {"key_file": self.key_file + ".absent"},
            "missing output directory": {"output": os.path.join(self.directory, "no", "feed.json")},
        }
        self.server.serve(encode(make_feed(int(time.time()))))
        for label, options in cases.items():
            with self.subTest(case=label):
                result = self.run_once(**options)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b"configuration error", result.stderr)
        self.assertEqual(self.server.hits, [])
        self.assertEqual(os.listdir(self.directory), [])

    def test_missing_required_flags_and_bad_interval_exit_2(self):
        for arguments in (["--once"],
                          ["--source", self.server.url, "--once"],
                          ["--hmac-key-file", self.key_file, "--once"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, "-I", "-B", SCRIPT] + arguments,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        timeout=60)
                self.assertEqual(result.returncode, 2, result.stderr)
        for interval in ("0", "-3", "nan", "inf", "0.01", "86400"):
            with self.subTest(interval=interval):
                result = subprocess.run(self.command("--once", "--interval", interval),
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        timeout=60)
                self.assertEqual(result.returncode, 2, result.stderr)

    def test_service_loop_publishes_and_stops_cleanly_on_sigterm(self):
        first = encode(make_feed(int(time.time()) - 5))
        self.server.serve(first)
        process = subprocess.Popen(self.command("--interval", "1"), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            self.wait_for(first)
            second = encode(make_feed(int(time.time())))
            self.server.serve(second)
            self.wait_for(second)
            process.send_signal(signal.SIGTERM)
            _, stderr = process.communicate(timeout=30)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        self.assertEqual(process.returncode, 0, stderr)
        self.assertIn(b"stopped", stderr)
        self.assertEqual(read_bytes(self.output), second)

    def wait_for(self, expected):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if os.path.exists(self.output) and read_bytes(self.output) == expected:
                return
            time.sleep(0.05)
        self.fail("the expected feed was not published in time")


class ServiceUnitTest(unittest.TestCase):
    """The unit file must keep the settings the deployment relies on."""

    def setUp(self):
        with open(os.path.join(HERE, "zolana-explorer-pull-v0.service"), encoding="utf-8") as stream:
            self.lines = [line.strip() for line in stream
                          if line.strip() and not line.lstrip().startswith("#")]

    def test_required_directives_are_present(self):
        required = [
            "User=zolana-explorer",
            "Group=zolana-explorer",
            "StateDirectory=zolana-explorer-pull-v0",
            "StateDirectoryMode=0755",
            "UMask=0022",
            "LoadCredential=hmac:/etc/zolana-explorer-pull-v0/hmac.key",
            "NoNewPrivileges=yes",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
            "MemoryMax=64M",
            "CPUQuota=10%",
            "Restart=always",
            "RestartSec=3",
        ]
        for directive in required:
            with self.subTest(directive=directive):
                self.assertEqual(self.lines.count(directive), 1)

    def test_exec_start_runs_the_puller_with_the_credential_and_placeholder(self):
        commands = [line for line in self.lines if line.startswith("ExecStart=")]
        self.assertEqual(commands, [
            "ExecStart=/usr/bin/python3 -I -B /opt/zolana-explorer-pull-v0/explorer_pull_v0.py "
            "--source SOURCE_URL --hmac-key-file %d/hmac"])

    def test_placeholder_is_rejected_until_it_is_replaced(self):
        with self.assertRaises(pull.ConfigError):
            pull.parse_source("SOURCE_URL")

    def test_default_output_lives_in_the_state_directory(self):
        self.assertEqual(pull.DEFAULT_OUTPUT, "/var/lib/zolana-explorer-pull-v0/feed.json")
        self.assertEqual(pull.DEFAULT_INTERVAL, 3.0)
        self.assertEqual(pull.HTTP_TIMEOUT, 4.0)


if __name__ == "__main__":
    unittest.main()
