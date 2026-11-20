"""What bulk authorization changes in the gateway handler for the cohort service.

The cohort service constructs the gateway with `authorize_many=True`. These
cases call the real request-authorization method with a recording stand-in for
the faucet process, so no native binary runs.
"""
import base64
from email.message import Message
import json
import types
import unittest

import testnet_gateway as gateway
from wallet_sync_snapshot import PREPAID_UNITS

PROOF = {"signature": "stand-in"}
ADDRESS = "1" * 32


class Recorder:
    def __init__(self, limit=None):
        self.calls, self.limit, self.used = [], limit, 0

    def command(self, name, data=None, extra=()):
        self.calls.append((name, data, list(extra)))
        units = int(extra[1]) if name == "authorize-many" else 1
        if self.limit is not None and self.used + units > self.limit:
            raise ValueError("request quota exhausted")
        self.used += units
        return {"authorized": True, "units": units} if name == "authorize-many" else {"authorized": True}


def authorize(request, bulk, limit=None):
    handler = object.__new__(gateway.Handler)
    handler.headers = Message()
    handler.headers["X-Testnet-Access"] = base64.urlsafe_b64encode(json.dumps(PROOF).encode()).decode().rstrip("=")
    faucet = Recorder(limit)
    handler.server = types.SimpleNamespace(app=types.SimpleNamespace(faucet=faucet, authorize_many=bulk))
    try:
        handler._authorize_rpc_request(dict(jsonrpc="2.0", id=1, **request))
        return faucet, None
    except ValueError as error:
        return faucet, str(error)


SNAPSHOT = dict(method="getWalletSyncSnapshot", params=[0])
BATCH = dict(method="getWalletReadBatch", params=[[dict(method="getBalance", params=[ADDRESS, {"commitment": "confirmed"}])] * 16])
HISTORY = dict(method="getWalletHistoryBlocks", params=[list(range(1, 257))])
SINGLE = dict(method="getBalance", params=[ADDRESS, {"commitment": "confirmed"}])


class BulkAuthorization(unittest.TestCase):
    def test_one_ledger_write_replaces_one_per_unit_and_debits_the_same_units(self):
        self.assertEqual(PREPAID_UNITS, 21)
        for request, units in ((SNAPSHOT, 21), (BATCH, 16), (HISTORY, 16)):
            with self.subTest(method=request["method"]):
                before, error = authorize(request, False)
                self.assertIsNone(error)
                self.assertEqual(before.calls, [("authorize", PROOF, [])] * units)
                after, error = authorize(request, True)
                self.assertIsNone(error)
                self.assertEqual(after.calls, [("authorize-many", PROOF, ["--units", str(units)])])
                self.assertEqual((before.used, after.used), (units, units))

    def test_single_unit_requests_are_unchanged(self):
        for bulk in (False, True):
            faucet, error = authorize(SINGLE, bulk)
            self.assertIsNone(error)
            self.assertEqual(faucet.calls, [("authorize", PROOF, [])])

    def test_exhausted_quota_refuses_the_request_in_both_modes(self):
        # One unit short of a snapshot. Per-unit debits consume the remainder
        # before refusing; the bulk debit refuses whole and consumes nothing.
        for bulk, consumed in ((False, 20), (True, 0)):
            faucet, error = authorize(SNAPSHOT, bulk, limit=20)
            self.assertIn("quota exhausted", error)
            self.assertEqual(faucet.used, consumed)

    def test_acknowledgment_must_match_the_requested_units(self):
        handler_faucet = Recorder()
        handler_faucet.command = lambda name, data=None, extra=(): {"authorized": True, "units": 20}
        handler = object.__new__(gateway.Handler)
        handler.headers = Message()
        handler.headers["X-Testnet-Access"] = base64.urlsafe_b64encode(json.dumps(PROOF).encode()).decode().rstrip("=")
        handler.server = types.SimpleNamespace(app=types.SimpleNamespace(faucet=handler_faucet, authorize_many=True))
        with self.assertRaisesRegex(ValueError, "acknowledgment mismatch"):
            handler._authorize_rpc_request(dict(jsonrpc="2.0", id=1, **SNAPSHOT))


if __name__ == "__main__":
    unittest.main()
