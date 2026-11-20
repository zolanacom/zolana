"""Slot journal size and the read-only `replan` entry point, with native mocks.

Covers the required plan size of the slot journal and `replan` on the planner
test's disposable fixture. No native binary runs here.
"""
import hashlib
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import native_pilot_cohort as cohort
import native_pilot_cohort_test as fixtures
from wallet_release import atomic


class ReplanGuards(fixtures.Guards):
    def used(self):
        """A sealed ten-wallet cohort with two issued slots and one claim."""
        self.prepare()
        self.issue("tester-01", fixtures.b58(bytes([7]) * 32))
        self.issue("tester-10")
        fee = fixtures.b58(bytes([7]) * 32)
        claims = cohort.private_json(self.root / "faucet/claims.json")
        atomic(self.root / "faucet/claims.json", dict(claims, claims=[{"fee_address": fee}]))
        # Codec-only grant journal, as in the planner test: no chain execution is claimed.
        self.private(self.root / "faucet" / (hashlib.blake2b(fee.encode(), digest_size=32).hexdigest() + ".json"),
                     dict(gas_attempts=0, gas=None, gas_done=True, private_attempts=1, proof=None, private_done=True))

    def replan(self, size, digest=None):
        return cohort.replan(self.root, digest or self.digest, size, self.templates, base_config=self.config)

    def install(self, result):
        for path in (self.templates / "relay.json", self.root / "relay/config.json"):
            value = json.loads(path.read_bytes())
            path.chmod(0o600)
            atomic(path, dict(value, max_jobs=result["relay"]["max_jobs"]))
        for name, key in (("claims.json", "faucet_policy"), ("admission.json", "admission_policy")):
            value = cohort.private_json(self.root / "faucet" / name)
            atomic(self.root / "faucet" / name, dict(value, policy=result[key]))
        (self.templates / "plan.json").chmod(0o600)
        atomic(self.templates / "plan.json", result["plan"])
        self.digest = result["plan_sha256"]
        atomic(self.root / "issuance-pin.json", dict(format="zolana-native-cohort-issuance-pin-v1", plan_sha256=self.digest))
        journal = cohort.private_json(self.root / "issuance.json")
        atomic(self.root / "issuance.json", dict(journal, plan_sha256=self.digest))

    def test_slot_journal_has_no_default_size(self):
        self.prepare()
        with self.assertRaises(TypeError):
            cohort.issuance(self.root, self.digest)
        self.assertEqual(cohort.issuance(self.root, self.digest, 10)["slots"], {})
        for bad in (0, 501, True, None, "10"):
            with self.subTest(size=bad), self.assertRaises(ValueError):
                cohort.issuance(self.root, self.digest, bad)
        # A journal naming the eleventh slot is valid only under a plan of that size.
        journal = cohort.private_json(self.root / "issuance.json")
        atomic(self.root / "issuance.json", dict(journal, slots={"tester-11": dict(bind_fee=None)}))
        with self.assertRaises(ValueError):
            cohort.issuance(self.root, self.digest, 10)
        self.assertEqual(list(cohort.issuance(self.root, self.digest, 11)["slots"]), ["tester-11"])

    def test_replan_of_used_state_is_read_only_and_keeps_everything_but_the_capacities(self):
        self.used()
        before = self.snapshots()
        calls = len(self.native.calls)
        result = self.replan(200)
        self.assertEqual(self.snapshots(), before)
        self.assertEqual(set(self.native.calls[calls:]), {"access-info"})
        plan = cohort.validate_plan(public := json.loads((self.templates / "plan.json").read_bytes()))
        new = result["plan"]
        self.assertEqual(result["plan_sha256"], cohort.hash_value(new))
        self.assertEqual({key for key in new if new[key] != plan[key]}, {"cohort_size", "private_budget", "public_budget",
            "relay_policy_sha256", "faucet_policy_sha256", "admission_policy_sha256"})
        self.assertEqual((new["cohort_size"], new["private_budget"], new["public_budget"]), (200, 4_000_000_000, 90_000_000_000))
        self.assertEqual(result["relay"]["max_jobs"], 1200)
        self.assertEqual((result["faucet_policy"]["max_claims"], result["admission_policy"]["max_invites"],
                          result["admission_policy"]["daily_admissions"]), (200, 200, 200))
        self.assertEqual((result["previous_cohort_size"], result["reserved_slots"], result["issued"],
                          result["reserved_claims"], result["relay_jobs"], result["state_modified"]), (10, 2, 2, 1, 0, False))
        self.assertEqual(public, plan)

    def test_installed_replan_validates_and_opens_the_next_slot(self):
        self.used()
        exports = {path.name: path.read_bytes() for path in (self.root / "invitations").iterdir()}
        old = self.digest
        with self.assertRaises(ValueError):
            self.issue("tester-11")
        self.install(self.replan(200))
        report = self.audit()
        self.assertEqual((report["cohort_size"], report["reserved_slots"], report["issued"]), (200, 2, 2))
        self.assertEqual({path.name: path.read_bytes() for path in (self.root / "invitations").iterdir()}, exports)
        self.assertEqual(self.issue("tester-11")["slot"], "tester-11")
        self.assertEqual(self.issue("tester-200")["slot"], "tester-200")
        with self.assertRaises(ValueError):
            self.issue("tester-201")
        with self.assertRaises(ValueError):
            cohort.audit(self.root, old, self.templates, base_config=self.config)
        # Replanning the installed plan at its own size is the identity.
        self.assertEqual(self.replan(200)["plan_sha256"], self.digest)

    def test_shrink_wrong_hash_and_fresh_state_fail_closed_without_writes(self):
        self.used()
        before = self.snapshots()
        for size in range(1, 10):  # tester-10 is reserved
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, "cannot shrink"):
                self.replan(size)
        for size in (0, 501, True, None):
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.replan(size)
        with self.assertRaises(ValueError):
            self.replan(200, "0" * 64)
        self.assertEqual(self.snapshots(), before)
        claims = cohort.private_json(self.root / "faucet/claims.json")
        atomic(self.root / "faucet/claims.json", dict(claims, policy=dict(claims["policy"], max_claims=200)))
        with self.assertRaises(ValueError):  # state already differs from its sealed plan
            self.replan(200)

    def test_replan_never_creates_the_issuance_lock_of_an_unused_cohort(self):
        plan = self.build()
        self.template(self.templates / "plan.json", plan)
        with self.assertRaisesRegex(ValueError, "original used issuance state"):
            cohort.replan(self.root, cohort.hash_value(plan), 200, self.templates, base_config=self.config)
        self.assertFalse((self.root / "issuance.lock").exists())

    def command(self, *arguments):
        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, "argv", ["native_pilot_cohort.py", *arguments]), \
                redirect_stdout(output), redirect_stderr(errors):
            cohort.main()
        return output.getvalue()

    def test_command_line_replan_requires_the_current_hash_and_the_new_size(self):
        with patch.object(cohort, "replan", return_value={"plan_sha256": "f" * 64}) as replan:
            self.assertEqual(json.loads(self.command("replan", "--plan-sha256", "a" * 64, "--cohort-size", "200")),
                             {"plan_sha256": "f" * 64})
            replan.assert_called_once_with(cohort.ROOT, "a" * 64, 200, cohort.ETC)
            for arguments in (("replan", "--cohort-size", "200"), ("replan", "--plan-sha256", "a" * 64),
                              ("audit", "--plan-sha256", "a" * 64, "--cohort-size", "200"),
                              ("issue", "--plan-sha256", "a" * 64, "--slot", "tester-01", "--cohort-size", "200")):
                with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                    self.command(*arguments)
            self.assertEqual(replan.call_count, 1)


def load_tests(loader, tests, pattern):
    names = [name for name in loader.getTestCaseNames(ReplanGuards) if name not in loader.getTestCaseNames(fixtures.Guards)]
    return unittest.TestSuite(ReplanGuards(name) for name in names)


if __name__ == "__main__":
    unittest.main()
