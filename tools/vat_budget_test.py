"""Synthetic public-input tests; no validator, key, RPC or funding access."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import vat_budget as budget

ACCOUNTS = ['7WHFCYkHZZ8L9FoKteoM8yRKJsFJSU3bMrVm1xCQWAYn',
            'Fx4LYYr8xmnz8d7N2L4D5eJKsAyb8jAmNsBtkuPGxWFX',
            'GEmo5tnbeEHXo7fqoWQSEzimS2Udb8dRR7y9xVu5evju']


def fixtures():
    policy = dict(format='zolana-vat-budget-policy-v1', network=dict(network=[7]*32, genesis_hash='1'*32),
                  vote_accounts=ACCOUNTS.copy(), vat_charge_units=800000000, minimum_vote_balance_units=800000100,
                  epoch_schedule=dict(first_epoch=0, first_slot=0, slots_per_epoch=2048, eligibility_lag_epochs=1),
                  critical_epochs=2, low_epochs=5, max_age_seconds=30,
                  quorum_requirement=dict(numerator=2, denominator=3, strict=True),
                  evidence_sha256=dict(profile='a'*64, vat_parameters='b'*64, epoch_parameters='c'*64, original_cohort='d'*64))
    observation = dict(format='zolana-vat-budget-observation-v1', network=copy.deepcopy(policy['network']),
                       policy_sha256='e'*64, observed_at_unix=1000, finalized_slot=411647,
                       epoch=200, slot_index=2047, slots_in_epoch=2048,
                       accounts=[dict(vote_account=key, balance_units=800000100 + 9*800000000, context_slot=411647) for key in ACCOUNTS],
                       current_quorum=None)
    return policy, observation


class BudgetTests(unittest.TestCase):
    def run_report(self, policy=None, observation=None, now=1001):
        p, o = fixtures()
        return budget.report(policy or p, observation or o, 'e'*64, now)

    def test_threshold_and_rent_reserve_boundaries(self):
        policy, observation = fixtures()
        for balance, expected in [(800000099, 0), (800000100, 1), (1600000099, 1), (1600000100, 2), (27074400, 0)]:
            observation['accounts'][0]['balance_units'] = balance
            row = self.run_report(policy, observation)['vote_accounts'][0]
            self.assertEqual(row['funded_future_admissions'], expected)
        self.assertEqual(row['first_balance_insufficient_check_epoch'], 201)
        self.assertEqual(row['first_potentially_affected_eligibility_epoch'], 202)

    def test_future_admissions_are_not_current_membership(self):
        policy, observation = fixtures()
        for account in observation['accounts']:
            account['balance_units'] = 0
        observation['current_quorum'] = dict(epoch=200, bank_slot=411647, total_stake_units=300, observed_voting_stake_units=300)
        result = self.run_report(policy, observation)
        self.assertEqual(result['status'], 'critical')
        self.assertEqual(result['current_quorum']['status'], 'observed_at_or_above_threshold')
        self.assertEqual(result['current_quorum']['threshold_units'], 201)
        self.assertEqual(result['slots_until_next_check'], 1)

    def test_explicit_low_critical_and_ok_budgets(self):
        policy, observation = fixtures()
        for count, expected in [(0, 'critical'), (2, 'critical'), (3, 'low'), (5, 'low'), (6, 'ok')]:
            for account in observation['accounts']:
                account['balance_units'] = 0 if count == 0 else policy['minimum_vote_balance_units'] + (count-1)*policy['vat_charge_units']
            self.assertEqual(self.run_report(policy, observation)['status'], expected)

    def test_missing_balance_is_unknown_not_zero_or_healthy(self):
        policy, observation = fixtures()
        observation['accounts'].pop()
        result = self.run_report(policy, observation)
        self.assertEqual(result['status'], 'unknown')
        self.assertIsNone(result['vote_accounts'][2]['funded_future_admissions'])
        self.assertIsNone(result['current_quorum']['threshold_units'])

    def test_critical_is_not_hidden_by_another_unknown_account(self):
        policy, observation = fixtures()
        observation['accounts'][0]['balance_units'] = 0
        observation['accounts'].pop()
        result = self.run_report(policy, observation)
        self.assertEqual(result['status'], 'critical')
        self.assertTrue(result['unknown_inputs'])

    def test_stale_future_or_mixed_bank_samples_cannot_clear_alarm(self):
        for now in [1031, 999]:
            result = self.run_report(now=now)
            self.assertEqual(result['status'], 'unknown')
            self.assertTrue(all(row['funded_future_admissions'] is None for row in result['vote_accounts']))
        policy, observation = fixtures()
        observation['accounts'][1]['context_slot'] -= 1
        self.assertEqual(self.run_report(policy, observation)['vote_accounts'][1]['status'], 'unknown')

    def test_changed_epoch_schedule_and_missing_epoch_are_unknown(self):
        policy, observation = fixtures()
        for key, value in [('slots_in_epoch', 4096), ('epoch', 201), ('slot_index', None), ('finalized_slot', None)]:
            changed = copy.deepcopy(observation); changed[key] = value
            self.assertEqual(self.run_report(policy, changed)['status'], 'unknown')

    def test_quorum_never_guesses_requirement_current_epoch_or_weights(self):
        policy, observation = fixtures()
        observation['current_quorum'] = dict(epoch=200, bank_slot=411647, total_stake_units=300, observed_voting_stake_units=200)
        self.assertEqual(self.run_report(policy, observation)['current_quorum']['status'], 'observed_below_threshold')
        policy['quorum_requirement'] = None
        self.assertIsNone(self.run_report(policy, observation)['current_quorum']['threshold_units'])
        policy, _ = fixtures(); observation['current_quorum']['epoch'] = 201
        self.assertEqual(self.run_report(policy, observation)['current_quorum']['status'], 'unknown')

    def test_policy_and_observation_binding_or_substituted_account_refused(self):
        policy, observation = fixtures()
        for key, value in [('policy_sha256', 'f'*64), ('network', dict(network=[8]*32, genesis_hash='1'*32))]:
            changed = copy.deepcopy(observation); changed[key] = value
            with self.assertRaises(ValueError):
                self.run_report(policy, changed)
        for key, value in [('vote_account', '1'*32), ('balance_units', True), ('context_slot', 2**64)]:
            changed = copy.deepcopy(observation); changed['accounts'][0][key] = value
            with self.assertRaises(ValueError):
                self.run_report(policy, changed)
        observation['accounts'][1] = observation['accounts'][0].copy()
        with self.assertRaises(ValueError):
            self.run_report(policy, observation)

    def test_repeat_after_restart_is_stateless_and_stale_input_becomes_unknown(self):
        p, o = fixtures()
        raw_p, raw_o = json.dumps(p), json.dumps(o)
        first = self.run_report(json.loads(raw_p), json.loads(raw_o))
        self.assertEqual(first, self.run_report(json.loads(raw_p), json.loads(raw_o)))
        self.assertEqual(self.run_report(json.loads(raw_p), json.loads(raw_o), now=1031)['status'], 'unknown')

    def test_duplicate_json_and_unbounded_or_symlink_inputs_refused(self):
        with self.assertRaises(ValueError):
            budget.decode('{"format":1,"format":2}')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); data = root/'public.json'; data.write_bytes(b'x'*(budget.MAX_BYTES+1))
            with self.assertRaises(ValueError):
                budget.read_public(data)
            data.write_text('{}'); link = root/'linked.json'; link.symlink_to(data)
            with self.assertRaises(OSError):
                budget.read_public(link)

    def test_cli_policy_digest_refusal_is_sanitized_and_nonzero(self):
        policy, observation = fixtures()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); p, o = root/'policy.json', root/'observation.json'
            p.write_text(json.dumps(policy)); o.write_text(json.dumps(observation))
            args = [sys.executable, str(Path(budget.__file__)), '--policy', str(p), '--policy-sha256', '0'*64, '--observation', str(o), '--output', 'json']
            result = subprocess.run(args, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 4); self.assertEqual(result.stdout, '')
            self.assertNotIn('Traceback', result.stderr)
            pin = hashlib.sha256(p.read_bytes()).hexdigest(); observation['policy_sha256'] = pin
            o.write_text(json.dumps(observation)); args[args.index('--policy-sha256')+1] = pin
            result = subprocess.run(args, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 3)  # Synthetic timestamp is stale today.
            self.assertEqual(json.loads(result.stdout)['status'], 'unknown')


if __name__ == '__main__':
    unittest.main()
