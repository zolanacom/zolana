# Private-pilot vote-admission funding

`tools/vat_budget.py` prepares a read-only funding report for the three original
vote accounts. It does not collect RPC data, read keys, send alerts, fund accounts,
change consensus rules or restart services. It is not installed or activated.
Its result is a funding estimate, not acceptance of network readiness or quorum.

This tool follows a private-pilot outage. The pilot stopped at finalized slot
411647, epoch 200, immediately before the 2048-slot epoch 201 boundary. The
effective 200 ms slot parameters charge 800,000,000 native test units per admitted
vote account per epoch. The retained warning reported 27,074,400 units below an
800,000,000 minimum. All three original accounts eventually lacked admission
funding. Their removal left the future eligible stake map empty; leader-schedule
construction panicked. A running process or completed restart did not establish
restored consensus. The separate consensus repair remains an independent
acceptance gate; this report does not apply or endorse that repair.

The relevant Agave 4.3.2 candidate source is `runtime/src/slot_params.rs`
(`SLOT_PARAMS_200MS`), `runtime/src/bank.rs`
(`minimum_vote_account_balance_for_vat`, `maybe_burn_vat_from_staked_accounts`)
and `core/src/replay_stage.rs` (`maybe_report_vat_health`). The minimum is the
actual vote-account rent minimum **plus** the effective VAT charge. Do not copy
a mainnet rate, use the legacy 400 ms default or infer a new rent minimum from an
old warning. VAT balance alone does not establish BLS eligibility, stake rank,
current frozen membership, voting liveness or finality.

Fresh live balances and activated stake weights were unavailable during the
outage. Do not turn a historical warning or genesis stake into a fresh sample.

## Inputs and calculation

A reviewed public policy uses format `zolana-vat-budget-policy-v1`, the exact
network/genesis, the three vote accounts, explicit `vat_charge_units`,
`minimum_vote_balance_units`, integer alert thresholds `critical_epochs` and
`low_epochs`, and `max_age_seconds`. Its `epoch_schedule` has `first_epoch`,
`first_slot`, `slots_per_epoch` and `eligibility_lag_epochs`. This helper supports
an explicitly fixed epoch interval; warmup or changed schedules fail unknown.
For this pilot the reviewed interval is 2048 slots, with the next epoch's check
affecting eligibility one epoch later. Reconfirm the effective parameters before
activating a policy.

`evidence_sha256` must contain four reviewed byte hashes: `profile`,
`vat_parameters`, `epoch_parameters`, `original_cohort`. The operator separately
pins the complete policy bytes with `--policy-sha256`. These pins establish
reviewed input identity; the helper does not prove the evidence's semantics or
silently extract an operating policy from old logs.

For balance B, minimum M and charge C, remaining funded future admissions are zero
when B < M, otherwise `1 + (B-M)//C`. This preserves the configured rent reserve.
At observation epoch E, a budget of N covers N further admission checks; the first
balance failure is at check epoch E+N+1, potentially affecting eligibility at that
epoch plus `eligibility_lag_epochs`. Current membership is already frozen and
must be checked separately. No reward, refill or top-up is assumed.

The public observation format `zolana-vat-budget-observation-v1` contains:

```json
{
  "format": "zolana-vat-budget-observation-v1",
  "network": {"network": ["32 reviewed byte values"], "genesis_hash": "reviewed genesis"},
  "policy_sha256": "reviewed policy digest",
  "observed_at_unix": 0,
  "finalized_slot": null,
  "epoch": null,
  "slot_index": null,
  "slots_in_epoch": null,
  "accounts": [],
  "current_quorum": null
}
```

This is a schema illustration, **not a valid active configuration**. Every
account observation has exactly `vote_account`, `balance_units`, `context_slot`.
Use null or omit an unavailable account; never substitute zero. A balance must
come from the same finalized bank as the epoch sample. Samples older than the
policy limit, future timestamps, inconsistent epochs or bank mismatches report
unknown. Do not re-date an old sample on monitor restart.

Optional `quorum_requirement` is either null or the separately reviewed
`{numerator, denominator, strict}`. Optional observation `current_quorum` is
either null or `{epoch, bank_slot, total_stake_units,
observed_voting_stake_units}` from the current frozen committee at that same
bank. Missing requirement or current inputs leave the threshold unknown. A
strict 2/3 rule needs `floor(total*2/3)+1`, not rounded-down stake. Even a supplied
observation above its configured threshold is not a consensus-health proof.
Do not use remaining vote-account balances to infer current quorum weights.

## Activation recipe

1. Obtain and independently check fresh public epoch, effective VAT/minimum,
   original vote-account balances and, if available, current frozen-committee
   observations through the existing authorized operator read path. No new raw
   RPC or user-gateway method is required by this helper.
2. Review the policy, source evidence pins, warning lead thresholds and policy
   byte digest. Produce a bounded public observation with the same policy digest
   and original sample time. Publish that observation atomically from the
   existing operator collector only after that collector is separately reviewed.
3. Run one report locally:

   ```sh
   python3 -I /absolute/path/tools/vat_budget.py --policy /reviewed/public-policy.json --policy-sha256 REVIEWED_SHA256 --observation /public/vat-observation.json --output text
   ```

4. JSON output is available with `--output json`. Exit 0 means only all three
   funding budgets exceed the low threshold; 1 means low funding, 2 critical,
   3 unknown input, 4 invalid/unavailable input. A known critical account is
   retained even if another account is unknown. Never interpret exit 0 as network
   readiness, and never clear an incident because the monitor process restarted.
5. Connecting these states to the existing durable off-host monitor/pager
   requires a separately reviewed schema, route and failure/restart acceptance.
   This preparation performs no external delivery or automatic refill. A budget
   incident closes only after a fresh independently checked funded sample; actual
   finality and original wallet/nullifier recovery remain separate checks.

The existing monitor heartbeat/pager schemas are intentionally unchanged: their
historical two-validator assumptions and signed package inventories make an
unreviewed in-place merge inappropriate. This tool is the narrow prepared seam.
