#!/usr/bin/env python3
"""Read-only private-pilot vote-admission budget report; no RPC, keys or funding."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

U64 = 2**64 - 1
MAX_BYTES = 65536
PUBLIC_KEY = re.compile(r"[1-9A-HJ-NP-Za-km-z]{32,44}")
HEX = re.compile(r"[0-9a-f]{64}")


def natural(value, maximum=U64):
    return type(value) is int and 0 <= value <= maximum


def exact(value, names):
    return isinstance(value, dict) and set(value) == set(names)


def unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate JSON field')
        value[key] = item
    return value


def decode(raw):
    def invalid(_):
        raise ValueError('Nonfinite JSON value')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)


def read_public(path):
    """Only the explicitly named bounded public input, never a private key path."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_BYTES:
            raise ValueError('Bounded regular public JSON input required')
        raw = stream.read(MAX_BYTES + 1)
        after = os.fstat(stream.fileno())
        if len(raw) > MAX_BYTES or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('Public input changed or exceeded its bound')
        return raw


def network(value):
    return (exact(value, ('network', 'genesis_hash')) and
            isinstance(value['network'], list) and len(value['network']) == 32 and
            all(natural(byte, 255) for byte in value['network']) and any(value['network']) and
            isinstance(value['genesis_hash'], str) and PUBLIC_KEY.fullmatch(value['genesis_hash']) is not None)


def validate_policy(value):
    keys = ('format', 'network', 'vote_accounts', 'vat_charge_units', 'minimum_vote_balance_units',
            'epoch_schedule', 'critical_epochs', 'low_epochs', 'max_age_seconds',
            'quorum_requirement', 'evidence_sha256')
    if not exact(value, keys) or value['format'] != 'zolana-vat-budget-policy-v1' or not network(value['network']):
        raise ValueError('Invalid public VAT policy schema')
    accounts = value['vote_accounts']
    if (not isinstance(accounts, list) or len(accounts) != 3 or
            any(not isinstance(key, str) or PUBLIC_KEY.fullmatch(key) is None for key in accounts) or len(set(accounts)) != 3):
        raise ValueError('Exactly three unique reviewed original vote accounts required')
    if (not natural(value['vat_charge_units']) or value['vat_charge_units'] == 0 or
            not natural(value['minimum_vote_balance_units']) or value['minimum_vote_balance_units'] < value['vat_charge_units'] or
            not natural(value['critical_epochs'], 1000000) or not natural(value['low_epochs'], 1000000) or
            value['low_epochs'] <= value['critical_epochs'] or not natural(value['max_age_seconds'], 3600) or value['max_age_seconds'] == 0):
        raise ValueError('Explicit VAT charge, minimum balance and alert thresholds required')
    schedule = value['epoch_schedule']
    if (not exact(schedule, ('first_epoch', 'first_slot', 'slots_per_epoch', 'eligibility_lag_epochs')) or
            not natural(schedule['first_epoch']) or not natural(schedule['first_slot']) or
            not natural(schedule['slots_per_epoch'], 1000000) or schedule['slots_per_epoch'] == 0 or
            not natural(schedule['eligibility_lag_epochs'], 10)):
        raise ValueError('Explicit fixed epoch schedule required; warmup is not inferred')
    requirement = value['quorum_requirement']
    if requirement is not None and (not exact(requirement, ('numerator', 'denominator', 'strict')) or
            not natural(requirement['numerator'], 1000000) or not natural(requirement['denominator'], 1000000) or
            not 0 < requirement['numerator'] < requirement['denominator'] or type(requirement['strict']) is not bool):
        raise ValueError('Invalid explicitly reviewed quorum requirement')
    evidence = value['evidence_sha256']
    if (not exact(evidence, ('profile', 'vat_parameters', 'epoch_parameters', 'original_cohort')) or
            any(not isinstance(pin, str) or HEX.fullmatch(pin) is None for pin in evidence.values())):
        raise ValueError('Public profile, effective VAT, epoch and original cohort evidence pins required')
    return value


def validate_observation(value, policy, policy_sha256):
    keys = ('format', 'network', 'policy_sha256', 'observed_at_unix', 'finalized_slot',
            'epoch', 'slot_index', 'slots_in_epoch', 'accounts', 'current_quorum')
    if (not exact(value, keys) or value['format'] != 'zolana-vat-budget-observation-v1' or
            value['network'] != policy['network'] or value['policy_sha256'] != policy_sha256 or
            not natural(value['observed_at_unix']) or
            any(value[key] is not None and not natural(value[key]) for key in ('finalized_slot', 'epoch', 'slot_index', 'slots_in_epoch'))):
        raise ValueError('Observation network, policy binding or epoch schema differs')
    accounts = value['accounts']
    if not isinstance(accounts, list) or len(accounts) > 3:
        raise ValueError('Bounded original vote-account observations required')
    seen = set()
    for account in accounts:
        if (not exact(account, ('vote_account', 'balance_units', 'context_slot')) or
                account['vote_account'] not in policy['vote_accounts'] or account['vote_account'] in seen or
                any(account[key] is not None and not natural(account[key]) for key in ('balance_units', 'context_slot'))):
            raise ValueError('Duplicate, substituted or invalid public vote-account observation')
        seen.add(account['vote_account'])
    quorum = value['current_quorum']
    if quorum is not None and (not exact(quorum, ('epoch', 'bank_slot', 'total_stake_units', 'observed_voting_stake_units')) or
            any(not natural(quorum[key]) for key in quorum) or quorum['total_stake_units'] == 0 or
            quorum['observed_voting_stake_units'] > quorum['total_stake_units']):
        raise ValueError('Invalid current frozen-committee observation')
    return value


def report(policy, observation, policy_sha256, now):
    validate_policy(policy)
    validate_observation(observation, policy, policy_sha256)
    if not natural(now):
        raise ValueError('Integer current time required')
    reasons = []
    if observation['observed_at_unix'] > now:
        reasons.append('observation_in_future')
    elif now - observation['observed_at_unix'] > policy['max_age_seconds']:
        reasons.append('observation_stale')
    slot, epoch = observation['finalized_slot'], observation['epoch']
    schedule = policy['epoch_schedule']
    schedule_ok = (slot is not None and epoch is not None and slot >= schedule['first_slot'] and
                   epoch == schedule['first_epoch'] + (slot - schedule['first_slot']) // schedule['slots_per_epoch'] and
                   observation['slot_index'] == (slot - schedule['first_slot']) % schedule['slots_per_epoch'] and
                   observation['slots_in_epoch'] == schedule['slots_per_epoch'])
    if not schedule_ok:
        reasons.append('epoch_missing_or_schedule_changed')
    observations = {item['vote_account']: item for item in observation['accounts']}
    rows = []
    for key in policy['vote_accounts']:
        item = observations.get(key)
        why = list(reasons)
        if item is None or item['balance_units'] is None:
            why.append('balance_unavailable')
        elif item['context_slot'] is None or item['context_slot'] != slot:
            why.append('balance_bank_does_not_match_epoch_sample')
        count = None
        if not why:
            balance = item['balance_units']
            count = 0 if balance < policy['minimum_vote_balance_units'] else 1 + (balance - policy['minimum_vote_balance_units']) // policy['vat_charge_units']
        status = 'unknown' if count is None else 'critical' if count <= policy['critical_epochs'] else 'low' if count <= policy['low_epochs'] else 'ok'
        first_failure = None if count is None else epoch + 1 + count
        rows.append(dict(vote_account=key, status=status, reasons=why,
                         balance_units=None if why else item['balance_units'], funded_future_admissions=count,
                         next_admission_check_epoch=None if count is None else epoch + 1,
                         first_balance_insufficient_check_epoch=first_failure,
                         first_potentially_affected_eligibility_epoch=None if first_failure is None else first_failure + schedule['eligibility_lag_epochs']))
    quorum = dict(status='unknown', threshold_units=None, observed_voting_stake_units=None,
                  reason='current_committee_or_reviewed_threshold_unavailable')
    q, requirement = observation['current_quorum'], policy['quorum_requirement']
    if not reasons and q is not None and requirement is not None and q['epoch'] == epoch and q['bank_slot'] == slot:
        numerator = q['total_stake_units'] * requirement['numerator']
        threshold = numerator // requirement['denominator'] + 1 if requirement['strict'] else (numerator + requirement['denominator'] - 1) // requirement['denominator']
        quorum = dict(status='observed_at_or_above_threshold' if q['observed_voting_stake_units'] >= threshold else 'observed_below_threshold',
                      threshold_units=threshold, observed_voting_stake_units=q['observed_voting_stake_units'],
                      reason='public_observation_only_not_a_consensus_health_proof')
    statuses = {row['status'] for row in rows}
    overall = 'critical' if 'critical' in statuses else 'unknown' if 'unknown' in statuses else 'low' if 'low' in statuses else 'ok'
    return dict(format='zolana-vat-budget-report-v1', scope='vote-admission-funding-only', status=overall,
                policy_sha256=policy_sha256, observed_at_unix=observation['observed_at_unix'],
                finalized_slot=slot, epoch=epoch, unknown_inputs='unknown' in statuses,
                vat_charge_units=policy['vat_charge_units'], minimum_vote_balance_units=policy['minimum_vote_balance_units'],
                slots_until_next_check=None if not schedule_ok else schedule['slots_per_epoch'] - observation['slot_index'],
                vote_accounts=rows, current_quorum=quorum, network_readiness_assessed=False,
                funding_actions=False, network_requests=False,
                interpretation='Funding-only estimate at the unchanged configured VAT charge. Stake, BLS, rank, frozen membership and actual finality are separate checks.')


def human(value):
    lines = [f"Vote-admission funding: {value['status']}",
             f"Finalized slot: {value['finalized_slot']}; epoch: {value['epoch']}",
             f"Configured VAT: {value['vat_charge_units']} test units per admission; minimum vote balance: {value['minimum_vote_balance_units']}."]
    for row in value['vote_accounts']:
        count = row['funded_future_admissions']
        lines.append(f"{row['vote_account']}: {row['status']} — " +
                     ('remaining admissions unknown (' + ', '.join(row['reasons']) + ')' if count is None else
                      f"funded for {count} further epoch admissions; first balance failure at check epoch {row['first_balance_insufficient_check_epoch']}, potentially affecting eligibility epoch {row['first_potentially_affected_eligibility_epoch']}"))
    q = value['current_quorum']
    lines.append(f"Current quorum observation: {q['status']}; required stake threshold: {q['threshold_units']}.")
    lines.append(value['interpretation'])
    lines.append('Read-only report. No funding, account changes, key access or alert delivery performed.')
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--policy-sha256', required=True)
    parser.add_argument('--observation', type=Path, required=True)
    parser.add_argument('--output', choices=('json', 'text'), default='text')
    args = parser.parse_args(argv)
    try:
        raw = read_public(args.policy)
        if HEX.fullmatch(args.policy_sha256) is None or hashlib.sha256(raw).hexdigest() != args.policy_sha256:
            raise ValueError('Reviewed public policy digest differs')
        value = report(decode(raw), decode(read_public(args.observation)), args.policy_sha256, int(time.time()))
    except (OSError, ValueError, TypeError):
        print('VAT budget input invalid or unavailable; current runway and quorum are unknown. No action was taken.', file=sys.stderr)
        return 4
    print(json.dumps(value, sort_keys=True, allow_nan=False) if args.output == 'json' else human(value))
    return {'ok': 0, 'low': 1, 'critical': 2, 'unknown': 3}[value['status']]


if __name__ == '__main__':
    raise SystemExit(main())
