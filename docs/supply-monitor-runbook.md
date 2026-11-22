# Supply and pool-backing monitor

`tools/supply_monitor.py` reads one validator RPC endpoint and answers two questions: is every unit the shielded pool records as backing actually in the pool account, and has the total supply stayed within what the chain is scheduled to issue? It writes a result document that an operator can sign and publish. It sends no transaction, holds no wallet capability and creates no key. It is one file: Python 3.9+ and `/usr/bin/openssl`, no other project module, so a reader can fetch and review it on its own.

Shielded amounts are hidden by design, so nobody can add up the notes. What stays public is the boundary of the pool: the pool account's balance, the backing the payment program records in that account, and the chain's total supply. The monitor watches that boundary. Read "What a green result establishes" before relying on it.

## What it reads

One request carries five reads at the chosen commitment level (`finalized` unless `--commitment confirmed` is given for local work):

| Read | Used for |
| --- | --- |
| `getAccountInfo` of the pool address | balance, owner and the pool header: format, network domain, rent floor, backing, note count |
| `getSupply` | total, circulating and non-circulating supply |
| `getAccountInfo` of the epoch rewards account | rewards computed for the epoch and the block heights in which they are credited |
| `getEpochInfo` | slot, epoch, slots in the epoch, block height |
| `getInflationRate` | the validator inflation rate |

Three single reads follow: `getGenesisHash`, `getMinimumBalanceForRentExemption` for the pool's data length, and `getBlockTime` for the slot (a pruned block time is tolerated and published as `null`). The pool address is not configured; the tool derives it from the payment program's identifier and seed, and its tests pin both against the protocol crate.

The header is parsed in Python with the same range rules as `PoolState::decode`. The note-tree frontier and anchors behind the header are not re-verified; the validator does that on every payment.

### Commitment and reads at different slots

The default is `finalized`, because a public result must not flip when a fork is abandoned. Finalized state trails the tip by roughly thirty slots.

Two rules keep reads at different slots from raising a false alarm:

1. **Backing is only compared with the balance of the same account record.** The balance and the header arrive in one `getAccountInfo` response for one account, so they are one version of that account. The monitor never fetches the balance with a second call.
2. **Everything else must name one slot.** All five reads go in one JSON-RPC batch, each answer names the slot it was served from, and the monitor repeats the batch (eight tries by default) until they agree. An endpoint that refuses batches is read one call at a time under the same rule. If the answers never agree the result is `unknown`, not red.

A same slot in the answers is weaker than it looks. The supply, epoch and block height come from the node's bank for that slot, but a node serves account contents from its latest root, which can be ahead of the slot it reports as finalized. On the local two-validator network the second validator served the reward account one slot ahead of its supply at epoch boundaries. The checks are built so that newer account contents cannot produce an alarm: the pool checks use the pool account alone, and pending rewards are derived from the bank's block height and the reward window rather than from the reward account's own progress counter.

For the same reason, point a baseline at one node. Behind a balancer, a second node at the same slot can still serve an older pool account, which reads as a note count that fell.

## Checks

Amounts are whole base units. Each check is true, false, or `null` when it could not be evaluated.

| Check | Rule |
| --- | --- |
| `pool_account` | the account exists, is owned by the payment program, is not executable, and its data is a pool header in a known format (`NPOOL003`, 3,137 bytes; `NPOOL004`, 25,728 bytes) with a non-zero network domain, backing at most 2^63 - 1 and an even note count at most 2^32 - 2 |
| `pool_backing` | `lamports >= rent_floor + backing`. Published as `surplus = lamports - rent_floor - backing`, which must not be negative. This is the rule the payment program applies before every payment |
| `pool_rent_floor` | `rent_floor >= rent_exempt_minimum(data_bytes)` as the endpoint reports it. A floor below the minimum would leave the last units of backing impossible to withdraw |
| `supply_identity` | `total == circulating + non_circulating` |
| `pool_within_supply` | `lamports <= total` |
| `supply_ceiling` | `total <= --supply-ceiling`; `null` when no ceiling is given |
| `continuity` | against the baseline: format, network domain and rent floor unchanged; note count not lower; and backing unchanged when the note count is unchanged, because backing only moves with a payment and every payment adds two notes |
| `supply_issuance` | against the baseline: `total - baseline.total <= allowance` |

The allowance is the most the chain may have issued since the baseline:

```
allowance = baseline.rewards_pending + issuance_slack
repeat once for every epoch boundary crossed since the baseline:
    allowance += ceil((baseline.total + allowance) * rate * slots_in_epoch / (10^9 * slots_per_year))
```

`rate` is the larger of the validator inflation rates at the baseline and now, in parts per billion, and `slots_in_epoch` the larger of the two epoch lengths. `rewards_pending` is the whole reward amount computed for the current epoch until the bank's block height has passed the last block of the reward window, and zero afterwards. If the endpoint has no reward account, one epoch of issuance is assumed pending. Inside an epoch, after the rewards have landed, the allowance is exactly `issuance_slack` (zero by default): the total may only fall.

A surplus is green. Anyone can transfer units to the pool address; the program ignores them, they mint no notes and they cannot be withdrawn. The result shows the surplus so a reader can see it.

`--slots-per-year` must match the network's genesis timing. The default, 78,894,000, is the validator's default of 2.5 slots per second. A larger value than the network's makes the allowance too small and raises false alarms; a smaller one loosens the bound.

## Baseline

`--baseline PATH` names the last green result. The monitor reads it if it exists, judges `continuity` and `supply_issuance` against it, and replaces it only when the new result is green. A red result therefore stays red for as long as its cause remains, instead of becoming the next reference. The baseline must be an untouched green result at the same commitment level; anything else is refused with exit code 2.

The first run has no baseline, so the two baseline checks are `null`; it establishes the reference. Do not take the first baseline in the first slots after genesis: the validator creates its system accounts there, which adds to the supply once (about 143 million units on the local network) and would be reported by the next run. To accept a known one-time change, such as a feature activation that creates an account, run once with `--issuance-slack` or start a new baseline by removing the file. Starting a new baseline is visible to readers: that result has `"baseline": null`.

## Result document

The file is canonical JSON: keys sorted, two-space indentation, one trailing newline. `format` is `native-supply-monitor-v1`. All amounts are decimal strings, because they exceed what JSON numbers carry safely.

| Field | Meaning |
| --- | --- |
| `status` | `green`, `red` or `unknown` |
| `failed` | identifiers of the false checks, in the order of the table above |
| `reason` | `null`, or for `unknown` one of `rpc_unavailable`, `rpc_error`, `malformed_response`, `inconsistent_slots`, `wrong_network`, `stale_endpoint` |
| `observed_at` | the monitor's clock, seconds since the epoch |
| `commitment`, `read_mode` | commitment level; `batch` or `sequential` |
| `genesis_hash`, `program`, `pool_address` | the network and the fixed addresses read |
| `slot`, `epoch`, `block_time` | the slot every read named, its epoch, and the chain's time for it |
| `pool` | `present`, `owner`, `executable`, `lamports`, `data_bytes`, `data_sha256`, `format`, `domain`, `rent_floor`, `backing`, `note_count`, `rent_exempt_minimum`, `surplus`; header fields are `null` when the data is not a pool header |
| `supply` | `total`, `circulating`, `non_circulating`, `validator_rate_ppb`, `slots_in_epoch`, `block_height`, `rewards_pending` |
| `policy` | `supply_ceiling`, `slots_per_year`, `issuance_slack` as given on the command line |
| `baseline` | `null`, or the SHA-256 of the baseline file with the numbers taken from it: `slot`, `epoch`, `total`, `rewards_pending`, `validator_rate_ppb`, `slots_in_epoch`, `format`, `domain`, `rent_floor`, `backing`, `note_count` |
| `checks` | the eight checks as `{id, ok, detail}` |
| `signer` | `null`, or `{algorithm: "ecdsa-p256-sha256", key_sha256}` |

An `unknown` result carries no `pool`, `supply`, `slot`, `epoch` or checks. The endpoint's address is never written to the result.

The verdict is a function of the published numbers. `status`, `failed` and every `ok` can be recomputed from `pool`, `supply`, `epoch`, `baseline` and `policy`, and both the tool and its verifier refuse a document where they do not match. Through `baseline.sha256` each result names the result it was judged against.

## Exit codes

| Code | `check` | `verify` |
| --- | --- | --- |
| 0 | green | authentic and green |
| 1 | red: a check is false on a consistent read | authentic and red |
| 2 | unusable invocation or local file | the same |
| 3 | unknown: no trustworthy observation; an `unknown` result is still written and signed | authentic and unknown |
| 4 | signing failed; nothing was written | not authentic, stale, or for another network |

Alert on 1. Treat 3 as "the monitor could not look", which needs attention if it persists but says nothing about the pool.

## Running it

Unsigned, to the terminal:

```sh
python3 -B tools/supply_monitor.py check --rpc http://127.0.0.1:18899
```

Continuously, signed, with a baseline (run it from a timer; each run is independent):

```sh
python3 -I -B tools/supply_monitor.py check \
  --rpc https://rpc.example.org \
  --expect-genesis GENESIS_HASH \
  --baseline /var/lib/supply-monitor/baseline.json \
  --output /var/lib/supply-monitor/latest.json \
  --signing-key /etc/supply-monitor/signing.pem
```

This writes `latest.json` and `latest.json.sig`, each by atomic replacement. Publish the two files together; a reader who fetches them between the two replacements sees a pair that does not verify and should fetch again. Plain `http` is only read from loopback unless `--insecure-http` is given, because a result is no better than the path it was read over. The tool connects directly, ignoring proxy settings, and follows no redirect.

## Signing

The signing key is an input. The operator creates and keeps it; the tool is given a path and never generates, reads, copies or prints a private key. It passes the path to the system OpenSSL, withholds that program's diagnostics, and checks the signature it gets back before writing anything. The key file must be a regular file owned by the caller with no group or other access. An encrypted key takes `--password-file`, under the same file rules. Without `--signing-key` the result is unsigned and says so (`"signer": null`); the tool refuses to write an unsigned result beside an existing signature file.

The scheme follows the wallet release signatures: ECDSA over P-256 with SHA-256, a detached DER signature over the domain prefix `native-supply-monitor-signature-v1` followed by one zero byte and the exact bytes of the result file. The key is identified by the SHA-256 of its public SubjectPublicKeyInfo DER, which the signed result names in `signer.key_sha256`.

### What a verifier does

A reader needs the two published files, the operator's public key, and the key's SHA-256 obtained through a channel that does not depend on the page serving the result.

```sh
python3 -I -B supply_monitor.py verify \
  --result latest.json --public-key operator.pub \
  --key-sha256 PINNED_SHA256 --expect-genesis GENESIS_HASH --max-age 900
```

`verify` checks that the public key matches the pin, that the signature covers these exact bytes, that the result names that key, that the document is well formed and canonical, that its verdict follows from its numbers, and that it is fresh and for the expected network. A reader who tracks results should also pass `--min-slot` with the highest slot already seen, so an old green result cannot be replayed over a newer red one. The signature alone can be checked without this tool:

```sh
{ printf 'native-supply-monitor-signature-v1\0'; cat latest.json; } |
  openssl dgst -sha256 -verify operator.pub -signature latest.json.sig
```

A valid signature means the key holder's monitor reported these numbers from its endpoint. It is not a proof of chain state. Anyone with an RPC endpoint can run `check` themselves and compare `slot`, `pool.data_sha256` and the amounts with the published result.

## What a green result establishes

It establishes, for the node that was read and at the slot named:

- every unit of recorded backing, and the rent reserve, is in the pool account;
- the pool account is the payment program's, in a known format, and has not changed except through payments since the baseline;
- the supply the node reports is consistent with itself, covers the pool, respects a declared ceiling, and has not grown since the baseline by more than the pending rewards and the scheduled inflation of the epochs crossed.

It does not establish:

- **That no note was forged.** A forged note inside the pool changes neither backing nor balance, so no public reading shows it. What the boundary guarantees is a limit on the damage: a withdrawal lowers backing, the program refuses to take backing below zero, and backing is covered by real units. Forged notes could at worst take backing that belongs to honest notes; they cannot raise the total supply. The first public sign would be honest withdrawals failing while the monitor is still green.
- **That account balances add up to the total.** `total` is the node's own running count. No RPC method lists every account at one slot, so the monitor cannot sum them. Validators check that sum when they load a snapshot.
- **An exact reconciliation of supply.** `supply_issuance` is an upper bound. Fees burned since the baseline are not measured, since that would need every block, so units created in an amount smaller than the burn in the same interval would pass. Frequent runs keep that interval, and so that amount, small. Across an epoch boundary the bound is the scheduled maximum, not the amount actually paid.
- **Anything the endpoint did not tell truthfully.** The monitor trusts its endpoint. Run it against a node the operator controls, and treat independent monitors with independent nodes as the way to check the operator.

## Local verification

The unit tests need no network:

```sh
python3 -B -m unittest discover -s tools -p 'supply_monitor_test.py'
```

They run the monitor against a loopback stand-in for the validator's RPC whose pool account bytes are written by the real encoder. `protocol/payments/tests/pool_backing_vectors.rs` builds both pool formats through two deposits, a private send and two withdrawals and pins the bytes in `tools/fixtures/pool_backing_vectors_v1.json`, so a change to the encoding fails the Rust test before the Python decoder can drift. The stand-in reproduces what the local network shows: a fee burn in every slot, rewards computed at an epoch boundary and credited one block later, and account contents newer than the reported slot. Signature tests use disposable keys made by the test with the system OpenSSL.

On a real local network, with a fresh pool:

```sh
sh tools/build_localnet.sh
python3 -B tools/localnet.py init --root .data/supply
python3 -B tools/localnet.py start --root .data/supply
python3 -B tools/supply_monitor_localnet.py --root .data/supply
python3 -B tools/localnet.py stop --root .data/supply
```

`tools/supply_monitor_localnet.py` runs the monitor against both validators several times a second, each with its own baseline, while the payment exercise makes a deposit, a private send and a withdrawal and the network crosses epoch boundaries. Every result must be green, and each validator must be seen to pass through the deposit, the private send and the withdrawal with no surplus. It then puts a loopback relay in front of the first validator that alters the answers about the pool account or the supply, and requires each alteration to be reported red under the expected check, with the baseline untouched, and the unaltered relay to be green before and after. Last, it signs a green and a red result with a disposable key and verifies both, and confirms that an edited signed result is refused. Evidence is written under `supply-monitor/` in the network directory.

The relay alters answers because the validator will not produce an inconsistent pool: the payment program refuses any payment that would break `pool_backing`, and nothing else can write the account. An inconsistent pool written into a real ledger would need a modified genesis or a modified validator, which this harness does not build.
