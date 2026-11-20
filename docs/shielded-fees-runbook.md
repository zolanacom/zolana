# Opt-in native shielded sends

This experimental path uses the separate `native-shielded` binary. Existing
wallet UI sends, user-paid public gas mode and installed wallet releases are not
silently changed. Use a separately activated test network and a gateway whose
operator explicitly enables the bounded shared relay. No real-money deployment
or public service activation is part of this path.

## User

Use the same encrypted wallet and pinned invited tester profile as native-wallet.
No public gas funding, sponsor file or operator password is required. Admission
still signs with an off-chain identity: ingress can associate the request with
that member. That identity does not appear in the send's on-chain account list.

```
native-shielded send --network tester-profile.json --wallet wallet.enc.json \
  --password-file - --amount <native-units> --to <private-address> \
  --max-shielded-fee <maximum-native-units>
native-shielded resolve --network tester-profile.json --wallet wallet.enc.json \
  --password-file -
```

Enter the wallet password through local stdin. The fee quote identifies the
shared relay's public payee and exact fee. Only the amount plus that fee is
removed from private notes, and only if the native proof is accepted. The fee
and relay payee are public; recipient amount, recipient and change are encrypted.
There is no automatic fallback to a public gas wallet or an operator subsidy.

The original signed proof is saved in `wallet.enc.json.shielded.json` before
submission. Keep it while the outcome is unknown. Other spending commands refuse
to replace it. Resolve reuses the same proof and idempotent job ID, then requires
full canonical history to authenticate the exact payload. Relay status alone
cannot clear an intent. A failed upload does not charge a shielded fee, but an
aborted or withheld proof remains potentially executable until its signed slot
expiry. Resolve fails closed until canonical history establishes acceptance or
expiry without execution. Seed restoration recovers balances and nullifiers;
keep the journal separately for recovery of an unresolved request.

## Operator

Run the gateway with `--shielded-relay /absolute/owner-only/relay-directory`.
The directory contains an owner-only `config.json` with fixed operator paths:

```
{
  "format": "native-shielded-relay-v1",
  "network": {"network": ["32 integer bytes"], "genesis_hash": "pinned genesis"},
  "network_file": "/fixed/network.json",
  "rpc": "http://127.0.0.1:18899",
  "rpc_access_file": "/fixed/rpc-access.key",
  "payer": ["32 integer public-key bytes"],
  "payer_file": "/fixed/relay.keypair.json",
  "binary": "/fixed/native-shielded",
  "fee": 3000000,
  "gross_cap": 150000000,
  "max_jobs": 32,
  "per_member": 8
}
```

The byte-array placeholders above must be replaced with the exact network/payee
bytes. `rpc_access_file` is optional for a disposable public-key loopback fixture;
production isolation must keep using the protected operator transport. The
example amounts are development units, not final fee policy. Derive a net fee
from permanent nullifier rent, actual transaction fees, allowed upload repair
and service margin. Exclude refundable staging rent from the net user charge.
The operator's gross cap must separately cover staging rent, permanent markers,
all potential broadcasts, cleanup reserve and minimum remaining public balance.

At most 3000 lifetime jobs and 8 jobs per member are allowed by the current schema;
configuration can lower these limits. Completed/aborted jobs keep their slots
across restarts. Quota reset or job deletion is not a recovery mechanism. The
relay holds a single process lock and uses one bounded worker. Before spending
public funds, the worker verifies the complete signed proof, current anchor,
expiry and nullifier accounts. Per-attempt gas debits reuse the durable gross-cap
journal. Unknown pending transactions are resolved canonically before cleanup;
an interrupted partial upload is closed, not regenerated or blindly retried.

### Relay capacity and workers

One worker runs one child at a time and waits for that job's finality before it
starts the next. A wallet's proof expires 512 slots after it is built, so a
burst is served only while its proofs are still valid: with 0.2-second slots
and about five seconds a job, one worker relays about twelve payments a minute
(about 700 an hour), and about twenty from one burst before the proofs queued
behind them expire. An expired job is aborted after its three tries and still
counts against the member's lifetime jobs.

`Relay.start(workers)` accepts 1 to 4 workers; `start()` keeps the single
worker. With more than one, a job is held by exactly one worker, two jobs of
the same member never run together (a wallet's payments keep their order and
two proofs spending one note are never sent side by side), each child runs with
one proof thread instead of two, and a worker that fails ends all of them so
the supervising service notices. Every job keeps its own directory, lock and
journals. What workers share is the payer account, the private RPC and the
service's CPU allowance, which the grant worker also uses under its own time
limit; the payer's balance check is not atomic across jobs, so keep the payer
funded well above one job's cap for each worker. The cohort service starts one
worker (`RELAY_WORKERS` in `tools/native_cohort_service.py`). Raise it only
after measuring grant duration and RPC latency on the host with that many
relay children running.

Activate `SHIELDED_FEE_ACTIVATION_ID` through the chain's reviewed feature process.
New disposable genesis configurations enable it. Existing ledgers/genesis files
are preserved; copying a new wallet or gateway alone cannot activate native V3
acceptance. Build `native-validator` in the same root workspace to link the exact
native adapter and feature set; never test this upgrade with an older validator
binary. This target reuses the imported validator CLI entrypoint and root lockfile.

## Acceptance

On Linux, build native-wallet (all binaries), native-localnet and native-validator.
Run `python3 -B tools/shielded_fees_localnet.py --name f54a` only with a new fixture
name. It refuses macOS and existing fixture roots. Test listeners are loopback
only and are shut down after the run. The disposable public-key genesis is not
an installed pilot host or a service-account-isolation acceptance.

The harness exercises zero-user-gas sends, exact private balance/backing,
lost acknowledgement, relay process-group SIGKILL, both validators' SIGKILL and
original-ledger/tower restart, partial-upload cleanup, pre-expiry refusal,
canonical expiry without execution and encrypted seed restore. Bank and wallet
unit tests additionally exercise fee/payee tampering, version downgrades, feature
activation, failed-transaction rollback, duplicate proof rejection and exact
replay. Gateway tests cover admission, ownership, durable quotas and worker locks.
