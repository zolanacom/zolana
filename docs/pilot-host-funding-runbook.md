# Pilot host and funding preparation

The host packet is a reviewed local setup contract. It is not an installer, external deployment or proof that hosts are independent. The funding checker observes the prepared faucet's actual balances; it never signs a transfer, refills a wallet, starts admission or changes a firewall. Preserve all existing networks and wallets.

## Host packet

```sh
python3 -B tools/pilot_host.py prepare --plan <reviewed-cohort-plan.json> --output <new-host-packet>
python3 -B tools/pilot_host.py check --output <host-packet> --manifest-sha256 <printed-digest>
```

The allowlisted packet contains the exact cohort plan, host plan, funding budget, setup instructions and manifest. All inputs are public configuration; no password, seed, invitation code, operator RPC capability, TLS private key or host login is included. Creation refuses an existing directory. Verification rejects changed/missing/additional files, final symlinks, different reviewed digests or a host/budget contract inconsistent with the cohort. It never runs SSH, a cloud API, a package installer or service manager.

The draft has three **unassigned** roles/failure domains:

| Role | Prepared boundary | Still to establish |
| --- | --- | --- |
| Primary | Existing tested macOS arm64 service, two local validators, invited ingress/faucet, automatic history collector; dedicated no-login identity and private Unix RPC | Actual host/custody, reviewed cohort runtime binding and external TLS audience routing |
| Recovery | Independent history receiver and requirement for canonical archival RPC | Actual independent storage/host, archive runtime/networking, credentials and source-loss rehearsal |
| Observer | Independent monitor, pager and watchdog with scoped capabilities | Actual independent host/supervision, recipient authorization and human receipt |

Both current validators occupy the same primary host and failure domain. This packet does not turn them into independent validator hosts or prove multi-host consensus. The existing supervisor is macOS-specific; Darwin binaries must not be installed on Linux. A Linux/split-peer pilot needs its own reviewed build and runtime adapter. No host/provider/hardware purchase is selected by this draft.

The installed service currently owns its preserved two-client rehearsal, while `pilot_cohort.py` creates a separate reviewed faucet. The separate [funded-cohort host runtime](pilot-runtime-runbook.md) binds a new reviewed cohort with a durable first activation and preserved active restart. It does not replace the installed rehearsal; actual service-account packaging/installation remains required. Do not replace old state or edit its automatic setup to reuse funded keys. The installed/default TLS listeners retain loopback audiences. The separate opt-in [direct HTTPS adapter](direct-tls-runbook.md) is now available for reviewed public audiences, exact Host/SNI and actual socket-peer quotas. It rejects proxy forwarding headers and needs direct TLS termination. It is not installed or integrated with the protected supervisor. Actual cohort/service binding, TLS identities, firewall isolation and external-device acceptance are still required before activation.

`check` always leaves activation disabled and external-tester readiness false. It reports the missing deployment evidence, current platform mismatch when relevant, and local-only profile status. Endpoint format eligibility is not DNS, TLS, reachability, placement or firewall verification. Actual host identities, recovery, human paging and an external-device payment/restart test cannot be demonstrated by this Mac-only packet.

## Bind a funding intent

Run preparation as the intended dedicated service UID, using the original reviewed cohort and its original private Unix RPC capability. Follow the [cohort runbook](pilot-cohort-runbook.md); never point this tool at an existing user wallet or initialize over a funded root.

```sh
python3 -B tools/pilot_funding.py intent \
  --root <prepared-cohort> --plan-sha256 <reviewed-cohort-digest>
```

This writes `funding-intent.json` once, bound to the exact plan, genesis/network, shielded source address, public gas authority, encrypted source-wallet digest and conservative allocation. Review those recipients before an operator ceremony. It explicitly says `automatic_refill:false` and `transfer_authorized:false`. The intent is a funding destination/budget document, not a signed transaction or approval to execute one.

For the ten-wallet candidate, the intent will require 10,000,000 private units and 6,000,300,000 public units. The native reservoir's own setup fees are separate. All amounts are raw valueless test units; production denominations/economics remain undecided. The existing `fund-faucet-check` command supplies exactly one 1,000,000,000-unit fixture transfer to an empty gas account and refuses repetition. It is not a general ten-wallet treasury provisioner. The external pilot needs a separately reviewed bounded treasury transfer/signing ceremony for its actual intent; never repeat that fixture helper or discard its journals to approximate a larger allocation. Existing sponsored deposits also have finite per-attempt/identity/lifetime caps; do not raise those implicitly to meet a plan.

Complete actual funding through the reviewed operator path, with cold treasury custody and preserved unique request IDs, signed outcomes, pending/upload journals and canonical recovery. Keep grant workers and admissions closed during this initial funding check. A missing or ambiguous transfer outcome requires recovery of that original transaction, not another transfer. This implementation adds the intent and verification parts of that workflow, not a new treasury signer.

## Verify actual balances

```sh
python3 -B tools/pilot_funding.py verify \
  --root <prepared-cohort> --plan-sha256 <reviewed-cohort-digest> \
  --password-file <private-faucet-password-file> --check-id preflight-01
python3 -B tools/pilot_funding.py check \
  --root <prepared-cohort> --plan-sha256 <reviewed-cohort-digest> --check-id preflight-01
```

The checker holds the same native grant-worker and claim locks plus the cohort lock. It requires zero issued invitations/claims, the original profiles/binaries/RPC capability and source key binding, and no pending/staging payment. The worker cannot submit a grant while the check runs. It invokes only the native wallet's verified `balance` scan, using the original private operator transport, then checks the genesis, a stable finalized block header and finalized public gas balance at or after the scan slot. Password input goes to the native child's stdin, never command arguments or RPC. The native scan may update its encrypted scan cache; original encrypted wallet, claims and admission records must remain unchanged.

The shielded balance must cover **all** planned grants, and the native `max_single_payment` must also cover that entire allocation using the current two-note input limit. This conservative spendability check rejects a reservoir that could fund the first grant but strand later grants in small notes. The sender's change retains the remaining allocation under the existing native selection rules. Ten slots can be provisioned as two 5,000,000-unit deposits under the current per-deposit cap, subject to the separately reviewed sponsor ceremony and its remaining limits; no deposit is automatically submitted here. Public gas must cover the **conservative** budget. Wrong genesis/authority, missing history/header, changing canonical evidence, insufficient or fragmented funds, active recovery files, concurrent work, changed state and clock rollback fail closed. Public RPC observations are bounded/read-only; redirects and mutation methods are refused. No treasury or sponsor key is opened, and no transfer is submitted by the checker.

Successful immutable receipts live under `funding-checks/<check-id>.json` and expire five minutes after the observation began. They identify required/observed amounts, native maximum private payment, private/public finalized slots, anchor block hash, source authority, intent/plan digests and `transfers_submitted:0`. The private scan and public read can observe different finalized slots; the receipt is not an atomic state snapshot, independent consensus proof or guarantee against later spending. It trusts the pinned operator validator and native verification boundary.

Retrying a completed check returns the exact original receipt/time and does not scan or transfer again. A stale check requires a new nonpersonal check ID and fresh observations; its timestamp is never extended. An interrupted check before publication safely repeats only those read operations. A committed receipt survives acknowledgement loss. Verification/checks refuse an initial receipt after invitations or claims exist, even if it is still within five minutes. Existing invitation tools remain preparation tools; this checker does not automatically activate them or override their native quotas.

## Local acceptance

```sh
python3 -B -m unittest discover -s tools -p 'pilot_funding_test.py'
python3 -B -m unittest discover -s tools -p 'pilot_host_test.py'
RAYON_NUM_THREADS=2 nice -n 15 python3 -B tools/pilot_funding_localnet.py \
  --root .data/new-funding-check --evidence <new-private-evidence-directory>
```

The bounded runner creates fresh local keys/ledgers, rejects a real reservoir with zero public gas, then verifies a real funded reservoir. It SIGKILLs only its own checker before/after receipt publication, repeats read-only checks, verifies the disabled packet, then runs the existing interrupted-grant/user-paid-send/validator-crash/seed-restore acceptance. It preserves evidence and always stops its owned validators in cleanup. The live cohort is one slot to limit heat; ten-wallet budgets are arithmetic/native-policy preparation, not ten-wallet live-load evidence. No installed service or existing wallet is changed.

Use `--funding-only` for a shorter fresh rehearsal that stops before issuing invitations or sending grants: it tests the same real balances, receipt SIGKILL boundaries, a real both-validator crash/restart, original receipt reuse and a fresh native spendability scan after restart. It preserves the initial pool/two nullifiers and then stops its validators.

The separate [installation and ten-tester ceremony](pilot-installation-runbook.md) now supplies an explicit sign-once provisioning workflow. `pilot_funding.py` remains read-only: preparing its intent does not authorize a transfer. Only a separately reviewed `pilot_provision.py` digest and an explicit `run` with original operator custody initiate the finite test-unit allocation. Actual host/account installation and external acceptance remain outstanding.
