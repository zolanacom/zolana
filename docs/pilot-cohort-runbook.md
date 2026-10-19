# Finite pilot admission and funding preparation

This is a local preparation tool, not a deployer or faucet refill mechanism. It never connects to RPC, transfers coins, starts services, edits the installed service, publishes profiles or sends invitations. Keep the current two-client rehearsal and its original wallets/claims intact. Pick a pilot genesis and deployment policy separately before external invitations.

`tools/pilot_cohort.py` uses the existing native profile parser, faucet ledger and admission implementation. It adds an explicitly hashed public plan, separate owner-only setup, persistent named invitation slots and restart checks. The native faucet remains the authority for lifetime capacity, daily admissions, membership, revocations and quotas. No new consensus or privacy rule is introduced.

## Review a plan

Supply two complete public wallet profiles with the same network/genesis/program/pool. The source profile uses separate operator-loopback RPC without invitations or a faucet endpoint. The tester profile pins the invited gateway and faucet; remote tester endpoints require HTTPS under existing native validation. Operator RPC access remains protected by its existing credential/private socket transport. The public source profile contains no credential and is never a tester access route.

```sh
python3 -B tools/pilot_cohort.py plan \
  --source-profile <operator-public-profile.json> \
  --tester-profile <invited-public-profile.json> \
  --size 10 --daily 3 --rpc-limit 2000 --ttl 86400 \
  --output <new-plan.json>
```

The output prints the canonical plan SHA-256 and integer-unit budget. Review the identity, endpoints, cohort size, limits and amounts. The ten-wallet default is a draft local cohort assumption; it does not select production token economics, promise tester access or authorize external invitations. Membership duration remains the native seven days; unused invitation validity defaults to one day from issuance. Existing native caps are 1–100 lifetime slots, 1–10,000 member RPC requests/minute and a maximum seven-day invitation validity. Revocation/expiry never refunds a lifetime slot.

Each admitted wallet receives exactly 1,000,000 shielded test units and 150,000,000 public gas units. For ten slots:

| Requirement | Raw test units |
| --- | ---: |
| Shielded grants | 10,000,000 |
| Public gas grants | 1,500,000,000 |
| One serialized payment's initial working reserve | 150,000,000 |
| Gas-transfer fees, three attempts at the native 10,000 cap per wallet | 300,000 |
| Initial public funding floor | 1,650,300,000 |
| Conservative public budget | 6,000,300,000 |

The conservative budget reserves all three native private-payment attempts at their 150,000,000 gross-debit cap for every slot, plus gas grants and capped gas-transfer fees. Returned rent can make actual spending lower. This is a provisioning budget, not a throughput promise or a guarantee under arbitrary failures. The source reservoir's own initial deposit/operational setup is funded separately. Do not silently raise native caps when a budget fails; preserve journals and review the shortfall. The tool does not verify on-chain balances: audits always say `funding_verified:false`.

## Prepare a separate faucet

Choose a new child of an owner-only operator directory. Use a separate bounded owner-only faucet password file, not an existing user wallet password. The tool pins both native binaries, the public plan and any supplied RPC credential. It creates a new encrypted seed and encrypted recovery file; never substitute this seed into a prior funded faucet or reuse its ledgers.

```sh
python3 -B tools/pilot_cohort.py prepare \
  --plan <reviewed-plan.json> --plan-sha256 <printed-digest> \
  --root <new-private-operator-directory/pilot> \
  --password-file <private-faucet-password-file> \
  --rpc-access-file <existing-operator-rpc-capability>
```

The RPC capability is required when the operator RPC is isolated; omitting it is only suitable for an explicitly disposable unisolated loopback fixture. The existing native initializer preserves private Unix capability routing when supplied. The capability is not added to the public plan, exported invitation or tester package. Provision/own the resulting faucet under the deployment's dedicated service account; desktop preparation alone does not establish host isolation.

The prepared receipt contains funding addresses and budgets, with `funded:false`, `installed:false`, `services_started:false`, `published:false`. Back up its original keys, plan, admission/claim/issuance ledgers and all payment journals. Fund and verify the complete conservative budget through a separately reviewed operator ceremony before issuing tester invitations. No automatic refill exists. Configure the isolated service to use this new reviewed root only after the relevant host/TLS/backup/monitoring work; this tool does not replace the installed rehearsal configuration.

[Host/funding preparation](pilot-host-funding-runbook.md) now provides a disabled secret-free role packet, an authority-bound funding intent and native verified initial-balance receipts. This remains separate from the cohort tool's preparation-only audit. The separate [pilot runtime](pilot-runtime-runbook.md) now binds an original funded cohort to validators, retention, direct HTTPS and the grant worker. Neither preparer installs it; actual host custody, treasury signing and deployment remain separate.

For interrupted setup, rerun the exact prepare command with `--resume`. A completed native init or admission commit resumes with the same keys/policy. An incomplete native seed/admission write fails closed and remains preserved. Never delete a partial directory, marker or ledger to retry with its funded key. Changed plan, profile, native binary, RPC credential or policy refuses recovery. An updated binary needs a separately reviewed migration, not an edited pin.

## Issue one invitation per named slot

```sh
python3 -B tools/pilot_cohort.py issue \
  --root <pilot> --plan-sha256 <reviewed-digest> \
  --slot tester-01 --bind-fee <known-test-wallet-fee-address>
```

The code exists only in the owner-only `invitations/tester-01.json` file. Stdout contains its hashed ID, expiry, nonpersonal slot and status. An unused unbound code is a bearer credential; use a fee-authority binding when available. This task does not send codes to anyone. Store/transfer invitations only through an explicitly authorized channel, never a URL, Git, screenshot or log.

Repeating the same slot and binding returns the same native invitation, even after a lost acknowledgement or restart. A concurrent issuer fails closed until the first lock is released; retry the same slot. Revoked, expired or redeemed slots never mint replacements. A native export without its ledger commit, a missing committed export or a missing issuance ledger refuses further issuance; retain the original files for recovery. There is no automatic reset or capacity refund. The journal reserves a named slot before native issuance; a failed slot cannot be repurposed to another authority.

Revocation uses the existing native command with the hashed invite ID:

```sh
target/debug/native-faucet invite-revoke --root <pilot/faucet> --invite-id <hashed-id>
python3 -B tools/pilot_cohort.py audit --root <pilot> --plan-sha256 <reviewed-digest>
```

Audit checks original pins, policy, native capacity and both directions of the invitation/export registry without unlocking the faucet or showing codes. It reports reservations and budgets, not network readiness or current funding. Seed restoration recovers a tester's original admission and claim; it does not allocate a new grant.

## Bounded local acceptance

```sh
python3 -B -m unittest discover -s tools -p 'pilot_cohort_test.py'
RAYON_NUM_THREADS=2 nice -n 15 python3 -B tools/pilot_localnet.py \
  --root .data/new-pilot-check --evidence <new-private-evidence-directory>
```

The first suite uses real native profile/key/admission operations and a worker-free admission HTTP server. It does not start validators or transfer coins. The second uses fresh keys/ledgers, two real local validators and one new invited sender plus an offline receiver. It funds the conservative one-slot budget, kills the grant worker after an actual gas acknowledgement is withheld, recovers the same grant, sends with user-paid gas, crashes/restarts both validators and restores the original spent seed. Both peers must agree on balances and six permanent nullifiers. The fixture's raw RPC/operator reader is explicitly local and is not a proof of deployed host isolation. Existing protected service and real wallets are untouched. The runner refuses existing roots and stops its owned validators in cleanup; completed evidence cannot be resumed or overwritten.

See LOCAL-042 validation for observed results and remaining external-testnet gates.
