# Reviewed funded-cohort host runtime

The pilot runtime binds an existing, separately reviewed and funded cohort to its original network. It supervises the validator pair, verified retained history, direct HTTPS gateway/faucet and serialized native grant worker. It does not generate keys/genesis, fund accounts, issue invitations, refill budgets, install services or replace the protected two-client rehearsal.

All current acceptance is local, on macOS arm64 with two co-located validators. The runtime uses the existing `localnet`/coordinated-restart implementation and its project-local private network-root policy. It does not supply Linux binaries, split-host consensus or an independently deployed archive. Actual dedicated-account custody, immutable runtime packaging/installation, TLS/firewall configuration and external-device acceptance remain deployment work. Running the fixture under the desktop UID does not establish isolation from other applications under that UID.

## Prerequisites and binding

Prepare the original network with private keys and hardened **Unix-only** raw RPC before funding it. Use a new cohort root under the intended service identity, its reviewed plan and original network RPC capability. Follow the [cohort](pilot-cohort-runbook.md), [funding](pilot-host-funding-runbook.md) and [direct TLS](direct-tls-runbook.md) runbooks. Verify the entire conservative budget with the native balance/spendability checker while the cohort is still unused. Do not create invitations yet.

```sh
python3 -B tools/pilot_runtime.py bind \
  --network-root <original-private-network> \
  --cohort-root <prepared-funded-cohort> --plan-sha256 <reviewed-plan-digest> \
  --check-id <fresh-native-funding-check-id> --password-file <private-faucet-password> \
  --rpc-listener <reviewed-rpc-listener.json> --rpc-sha256 <reviewed-listener-digest> \
  --rpc-cert <reviewed-rpc-chain.pem> --rpc-key <private-rpc-key.pem> \
  --faucet-listener <reviewed-faucet-listener.json> --faucet-sha256 <reviewed-listener-digest> \
  --faucet-cert <reviewed-faucet-chain.pem> --faucet-key <private-faucet-key.pem>
```

This creates four private binding records in the original network root, without starting any service or submitting a transfer. It refuses an existing/partial binding or legacy `ingress-setup.json`; never point it at the protected rehearsal to replace that setup. Preserve partial files after interruption. There is no automatic overwrite/reset or inferred recovery of missing activation state.

Code hashing accepts developer-owned code or immutable root-owned installed code; root-owned code must also have real root-owned non-writable ancestors. Private state, wallets and credentials still require the service UID and keep their original private-reader rules. This permits a dedicated service UID to hash sealed binaries without owning or making them writable.

The binding pins the exact network configuration, genesis/profile/authority, cohort plan and initial funding receipt, original Unix RPC capability, service UID/GID/platform, native binaries and runtime helper sources, password-file bytes and both reviewed listener configurations/certificate/key files. All paths must be real and owned as required by the underlying private readers. It is a local service contract, not a publicly distributable secret-free packet. It includes local paths and private credential digests; keep it out of Git and tester downloads. A binary, runtime source, password re-encryption, TLS rotation or policy change needs an explicit reviewed migration; editing pins to bypass a failure is not recovery.

## First activation and restart

```sh
python3 -B tools/pilot_runtime.py check \
  --network-root <original-private-network> --binding-sha256 <printed-reviewed-binding-digest>
```

`check` starts no service and refuses the live supervisor lock before touching native worker locks. Read the existing private status file to inspect a running host. It verifies the binding and native policies under the existing cohort/worker/claim locks and advances a private monotonic-clock observation. The persistent runtime lock excludes two host supervisors. The separate runtime requires its own OS process group; run it through the reviewed host service manager, whose failure policy must terminate the **entire group**. Validators, native grant children and the collector stay in that group. A bare shell invocation sharing the shell's group refuses service. The local acceptance runner uses `subprocess.Popen(..., start_new_session=True)` and performs explicit group cleanup; it does not install a launchd job.

The manager's program arguments are:

```sh
python3 -B tools/pilot_runtime.py run \
  --network-root <original-private-network> --binding-sha256 <reviewed-binding-digest>
```

Use `--duration <1..3600 seconds>` for a bounded rehearsal. Omission allows an explicitly launched service to continue; no service is started by `bind` or `check`. The acceptance runner always uses a bounded duration and stops its owned processes in cleanup. On macOS, an actual launchd deployment must retain process-group cleanup (do not enable `AbandonProcessGroup`) and reviewed restart/backoff behavior; a process-only supervisor is insufficient. Crash of a manager that fails to clean descendants is not repaired by guessing/killing arbitrary saved PIDs. Such a deployment is not established by these local checks.

Startup verifies the original binding before starting validators, reuses the existing coordinated replay/tower/checkpoint guards and waits for fresh converged finality. Verified primary/mirrored history must be healthy before any tester listener opens. The gateway serves both retained-history and canonical recovery lanes through the original private operator transport. Existing required replication policy, if configured, remains enforced by retention.

For **first activation**, the cohort must still have no invitations/claims or incomplete funding journals. The original funding receipt must remain within its five-minute window, including a recheck after the wallet's offline authority verification. The durable `active` state commits **before** listeners or grant workers start. A crash before that commit can retry only with intact bound state and still-fresh original funding evidence. A crash after commit reuses the exact original activation time and funding identity.

For **active restart**, the initial funding receipt remains immutable historical evidence. It is not renewed and its initial balance floor is not reapplied after legitimate grants spend funds. The runtime verifies the original cohort, keys, native policy/capacity, receipt and activation instead. Existing claim progress, accepted outcomes, pending/staging transactions, invitations, revocation and quotas remain authoritative; the worker recovers those same operations. Missing activation, binding, clock, original receipt or mismatched inputs blocks startup. Clock rollback also blocks. No path recreates an unused faucet, resets capacity or falls back to the old two-client setup.

The runtime watches native child exit, ingress threads, history health and finality progress. A failed native grant child is treated as a service failure rather than an idle healthy worker. It closes ingress and retention and stops both owned validators. A normal SIGTERM or bounded duration does the same orderly cleanup. SIGKILL requires the host manager's group cleanup before restarting the original binding. Private `pilot-runtime-status.json` records the supervisor/group, validator and active grant-child PIDs; it is operator evidence, not a public health endpoint. Private failure diagnostics stay in the same owner-only network root.

Only after the first ready activation should the operator use the existing named-slot invitation tool. This task does not send invitations or notifications. Back up the original binding/state/clock, plan, source wallet, receipts, admission/claim/issuance records, all payment journals and ledger/tower/history state. A lost activation record requires explicit evidence-backed operator recovery, not a new initial receipt. Initial funding receipts remain observations of trusted native RPC state, not independent finality proofs or guarantees against an authorized operator spending funds later.

## Local acceptance

```sh
python3 -B -m unittest discover -s tools -p 'pilot_runtime_test.py'
RAYON_NUM_THREADS=2 nice -n 15 python3 -B tools/pilot_runtime_localnet.py \
  --root .data/new-runtime-check --evidence .local/new-runtime-evidence
```

The focused suite uses real native keys/admission and mocked funding observations; it starts no validator. It tests first-activation freshness, expiry during unlock, real activation-process SIGKILL before/after durable commit, active restart after receipt expiry/issuance, missing/partial/tampered evidence, clock rollback, preserved pending journals, exclusive runtime locks, and lifecycle cleanup on retention/worker failure.

The live runner uses a new one-slot funded cohort and hardened Unix RPC. The actual runtime owns fresh validators, retention, HTTPS and the automatic grant worker. It interrupts native grant work after gas finalization, checks fail-closed group shutdown, rejects missing activation, recovers that original grant, sends privately with user-paid fees, SIGKILLs the entire host group and restores the original seed/membership/claim/balance and nullifiers after restart. It never reuses pre-existing wallets or the installed service. One funded live slot is not a funded ten-tester deployment or load measurement.

The guarded `--resume-operator-check` mode accepts only the exact harness failures recorded during its original acceptance and a still-pinned, active one-slot cohort with the original completed grant. It preserves prior failure records/logs and never repeats funding or initializes wallets. Completed or unrelated results are rejected. Current code pins intentionally reject old bindings after runtime changes; use reviewed migration or the captured accepted source for historical-fixture reproduction, never silently replace pins.

[Installation and ten-tester provisioning](pilot-installation-runbook.md) now describe the separate disabled bundle and exact finite funding ceremony. The runtime never invokes that ceremony or refills the faucet.

The [complete ten-wallet rehearsal](ten-wallet-rehearsal.md) extends the historical funded ten-slot fixture through all ten grants, two concurrent user-paid payment jobs and complete host/seed recovery. Source balance audits must use an isolated encrypted fixture-seed copy/cache path rather than contend with the live automatic worker.
