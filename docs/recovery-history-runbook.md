# Retained ciphertext history

An independent privacy L1 needs a recovery path after validator transaction history is pruned. Native snapshots retain the pool and permanent nullifiers but not old ciphertexts from closed staging accounts. `native-wallet archive` collects the public finalized native history separately; a fresh seed can then discover its notes through a snapshot-restored peer plus this retained prefix.

Build the locked offline wallet, then collect from an authenticated full-history local RPC before it prunes:

```sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p native-wallet
target/debug/native-wallet archive --network .data/l3/network.json --rpc http://127.0.0.1:18899 --history .data/l3/recovery-history
```

No wallet, password or sponsor key is required. The command verifies all retained proofs again, reads the new finalized RPC suffix and checks the complete pool and latest finalized header before publishing the manifest. Repeat the same command to extend an operator archive. The dedicated local service now runs this bounded collector automatically, as described below. Initial collection requires history from genesis; running it for the first time against a snapshot-only RPC cannot recreate lost ciphertexts.

The archive retains block continuity fields and successful signed native transactions, including upload/seal/finalize/close data and needed loaded addresses. Unrelated transaction bodies are discarded. These are public chain ciphertexts/metadata; wallet seeds, passwords and decrypted notes are never retained here.

Segments have immutable checksum-addressed filenames. Each contains at most 1,024 produced blocks and 32 MiB, with an 8 MiB per-record bound. The manifest has a 4 MiB/16,384-segment bound. Every successful collection can add a partly filled segment, so collection frequency affects the segment limit. Monitor both bytes and descriptor count; capacity exhaustion fails closed. Full retained replay and wallet tree/witness storage still grow with history. This implementation is not the final production indexing design.

The writer requires an owner-only directory and holds an OS-backed exclusive lock. It syncs a temporary segment before publishing its immutable name with a non-overwriting hard link. It atomically replaces and directory-syncs the manifest only after the complete verified extension succeeds. An interrupted temporary write is unreferenced; a complete identical orphan can be reused. Existing segments are never overwritten, and a lagging RPC cannot roll the manifest backward. Do not remove the lock while a writer runs. Stop collection before copying the directory for backup, or copy a captured manifest and its complete referenced immutable files. A generic live directory copy can race a newly published manifest and will be rejected if incomplete.

For a newly restored seed, supply retained history on balance or payment commands:

```sh
target/debug/native-wallet balance --network .data/l3/network.json --wallet .data/my-wallet/recovered.wallet.json --password-file .data/my-wallet/unlock.password --rpc http://127.0.0.1:19899 --history .data/l3/recovery-history
```

`deposit`, `send` and `withdraw` accept the same option. The wallet verifies signatures, native staging authorization, Orchard proofs, nullifiers, commitments/backing, continuity and the complete live finalized pool. It reads a continuous recent suffix from RPC when the retained prefix ends earlier. A prefix may cover a slightly lagging peer's target; the target header must still match that peer. Cache reuse retains its existing finalized-checkpoint protections. A damaged/missing segment, wrong network, gap, mismatched latest header or state discrepancy cannot produce a partial balance. Fix the retained files from a verified backup or use a complete archive RPC; do not reset the seed or payment journals.

Checksums detect damage, not consensus. The configured genesis and RPC consensus remain trusted. Retained block metadata is not an independent proof that an outer transaction signature executed or was absent. The scanner discards retained transaction identities for this purpose and takes the final block height from RPC. `resolve` rejects `--history` and continues to require canonical full RPC history/status checks; `reclaim` also retains its existing authoritative checks. An unknown payment stays blocked if those checks are unavailable. The invited gateway can now supply a separate pinned canonical archival lane for this recovery case; see [canonical pending recovery](invited-testnet-runbook.md#canonical-archival-pending-recovery).

The device-local UI automatically uses `<network-root>/recovery-history` when its manifest exists. `--rpc-index 1` selects the fixture's second local peer; the default remains peer 0. This is operator configuration, not an API-controlled RPC URL. An example while both validators are running:

```sh
python3 -B tools/wallet_ui.py --root .data/l3 --profile recovered --rpc-index 1 --port 8766 --duration 600
```

Repeat actual snapshot-peer acceptance on a fresh fixture:

```sh
python3 -B tools/archive_localnet.py --root .data/archive-new
```

The runner owns/stops two loopback validators. It checks collector restart/immutability, actual full-snapshot loading and new finalization, seed recovery that fails without retained history, a recovered-witness private send, a second seed restore, backend integration, corruption/missing files, payment omission with recomputed checksums, permanent nullifiers and pending-payment safety. Private evidence remains under its ignored root. See LOCAL-010 validation.

## Automatic dedicated-service retention

The current sealed service bundle (`native-service-bundle-v6`) includes `history_retention.py`. Updating an older v1/v2/v3/v4/v5 installation preserves its original private data and loaded/paused state; it does not start a deliberately paused service. On a subsequent authorized start, the unprivileged service collects and verifies a complete prefix before opening the invited gateway/faucet. It repeats collection every 60 seconds while validators run. It needs only the fixed operator RPC credential; no wallet, password, faucet signer or sponsor authority is passed to the collector.

The service writes `recovery-history` and publishes a separate `recovery-history-mirror` under its owner-only network root. Each backup captures one manifest, copies only its referenced immutable payloads and publishes the manifest last, with file/directory sync. A failed copy retains the previous committed backup. Complete identical unreferenced files can be reused after interruption. No archive segment is removed, replaced or silently repartitioned. The mirror cannot roll back or change a previously committed prefix. Unrelated files, secrets, locks and uncommitted temporary payloads are excluded from copies.

Collection verifies all native signatures/proofs and reconciles finalized state; the Python mirror additionally checks identity, checksums, continuity and bounds. Those mirror checks are not consensus proofs. Fresh wallets still perform their own complete replay and live finalized-pool reconciliation. The archive remains unsuitable as authoritative inclusion/absence evidence for resolving an interrupted outer transaction.

`service_runtime.py history-status`, run through the existing dedicated-account administrator wrapper, returns the **last recorded** phase, collection PID, success timestamp, retained tip, observed finalized tip, segment count, source/mirror bytes and sanitized error. `status` also includes this record after checking live validators. A persisted `ready` file alone is not proof that a stopped service is live. No new desktop access to private files or raw RPC is granted.

Admission stays closed if initial verification fails. Later collection failure, an observed tip more than 1,024 slots behind, no success within 180 seconds, or an invalid worker stops ingress and both validators and parks the service without reinitializing anything. Each collection is limited to 120 seconds. Storage is monitored during collection: each store is limited to 256 MiB, and at least 1.5 GiB plus one maximum 32 MiB segment of disk headroom is required. Existing native manifest/segment bounds also apply. Temporary/orphan files count toward capacity. These are monitored development limits, not filesystem quotas. An unusually large write can cross a limit before the monitor stops collection; committed files are retained for investigation. A failed capture never publishes an incomplete backup.

To recover a damaged primary, first stop the service and preserve the failure evidence and both histories. Validate a captured mirror with a fresh restored seed against a trusted current RPC, including balance reconciliation. Reconstruct the primary from that verified committed manifest and its exact referenced files **as the service identity**, retaining owner-only permissions; preserve the displaced damaged directory. Restart the original service with its original keys, journals, policies and genesis. If the mirror ends before history still available from the RPC, repair from another complete retained copy; never clear manifests to pretend the missing prefix was empty. This version fails closed and requires this operator recovery step rather than silently replacing a damaged primary.

The two stores are on the same disk. This covers interrupted collection/copy and some file damage; it does **not** cover disk or host loss. Independent off-host storage, alert delivery, longer retention/capacity policy and sustained/adversarial load evidence remain public-testnet work. The invited gateway now serves separate authenticated retained pages from the mirror; ordinary RPC responses stay canonical. Updated wallets can recover their balance and witnesses through a snapshot-only peer plus that prefix. Historical unknown outer-transaction outcomes still require complete canonical RPC evidence; retain access to an archival RPC for those cases. See [the gateway runbook](invited-testnet-runbook.md#retained-history-pages).

Repeat automatic collection, actual collector SIGKILL, fresh-seed snapshot-peer recovery and recovered-witness spending locally:

```sh
PYTHONPATH=tools nice -n 15 python3 tools/retention_localnet.py --root .data/rh-new
```

This uses a new disposable fixture, stops its own validators in cleanup and has a ten-minute acceptance timer. The installed-service rehearsal uses a separate finite deadline and restores the normal launchd definition to its unloaded state. See LOCAL-026 validation.

Before public testnet this needs independent replicated retention, operational alerting, sustained/adversarial load evidence. Production wallet/sponsor keys, launch parameters and independent protocol/runtime review remain separate release gates. No public deployment is authorized by these tools.

## Independent replica

LOCAL-030 adds separately runnable TLS replication and source-stopped recovery. Optional configured replication must durably acknowledge the exact captured mirror checkpoint before retention reports success. Its persistent requirement survives service restart; removing or damaging the configuration cannot silently restore local-only health. A required receiver outage closes ingress and pauses validators through the existing supervisor. Only a dedicated history credential crosses this boundary; wallet/sponsor/validator/raw-RPC keys are excluded.

See the [replica runbook](history-replica-runbook.md). Actual TLS/process crashes, source-history-unavailable fresh-seed snapshot-peer recovery and a recovered-witness spend passed locally. The original installed service also preserved its pool/20 nullifiers and all 27 private files through receiver outage/restart. The final corrected receiver shutdown audit passed with validators paused. These independent processes remain on one Mac: real off-host placement, canonical archive redundancy and alert delivery remain external-testnet operations work. Ciphertext replicas do not replace canonical transaction-status evidence or validator/key/tower backups.
