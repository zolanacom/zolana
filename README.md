# Native private payments

Local development of protocol-native shielded payments for an independent Agave-derived network. The project name is undecided.

The selected architecture is an [independent privacy L1 with its own native coin](docs/decisions/0005-independent-privacy-l1.md). A Solana asset bridge is later work; no mainnet settlement or bridge is implemented.

This repository starts from upstream Agave source and a new development history. Networking and consensus are retained while a separate payment module is evaluated. Public transfers remain supported in the minimal design; privacy is an additional native capability, not a claim about every transaction or application.

See development status for the current prototype stage, completed components and production gaps.

## Layout

- `protocol/payments/`: bounded payment validation and submission primitives.
- `clients/cli/`: local proof and payment development commands.
- `clients/wallet/`: encrypted seed wallet, verified history scanning, witnesses and signed RPC payments.
- `node/agave/`: upstream validator source with gated native-payment registration.
- `node/adapter/`: metered native execution, staging and real coin accounting.
- `node/validator-check/`: signed-transaction integration tests using Agave Bank.
- `node/localnet/` and `tools/localnet.py`: real local validators, RPC fixtures and snapshot/restart checks.
- `docs/decisions/`: architecture and scope decisions.

See LOCAL-001 for the first implementation milestone and its validation record. The standalone verifier and real-proof offline fixture are implemented. Native runtime integration and coin accounting are implemented locally; see LOCAL-002 and [the integration design](docs/decisions/0003-native-validator-integration.md). Nothing in this repository has been deployed or connected to a production network.

## Run the local proof fixture

```
sh tools/dev.sh fetch --locked
sh tools/dev.sh run --offline --locked -p payment-lab -- proof-smoke
CARGO_BUILD_JOBS=2 sh tools/dev.sh test --offline --locked -p native-payment-program --test runtime
CARGO_BUILD_JOBS=2 sh tools/dev.sh test --offline --locked -p native-validator-check --test bank
sh tools/check.sh
```

This uses a project-local dependency cache and the installed Rust 1.92 toolchain. The fixture uses public synthetic test keys and creates no real funds. It verifies real proofs and authorization, stages/decodes the payment and confirms local decryption of payment and change. The proof-smoke command is not a wallet or an on-chain transfer. The separate runtime and Bank tests execute synthetic native payments. Two local validator processes have executed payments over RPC, restored a fresh ledger from a full snapshot and restarted the recovered ledger. See [the local runbook](docs/local-validator-runbook.md) and LOCAL-004 validation. Permanent proof-derived nullifier accounts now replace the original 128-payment array; see [the storage decision](docs/decisions/0004-durable-nullifiers.md) and LOCAL-006 validation. The Bank test accepted 129 distinct real-proof payments; the new format also passed two-validator RPC, snapshot and restart checks. This is a fresh-genesis development format with separate permanent storage rent and a fixed-depth tree limit. Wallet scan performance, archive availability and throughput work remain.

The local wallet supports random private keys, encrypted seed-only backups, network-bound addresses, finalized note discovery, balances, private sends with change, withdrawal and pending-payment resolution. See [the wallet runbook](docs/local-wallet-runbook.md) and LOCAL-003 validation. It reconstructs private notes from complete archive history and fails closed when history is missing. RPC consensus remains trusted; the scanner is not a light client. No note cache is needed for seed recovery, but archive availability, scan performance, independent security review and production economics remain development work.

Interrupted uploads now retain a private staging journal and support guarded rent reclamation, with OS locks serializing value-changing commands on one wallet path. See [staging recovery](docs/staging-recovery-runbook.md) and LOCAL-007 validation.

For majority or whole-cluster restarts, use the [coordinated restart runbook](docs/coordinated-restart-runbook.md). The explicit path verifies a saved tower and retained bank checkpoint before invoking the upstream hash/shred-version/stake gate, then requires new finalization. It preserves ordinary restart guards and signed ledger data.

The [fault recovery runner](docs/fault-recovery-runbook.md) exercises owned-process SIGKILL, competing private payments during a shred partition and canonical rejoin. Its explicitly enabled loopback fault control uses the upstream shred-reception gate. See the fault validation record for observed recovery, nullifier rollback and remaining coverage.

The [offline recovery runner](docs/offline-recovery-runbook.md) covers multiple epoch boundaries, expired staging, snapshot fallback and damaged-archive rejection. Its validation record preserves the failed ordinary-repair attempt separately from successful snapshot-assisted recovery.

## Attribution

Upstream attribution is preserved in [THIRD_PARTY.md](THIRD_PARTY.md) and vendored notices.
