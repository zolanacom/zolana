# Native private payments

Local development of protocol-native shielded payments for an independent Agave-derived network. The project name is undecided.

The selected architecture is an [independent privacy L1 with its own native coin](docs/decisions/0005-independent-privacy-l1.md). A Solana asset bridge is later work; no mainnet settlement or bridge is implemented.

Fresh local rehearsals support [recipient-bound native withdrawals](docs/withdrawal-runbook.md): the user chooses a public account independently from the fee sponsor, with the default signing authority recoverable from the encrypted wallet seed. Existing genesis, historical payment bytes and sponsor policies remain preserved.

[User-paid withdrawals](docs/user-paid-fees-runbook.md) can use a fee authority recovered from the encrypted seed, with an explicit gross-debit cap and crash recovery. They work without operator sponsor credentials once the public fee account has native coins for fees and refundable upload rent.

This repository starts from upstream Agave source and a new development history. Networking and consensus are retained while a separate payment module is evaluated. Public transfers remain supported in the minimal design; privacy is an additional native capability, not a claim about every transaction or application.

See development status for the current prototype stage, completed components and production gaps.

The [standalone tester wallet](docs/tester-wallet-runbook.md) packages the device-local client independently of the checkout and operator keys, with a pinned genesis/RPC profile, HTTPS for remote endpoints and preserved wallet data across package replacement. Extracted-package acceptance passed offline recovery and real local-validator reads. This unsigned development bundle remains local; hosting and release review are still required before inviting testers.

[Sponsor-free private sends](docs/private-send-runbook.md) use the same seed-derived fee authority with an explicit gas/rent quote and durable cap. Real browser/CLI sends, interrupted uploads, lost finalized replies, validator crash/restart, spent-proof rejection and restored-seed spending passed locally. Recipients receive the full private amount; the sender funds fees and refundable staging rent publicly. No protocol or consensus change is needed.

[Self-service test distribution](docs/test-faucet-runbook.md) supplies a fixed private test grant and public gas through a pinned faucet, using a separate encrypted reservoir wallet, signed claims and finite lifetime limits. The device-local wallet requests both together and checks finalization automatically. [Invited tester access](docs/invited-testnet-runbook.md) gates the wallet RPC gateway and faucet with single-wallet codes, expiry/revocation and durable request budgets. Raw validator RPC remains operator-loopback; external hosting and network isolation remain deployment work. Everything remains local.

The product is an independent privacy blockchain with its own validators and fee/staking coin. Its first user interface is a payments wallet; building that interface does not turn the chain into a Solana application. A DEX, private swaps and an Axiom-style terminal are not implemented. The Solana bridge remains later work.

The [local wallet preview](docs/local-wallet-ui-runbook.md) now creates encrypted wallets, guides recovery-file backup, sponsors test funding and submits real private payments. Concurrent acceptance finalized 24 deposits and 24 private sends and preserved pool/nullifier state through a coordinated restart; see LOCAL-008 validation. This uses fresh-genesis NPOOL003; preserve older fixtures and use their corresponding historical builds.

Encrypted incremental scanning reduced a preserved archive sync from 5.080 s to 1.092 s in a local measurement. Browser copy/paste recovery restored a funded wallet and finalized a private send, with balances and nullifiers verified on both peers; see LOCAL-009 validation.

Phone-sized onboarding, actual recovery-file download/upload and private payments now pass isolated browser acceptance. Separately retained ciphertext history also recovers fresh seeds and supports spending through a snapshot-restored validator without its old transaction ledger. See LOCAL-010 validation and the [retention runbook](docs/recovery-history-runbook.md). This remains local testnet preparation, with independent security review, production keys/sponsorship and retention operations still open.

## Layout

- `protocol/payments/`: bounded payment validation and submission primitives.
- `clients/cli/`: local proof and payment development commands.
- `clients/wallet/`: encrypted seed wallet, verified history scanning, witnesses and signed RPC payments.
- `clients/wallet-ui/` and `tools/wallet_ui.py`: device-local onboarding and payments interface over the real wallet CLI.
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

The local wallet supports random private keys, encrypted seed-only backups, network-bound addresses, finalized note discovery, balances, private sends with change, withdrawal and pending-payment resolution. See [the wallet runbook](docs/local-wallet-runbook.md) and LOCAL-003 validation. It reconstructs private notes from complete RPC history or separately retained verified ciphertexts plus a recent RPC suffix, and accelerates repeat scans with encrypted checkpoints. Unknown-payment resolution retains canonical full-RPC checks; missing required history fails closed. RPC consensus remains trusted; the scanner is not a light client. No note cache is needed for seed recovery, but retention operations, bounded cache/tree scaling, independent security review and production economics remain development work.

Interrupted uploads now retain a private staging journal and support guarded rent reclamation, with OS locks serializing value-changing commands on one wallet path. See [staging recovery](docs/staging-recovery-runbook.md) and LOCAL-007 validation.

For majority or whole-cluster restarts, use the [coordinated restart runbook](docs/coordinated-restart-runbook.md). The explicit path verifies a saved tower and retained bank checkpoint before invoking the upstream hash/shred-version/stake gate, then requires new finalization. It preserves ordinary restart guards and signed ledger data.

The [fault recovery runner](docs/fault-recovery-runbook.md) exercises owned-process SIGKILL, competing private payments during a shred partition and canonical rejoin. Its explicitly enabled loopback fault control uses the upstream shred-reception gate. See the fault validation record for observed recovery, nullifier rollback and remaining coverage.

The [offline recovery runner](docs/offline-recovery-runbook.md) covers multiple epoch boundaries, expired staging, snapshot fallback and damaged-archive rejection. Its validation record preserves the failed ordinary-repair attempt separately from successful snapshot-assisted recovery.

## Attribution

Upstream attribution is preserved in [THIRD_PARTY.md](THIRD_PARTY.md) and vendored notices.
