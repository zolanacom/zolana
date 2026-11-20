# 0003: Native validator payment integration

The fork registers `native_private_payments` in Agave's builtin registry behind a new feature account. The activation identifier is part of the feature set. Genesis must activate that feature and provision the fixed pool PDA owned by the native payment program. There is no payment instruction for initializing or replacing the pool. Unmodified upstream validators cannot execute this built-in or validate this network's payments.

The integration lives in `node/adapter`; the cryptographic rules and serialized pool state remain in `protocol/payments`. `node/validator-check` exercises the actual Agave Bank and builtin registration from a fresh synthetic genesis. This is the chain-specific change: validators verify proofs and apply shielded state transitions as part of transaction execution and Bank state hashing.

The pool account stores its network domain, reserved rent, backing, Orchard frontier, recent anchors and spent nullifiers. The domain is an independently chosen nonzero identifier committed by genesis, not the literal genesis hash (which would be self-referential). Wallet configuration must independently check the real genesis fingerprint. Fixtures use a public synthetic domain; it is not a launch configuration.

Each accepted two-action payment records both nullifiers and commitments. Negative public value balance invokes a signed System Program transfer from the sponsor into the pool; positive balance releases pool backing to that sponsor. Internal transfers preserve backing. Backing and rent are checked separately; surplus donations cannot mint notes and do not block payments. State, backing and staging consumption rely on Bank transaction atomicity. A shared fixed pool serializes payments and is a deliberate development constraint.

The first boundary counterparty is also the sponsor: deposit source and public withdrawal recipient are the sponsor account committed by the payment authorization. A shared sponsor can submit private transfers but no automatic fee reimbursement is implemented. Sponsor keys, transaction fees, timing, staging accounts and public deposit/withdrawal amounts remain visible. The network does not provide network-layer anonymity or private execution of arbitrary applications.

A sponsor creates a rent-funded staging account, writes sequential chunks, seals the digest, then finalizes using a small instruction. Initialization requires both account and sponsor signatures. Staging is bounded to 16 KiB, chunks to 768 bytes and expiry to 1,024 slots. Only its sponsor may close the buffer and reclaim rent, including after expiry or consumption. The pool cannot be closed through that path. Invocation into this native handler via CPI is rejected in this version.

Finalization charges 1,100,000 compute units before proof verification; fixture clients request 1,400,000 units explicitly. Other operations charge 10,000. These are conservative local development charges, not calibrated production throughput claims. The roughly 9 KiB proof travels in multiple ordinary signed transactions; no network packet limit is enlarged.

The persisted development pool holds 256 nullifiers (128 payments including deposits and withdrawals) and 16 recent roots. It fails closed at capacity. Durable paging, long-lived witness maintenance, production metering, wallet scanning, snapshot restoration and multi-process network tests remain follow-up work. The account format and development IDs are experimental.

Rust 1.92 is used throughout the tested root workspace. Changes in imported code include builtin and feature registration, matching syscall dependency pins, explicit lifetime annotations and narrow compatibility adjustments for compiler-generated warnings. Upstream ownership notices remain intact. The root lockfile is the tested dependency graph; the separate full Agave workspace and validator executable are not certified by these tests.

## Status update (2026-11-20)

This record describes the first integration and is kept as written. Two figures in its capacity paragraph no longer describe the code:

- The pool no longer stores spent nullifiers, and the 128-payment cap is gone. Each nullifier is a permanent 40-byte marker account (`MARKER_BYTES` in `node/adapter/src/nullifiers.rs`; [decision 0004](0004-durable-nullifiers.md)).
- The pool keeps 64 recent roots, not 16, in format `NPOOL003` (`MAX_ROOTS` in `protocol/payments/src/state.rs`; [decision 0006](0006-concurrent-anchor-window.md)). The later `NPOOL004` format keeps a 512-slot anchor history instead of per-payment roots (`ANCHOR_WINDOW_SLOTS` in `protocol/payments/src/anchors.rs`).
