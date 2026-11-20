# Durable nullifiers in native accounts

The original pool stored 256 spent nullifiers and stopped after 128 two-action payments. Increasing that array would only move the lifetime limit and would make every payment read and rewrite a growing spent set.

Each accepted action now creates a permanent, 40-byte account owned by the native payment program. Its PDA seeds are `native-payment-spent-v1`, the pool address and the action's full 32-byte nullifier. Its data is `NSPENT01` followed by that nullifier. Finalize requires exactly six accounts: pool, sealed buffer, signed public sponsor, System Program and the two writable marker PDAs in action order. The native processor derives these addresses from the decoded signed proof. Supplying arbitrary absent accounts, omitting a marker, aliasing the pair or supplying a read-only marker fails.

An existing native-owned account at either derived address rejects the payment, even if its data is malformed. An unused address must be System-owned and empty. The processor verifies the real Orchard proof before allocating markers. It tops each address up to rent exemption, allocates it and assigns it through System Program CPI, signing only for the authenticated PDA. Using allocate/assign supports addresses that already received unsolicited funds. Existing donations are retained. There is no operation to close, overwrite or reset a marker; the staging close operation rejects its format and size.

Marker rent is a permanent sponsor expense, separate from shielded backing and transaction fees. At the current development rent schedule, each 40-byte marker requires 1,169,280 units; two new markers require 2,338,560 units before fees. Existing contributions reduce the top-up. A withdrawal credits its public value to the sponsor but still pays marker rent. Storage cost and account growth need economic calibration before any public release.

Proof validation, public movement, marker allocation, frontier/backing changes and staging consumption execute in the same Bank transaction. Any subsequent instruction failure must roll back all these effects, including the System Program debit and rent transfers. Marker data lives in ordinary authenticated runtime accounts, so replay, snapshots and fork selection use the existing account machinery rather than a side database or RPC-maintained spent set.

The pool format is now `NPOOL002`, 1,601 bytes: network domain, rent floor, backing, commitment count, root count, a 32-level frontier and 16 recent anchors. The old format is rejected. This is an incompatible local-development revision: use a fresh genesis, preserve the previous network and never point the new binary at its old ledger. No migration or public upgrade is claimed. The proof authorization and submission wire formats remain version 1 because their cryptographic statements have not changed.

The 128-payment storage cap is removed. The compact frontier explicitly fails closed at 4,294,967,294 commitments (2,147,483,647 two-action payments), avoiding overflow of the fixed-depth tree; tree rollover is separate future work. Checking two markers remains bounded as history grows. This does not remove the shared-pool write lock, the 16-root witness freshness window, the need for a wallet/indexer, storage growth, or the need to benchmark and audit the protocol. Nullifiers, sponsors, submission timing and public boundaries remain visible.

## Status update (2026-11-20)

The marker design above is kept as written. The pool format and root window it names have since been replaced:

- `NPOOL002` (1,601 bytes, 16 recent anchors) is rejected by the current decoder (`PoolState::decode` in `protocol/payments/src/state.rs`). The accepted formats are `NPOOL003`, 3,137 bytes with 64 recent roots (`STATE_BYTES`, `MAX_ROOTS`; [decision 0006](0006-concurrent-anchor-window.md)), and `NPOOL004`, which keeps a 512-slot anchor history instead of per-payment roots (`SLOT_STATE_BYTES` in `state.rs`; `ANCHOR_WINDOW_SLOTS` in `protocol/payments/src/anchors.rs`).
- The "16-root witness freshness window" in the last paragraph is accordingly 64 roots under `NPOOL003` and 512 slots under `NPOOL004`.
