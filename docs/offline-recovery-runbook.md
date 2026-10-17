# Offline and damaged-snapshot acceptance

Use Rust 1.92 and Python 3.14 from the repository root. Stop any other fixture using RPC ports 18899/19899, then build and run against a new ignored directory:

```sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p native-localnet
python3 -B tools/offline_localnet.py --root .data/off1
```

This requires the already built fork validator and native wallet binaries. Keep the root path short enough for the local admin socket. The runner uses two real loopback validators with 80%/20% stake, public fixture validator/sponsor keys and random encrypted wallet keys. It retains receipts, logs and an `offline-result.json` journal and stops owned children on every exit. Reserve at least 2 GiB of free space. The test takes several minutes because epoch advancement and proof expiry are observed through finalized RPC state.

The baseline deposits 100 units to Alice and sends 20 to Bob. An unused one-unit deposit proof is uploaded and sealed on both nodes. Its dummy nullifiers are distinct from accepted payments. The minority stops while the majority sends five units from Alice to Bob and withdraws two for Bob. The runner waits for four epoch boundaries and a finalized slot beyond the unused deposit's original expiry. It does not edit authorization data or lower consensus thresholds.

An ordinary saved-tower restart is attempted first. Fresh finalized roots and exact native state are required; an available RPC with stale balances does not pass. If ordinary repair stalls for the bounded observation interval, the runner stops that process, preserves its ledger/tower and loads a newer full snapshot into a separate genesis-only ledger. It records which path recovered the state. The expired sealed deposit must fail at the native finalizer, leave its buffer and pool unchanged, create no nullifiers and allow staging rent cleanup. Another private send must succeed, and a newly staged copy of that live spent proof must fail on the recovered peer.

Next, stop the minority and select a full archive beyond its shutdown tip. `prepare_snapshot_recovery` creates a genesis-only replacement ledger and verifies the copied archive's SHA-256 before returning it. Stale or changed input cannot select a new active ledger. The experiment deliberately truncates only a copied archive, forces the actual validator to load it and requires a nonzero exit with exact signed-tower bytes preserved. It retains that damaged ledger for diagnosis.

A separate genesis-only ledger receives a verified clean copy. Startup must log extraction of the selected full archive, bank reconstruction and successful bank verification. Fresh finalization and identical pool/permanent-marker accounts are required. Old account files and post-genesis transaction history are not copied. A new real deposit is then staged and finalized through the restored peer's RPC, with live replay rejection and rent cleanup.

The snapshot peer must reject a wallet balance request when ciphertext archive history is unavailable. Seed-only restored wallets instead scan the complete archive node and must recover Alice/Bob balances 75/24, backed by 99 native units. Final native state contains 12 commitments and 12 permanent nullifiers. A compact validator snapshot alone is not a wallet history service.

This is bounded catch-up on a 128-slot-epoch fixture. It does not establish arbitrary-duration offline recovery, history pruning recovery, power-loss durability, malicious snapshots that are well formed, Byzantine behavior or public-network operations.

For an earlier failed attempt that stopped specifically at ordinary offline catch-up, `--resume-offline` can continue the preserved root. It verifies the recorded four-payment sequence and source state, saves the failed journal, uses the guarded coordinated path to restart the majority, then recovers the minority from a fresh snapshot. It never repeats the recorded payments. Other failure phases and completed runs are rejected. This continuation exists to retain diagnostic provenance, not to turn a failed ordinary repair into a passed ordinary-repair claim.
