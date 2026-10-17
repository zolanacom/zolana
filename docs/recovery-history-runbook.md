# Retained ciphertext history

An independent privacy L1 needs a recovery path after validator transaction history is pruned. Native snapshots retain the pool and permanent nullifiers but not old ciphertexts from closed staging accounts. `native-wallet archive` collects the public finalized native history separately; a fresh seed can then discover its notes through a snapshot-restored peer plus this retained prefix.

Build the locked offline wallet, then collect from an authenticated full-history local RPC before it prunes:

```sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked -p native-wallet
target/debug/native-wallet archive --network .data/l3/network.json --rpc http://127.0.0.1:18899 --history .data/l3/recovery-history
```

No wallet, password or sponsor key is required. The command verifies all retained proofs again, reads the new finalized RPC suffix and checks the complete pool and latest finalized header before publishing the manifest. Repeat the same command to extend the archive. It is a bounded one-shot collector, not an installed daemon or scheduled service. Initial collection requires history from genesis; running it for the first time against a snapshot-only RPC cannot recreate lost ciphertexts.

The archive retains block continuity fields and successful signed native transactions, including upload/seal/finalize/close data and needed loaded addresses. Unrelated transaction bodies are discarded. These are public chain ciphertexts/metadata; wallet seeds, passwords and decrypted notes are never retained here.

Segments have immutable checksum-addressed filenames. Each contains at most 1,024 produced blocks and 32 MiB, with an 8 MiB per-record bound. The manifest has a 4 MiB/16,384-segment bound. Every successful collection can add a partly filled segment, so collection frequency affects the segment limit. Monitor both bytes and descriptor count; capacity exhaustion fails closed. Full retained replay and wallet tree/witness storage still grow with history. This implementation is not the final production indexing design.

The writer requires an owner-only directory and holds an OS-backed exclusive lock. It syncs a temporary segment before publishing its immutable name with a non-overwriting hard link. It atomically replaces and directory-syncs the manifest only after the complete verified extension succeeds. An interrupted temporary write is unreferenced; a complete identical orphan can be reused. Existing segments are never overwritten, and a lagging RPC cannot roll the manifest backward. Do not remove the lock while a writer runs. Stop collection before copying the directory for backup, or copy a captured manifest and its complete referenced immutable files. A generic live directory copy can race a newly published manifest and will be rejected if incomplete.

For a newly restored seed, supply retained history on balance or payment commands:

```sh
target/debug/native-wallet balance --network .data/l3/network.json --wallet .data/my-wallet/recovered.wallet.json --password-file .data/my-wallet/unlock.password --rpc http://127.0.0.1:19899 --history .data/l3/recovery-history
```

`deposit`, `send` and `withdraw` accept the same option. The wallet verifies signatures, native staging authorization, Orchard proofs, nullifiers, commitments/backing, continuity and the complete live finalized pool. It reads a continuous recent suffix from RPC when the retained prefix ends earlier. A prefix may cover a slightly lagging peer's target; the target header must still match that peer. Cache reuse retains its existing finalized-checkpoint protections. A damaged/missing segment, wrong network, gap, mismatched latest header or state discrepancy cannot produce a partial balance. Fix the retained files from a verified backup or use a complete archive RPC; do not reset the seed or payment journals.

Checksums detect damage, not consensus. The configured genesis and RPC consensus remain trusted. Retained block metadata is not an independent proof that an outer transaction signature executed or was absent. The scanner discards retained transaction identities for this purpose and takes the final block height from RPC. `resolve` rejects `--history` and continues to require canonical full RPC history/status checks; `reclaim` also retains its existing authoritative checks. An unknown payment stays blocked if those checks are unavailable. Preserve access to an archival RPC for this recovery case.

The device-local UI automatically uses `<network-root>/recovery-history` when its manifest exists. `--rpc-index 1` selects the fixture's second local peer; the default remains peer 0. This is operator configuration, not an API-controlled RPC URL. An example while both validators are running:

```sh
python3 -B tools/wallet_ui.py --root .data/l3 --profile recovered --rpc-index 1 --port 8766 --duration 600
```

Repeat actual snapshot-peer acceptance on a fresh fixture:

```sh
python3 -B tools/archive_localnet.py --root .data/archive-new
```

The runner owns/stops two loopback validators. It checks collector restart/immutability, actual full-snapshot loading and new finalization, seed recovery that fails without retained history, a recovered-witness private send, a second seed restore, backend integration, corruption/missing files, payment omission with recomputed checksums, permanent nullifiers and pending-payment safety. Private evidence remains under its ignored root. See LOCAL-010 validation.

Before public testnet this needs replicated retention, capacity/lag alerts, backup recovery drills and sustained/adversarial load evidence. Production wallet/sponsor keys, launch parameters and independent protocol/runtime review remain separate release gates. No public deployment is authorized by these tools.
