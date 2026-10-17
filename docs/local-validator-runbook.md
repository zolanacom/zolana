# Local validator and recovery runbook

This tooling creates disposable local funds and public-key payment fixtures. It is not a wallet for external funds. Every RPC URL is loopback; both endpoints must match the saved genesis hash before the payment harness sends transactions. Generated identities, signing files, proofs, ledgers, snapshots, logs and result JSON stay under ignored `.data/`. Network directories are private to the local OS account, and signing files have mode 0600.

## Build and start

Run from the repository root:

```
sh tools/dev.sh fetch --locked
sh tools/build_localnet.sh
python3 -B tools/localnet.py init --root .data/v2
python3 -B tools/localnet.py start --root .data/v2
python3 -B tools/localnet.py status --root .data/v2
python3 -B tools/localnet.py verify --root .data/v2
```

The build uses the fork's actual Agave validator source and the root lockfile, including the upstream-pinned networking patches and compatible SDK versions. It does not use the separately installed validator binary. Native libraries compile locally with debug symbols disabled. The local executable uses the platform allocator because jemalloc’s configure step rejects spaces in this workspace path; the imported validator’s default jemalloc feature remains available for other builds. Keep space for the native build and two ledgers; the tooling does not delete unrelated files.

The default RPC endpoints are `http://127.0.0.1:18899` and `http://127.0.0.1:19899`. Validator identities and genesis fingerprints are in `.data/v2/network.json`. No public entrypoints, faucet, production assets or hosted services are used. Validator gossip and RPC bind to loopback. The two processes have distinct keys and ledgers and genesis stake weights of 80% and 20%.

The current pool format is `NPOOL003`; the earlier fixtures use `NPOOL001` or `NPOOL002` and must remain preserved. Startup rejects that old format before launching the new binary. This development change requires a fresh genesis; it does not migrate existing notes. Initialization refuses an existing network directory. To repeat the complete fresh-pool experiment, stop the current network and choose a new directory using `--root .data/<new-directory>` on every command. No reset/delete command is provided.

Restarting majority stake needs the explicit [coordinated restart procedure](coordinated-restart-runbook.md). Ordinary startup can expose RPC before ledger replay and quorum startup finish; use new finalized blocks as the liveness criterion.

## Verification contract

The test stages real two-action Orchard v2 proofs in signed transactions and checks the serialized signed packet bound. Deposits debit a real sponsor account; a private payment sends 40 with 60 change; withdrawal returns 40, leaving 60 units of backing and six commitments. Negative tests require confirmed on-chain instruction errors at the expected instruction index. RPC errors, timeouts and preflight failures do not count as successful rejection tests.

Failure after a funded deposit must roll back both its System Program debit and note/staging effects. Failure after a private finalization must also roll back pool and staging bytes. An invalid proof and a sponsor unable to fund its deposit must not change the pool. Both permanent nullifier accounts must roll back too. An unsolicited rent-sized contribution to a marker address must not block a valid payment; allocation retains its donation. The second validator must converge to exactly the same complete pool account and all six permanent marker accounts.

The recovery sequence stops the follower and waits for a finalized full snapshot beyond the leader tip observed at shutdown. It creates a separate genesis-only ledger, checks the archive's SHA-256 copy digest and forces archive extraction at startup. No old account files or post-genesis transaction ledger are copied. It checks startup log evidence for archive loading, Bank reconstruction and successful Bank verification, waits for the follower to catch up, and repeats the pool, permanent-marker data/owner/balance and spent-payment tests over RPC. It then restarts that same recovered ledger and repeats the checks again while the original proof authorization remains valid.

Consensus tower files stay in per-identity `consensus-*` directories outside the replaceable ledger. Subsequent starts require the saved tower. Only the initial bootstrap leader can start producing before voting; the follower retains the normal vote-before-leader gate. Recovery directory names are short enough for macOS admin sockets. The harness uses admin RPC shutdown and explicitly reaps or waits for the managed process.

Results are written to `.data/v2/payment-result.json` and, only after both restore and restart succeed, `.data/v2/recovery-result.json`. Test completion leaves both local processes running and reduces their background logs to warnings/errors. Startup retains the snapshot and Bank verification messages needed by the recovery checks. To stop them through their local admin sockets:

```
python3 -B tools/localnet.py stop --root .data/v2
```

Both programs and their local data are experimental. The pool keeps 16 recent roots; permanent nullifier accounts remove the old 128-payment storage cap. Each payment creates two 40-byte markers, costing 2,338,560 units of permanent sponsor rent at the current schedule, plus transaction fees. Rent is separate from shielded backing. The fixed-depth tree accepts at most 4,294,967,294 commitments before failing closed. Shared-pool throughput, tree rollover, wallet recovery and independent cryptographic review remain separate work. See the durable-storage decision in docs/decisions/0004-durable-nullifiers.md. The earlier LOCAL-004 validation record describes the original bounded format; current-format evidence is recorded separately in LOCAL-006.
