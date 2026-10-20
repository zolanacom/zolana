# Opt-in LOCAL-059 original-checkpoint ancestry source

LOCAL-059 removes the fixed 100,000-entry ancestry cutoff in the isolated SDK4
Agave 4.3.2 resume driver at upstream commit
`a203300045b405f86c9c84308b2eae76af69ac3b`. It retains the original immutable checkpoint and walks the actual
Blockstore parent metadata from a pinned resumed root to that checkpoint. It
changes only `zolana-fast-check/src/ancestry.rs`, `ancestry_tests.rs`, `main.rs`,
`resume.rs` and `service.rs`. Cargo manifests and the lockfile are unchanged.
The frozen LOCAL-056, LOCAL-057 and LOCAL-058 patches remain unchanged.

Prepare source from the already local pinned upstream archive:

```sh
python3 tools/prepare_native_candidate.py \
  --archive /absolute/path/agave-a203300.tar.gz \
  --output /absolute/path/new-LOCAL-059-directory \
  --native-restart-059 --manifest
```

The revision flag explicitly applies the frozen LOCAL-056 patch, then each
pinned LOCAL-057, LOCAL-058 and LOCAL-059 delta. It is mutually exclusive with
`--native-fee-057` and `--native-service-058`; the default remains LOCAL-056.
Every transition checks the exact before/after content of its changed files,
including absence before introducing the new ancestry helper and test module.
The LOCAL-059 manifest also pins final bytes and SHA-256 for every file changed
by the complete patch chain. Preparation verifies this final inventory and records
the ordered patch/manifest provenance in `zolana-candidate.json`.

The output must be fresh and its parent must already exist. Preparation never
downloads, resolves dependencies, builds, starts validators, opens wallet keys,
changes an existing source tree, or touches a ledger. Partial failed outputs are
retained for inspection.

The ancestry verifier reads fallible metadata, requires each parent to be strictly
below its child and never below the original target, and succeeds only on reaching
the actual original checkpoint. Missing metadata, invalid links, cancellation,
read errors and the existing startup deadline fail closed. The loop yields every
4,096 entries while retaining its progress; this is not an acceptance cutoff.
The walk remains O(history), with the existing 60-second total resume-validation
budget; removing the entry cutoff does not make startup time unlimited.
The driver releases the BankForks read lock before walking Blockstore history.
Service stop signals can cancel that walk without publishing readiness.

Existing original genesis, identity/voting keys, signed vote histories, retained
certified checkpoint BANK hash, native feature and NPOOL004 layout checks remain
required. No checkpoint is advanced, no resume manifest is rewritten, no alternate
ancestry is accepted, and no retention or pruning policy is changed. Operators
must retain the original checkpoint and all required ancestry; unavailable
history causes refusal rather than initialization or recovery from guessed state.

The invocation remains resume-only:

```sh
zolana-fast-check --resume-root /original/absolute/fixture/root --service
```

This source revision does not alter native payments, fees, proof verification,
consensus thresholds, the wallet, gateway or Linux sandbox. It does not itself
establish a successful Linux build, a live long-history restart, cryptographic
security, independent validators or production readiness. Build and live restart
evidence must be recorded separately against the exact final source hashes.

The LOCAL-059 delta SHA-256 is
`40d48bb66ee03502861a66876f921740e4282897279a8fa765009ab6127f7367`.
The `LOCAL-059-source.json` SHA-256 is
`d11952a9f613a7dcfc679f4eff9dd5de6081d47740688d1863226db7b113ec19`.
Its final inventory covers 84 files changed by the complete patch chain.
The unchanged 337,354-byte lock SHA-256 remains
`36a97da6d6f94eae278de847aea50c2adba39aaf54a329cae6f813adbcf4ebec`.

Fresh local reproduction matches all 1,903 file/symlink contents of the final
isolated source, and the vendored transaction-view provenance guard passes.
Eleven Python preparation tests pass. The new Rust module contains 13 focused
tests, including an actual Blockstore path beyond 100,000 links before and after
reopening the same database, corrupt raw metadata, malformed links, cancellation
and deadline failures. Those Rust tests have not been executed by source
preparation. The initial reproduction is retained; the final reproduction includes
the subsequently reviewed corrupt-metadata test and per-walk timing output.
Reproduction 003 additionally includes the explicit `Result<()>` closure annotation
required by the first Linux compile's type-inference error. Reproductions 001/002
and the failed compile evidence are retained; source reproduction does not claim
that a subsequent build succeeded.
