# Isolated supported Agave candidate

This source candidate ports native private payments onto Agave **4.3.2**, commit
`a203300045b405f86c9c84308b2eae76af69ac3b`. It is separate from `node/agave` and
requires Rust **1.97.1**. The patch includes the isolated native adapter, protocol,
wallet crypto/history, bounded native ingress, slot-sealed payment anchors,
original-ledger recovery, full-snapshot tests, and Linux acceptance drivers.
The existing Agave 3.x runtime, wallets and ledgers are not changed.

## Reconstruct the current source candidate

Run the following from the repository root with Python 3.11 or newer and Git.
The declarative [reconstruction plan](reconstruction-plan.json) pins the complete
source chain through LOCAL-098-r3 using repository-relative manifests and patches.
Its SHA-256 is
`f7e49b5c08901b0c868b826f8f828215f025cf4b42499a7707b1d3763b8075b0`.

First verify the plan and all of its retained source inputs.

```sh
python3 -B tools/reconstruct_native_candidate.py verify-plan \
  --plan-sha256 f7e49b5c08901b0c868b826f8f828215f025cf4b42499a7707b1d3763b8075b0
```

Then supply an already local copy of the exact upstream archive and a fresh
output path whose parent directory already exists.

```sh
python3 -B tools/reconstruct_native_candidate.py prepare \
  --plan-sha256 f7e49b5c08901b0c868b826f8f828215f025cf4b42499a7707b1d3763b8075b0 \
  --archive /absolute/path/agave-a203300.tar.gz \
  --output /absolute/path/new-current-candidate
```

The chain applies the base patch, then LOCAL-057, 058, 059, 072, 085, 092, 093,
094, 095 and the cumulative LOCAL-098-r3 patch. That final patch includes the
096/097 changes. The plan validates each transition's before and after file
identities and records the completed source hashes in
`new-current-candidate/zolana-reconstruction.json`. A failure retains any newly
created partial output for inspection. Choose a new output path for another
attempt.

The source-only regression suite uses disposable archives and Git patch
application and also verifies the retained plan's artifact hashes.

```sh
python3 -B -m unittest discover -s tools -p 'reconstruct_native_candidate_test.py' -v
```

Source preparation is offline. Compiling the resulting candidate requires its
pinned Rust 1.97.1 toolchain, dependencies and applicable Linux build environment.
Build, runtime acceptance and installation are separate steps.

## Reconstruct the original base candidate

The earlier entrypoint prepares the base patch from an already local copy of the
exact upstream source archive.

```sh
python3 tools/prepare_native_candidate.py \
  --archive /absolute/path/agave-a203300.tar.gz \
  --output /absolute/path/new-candidate-directory \
  --manifest
```

The output must not exist. Its parent must already exist. The script verifies
archive SHA-256
`917912ac67fc0b6ffec94e33e1ce113db581e1f1706aa1ecbe4224b967b15f30`
and the archive's full-commit root before extracting and applying
`agave-4.3.2.patch`. It never downloads dependencies, builds, starts validators,
changes an existing output, or opens wallet keys. On failure, a newly created
partial output is retained for inspection.

The upstream archive is available at
<https://github.com/anza-xyz/agave/archive/a203300045b405f86c9c84308b2eae76af69ac3b.tar.gz>.
Download is a separate explicit step. A matching checksum pins source bytes; it
is not a signature or security audit.

The patch contains 78 changed or added files. Its SHA-256 is
`d582e38f06cd6a1bed8686aa927141d8bb496d078674a4b0dd995177850d0e32`.
The included 337,261-byte `Cargo.lock` was resolved on Linux with the pinned
Rust toolchain; its SHA-256 is
`7500a89c82223a9efa597d0cbe396bbe782db01d2838f6adea6fa6c7caa97b38`.
This locks the candidate's added dependencies as well as the upstream graph.

The vendored `agave-transaction-view` 6.0.0 source records its published registry
checksum, upstream Git revision, original file hashes and two local modifications
in `zolana-native/vendor/agave-transaction-view/ZOLANA-PROVENANCE.json`.
Run `python3 zolana-native/vendor/verify_transaction_view.py` in the prepared
source to verify those bytes. The explicit bounded Legacy parser supports the
native ingress; the default parser retains its published transaction size limits.

Completed Linux acceptance evidence at this source freeze:

- `private-v4-004`: three co-located validators finalized and recorded all three
  full-proof private transfers; every peer agreed on the pool and eight permanent
  nullifier accounts. An original-ledger node restart preserved those payments.
- The same run stopped two of the three equal-stake validators. For eight seconds
  the survivor neither advanced its finalized root nor finalized a fresh public
  transfer. Restoring the original ledgers and signed voting histories recovered
  finality and preserved the private state, without consensus threshold overrides.
- Full-snapshot recovery restored real AccountsDb state twice, checked exact pool,
  checkpoints and nullifiers, rejected duplicate spends and allowed recipient and
  change notes to be spent after recovery.
- `smoke2`: a fresh process resumed the original ledgers, genesis, identity and
  voting keys, signed voting histories and root ancestry after an orderly stop.

Subsequent acceptance recovered the
same ledgers and original payment after actual whole-process SIGKILL. The first
restart refused a still-held lock; wait for process/lock release before resuming,
without deleting the lock or any ledger. A manually continued scenario verified
matching state; its earlier orchestration failures are retained.

The final unattended Mac client run measured three warm durable-payment hops at
2.66–2.77 seconds with four proving threads, and passed ACK-loss, client-SIGKILL
and backup replay. This separate client/runtime fixture does not change the
source patch hash or upgrade any installed runtime.
Co-located validators do not demonstrate independent production operators or WAN
consensus performance. The private driver measures RPC-observed finality and
in-memory recipient readiness, not a light-client certificate or durable wallet
commit. Admission acknowledgements are not finality. Source preparation alone
establishes reproducible source, not a build, cryptographic audit or deployment.
No production wallet or old-ledger migration is performed by this candidate.

The additive [LOCAL-094 native exporter candidate](LOCAL-094-README.md) follows
the exact LOCAL-093 after-state and preserves its four-file patch and source
manifest in this directory. Its isolated offline/locked Linux build passed all
71 native tests. It adds a bounded, fixed read-only stdin/stdout source for
canonical archive capture; it does not establish actual pilot capture completion,
activate the installed runtime or authorize existing-pilot pruning.

The additive [LOCAL-095 indexed ancestry candidate](LOCAL-095-README.md) follows
the exact LOCAL-094 compiled after-state. It adds bounded streaming publication
and indexed full-metadata recovery, using the existing locked zstd dependency.
Its seven-file delta preserves the original-root/snapshot/policy gates and the
small v1 format. Its Linux source/runtime build is accepted with all 79 native tests,
including a 1,000,003-record full-metadata fixture. The separate fresh Linux fixture passes two validator crashes, normal snapshot
resumes and accepted/expired-absent original-pending recovery; closure preserves
the original pilot. Large-pilot metadata/export and copy-based
retention acceptance remain separate; existing-pilot pruning and activation are
not authorized by the candidate.

The additive [LOCAL-096 original-pilot metadata candidate](LOCAL-096-README.md)
follows the exact LOCAL-095 compiled after-state with only a fixed keyless
read-only export module and early dispatch. Its Linux build passes 87 tests.
Actual original-pilot export publishes and reloads 520,151 FULL native metadata
records per peer with real older-snapshot bounds and immutable O44; a separate
seven-file 237,966,471-byte SSD publication passes independent byte/hash/fsync
checks. Final preservation checks also pass. Fresh native SSD reload, host reboot
and copy-based retention/restart remain separate gates. It creates no retention policy
and authorizes no original-pilot pruning or installed-runtime/gateway activation.
