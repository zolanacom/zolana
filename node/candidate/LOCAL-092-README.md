# LOCAL-092 native ancestry seam — staged only

This three-file delta preserves the reviewed LOCAL-092 R2 implementation.
It applies to the **exact observed inherited source**
identified by the 18 original-file pins in `LOCAL-092-source.json`. This is not a
complete reproduction of the d805 runtime source graph or a retroactive
source-to-binary attestation. The existing `prepare_native_candidate.py` has no
LOCAL-092 revision support and has not been changed.

The patch changes `zolana-fast-check/src/ancestry.rs` and adds
`ancestry_prefix.rs` and `ancestry_prefix_tests.rs`. It does not change main,
service, resume, Cargo manifests, the lockfile, cleanup configuration or the
accepted runner. The original live ancestry tests and parallel tests are
unchanged. The actual `solana-ledger::blockstore_meta::SlotMeta` is used, including
all non-parent fields; no transplanted metadata stub or new dependency is used.

The existing full-metadata ancestry predicate is extracted into a fallible read
callback. Its live entry point, strict parent rules, target-metadata requirement,
deadline/cancellation checks and complete parallel coordinator remain unchanged.
The new private in-memory prefix validates complete native metadata and permits
fallback only when a live record is missing within its approved prefix. Live
read errors and any full-record overlap disagreement fail. Missing live tail
metadata above the cutoff cannot be supplied from the prefix.

This first slice is bounded to 4,096 records, 64 KiB per canonical record and
32 MiB of canonical record bytes. Native wincode decoding has a 64 KiB sequence
preallocation limit and rejects trailing or noncanonical bytes. These are small
prototype bounds, not production-scale archive sizing or a retention policy.
No root/certificate evidence, domain or generation authority, durable export,
snapshot validation, canonical transaction archive or resume integration is
implemented. A validated metadata path does not independently prove finality.

## Source-only application

Use an independently prepared, disposable copy of the exact inherited source
graph. Do not apply this to an accepted checkout or infer that pristine Agave
4.3.2 or an arbitrary prior candidate satisfies the before-state. From this
repository root, the following verifies all 18 original pins, both new paths
being absent, and the patch checksum before applying the delta. It then checks
every result against the frozen R2 bytes. It uses only the existing patch helper,
not a supported preparer revision or a dependency/build operation.

```sh
python3 -B - /absolute/path/disposable-exact-inherited-source <<'PY'
from pathlib import Path
import hashlib, json, sys
sys.path.insert(0, str(Path('tools').resolve()))
from prepare_native_candidate import apply_patch
root = Path(sys.argv[1]).resolve(strict=True)
manifest = Path('node/candidate/LOCAL-092-source.json').resolve(strict=True)
spec = json.loads(manifest.read_text())
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
for name, expected in spec['baseline']['required_original_file_sha256'].items():
    assert digest(root / name) == expected, name
for name, transition in spec['files'].items():
    path = root / name
    before = transition['before']
    if before is None:
        assert not path.exists() and not path.is_symlink(), name
    else:
        assert len(path.read_bytes()) == before['bytes'], name
        assert digest(path) == before['sha256'], name
patch = manifest.parent / spec['application']['delta_patch']
assert digest(patch) == spec['application']['delta_patch_sha256']
apply_patch(root, patch)
for name, transition in spec['files'].items():
    path, expected = root / name, transition['after']
    assert len(path.read_bytes()) == expected['bytes'], name
    assert digest(path) == expected['sha256'], name
print('LOCAL-092 three-file source delta verified; no build or activation')
PY
```

The repository packaging check actually applied this patch to a disposable local
source subset with Git discovery disabled at its parent boundary. All three
after-hashes matched staged R2, and both test-support files stayed byte-exact.
This local check did not reconstruct the full 18-file baseline or compile Rust.

## Native evidence and limits

R1 compiled on isolated Linux RAM storage using the real runner graph, unchanged
lockfile and Rust/Cargo 1.97.1. All **33 ancestry tests passed**: 12 new prefix
tests and 21 existing live/parallel tests. Result receipt:
`a69140c7e4bf0e7add056e6cabad392427ae30146262504de8d12d822e21e18e`.
The accepted source was preserved, and no accepted runtime, financial operation
or real-ledger purge was performed.

R2 adds one test only. It calls the actual upstream
`Blockstore::purge_slots(0, 7, PurgeType::Exact)` on a disposable database,
closes/reopens that database, and checks removed old metadata/root/optimistic/
bank-hash rows, unchanged protected head/tail rows, live-only ancestry failure,
and identical merged ancestry using the **same process-local in-memory prefix**.
Its fixture has no shred or transaction-special-column data. It does not test
disk reclamation, durable prefix reload, snapshot restoration, consensus-created
certificates or validator restart.

R2 then compiled with the same offline, locked real runner feature graph and
**all 34 ancestry tests passed**, including that exact purge/reopen test. The
incremental compile command took 3.001 seconds; the native test harness reported
1.44 seconds (the bounded controller measured 2.000 seconds for its test command).
R2 result receipt:
`3c35575a1ec327c560364a2da0526461b912abdedbbc0ab2ebed8230bb128d3e`.
Collection receipt:
`55f48948e69af76b59a580b5c0d339e4cf67c3766ae40efc49c91114c4fd86ae`.
Original source was preserved, the active marker was absent, and all collected
actors remained off before and after testing. The R2 result proves the stated
process-local metadata/DB-reopen test; it does not close the durable archive,
snapshot, validator-restart or real retention gates.

This package grants no permission to deploy, start a service, prune or delete
data, change a cleanup threshold or access wallet keys. Durable
original-root evidence, canonical full-transaction recovery, protected snapshot/
tail cutoffs, crash-safe publication and actual copy-restart acceptance remain
separate prerequisites before any real retention operation.
