# LOCAL-094 fixed read-only canonical exporter candidate

This four-file delta preserves the native exporter source.
Apply it **after the exact LOCAL-093 candidate**. Its before
and after states are pinned in [LOCAL-094-source.json](LOCAL-094-source.json).
It does not apply directly to pristine Agave or an arbitrary earlier candidate.
The existing source preparer has no LOCAL-094 revision option and is unchanged.

The isolated Linux build passed all **71 discovered native tests**, including
the four exporter tests. This package does not claim a completed actual pilot
capture, production service activation or a retroactive source attestation for
the installed d805 runtime. The inherited source graph has its own observed
compiled-source manifest; the installed source, runtime and pilot data were
unchanged by the build.

## What changes

The patch adds `offline_canonical.rs`, adds its early dispatch to `main.rs`, and
adds the existing `solana-transaction-status` dependency to the runner manifest
and lockfile. Only that dependency edge changes: no package version, source,
checksum or resolution changes. The accepted lock remains
`26789f9b60030e7075788df1b3150e0172f4c630fc2ccd1177bf56c4dd3859b7`.
The separate compiled candidate lock is
`8989b37ae537c1d28f0c45d7b385da135381a562bb6160467153b2edb39e8f21`.

The single exact `--offline-canonical-export` flag selects a pilot-specific
stdin/stdout exporter. Combining it with other runtime or path flags refuses.
Its fixed UID, three ledger paths, network/genesis, original resume bytes and
original certified root cannot be supplied by a requester. It opens the three
paused pilot Blockstores with upstream `AccessType::ReadOnly`. It does not
start validators, replay ledgers, load wallet/identity keys, generate snapshots
or invoke pruning.

The exporter selects the minimum static root across all three sources, requires
matching certified BANK evidence there, and checks the original root and resume
identity. Full blocks use the actual upstream `get_complete_block` conversion
and `ConfirmedBlock::encode_with_options`. Base64 transaction bodies and
execution metadata are retained; headers, full bodies and rooted ranges must
agree across all three sources. Requested transaction rewards are omitted in
the same way as the fixed existing RPC contract. This is trusted operator data,
not an independent consensus proof or a new light-client trust root.

There is no HTTP listener or new authentication route. Only the four existing
finalized read shapes are allowed. Bounds are 16 produced slots per range,
4 KiB request lines, 8 MiB full block JSON, 16 MiB response lines, one million
requests and a 600-second lifetime. The operator still must enforce stopped
actors and a read-only kernel namespace, collect before/after evidence, and
validate complete canonical capture separately. A partial capture grants no
absence, pruning or cleanup authority.

## Source-only application

Prepare an independent disposable copy of the exact LOCAL-093 after-state and
verify its prerequisites first. From this repository root:

```sh
python3 -B - /absolute/path/disposable-exact-LOCAL-093-source <<'PYAPPLY'
from pathlib import Path
import hashlib, json, sys
sys.path.insert(0, str(Path('tools').resolve()))
from prepare_native_candidate import apply_patch
root = Path(sys.argv[1]).resolve(strict=True)
manifest = Path('node/candidate/LOCAL-094-source.json').resolve(strict=True)
spec = json.loads(manifest.read_bytes())
def digest(path):
    assert path.is_file() and not path.is_symlink(), path
    return hashlib.sha256(path.read_bytes()).hexdigest()
for key in ('predecessor_source', 'predecessor_patch'):
    expected = spec['application'][key]
    path = Path(expected['path'])
    assert path.stat().st_size == expected['bytes'], path
    assert digest(path) == expected['sha256'], path
for name, expected in spec['baseline']['required_file_sha256'].items():
    assert digest(root / name) == expected, name
for name, transition in spec['files'].items():
    path, expected = root / name, transition['before']
    if expected is None:
        assert not path.exists() and not path.is_symlink(), name
    else:
        assert path.stat().st_size == expected['bytes'], name
        assert digest(path) == expected['sha256'], name
patch = manifest.parent / spec['application']['delta_patch']
assert digest(patch) == spec['application']['delta_patch_sha256']
apply_patch(root, patch)
for name, transition in spec['files'].items():
    path, expected = root / name, transition['after']
    assert path.stat().st_size == expected['bytes'], name
    assert digest(path) == expected['sha256'], name
print('LOCAL-094 four-file source delta verified; no build or activation')
PYAPPLY
```

Packaging applied the actual patch to a fresh disposable local subset with
enclosing Git discovery disabled. All four outputs matched the Linux compiled
source manifest. The lockfiles were independently parsed and compared: adding
the one existing dependency edge produced the complete new graph exactly.
That packaging check neither reconstructs the entire inherited source nor runs
a Mac Rust build.

## Exact Linux build evidence

The existing Rust/Cargo 1.97.1 toolchain built this candidate offline and locked
on isolated Linux RAM storage with `zolana-pilot-202-recovery`. All 71 native
tests passed. The non-test runner was then built, and only its `--build-info`
path was executed during this build step. No accepted runtime was started.

- Preparation: `657133e3e802151b442551301e96e9a051ddc24cfdc311d51c2e03e3cf8710f0`
- Build result: `7c1e18c46c09be83994e3b3b431dd55cfa3170da64abb0348a8961697723ceed`
- Compiled source manifest: `87fdca263765f3e04ca32763c938c40ae118b771c3fa142be5b02340404e10d4`
- Non-test runner: `12763a765304f423ba583f6a80ffe0247ca386ef2ada18786f188a8e64d8a1d0`
- Test binary: `78c0a1e62ceac10a4dbe8645aed566723638d6f6c784af216c7b5e26a33c42ce`
- Read-only collection: `621b94578057e1c386c3a1ecfbad688fcda48d06465a365a85d953af7aebfabe`

Local evidence paths and file-level pins are recorded in the JSON manifest.
The preparation document's earlier `source-only-uncompiled` status is preserved;
the later build result above records the successful compilation and tests.
The collection records the existing actors inactive before and after the build.
It is not evidence that the exporter has completed an actual pilot capture.

Actual read-only pilot export/capture, full coverage validation, rolling service
activation and production retention remain separate gates. This source package
does not authorize host changes, key access, wallet changes, transfers,
pruning/deletion or cleanup changes.
