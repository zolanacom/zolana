# LOCAL-085 cumulative recovery candidate — unaccepted

This export preserves the reviewed LOCAL-085 source.
It is a delta from the **exact LOCAL-072 Agave 4.3.2 overlay**, upstream
commit `a203300045b405f86c9c84308b2eae76af69ac3b`. It does not modify `node/agave`,
the frozen LOCAL-072 patch, any installed service, wallet, key or ledger.

The 27-file delta includes the prior parallel original-checkpoint ancestry walk
and quorum-runner selection changes, followed by the frozen epoch-202 runtime,
Votor egress and runner changes. It also includes the exact root lockfile delta.
Five standalone public diagnostic bin sources are also retained to match the
observed build tree. The selected `--bin zolana-fast-check` runner does not
compile or import those unselected Cargo targets. The lock adds only three already-resolved direct dependencies to the
`zolana-fast-check` package entry; registry/git package versions and checksums
are unchanged. The separate `dev-bins/Cargo.lock` remains LOCAL-072's pinned lock.

`zolana-pilot-202-recovery` is **OFF by default**. It is mutually exclusive with
the old `zolana-pilot-vat-recovery` retry. The new path keeps historical epoch-201
Bank state unchanged; its future-only view is pinned to certified slot 413694 and
signed parent 413695. Only a new mutable epoch-202 child of that exact parent may
materialize the real membership and pay deferred epoch-202 admission. Ordinary
epoch-203 processing remains separate. Raw/current VM stake APIs, frozen parent
accounts, Bank serialization and consensus thresholds are not substituted.

## Reproduce source only

First use the existing preparer and an **already local**, exact upstream archive.
The output must be fresh; its parent must already exist. This step verifies and
applies the unchanged 056→057→058→059→072 source chain.

```sh
python3 tools/prepare_native_candidate.py \
  --archive /absolute/path/agave-a203300.tar.gz \
  --output /absolute/path/fresh-LOCAL-085-source \
  --native-restart-snapshot-072 --manifest
```

Then run this from the repository root, replacing the output path. It verifies
all LOCAL-072 inventory entries and every additional before-state, checks the
export checksum, applies the delta without discovering an enclosing worktree,
and verifies the complete 109-file cumulative changed-file inventory. It uses
the existing preparation helpers and does not resolve dependencies or build.

```sh
python3 - /absolute/path/fresh-LOCAL-085-source <<'PY'
from pathlib import Path
import hashlib, json, os, sys
sys.path.insert(0, str(Path('tools').resolve()))
from prepare_native_candidate import apply_patch, verify_final_files, verify_transition
root = Path(sys.argv[1]).resolve(strict=True)
manifest_path = Path('node/candidate/LOCAL-085-source.json').resolve(strict=True)
spec = json.loads(manifest_path.read_text())
base_path = manifest_path.parent / spec['baseline_delta_manifest']
assert hashlib.sha256(base_path.read_bytes()).hexdigest() == spec['baseline_delta_manifest_sha256']
base = json.loads(base_path.read_text())
verify_final_files(root, base['final_files'])
verify_transition(root, spec['files'], 'before')
patch = manifest_path.parent / spec['delta_patch']
assert hashlib.sha256(patch.read_bytes()).hexdigest() == spec['delta_patch_sha256']
apply_patch(root, patch)
verify_final_files(root, spec['final_files'])
actual_ref = spec['source_reproduction']['actual_source_inventory']
actual_path = manifest_path.parent / actual_ref['path']
assert hashlib.sha256(actual_path.read_bytes()).hexdigest() == actual_ref['sha256']
actual = json.loads(actual_path.read_text())
for name, meta in actual['files'].items():
    data = (root / name).read_bytes()
    assert len(data) == meta['bytes'] and hashlib.sha256(data).hexdigest() == meta['sha256'], name
for name, target in actual['symlinks'].items():
    assert (root / name).is_symlink() and os.readlink(root / name) == target, name
record = {
    'format': 'zolana085-source-reproduction-v1',
    'revision': 'LOCAL-085',
    'candidate_status': spec['candidate_status'],
    'source_manifest_sha256': hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
    'delta_patch_sha256': spec['delta_patch_sha256'],
    'cargo_lock_sha256': spec['lock']['after_sha256'],
    'final_inventory_count': len(spec['final_files']),
    'source_only': True,
    'actual_build_workspace_equivalence': spec['source_reproduction']['full_actual_build_source_chain_inventory_verified'],
    'validators_started': False,
}
with (root / 'zolana-candidate-LOCAL085.json').open('x') as output:
    json.dump(record, output, sort_keys=True, indent=2)
    output.write('\n')
print(json.dumps(record, sort_keys=True, indent=2))
PY
```

The first local patch rehearsal was correctly rejected by its after-hash check:
Git found the enclosing repository and silently skipped the patch. The retained
second rehearsal used the existing preparer's ceiling/no-index/skipped-patch
guards and verified all 22 resulting changed files. The final rehearsal added the five
exact standalone diagnostic sources and verified all 27 resulting changed files.
The complete reconstructed source inventory matches 1,916 regular files
(29,739,768 bytes) and four symlinks in the actual Linux source tree. The generated
`zolana-candidate.json` preparer receipt is separately identified metadata, absent
from that build tree and not a Rust/Cargo source input. This is source reproduction,
not evidence that a rebuilt executable is bit-for-bit identical.

## Separate build step

After source-chain review, the recorded Linux build used Rust/Cargo **1.97.1**
and the exact lockfile with this bounded target:

```sh
cargo build --offline --locked -j2 -p zolana-fast-check \
  --bin zolana-fast-check --features zolana-pilot-202-recovery \
  --message-format=json-render-diagnostics
```

`--offline` requires a previously populated dependency cache; preparation does
not populate one. Capture actual Cargo artifact features and the produced
executable's `--build-info`. The latter is a public linkage check before
configuration, keys or ledgers are opened. A manifest flag alone is insufficient.
No service-start command is part of this source export.

## Evidence and acceptance boundaries

The frozen incremental build input is SHA-256
`99c936bd90dab96b9788e7d573834f7801d99c2dfad527fd0cdd81a875a6b69f`.
It covers 15 newly overlaid files, **not the entire build workspace**. This export
adds the cumulative prior changes and all five extra public diagnostic sources.
A separate complete source-inventory comparison found **zero mutated source
files, zero unexplained extras and four matching symlinks**. It does not infer
workspace equivalence from those 15 hashes. The exact observed inventory is
`LOCAL-085-linux-source-inventory.json`, SHA-256
`e78fff0241f87b9c85c6f8d07c3b4a227580e99ee97513fa36ee2b2e2bf11e75`.
The comparison receipt is `LOCAL-085-reproduction.json`, SHA-256
`7a5d4e6d5d3b7284b4fef2be9f24cb91fa1e9c25bce675819e3020fc3b7a6a76`.
This establishes source-inventory equivalence; it does **not** claim a
bit-identical executable rebuild.

The actual Linux candidate executable was SHA-256
`939ccf20bd67fd3d1276431e27a86ad4e1171cc290598af45e657fc865eda492`.
Its actual `--build-info` reported the new runtime and Votor feature enabled and
the old retry disabled. Thirty-two focused runtime/Votor tests and three runner
tests passed. Read-only copied-ledger probes of all three peers were accepted separately;
those results do not authorize live activation. Exact local build/evidence paths
and hashes are recorded in `LOCAL-085-source.json`.

The existing quorum helper's “equal stake” and “one third” wording is an inaccurate
diagnostic label for this pilot's unequal real stake weights. Its behavior must
be assessed using the explicit membership totals and actual 60%/80% threshold
acceptance evidence. This export makes no equal-weight or quorum-success claim
from that wording. No executable was changed merely to relabel the messages.

**Candidate acceptance remains separate.** Verified source-tree equivalence and
the separately accepted offline old-history/accounting probes do not substitute
for actual weighted quorum, live recovery and restart acceptance against exact
source/binary hashes. This export is not
production readiness, a cryptographic audit, permission to start a service, or a
promise about independently operated validators.
