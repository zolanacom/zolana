# LOCAL-093 durable ancestry candidate — disposable recovery accepted

This seven-file delta preserves the exact tested LOCAL-093 implementation.
Apply it **after the exact LOCAL-092 R2 candidate**.
The required before-state and seven after-states are pinned in
`LOCAL-093-source.json`. The LOCAL-092 `ancestry_prefix_tests.rs` remains required
and byte-exact; it is not duplicated by this patch.

The baseline is the exact observed inherited source graph with LOCAL-092 applied.
Its original 18-file inventory is not a complete d805 reproduction or a retroactive
source-to-binary attestation. The isolated LOCAL-093 build has its own full compiled
source manifest. Existing `prepare_native_candidate.py` has no LOCAL-092 or
LOCAL-093 revision support and has not been changed. This delta does not apply
directly to pristine Agave 4.3.2 or an arbitrary earlier candidate.

## What is implemented

The patch changes `ancestry.rs`, `ancestry_prefix.rs`, `main.rs`, `resume.rs` and
`restart_snapshots.rs`, and adds `ancestry_archive.rs` and its tests. Cargo,
the lockfile, service code and the original live/parallel ancestry tests are
unchanged. Complete native `solana-ledger::blockstore_meta::SlotMeta` records
and existing dependencies are used; no substituted metadata type is introduced.

The archive remains bounded to 4,096 records, 64 KiB per canonical record and
32 MiB of canonical metadata bytes. Exact native wincode decoding, trailing-byte
rejection and bounded sequence allocation are retained. The unchanged ancestry
predicate reads live metadata first. Any live error or full-field overlap conflict
is fatal; only a missing record at or below the approved cutoff may use the
validated archived record. Missing live tail metadata is never replaced.

A generation is usable only with an independently supplied manifest SHA256 and
exact domain/root binding: network, genesis, node, voter, relative ledger path,
immutable resume bytes and original O/certified BANK evidence. Archive bytes do
not independently establish a new trust root. Private owner/path/type checks
reject links, unsafe permissions and FIFOs. Publication fsyncs both files and
the pending directory, uses Linux `renameat2(RENAME_NOREPLACE)`, then fsyncs the
parent. Failed or abandoned generations are not adopted or overwritten.

Integration is opt-in for a **new disposable private three-validator fixture**.
It binds exact protected full-snapshot files and the original O in an externally
pinned `retention-policy.json`. All-peer preparation and standard upstream
`PurgeType::Exact` are explicit offline operations. The cutoff is below the
protected snapshot parent; the current restored-root certificate, signed vote
history, normal snapshot/accounts validation and canonical live tail remain
required. Ordinary resume does not silently discover or adopt an unpinned policy.

The policy also pins a separate closed full-transaction canonical SQLite export
through fixed E above every prune cutoff. Native byte/domain checks do not replace
validation of all canonical block bodies, metadata and old payments. That is a
separate controller gate. The small metadata bound does not support a claim that
existing million-slot pilot ledgers can be pruned with this prototype.

## Source-only application

First independently prepare the exact LOCAL-092 R2 source and verify its own
manifest. Then, from this repository root, use a disposable source copy only:

```sh
python3 -B - /absolute/path/disposable-exact-LOCAL-092-R2-source <<'PYAPPLY'
from pathlib import Path
import hashlib, json, sys
sys.path.insert(0, str(Path('tools').resolve()))
from prepare_native_candidate import apply_patch
root = Path(sys.argv[1]).resolve(strict=True)
manifest = Path('node/candidate/LOCAL-093-source.json').resolve(strict=True)
spec = json.loads(manifest.read_text())
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
    path, before = root / name, transition['before']
    if before is None:
        assert not path.exists() and not path.is_symlink(), name
    else:
        assert path.stat().st_size == before['bytes'], name
        assert digest(path) == before['sha256'], name
patch = manifest.parent / spec['application']['delta_patch']
assert digest(patch) == spec['application']['delta_patch_sha256']
apply_patch(root, patch)
for name, transition in spec['files'].items():
    path, expected = root / name, transition['after']
    assert path.stat().st_size == expected['bytes'], name
    assert digest(path) == expected['sha256'], name
for name, expected in spec['unchanged_test_support'].items():
    assert digest(root / name) == expected, name
print('LOCAL-093 seven-file source delta verified; no build or activation')
PYAPPLY
```

Packaging actually checked and applied the patch to a disposable local subset
with enclosing Git discovery disabled. All seven results matched the exact
integration-build source bytes and the compiled-source manifest. Three unchanged
ancestry test-support files also matched. This was not a reconstruction of the
full 20-file prerequisite set and did not run a Mac Rust build.

## Actual native build evidence

The combined real runner graph compiled offline and locked on isolated Linux
RAM storage using Rust/Cargo 1.97.1 and the existing
`zolana-pilot-202-recovery` feature. **All 67 discovered native tests passed.**
The accepted source was preserved; no accepted runtime or financial operation
was started by this build. During that build-only step the resulting runner used only `--build-info`,
which opened no ledgers or keys and started no validators. The subsequent
disposable runtime acceptance is recorded below.

The archive tests include fresh full-metadata file reload after standard purge
and DB reopen, hostile frames/domain/path/conflict checks, and two real SIGKILL
subprocess tests before publication rename and after committed publication.
Their expected manifest pins are supplied by the parent test independently.
These are archive-library crash tests, not full-validator recovery tests.

Exact build bindings:

- Result: `a79b4750176b179e0db38fc03f842644e255b2e08dd1dcbad27caf59ca8078ab`
- Compiled source manifest: `73f9b907e801fc7b28aa8d186b02fe36460898e0fba4c00a86ac14b7706306cb`
- Compiled runner: `3dcf349026e272cebc21d5818a034ec1edcfef08934da40dcfbd29af2b7e8454`
- Test binary: `9e33348f4f93a2d025017c4946dad57a3c0f2cf8e8c5046dc3296a7d7995df80`

## Remaining production gates

Production-scale retention and existing-pilot pruning remain unaccepted. The
completed disposable full-validator result below does not establish a rolling
canonical capture/serving daemon, production archive sizing, automatic cleanup,
independent-host recovery or hardware power-loss safety.

This source package grants no permission to deploy, activate a runtime, invoke
pruning/deletion, change cleanup configuration or access wallet keys.
Existing pilot data and existing wallets remain outside its scope.

## Subsequent full-validator acceptance

The SSD-backed disposable recovery sequence now passes. Both audited fresh
processes load all three exact protected full snapshots through normal bank and
accounts verification, preserve the original root/keys/signed vote history,
advance finalized roots and recover the same eight notes/994 backing/eight
permanent markers. After the first complete audit, actual SIGKILL and a second
complete restore/audit pass. All original full-proof payments below the one-time
prune cutoff are absent on the primaries and recover byte-exact through the
canonical reader. Result `0058accfef44f94f6ad6b85ee73cd675d6ee890cd779666b9a6bb0fb35e22c8b`;
collection `28e38bb33f8b4bbcc830c1682041f97513471e9f827ba1013ca0f0dca9215f66`.
The earlier fixture-permission failure and RPC-audit refusal remain preserved;
the subsequent readiness-gated audits pass. The exact refused RPC method in
the earlier run was not recorded. No native acceptance predicate
was weakened. This is not a production retention rollout, power-loss test,
independent-host proof or million-slot sizing acceptance. Existing pilot state
and the installed d805 binary remain unchanged.
