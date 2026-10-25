# LOCAL-096: fixed read-only original-pilot metadata export

This additive two-file candidate follows the exact **LOCAL-095 compiled after-state**.
The inherited main file remains the LOCAL-094 version, SHA256
`6516a7881f86fb9b11cb91ec3b9c5ba02570941b040f054c111b3f606b82b81e`.
The new `offline_metadata.rs` must be absent before applying this delta.
[LOCAL-096-source.json](LOCAL-096-source.json) records both before/after pins,
preparation, current census, inherited native build and disposable reconstruction.
The patch is `agave-4.3.2-LOCAL-096.patch`, SHA256
`b5cbee75f001907eeae9ada8a0c6bf433b42ccae5c61dfee08f61e254dd522ad`.
Every older candidate artifact is preserved. The existing preparer is unchanged
and does not apply this revision automatically.

The new fixed flag, `--offline-pilot-metadata-export`, dispatches before any live
argument parsing. It accepts no other arguments or requester-controlled paths.
It requires UID995, the exact original pilot root, public resume SHA, genesis,
three public identity/voter/ledger records and immutable certified checkpoint O44.
It opens only the already tested LOCAL-094 `AccessType::ReadOnly` Blockstore API;
it does not substitute upstream Secondary access. Existing source paths must
already exist, with a kernel read-only source namespace, original keys inaccessible
and all original actors stopped. These operator gates remain mandatory.

The utility pins both actual full-snapshot files per peer, including exact census
bytes and SHA256. It uses the **older S520508** and its actual canonical parent P
for the V2 binding, preserving the newer S521532 rollback option. Both snapshot
slots must be rooted ancestors of actual current N. The certified archive head H
must be at or below P, its proposed cutoff is H minus one and the complete accepted
canonical transaction export through E522202 must cover that cutoff. The actual
E blockhash/height and all-three certified BANK parity are checked. The separately
owned canonical SQLite file is not opened; its accepted external pins are recorded.
Snapshot filename/hash inventory is not ordinary snapshot bank/accounts validation.

One peer at a time, the unchanged LOCAL-095 publisher streams complete native
SlotMeta from H through immutable O44 into a new exclusive V2 generation. The
utility reloads it using the independently returned manifest SHA and verifies the
complete current N to O44 path, including unchanged live/archive conflict rules.
It rechecks original public resume, snapshot bytes and current root before reporting.
The whole invocation is bounded to 600 seconds; all work for each peer shares at
most 180 seconds. Existing V2 record, stored/decoded byte and index caps remain.

Output goes only to the fresh private RAM directory
`/dev/shm/zolana-pilot-metadata-096-export-r1/data`, with three fixed public-identity
peer directories and a final exclusive `export.json` after all three peers pass.
Partial output is preserved and never adopted or overwritten. **This RAM output is
volatile.** File/directory fsync here is not an SSD or reboot-durability claim.
The full H to O44 prefix and separately verified N to O44 path are reported with
actual counts; this is not a claim to export every historical block or genesis.
The keyless highest stored SlotMeta slot is reported; the signed frontier remains
unclaimed because no signed-history or key API is invoked.

Eight focused tests cover flag isolation, changed public domain/root, exact
snapshot inventory, bounded file/link refusal, incomplete/nondecreasing parent
paths, deadline/original boundary and independent manifest/binding pins. The
module passes local rustfmt parser/format checks. A disposable two-file
reconstruction passes `git apply --check`, applies the patch and matches both
expected after hashes; this verifies the delta rather than the full workspace.

The isolated offline/locked Linux build now passes all **87 tests: baseline79 plus
eight new tests, zero failed, ignored or filtered**. The anchored test summary is
11.01 seconds; the bounded controller measured the test command at 12.001 seconds,
compilation at 4.001 seconds and the separate runtime build at 5.001 seconds. These
are native build/storage-test timings, not payment or wallet performance.
Result SHA256:
`5b2d031bab8a58d3917218705b27d35799c94bc65007d683d66daeb7fa1b3112`;
collection SHA256:
`669b6d6c1234c2b58f2fdd87946163602d0546f798067df292d8b23dfe550a2d`.
The compiled source inventory SHA256 is
`dd04e1eddfcecd4af6ae678a5b07570309610e009d99ec6c5a83177f6b9691b6`.
The new separately sealed runtime SHA256 is
`a26bdc78a0050fae69ff6c62fc08d076e8cbeff898572996c24b1a4468b7d0d2`.
Its public `--build-info` probe confirms linked runner/runtime/votor recovery
features and reports no validator starts, ledger opens, key reads or financial
operations in that probe. It does not activate the installed runtime.

After the two-leaf scratch overlay, the complete prepared source was restored to
its exact LOCAL-095 manifest
`21257b7a6c32c810de01fc80314ec1f7969edc626bc56750ab86049dcd32074d`.
A separate postflight check confirms restoration without a fallback and preserves
the old sealed095 runtime
`5c99ead8b97ebcb9427b8d5874ab3f966b31786b85b15d1fbe52e17cad20ab54`.
The patch and its source bytes remain unchanged. The build receipt is distinct
from the subsequent scoped export and byte-copy evidence below.

## Actual original-pilot metadata export and SSD byte copy

The fixed keyless native utility completed against the original paused pilot,
using read-only Blockstores and inaccessible keys. Each of the three peers
published and reloaded **520,151 FULL native SlotMeta records**, H520507 through
immutable O44. Each full live and loaded merged path from current N522202 through
O44 contained 521,846 entries. The actual binding is C520506, P520507 and older
snapshot S520508; newer S521532 is also independently byte-pinned. These are
metadata counts, not payments and not a claim to export every block or genesis.

The per-peer metadata publication/load/verification observations were 9.790,
11.567 and 9.852 seconds. Payloads were 79,315,254, 79,315,253 and 79,315,251 bytes.
These are storage-path timings, not wallet, payment, validator restart or network
latency. Native execution receipt SHA256:
`20437e065bfec0d29493f18b4ffd4f1168cd2f9d017221e1f8ebcb83fa4a312d`.
The native receipt retains its original `completed-unreviewed` label; the
subsequent operator review accepts only the scoped results stated here. Its new
V2 files were loaded from RAM within that same native process. No ordinary full
snapshot bank/accounts load was performed and signed frontier remains unclaimed.

A separate exclusive SSD publication then independently rehashed and fsynced all
**seven files, 237,966,471 logical bytes**, to
`/var/lib/zolana-metadata-096-r1/data`. Byte-copy receipt SHA256:
`a7e53cc44fcf409cf90e591e928664a5d96995cdaccf26dbd9eaf0334e320cfd`.
The source remained unchanged, including exact `export.json` SHA256
`40fe0ec0acb088390f6c2580f0f2b6ad7936aae7cd878a32e79a39893e64cd68`.
That original receipt still truthfully describes volatile RAM preparation; the
separate copy receipt records the SSD file/directory/parent fsync and byte checks.
It establishes neither a **fresh native SSD reload** nor host reboot/power-loss
recovery. The small metadata archive does not replace the original complete
Blockstore data: full snapshots and complete replay tail remain separate inputs.
Final preservation checks pass: the original 5321 metadata entries, nine small
file hashes and all six old protected artifacts remain exact. All actors are
off. The final preservation review receipt is
`f10857db9ee2e50b9ed3f722b13896fdb00a533b535a53abe656e15fb381c806`.
Copy-based retention/restart remains a separate gate; this metadata export
creates no policy or pruning permission.

No Cargo, lockfile, ledger API, indexed format, resume fence or installed service
configuration changes. No keys, wallet, signed vote history, retention policy,
pruning, snapshot replay or validators are touched by this utility. Compact-copy
retention/restart, original-pilot pruning, fresh native SSD loading and live
activation remain separately reviewed gates. This candidate adds no payment-speed,
public-testnet launch or competitor-superiority claim.
