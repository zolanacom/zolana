# LOCAL-095: bounded indexed native ancestry

This additive source candidate follows the **exact LOCAL-094 compiled after-state**.
It changes seven files and preserves every earlier candidate patch. The patch is
`agave-4.3.2-LOCAL-095.patch`, SHA-256
`81d79b5c320204f55cbd8a9f25a22c260085e37785d06c7a36050013e3a8b699`.
[LOCAL-095-source.json](LOCAL-095-source.json) records every existing before pin,
new-file absence, after pin and the observed LOCAL-094 compiled inventory.
These pins do not establish a complete reproduction or retroactive attestation
of the installed `d805` runtime.

The existing preparer is unchanged and does not apply this additive revision.
Apply the delta only to a separate, independently verified exact LOCAL-094
after-state. A disposable seven-file reconstruction passed `git apply --check`,
applied the patch and matched every after hash. This checks the bounded delta;
it does not replace a full native build.

## What changes

LOCAL-093's durable metadata archive materializes a complete prefix and retains
its deliberately small 4,096-record/32MiB limits. LOCAL-095 adds a separate
streaming indexed format while retaining the old format, loader and tests.
`publish_indexed(..., &Blockstore, ...)` reads one complete native `SlotMeta` at
a time from the certified head down through the original checkpoint. It retains
all fields, including the fixed 4KiB completed-shred bitmap, parent block ID,
replay index and fields unrelated to the parent link.

Each new-format record contains encoded and decoded lengths, one zstd frame and
the SHA-256 of the exact decoded canonical full metadata. Publication keeps a
bounded buffer, hashes the complete encoded payload, fsyncs the files and pending
directory, publishes with exclusive rename and fsyncs the parent. Failed pending
generations are preserved and never adopted. Readers verify the independently
pinned manifest, complete payload hash and entire decreasing head-to-original
chain before returning a loaded archive.

The loaded representation keeps the file descriptor and a 48-byte index entry
per record: slot, file offset and the independently verified decoded-record
digest. Lookups read only the bounded requested frame. A mutable frame's own
replacement digest cannot authorize new metadata. File identity, size,
timestamps, ownership, permissions and link count are checked around reads, and
the decoded body must match the digest retained in memory. Full live/archive
metadata conflicts and live read/decode errors remain fatal. Archived records
can fill only missing records at or below the pinned cutoff; a missing live tail
is never filled by widening the cutoff.

The format and magic explicitly identify zstd compression. The decoder requires
exactly one frame with no concatenated or trailing bytes, bounded decompression,
the declared exact output size and the existing full native canonical decoder.
This preserves full metadata; it does not substitute a parent-only projection.

## Explicit budgets

- At most 1,048,576 records and a 48MiB index per peer.
- At most 512MiB of stored compressed record bodies, plus bounded framing.
- At most 8GiB of cumulative decoded metadata work, streamed rather than retained.
- At most 64KiB decoded and 65KiB encoded per record.
- The shared load, preparation and purge budgets are 180 seconds each.

The old private `full_prefix` helper still exists with its original 4,096-record
limit, but the selected new durable preparation path no longer calls it or
collects its complete `Vec`. The old v1 reader keeps its original small limits.
The core fallible ancestry predicate is unchanged; its visibility is widened
only so the indexed reader can call that same predicate. The head search keeps
the deadline and decreasing-parent checks without its former count cutoff.

The only dependency change adds `zstd = { workspace = true }` and the existing
`zstd` dependency edge for `zolana-fast-check`. The workspace already specifies
zstd 0.13.3. Removing that one edge from the parsed new lockfile yields the exact
parsed previous lockfile: no package, version, source, checksum or other resolved
dependency changes. The actual locked zstd-safe 7.2.1 exposes
`find_frame_compressed_size`, used to reject extra frame bytes.

## Recovery boundaries remain

Durable recovery still requires the explicit independently pinned policy and its
fresh disposable three-validator fixture fence. Immutable resume/genesis,
identity/voter, original certified BANK root, current live certification,
protected actual full snapshots and normal snapshot verification remain
mandatory. There is no reset or genesis fallback and no automatic generation
selection. This candidate does not authorize pruning the existing pilot.

The metadata archive is distinct from LOCAL-094's full canonical transaction
archive. Old pending-payment acceptance/absence still requires complete canonical
transaction coverage and the existing exact target/anchor checks. Metadata,
retained ciphertext or a file checksum alone is not an independent finality
proof. No gateway, public listener or installed runtime is activated by this
patch.

## Accepted native build and scoped Linux recovery

The first Linux source compiled, then its million-record test correctly refused
the 512MiB uncompressed-body cap: the full metadata codec always includes the
4KiB bitmap. The candidate therefore uses the existing zstd implementation;
the fixture was not shortened to conceal its actual decoded work.

The compressed revision's Linux test process subsequently completed all
**79 tests with zero failed, ignored or filtered tests** in 11.11 seconds. Its
controller then refused an invalid assumption that each test name and `ok`
would remain contiguous under `--nocapture`; emitted JSON can intervene.
That failed instrumentation receipt and its exact streams are preserved. A
separate validation-only continuation checks those independently pinned outputs,
the exact unfiltered invocation, all 71 previous plus eight new test names, the
anchored pass summary and measured scale accounting. It changes no native source
and reruns no tests before building the runtime and checking public linkage.
That continuation passed. Its result SHA-256 is
`ea859b83f444cb800db20076b7e4b5fd4a40286b8ef688225264870268ada071`;
the compiled source manifest remains
`21257b7a6c32c810de01fc80314ec1f7969edc626bc56750ab86049dcd32074d`.
The separately built runtime SHA-256 is
`5c99ead8b97ebcb9427b8d5874ab3f966b31786b85b15d1fbe52e17cad20ab54`.
Its `--build-info` probe confirms the linked runtime/votor recovery features and
reports no validator starts, ledger opens, key reads or financial operations.

The million-record fixture measured **4,205,012,615 decoded bytes**, **59,956,367
compressed record bytes**, **107,956,519 total payload bytes** and a **48,000,144-byte
index**. Streaming publication took 3.008 seconds; publication plus complete load
validation took 5.727 seconds; adding a full merged ancestry verification took
9.502 seconds. These are synthetic metadata/storage timings on the Linux test
host, not private-payment latency, live-pilot capture or validator restart times.

The eight new tests cover 1,000,003 complete records with measured raw, stored,
payload and index sizes; v1/v2 dispatch and actual Blockstore publication; full
overlap conflicts and missing-tail refusal; external pins and hostile bounds;
malformed/truncated/bomb/trailing/concatenated compressed frames and wrong output
lengths; post-load body-plus-digest replacement; failed publication preservation;
and actual child-process SIGKILL before and after the publication commit.
Those process tests concern disposable archive publication, not a claim that
scaled pilot-validator crash recovery has completed.

The separate actual R7 Linux fixture also passes: two validator-process
SIGKILLs, two ordinary protected full-snapshot resumes and complete old-pending
recovery after ordinary pruning through 1039. Alice's original expired-absent
packet restores 21M test units; Bob's exact original accepted at 306 restores 16M.
R7 constructs no proof and submits no payment. Its first native browser-core
replay is followed by an exact cached settlement reload after the second crash,
not a second canonical client replay. Both audits preserve 14 notes/markers,
37,000,994 backing units and all earlier funded markers. The full canonical
export covers 2,049 produced blocks through 2066. This is the same preserved
fresh 095 fixture, distinct from the million-record synthetic metadata test and
the original 521,886-block pilot. Result SHA256:
`09cf5731725b4aed436525c161feac43dc3543f743850cf95c816dbc902f5f92`.

Final closure and preservation checks pass. The grown 3GiB fixture is
unmounted with its loop detached and both filesystem images preserved. Original
pilot metadata/keys/resume, installed d805, the closed 093 fixture and the 094
canonical archive remain exact. All original and 095 actors are off.

These finite bounds address the next scale gate; they are not unbounded
multi-year retention. Actual original-pilot metadata export, large-copy
prune/restart acceptance, live gateway/runtime activation and sustainable public
operation remain separate gates. This result provides no new Chrome/WASM or
Mac-to-Linux speed, public-testnet launch or competitor-superiority claim.
