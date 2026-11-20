# LZ4 compression for the large ledger columns

Status: **running on the public devnet since 20 November 2026.** The patch was
built on Linux x86-64, passed the runner's test gate, and the three devnet
ledgers were rewritten once with the tool in this directory. It is kept under
`drafts/` because it is not yet part of `reconstruction-plan.json`; see
"What has and has not been verified".

## Why

The devnet keeps its whole ledger: nothing is pruned, so the blockstore only
grows. Every RocksDB column family except `transaction_status` is written
uncompressed, and the two shred columns hold most of the bytes. On three
ledger copies taken from the devnet validators, the shred columns were 87 % of
the directory and `index` plus `meta` another 5 %.

## What is here

| Path | What it is |
| --- | --- |
| `agave-4.3.2-LOCAL-100-lz4.patch` | Validator change, two files |
| `ledger-shrink-tool/` | Offline tool that rewrites an existing, stopped blockstore with LZ4 and proves the contents are unchanged |

### The patch

- `ledger/src/blockstore_db.rs`: `should_enable_compression` delegates to a new
  `should_enable_cf_compression(name)`. It is true for `transaction_status`
  (as upstream) and now also for `data_shred`, `code_shred`, `index`, `meta`
  and their alternate-block twins. None of the added columns has a compaction
  filter. One new unit test.
- `zolana-fast-check/src/main.rs`: the runner's validator config sets the
  existing `column_options.compression_type` to `Lz4`. One new unit test, which
  also asserts that the cleanup strategy is still `None` (nothing is pruned).

No new option, flag or dependency. `compression_type` still defaults to
`None`, so `Blockstore::open()` and every other default open behave as before.
Compression only changes how new SST blocks are encoded: no key is added,
removed or skipped, and files written earlier stay readable. LZ4 is the only
codec compiled into the current build, and that build can already read LZ4
files, so a compressed ledger can be opened by the previous binary.

The patch was written against the runner revision that follows LOCAL-098-r3.
`ledger/src/blockstore_db.rs` is byte-identical to its LOCAL-098-r3 state
before the patch (sha256 `4bca8139…2b2553c`); the hunks for
`zolana-fast-check/src/main.rs` may need a line offset on LOCAL-098-r3. It is
not part of `reconstruction-plan.json`.

### The shrink tool

New files are compressed as they are written, but existing files stay as they
are until they are rewritten. `zolana-ledger-shrink` does that rewrite once,
offline:

1. opens the directory read-only and records, for every column family, the
   entry count and a SHA-256 over every key and value;
2. reopens read-write with automatic compactions off and LZ4 selected for the
   chosen columns, and runs one forced full manual compaction per column;
3. reopens read-only, recomputes the digests, and requires them to be
   identical for every column family and every rewritten SST file to carry the
   LZ4 table property;
4. writes a JSON receipt and exits 0 only if all of that held.

It never creates a database, drops a column family or deletes a key. It is a
workspace of its own and pins the same `rust-rocksdb` revision the validator
links.

```
zolana-ledger-shrink support
zolana-ledger-shrink inspect --db /abs/path/rocksdb [--digest]
zolana-ledger-shrink shrink  --db /abs/path/rocksdb --receipt /abs/new.json
```

## Measurements

Devnet upgrade, 20 November 2026 (Linux x86-64, three validators, chain stopped
for 34 minutes in total):

| Measurement | Result |
| --- | --- |
| Each validator ledger, on disk | 26.1 GiB to 4.1 GiB, 6.4x |
| All three ledgers | 78 GiB to 12 GiB |
| Content digests before and after, every column family, all three ledgers | identical |
| Rewritten files carrying the LZ4 table property | all |
| Block production after restart on the rewritten ledgers | normal, 5.00 slots per second |
| Newest `OPTIONS-*` in each ledger | `kLZ4Compression` for `data_shred`, `kNoCompression` for `root` |

Earlier measurements on copies (macOS, Apple silicon):

| Measurement | Result |
| --- | --- |
| Three earlier, smaller devnet ledger copies | about 1,597 MB to about 284 MB each, 5.6x |
| Data shreds / coding shreds | 8.9x / 3.7x |
| 30 GB synthetic database, shrink with full content check | 103 s |

Two things compression does not change: write-ahead logs are never compressed,
and a deduplicating backup that already compresses its input gains little
(about 22 % in our test) and has to upload a rewritten ledger in full once.

## What has and has not been verified

Done:

- the patch applies cleanly to a freshly reconstructed source tree, on macOS
  and on the Linux build host;
- validator built on Linux x86-64 with the patch; the runner test gate passes
  with 130 tests: the 129 retained cases plus
  `ledger_compression_tests::pilot_config_compresses_new_ledger_blocks_and_never_prunes`;
- the shrink tool built on Linux x86-64; trial on a copy of a real 19.9 GiB
  ledger (2.9 GiB afterwards, contents identical), then the three live ledgers;
- the patched validator started on the rewritten ledgers and the devnet has
  been producing blocks on it since.

Not done:

- `blockstore_db::tests::test_should_enable_cf_compression` in the ledger crate
  was not run on the build host (only the runner gate was);
- on-disk growth per hour with compression on has not yet been measured over a
  full window;
- the patch is written against the runner revision that follows LOCAL-098-r3
  and is not wired into `reconstruction-plan.json`.

## Remaining

1. Run the ledger crate test above on the build host.
2. Publish the intermediate runner revision and add this patch to the
   reconstruction plan, then move it out of `drafts/`.
3. Record measured growth per hour over several windows.
