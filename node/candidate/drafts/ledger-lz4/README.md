# Draft: LZ4 compression for the large ledger columns

Status: **draft, not built into any release.** The validator patch has not yet
been compiled against the full workspace and nothing here has run on Linux
x86-64. See "What has and has not been verified" before relying on any of it.

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

All on macOS (Apple silicon), on copies, with the tool in this directory.

| Measurement | Result |
| --- | --- |
| Three devnet ledger copies, on disk | about 1,597 MB to about 284 MB each, 5.6x |
| Data shreds | 8.9x |
| Coding shreds | 3.7x |
| 30 GB synthetic database, shrink with full content check | 103 s |
| Content digests before and after, all column families | identical in all four runs |

Two things compression does not change: write-ahead logs are never compressed,
and a deduplicating backup that already compresses its input gains little
(about 22 % in our test) and has to upload a rewritten ledger in full once.

## What has and has not been verified

Done:

- the patch applies cleanly to a freshly reconstructed source tree;
- both changed files parse with rustfmt (edition 2024);
- a reduced model of the changed function and its test compiles and passes;
- the shrink tool builds and passes its content check on the four databases
  above, on macOS.

Not done:

- the patched validator has not been compiled or tested against the full
  workspace;
- neither the tool nor the patched validator has run on Linux x86-64;
- no replay of a compressed ledger by a patched validator;
- compression ratio on later, fuller blocks.

## Before this can ship

1. Build the validator with the patch and run the runner test gate plus
   `blockstore_db::tests::test_should_enable_cf_compression`.
2. Replay drill on a disposable ledger copy: shrink it, start the patched
   validator on it, and confirm the newest `OPTIONS-*` file shows
   `kLZ4Compression` for `data_shred`, `code_shred`, `index` and `meta`, and
   `kNoCompression` for `root`.
3. Size backup storage for one full re-upload of the rewritten ledger.
