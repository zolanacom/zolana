# Third-party source

`node/agave/` contains the upstream Agave v3.0.14 source snapshot from <https://github.com/anza-xyz/agave>, commit `f516a8927c76c07f0ebc54ca7a4ce8b2046eee86`. It retains its Apache-2.0 license and file-specific notices. Dependencies retain their own licenses and authorship.

The independent payment module is new project code. Its use of third-party cryptographic libraries does not imply endorsement or inherited security of the integration.

Local modifications to the Agave snapshot register a gated native-payment built-in pin matching syscall APIs, update the toolchain and make explicit lifetime annotations and narrow warning compatibility fixes for Rust 1.92. The pristine upstream source tree is recorded as `a4c75a1781d4ca56e7325a39d0614e1faa26030d`. Existing upstream licenses and notices remain in place.

Local validator build support also selects the upstream networking patches and release-compatible SDK types through the root lockfile, uses a Cargo-packaged Protocol Buffers compiler, and provides an optional platform-allocator build for paths unsupported by jemalloc. The scheduler benchmark retains its allocator as a development dependency. Compiler-compatibility annotations in ledger, gossip and core code do not change their algorithms.

The feature-set and SVM feature mapping also include a separate gate for recipient-bound native withdrawals. Existing payment activation and historical payloads remain supported; the new gate is enabled explicitly in fresh local genesis. Payment authorization and account movement remain in the independent protocol/adapter modules.

The RPC HTTP sender also returns an ordinary error for unfollowed 3xx responses instead of assuming every non-success status is a reqwest 4xx/5xx error and panicking. The wallet disables redirects explicitly. This does not alter validator consensus.

## Agave snapshot: pristine tree, later modifications and changed files

The pristine tree `a4c75a1781d4ca56e7325a39d0614e1faa26030d` named above is a Git tree object. It is the `node/agave` directory of the second commit in this repository's history; the first commit holds an incomplete copy of the snapshot. Every local change can be listed with:

```sh
git diff a4c75a1781d4ca56e7325a39d0614e1faa26030d HEAD:node/agave
```

The description above was written before the later changes below. In addition to what it describes, the local modifications:

- add opt-in validator startup flags `--native-restart-checkpoint`, `--native-durable-votes` and `--native-restart-epoch-horizon` (with its anchor slot and hash arguments), and the replay, vote-recording and leader-schedule logic behind them, in `core/src/replay_stage.rs`, `core/src/validator.rs`, `core/src/validator/native_restart.rs`, `core/src/tvu.rs`, `ledger/src/leader_schedule_cache.rs`, `ledger/src/native_restart_schedule.rs` and `ledger/src/blockstore_processor.rs`. These change validator behaviour when the flags are given. See `docs/decisions/0021-preserved-restart-checkpoint.md`;
- add `--native-rpc-access-file`: an operator capability check on raw HTTP RPC routes that also disables raw WebSockets, and an owner-only Unix-socket RPC transport, in `rpc/src/rpc_service.rs`, `rpc/src/rpc.rs` and the validator argument parsing. They use the first-party `node/rpc-access` crate. See `docs/decisions/0014-tls-and-raw-rpc-isolation.md` and `docs/decisions/0015-private-host-rpc-transport.md`;
- add an explicitly enabled shred-reception fault control for loopback test fixtures, in `validator/src/commands/run/local_fault.rs`;
- add a macOS link directive for the C++ runtime, in `validator/build.rs`;
- register two further feature gates in `feature-set/src/lib.rs` and `svm-feature-set/src/lib.rs`, for native shielded-fee reimbursement and for inline shielded payment execution, beside the two gates described above.

The following 67 files under `node/agave/` differ from the pristine upstream tree. This list is the notice that this project changed them.

Added by this project (4 files):

- `core/src/validator/native_restart.rs`
- `ledger/src/native_restart_schedule.rs`
- `validator/build.rs`
- `validator/src/commands/run/local_fault.rs`

Modified (63 files):

- `Cargo.toml`
- `accounts-db/src/account_info.rs`
- `accounts-db/src/accounts_file.rs`
- `accounts-db/src/accounts_index/secondary.rs`
- `accounts-db/src/append_vec.rs`
- `accounts-db/src/blockhash_queue.rs`
- `accounts-db/src/tiered_storage/hot.rs`
- `accounts-db/src/tiered_storage/meta.rs`
- `builtins/Cargo.toml`
- `builtins/src/lib.rs`
- `core/Cargo.toml`
- `core/src/banking_stage/immutable_deserialized_packet.rs`
- `core/src/banking_stage/transaction_scheduler/transaction_state_container.rs`
- `core/src/consensus/heaviest_subtree_fork_choice.rs`
- `core/src/replay_stage.rs`
- `core/src/tvu.rs`
- `core/src/validator.rs`
- `feature-set/src/lib.rs`
- `gossip/src/crds_value.rs`
- `gossip/src/ping_pong.rs`
- `gossip/src/protocol.rs`
- `ledger/src/bit_vec.rs`
- `ledger/src/blockstore.rs`
- `ledger/src/blockstore/error.rs`
- `ledger/src/blockstore_db.rs`
- `ledger/src/blockstore_processor.rs`
- `ledger/src/leader_schedule_cache.rs`
- `ledger/src/shred.rs`
- `ledger/src/shred/merkle.rs`
- `ledger/src/shred/shred_code.rs`
- `ledger/src/shred/shred_data.rs`
- `ledger/src/shred/wire.rs`
- `rpc-client/src/http_sender.rs`
- `rpc/Cargo.toml`
- `rpc/src/rpc.rs`
- `rpc/src/rpc_service.rs`
- `runtime-transaction/src/runtime_transaction.rs`
- `runtime-transaction/src/runtime_transaction/sdk_transactions.rs`
- `runtime-transaction/src/runtime_transaction/transaction_view.rs`
- `runtime-transaction/src/transaction_with_meta.rs`
- `runtime/src/bank.rs`
- `runtime/src/stakes.rs`
- `runtime/src/stakes/serde_stakes.rs`
- `rust-toolchain.toml`
- `storage-proto/Cargo.toml`
- `storage-proto/build.rs`
- `svm-feature-set/src/lib.rs`
- `svm-transaction/src/svm_message.rs`
- `svm-transaction/src/svm_message/sanitized_message.rs`
- `svm-transaction/src/svm_message/sanitized_transaction.rs`
- `svm/src/transaction_processor.rs`
- `transaction-context/src/lib.rs`
- `transaction-view/src/resolved_transaction_view.rs`
- `transaction-view/src/transaction_view.rs`
- `validator/Cargo.toml`
- `validator/src/commands/run/args.rs`
- `validator/src/commands/run/args/json_rpc_config.rs`
- `validator/src/commands/run/execute.rs`
- `validator/src/commands/run/mod.rs`
- `validator/src/main.rs`
- `vote/src/vote_state_view.rs`
- `wen-restart/Cargo.toml`
- `wen-restart/build.rs`

## Components inside the Agave snapshot with their own notices

The snapshot includes third-party components that carry their own licence or copyright notices. They are retained unchanged, for example `node/agave/ci/semver_bash/LICENSE` (Copyright (c) 2013, Ray Bejjani), the KaTeX distribution under `node/agave/docs/static/katex/` (licence stated in its `README.md` and source headers), and files with their own copyright headers under `node/agave/docs/src/theme/` and `node/agave/install/`.

## Agave 4.3.2 candidate patches in `node/candidate/`

The files `node/candidate/*.patch` are patches against upstream Agave v4.3.2 from <https://github.com/anza-xyz/agave>, commit `a203300045b405f86c9c84308b2eae76af69ac3b`, which is licensed under Apache-2.0. The upstream source archive is not included in this repository. As diffs, the patches reproduce lines of upstream Agave source as context and as modified lines, alongside this project's additions. That upstream code keeps its Apache-2.0 licence and its original authorship.

The base patch `agave-4.3.2.patch` also adds a vendored copy of the crate `agave-transaction-view` version 6.0.0 under `zolana-native/vendor/agave-transaction-view/`. Its included manifest names the authors as "Anza Maintainers <maintainers@anza.xyz>" and the licence as Apache-2.0. Its recorded origin is <https://github.com/anza-xyz/agave-sdk>, revision `6f2c02c1d0865fa03841476b41ac35cb26a6a2ec`, path `transaction-view`. Two of its files are locally modified, `src/sanitize.rs` and `src/transaction_view.rs`, to add an explicit bounded Legacy structural-sanitization API. The `ZOLANA-PROVENANCE.json` file added beside the crate records the registry checksum, the original SHA-256 of every vendored file and the SHA-256 of the two patched files. The vendored copy carries no separate licence file; a copy of the Apache License 2.0 is at `node/agave/LICENSE`.

The later patches (`agave-4.3.2-LOCAL-*.patch`) modify further upstream files, including files under `rpc/`, `runtime/`, `votor/`, `ledger/` and `ledger-tool/` and the upstream `Cargo.lock`, and add this project's own modules.

## Dependencies fetched at build time

Rust crates listed in `Cargo.lock` are downloaded by Cargo and are not copied into this repository. They keep their own licences and authorship. The root `Cargo.toml` patches `crossbeam-epoch`, `quinn` and `quinn-proto` to revisions of <https://github.com/anza-xyz/crossbeam> and <https://github.com/anza-xyz/quinn>, matching the upstream validator.
