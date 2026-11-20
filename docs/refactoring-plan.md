# Zolana refactoring plan

This review covers Zolana source added or changed since the Agave fork. The
initial inventory contained 356 first-party source, UI, script and test files,
plus 67 files changed in the imported Agave tree.

Use the pristine Agave v3.0.14 tree recorded in `THIRD_PARTY.md` to identify
our changes in `node/agave`: it is the `node/agave` directory of the second
commit in this repository's history. Review the Agave 4.3.2 candidate patches
and reconstruction under `node/candidate` against their separate baseline.
First-party code outside the vendor tree includes initial scaffolding, so
review all current source in those directories.

| Order | Code | Work and verification |
| --- | --- | --- |
| 1 | Browser Rust/Wasm and wallet worker | Assign stable error codes where the Rust failures originate. Keep diagnostics and UI copy separate. Verify existing error categories, password cleanup, encrypted backup compatibility and unknown-error handling. |
| 2 | Browser session, sync, payments and storage | Give one owner responsibility for vault lifetime, cancellation and request generations. Keep the worker action protocol and durable IndexedDB formats compatible. Verify lock during in-flight and queued work, original-payment recovery, and sync and storage regressions. |
| 3 | Native wallet RPC | Keep the `Chain` API and extract history scanning, fee policy and staged payment lifecycle into focused modules. Preserve journal and checkpoint formats. Run native wallet recovery and transport tests. |
| 4 | Python/shell tooling and gateways | Review HTTP framing, authorization, transport, cache and lifecycle ownership. Extract compatible operations and make resource cleanup explicit. Exercise existing gateway, relay, archive, renewal, monitoring and failure fixtures. |
| 5 | Shared wallet core, seed, protocol and adapter | Review each public boundary and the transaction execution phases. Preserve cryptographic inputs, wire formats, feature IDs, durable state and nullifier semantics. Use deterministic vectors and existing protocol, replay and Bank integration tests. |
| 6 | Local validators, operator RPC and Agave patches | Review restart, fork handling, build compatibility and protected transport against the upstream source. Keep patch intent and integration tests easy to locate. Verify offline with cached toolchains and synthetic inputs. |
| 7 | Client UI, CLI, build and release tooling | Review component ownership and contributor entry points. Complete the first-party format and regression commands and document reproducible candidate reconstruction. Keep historical release and acceptance evidence intact. |

For each stage, trace real callers and persisted data first. Keep public
entry points stable or provide a compatibility path. Give each module a clear
responsibility and leave working code in place when its boundary is already
clear. Run targeted regressions before moving on, followed by the applicable
broader checks. Record tests that require unavailable local dependencies or
live infrastructure separately from passing local tests.

Use cached dependencies with Cargo `--offline --locked`, the browser wallet
and network portal Node suites, and the relevant Python fixture suites. Use
disposable test state. Preserve existing wallet and ledger data and original
transaction and admission history. Work offline and leave deployment outside
this refactor.

The refactor is complete after each source area has a documented review,
its justified changes have landed in the workspace, and the corresponding
offline checks and remaining limitations have been recorded.

## Implementation and ownership

| Area | Result and maintenance boundary |
| --- | --- |
| Browser Rust errors | `clients/browser-core/src/error.rs` owns typed failures and stable versioned Wasm codes. Vault, session and access checks assign their categories at the source. The worker maps codes to fixed public copy. Existing encrypted records, seed derivation and cryptographic inputs retain their formats. |
| Browser lifetime | `WalletSession` in `clients/browser-wallet/product-worker.js` owns vault/store handles, request generations, cancellation, queued passwords and transient payment state. Cleanup detaches owned state and attempts each remaining handle independently. The worker remains one packaged asset so its reviewed asset-loading path remains usable. Sync, payment and IndexedDB transaction ordering retain their existing entry points. |
| Native RPC | `rpc.rs` retains the public `Chain` interface and shared serialized structs. `rpc/scan.rs`, `rpc/fee_policy.rs` and `rpc/staged_payment.rs` own replay, fee rules and staged-payment lifetime. Recovery tests have their own module. Explicit imports make dependencies visible. |
| Native CLI and credentials | `cli.rs` parses arguments before state or transport access. `access/client.rs` and `access/proof.rs` isolate client/proof work from authority locking, quotas and durable state. `faucet/client.rs` and `faucet/gas_transfer.rs` isolate transport and gas transfer from the tick lifecycle. Public import paths remain available through re-exports. |
| Adapter execution | `node/adapter/src/processor/finalization.rs` names the account loading, recipient checks, permanent marker checks, proof validation and execution phases. The dispatcher retains feature gating and lazy verification-key ownership. Check and mutation order, account borrowing and native invocation remain explicit. |
| Gateway and relay | Gateway POST handling separates framing, authorization, routing and response writing while retaining stage labels, deadlines, quotas and upstream response bytes. Relay construction releases its worker lock on every initialization failure, including failures whose traceback is retained. |
| Release tooling | Installation construction separates trust and state loading while retaining pending-operation and anti-rollback checks. Lock ownership has one failure cleanup path. Existing service, archive, renewal, monitoring and signing modules retain their focused boundaries. |
| Candidate provenance | `node/candidate/reconstruction-plan.json` declares all ten retained source transitions. `tools/reconstruct_native_candidate.py` verifies archive and patch identities, applies the complete chain to fresh output and writes final source identities. Historical patch and acceptance packages remain pinned. |
| Contributor checks | `tools/check.sh --development-only` checks all eleven first-party Rust crates, builds workspace CLI prerequisites and runs Rust, Python and Node regressions. Cargo compilation and tests use cached, locked dependencies. |

The scope review also covered protocol envelopes, authorization domains,
anchors, pool/nullifier invariants, shared wallet scanning and encrypted state,
localnet restart and branch selection, private RPC socket ownership, and the
browser/portal UI boundaries. Existing focused boundaries were retained after
tracing their callers and regression coverage. Historical acceptance-driver
coverage consists of architecture, caller and dependency review plus scoped
regressions.

## Platform verification limits

| Check | Local result and next dependency |
| --- | --- |
| Browser Wasm compilation | A follow-up check installed isolated Rust 1.92.0 with `wasm32-unknown-unknown` and verified wasm-bindgen 0.2.129 against its upstream release digest. The scalar release build and web bindings passed. Fresh Chromium passed seven checks covering 14 storage assertions, 14 vault assertions, reload recovery, the current product worker and two synthetic proof/native-parity runs. Other browsers, the parallel artifact and live payment acceptance remain separate checks. |
| Agave 4.3.2 runtime | The complete candidate source chain reconstructed successfully from the pinned cached archive. The follow-up acquired Rust 1.97.1 in an isolated Linux/amd64 container. The normal binary and recovery-feature test executable built with networking disabled. Of 124 unique cases, 123 passed after correcting writable fixture paths. One million-record archive publication case still reaches its unchanged 180-second deadline under x86-64 emulation, including targeted optimized retries on Linux tmpfs. Native x86-64 verification remains open. Read-only `--build-info` passed. The retained candidate emits 17 unique unused-code warnings. |
| Historical upstream provenance | The retained pristine Agave tree matches `THIRD_PARTY.md`. The corresponding upstream commit object is unavailable in the local repository, limiting ancestry verification to that retained import. |
| Python optional crypto tests | Nine native cohort funding cases need the optional `cryptography` package and are skipped without it. All nine passed with cryptography 50.0.2 in an isolated virtual environment. |
| Linux socket activation | Two direct-TLS activated-socket cases run only on Linux. Both passed in an isolated Linux container with networking disabled and disposable sockets. |
