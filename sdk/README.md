# Zolana developer SDK 0.1

This directory is the starting point for building on Zolana's wallet and
protocol libraries. It is a source SDK: you clone the repository and build from
it.

| | |
| --- | --- |
| Version | 0.1, the version of the workspace crates |
| Distribution | Source only. Nothing is published to crates.io or npm, and there is no prebuilt Wasm module |
| Review | Not independently audited |
| Network | Devnet only. Devnet test coins are valueless and distinct from the ZOL token issued on Solana. Mainnet is not yet live |
| Stability | Wire formats, account layouts, identifiers and the custom RPC methods are experimental and can change without migration |

Read [Limits](#limits) before you plan around it.

## What is here

| Path | What it is |
| --- | --- |
| [`rust-examples/`](rust-examples) | Six runnable, offline Rust examples, the `inspect-payment` command and two test files, as the workspace package `zolana-sdk-examples` |
| [`EXAMPLES.md`](EXAMPLES.md) | Each example with its command and the output it printed |
| [`build-browser-core.sh`](build-browser-core.sh) | Builds the browser wallet core to WebAssembly |
| [`js/zolana-browser-core.d.ts`](js/zolana-browser-core.d.ts) | TypeScript types for the browser core, including the shapes of its JSON results |
| [`js/rpc.mjs`](js/rpc.mjs), [`js/rpc.d.mts`](js/rpc.d.mts) | A dependency-free JSON-RPC client for the methods the wallets call, with types |
| [`js/vault-example.mjs`](js/vault-example.mjs) | Loads the built core and creates a disposable wallet |
| [`js/formats.mjs`](js/formats.mjs), [`js/explorer.mjs`](js/explorer.mjs) | Offline readers for a payment, the pool account, a shielded address and the explorer feed, with runnable examples ([JavaScript guide](js/README.md)) |
| [`fixtures/`](fixtures) | Real payments with real proofs, and the pool account after them, for the tests and the examples |
| [`../docs/cookbook/`](../docs/cookbook/README.md) | Short recipes built on the parts above, each checked by a test |
| `js/*.test.mjs` | Tests for the client, the types, the readers, the examples and the cookbook, run with Node's built-in test runner |

## What you can do with it

Without a network, a node or any funds:

- derive a wallet from a seed, write and read its encrypted recovery file, and
  encode and decode its shielded address (`npriv1…`);
- build real shielded payments (deposit, private send with a shielded fee) and
  their proofs, and verify them the way a validator does;
- encode and decode the payment wire format and the single-transaction envelope;
- decode the pool account and work out which anchors it accepts;
- compute the pool address and the address of a nullifier account;
- replay payments into a wallet's balance and notes.

With an endpoint:

- call the JSON-RPC methods the wallets use, against a local network or, for a
  wallet that holds a cohort membership, against a devnet gateway.

## Quick start

You need Git, Rust 1.92 (pinned in `rust-toolchain.toml`) and a C/C++
toolchain, as described in the [repository README](../README.md#build-and-run).
The `fetch` step needs network access; everything after it runs offline.

```sh
git clone https://github.com/zolanacom/zolana.git
cd zolana
sh tools/dev.sh fetch --locked
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example wallet_address
```

The last command prints (the recovery file's size varies by a few bytes):

```text
recovery file: format native-wallet-seed-v1, 1259 bytes
wrong password: password is incorrect or encrypted seed was modified
private address: npriv1gZWMfgeB9UAafpZyPa5Pf92AdWqYpJKVgDuHNf7Z7JGnpxQSqAYXtCgvrYcFkwfzSUDXFBDx5gtWuSQnRnGCDr6fVn3Ba7NwiuLA386Xd2dV
same text on another network: receiving address checksum or network mismatch
```

`fetch` downloads the dependencies of the whole workspace, including the
validator's. The examples compile only the crates they need.

Run the other examples the same way: `verify_proof`, `wire_message`,
`private_payment`, `nullifier_address`, `pool_state`. [EXAMPLES.md](EXAMPLES.md)
walks through each. Then run the tests:

```sh
sh tools/dev.sh test --offline --locked -p zolana-sdk-examples
node --test sdk/js/*.test.mjs
```

## The Rust crates

Three crates do not depend on the vendored validator in `node/agave`:

| Package | Path | Use it for |
| --- | --- | --- |
| `native-payments` | `protocol/payments` | The payment wire format, the verifier, the pool state, slot anchors, staging and the inline envelope, the program and account addresses |
| `native-wallet-core` | `clients/wallet-core` | The `npriv1` address format, payment construction with proofs (`PaymentProver`), and replay of history into notes, a balance and witnesses (`WalletState`, `Replay`) |
| `native-wallet-seed` | `clients/wallet-seed` | The encrypted recovery file (`native-wallet-seed-v1`) |

They build on the [`orchard`](https://crates.io/crates/orchard) crate, version
0.16.0, and its types (keys, addresses, bundles) appear in their APIs.

`native-wallet` and `native-payment-program` are different: they depend on
crates inside `node/agave` by path and build only inside this workspace. That
includes the builders for the program's instructions
(`node/adapter/src/instructions.rs`) and everything that signs and sends
transactions. See [Limits](#limits).

### API reference

The public items carry doc comments. Generate the reference locally:

```sh
sh tools/dev.sh doc --offline --locked --no-deps -p native-payments -p native-wallet-core -p native-wallet-seed
```

It is written to `target/doc/native_payments/index.html`.

### Use the crates from your own project

Add them as Git dependencies and pin a commit. The package names are the
`native-*` names above; Cargo finds each package inside the repository.

```toml
[dependencies]
native-payments = { git = "https://github.com/zolanacom/zolana", rev = "4c36000033f1109f097635a3ac7511c6e7e23a9d" }
native-wallet-core = { git = "https://github.com/zolanacom/zolana", rev = "4c36000033f1109f097635a3ac7511c6e7e23a9d" }
native-wallet-seed = { git = "https://github.com/zolanacom/zolana", rev = "4c36000033f1109f097635a3ac7511c6e7e23a9d" }
# The same orchard configuration as the Zolana workspace.
orchard = { version = "=0.16.0", default-features = false, features = ["circuit", "std", "zeroize"] }

# Profiles are not inherited from a dependency's workspace. Without this the
# proof system is compiled unoptimized in debug builds.
[profile.dev.package."*"]
opt-level = 2
```

`rev` is the commit this was checked against; replace it with the commit you
have reviewed. Things to know:

- Your project needs Rust 1.92 or later.
- Cargo clones the whole repository, including the vendored validator source,
  but compiles only what the three crates need. In the check below that was 148
  crates, none of them from `node/agave`.
- Your project resolves its own dependency versions. To start from the versions
  this repository tests with, copy the repository's `Cargo.lock` next to your
  `Cargo.toml` before the first build; Cargo keeps the entries it needs and
  drops the rest.
- The `[patch]` section of the repository's `Cargo.toml` does not apply to your
  project. It concerns validator dependencies.
- There is no compatibility promise between commits. Follow changes by reading
  the history.

How this was checked: a separate crate outside the workspace, with exactly the
dependencies above, derived an address, wrote and read a recovery file, decoded
a pool account, built a deposit with a real proof and replayed it into a
balance. It was built and run offline in two forms: with `path` dependencies on
a checkout, and with `git` dependencies on a local clone of the commit named
above (`git = "file://…"`). Fetching from github.com was not part of the check.

The smallest wallet integration implements one trait:

```rust
use native_wallet_core::{Result, WalletKeys};
use orchard::keys::SpendingKey;

struct Wallet { network: [u8; 32], genesis: String, seed: [u8; 32] }

impl WalletKeys for Wallet {
    fn network_domain(&self) -> [u8; 32] { self.network }
    fn genesis_hash(&self) -> &str { &self.genesis }
    fn spending_key(&self) -> Result<SpendingKey> {
        Option::from(SpendingKey::from_bytes(self.seed)).ok_or_else(|| "invalid seed".into())
    }
}
```

That is `DemoWallet` in [`rust-examples/src/lib.rs`](rust-examples/src/lib.rs),
which every wallet example uses.

## The browser core (Wasm)

`clients/browser-core` is the Rust core of the browser wallet. It keeps the
seed, note decryption and proof construction inside WebAssembly; JavaScript
owns storage and transport.

```sh
sh sdk/build-browser-core.sh
```

The script does not install anything. It needs:

1. the dependencies fetched (`sh tools/dev.sh fetch --locked`);
2. the `wasm32-unknown-unknown` target for the pinned Rust toolchain
   (`rustup target add wasm32-unknown-unknown`);
3. the `wasm-bindgen` command-line tool in `PATH`, at exactly version 0.2.129,
   the version of the `wasm-bindgen` dependency pinned in
   `clients/browser-core/Cargo.toml` (for example
   `cargo install --locked wasm-bindgen-cli --version 0.2.129`). The script
   refuses any other version.

It runs a release build of the library for that target and then `wasm-bindgen
--target web`, and writes `browser_core.js`, `browser_core_bg.wasm` and
wasm-bindgen's own `.d.ts` files to `clients/browser-core/pkg/`, which is
git-ignored. The comments at the top of the script say where each step comes
from in the repository.

Then load it:

```sh
node sdk/js/vault-example.mjs
```

In a page or worker the same module is loaded with
`const core = await import("/wasm/browser_core.js"); await core.default();`,
which is what `clients/browser-wallet/product-worker.js` does.

What was and was not checked:

- The script was run on macOS (Apple Silicon) with Rust 1.92.0 and wasm-bindgen
  0.2.129, and `vault-example.mjs` ran against its output in Node 25.2.
- The output was **not loaded in a browser** as part of this SDK.
- The **threaded build** (the `browser-multicore` feature) is not covered. It
  needs shared Wasm memory, atomics, cross-origin isolation and an initialised
  thread pool, and the repository does not record the compiler flags for it.
- Whether the `.wasm` bytes are reproducible across machines has not been
  checked. Do not expect them to match the files of a deployed wallet.

Read the threat model before you ship anything built on it. From
[decision 0035](../docs/decisions/0035-browser-first-wallet-delivery.md): "WASM
is not an isolated secret vault. A compromised first-party site can steal an
unlocked seed or alter a recipient."

## JavaScript and TypeScript

### Types for the browser core

wasm-bindgen types every JSON result of the core as `string`.
[`js/zolana-browser-core.d.ts`](js/zolana-browser-core.d.ts) describes the same
exports and adds the JSON shapes, as far as the Rust source fixes them: 23
`BrowserVault` methods, 6 functions and the 11 error codes. To use it, copy it
over `clients/browser-core/pkg/browser_core.d.ts` after a build.

It is written by hand. Two things keep it honest: `browser-core-types.test.mjs`
compares its exported names and error codes with the Rust source, and its
signatures were compared once with the `.d.ts` that wasm-bindgen generated,
using the TypeScript 5.9 compiler. TypeScript is not a dependency of this
repository, so that second comparison is not part of the test run.

### The JSON-RPC client

[`js/rpc.mjs`](js/rpc.mjs) is plain ESM with JSDoc types and no dependencies;
[`js/rpc.d.mts`](js/rpc.d.mts) is generated from it for TypeScript users. It
needs a runtime with `fetch`.

```js
import { createRpcClient } from "./sdk/js/rpc.mjs";

// A local network (tools/localnet.py) needs no access header.
const rpc = createRpcClient({ url: "http://127.0.0.1:18899" });
console.log(await rpc.getGenesisHash());
console.log(await rpc.getSlot());
```

A wallet that has been admitted to a devnet cohort passes its access proof.
`vault` is an unlocked `BrowserVault`, and the audience is the gateway's RPC
URL:

```js
const rpc = createRpcClient({
  url: gatewayRpcUrl,
  accessHeader: () => vault.rpc_header(gatewayRpcUrl, BigInt(Math.floor(Date.now() / 1000))),
});
```

**The public devnet admits cohort wallets only.** Without a membership a
gateway answers every method except `getGenesisHash` with HTTP 403. There is no
public RPC endpoint and no public faucet. Develop against a
[local network](../docs/local-validator-runbook.md).

What the client does:

- sends one JSON object per request with the exact headers and size limits the
  invited gateway enforces, reads a bounded response, and times out;
- never retries. After a failed `submitShieldedPayment` the outcome is unknown:
  resolve the saved payment from finalized history before building another;
- throws `HttpError` (for example 403 or 429 from a gateway), `RpcError` (a
  JSON-RPC error; `capacityScope` reports the relay's capacity limit) or
  `TransportError` (timeout, network failure, malformed answer);
- offers typed wrappers for the standard reads the wallets use, the three relay
  methods and the bounded wallet reads, and `call(method, params)` for anything
  else.

What it does not do: it holds no keys, signs nothing, builds no transactions
and does not sync a wallet. Syncing, storage and recovery are the logic in
`clients/browser-wallet/product-worker.js`, which this SDK does not package.

The tests run the client against a loopback server that applies the invited
gateway's request rules. **The client was not run against a validator or a
devnet gateway.**

## Limits

- **Nothing is published.** No crates.io packages, no npm package, no prebuilt
  Wasm. The package names are the workspace's internal names.
- **No stability.** The wire module calls itself "not a released protocol".
  There are two pool formats. The custom RPC methods are unversioned.
- **No audit.** Neither the protocol code nor this SDK has been independently
  reviewed.
- **You cannot send a payment to a chain with the three crates alone.** They
  produce and verify payment bytes. Wrapping those bytes in transactions,
  signing and sending is in `native-payment-program` and `native-wallet`, which
  build only inside this workspace. On a local network, use the `native-wallet`
  command line ([local wallet runbook](../docs/local-wallet-runbook.md)).
- **The devnet is not open to developers.** Access needs an invitation to a
  finite cohort. Deploying programs there is not supported.
- **The JavaScript side is a description and a transport, not a wallet.** There
  is no packaged sync, storage or recovery logic, and no typed access to the
  admission routes. The readers in `js/formats.mjs` decode public bytes; they
  verify no signature and no proof.
- **A client trusts its RPC endpoint for consensus.** Replay verifies proofs,
  signatures and the continuity of the history it is given. It is not a light
  client.
- **No viewing-key export, no watch-only mode, no payment-request format.**
- **Platforms.** Everything here was run on Apple Silicon macOS only.

Shielding hides amounts and counterparties from the public ledger. Fees,
timing and nullifiers stay public, deposits and withdrawals reveal their
amounts and public accounts, and a gateway operator can link submitted payments
to a member. See the repository README's
[Status and limitations](../README.md#status-and-limitations).
