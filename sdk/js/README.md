# Zolana SDK 0.1: JavaScript

Plain ES modules with JSDoc types and no dependencies. The modules use no
Node-only interface; the examples and the tests do. They were run in Node, not
in a browser.

This is source in a repository, not a package on a registry. **Nothing here is
published to npm.** You use it from a checkout. The code has not been
independently audited, and the formats it reads are experimental.

| Module | What it does | Needs |
| --- | --- | --- |
| [`rpc.mjs`](rpc.mjs) | JSON-RPC client for the methods the wallets call | `fetch` |
| [`formats.mjs`](formats.mjs) | Offline readers: a payment, an inline envelope, the payment id, the pool account, a shielded address | `BigInt` |
| [`explorer.mjs`](explorer.mjs) | Reads the devnet explorer feed and looks a transaction up in it | nothing |
| [`index.mjs`](index.mjs) | All of the above from one module | |
| [`zolana-browser-core.d.ts`](zolana-browser-core.d.ts) | Types for the Wasm core of the browser wallet | a build of the core |

Each module has a declaration file next to it for TypeScript (`rpc.d.mts`,
`formats.d.mts`, `explorer.d.mts`, `index.d.mts`).

## Quick start

You need Git and Node.js. Nothing is installed and no request is made.

```sh
git clone https://github.com/zolanacom/zolana.git
cd zolana
node sdk/js/examples/decode-payment.mjs
```

It reads a stored payment, in which Alice pays Bob 40 units with a shielded fee
of 3, and prints the public part:

<!-- output: node sdk/js/examples/decode-payment.mjs -->
```text
shielded-fee-payment: 9230 bytes, tag NPAY0003
network       0707070707070707070707070707070707070707070707070707070707070707
payment id    2b8296f7d96e1f6077bdc31d4541859544c849af0bcd5261aedacd50225c8832
expiry slot   100
public value  3
shielded fee  3
sponsor       6cGXszer5keoaWm8Co5G9f4KGBThuGz4NsKTqYij1emg
anchor        1fbe1c80664a1b478518e05c8029b49418782b2c39b077cf627d4af0b0b5b31d
nullifier     6154b85afc11f06db91f2f7a1f9a860a0e7504217cb12dbd3422e16abb179604
commitment    593c0de55f92909e654bfc77e9307b582c2ff968fd2760f0c1cb4149b0293b02
nullifier     f017eb9715131a11a425e3a24d208b3ea7399541f71575ffe7a5303af95b6c27
commitment    5a4f325f4f2ea8d2f6b4f648215dabedc1d138a51a5fe71853eb27a2188ff82b
for another network: WrongNetwork
```

The other examples run the same way. Each has a page in the
[cookbook](../../docs/cookbook/README.md):

| Example | Cookbook page |
| --- | --- |
| [`examples/decode-payment.mjs`](examples/decode-payment.mjs) | [Decode a payment](../../docs/cookbook/decode-a-payment.md) |
| [`examples/check-address.mjs`](examples/check-address.mjs) | [Check an address](../../docs/cookbook/check-an-address.md) |
| [`examples/watch-pool.mjs`](examples/watch-pool.mjs) | [Watch the pool account](../../docs/cookbook/watch-the-pool-account.md) |
| [`examples/payment-landed.mjs`](examples/payment-landed.mjs) | [Check that a payment landed](../../docs/cookbook/check-that-a-payment-landed.md) |

Then run the tests:

```sh
node --test sdk/js/*.test.mjs
```

## Use it from your own code

Import the modules by path from a checkout:

```js
import { decodePayment, paymentId, checkAddress } from "./zolana/sdk/js/formats.mjs";
import { createRpcClient } from "./zolana/sdk/js/rpc.mjs";
```

Or import them under one name. [`package.json`](package.json) gives this
directory the name `zolana-sdk-js` and marks it `private`, so it cannot be
published. Installing it from a path links your checkout into `node_modules`:

```sh
npm install ./zolana/sdk/js
```

```js
import { decodePayment, createRpcClient, findTransaction } from "zolana-sdk-js";
import { decodePoolAccount } from "zolana-sdk-js/formats";
```

That was checked with npm 11.6 and `--offline`: one linked package, no
download. Install it only from a path you control. This project publishes no package
under this or any other name; a package of this name on a registry is not this
code.

## What the readers do

`formats.mjs` follows the Rust decoders check for check, as far as plain
JavaScript can.

| Function | Follows | It checks | It leaves to Rust |
| --- | --- | --- | --- |
| `decodePayment` | `wire::decode` | Length, tag, network, the public fields and their rules, canonical field elements, flags, action count, proof length | Signatures, the proof, and that the keys of an action are curve points |
| `decodeEnvelope` | `envelope::decode` | The framing, the payment id, the payment, the expiry against a slot you pass | Re-encoding the payment to prove it canonical |
| `paymentId` | `staging::payload_digest` | | |
| `decodePoolAccount` | `PoolState::decode` | Both layouts, the header rules, the frontier's shape, the slot anchors and their order | Recomputing the tree root from the frontier |
| `acceptedRoots` | `PoolState::accepted_roots` | | |
| `checkAddress` | `decode_address` | Prefix, length, version, checksum and the network tag | That the address bytes are a valid shielded address |

A refusal is a `FormatError` whose `code` is the name of the error the Rust
decoder returns for the same bytes. The tests apply one list of changes,
[`fixtures/refusals.json`](../fixtures/refusals.json), to both decoders; the
three entries JavaScript cannot refuse are marked in that list.

To verify a payment, use the Rust command:
[Verify a payment offline](../../docs/cookbook/verify-a-payment-offline.md).

`explorer.mjs` applies the same contract as the Python check the web host runs
before it publishes a feed (`validate_feed` in
`tools/devnet_explorer/explorer_pull_v0.py`). The tests give both checks the
same documents and require the same verdicts.

A feed has one of two shapes under one format name, and both checks accept
both. The second marks the transactions that invoke the native payment program:
`marksPayments(feed)` tells the shapes apart, `paymentStep(transaction)` reads a
mark, and `findTransaction` returns it as `payment`. The fields are described in
[`tools/devnet_explorer/README.md`](../../tools/devnet_explorer/README.md#payment-program-transactions)
and used in [Check that a payment landed](../../docs/cookbook/check-that-a-payment-landed.md#when-the-feed-marks-payments).

## Limits

- **Not a wallet.** No keys, no signing, no proof construction, no sync. That
  is the browser core and the logic in
  `clients/browser-wallet/product-worker.js`.
- **Not a verifier.** Nothing here checks a signature or a proof.
- **Not run against a network.** The client and the examples were tested with
  fixtures and loopback servers, not against a validator, a devnet gateway or a
  deployed explorer.
- **The public devnet admits cohort wallets only.** Develop against a
  [local network](../../docs/local-validator-runbook.md). Devnet test coins are
  valueless and distinct from the ZOL token.
- **Declarations are generated, and checked by name only.** The `.d.mts` files
  were generated from the modules with TypeScript 5.9, by the command at the
  top of each. The new modules and the examples passed its `--checkJs --strict`
  check, and a small strict TypeScript program compiled against the
  declarations. TypeScript is not a dependency of this repository, so the test
  run only compares the exported names with the modules.
- **Platforms.** Run on Apple Silicon macOS with Node 25.2 only.
