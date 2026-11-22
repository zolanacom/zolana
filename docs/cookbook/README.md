# Cookbook

Short recipes for the [developer SDK](../../sdk/README.md). Each one runs from a
checkout with no network, no node and no funds: the inputs are fixtures in
[`sdk/fixtures`](../../sdk/fixtures), real payments with real proofs made by
the repository's own code.

| Recipe | Language | What you get |
| --- | --- | --- |
| [Decode a payment](decode-a-payment.md) | JavaScript | The public fields of a payment, from its bytes |
| [Verify a payment offline](verify-a-payment-offline.md) | Rust | A check of the signatures and the proof, and a list of what that does not cover |
| [Watch the pool account](watch-the-pool-account.md) | JavaScript | The pool's note count, backing and latest root, from a file or from an RPC endpoint |
| [Check that a payment landed](check-that-a-payment-landed.md) | JavaScript | What the devnet explorer feed says about a transaction |
| [Check an address](check-an-address.md) | JavaScript | A typing and network check of a shielded address before you pay it |

Before the first recipe, clone the repository. The JavaScript recipes need only
Node.js; they have no dependencies, nothing is installed, and they run in
well under a second. The Rust recipe needs the toolchain and the one-time
`fetch` described in the [SDK quick start](../../sdk/README.md#quick-start),
and its first build compiles the proof system.

Things that hold for every recipe:

- The SDK is source only. Nothing is published to npm or crates.io.
- The formats are experimental and can change without migration.
- The code has not been independently audited.
- The public devnet admits cohort wallets only, and devnet test coins are
  valueless and distinct from the ZOL token. Develop against a
  [local network](../local-validator-runbook.md).

## How these pages stay true

Every JavaScript or Rust block on these pages is a passage of a file in the
repository, and every output block is what that file printed. `sdk/js/cookbook.test.mjs` checks
both on each test run: it compares the code blocks with the files, runs the
JavaScript examples and compares what they print, and compares the Rust
command's output with a file that the Rust tests compare with the command.

```sh
node --test sdk/js/*.test.mjs
sh tools/dev.sh test --offline --locked -p zolana-sdk-examples
```
