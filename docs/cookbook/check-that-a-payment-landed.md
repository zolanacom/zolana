# Check that a payment landed

The devnet explorer page shows a feed of recent blocks and transactions.
[`sdk/js/explorer.mjs`](../../sdk/js/explorer.mjs) reads the same document:
`validateExplorerFeed` applies the feed contract, and `findTransaction` looks
a signature up.

```sh
node sdk/js/examples/payment-landed.mjs
```

With no argument the example reads the sample feed in
`clients/devnet-explorer` and looks up its newest transaction, its oldest one
and a signature it does not hold. Pass signatures to look up your own, and
`--feed <file or URL>` to read another feed.

<!-- snippet: sdk/js/examples/payment-landed.mjs -->
```js
const feed = validateExplorerFeed(JSON.parse(text));
const finalized = feed.network.finalized_slot;
console.log(`feed ${feed.format}: status ${feed.network.status}, finalized slot ${finalized ?? "unknown"}, ${feed.transactions.length} transactions in the window`);

const signatures = wanted.length > 0 ? wanted
  : [feed.transactions[0].signature, feed.transactions.at(-1)?.signature ?? "", "1".repeat(64)];
for (const signature of signatures) {
  const found = findTransaction(feed, signature);
  if (found === null) {
    // Not in the window. This says nothing about whether it was ever executed.
    console.log(`${signature}\n  not in the feed's window`);
    continue;
  }
  const { transaction, atOrBelowFinalized } = found;
  const place = atOrBelowFinalized === null ? "the feed reports no finalized slot"
    : atOrBelowFinalized ? "at or below the feed's finalized slot" : "above the feed's finalized slot: look again later";
  console.log(`${signature}\n  slot ${transaction.slot}, ${transaction.ok ? "no error recorded" : "failed"}, fee ${transaction.fee}, ${place}`);
}
```

<!-- output: node sdk/js/examples/payment-landed.mjs -->
```text
feed zolana-explorer-feed-v0: status live, finalized slot 254839, 37 transactions in the window
4m8QYMPsQaqE45rVXdXLPQp1EnRjGGpKdwgoNg8ZuWbkQfgffdGmFVHG3YiEMDzVJvgeNhEMb8iHicTGquV9Zf6U
  slot 254867, no error recorded, fee 5000, above the feed's finalized slot: look again later
4x12uCZs95HQKtXoDhpom9Gry6Go7Fta7hzb3osKZHBSpPSx8NYtj2XKUAwocY9dGsUL5DGHg5PZw17Uzoiuv8zZ
  slot 250981, no error recorded, fee 5000, at or below the feed's finalized slot
1111111111111111111111111111111111111111111111111111111111111111
  not in the feed's window
```

Where the signature comes from: `sendTransaction` returns it, and for a
payment handed to the relay `getShieldedPaymentStatus` carries a `signature`
field once the payment's state is `accepted` or `aborted`.

Read the answer for what it is:

- **A match** means the feed service read a block that lists the signature.
  `ok` and `fee` come from the node's execution record when the service read
  the block in full. When the node returned signatures only, the service
  reports `ok: true` and a fee of 0 for every transaction of that block.
- **At or below the finalized slot** compares the transaction's slot with the
  finalized slot the feed reports. The service may list a block before it is
  finalized.
- **No match** means the signature is not in the window: at most 200
  transactions and 120 blocks. It does not mean the transaction failed or was
  never sent.
- The feed is a convenience view. It carries no signature a reader can check,
  and it is not history. A wallet settles a payment from finalized blocks; the
  relay's status is a hint as well.

The page loads the feed from `/explorer/feed.json` on its own origin. The
example was tested with the sample file and with a loopback server, not
against a deployed explorer.

## When the feed marks payments

A feed may also mark the transactions that invoke the native payment program.
Each transaction of such a feed carries `payment_instructions`, the names of
the payment-program instructions at its top level, and `findTransaction`
returns `payment`, what that mark says. `marksPayments(feed)` tells the two
shapes of the feed apart; `validateExplorerFeed` accepts both.

<!-- snippet: sdk/js/examples/payment-landed.mjs -->
```js
if (marksPayments(feed)) {
  for (const signature of signatures) {
    const found = findTransaction(feed, signature);
    if (found === null) continue;
    const names = found.transaction.payment_instructions ?? [];
    console.log(`${signature}\n  payment program: ${found.payment}${names.length > 0 ? ` (${names.join(", ")})` : ""}`);
  }
}
```

<!-- output: node sdk/js/examples/payment-landed.mjs --feed clients/devnet-explorer/feed.payments.json -->
```text
feed zolana-explorer-feed-v0: status live, finalized slot 254839, 37 transactions in the window
4m8QYMPsQaqE45rVXdXLPQp1EnRjGGpKdwgoNg8ZuWbkQfgffdGmFVHG3YiEMDzVJvgeNhEMb8iHicTGquV9Zf6U
  slot 254867, no error recorded, fee 5000, above the feed's finalized slot: look again later
4x12uCZs95HQKtXoDhpom9Gry6Go7Fta7hzb3osKZHBSpPSx8NYtj2XKUAwocY9dGsUL5DGHg5PZw17Uzoiuv8zZ
  slot 250981, no error recorded, fee 5000, at or below the feed's finalized slot
1111111111111111111111111111111111111111111111111111111111111111
  not in the feed's window
4m8QYMPsQaqE45rVXdXLPQp1EnRjGGpKdwgoNg8ZuWbkQfgffdGmFVHG3YiEMDzVJvgeNhEMb8iHicTGquV9Zf6U
  payment program: executed (finalize, close)
4x12uCZs95HQKtXoDhpom9Gry6Go7Fta7hzb3osKZHBSpPSx8NYtj2XKUAwocY9dGsUL5DGHg5PZw17Uzoiuv8zZ
  payment program: none
```

`clients/devnet-explorer/feed.payments.json` is the sample feed with marks;
its values are synthetic.

- **`executed`**: the transaction succeeded and carries `finalize` or
  `inline`, the two instructions that execute a payment. This is what the
  explorer page counts as a shielded payment.
- **`failed`**: it carries one of those two and failed, so no payment was
  executed.
- **`staging`**: it carries neither, only instructions that initialize,
  write, seal or close a staging account.
- **`other`**: it carries only an instruction the feed could not name.
- **`none`**: it carries no instruction of the payment program.
- **`not-marked`**: the feed does not say. Every transaction of a feed that
  carries no marks reads this way, and so does a transaction of a block the
  feed service read without its instructions.

The mark is what the ledger shows to anyone who reads the block: the program
an instruction is addressed to, and the first byte of its data, which names
the instruction. It does not say whether a payment is a deposit, a private
send or a withdrawal, and it carries no amount, account, nullifier,
commitment or ciphertext. An `executed` mark is the feed's reading of a block,
with the limits listed above: it is not a receipt.
