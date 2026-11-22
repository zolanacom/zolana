# Watch the pool account

All shielded value sits behind one account, the pool. Its data holds the note
count, the backing (the public coins held for the notes) and the recent roots
of the note tree. `decodePoolAccount` in
[`sdk/js/formats.mjs`](../../sdk/js/formats.mjs) reads it.

```sh
node sdk/js/examples/watch-pool.mjs
```

With no argument the example decodes a fixture: the pool after a deposit of
100, a send with a fee of 3 and a withdrawal of 20.

<!-- snippet: sdk/js/examples/watch-pool.mjs -->
```js
function describe(data) {
  const pool = decodePoolAccount(new Uint8Array(Buffer.from(data, "base64")));
  const latest = pool.slotAnchors.at(-1);
  return `${pool.tag}: ${pool.noteCount} notes, backing ${pool.backing}` +
    (latest ? `, latest root ${latest.root} at slot ${latest.slot}` : "");
}
```

<!-- output: node sdk/js/examples/watch-pool.mjs -->
```text
NPOOL004: 6 notes, backing 77, latest root 30948a46bf1dae55da625ae554938b4b003dfd3ea6b660bacfecae57155bee1a at slot 3
```

Six notes are three payments of two actions each, and the backing is 100 less
the fee of 3 and the withdrawal of 20.

## Against an endpoint

```sh
node sdk/js/examples/watch-pool.mjs --url http://127.0.0.1:18899
```

That is the default RPC address of a
[local network](../local-validator-runbook.md). The example asks for the
account every two seconds and prints a line when it changes:

<!-- snippet: sdk/js/examples/watch-pool.mjs -->
```js
  const rpc = createRpcClient({ url });
  let previous;
  for (let poll = 0; poll < polls; poll++) {
    if (poll > 0) await sleep(interval);
    const account = await rpc.getAccountInfo(POOL_ADDRESS);
    if (account.value === null) throw new Error("this network has no pool account");
    // The pool is the account at this address that the payment program owns.
    if (account.value.owner !== PROGRAM_ID) throw new Error("the account is not owned by the payment program");
    const line = describe(account.value.data[0]);
    if (line !== previous) console.log(`slot ${account.context.slot}: ${line}`);
    previous = line;
  }
```

The pool address and the program id are fixed development values;
`POOL_ADDRESS` and `PROGRAM_ID` are exported by `formats.mjs`.

Limits:

- This polls with `getAccountInfo`. The SDK's client has no subscription.
- The decoder checks the layout and the bookkeeping rules but does not
  recompute the tree root from the stored frontier. The Rust
  `PoolState::decode` does.
- An account is only as trustworthy as the endpoint that served it. A wallet
  replays finalized history and reconciles the result with this account; it
  does not take balances from it.
- The loop was tested against a loopback server that serves the fixture, not
  against a validator.

`acceptedRoots(pool, slot)` returns the roots a payment may be anchored to
when it executes at a slot: the roots of completed earlier slots younger than
512 slots.
