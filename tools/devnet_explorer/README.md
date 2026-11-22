# Devnet explorer feed

A small read-only pipeline that lets a static web page show recent blocks from
the public devnet without exposing validator RPC.

- `explorer_feed_v0.py` runs next to the validators. It polls a fixed allowlist
  of read-only JSON-RPC methods, keeps a rolling window (120 blocks, 200
  transactions), and serves `feed.json` plus an HMAC-SHA256 signature
  (`feed.sig`) to an allowlisted address.
- `explorer_pull_v0.py` runs on the web host. It fetches both files, verifies
  the signature over the exact bytes, validates the document strictly, and
  publishes it atomically for the static page. It never publishes an older
  feed over a newer one.
- The page in `clients/devnet-explorer/` reads the published file from its own
  origin every five seconds and shows "Live" or "Paused" from the feed's age.
  It fetches nothing else and never talks to a validator.

The two unit files are templates: replace `ALLOW_IP`, `READY_FILE` and
`SOURCE_URL` at install time. Both hosts must hold the same 32-byte key file.

The validators choose new loopback RPC ports at every start. `rpc_env.py` runs
before each start of the feed and passes it the port recorded in the
validators' readiness file, so a validator restart no longer leaves the feed
polling a dead port. Restart the feed after the validators (for example with
`PartOf=` on the validator unit) so it picks up the new port.

## Payment-program transactions

The feed marks the transactions that invoke the native payment program, the
built-in program that executes shielded payments, and counts them. The format
name stays `zolana-explorer-feed-v0`; these fields are an addition to it.

| Where | Field | Meaning |
| --- | --- | --- |
| each transaction | `payment_instructions` | The names of the payment-program instructions at the top level of the transaction, each once, in the order `initialize`, `write`, `seal`, `finalize`, `close`, `inline`, `unknown`. `[]` when it carries none, `null` when that is not known |
| each block | `payment_tx_count` | Transactions of the block that carry at least one such instruction, whether they succeeded or failed |
| each block | `executed_payment_count` | Of those, the ones that succeeded and carry `finalize` or `inline`, the two instructions that execute a payment |
| `stats` | `payment_transactions_seen`, `executed_payments_seen` | The same two counts over every block read since `payments_since` |
| `stats` | `payments_since` | When those two counters started: `since`, or the start of the service when it reloaded a window saved before it counted payments |
| each validator | `root_slot` | The validator's root slot as `getVoteAccounts` reports it, or `null` |

The counts of a block cover all its transactions, listed in the feed or not.
Both are `null`, and so is `payment_instructions` of each of its transactions,
for a block the service read without instructions: one the node returned as
signatures only, or one reloaded from a window saved before the service
marked payments. The counters in `stats` leave such blocks out.

**What is read and what is shown.** For each top-level instruction of a
transaction the service reads the program it is addressed to and, when that
is the payment program, the first byte of the instruction data. That byte is
the opcode ([protocol-spec.md, section 13.3](../../docs/protocol-spec.md#133-instructions))
and selects the name; any other first byte, or no data, is `unknown`. Nothing
after that byte is kept and no account of the instruction is read, so the
feed carries nothing of a payment's own bytes: no amount, sponsor, recipient,
nullifier, note commitment or ciphertext. The program address and the
instruction data are in every block a node returns; the mark adds nothing to
what the ledger already shows.

The opcode does not say what a payment is. A deposit, a private send and a
withdrawal are executed by the same instruction, and the feed does not tell
them apart. `finalize` executes a payment that earlier transactions wrote
into a staging account with `initialize`, `write` and `seal`; `close` returns
that account's rent; `inline` carries a whole payment in one instruction.

**One format name, two shapes.** A feed without these fields is still a valid
feed. `validate_feed` in the puller, `validateExplorerFeed` in
`sdk/js/explorer.mjs` and the page accept both. The two strict checks hold a
feed to one shape: when `stats` carries one of the three payment counters,
every validator, block and transaction must carry its fields, and when it
carries none, no row may. The name was kept because a page compares it
exactly: under a new name every earlier page would refuse the feed, while
earlier pages ignore fields they do not know. A puller from before these
fields does not: it checks every key, refuses a feed that carries them and
keeps the last feed it published. Update the puller before the feed service.

## What the page shows

Everything on the page is computed in the browser from the one feed document.

- **Status row.** Tip slot, finalized slot and block height as the feed
  reports them; each counts up from the previous feed value to the newest one.
  "Validators voting" is the number of validators the feed marks active out of
  those it lists.
- **Recent window.** Figures for the blocks held in the feed (at most 120):
  transactions, non-vote transactions and skipped slots are counts over those
  blocks. "Shielded payments" is the sum of `executed_payment_count` over
  them, and the line under it says how many payment-program transactions that
  came from; when the feed marks only some of the blocks it says how many,
  and when it marks none the figure is not shown. "Block time" is the feed's average slot time multiplied by the mean
  number of slots between a block and its parent in the window, and "Blocks
  per minute" follows from it. Neither is measured block by block: the block
  times in the feed are the chain's own clock in whole seconds. Block time,
  blocks per minute and validators voting are shown only while the page is
  Live; the counts stay while it is Paused.
- **Charts.** One column per block, oldest on the left: the block interval
  (slots since the parent, multiplied by the average slot time) and the
  transactions per block with the non-vote part marked. A mark above a column
  shows a block with payment-program transactions, bright when one of them
  executed a payment. A column can be read with the pointer or the arrow keys
  and opened with Enter.
- **Payment filter.** "Payment program" limits the transaction list to
  payment-program transactions and redraws the second chart as
  payment-program transactions per block with the executed payments marked.
  It is offered only while the feed marks them.
- **Kind.** A transaction's kind is "Vote" or "Program", or from its mark:
  "Shielded payment" when it carries `finalize` or `inline` (the result column
  says whether it succeeded), "Payment staging" for the other instructions,
  "Payment program" when the feed could not name its instruction.
- **Details.** A block or a transaction opens in a panel with copy controls
  and steps to the previous and next item. For a marked transaction the panel
  names its payment-program instructions and says in one sentence what they
  did; for a marked block it gives both counts. `#block=<slot>` and
  `#tx=<signature>` in the address open an item while it is in the window; an
  open panel says when its item has left the window.
- **Search.** A slot number, or the first characters of a blockhash or
  signature. A miss says why: the slot is ahead of the window, older than it,
  was skipped, or its block is not in the feed.
- **Fees** are shown in test coins and lamports.
- **A feed without marks.** The page reads it as before and says "The feed
  does not mark which transactions are shielded payments." It does not guess.

With `prefers-reduced-motion`, counters and new rows change at once.

`index.html` is the explorer section inside a page shell whose shared style
sheets, images and scripts (`/style.css` and the others it names by absolute
path) belong to the website and are not in this repository. `explorer.js` and
`explorer.css` are complete. The script also fills a status badge, a strip of
recent slots, a block-height line and a list of the validators in the feed on
any page that carries the matching `data-zolana-*` elements; this repository
holds no such page. The list has one row per validator: identity, vote
account, last vote, how many slots that vote is behind the tip slot of the
same feed, the root slot when the feed carries one, and whether the feed
marks the validator active. While the page is not Live the last column says
"when last recorded".

Limits: only the recent window is shown and searchable; there is no deep
history. Block times come from the chain's clock, so the page shows ages
relative to when the feed last saw a new block.

## Tests

`python3 -B -m unittest test_explorer_feed_v0 test_rpc_env` and
`python3 -B test_explorer_pull_v0.py` in this directory.

`tools/check.sh` runs the same three suites: `tools/devnet_explorer_test.py`
hands them to its `unittest discover` run, which does not find files named
`test_*.py` on its own.

For the page, from the repository root:

```sh
node --test clients/devnet-explorer/*.test.mjs
```

`explorer.test.mjs` tests the validation, formatting, state, search,
recent-window, payment-mark, validator and link functions of `explorer.js`
against the sample feeds: `feed.sample.json` and `feed.paused.json` carry no
marks, and `feed.payments.json` is the first of them with marks. The values
of all three are synthetic. `page.test.mjs` checks, as text, that
`index.html` carries every element the script binds and every field it fills,
and the wording of the figures. Both run in `tools/check.sh` and in the checks workflow. Neither
opens a browser: drawing, motion, the keyboard, copying, the payment filter's
buttons, the validators list and layout are not covered by tests in this
repository.
