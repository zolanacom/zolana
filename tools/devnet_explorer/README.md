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

## What the page shows

Everything on the page is computed in the browser from the one feed document.

- **Status row.** Tip slot, finalized slot and block height as the feed
  reports them; each counts up from the previous feed value to the newest one.
  "Validators voting" is the number of validators the feed marks active out of
  those it lists.
- **Recent window.** Figures for the blocks held in the feed (at most 120):
  transactions, non-vote transactions and skipped slots are counts over those
  blocks. "Block time" is the feed's average slot time multiplied by the mean
  number of slots between a block and its parent in the window, and "Blocks
  per minute" follows from it. Neither is measured block by block: the block
  times in the feed are the chain's own clock in whole seconds. Block time,
  blocks per minute and validators voting are shown only while the page is
  Live; the counts stay while it is Paused.
- **Charts.** One column per block, oldest on the left: the block interval
  (slots since the parent, multiplied by the average slot time) and the
  transactions per block with the non-vote part marked. A column can be read
  with the pointer or the arrow keys and opened with Enter.
- **Details.** A block or a transaction opens in a panel with copy controls
  and steps to the previous and next item. `#block=<slot>` and
  `#tx=<signature>` in the address open an item while it is in the window; an
  open panel says when its item has left the window.
- **Search.** A slot number, or the first characters of a blockhash or
  signature. A miss says why: the slot is ahead of the window, older than it,
  was skipped, or its block is not in the feed.
- **Fees** are shown in test coins and lamports. The feed does not mark which
  transactions are shielded payments, and the page does not guess.

With `prefers-reduced-motion`, counters and new rows change at once.

`index.html` is the explorer section inside a page shell whose shared style
sheets, images and scripts (`/style.css` and the others it names by absolute
path) belong to the website and are not in this repository. `explorer.js` and
`explorer.css` are complete. The script also fills a status badge, a strip of
recent slots and a block-height line on any page that carries the matching
`data-zolana-*` elements; this repository holds no such page.

Limits: only the recent window is shown and searchable; there is no deep
history. Block times come from the chain's clock, so the page shows ages
relative to when the feed last saw a new block.

## Tests

`python3 -B -m unittest test_explorer_feed_v0 test_rpc_env` and
`python3 -B test_explorer_pull_v0.py` in this directory.

For the page, from the repository root:

```sh
node --test clients/devnet-explorer/*.test.mjs
```

`explorer.test.mjs` tests the validation, formatting, state, search,
recent-window and link functions of `explorer.js` against the two sample
feeds. `page.test.mjs` checks, as text, that `index.html` carries every
element the script binds and every field it fills, and the wording of the
figures. Both run in `tools/check.sh` and in the checks workflow. Neither
opens a browser: drawing, motion, the keyboard, copying and layout are not
covered by tests in this repository.
