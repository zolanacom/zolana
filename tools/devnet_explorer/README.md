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

The two unit files are templates: replace `ALLOW_IP`, `READY_FILE` and
`SOURCE_URL` at install time. Both hosts must hold the same 32-byte key file.

The validators choose new loopback RPC ports at every start. `rpc_env.py` runs
before each start of the feed and passes it the port recorded in the
validators' readiness file, so a validator restart no longer leaves the feed
polling a dead port. Restart the feed after the validators (for example with
`PartOf=` on the validator unit) so it picks up the new port.

Limits: only the recent window is shown and searchable; there is no deep
history. Block times come from the chain's clock, so the page shows ages
relative to when the feed last saw a new block.

Tests: `python3 -B -m unittest test_explorer_feed_v0 test_rpc_env` and
`python3 -B test_explorer_pull_v0.py` in this directory, and
`node explorer_logic_test.js` in `clients/devnet-explorer/`.
