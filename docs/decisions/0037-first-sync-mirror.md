# First-sync history mirror beside the cohort service

Status: accepted for the devnet cohort service, 2026-11-20. No protocol, wallet or admission change.

## Context

A new wallet verifies the whole chain before it shows a balance. Through the cohort gateway it read every produced block from the node, at most 256 blocks a request, so the wait grew with the chain: about 190,000 blocks took a new browser wallet 25 minutes on the devnet, and the gateway's own time, 1.09 s for a 256-block request, comes to about 14 minutes at 200,000 blocks. The wallet and the gateway already had a faster way to deliver the same history, retained pages of up to 32,768 block headers plus the payment transactions, but the cohort service kept no store to serve them from and its gateway was not told to look for one. The existing retention worker (`history_retention.Retention`) does not fit a chain of this length that is already running: it allows 120 seconds a collection, and the service it belongs to pauses when a collection fails.

## Decision

Keep a verified copy of the chain's public payment history beside the running cohort service, and let its gateway serve it.

1. **A collector that runs beside the service** (`tools/first_sync_mirror.py`), not inside it. The verification is the wallet engine's: `native-wallet archive` replays the whole store and the new finalized blocks, checks every payment's signatures and proof and reconciles with the finalized pool before it commits. The program schedules that, publishes each committed result with the existing `history_retention.capture()`, and reads the node only through a read-only forwarder that allows one request at a time and slows down when the chain does. It holds no wallet, password, signer or admission state. Its failures never stop the chain; they leave the store behind, or set its manifest aside.
2. **An optional source in the cohort gateway** (`RetainedFirstSync` in `tools/native_cohort_service.py`) over one fixed directory. No store, or a store that cannot be read, is answered as "no mirror" on the first page of a sync, which sends the wallet down the block-by-block path it used before. A store that appears later is picked up without a restart. A page that continues a sync is refused rather than answered from anything else.
3. **Compact pages are charged at the compact rate**, 256 headers a unit and never less than one unit per 64 KiB, an existing option of the gateway. At the default 16 headers a unit a full page costs 2,048 units and a sync fails at the per-minute limits after a few pages.

Not chosen: passing the store to the gateway's existing `history_root` argument. The gateway would refuse to start without a store, never notice a later one, and turn every store error into a failed sync with no fallback.

## What this does not change

The wallet trusts exactly what it trusted before. On both paths it takes the finalized pool account, the finalized header and the blocks from the gateway, and on both it verifies block continuity, every payment's signatures and proof, and that its replay ends on the finalized header with a pool equal to the finalized pool account. The collector's verification and the store's checksums protect the operator from serving a wrong store; the wallet relies on neither. A dishonest gateway can do on the mirror path what it could already do: refuse or fail a sync, answer with an older consistent state, or present a history the validators did not finalize if it can build one from valid payments. It still cannot make a wallet count a payment that does not verify, drop or alter a payment under the true pool, or end the history on another block. Retained blocks are never evidence that one particular payment executed; a wallet with a pending payment does not use them. The full account is in [the runbook](../first-sync-mirror-runbook.md#what-the-wallet-verifies-and-what-it-takes-from-the-gateway).

## Limits accepted

- **256 MiB a store** (`history_retention.STORE_BUDGET`). The collector stops extending the store at about 1.05 to 1.1 million blocks; the mirror stays served and the tail read block by block grows again. Raising it means changing that constant, which the gateway reads, together with the collector's configuration.
- **16,384 segments.** Every collection adds a partly filled segment: about four weeks at a 300 s interval.
- **The whole store is replayed and copied on every collection.** 11 s at 200,310 blocks and 24 s at 1,000,000 on a workstation. The collector binary must complete an empty block without recomputing the note-tree root; one that does not costs about 13 ms a block and cannot keep up.
- **A store that differs from the chain fails first syncs** until it is moved aside or the collector sets its manifest aside. Hence one operator rule: if the chain is ever restored to anything other than its own last stopped state, move the store aside before the gateway starts.

## Measured

In a local rehearsal on a workstation, loopback only, with the browser wallet's worker and WebAssembly engine under Node.js, the unchanged gateway handler and reader, a node stand-in and a generated chain with 250 real payments: a first sync took 47 s at 200,310 blocks and 67 s at 1,000,000, and the same wallet's next sync 1.8 s. Not measured: a browser on the public network path with the mirror. Conditions and the other figures are in [the runbook](../first-sync-mirror-runbook.md#measured).

## Not decided here

The value of a larger store budget, a store format that does not need a whole replay per collection, a fallback in the wallet when retained pages fail verification, and replication of the store.
