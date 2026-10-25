# Canonical archive operator runbook

This runbook describes bounded canonical capture and serving in the invited
gateway. It is a configuration and recovery reference; live gateway activation
and pruning of an existing ledger remain separate gates. The native exporter
candidate is described in
[LOCAL-094-README](../node/candidate/LOCAL-094-README.md).

A separate indexed full-metadata archive is described in
[LOCAL-095-README](../node/candidate/LOCAL-095-README.md). Its finite bounds are
not unbounded multi-year retention. It does not change the canonical SQLite
store, CLI, coverage semantics or activation instructions below. Metadata cannot
replace full transaction history for pending acceptance/absence. No
public-testnet or payment-speed claim follows.

## Fixed configuration and ownership

The gateway operator selects one real absolute local SQLite path. Requests
cannot select an archive path, upstream or network. The archive parent must
already exist, belong to the process UID and have mode `0700`; the database must
be a regular single-link file owned by that UID with mode `0600`. Symlinks,
unsafe ownership/permissions and a different network/genesis refuse. Python
3.11 or later is required for the stored-value SQLite limits.

These are options added to the gateway's separately reviewed launch
configuration, **not a complete command to run against the pilot**:

| Option | Meaning |
| --- | --- |
| `--archive-store /fixed/private/full-history.sqlite3` | Serve this store through the existing canonical history method. Without capture, reads do not create or repair it. |
| `--archive-capture` | Explicitly start one bounded writer using the existing gateway's primary transport. Requires `--archive-store`. |
| `--archive-capture-max-bytes 8589934592` | Database cap in bytes; default is 8 GiB. The lifecycle accepts 1 MiB through 1 TiB. This is not an automatic retention/deletion policy. |
| `--archive-rpc` | Alternative existing archive source; mutually exclusive with `--archive-store`. |

Capture retains a minimum **28 GiB free-space floor**, plus a conservative
batch/journal reserve, on the store filesystem. The CLI does not lower that
floor. Checks do not reserve disk against other processes. Reaching the cap or
floor stops the affected capture window safely; it never deletes old blocks.

The existing invitation admission, quotas, listener/TLS configuration and raw
RPC isolation remain required. No additional public listener or credential is
created. A filtered retained-history mirror configured with `--history` is
separate and cannot substitute for canonical full blocks.

## Capture, coverage and capacity

The CLI fixes capture to at most 16 complete blocks per transaction, 64 batches
per window, a 30-second window, a 6-second batch budget and a 1-second poll.
Each window pins a finalized target E from its fixed source. E cannot move
within that window. Subsequent windows resume from the validated committed
SQLite head H and may select a newer E. There is no arbitrary RPC retry within
a failed window; a later scheduled window is a new bounded attempt.

Only complete validated batches publish. Full transaction bodies, failed and
unrelated transactions, execution metadata and unknown JSON fields are retained
under the existing full-block RPC contract. Range, parent, height, network and
exact target checks are mandatory. A `bounded` result or a failed later batch
leaves only the earlier committed prefix authoritative.

A wallet page for target T may find T newer than H. With capture enabled,
`ensure_coverage(T, deadline)` wakes the worker and waits within the page's
original **15-second budget**. It verifies committed H with a short Reader and
closes that transaction before waiting, so the wait cannot hold a SQLite SHARED
lock against publication. Completed fsynced batches notify waiters. Real
progress can wake the next bounded window; stalled sources retain normal
polling. It checks committed coverage before requesting any wake: already-covered
pages cause no additional capture window or capture RPC reads. Every page still
checks T against a fresh primary header and validates the exact continuation
anchor.

The budget includes catch-up and the page's fresh primary check. It is not a
promise that a large backlog can finish in 15 seconds. Expiry, stop,
corruption or a failed window before validated coverage returns an error; none may
be converted to an empty successful page. Without capture enabled, T greater
than H refuses immediately. H is never evidence that a payment is absent
beyond H. Request and response bounds remain 16 blocks per page, 8 MiB per
full block and 16 MiB per page.

Capture calls the already-bound `Gateway.forward`, sharing the gateway's global
two upstream permits with serving. There is no additional Operator or private
capacity bypass. Default archive reader capacity is two; excess concurrent
pages refuse immediately instead of joining an unbounded queue. Capture can
therefore contend with client reads; monitor lag and errors before increasing
load. The worker starts explicitly before request serving and closes on service
exit. If a transport ignores its timeout and bounded close fails, stop the
owning service; do not leave an orphan writer running.

## Crash and restart handling

The store uses SQLite rollback journals and FULL synchronization. A complete
commit is closed and fsynced before progress is reported. Process death before
commit leaves the old committed prefix; death after commit leaves the new one.
On the next **owned writer** invocation, the normal read/write open lets SQLite
recover an interrupted hot journal, then validates the recovered committed
state before capture continues. Do not delete the journal, replace the database
or infer coverage from an abandoned temporary state.

A read-only Reader cannot perform hot-journal recovery and refuses when that
recovery is required. This is expected. Keep the archive unavailable until the
single authorized writer has recovered it. Corrupt bodies, indexes, state,
network or anchors also refuse; they are not repaired or treated as missing.
After an ordinary restart, check network/genesis, committed H, exact target
header, a nonzero continuation and full old-payment evidence before declaring
recovery successful. Keep previous evidence and failures.

## Transferring a prepared store

To transfer a closed store, stop the capture writer and readers, confirm
their processes are gone, and let the owned writer finish any required journal
recovery before closing. Record the closed database's SHA256, size, exact
network/genesis and committed target/header. Preserve the original evidence.
Then place a verified copy at the fixed gateway-owned path, with parent `0700`
and database `0600`, owned by the gateway service UID. Recheck the exact byte
hash after transfer and ownership changes. Never copy a live SQLite database
or give the gateway access to validator keys to accomplish the transfer.

Under the reviewed service configuration, verify the same store as the gateway
service UID, invitation/denial/quota behavior, fresh target and continuation
checks, bounded catch-up, crash/restart recovery and the 28 GiB floor before
making it available to testers. Do not change the installed unit or enable
listeners on the basis of this document alone.

## Limits

Canonical data remains trusted operator RPC data. A checksum or three
co-located sources do not create an independent light-client proof. Neither
local tests nor archive coverage authorize pilot pruning, automatic cleanup,
deletion, consensus changes or a production retention rollout.
