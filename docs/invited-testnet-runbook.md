# Local invitation admission rehearsal

Keep raw validator RPC and gossip on operator-loopback. The gateway and faucet below are also loopback-only. The [local TLS/isolation runbook](tls-rpc-isolation-runbook.md) adds HTTPS and raw RPC capabilities. Public TLS, firewall routing, independent validator hosting and operational release review remain deployment work; no external hosting or invitations are created by this procedure.

Use a **new** pre-funded faucet root following the [test distribution runbook](test-faucet-runbook.md). Its source profile points directly to operator RPC, has `invite_required` omitted/false, and uses a dedicated reservoir seed. Never point the worker at its own invited gateway. Preserve that source profile and all original budgets/journals.

Create a second public tester profile with the same network/genesis and:

```json
{
  "rpc": {"transport": "loopback-http", "url": "http://127.0.0.1:18898"},
  "faucet": {"transport": "loopback-http", "url": "http://127.0.0.1:8780"},
  "invite_required": true
}
```

These are fields within the complete validated public profile, not a standalone profile. The packaging tool adds them with `--invite-only --rpc http://127.0.0.1:18898 --faucet http://127.0.0.1:8780 --transport loopback-http`. No codes, admission ledger, source seed or server executable enter the package.

Before any claim, enable admission:

```sh
target/debug/native-faucet access-init --root .data/new-invited-faucet \
  --profile invited-profile.json --daily-admissions 3 --rpc-limit 2000
```

Daily admissions must fit the original faucet lifetime capacity. This setup refuses an existing admission ledger or any existing claim. A partial setup is deliberately closed: preserve the original files for operator recovery, never delete its permanent marker or reinitialize a funded seed.

Issue a code to a **new owner-only output file**; stdout contains only its hashed identity and expiry:

```sh
target/debug/native-faucet invite-issue --root .data/new-invited-faucet \
  --output private-invitation.json --expires-in 86400
```

Use `--bind-fee <tester-fee-address>` when that wallet authority is known. Otherwise anyone holding the unused code can redeem it first. The output contains the code and must be kept out of logs, URLs, Git, screenshots and bug reports. This local-only task does not send invitations. Revocation uses the nonsecret `invite_id` returned at issuance:

```sh
target/debug/native-faucet invite-revoke --root .data/new-invited-faucet \
  --invite-id <hashed-invitation-id>
```

Start the worker/admission service and separate RPC gateway with the original owner-only source password file:

```sh
python3 -B tools/test_faucet.py --root .data/new-invited-faucet \
  --password-file <private-file> --port 8780
python3 -B tools/testnet_gateway.py --root .data/new-invited-faucet \
  --password-file <private-file> --port 18898
```

The gateway checks upstream genesis before listening. Raw validator RPC must remain inaccessible to testers outside the gateway. A client profile is a pin, not a firewall. In a remote deployment HTTPS termination, Host forwarding and socket-peer accounting require explicit validation: these loopback services intentionally ignore forwarded-IP headers. Do not assume the local tests prove public network isolation or protection against a distributed flood.

Wallet flow: create → save/confirm encrypted recovery → **Join testnet + get test coins** → fixed grant finalization → user-paid private sends. **Check existing access** recovers an admitted seed without a code. Receive, encrypted recovery and offline key restoration remain available before admission. Restoring does not recreate a grant or replenish budgets. The CLI offers `join --invitation-file <private-file>` and `access-status`; password input remains bounded stdin/private input. The invited `--check` handshake verifies genesis only; pool/history checks require unlocking an admitted wallet.

On crash, restart the same services and roots with the original ledgers, seed and pending/staging/outcome records. Redemption saved before a missing grant reservation is completed by the same wallet's retry. Codes cannot be redeemed for a second wallet. Revocation/expiry denies new protected RPC and claim operations; accepted grant obligations still recover normally. An exhausted minute/day limit waits for its actual next time boundary. Restarting, restoring a seed, reissuing a package or adding reservoir funds does not reset limits. If clocks move backwards, fix the operator clock and preserve state.

Repeatable fresh-root acceptance:

```sh
python3 -B tools/invite_localnet.py --root .data/new-invite-check \
  --evidence <new-private-evidence-directory> \
  --browser-script <temporary-playwright-script> \
  --playwright-module <cached-playwright-module>
```

This creates private rehearsal keys, funds one finite reservoir, disables operator sponsor material after setup, uses two real validators, races code redemption, tests rejection/quotas/revocation and service/validator recovery, then verifies actual browser admission and a native private send. It refuses existing roots unless one of the explicitly named narrow failed-checkpoint guards validates the original state; completed evidence cannot be resumed. It never automatically repeats a failed value operation. Evidence and original journals are preserved even on failure. See LOCAL-017 for the accepted run and limits.

### First-sync history reads

Updated invited wallets use `getWalletHistoryBlocks` on the invited gateway: `params` is one strictly increasing list of 1–16 positive slot numbers. The gateway permits only full, base64, finalized `getBlock` reads with transaction version 0 and an aggregate response bound of 16 MiB. It does not accept general JSON-RPC batches or caller-supplied upstream methods/configuration. Update the gateway before distributing this wallet version; older invited gateways fail clearly instead of silently skipping verification. Direct operator/ordinary RPC profiles retain single-block reads.

Each history RPC consumes one original member/global RPC request unit, just like other bounded RPC methods. Each incoming HTTP request consumes one original ingress unit, including malformed or unauthorized requests. The native admission implementation and stored policy schema are unchanged. The history method has an independent fixed 16-block, 16-MiB and 15-second work bound; it cannot include writes or arbitrary methods. Request counters are durably committed before upstream work; a failed read can consume its reserved units. Limits, revocation, proof expiry, ledger locking and restart persistence are unchanged. A 429 response supplies a bounded `Retry-After` until the next quota minute; the wallet's existing native HTTP sender honors it. No authorization decision or quota is cached in memory.

The wallet still checks every requested slot, block-parent/hash continuity, complete transaction data and payment proofs, then reconciles with the finalized pool before publishing its authenticated cache. `sync` reports `block_rpc_requests`, `fetch_ms`, `replay_ms` and `setup_ms` alongside block/proof counts. The UI separates access checks from finalized-history verification and shows elapsed time rather than an estimated percentage. First sync still scales with retained chain history and may pause at existing request limits; this is not a trusted history index or an independent consensus proof.

### Retention before invitations

The dedicated local service now collects and mirrors verified history automatically, with admission closed until initial success and a validator pause on later retention failure. See the [recovery-history runbook](recovery-history-runbook.md). The current gateway can serve retained ciphertext pages to updated wallets separately from canonical RPC. Keep complete canonical RPC history for ambiguous historical payment outcomes; retained metadata does not prove inclusion or absence. Same-disk mirrors do not cover host loss; off-host backup, alerting and hosted ingress remain release gates.

### Retained history pages

`getWalletRetainedHistory` takes exactly `[after_slot, target_slot, checkpoint_or_null]`. The first request uses null; subsequent requests reuse the returned checkpoint and next slot until complete. The result identifies the network, immutable descriptor-prefix checkpoint, retained tip, bounded through/next slots, completion flag and compact native-history blocks. Each page has at most 16 blocks and 16 MiB with a shared 15-second deadline. It uses one original authorized RPC request unit plus the ordinary ingress charge, including denied ingress. There is no new quota policy, cached authorization, token/session issuance or arbitrary filesystem route.

The checkpoint hashes canonical descriptor-prefix JSON and its network, with the segment count. A gateway restart can reconstruct it from a later append-only mirror. Interrupted/uncommitted payloads are not served. A changed prefix, wrong network, missing/corrupt file, unsafe ownership/symlink or bound violation denies the page. Requests cannot supply an upstream URL or history path. The operator may add `--history <owner-only-mirror>` to `testnet_gateway.py`; the dedicated v4 service always supplies its fixed `recovery-history-mirror`.

Deploy the updated gateway before using the updated wallet binary. An old invited gateway fails with an update-required error. A gateway with no configured history, or an initial empty archive, returns null and the wallet tries complete canonical RPC. On a new device the wallet replays retained signatures/proofs, reads the recent canonical suffix and checks the live finalized header and full pool before saving its encrypted checkpoint. A valid checkpoint uses recent canonical RPC directly. No history directory is copied to the tester.

Ordinary `getBlock/getBlocks/getTransaction/getSignatureStatuses/getBlockHeight` are unchanged. Checkpoints remember canonical coverage; old checkpoint provenance is unknown. Retained records supply neither canonical signature receipts nor absence. Unknown outcomes try a complete canonical scan without the retained endpoint; when unavailable the original pending record stays blocked. See LOCAL-027.

## Canonical archival pending recovery

The updated gateway also supports `getWalletCanonicalHistory` for old pending payments. Configure its fixed full-history validator with `--archive-rpc http://127.0.0.1:<raw-port>`; tester requests cannot choose or override it. The v5 dedicated service uses its existing full-history primary at port 23899 through the private Unix socket. A separate snapshot-only primary can instead use a full-history archive validator. This lane does not manufacture canonical data from the retained mirror and is not an independent archive replica by itself.

Each request is `[after_slot, target_slot, anchor_or_null]`. A first page starts at zero; continuations carry the exact returned `{slot, blockhash, block_height}`. Each page checks archive genesis and matches the primary and archive finalized target header, returning at most 16 full blocks within 16 MiB/15 seconds. The wallet verifies continuity, native signatures/proofs, the primary target header and pool. Existing invitation/revocation and durable quota checks apply to every page. No change to the public wallet profile or operator credential export is required.

`resolve` requests this lane only when existing canonical evidence cannot settle the original pending payment. Full coverage can establish acceptance, canonical failure, or finalized expiry without execution. The exact saved staging identity and withdrawal recipient/amount/sponsor must match. On archive outage, pruning, changed anchor, incomplete bodies or inconsistent evidence, keep the original journals and retry recovery later. Do not send again or clear recovery files. Resolution itself broadcasts no payment; original upload rent cleanup remains a separate `reclaim` action. See [the trust model](decisions/0020-canonical-archival-recovery.md).

Repeat the finite snapshot/old-payment crash acceptance on a **new** short fixture root:

```sh
PYTHONPATH=tools RAYON_NUM_THREADS=2 nice -n 15 python3 tools/canonical_archive_localnet.py --root .data/c28-new
```

The runner retains evidence and journals and stops its owned validators in cleanup. It does not start or reset the installed service. Keep validators stopped outside these bounded tests.
