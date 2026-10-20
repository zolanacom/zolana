# Fast, repeatedly spendable native private cash

The selected product is an independent privacy L1 and its native currency ZOL.
The concrete capability to demonstrate is receiving a private payment, verifying
successful final execution, then spending that received value again within a few
seconds. The payer's change must also be reusable. A warm, unlocked, synchronized
wallet has an engineering target of approximately three seconds per payment;
the isolated Agave 4.3.2 candidate now meets that target in three named Mac samples,
not a mobile guarantee or production consensus security claim.

The acceptance flow is Alice -> Bob -> Charlie, plus Alice spending her returned
change after an intervening payment updates the note tree. Each hop must measure
proof construction, admission, execution, certified finality, recipient discovery
and witness persistence. Report distributions under named devices, network
conditions and load. Pending display, zero-confirmation acceptance and a relay's
acknowledgement do not count as finality. A new network's security and liquidity
must be evaluated separately from its latency.

## Execution foundation

`protocol/payments/src/envelope.rs` frames a complete existing V3 shielded-fee
payment. The canonical two-action 9,230-byte payload becomes a 9,332-byte frame.
The frame has a fixed version/domain, exact network, signed expiry, canonical
payload identity and a total 16 KiB cap. The framing domain is not an additional
signature domain: existing V3 authorization already binds the genesis-committed
network domain (the actual genesis fingerprint is separately pinned), effects,
expiry, exact fee and relay payee. The payment identity remains the existing
canonical payload digest, including during recovery.

Native opcode 5, gated by `INLINE_PAYMENT_ACTIVATION_ID`, verifies the complete
frame and reuses the existing proof verification, backing, fee reimbursement and
permanent nullifier accounts. Both the inline and shielded-fee features must be
active. Accounts are exactly pool, signed relay payee, system program and two
proof-derived nullifier PDAs. No staging account is used for an inline payment.
Both ingress paths share the spent set, so crossing paths cannot spend twice.
Deposits and withdrawals retain the existing reviewed staging path.

This foundation alone is a Bank execution candidate. The preserved Agave 3.x
runtime's ordinary RPC, TPU and ledger admission still enforce the 1,232-byte
transaction bound. Bank execution tests intentionally
bypass that admission layer and explicitly verify network admission rejects the
large transaction. The new feature is not activated in the existing localnet
builder or any installed service. No existing genesis or ledger is migrated.

Wallet history replay recognizes complete inline instructions, verifies their
proofs and reconstructs notes, fees and nullifiers. Only canonically sourced,
successfully replayed payments produce recovery receipts. Retained ciphertext
history alone cannot assert canonical execution. Existing encrypted snapshot
fields remain unchanged; incremental Merkle branches are rebuilt from their
authenticated leaves on restore. Warm witnesses read and hash 32 siblings instead
of rebuilding the entire tree for each spend. Retained history, memory and cold
restore remain proportional to history; this change does not prune them.

## Slot anchors and explicit activation

The preserved NPOOL003 format retains 64 roots per payment and remains unchanged
for compatibility. The candidate activates an explicit NPOOL004 format only in fresh
isolated candidate genesis. Bank freeze seals the end-of-produced-slot root
before hashing, including empty produced blocks. Roots are aged by 512 execution
slots; intermediate roots and invented checkpoints for skipped slots cannot
authorize spends. Wallets replay the same complete-block seals. There is no
silent old-pool rewrite or installed-ledger migration.

## Validated isolated network candidate

The [candidate](../../node/candidate/README.md) ports native execution to separately pinned
Agave 4.3.2 with actual upstream Alpenglow and unchanged safety thresholds. Bounded
loopback native ingress admits only the exact feature-gated Legacy payment shape.
Every proof byte remains in the transaction, standard shreds, blockstore and
follower replay. Ordinary global transaction size limits stay unchanged.

Three co-located Linux validators finalized and recorded the same private
payments, including immediate recipient and change reuse. Actual original-ledger
SIGKILL recovery, quorum loss/rejoin and full snapshot recovery preserved native
accounting and permanent nullifiers. A real free-rent test exposed zero-lamport
spent markers being purged; markers now carry at least one unit and wallet
accounting agrees.

The separate Mac client durably journals exact packets before submission. It
requires successful finalized canonical history, verified note discovery and
separately encrypted sender/recipient checkpoints before clearing an intent.
Bounded concurrent admission and independent scans reduce WAN overhead. Three
warm Mac-to-Linux samples with four proving threads measured 2,679 / 2,765 /
2,662 ms through durable recipient readiness. Connection loss, client SIGKILL
and backup replay passed. This is a named low-load development topology with
trusted RPC observation; it is not independent light-client finality verification,
a latency distribution or a production security result.

## Work before promoting the candidate

1. Independently review cryptography, native authorization/accounting, admission,
   slot-seal integration and the pinned validator/consensus changes.
2. Integrate reviewed native ingress with the invited TLS gateway, service-UID
   isolation, funding controls and real delivered wallet; current installed
   runtime and UI bindings remain preserved.
3. Implement authenticated light-client execution/finality evidence if removing
   trusted RPC is part of the supported wallet threat model. Generic bank hashes
   alone do not provide that capability.
4. Test multiple independent operators, validator-set changes, actual receiving
   devices/mobile, packet faults and sustained/adversarial load. Record throughput,
   cold recovery and latency distributions separately from warm send samples.
5. Review production parameters, economics, relay behavior, history retention,
   upgrade/migration and recovery operations before a public pilot.

ZOL remains the only implemented payment asset. SOL/USDC backing and bridging,
private staking, private application execution and post-quantum migration are
separate work. The relay payee, exact fee and timing remain public; ingress can
observe admission identity and network metadata. No broader anonymity or audited
security claim follows from this iteration.
