# Shielded payment protocol: the formats and rules the code implements

This document describes the shielded-payment protocol as the code in this repository implements it: every byte of every encoding, the state the validator keeps, the rules that change that state, and the limits. It is written so that a reviewer can check the code against a statement, and so that a second implementation can be written from it and checked against the [test vectors](../protocol/payments/tests/vectors/README.md).

It describes what exists. It makes no statement about what the protocol will become. The encodings are experimental (`protocol/payments/src/wire.rs:1` says "This format is not a released protocol"), every amount and limit is a development parameter, and nothing here has been reviewed by anyone outside the project. Where the code is ambiguous, surprising or inconsistent, this document says what the code does and lists the point in [section 15](#15-open-questions-and-observations) instead of choosing an interpretation.

## Contents

1. [Scope and sources](#1-scope-and-sources)
2. [Conventions](#2-conventions)
3. [Overview](#3-overview)
4. [Cryptographic components](#4-cryptographic-components)
5. [Payment encoding](#5-payment-encoding)
6. [Authorization digest](#6-authorization-digest)
7. [Payment verification](#7-payment-verification)
8. [Pool account](#8-pool-account)
9. [Anchors](#9-anchors)
10. [Nullifier markers](#10-nullifier-markers)
11. [Staging](#11-staging)
12. [Envelope](#12-envelope)
13. [Native program](#13-native-program)
14. [Test vectors](#14-test-vectors)
15. [Open questions and observations](#15-open-questions-and-observations)
16. [Statements elsewhere that differ from the code](#16-statements-elsewhere-that-differ-from-the-code)
17. [What this document does not cover](#17-what-this-document-does-not-cover)

Appendices: [A. Constants and limits](#appendix-a-constants-and-limits), [B. Domain separation](#appendix-b-domain-separation), [C. Errors](#appendix-c-errors).

## 1. Scope and sources

The specification is taken from two crates of the workspace:

- `protocol/payments` (`native-payments`): encodings, the authorization digest, verification, pool state, anchors, staging and the envelope. Below, a bare file name such as `wire.rs` means `protocol/payments/src/wire.rs`.
- `node/adapter` (`native-payment-program`): the native program that executes payments inside the validator. Below, `adapter/` means `node/adapter/src/`.

References have the form `file:line`. Decision records are cited by number, as in "decision 0004", and live in `docs/decisions/`.

**Two code lines.** The repository contains a second copy of both crates inside `node/candidate/agave-4.3.2.patch`, which the Agave 4.3.2 candidate builds. This document specifies the workspace crates. The rule by which a payment against an `NPOOL004` pool selects its anchors is in both copies of the native program. Two things it depends on exist only in the candidate: the feature that makes such a pool usable, as something a runtime can activate, and the completion of a slot at the end of a block. They are described in [section 9.4](#94-how-the-candidate-uses-slot-checkpoints) with references into the patch file and are marked as such. A comparison made for this document of the files that the base patch adds under `zolana-native/protocol/src` with `protocol/payments/src` found `anchors.rs`, `staging.rs` and `verification.rs` identical; `wire.rs`, `envelope.rs` and `lib.rs` different only in visibility, derived traits and comments; `state.rs` different in the body of slot completion and in tests; and no `native_accounts.rs`. The workspace's `state.rs` has since gained two rules that the candidate's copy does not have, rule 8 of [section 8.4](#84-decoding-npool004) and the empty-leaf rule of [section 8.5](#85-applying-a-payment); a patch that adds them to the copy is proposed in `node/candidate/drafts/pool-state-hardening/` and is not part of the reconstruction plan. The later patches of the series contain no change under `zolana-native/protocol` or `zolana-native/adapter`. The adapter copies were not compared for this document beyond the differences listed in section 15; [decision 0043](decisions/0043-one-protocol-copy.md) records a comparison of the two programs by running them side by side. `tools/protocol_copy_guard.py` compares both pairs of copies file by file against a reviewed record of their differences (`node/candidate/README.md`).

**Versions.** The formats carry their own version tags: `NPAY0001`, `NPAY0002`, `NPAY0003` (payments), `NPOOL003`, `NPOOL004` (pool), `ZOLANCH1` (checkpoint history), `NBUF0001` (staging account), `NSPENT01` (nullifier marker), `ZOLNPAY1` (envelope). `PROTOCOL_VERSION` is 1 (`verification.rs:13`). The Orchard dependency is pinned to version `=0.16.0` in the workspace `Cargo.toml`.

## 2. Conventions

- All integers are little-endian. `u16`, `u32`, `u64` are unsigned; `i64` is two's complement.
- Offsets and sizes are in bytes and count from zero. A range `a..b` includes `a` and excludes `b`.
- Text in quotation marks, such as `"NPAY0001"`, is the ASCII bytes of that text with no terminator.
- **Amounts** are in base units of the native coin, the unit the runtime calls a lamport.
- **Slot** is the slot of the bank that executes the transaction, read from the Clock sysvar (`adapter/processor.rs:52`). No rule uses wall-clock time.
- **Network domain** is a 32-byte value stored in the pool account and fixed at genesis. It is not the genesis hash (decision 0003). It must not be all zero. The code names it `genesis` in some signatures and `network` in others; they are the same value.
- **Field element** means an element of the Pallas base field, encoded as 32 bytes little-endian. An encoding is *canonical* when its value is below the modulus `p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001`. Every field element in these formats must be canonical.
- **Point** means a point of the Pallas curve `y^2 = x^3 + 5`, encoded as 32 bytes: the x-coordinate little-endian with the top bit of the last byte holding the parity of y. Thirty-two zero bytes encode the identity. An encoding is valid when the x-coordinate (top bit cleared) is canonical and either all 32 bytes are zero or `x^3 + 5` is a square in the field.
- **BLAKE2b-256(personalization, data)** is BLAKE2b with a 32-byte output, no key, no salt and the given 16-byte personalization.
- A rule written "X, else `E`" means the code returns error `E` when X does not hold. Rules in a numbered list are applied in that order; the first failure is the result.

## 3. Overview

### 3.1 Objects

| Object | Where it lives | What it is |
| --- | --- | --- |
| Pool account | One account at a fixed program-derived address, owned by the native program | Network domain, rent floor, backing, the frontier of the note commitment tree, and the roots a payment may use as its anchor |
| Note | Nowhere in public state | A shielded amount owned by an Orchard address. Only its commitment enters the tree; its contents travel encrypted in the payment that creates it |
| Note commitment | Leaf of the tree | 32 bytes per created note, appended in order |
| Nullifier | A marker account per nullifier | 32 bytes revealed when a note is spent. The marker account makes a second spend fail |
| Anchor | Field of a payment | A past root of the tree, against which the payment proves that its spent notes exist |
| Payment | Bytes in a staging account or in an instruction | Two Orchard actions, a proof, signatures and a public context |
| Sponsor | A System-owned public account that signs the transaction | Pays transaction fees and account rent; source of a deposit; destination of a fee reimbursement |

### 3.2 Kinds of payment

Every payment has exactly two actions. Each action spends one note and creates one note; an action that has nothing real to spend or create uses a zero-value dummy. The public effect is one signed number, the *public value balance*:

| Public value balance | Tag | Meaning | Public movement |
| --- | --- | --- | --- |
| negative | `NPAY0001` | Deposit | That amount moves from the sponsor's account into the pool |
| zero | `NPAY0001` | Private send | None |
| positive | `NPAY0001` | Withdrawal to the sponsor | That amount moves from the pool to the sponsor's account |
| positive | `NPAY0002` | Withdrawal to a bound recipient | That amount moves from the pool to the recipient account named in the payment |
| positive | `NPAY0003` | Private send with a shielded fee | That amount, equal to the stated fee, moves from the pool to the sponsor's account |

The tag is not a free label: it selects the layout, the personalization of the authorization digest and the feature gate ([section 13.2](#132-feature-gates)).

### 3.3 Two ways a payment reaches the program

- **Staged.** The payment bytes are written in chunks into a staging account by several transactions, sealed against a digest, and then executed by a small *finalize* instruction ([section 11](#11-staging)). All three tags can be staged.
- **Inline.** The payment bytes travel inside one instruction, wrapped in an envelope ([section 12](#12-envelope)). Only `NPAY0003` payments can be inline.

Both paths end in the same finalization ([section 13.5](#135-finalization)) and share the same nullifier markers.

### 3.4 What a payment shows and what it does not contain

A payment's bytes are public. They contain: the tag, the network domain, the expiry slot, the public value balance, the sponsor's key, the fee (`NPAY0003`) or the recipient's public address (`NPAY0002`), the anchor, both nullifiers, both randomized spend keys, both new note commitments, the ephemeral keys, the ciphertexts, the value commitments, the proof and the signatures. The transaction that carries it also shows its fee payer, its timing and the accounts it names.

A payment's bytes do not contain, in the clear: which earlier commitments it spends, the shielded address of a recipient, the value of any note, or a memo. Those appear only inside the Orchard ciphertexts and behind the proof. A deposit and a withdrawal state their amount and a public account; a private send states neither amount nor counterparty; an `NPAY0003` payment states its fee and the account reimbursed. The two-action shape is the same for every payment. The anchor tells an observer which recent state of the tree the sender had seen.

What an observer of the network, of a gateway or of a relay can learn beyond the bytes is outside this document; see [privacy-boundary.md](privacy-boundary.md). This document makes no claim about the strength of the properties above: they rest on the Orchard construction and on this integration of it, and neither has had an independent review in this repository.

## 4. Cryptographic components

The project does not define a circuit. It uses the `orchard` crate, version 0.16.0, unchanged:

- **Bundle version** `BundleVersion::orchard_v2()` (`verification.rs:18-20`): the Orchard pool with the circuit that crate calls `FixedPostNu6_2`. A verifying key of any other circuit version is refused (`verification.rs:131-133`).
- **Flags**: the default flags of that version, spends enabled and outputs enabled, encoded as the byte `0x03`.
- **Proof**: a Halo 2 proof for two actions, 7,264 bytes (`Proof::expected_proof_size(2)`).
- **Signatures**: RedPallas. One spend authorization signature per action under that action's `rk`, and one binding signature under the bundle's binding validating key.
- **Note encryption**: Orchard's, with 580-byte note ciphertexts and 80-byte outgoing ciphertexts.
- **Tree hash**: Orchard's `MerkleCRH`, a Sinsemilla hash, over a tree of depth 32 ([section 8.2](#82-the-note-commitment-tree-and-its-frontier)).

The project's own definitions, which the following sections specify, are: the payment encoding; the authorization digest and what it adds to Orchard's bundle commitment; the fixed two-action shape; the mapping of the bundle's value balance to a public movement of coins; the fee and recipient contexts; the pool state and its anchors; the nullifier accounts; staging and the envelope.

The verifying key is built in the process from the circuit (`adapter/processor.rs:16-17`); there is no parameter file.

## 5. Payment encoding

Source: `wire.rs`. One payment is one of three layouts, selected by its first eight bytes.

### 5.1 Layout

`X` is the size of the tag-specific field: 0 for `NPAY0001`, 32 for `NPAY0002`, 8 for `NPAY0003`.

| Offset | Size | Field | Contents |
| --- | --- | --- | --- |
| 0 | 8 | tag | `"NPAY0001"`, `"NPAY0002"` or `"NPAY0003"` |
| 8 | 32 | network | Network domain |
| 40 | 8 | expires_at | `u64`: last slot in which the payment may execute |
| 48 | 8 | public_value_balance | `i64` |
| 56 | 32 | sponsor | Public key of the sponsor account |
| 88 | X | | `NPAY0002`: withdrawal_recipient, a 32-byte public key. `NPAY0003`: shielded_fee, a `u64`. `NPAY0001`: nothing |
| 88 + X | 32 | anchor | Field element |
| 120 + X | 1 | flags | `0x03` |
| 121 + X | 1 | action count | `0x02` |
| 122 + X | 884 | action 0 | See below |
| 1,006 + X | 884 | action 1 | |
| 1,890 + X | 4 | proof length | `u32`, the value 7,264 |
| 1,894 + X | 7,264 | proof | |
| 9,158 + X | 64 | binding signature | |

Total size: 9,222 bytes for `NPAY0001`, 9,254 for `NPAY0002`, 9,230 for `NPAY0003`. `HEADER_BYTES` is 122 and `ACTION_BYTES` is 884 (`wire.rs:26-28`).

One action:

| Offset in action | Size | Field | Contents |
| --- | --- | --- | --- |
| 0 | 32 | nullifier | Field element: the nullifier of the note this action spends |
| 32 | 32 | rk | Point: the randomized spend validating key |
| 64 | 32 | cmx | Field element: the commitment of the note this action creates |
| 96 | 32 | epk | Point: the ephemeral key of the note encryption |
| 128 | 580 | enc_ciphertext | Encrypted note |
| 708 | 80 | out_ciphertext | Encrypted outgoing data |
| 788 | 32 | cv_net | Point: the value commitment |
| 820 | 64 | spend authorization signature | |

### 5.2 Decoding

`wire::decode(network, bytes)` (`wire.rs:106-213`) applies these rules in order:

1. Compute `X` from the first eight bytes: 32 if they are `"NPAY0002"`, 8 if they are `"NPAY0003"`, otherwise 0. The length must be exactly `9,222 + X`, else `InvalidLength`.
2. The tag must be one of the three, else `UnsupportedVersion`.
3. The caller's network domain must not be zero and must equal the network field, else `WrongNetwork`.
4. `NPAY0003`: the fee must not be zero, must not exceed `2^63 - 1`, and must equal the public value balance, else `InvalidContext`.
5. The sponsor must not be zero, else `InvalidContext`.
6. `NPAY0002`: the recipient must not be zero and the public value balance must be positive, else `InvalidContext`.
7. The anchor must be a canonical field element, else `InvalidEncoding`.
8. The flags byte must be `0x03` and the action count must be 2, else `InvalidShape`.
9. For each action in order, else `InvalidEncoding`: the nullifier and `cmx` must be canonical field elements; `rk` must be a valid point encoding and not the identity; `epk` must be a valid point encoding and not the identity; `cv_net` must be a valid point encoding (the identity is accepted).
10. The proof length field must be 7,264, else `InvalidLength`.

Decoding does not examine: the ciphertexts, the bytes of the proof, the bytes of any signature, whether the two nullifiers differ, the sign of the public value balance of an `NPAY0001` payment, or the expiry. Those are matters for verification and execution. A decoded payment is not a verified payment.

The encoding is canonical: an accepted byte string is the only encoding of its contents, and `wire::encode` of a decoded payment returns the same bytes. There is no padding and no optional field other than the one the tag selects.

### 5.3 Encoding

`wire::encode(network, context, bundle)` (`wire.rs:36-104`) chooses the tag from the context: `NPAY0003` when a shielded fee is present, otherwise `NPAY0002` when a withdrawal recipient is present, otherwise `NPAY0001`. A context cannot carry both (`verification.rs:34-45`). It refuses, before writing anything: a context that rule 4 or 6 above would refuse, a zero network domain or a zero sponsor (`InvalidContext`); a bundle of another version (`UnsupportedVersion`); a bundle that does not have two actions, the default flags and a 7,264-byte proof (`InvalidShape`); a bundle whose value balance differs from the context's public value balance (`WrongValueBalance`).

## 6. Authorization digest

Source: `verification.rs:67-115`. Every signature in a payment is made over one 32-byte digest. The digest is what ties the Orchard bundle to this network and to the public context.

### 6.1 Bundle commitment

The digest contains Orchard's commitment to the bundle's effects, computed by the `orchard` crate as `bundle.commitment(TxVersion::V5)`. In terms of the payment bytes ([section 5.1](#51-layout)):

```
compact     = BLAKE2b-256("ZTxIdOrcActCHash",
                for each action: nullifier || cmx || epk || enc_ciphertext[0..52])
memos       = BLAKE2b-256("ZTxIdOrcActMHash",
                for each action: enc_ciphertext[52..564])
noncompact  = BLAKE2b-256("ZTxIdOrcActNHash",
                for each action: cv_net || rk || enc_ciphertext[564..580] || out_ciphertext)
commitment  = BLAKE2b-256("ZTxIdOrchardHash",
                compact || memos || noncompact || flags || public_value_balance || anchor)
```

`flags` is the one byte `0x03`, `public_value_balance` the eight bytes of the `i64`, and each "for each action" concatenates action 0 then action 1. The vector test computes these four values from the payment bytes in this way and requires the result to equal the crate's.

### 6.2 Digest

```
digest = BLAKE2b-256(personalization,
           network || protocol_version || commitment || expires_at ||
           public_value_balance || sponsor || [shielded_fee] || [withdrawal_recipient])
```

- `protocol_version` is the `u32` value 1.
- `shielded_fee` (8 bytes) is present only for `NPAY0003`; `withdrawal_recipient` (32 bytes) only for `NPAY0002`.
- The personalization is `"NativePayAuthV1!"` for `NPAY0001`, `"NativePayAuthV2!"` for `NPAY0002` and `"NativePayAuthV3!"` for `NPAY0003`.

In terms of the payment bytes, the input is `payment[8..40] || 01 00 00 00 || commitment || payment[40..88 + X]`: 116, 148 or 124 bytes.

The function refuses a context that decoding would refuse, a zero network domain and a bundle of another version.

### 6.3 What is bound, and by what

| Value | Bound by |
| --- | --- |
| Network domain, protocol version, expiry, sponsor | The digest directly |
| Public value balance | The digest directly, and again inside the bundle commitment |
| Shielded fee, withdrawal recipient | The digest directly; and the choice of personalization fixes which of them exists |
| Nullifiers, `rk`, `cmx`, `epk`, ciphertexts, `cv_net`, flags, anchor | The digest, through the bundle commitment |
| The digest | Each action's spend authorization signature, valid under that action's `rk`; and the binding signature, valid under the binding validating key |
| Anchor, `cv_net`, nullifier, `rk`, `cmx`, the two enable flags | The proof, as the public inputs of each action |
| The sum of the two `cv_net` against the public value balance | The binding validating key, which is that sum less a commitment to the public value balance with zero randomness |

Consequences that follow from the construction and that the vectors exercise:

- Changing any byte of the context or of an action makes the digest different, so the spend signatures no longer verify (`InvalidSpendAuthorization`).
- A payment cannot be moved to another tag. Dropping the recipient of an `NPAY0002` payment or the fee of an `NPAY0003` payment and relabelling it `NPAY0001` yields bytes that decode, and a digest under another personalization.
- A payment for one network domain does not decode under another (`WrongNetwork`), and its digest differs.
- The proof bytes and the signature bytes are not inputs of the digest. Two payments can have the same effects and different bytes. What prevents the second from executing is the nullifier markers, not the digest ([section 10](#10-nullifier-markers)).

What the proof establishes about the hidden values (that a spent note exists under the anchor, that the nullifier belongs to it, that the value commitment is honest, that `rk` derives from the note's spend key) is the Orchard Action statement, which this document does not restate. The project's addition is the digest: the proof alone does not mention the network, the expiry, the sponsor, the fee or the recipient.

## 7. Payment verification

Source: `PaymentVerifier::verify`, `verification.rs:139-207`. Verification reads no state of its own. The caller supplies a view (`verification.rs:49-56`): the current slot, the set of accepted anchors, a set of spent nullifiers, and the public value balance that the caller is prepared to move.

The checks, in order:

1. The bundle has the pinned version, else `UnsupportedVersion`.
2. It has two actions, a 7,264-byte proof and the default flags, else `InvalidShape`.
3. `expires_at >= current_slot`, else `Expired`.
4. `expires_at - current_slot <= 1,024`, else `InvalidContext`.
5. The bundle's value balance equals the context's public value balance, and that equals the authorized public value balance of the view, else `WrongValueBalance`.
6. The anchor is in the accepted set, else `UnknownAnchor`.
7. The two nullifiers differ, else `DuplicateNullifier`.
8. Neither nullifier is in the spent set, else `SpentNullifier`.
9. Each action's spend authorization signature verifies under its `rk` over the digest of [section 6](#6-authorization-digest), else `InvalidSpendAuthorization`.
10. The binding signature verifies over the same digest, else `InvalidBindingSignature`.
11. The proof verifies, else `InvalidProof`.

The cheap checks precede the proof. A payment is therefore accepted in exactly the slots `expires_at - 1,024` to `expires_at`, both included: 1,025 slots.

The result (`verification.rs:58-63`) is the two nullifiers in action order, the two commitments in action order, and the public value balance. Nothing else leaves verification; the pool transition of [section 8.5](#85-applying-a-payment) consumes exactly this.

How the native program fills the view is stated in [section 13.5](#135-finalization): it passes an empty spent set and checks the marker accounts itself, and it passes the payment's own public value balance as the authorized one and then moves exactly that amount.

## 8. Pool account

Source: `state.rs`. The pool is one account. Its address is derived from the program ([section 10.1](#101-addresses)); it is created at genesis, owned by the native program, and no instruction creates, replaces or closes it (decision 0003). Two formats exist. A pool is created in one of them and is never converted (`state.rs:48`).

### 8.1 Layout

Both formats begin with the same 64 bytes:

| Offset | Size | Field | Contents |
| --- | --- | --- | --- |
| 0 | 8 | tag | `"NPOOL003"` or `"NPOOL004"` |
| 8 | 32 | network | Network domain, not zero |
| 40 | 8 | rent_floor | `u64`: lamports the account keeps beyond its backing |
| 48 | 8 | backing | `u64`, at most `2^63 - 1`: coins held for the notes |
| 56 | 8 | note_count | `u64`: commitments in the tree; even; at most 4,294,967,294 |

`NPOOL003`, 3,137 bytes (`STATE_BYTES`, `state.rs:17`):

| Offset | Size | Field | Contents |
| --- | --- | --- | --- |
| 64 | 1 | root_count | 1 to 64 |
| 65 | 32 × 32 | frontier | Level 0 first |
| 1,089 | 64 × 32 | recent roots | `root_count` roots, oldest first, the present root last; zero bytes after them |

`NPOOL004`, 25,728 bytes (`SLOT_STATE_BYTES`, `state.rs:19`):

| Offset | Size | Field | Contents |
| --- | --- | --- | --- |
| 64 | 32 × 32 | frontier | Level 0 first |
| 1,088 | 4 | history_length | `u32`: size of the checkpoint history that follows, at most 24,636 |
| 1,092 | history_length | checkpoint history | The encoding of [section 9.2](#92-slot-checkpoint-history) |
| 1,092 + history_length | to 25,728 | padding | Zero bytes |

### 8.2 The note commitment tree and its frontier

The tree is a binary Merkle tree of depth 32 whose leaves are note commitments in the order payments create them. A position that holds no commitment yet holds the *empty leaf*, the field element 2. `empty_root(L)` is the root of a subtree of height `L` made only of empty leaves; `empty_root(0)` is the empty leaf and `empty_root(32)` is the root of the empty tree. All 33 values are in `pool.json`.

The parent of two nodes at level `L` (leaves are level 0) is `combine(L, left, right)`, Orchard's `MerkleCRH`: the Sinsemilla hash, under the personalization `"z.cash:Orchard-MerkleCRH"`, of the message made of `L` as 10 bits, then the 255 low bits of `left`, then the 255 low bits of `right`, each least significant bit first. The result is the x-coordinate of the hash point, or zero if the hash is undefined.

The account does not store the tree. It stores a *frontier* of 32 nodes: slot `L` holds a node exactly when bit `L` of `note_count` is 1. That node is the root of a complete subtree of `2^L` commitments: with `c` equal to `note_count` with its bits below `L` cleared, the leaves at positions `c - 2^L` to `c - 1`. A slot whose bit is 0 holds 32 zero bytes.

The root is computed from the frontier (`state.rs:111-129`):

```
node = empty leaf
for L from 0 to 31:
    if bit L of note_count is 1:  node = combine(L, frontier[L], node)
    else:                         node = combine(L, node, empty_root(L))
root = node
```

A commitment is appended (`state.rs:149-167`):

```
node = commitment
for L from 0:
    if bit L of note_count is 0:  frontier[L] = node; stop
    node = combine(L, frontier[L], node); frontier[L] = empty
note_count = note_count + 1
```

### 8.3 Decoding `NPOOL003`

`PoolState::decode` (`state.rs:211-270`). Every failure is `InvalidEncoding`.

1. The length is 3,137 and the tag is `"NPOOL003"`.
2. The network domain is not zero; `backing <= 2^63 - 1`; `note_count <= 4,294,967,294` and even; `1 <= root_count <= 64`.
3. Each frontier slot whose bit is set holds a canonical field element; each other slot holds zero bytes.
4. Each of the first `root_count` recent roots is a canonical field element; every later root slot holds zero bytes.
5. The last stored root equals the root computed from the frontier.

### 8.4 Decoding `NPOOL004`

`decode_slot_anchored` (`state.rs:272-341`), reached when the bytes begin with `"NPOOL004"`:

1. The length is 25,728, else `InvalidEncoding`.
2. The network domain is not zero; `backing <= 2^63 - 1`; `note_count <= 4,294,967,294` and even; else `InvalidEncoding`.
3. The frontier rule of 8.3, else `InvalidEncoding`.
4. `history_length <= 24,636`, else `InvalidLength`. The account has exactly 24,636 bytes after the length field, so a history of any permitted length fits.
5. Every byte after the history is zero, else `InvalidEncoding`.
6. The history decodes under the pool's network domain by the rules of [section 9.2](#92-slot-checkpoint-history); its errors pass through unchanged.
7. If the history has a newest checkpoint: its note count is not above the pool's, and if the two are equal its root equals the root computed from the frontier; else `InvalidEncoding`.
8. The tree is one that the next completed slot could record (`state.rs:330-339`): if `note_count` is not zero, the root computed from the frontier is not the root of the empty tree; and no checkpoint of the history, the newest or an older one, holds that root under a note count other than the pool's; else `InvalidEncoding`.

### 8.5 Applying a payment

`with_payment` (`state.rs:132-175`) takes the result of verification and returns the next state, leaving the present one unchanged on any error:

1. `note_count <= 4,294,967,292`, else `CapacityExceeded`. The limit `MAX_COMMITMENTS = 2^32 - 2` (`state.rs:13`) leaves the tree able to take two more commitments at every accepted state.
2. If the public value balance is negative, `backing` grows by its absolute value. Otherwise `backing` shrinks by it; if it exceeds `backing`, `InsufficientBacking`.
3. `backing <= 2^63 - 1`, else `CapacityExceeded`.
4. The two commitments are appended in order. Each must be a canonical field element and must not be the empty leaf, else `InvalidEncoding`. A commitment equal to the empty leaf would raise the note count and leave the root as it was.
5. `NPOOL003` only: the new root is added after the stored roots; if that makes 65, the oldest is dropped. `NPOOL004`: the checkpoint history is not touched.

The transition does not look at nullifiers. The caller must have established that both are unspent.

Stated as invariants, which the vectors exercise on the two flows in `pool.json`: `backing` changes by exactly the negated public value balance of each accepted payment and by nothing else; `note_count` grows by two per accepted payment and never otherwise; `rent_floor` and the network domain never change.

### 8.6 Genesis values

`PoolState::new(network, rent_floor)` (`state.rs:33-46`) is an `NPOOL003` pool with no backing, no notes, an empty frontier and one stored root, the root of the empty tree. `new_slot_anchored` (`state.rs:49-53`) is an `NPOOL004` pool with the same values and an empty checkpoint history. The local network builder creates the account at genesis with `rent_floor` equal to the rent-exempt minimum of the account and the same number of lamports (`node/localnet/src/main.rs:264-278`), and it chooses the network domain at random. The workspace's builder creates `NPOOL003` only.

## 9. Anchors

An anchor is a root the tree once had. A payment proves membership against its anchor, so a validator must decide which past roots it still accepts. The two pool formats answer differently.

### 9.1 `NPOOL003`: the last 64 roots

The accepted set is the stored recent roots (`state.rs:101-106`): the present root and up to 63 before it, one per accepted payment. A root becomes usable by the very next payment, including one in the same slot. It stops being usable after 64 later payments, whatever the slots. Decision 0006 states the reason for the number.

### 9.2 Slot checkpoint history

Source: `anchors.rs`. An `NPOOL004` pool keeps, instead of per-payment roots, one checkpoint per completed slot: the slot, the note count and the root at the end of that slot.

Encoding (`anchors.rs:116-129`):

| Offset | Size | Field | Contents |
| --- | --- | --- | --- |
| 0 | 8 | tag | `"ZOLANCH1"` |
| 8 | 2 | version | `u16`, the value 1 |
| 10 | 16 | domain | `"ZolanaSlotRoots1"` |
| 26 | 32 | network | Network domain |
| 58 | 2 | count | `u16`: number of entries, at most 512 |
| 60 | 48 × count | entries | Each: slot `u64`, note_count `u64`, root (32 bytes) |

The size is 60 to 24,636 bytes.

**Entry rule** (`anchors.rs:177-187`). An entry is valid when its note count is even and at most 4,294,967,294; its root is not zero and is a canonical field element; and its root is the root of the empty tree exactly when its note count is zero.

**Order rule** (`anchors.rs:189-196`). For an entry and the one before it: the note count does not decrease; and the roots are equal exactly when the note counts are equal.

**Reuse rule** (`anchors.rs:198-206`). No two entries anywhere in the history have the same root with different note counts.

**Decoding** (`anchors.rs:131-174`):

1. The length is between 60 and 24,636, else `InvalidLength`.
2. The tag and version match, else `UnsupportedVersion`.
3. The domain matches, else `InvalidContext`.
4. The caller's network domain is not zero and equals the network field, else `WrongNetwork`.
5. `count <= 512` and exactly `48 × count` bytes follow, else `InvalidLength`.
6. Each entry in order satisfies the entry rule; its slot is strictly greater than the previous entry's; the order rule holds against the previous entry; the reuse rule holds against all earlier entries; else `InvalidEncoding`.
7. The last slot is less than 512 above the first, else `InvalidEncoding`.

**Recording** a checkpoint `(slot, note_count, root)` (`anchors.rs:63-88`). A refused record leaves the history unchanged.

1. The entry rule holds, else `InvalidEncoding`.
2. If there is a newest entry: `slot` is not below its slot, else `InvalidContext`; and the order rule holds against it, else `InvalidEncoding`.
3. The reuse rule holds against all stored entries, else `InvalidEncoding`.
4. Every stored entry whose slot is 512 or more below `slot` is removed.
5. If the newest remaining entry has the same slot, it is replaced; otherwise the new entry is appended.

Step 5 means that a slot's checkpoint can be recorded more than once while that slot is the newest; each record replaces the previous one. Step 4 bounds the history at 512 entries by slot span, whatever the number of payments.

**Accepted roots** for a payment executing in `execution_slot` (`anchors.rs:93-114`):

1. If the newest entry's slot is above `execution_slot`, the result is the error `InvalidContext`.
2. The set contains the root of every entry with `entry.slot < execution_slot` and `execution_slot - entry.slot < 512`.
3. If `execution_slot < 512`, the set also contains the root of the empty tree.

So the root recorded for slot `S` is accepted in slots `S + 1` to `S + 511`, both included, and in no other. The root of the slot being executed is never accepted in that slot, even after a record for it. The root of the empty tree is accepted in slots 0 to 511 without any entry.

### 9.3 Completing a slot

`PoolState::complete_slot(slot)` (`state.rs:81-98`) records the end of a slot for an `NPOOL004` pool: it calls the record operation of 9.2 with the pool's note count and root. The root is taken from the newest checkpoint when that checkpoint has the pool's present note count, and computed from the frontier otherwise. For an `NPOOL003` pool it returns `UnsupportedVersion`. `with_completed_slot` (`state.rs:72-76`) is the same operation on a copy.

`accepted_roots(execution_slot)` (`state.rs:63-68`) is the accepted set of 9.2 for an `NPOOL004` pool and the stored recent roots for an `NPOOL003` pool. `roots()` (`state.rs:101-106`) returns the stored recent roots for an `NPOOL003` pool and the empty set for an `NPOOL004` pool.

### 9.4 How the candidate uses slot checkpoints

Two rules of the native program use the checkpoints, and they are the same in the workspace's program and in the candidate's copy of it:

- An `NPOOL004` pool is refused by finalization unless the feature `native_slot_anchors` is active (`adapter/processor/finalization.rs:171-173`; patch line 3907).
- Finalization takes the accepted anchors from `state.accepted_roots(slot)` (`adapter/processor/finalization.rs:84-86`; patch lines 4037-4039).

What makes them a rule that a validator follows exists in `node/candidate/agave-4.3.2.patch` only:

- The feature as something a runtime can activate (patch lines 1779-1790). Its identifier is defined in both places (`adapter/lib.rs:41-45`; patch lines 3692-3696). The Agave 3.0.14 runtime that the workspace builds against has no such feature, and the workspace's program takes the answer from one function that says "not active" for that runtime (`adapter/processor/runtime_features.rs:70-72`). The program built from the workspace therefore refuses every `NPOOL004` pool with `InvalidAccountData`, which is what the candidate does while the feature is inactive. The workspace's tests of the two rules give the program the state of the feature themselves (`adapter/processor/slot_anchor_tests.rs`).
- The end of a slot. Nothing in the workspace's validator calls `complete_slot`. When a bank is frozen, before its hash is computed, and only with the feature active, the bank loads the pool account, and if it is program-owned and in the `NPOOL004` format replaces its data with the result of `with_completed_slot(slot)` (patch lines 1941 and 1953-1973). The hook treats a pool that does not decode, and a completion that returns an error, as fatal.

Under that hook a slot in which no block is produced gets no checkpoint, and a produced block with no payment gets a checkpoint that repeats the previous root, which keeps that root accepted for another 511 slots.

The vectors in `pool.json` exercise the crate's functions in that order: payments within a slot against `accepted_roots(slot)`, then `complete_slot(slot)`.

### 9.5 The two windows

A payment has two independent limits in slots under `NPOOL004`: its own expiry, at most 1,024 slots after the slot in which it is first acceptable ([section 7](#7-payment-verification)), and the age of its anchor, at most 511 slots after the slot that recorded it. A payment whose anchor stops being re-recorded becomes unacceptable when the anchor ages out, even if its expiry is later. Under `NPOOL003` the anchor's life is counted in payments and has no relation to slots.

## 10. Nullifier markers

Source: `native_accounts.rs:15-35`, `adapter/nullifiers.rs`, `adapter/processor/finalization.rs`. Decision 0004 gives the reasons.

### 10.1 Addresses

The program address is the 32 bytes `5b2209cb8c4a5c0ba714d249409b03dc1957c2347a1caaf11d832a584c6b0dbe` (`native_accounts.rs:15-18`), in base58 `78kCqctsuUaj7kyV8xNVwXQrqovY3QtSytt4eCYApVUh`.

Addresses are the runtime's program-derived addresses: for a list of seeds, the address is `SHA-256(seed_1 || ... || seed_n || bump || program address || "ProgramDerivedAddress")` for the largest one-byte `bump`, counting down from 255, for which that hash is not the encoding of a point of the Ed25519 curve.

| Account | Seeds |
| --- | --- |
| Pool | `"native-payment-pool-v1"` |
| Marker of a nullifier | `"native-payment-spent-v1"`, the pool address (32 bytes), the nullifier (32 bytes) |

The pool address is `4mJMnxFhRVMQ3aNcyn2LgW8fztTjgckUvaaWrXggdAAL` with bump 255. `accounts.json` gives the marker address and bump of each nullifier of the four vector payments.

### 10.2 Marker account

A marker is an account at the marker address, owned by the native program, with 40 bytes of data: `"NSPENT01"` followed by the nullifier (`adapter/nullifiers.rs:4-17`).

A nullifier is spent exactly when an account owned by the native program exists at its marker address. The check does not read the data: any program-owned account there counts, including one whose data is malformed (`adapter/processor/finalization.rs:272-276`).

Finalization creates both markers of a payment ([section 13.5](#135-finalization), step 13). No instruction closes, rewrites or resets a marker; the close instruction of the staging account cannot apply to one, because a marker does not decode as a staging account.

## 11. Staging

A payment is larger than a transaction of the ordinary size, so the staged path writes it into an account first.

### 11.1 Payload digest

`payload_digest(bytes) = BLAKE2b-256("NativeStageV1!!!", bytes)` (`staging.rs:9-17`). It identifies exact payment bytes. The same function gives the payment identifier of the envelope ([section 12](#12-envelope)).

### 11.2 Staging account

Source: `native_accounts.rs:38-143`. The account has a fixed size of 16,480 bytes: a 96-byte header and room for 16,384 payload bytes (`MAX_PAYLOAD_BYTES`, `staging.rs:6`), whatever the size of the payment.

| Offset | Size | Field | Contents |
| --- | --- | --- | --- |
| 0 | 8 | tag | `"NBUF0001"` |
| 8 | 32 | sponsor | The sponsor that initialized the account |
| 40 | 4 | length | `u32`: size of the payment, 1 to 16,384 |
| 44 | 4 | received | `u32`: bytes written so far |
| 48 | 32 | digest | The payload digest the payment must have |
| 80 | 8 | expiry | `u64`: last slot in which the account can be written, sealed or finalized |
| 88 | 1 | state | 0 open, 1 sealed, 3 consumed |
| 89 | 7 | reserved | Zero |
| 96 | 16,384 | payload | The first `received` bytes of the payment, then zero bytes |

**Decoding** (`native_accounts.rs:68-90`); every failure is `InvalidAccountData`: the size is 16,480; the tag matches; the state is 0, 1 or 3; the reserved bytes are zero; `1 <= length <= 16,384`; `received <= length`; if the state is not 0 then `received == length`; every payload byte from `received` on is zero.

**Operations**:

| Operation | Conditions | Effect | Failure |
| --- | --- | --- | --- |
| initialize(sponsor, length, digest, expiry) | The account's data is 16,480 zero bytes; `1 <= length <= 16,384` | Writes the header with `received = 0`, state 0 | `InvalidAccountData` |
| write(offset, chunk) | State 0; `offset == received`; `1 <= chunk size <= 768`; `offset + chunk size <= length` | Copies the chunk; `received` grows by its size | `InvalidInstructionData` |
| seal | State 0; `received == length`; the payload digest of the `length` bytes equals `digest` | State 1 | `InvalidAccountData` |
| payload | State 1 | Returns the `length` payload bytes | `InvalidAccountData` |
| consume | State 1 | State 3 | `InvalidAccountData` |

Writes are strictly sequential, so the bytes cannot be changed once written, and a sealed account cannot be written. A 9,222-byte payment takes thirteen writes of at most 768 bytes (`MAX_CHUNK_BYTES`, `staging.rs:7`).

The slot rules for the account (initialization, expiry, who may close it) belong to the native program and are in [section 13.4](#134-staging-instructions).

`staging.rs:19-73` also contains `StagedPayload`, an in-memory assembler with the same sequence rules and different error names. The native program does not use it.

## 12. Envelope

Source: `envelope.rs`. The envelope frames one complete `NPAY0003` payment for the inline path.

### 12.1 Layout

| Offset | Size | Field | Contents |
| --- | --- | --- | --- |
| 0 | 8 | tag | `"ZOLNPAY1"` |
| 8 | 2 | version | `u16`, the value 1 |
| 10 | 16 | domain | `"ZolanaNativePay!"` |
| 26 | 32 | network | Network domain |
| 58 | 8 | expires_at | `u64`: the payment's expiry, repeated |
| 66 | 32 | payment_id | The payload digest of the payment bytes |
| 98 | 4 | payload_length | `u32` |
| 102 | payload_length | payment | The payment bytes, unchanged |

The header is 102 bytes. A frame is at most 16,384 bytes (`MAX_ENVELOPE_BYTES`). Because the only payment accepted inside is the 9,230-byte `NPAY0003` layout, every valid frame is 9,332 bytes.

### 12.2 Decoding

`envelope::decode(network, current_slot, bytes)` (`envelope.rs:54-97`):

1. The length is above 102 and at most 16,384, else `InvalidLength`.
2. The tag and version match, else `UnsupportedVersion`.
3. The domain matches, else `InvalidContext`.
4. The caller's network domain is not zero and equals the network field, else `WrongNetwork`.
5. `1 <= payload_length <= 16,282`, and exactly that many bytes follow the header, else `InvalidLength`.
6. The payload digest of those bytes equals `payment_id`, else `DigestMismatch`.
7. The bytes decode as a payment under the same network domain ([section 5.2](#52-decoding)); its errors pass through.
8. The payment carries a shielded fee, else `UnsupportedVersion`.
9. Encoding the decoded payment gives the same bytes, else `InvalidEncoding`.
10. The header's `expires_at` equals the payment's, else `InvalidContext`.
11. `expires_at >= current_slot`, else `Expired`.
12. `expires_at - current_slot <= 1,024`, else `InvalidContext`.

`envelope::encode(network, payment)` (`envelope.rs:34-47`) applies rules 5 and 7 to 9 to the payment and writes the header.

The envelope adds no signature and no new signed value. The header's network, expiry and identifier repeat values that the payment's own signatures already cover, or that are computed from its bytes. A decoded envelope is not a verified payment; the same verification and finalization follow as for a staged payment.

## 13. Native program

Source: `node/adapter/src`. The program is a built-in of the validator: `node/agave/builtins/src/lib.rs:53-59` registers `native_payment_program::Entrypoint` at the program address under a feature gate. It is not deployed bytecode and has no upgrade authority.

### 13.1 Entry rules

For every instruction (`adapter/processor.rs:24-52`):

1. The instruction data is not empty, else `InvalidInstructionData`. Its first byte is the opcode.
2. Compute units are consumed: 1,100,000 for opcodes 3 and 5, 10,000 for any other first byte. If the transaction's remaining budget is smaller, `ComputationalBudgetExceeded`. The charge is flat and is made before any other check and before proof verification (`FINALIZE_COMPUTE_UNITS`, `adapter/lib.rs:24`).
3. The instruction is at the top level of the transaction, not invoked by another program, else `InvalidInstructionData`.

A transaction that finalizes a payment must therefore request a compute budget above the default; the repository's tests request 1,400,000 units. Decision 0003 calls these charges "conservative local development charges, not calibrated production throughput claims".

### 13.2 Feature gates

Each gate is an Agave feature account; the identifier is 32 bytes whose last 31 are `2f3d08493766597c11abc83358475f482bbd708d5be54c61150357d9a137d1` (`adapter/lib.rs:18-45`).

| First byte | Feature | Gates |
| --- | --- | --- |
| `c0` | `native_private_payments` | The program itself |
| `c1` | `native_recipient_withdrawals` | Finalizing an `NPAY0002` payment (`finalization.rs:213`) |
| `c2` | `native_shielded_fees` | Finalizing an `NPAY0003` payment, staged or inline (`finalization.rs:55-57`) |
| `c3` | `native_inline_payments` | Opcode 5 (`adapter/processor.rs:60-62`) |
| `c4` | `native_slot_anchors` | Finalizing against an `NPOOL004` pool (`finalization.rs:171-173`) |

An inline payment needs both `c2` and `c3`. The first four are switches of the runtime's feature set in both code lines. `c4` is a switch of the candidate's runtime only; on the runtime the workspace builds against it is never active ([section 9.4](#94-how-the-candidate-uses-slot-checkpoints)).

### 13.3 Instructions

| Opcode | Name | Instruction data | Accounts, in order |
| --- | --- | --- | --- |
| 0 | initialize | `00`, length `u32`, digest (32 bytes), expiry `u64`: 45 bytes | staging account (writable, signer); sponsor (signer) |
| 1 | write | `01`, offset `u32`, then 1 to 768 chunk bytes | staging account (writable); sponsor (signer) |
| 2 | seal | `02` | staging account (writable); sponsor (signer) |
| 3 | finalize | `03` | pool (writable); staging account (writable); sponsor (writable, signer); System program; marker of nullifier 0 (writable); marker of nullifier 1 (writable); for `NPAY0002` only, recipient (writable) |
| 4 | close | `04` | staging account (writable); sponsor (writable, signer) |
| 5 | inline | `05`, then an envelope | pool (writable); sponsor (writable, signer); System program; marker of nullifier 0 (writable); marker of nullifier 1 (writable) |

The builders are in `adapter/instructions.rs`. Any other first byte takes the path of opcodes 0 to 4 and, if the account checks of that path pass, ends in `InvalidInstructionData`.

### 13.4 Staging instructions

Opcodes 0, 1, 2 and 4 (`adapter/processor.rs:65-138`):

1. There are exactly two accounts and the second, the sponsor, is a signer, else `MissingRequiredSignature`.
2. The staging account is neither the pool nor the sponsor, else `InvalidArgument`.
3. The staging account is owned by the program, else `InvalidAccountOwner`.
4. Opcode 0: the data after the opcode is 44 bytes and the staging account is a signer, else `InvalidInstructionData`; `expiry >= slot` and `expiry - slot <= 1,024`, else `InvalidInstructionData`; then the initialize operation of [section 11.2](#112-staging-account) with the sponsor's key. Other opcodes: the account decodes.
5. The sponsor stored in the account is the signing sponsor, else `MissingRequiredSignature`.
6. For every opcode but 4: `slot <= expiry`, else `InvalidInstructionData`.
7. Opcode 1: at least five bytes of data; the write operation. Opcode 2: no further data; the seal operation. Opcode 4: no further data; all lamports of the staging account move to the sponsor and its data is truncated to zero bytes.

The staging account must exist before opcode 0, owned by the program and holding 16,480 zero bytes; the client creates it with the System program and signs with its key. Only the sponsor that initialized an account can write, seal or close it. Closing is allowed in any state, before or after expiry, and is the only way the account's rent returns.

### 13.5 Finalization

Opcode 3 and opcode 5 share one procedure (`adapter/processor/finalization.rs`). "Staged" refers to opcode 3 and "inline" to opcode 5. Opcode 3 must carry no data after the opcode, else `InvalidInstructionData` (`adapter/processor.rs:53-58`).

Checks, in order:

1. The account count is 5 (inline), or 6 or 7 (staged), and the sponsor is a signer, else `MissingRequiredSignature`.
2. The first account is the pool address and the System program is in its position, else `InvalidArgument`.
3. Staged: the staging account is neither the pool nor the sponsor, else `InvalidArgument`.
4. The pool is owned by the program; the sponsor account is owned by the System program and has no data; else `InvalidAccountOwner`.
5. The pool data decodes ([section 8](#8-pool-account)), else `InvalidAccountData`. If the pool is in the `NPOOL004` format, the feature `c4` is active, else `InvalidAccountData` (`finalization.rs:171-173`).
6. The pool holds at least `rent_floor + backing` lamports, else `InsufficientFunds`; if that sum does not fit in a `u64`, `ArithmeticOverflow`.
7. Staged: the staging account is owned by the program, else `InvalidAccountOwner`, and decodes, else `InvalidAccountData`.
8. The payment bytes are obtained. Inline: the envelope decodes under the pool's network domain at the current slot ([section 12.2](#122-decoding)), else `InvalidInstructionData`. Staged: the staging account's sponsor is the signing sponsor and `slot <= expiry`, else `InvalidArgument`; the account is sealed, else `InvalidAccountData`; its payload decodes under the pool's network domain ([section 5.2](#52-decoding)), else `InvalidInstructionData`.
9. If the payment carries a shielded fee, the feature `c2` is active, else `InvalidInstructionData`.
10. The payment's sponsor field is the signing sponsor's key, else `MissingRequiredSignature`.
11. The destination of a positive public value balance is resolved (`finalization.rs:195-250`):
    - No withdrawal recipient: the account count is exactly 5 (inline) or 6 (staged), else `InvalidArgument`. The destination is the sponsor.
    - Withdrawal recipient: the feature `c1` is active and there are exactly 7 accounts, else `InvalidInstructionData`. The seventh account's key is the recipient in the payment and it is writable, else `InvalidArgument`. It is owned by the System program, has no data, is not executable, its key is a point of the Ed25519 curve, and it is not the sponsor, else `InvalidAccountOwner`. Its balance after the withdrawal is at least the rent-exempt minimum of an account with no data, else `AccountNotRentExempt`. The destination is that account.
12. The two nullifiers differ, else `InvalidInstructionData`. For each, in action order (`finalization.rs:253-282`): the account in its position is at the marker address of that nullifier, else `InvalidArgument`; it is writable, else `InvalidArgument`; it is not owned by the program, else `InvalidInstructionData` (the nullifier is spent); it is owned by the System program and has no data, else `InvalidAccountData`.
13. The accepted anchors are `accepted_roots(slot)` of the pool ([section 9.3](#93-completing-a-slot)) for the current slot (`finalization.rs:84-86`). If that returns an error, which it does for an `NPOOL004` pool whose newest checkpoint is of a later slot, `InvalidAccountData`. The payment verifies ([section 7](#7-payment-verification)) with the current slot, those anchors, an empty spent set, and the payment's own public value balance as the authorized one, else `InvalidInstructionData`.
14. The pool transition succeeds ([section 8.5](#85-applying-a-payment)), else `InvalidInstructionData`.

Effects, after every check has passed (`finalization.rs:106-126`, `285-354`):

15. Staged: the staging account's state becomes 3, consumed.
16. Public movement. Negative balance: a System transfer of its absolute value from the sponsor to the pool. Positive balance: the pool's lamports fall by it and the destination's rise by it. Zero: nothing.
17. For each nullifier in action order: if the marker address holds fewer lamports than `max(rent-exempt minimum for 40 bytes, 1)`, the sponsor transfers the difference to it; the address is allocated 40 bytes and assigned to the program, the program signing for the derived address; its data becomes the marker of [section 10.2](#102-marker-account).
18. The pool's data becomes the encoding of the next state; staged, the staging account's data is written back.

All of this is one instruction of one transaction. If it, or any later instruction of the same transaction, fails, the runtime discards every effect, including the transfers.

After finalization the pool's lamports are at least `rent_floor + backing` again: a deposit raises both sides by the same amount, and a withdrawal lowers both. Lamports sent to the pool by any other means raise its balance without raising `backing`, and nothing in the program pays them out.

### 13.6 Who pays what

| Cost | Paid by | When | Returned |
| --- | --- | --- | --- |
| Transaction fees | The transaction's fee payer | Every transaction, by the runtime, before execution | No |
| Rent of the staging account (16,480 bytes) | Whoever funds the account's creation | Before opcode 0 | To the sponsor, by opcode 4 |
| Lamports of two markers | The sponsor | Finalization, step 17 | No |
| A deposit | The sponsor | Finalization, step 16 | As notes |

The `sponsor` field is a role, not a privileged identity: any System-owned account that signs can hold it. The three ways of paying that the repository's wallets implement differ only in who that account is and in the tag:

- A development sponsor signs and pays (decision 0003).
- The user's own public fee account signs and pays; the payment bytes are the same as in the first case (decisions 0009 and 0011).
- A relay signs and pays, and an `NPAY0003` payment reimburses it: the fee leaves the pool for the relay's account in the same instruction that executes the payment (decision 0032). The fee is public, is fixed by the payer's signatures, and comes out of the notes being spent. A payment that fails reimburses nothing.

A payment cannot both pay a shielded fee and withdraw to a recipient (`verification.rs:34-45`).

### 13.7 Admission of inline transactions in the candidate

An inline payment makes a transaction that carries a 9,332-byte frame, above the runtime's ordinary limit of 1,232 bytes. The workspace does not change that limit (`adapter/lib.rs:35`, `adapter/instructions.rs:73-76`); its tests execute inline payments by handing transactions to a bank directly. The candidate adds an exception, in `runtime/src/native_payment_admission.rs` of the patch (from patch line 2037), which this document reports and the vectors do not exercise. As read from the patch: the transaction is at most 16,384 bytes, of the legacy version, with one signature and no address lookup table; the features `c0`, `c2` and `c3` are active; it has exactly two instructions, a compute-budget instruction that sets the limit to exactly 1,400,000 units and the opcode 5 instruction with five accounts; the envelope decodes at the current slot under the network domain it names; the account keys are exactly the five accounts of [section 13.3](#133-instructions) and the two program addresses; and the fee payer is the payment's sponsor.

## 14. Test vectors

The vectors are in `protocol/payments/tests/vectors/`; the [README there](../protocol/payments/tests/vectors/README.md) lists the files and the conventions of the JSON.

**How they are produced.** `protocol/payments/tests/protocol_vectors.rs` builds every JSON file from the crate's own functions: it encodes with the crate's encoders and records what the crate's decoders, verifier and transition return. Four payments with real proofs are the starting material: a deposit, a private send that spends the deposit's note, an `NPAY0003` payment that spends the note the send created, and an `NPAY0002` withdrawal that spends the send's change. They are built from three fixed spending keys and a fixed byte stream in place of randomness.

**How they are checked.** The test `committed_vectors_are_what_the_code_produces` runs with the workspace tests. It reads the four payments, requires the verifier to accept each of them, regenerates every JSON file and requires it to equal the committed copy byte for byte. Each decoder case and each verification case in the generator also carries the result this specification states for it, and the test fails if the code returns another. A change of a format, a limit, a rule or an error name therefore fails the test until the vectors, and with them this document, are changed.

The test also computes several things in a second way and requires agreement: the bundle commitment and the authorization digest from the payment bytes as [section 6](#6-authorization-digest) writes them; the root of the tree from all leaves, against the root from the stored frontier; and the marker addresses from the seeds, against the crate's function.

**A second reading.** `tools/protocol_vectors_test.py` is written from this document in another language and shares no code with the crates. It decodes payments, envelopes, checkpoint histories, pool accounts and staging accounts by the rules of sections 5, 8, 9, 11 and 12, computes the digests of sections 6 and 11.1 and the addresses of section 10.1, applies the pre-signature checks of section 7 and replays the recorded sequences; every result must equal what the vectors record from the code. It does not implement the tree hash, signature verification or proof verification: for those it takes the recorded roots and results, and it names the five decoder cases whose refusal rests on the tree hash. It runs with the Python suites of `tools/check.sh`.

The ignored test `payments_are_reproduced_by_the_generator` rebuilds the four payments, proofs included, and compares them with the committed files. Rebuilding gives the same bytes when repeated on one machine. It has not been compared across platforms, which is why the ordinary test verifies the committed payments instead of rebuilding them.

**What they cover.**

| File | Sections |
| --- | --- |
| `payments.json` | 5, 6, 7: layouts with offsets, every intermediate digest, decoder cases, verification cases |
| `envelope.json` | 12: the frame, the slots at the edges of its window, decoder cases |
| `staging.json` | 11: digests, an account through its whole life with refused operations, stored accounts |
| `anchors.json` | 9.2: accepted and refused records, accepted roots at the edges of the window, the largest history, decoder cases |
| `pool.json` | 8, 9.1, 9.3: empty-tree values, tree hashes, both pool formats through the four payments, root rotation, capacity, decoder cases |
| `accounts.json` | 10.1 |

**What they do not cover.** The native program of [section 13](#13-native-program) is not exercised by these vectors: its account rules, instruction data, error codes, compute charge, feature gates and marker data are specified here from the source and are tested by the program's own tests (`node/adapter/src/processor/slot_anchor_tests.rs` and `runtime_features_tests.rs`, `node/adapter/tests`) and by `node/validator-check`, which this work did not change. Nor are the candidate's hook of section 9.4 and its rules of section 13.7.

## 15. Open questions and observations

Each item states what the code does and where. None is resolved here.

### Code lines and wiring

1. **The program built from the workspace accepts no payment against an `NPOOL004` pool.** Its finalization has the candidate's two rules: it uses `accepted_roots(slot)` (`adapter/processor/finalization.rs:84-86`; `node/candidate/agave-4.3.2.patch:4037-4039`) and gates the format on a feature (`adapter/processor/finalization.rs:171-173`; `node/candidate/agave-4.3.2.patch:3907`). But the runtime the workspace builds against cannot activate that feature, so the gate is always closed there (`adapter/processor/runtime_features.rs:70-72`), and slot completion is called only from the candidate's bank (`node/candidate/agave-4.3.2.patch:1941`, `node/candidate/agave-4.3.2.patch:1953-1973`). The workspace tests the two rules with the state of the feature and the end of a slot supplied by the test. `NPOOL004` as a rule that a validator executes therefore still exists only in a build of the patch file.
2. **The fifth feature identifier is defined in both places and is a feature in one.** `adapter/lib.rs:41-45` and `node/candidate/agave-4.3.2.patch:3692-3696` hold the same bytes. Only the candidate's feature set lists it (`node/candidate/agave-4.3.2.patch:1779-1790`); an account at that identifier activates nothing on the runtime the workspace builds against.
3. **The two copies of `state.rs` complete a slot differently.** The workspace reuses the newest checkpoint's root when the note count is unchanged (`state.rs:86-92`); the candidate's base patch recomputes the root from the frontier each time. For a state that the decoder accepts the two give the same root, by rule 7 of section 8.4; this was not tested across the copies.
4. **The `NPOOL004` decoder still accepts one kind of state that slot completion refuses.** Recording a checkpoint applies the entry, order and reuse rules of section 9.2 to the present root (`anchors.rs:177-206`), and `complete_slot` returns their error. Rule 8 of section 8.4 refuses a tree that those rules could not record, and rule 4 of section 8.5 keeps a payment from leaving one, so a state that decodes completes a slot. The exception: the decoder cannot tell whether the root of an older checkpoint is the root of a tree with that note count, so a constructed state may hold a checkpoint that claims the root the next payment will produce; that payment is applied and the slot is then refused. The transition never writes such a state. The two rules, how they were found and the tests that hold them are described in [protocol fuzz targets and property tests](protocol-fuzzing.md); the vectors hold no case for either rule. The candidate's copy of `state.rs` does not have them (section 1). The candidate's hook does not handle an error from decoding or from completion (`node/candidate/agave-4.3.2.patch:1964-1970`); [decision 0041](decisions/0041-slot-completion-failure-handling.md) is a draft of what it should do.

### Rules that may surprise

5. **An `NPAY0001` payment with a positive balance is still executable.** It pays the sponsor (`adapter/processor/finalization.rs:205-211`, `301-310`). Decision 0008 restricts this form in the command-line wallet; the program does not.
6. **Only the newest stored root is tied to the tree, and under `NPOOL004` not always that.** `NPOOL003` decoding checks the last root against the frontier (`state.rs:266-268`) and accepts any canonical field element as an older root. `NPOOL004` decoding ties the tree to a checkpoint only when the newest one has the present note count (`state.rs:323-329`); when the newest checkpoint has fewer notes than the pool, as it does between a payment and the end of its slot, the decoder requires only that the root of the frontier is not one that a checkpoint holds for another note count and is not the root of the empty tree (rule 8 of section 8.4). The vectors include an accepted pool of each format with an altered older root, and an accepted `NPOOL004` pool with an altered frontier node. Only the program and genesis write the account, so this concerns whoever constructs or restores a pool, not a transaction.
7. **A payment can outlive its anchor**, and under `NPOOL004` the anchor's life (511 slots) is shorter than the longest expiry (1,024 slots). See section 9.5.
8. **The current slot's root is never accepted under `NPOOL004`**, so a note cannot be spent in the slot that created it; under `NPOOL003` it can be spent by the next payment.
9. **The empty tree's root is accepted in slots 0 to 511 without a checkpoint** (`anchors.rs:102-104`), and afterwards only while some checkpoint carries it.
10. **A slot's checkpoint can be replaced while it is the newest** (`anchors.rs:81-83`). `state.rs:420-421` notes that the wallet's replay forbids reopening a completed block; the pool state itself does not.
11. **The staging account's expiry and the payment's expiry are separate values**, each at most 1,024 slots ahead when checked (`adapter/processor.rs:86-89`, `verification.rs:155-160`). Finalization needs both (`adapter/processor/finalization.rs:50`).
12. **Closing a staging account is allowed in every state**, including sealed and not yet finalized, and after expiry (`adapter/processor.rs:103`, `123-135`).
13. **The staging state byte takes the values 0, 1 and 3.** The value 2 is refused and nothing writes it (`native_accounts.rs:71`, `126`, `137`).
14. **Decoding a sealed staging account does not recompute its digest** (`native_accounts.rs:68-90`); only the seal operation does. The vectors include an accepted sealed account whose stored digest was altered.
15. **Compute units are consumed before the opcode is known to be valid and before the top-level check** (`adapter/processor.rs:40-51`): an unknown opcode costs 10,000 units and fails.
16. **The decoder accepts values that later steps refuse or that have no meaning**: two equal nullifiers (refused by verification), any public value balance in an `NPAY0001` payment including the most negative `i64` (refused by the pool transition as `CapacityExceeded`), an identity `cv_net`, and arbitrary proof and signature bytes. The vectors include each.
17. **The pool transition does not check that the two commitments differ** or that they are commitments at all, only that they are canonical field elements other than the empty leaf (`state.rs:149-157`). It relies on verification having run.
18. **`rent_floor` is trusted as stored.** The program compares the pool's balance with `rent_floor + backing` (`adapter/processor/finalization.rs:174-180`) and never compares `rent_floor` with the Rent sysvar or updates it.
19. **A withdrawal recipient must be a point of the Ed25519 curve** (`adapter/processor/finalization.rs:231`), so a program-derived address cannot receive a withdrawal.
20. **The proof and signature bytes are outside the authorization digest**, so the payload digest names exact bytes and not effects. `envelope.rs:308-309` says the same in a test comment.

### Error reporting

21. **The program reports almost every protocol failure as `InvalidInstructionData`** (`adapter/processor/finalization.rs:46`, `53`, `102`, `105`). An expired payment, an unknown anchor, a bad signature, a bad proof and a full tree are indistinguishable in a failed transaction.
22. **`SpentNullifier` is never returned on the chain.** The program passes an empty spent set (`adapter/processor/finalization.rs:98`) and detects a spent nullifier from the marker's owner (`:274-276`), again as `InvalidInstructionData`. The second comparison of the `WrongValueBalance` check likewise cannot fail there, because the program supplies the payment's own value (`:99`).
23. **A zero network domain is `InvalidContext` when encoding and `WrongNetwork` when decoding** (`wire.rs:42-44`, `125-127`).
24. **The two pool formats name the same kind of failure differently.** A wrong size is `InvalidEncoding` in both, but an `NPOOL004` history that does not fit is `InvalidLength` (`state.rs:301-307`), and errors of the embedded history pass through as `UnsupportedVersion`, `InvalidContext` or `WrongNetwork` (`state.rs:311`). The program maps all of them to `InvalidAccountData`.
25. **Staging rules exist twice**, in `StagedPayload` (`staging.rs:19-73`) and in the account buffer (`native_accounts.rs:41-143`), with different error types. The program uses the second; the proof fixture tool uses the first (`clients/cli/src/proof_smoke.rs:111-116`).

### Checks that cannot fail

26. **`wire.rs:100-102` and the second half of `wire.rs:117`** compare the size with 16,384 after it is already known to be 9,222, 9,230 or 9,254.
27. **`wire.rs:203-211`**: after the earlier checks, constructing the bundle cannot fail on proof size or flags.
28. **`envelope.rs:114-116`**: no input is known that decodes and then encodes differently; every case of the vector test that decodes also encodes back.
29. **`state.rs:139-140`**: for a decoded pool, `backing` is at most `2^63 - 1` and the absolute public value balance at most `2^63`, so the addition cannot overflow a `u64`; the error named there, `InvalidLength`, is unreachable from stored state, and `state.rs:146-148` returns `CapacityExceeded` instead. `backing` is a public field (`state.rs:25`), so code can set a value the decoder would refuse.
30. **`envelope.rs:22`** allows an inner payment of up to 16,282 bytes; the only size that decodes is 9,230.

### Names

31. **`genesis` and `network` name one value** (`verification.rs:68`, `wire.rs:37` and `106` against `envelope.rs:34` and `state.rs:23`). It is the pool's network domain, not the genesis hash.

## 16. Statements elsewhere that differ from the code

Decision records are kept as written when later work changes the facts; two of them carry a status update for that reason. The list below is every place found, in the records this document was written from (0002 to 0004, 0006, 0008, 0009, 0011, 0032, 0033) and in the comments of the two crates, where the text and the present code differ.

| Where | Text | Code |
| --- | --- | --- |
| `anchors.rs:1-4` | The module is "for a future native payment state version" and "is not wired into NPOOL003 or an activated validator rule" | `state.rs:19`, `29` and `49-53` embed it in `NPOOL004`; decision 0033 says the candidate activates that format |
| `envelope.rs:3` | "an opt-in execution candidate, not an enabled network transport" | True of the workspace. Decision 0033 describes the candidate admitting it |
| Decision 0002, second paragraph | Authorization commits to "the genesis identifier" | It commits to the pool's network domain; decision 0003 says the domain is "not the literal genesis hash" |
| Decision 0003, third paragraph | The pool account stores "recent anchors and spent nullifiers" | No nullifiers are in the pool since decision 0004. The record's status update covers the numbers of its capacity paragraph, not this sentence |
| Decision 0003, fourth paragraph | A positive balance "releases pool backing to that sponsor" | True for `NPAY0001` and `NPAY0003`; an `NPAY0002` payment pays the recipient (`adapter/processor/finalization.rs:212-248`) |
| Decision 0004, second paragraph | "Finalize requires exactly six accounts" | Six or seven when staged, five when inline (`adapter/processor/finalization.rs:141-146`) |
| Decision 0004, sixth paragraph | "The pool format is now `NPOOL002`, 1,601 bytes" | Refused by the decoder; covered by the record's status update |
| Decision 0008, second paragraph | "The Orchard proof and spend authorization bind network, genesis, sponsor, recipient, public value, anchor and expiry" | The signatures bind them, through the digest. The proof's public inputs are the anchor, `cv_net`, the nullifier, `rk`, `cmx` and the enable flags. Network and genesis are one value |
| Decision 0032, first paragraph | The finalizer pays the fee "atomically with backing, commitments, nullifiers and staging closure" | Finalization marks the staged payment consumed. Closing the account is a separate instruction, which the client places in the same transaction (`adapter/instructions.rs:114-126`) |
| Decision 0033, "Slot anchors and explicit activation" | `NPOOL003` "retains 64 roots per payment" | It retains the roots of the last 64 payments, one each |

The sizes the records give (9,222, 9,254, 9,230 and 9,332 bytes; 3,137 bytes; 13 chunks; 64 roots; 512 slots; 1,024 slots; 40-byte markers; 1,100,000 and 10,000 compute units) agree with the code.

## 17. What this document does not cover

- The Orchard Action statement, key derivation, note encryption and address formats. They are the `orchard` crate's, used unchanged.
- An argument that the integration is sound: that value is conserved, that each binding of section 6.3 is sufficient, or that the hidden values stay hidden. Section 6.3 states what is bound, not what follows.
- The wallets: note selection, scanning, witness maintenance, journals, recovery, fee quotes.
- The gateway, relay, faucet and other services, and what their operators observe.
- Consensus, block production, snapshots, replay and the validator outside the native program.
- The second copy of the code in `node/candidate`, beyond the points stated in sections 1, 9.4, 13.7 and 15.
- Economics: no fee, rent or supply schedule is specified, because none is chosen.

## Appendix A. Constants and limits

| Name | Value | Source |
| --- | --- | --- |
| `PROTOCOL_VERSION` | 1 | `verification.rs:13` |
| `ACTION_COUNT` | 2 | `verification.rs:14` |
| `MAX_EXPIRY_WINDOW` | 1,024 slots | `verification.rs:15` |
| `HEADER_BYTES` | 122 | `wire.rs:28` |
| `ACTION_BYTES` | 884 | `wire.rs:26` |
| Proof size | 7,264 bytes | `Proof::expected_proof_size(2)` |
| Payment size | 9,222 / 9,254 / 9,230 bytes | `wire.rs:110-116` |
| `MAX_PAYLOAD_BYTES` | 16,384 | `staging.rs:6` |
| `MAX_CHUNK_BYTES` | 768 | `staging.rs:7` |
| Staging header / account | 96 / 16,480 bytes | `native_accounts.rs:38-39` |
| `ENVELOPE_VERSION` | 1 | `envelope.rs:17` |
| `ENVELOPE_HEADER_BYTES` | 102 | `envelope.rs:19` |
| `MAX_ENVELOPE_BYTES` | 16,384 | `envelope.rs:21` |
| `MAX_INNER_PAYMENT_BYTES` | 16,282 | `envelope.rs:22` |
| `MAX_COMMITMENTS` | 4,294,967,294 | `state.rs:13` |
| `MAX_ROOTS` | 64 | `state.rs:16` |
| `STATE_BYTES` (`NPOOL003`) | 3,137 | `state.rs:17` |
| `SLOT_STATE_BYTES` (`NPOOL004`) | 25,728 | `state.rs:19` |
| Largest backing | `2^63 - 1` | `state.rs:146-148`, `225`, `282` |
| `ANCHOR_HISTORY_VERSION` | 1 | `anchors.rs:18` |
| `ANCHOR_WINDOW_SLOTS` | 512 | `anchors.rs:20` |
| `MAX_SLOT_ANCHORS` | 512 | `anchors.rs:21` |
| Checkpoint header / entry | 60 / 48 bytes | `anchors.rs:22-23` |
| `MAX_ANCHOR_HISTORY_BYTES` | 24,636 | `anchors.rs:24` |
| `MARKER_BYTES` | 40 | `adapter/nullifiers.rs:4` |
| `FINALIZE_COMPUTE_UNITS` | 1,100,000 | `adapter/lib.rs:24` |
| Other instructions | 10,000 compute units | `adapter/processor.rs:45` |
| Tree depth | 32 | `state.rs:27` |

## Appendix B. Domain separation

| Bytes | Kind | Used for | Source |
| --- | --- | --- | --- |
| `NPAY0001`, `NPAY0002`, `NPAY0003` | Tag | Payment layouts | `wire.rs:20-24` |
| `NativePayAuthV1!`, `NativePayAuthV2!`, `NativePayAuthV3!` | BLAKE2b personalization | Authorization digest, one per tag | `verification.rs:90-96` |
| `ZTxIdOrchardHash`, `ZTxIdOrcActCHash`, `ZTxIdOrcActMHash`, `ZTxIdOrcActNHash` | BLAKE2b personalization | Orchard bundle commitment | `orchard` crate |
| `NativeStageV1!!!` | BLAKE2b personalization | Payload digest and payment identifier | `staging.rs:12` |
| `NPOOL003`, `NPOOL004` | Tag | Pool account | `state.rs:180`, `195` |
| `ZOLANCH1` | Tag | Checkpoint history | `anchors.rs:16` |
| `ZolanaSlotRoots1` | Fixed field | Checkpoint history | `anchors.rs:17` |
| `NBUF0001` | Tag | Staging account | `native_accounts.rs:61` |
| `NSPENT01` | Tag | Nullifier marker | `adapter/nullifiers.rs:14` |
| `ZOLNPAY1` | Tag | Envelope | `envelope.rs:16` |
| `ZolanaNativePay!` | Fixed field | Envelope | `envelope.rs:18` |
| `native-payment-pool-v1` | Address seed | Pool address | `native_accounts.rs:22` |
| `native-payment-spent-v1` | Address seed | Marker addresses | `native_accounts.rs:30` |
| `z.cash:Orchard-MerkleCRH` | Sinsemilla personalization | Tree hash | `orchard` crate |

The network domain is a further separator: it is in every payment, every digest, the pool, the checkpoint history and the envelope.

## Appendix C. Errors

The protocol crate has one error type (`lib.rs:15-38`). The table says where each value arises in the rules above.

| Error | Arises in |
| --- | --- |
| `InvalidContext` | Fee and recipient rules (5.2, 5.3, 6.2); expiry more than 1,024 slots ahead (7, 12.2); domain field of a history or an envelope; header expiry of an envelope; a record for an earlier slot and a query before the newest checkpoint (9.2); a zero network domain when encoding or constructing |
| `UnsupportedVersion` | Unknown payment tag; tag or version of a history or an envelope; a payment without a fee inside an envelope; another bundle or circuit version; completing a slot of an `NPOOL003` pool |
| `InvalidShape` | Flags, action count, proof size |
| `Expired` | `expires_at` below the current slot (7, 12.2) |
| `WrongValueBalance` | Verification, check 5; encoding |
| `UnknownAnchor` | Verification, check 6 |
| `DuplicateNullifier` | Verification, check 7 |
| `SpentNullifier` | Verification, check 8 |
| `InvalidSpendAuthorization` | Verification, check 9 |
| `InvalidBindingSignature` | Verification, check 10 |
| `InvalidProof` | Verification, check 11 |
| `InvalidLength` | Size of a payment, an envelope, a history; proof length field; history length of a pool; the in-memory assembler |
| `InvalidChunk`, `IncompletePayload`, `SealedPayload`, `UnsealedPayload` | The in-memory assembler only (`staging.rs:19-73`) |
| `DigestMismatch` | Envelope identifier; the in-memory assembler |
| `InvalidEncoding` | Field elements and points; pool decoding; history entries; a commitment in the pool transition |
| `WrongNetwork` | Network field of a payment, a history or an envelope |
| `CapacityExceeded` | Pool transition: tree full, backing above `2^63 - 1` |
| `InsufficientBacking` | Pool transition: withdrawal above the backing |

The staging account has its own two errors (`native_accounts.rs:5-8`), `InvalidAccountData` and `InvalidInstructionData`, which the program passes on as the runtime errors of the same names. Section 13 gives the runtime error of every program rule.
