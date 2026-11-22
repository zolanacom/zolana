# Pool state hardening for the candidate's copy of the protocol

Status: **proposed, not built with the candidate toolchain, not running anywhere.**
The patch is kept under `drafts/` because it is not part of
`reconstruction-plan.json`; see "What has and has not been verified".

## Why

The candidate carries its own copy of the protocol library under
`zolana-native/protocol/src`. The workspace copy, `protocol/payments/src`,
gained two rules after its fuzz targets found pool states on which a slot could
not be completed ([protocol fuzz targets](../../../../docs/protocol-fuzzing.md)).
`seal_native_payment_slot` in the candidate's `runtime/src/bank.rs` completes a
slot inside `Bank::freeze` and panics when that is refused, so the copy the
validator is built from is the one that needs the rules most. This patch makes
the same change to it.

## What is here

| Path | What it is |
| --- | --- |
| `agave-4.3.2-pool-state-hardening.patch` | One file changed: `zolana-native/protocol/src/state.rs` |

The patch has no revision identifier yet. It takes the next one when it joins
the reconstruction plan.

### The patch

- `PoolState::with_payment` refuses a payment if either note is the empty
  leaf, with `InvalidEncoding`, for both pool formats.
- `PoolState::decode` refuses an `NPOOL004` state whose tree the next completed
  slot could not record: notes under the root of the empty tree, or a root that
  a stored checkpoint already holds for another note count.
- The existing test `compact_pool_exceeds_old_capacity_and_enforces_tree_limit`
  paid in empty leaves; it now pays in two ordinary notes.
- One new unit test,
  `refuses_empty_leaf_notes_and_trees_no_completed_slot_could_record`.

Every added and removed line is the same line as in the workspace copy: the
two files differed in 7 and 186 lines before the change and differ in the same
7 and 186 lines after it. No other file of the candidate is touched, and
`seal_native_payment_slot` still panics on a refusal;
[decision 0041](../../../../docs/decisions/0041-slot-completion-failure-handling.md)
is a draft of what it should do.

`zolana-native/protocol/src/state.rs` is added by the base patch and changed by
no later revision, so the patch applies to the source tree of any revision in
the plan.

| | bytes | sha256 |
| --- | --- | --- |
| `state.rs` before | 17994 | `3897cd6ca3a80e5ed767135f732c4697fde87fbd2bcdb8bf4940527ac659b81e` |
| `state.rs` after | 22062 | `51d7f679a842334157002703c433b3868449e5f4fe94836ace95951b2c5b06f4` |

## Does it change what a validator computes

For a pool state that the present rules can complete a slot on, and a payment
whose notes are not the empty leaf, nothing changes: the same bytes are
accepted, the same state results, and the same checkpoint is recorded.

The two rules differ from the present ones in these cases only:

- A payment with a note equal to the empty leaf was applied and is now
  refused. A valid proof is not expected to exist for such a payment: the
  circuit computes a note commitment as the x-coordinate of a curve point, and
  the empty leaf is not one.
- A pool account holding an `NPOOL004` state that no slot could record made
  `seal_native_payment_slot` panic at the checkpoint and now makes it panic one
  line earlier, at the decode. For the payment program the account was
  decodable and is now refused. Such a state is not left by any frozen block,
  because freezing a block records its tree.

A network on which no payment has carried the empty leaf therefore computes
the same bank hashes with and without the patch. That rests on the proof
system; a replay of an existing ledger with the patched validator is the check
that does not.

## What has and has not been verified

Done:

- the patch applies with `git apply --check` and `git apply` to a source tree
  reconstructed by `tools/reconstruct_native_candidate.py prepare` from the
  upstream archive and the pinned plan; `state.rs` had the "before" identity
  above and has the "after" identity afterwards, and no other file of the tree
  changed;
- the candidate's protocol crate, taken from that tree with the patch applied,
  compiles as a crate of its own and its 19 unit tests pass, with Rust 1.92 and
  the dependency versions of this repository's lock file;
- each of eight ways of weakening an added check in the patched file makes
  the new unit test fail, and each of two ways of widening one makes an
  existing unit test fail;
- the patched file is formatted as `rustfmt --edition 2024` leaves it.

Not done:

- no build with the candidate's pinned Rust 1.97.1 toolchain, its own
  `Cargo.lock` or its workspace, and no validator build;
- no validator, harness or runner test of the candidate was run;
- no replay of an existing ledger with a patched validator;
- the patch is not wired into `reconstruction-plan.json`, has no source
  manifest and no revision identifier.

## Remaining

1. Build the candidate with the patch on the build host and run its native
   test gate.
2. Replay a copy of an existing ledger with the patched validator and compare
   bank hashes.
3. Give the patch a revision identifier and a source manifest with the two
   identities above, add it to the reconstruction plan, and move it out of
   `drafts/`.
