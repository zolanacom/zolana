# A candidate revision that builds the workspace crates

Status: **proposed, not written as a patch, not built, not running anywhere.**
This directory holds no patch. It describes the candidate side of
[decision 0043](../../../../docs/decisions/0043-one-protocol-copy.md), option
(a), so that the change can be judged before anyone prepares it. Nothing in
`reconstruction-plan.json` refers to it.

## Why

The base patch adds its own text of the protocol library and of the native
program under `zolana-native/protocol/src` and `zolana-native/adapter/src`. The
workspace builds and tests `protocol/payments` and `node/adapter`. Since the
change described in decision 0043 the two programs apply the same rule to an
`NPOOL004` pool, but they are still two texts, and a correction made in one is
not made in the other.

## The revision

A new revision of the series would do three things.

1. **Stop carrying the two copies.** These twelve files leave the patched
   tree: `zolana-native/protocol/src/` `anchors.rs`, `envelope.rs`, `lib.rs`,
   `staging.rs`, `state.rs`, `verification.rs`, `wire.rs`, and
   `zolana-native/adapter/src/` `instructions.rs`, `lib.rs`, `nullifiers.rs`,
   `processor.rs`, `staging.rs`.
2. **Take the workspace files in their place**, byte for byte:
   `protocol/payments/src/` (the seven names above and `native_accounts.rs`)
   and `node/adapter/src/` (the five names above and
   `processor/finalization.rs`). They are produced by a tool from the
   repository at the revision's commit and are never edited in the patched
   tree. A check compares them with the workspace and accepts no difference.
   The workspace's two test files under `node/adapter/src/processor/` are
   written for the mock context of the older runtime; whether they are taken
   too is part of preparing the revision.
3. **Keep three files of its own**: the two crate manifests, and its variant
   of `processor/runtime_features.rs`, the binding file described next.

The hook in `runtime/src/bank.rs`, the feature in `feature-set` and
`svm-feature-set`, the registration in `builtins`, the admission module and
the candidate's harness tests are not part of this revision.

### The binding file

The workspace program is written against the Agave 3.0.14 runtime and the
candidate against 4.3.2. In the candidate's `processor.rs` nine call sites name
an interface that the older runtime spells differently. In the workspace
program all nine go through one function each of
`node/adapter/src/processor/runtime_features.rs`, so that this file is the only
one that differs between the two runtime lines:

| Function of the binding file | Call sites | In the candidate today (`agave-4.3.2.patch`) | In the workspace's file |
| --- | --- | --- | --- |
| `consume_compute_units(context, units)` | 1 | `context.compute_meter.consume_checked(..)`, line 3769 | `context.consume_checked(units)` |
| `sysvars(context)` | 3 | `context.environment_config.sysvar_cache()`, lines 3780, 3988, 4102 | `context.get_sysvar_cache()` |
| `invoke(context, instruction)` | 2 | `context.native_invoke_signed(instruction, &[])`, lines 4063, 4111 | `context.native_invoke(instruction, &[])` |
| `invoke_as_marker(context, instruction, marker, nullifier)` | 2 | `context.native_invoke_signed(instruction, &[signer_seeds])`, lines 4116, 4123 | `context.native_invoke(instruction, &[*marker])` |
| `slot_anchors(context)` | 1 | `context.get_feature_set().native_slot_anchors`, line 3907 | `false` |

The candidate's variant of the file would hold the middle column. Two points
need care when it is written:

- **The signer.** The older runtime is told the address the program signs
  for; the newer one is told the seeds. `invoke_as_marker` receives the
  marker's address and its nullifier. The candidate's variant has to build the
  seeds from the nullifier, as lines 4084-4095 of the base patch do today:
  the text `native-payment-spent-v1`, the pool address, the nullifier and the
  bump. Those seeds are also written in
  `protocol/payments/src/native_accounts.rs`, which gives the address and not
  the bump. If the variant's seeds were wrong, the runtime would derive
  another address than the one the System instruction names and refuse the
  invocation; it could not sign for a wrong account. The workspace's variant
  does not read the nullifier, so no test in the workspace shows that the
  right one is passed.
- **The types.** The workspace's functions return what the older runtime
  returns: a boxed error from the compute meter, a reference to the sysvar
  cache, an instruction error from an invocation. What the newer runtime's
  interfaces return is not recorded in this repository, which holds the
  candidate as a patch against an archive it does not contain. The callers
  use the results as the candidate's own text uses them (`.map_err(..)` on
  the charge, `.get_clock()?` and `.get_rent()?` on the cache, `?` on an
  invocation).

The variant has not been written or compiled. For the feature alone it would
be the candidate's present expression:

```rust
pub(super) fn slot_anchors(context: &InvokeContext) -> bool {
    context.get_feature_set().native_slot_anchors
}
```

## Does it change what a validator computes

The program: no. The two programs make the same checks in the same order with
the same errors; the candidate's program text has been run beside the
workspace's on the older runtime (below).

The protocol library: in the cases that the workspace copy already treats
differently from the candidate copy, and no others.

- Slot completion reuses the newest checkpoint's root when the note count has
  not changed, instead of computing it again. The bytes written are the same.
- The two rules of the
  [pool state hardening](../pool-state-hardening/README.md) apply. That
  document says which payments and pool accounts they affect. This revision
  would replace that draft, which patches the candidate copy by hand.

## What has and has not been verified

Done, outside this repository, with Rust 1.92 and the dependency versions of
this repository's lock file:

- the candidate's twelve files were taken from the pinned patch chain with Git
  patch application; no revision of the plan after the base patch changes
  them;
- the candidate's program compiles against the workspace's Agave 3.0.14
  runtime once the nine call sites are rewritten as in the table, with no
  other change, both linked to the candidate's own protocol copy and linked to
  the workspace's `protocol/payments` instead;
- in that form it was run beside the workspace program on the same accounts,
  instruction bytes, slots, compute budgets and feature switches, with real
  proofs, and no instruction gave a different result or left a different
  byte in any account; decision 0043 states what was compared and what was
  not.

Not done:

- the workspace program has not been compiled against the 4.3.2 runtime, and
  the binding file for it has not been written beyond the one function above.
  That the rest of the workspace program contains nothing else the newer
  runtime spells differently rests on a comparison of names: every method
  the workspace program calls on the runtime outside the binding file is
  also called in the candidate's own text. It has not been shown by a build;
- the workspace crates have not been built with the candidate's Rust 1.97.1
  toolchain, its `Cargo.lock` or its workspace manifest. The workspace
  protocol crate pins `solana-pubkey` 3.0.0 exactly, where the candidate's
  lock file has 4.3.0. The two functions it uses, `find_program_address` and
  `new_from_array`, are called by the candidate's program under 4.3.0 as
  well, but the crate has not been built there;
- no validator build, no harness or runner test of the candidate, no replay
  of an existing ledger;
- the tool that produces the files, the revision's patch, its source manifest
  and its plan entry do not exist.

## Remaining

1. Write the binding file for 4.3.2 and build the candidate with the
   workspace crates; run its native test gate, including
   `zolana-native/harness/tests/slot_anchors.rs`.
2. Replay a copy of an existing ledger and compare bank hashes.
3. Write the tool, the patch, the source manifest and the plan entry, give the
   revision an identifier, and remove this directory and the pool-state
   hardening draft.
