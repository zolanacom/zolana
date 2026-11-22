# Protocol fuzz targets and property tests

The `native-payments` crate decodes bytes that arrive from outside the node and keeps the state every payment changes. Two test files exercise it with generated input:

- `protocol/payments/tests/decoder_fuzz.rs`: one fuzz target for each decoder;
- `protocol/payments/tests/pool_properties.rs`: property tests for the pool state transition.

They are ordinary integration tests on the pinned stable toolchain, with no dependency that the crate did not already have. The generator is a small fixed algorithm in `protocol/payments/tests/support/mod.rs`, so a seed gives the same cases on every machine.

## What is checked

Each decoder target takes bytes and requires three things: the decoder does not panic; it accepts exactly the inputs that the reference statement of the format in `tests/support/reference.rs` accepts, size bounds included; whatever it accepts encodes back to the same bytes. The reference is written from the format, field by field, and shares no code with the decoders.

| Target | Decoder | Also checked |
| --- | --- | --- |
| `payment_decoder` | `wire::decode`, three tags | a wrong size is always refused as a length error; another network is refused |
| `payment_encoder_agrees_with_decoder` | `wire::encode` | the encoder refuses every context the decoder refuses; an accepted context comes back unchanged |
| `envelope_decoder` | `envelope::decode`, `envelope::encode` | the identity is the digest of the inner payment; expiry lies inside the window of the executing slot |
| `anchor_history_decoder` | `AnchorHistory::decode` | the eligible roots of a decoded history are those the slot rules give |
| `pool_state_decoder` | `PoolState::decode`, `NPOOL003` and `NPOOL004` | the decoded roots and checkpoints belong to the decoded tree; a decoded slot-anchored state completes a slot; a note equal to the empty leaf is refused; a payment and a completed slot leave a state that decodes |
| `staged_payload_and_buffer_decoder` | `StagedPayload`, `native_accounts::Buffer` | the in-memory assembler and the account buffer accept the same chunks; the account decodes after every instruction |
| `unstructured_bytes_reach_no_panic` | all of the above | bytes with a known tag and an exact size, and nothing else valid |

Inputs are valid encodings with one to three mutations (most of them aligned to fields), encodings assembled from parts that break one rule, and unstructured bytes.

The property test `pool_transition_keeps_its_invariants` runs random sequences of payments, completed slots, anchor queries and encode-decode reloads against a model, from fresh pools and from pools assembled a few payments below the tree limit or the backing limit. After every step:

- **Backing is conserved.** It moves by exactly the public value of an accepted payment and by nothing else, equals deposits less withdrawals, and stays between zero and the largest signed amount.
- **The note count is monotonic.** It never decreases and grows by two per accepted payment. The tree root equals that of an independent incremental Merkle tree.
- **Anchors come only from completed slots.** The roots a slot accepts are the roots recorded by slots completed before it and inside the window, plus the empty tree during the first window. The tree of the slot still executing is not among them.
- **A payment leaves a tree that a slot can record.** A note equal to the empty leaf is refused. After every accepted payment into a slot-anchored pool, the slot it executed in and later slots complete.
- **Capacity fails closed.** A full tree or a full backing refuses the payment. Every refused step leaves the state byte for byte unchanged.

`anchor_history_follows_the_slot_rules` checks the same slot rules on the history alone. Two tests do not depend on the random sequences: `capacity_fails_closed_at_every_limit` walks each limit, and `long_runs_rotate_the_recent_roots_and_the_slot_window` makes more payments than a legacy pool keeps roots and completes more slots than the window holds.

## Running

The workspace tests run every target at its built-in case count:

```sh
sh tools/dev.sh test --locked -p native-payments --test decoder_fuzz --test pool_properties -- --nocapture
```

Three environment variables change the run:

| Variable | Effect |
| --- | --- |
| `PROTOCOL_FUZZ_SCALE=4` | four times the built-in case count of every target |
| `PROTOCOL_FUZZ_SECONDS=60` | run every target for that long instead of counting cases |
| `PROTOCOL_FUZZ_SEED=7` | a different sequence of cases; the default seed is fixed |

With `--nocapture` each target prints its case count, how many inputs were accepted, the time taken and the seed. `tools/check.sh` and the checks workflow run the two files a second time with `PROTOCOL_FUZZ_SCALE=4`. The seed stays fixed there, so those runs repeat the same cases; use a new seed to explore.

## Reading a failure

A decoder target that fails prints the reason, the bytes that differ from the valid encoding the input was derived from, and the whole input in hexadecimal. Before printing, it puts bytes back to their valid value for as long as the failure remains, so what is left is the part that matters. A sequence test removes steps in the same way and prints the remaining steps. A failing target also names the case and the seed.

To keep a finding, add the printed input or steps as a test of its own that states the expected behaviour, mark it `#[ignore]` with a reference to this page if the behaviour is not being changed in the same commit, and describe it below.

## Findings and the hardening that followed

The first runs of these targets found two ways to reach a slot-anchored pool state on which `complete_slot` returned `InvalidEncoding`. Neither was a panic in this crate or an encoding that did not round-trip, and each refusal left the state unchanged. They mattered because of the caller: a validator completes the slot of every block it freezes, and a pool it cannot complete a slot on is a pool it cannot freeze a block with. Both had one cause, and both are now refused earlier.

**The cause.** Every unused position of the note tree holds a fixed value, the empty leaf. A note equal to that value is indistinguishable from an unused position, so a payment whose two notes are both the empty leaf raised the note count and left the root as it was. A checkpoint pairs a note count with a root, and the checkpoint rules allow one root for one note count only. The next completed slot therefore had to record the old root under a larger note count, or the root of the empty tree under a note count above zero, and was refused. The same states could also be written down directly and decoded.

**What was tightened.** Two rules, both in `protocol/payments/src/state.rs`:

1. `PoolState::with_payment` refuses a payment if either note is the empty leaf, with `InvalidEncoding`, for both pool formats. The check stands where a note that is not a field element is refused, after the capacity and backing checks, and a refused payment leaves the pool as it was.
2. `PoolState::decode` refuses an `NPOOL004` state whose tree the next completed slot could not record: a tree with notes that has the root of the empty tree, or a tree whose root a stored checkpoint, the newest or an older one, already holds for another note count. `NPOOL003` states complete no slots and decode as before.

A payment with a valid proof was never expected to carry the empty leaf. The circuit computes a note commitment as the x-coordinate of a curve point, and the empty leaf is not the x-coordinate of any point; `finding_payment_of_empty_leaves_leaves_a_completable_pool` asserts the second half of that. The pool state no longer depends on the first half.

**What follows from the two rules.** A slot-anchored state that decodes can complete a slot, at the slot of its newest checkpoint or any later one. A payment that is accepted adds two notes that are not the empty leaf, so the tree changes; the model in `pool_properties.rs` checks after every accepted payment that the slot it executed in, the next slot and the last possible slot all complete. The decoder target requires the same of every state it decodes and no longer sets any kind of state aside.

**Tests.** In `pool_properties.rs`:

| Test | States |
| --- | --- |
| `finding_decoded_state_with_reused_root_completes_a_slot`, `finding_decoded_state_with_empty_root_completes_a_slot`, `finding_payment_of_empty_leaves_leaves_a_completable_pool` | the three inputs as first recorded; each accepts a refusal or a completed slot |
| `a_note_equal_to_the_empty_leaf_is_refused_and_changes_nothing` | rule 1, either position, both formats, state unchanged |
| `a_stored_tree_whose_root_a_checkpoint_holds_for_another_count_is_refused`, `a_stored_tree_with_notes_and_the_empty_root_is_refused` | rule 2, each half on its own |
| `a_checkpoint_that_claims_a_later_root_still_refuses_slot_completion` | the limit described below |

`state.rs` has one unit test of its own for both rules, `refuses_empty_leaf_notes_and_trees_no_completed_slot_could_record`. The reference statement of the pool format in `tests/support/reference.rs` states rule 2 as one sentence: taken as the checkpoint the next slot would record, the tree is valid and agrees with every stored checkpoint.

**The cost.** Rule 2 needs the root of the tree, which is 32 hashes. The decoder already computed it for a state whose newest checkpoint is of the present tree. It now computes it for every `NPOOL004` state, so decoding a pool that has taken a payment since its newest checkpoint does that work where it did none before: every payment after the first in a slot, and the completion of a slot that had payments. Rule 1 is one comparison per note.

**What the two rules do not reach.** A state keeps the roots of its older checkpoints without the trees they came from, so decoding cannot tell whether such a root really is the root of a tree with that note count. A written-down state may therefore hold a checkpoint that claims the root the next payment will produce. `with_payment` accepts that payment and the slot is then refused, as before. The transition never writes such a state: a checkpoint is always the root of the tree it was taken from, and two different trees with one root would be a collision of the tree hash. `a_checkpoint_that_claims_a_later_root_still_refuses_slot_completion` records the behaviour, and the decoder target expects it exactly where a stored checkpoint already holds the new root. A caller of `complete_slot` or `with_completed_slot` still has to handle a refusal; [decision 0041](decisions/0041-slot-completion-failure-handling.md) is a draft of what the validator should do with one.

The validator candidate carries its own copy of `state.rs` in the patch series under `node/candidate`. The same two rules and the same unit test are prepared for that copy as a patch under [`node/candidate/drafts/pool-state-hardening`](../node/candidate/drafts/pool-state-hardening/README.md), which is not yet part of the reconstruction plan. Until it is, the candidate's copy has the earlier behaviour.

## What this does not cover

- No coverage-guided engine drives the targets. Each check is a function of a byte slice, so one can be added without rewriting them.
- Proof and signature verification (`verification.rs`) is not fuzzed; decoded payments carry random proofs and signatures that are never verified here.
- Only the `native-payments` crate of this workspace is exercised: not the native program's instruction decoding, and not any other copy of these formats. The candidate's copy of the pool state is covered by its own unit tests only.
- A property that holds for every generated case is not a proof, and none of this is an audit.
- The reference statements were written for the formats as they are. A deliberate format change needs the same change there.
