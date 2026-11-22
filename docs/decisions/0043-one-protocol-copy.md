# One copy of the payment protocol and the native program

Status: draft for review. The changes described under "What the workspace program does now" and "The binding file" are implemented and tested in the workspace: they are steps 1 and 2 of the recommendation. Step 3, the candidate revision, is not written, and nothing here has been built with the candidate's toolchain.

## The situation

The repository holds the payment protocol and the native program twice.

- **The workspace copy** is `protocol/payments` and `node/adapter`. It is built against the Agave 3.0.14 runtime in `node/agave`, and every Rust test of the workspace runs against it.
- **The candidate copy** is the set of files that `node/candidate/agave-4.3.2.patch` adds under `zolana-native/protocol/src` and `zolana-native/adapter/src` of the Agave 4.3.2 candidate. The workspace does not build it. No later patch of the series changes either directory.

The slot-anchored pool format `NPOOL004` was a working rule in the candidate copy only. A pool in that format keeps one checkpoint per completed slot instead of the last 64 roots, and a payment may name the root of a completed slot of the last 512 slots. Three things make that a rule a validator follows, and before this change the workspace had none of them:

| | Candidate | Workspace before this change |
| --- | --- | --- |
| The program asks the pool for the roots accepted in the executing slot | `accepted_roots(slot)`, `node/candidate/agave-4.3.2.patch:4037-4039`; an error becomes `InvalidAccountData` | `roots()`, which is empty for `NPOOL004`: a payment that passed every other check ended in `InvalidInstructionData` for an unknown anchor |
| A feature decides whether an `NPOOL004` pool is usable at all | `native_slot_anchors`, identifier `SLOT_ANCHOR_ACTIVATION_ID` (`:3692-3696`); checked straight after the pool decodes, refusal is `InvalidAccountData` (`:3906-3909`) | no check, no identifier |
| The runtime records each completed slot in the pool | `seal_native_payment_slot`, called from `Bank::freeze` (`:1941`, `:1951-1973`) | nothing under `node/agave/runtime` refers to the payment program |

Everything else about an `NPOOL004` payment is the same in both copies: the instructions and their account lists (`instructions.rs` is the same file in both), the order of the other checks and their errors, the coin movement and the spent markers. For an `NPOOL003` pool `accepted_roots(slot)` returns the stored recent roots whatever the slot, so both programs read the same anchors.

## What the workspace program does now

The part of the rule that lives in the program is now in `node/adapter`:

- `SLOT_ANCHOR_ACTIVATION_ID` is defined in `node/adapter/src/lib.rs:41-45` with the candidate's bytes. No second identifier exists for the rule.
- Finalization refuses an `NPOOL004` pool with `InvalidAccountData` unless the feature is active, at the same place in the order of checks: after the pool decodes and before its balance is compared (`node/adapter/src/processor/finalization.rs:171-173`).
- Finalization takes the accepted anchors from `accepted_roots(slot)` and answers an error from it with `InvalidAccountData` (`finalization.rs:84-86`).

One thing could not be taken over as it stands. The candidate reads the feature from the runtime's feature set, `context.get_feature_set().native_slot_anchors`. The feature set of the 3.0.14 runtime in `node/agave` has no such switch (`node/agave/svm-feature-set/src/lib.rs:3-5` lists three native switches), and a Bank of that runtime looks for feature accounts only at the identifiers its own list names (`node/agave/runtime/src/bank.rs:5446`, `node/agave/feature-set/src/lib.rs:25`), so an account at this identifier activates nothing. The workspace program therefore asks one function, `slot_anchors` in `node/adapter/src/processor/runtime_features.rs`, called once per instruction (`node/adapter/src/processor.rs:25`), and for this runtime the function answers "not active". On a runtime that has the switch the function is the candidate's one expression.

The consequences, stated plainly:

- **The registered workspace program still accepts no `NPOOL004` payment.** No instruction against such a pool succeeded before, and none does now. What changed is the refusal: the program now refuses the pool itself, with the error and at the point at which the candidate refuses it while the feature is inactive, where before it went on and failed at a later check, at the latest for an unknown anchor.
- **`NPOOL003` is untouched.** The feature check does not apply to it, and the anchors it reads are the ones it read before. The existing tests pass unchanged, and a new test requires the same account bytes for the same three payments from the registered program, from the program told the feature is inactive, and from the program told it is active.
- **The accept and refuse decisions of the rule are tested in the workspace**, with the feature given to the program by the test and the end of a slot performed by the test. Both stand-ins are described below.

## The binding file

The workspace program is written against one runtime release and the candidate against another. Besides the feature, the candidate's `processor.rs` names four things of the runtime in words the 3.0.14 runtime does not have, at eight places. In the workspace program each of them is now one function of `node/adapter/src/processor/runtime_features.rs`, and the rest of the program calls these functions and never the runtime's own names:

| Function | On the 3.0.14 runtime | Called from | The candidate's words (`node/candidate/agave-4.3.2.patch`) |
| --- | --- | --- | --- |
| `consume_compute_units(context, units)` | `context.consume_checked(units)` | `processor.rs:40`, once | `context.compute_meter.consume_checked(..)`, line 3769 |
| `sysvars(context)` | `context.get_sysvar_cache()` | `processor.rs:52` (the slot), `finalization.rs:241` (rent of a recipient), `finalization.rs:320` (rent of a marker) | `context.environment_config.sysvar_cache()`, lines 3780, 3988, 4102 |
| `invoke(context, instruction)` | `context.native_invoke(instruction, &[])` | `finalization.rs:293` (a deposit into the pool), `finalization.rs:327` (the rent of a marker) | `context.native_invoke_signed(instruction, &[])`, lines 4063, 4111 |
| `invoke_as_marker(context, instruction, marker, nullifier)` | `context.native_invoke(instruction, &[*marker])` | `finalization.rs:332` (allocation), `finalization.rs:341` (assignment) | `context.native_invoke_signed(instruction, &[signer_seeds])`, lines 4116, 4123, with the seeds built at lines 4084-4095 |
| `slot_anchors(context)` | `false` | `processor.rs:25` | `context.get_feature_set().native_slot_anchors`, line 3907 |

The first four pass their arguments to the runtime and return its answer unchanged. Which units are charged and when, which sysvar is read, which instruction is invoked and what an error becomes are decided where the functions are called, in `processor.rs` and `finalization.rs`. Those two files no longer contain a word that one of the two releases lacks, so they are the text a candidate can compile as it stands; the binding file is the one file a second runtime line replaces.

`invoke_as_marker` takes two descriptions of the same thing. The 3.0.14 runtime is told the address a program signs for; the 4.3.2 runtime is told the seeds and derives the address. The function is given the marker's address and the nullifier it belongs to. On this runtime it uses the address and does not read the nullifier, so the invocations are the ones the program made before, with the same arguments. A binding file for the later runtime builds the seeds from the nullifier, as the candidate does today.

Nothing changes in what the program does on the 3.0.14 runtime. The three feature switches both releases have, `native_recipient_withdrawals`, `native_shielded_fees` and `native_inline_payments`, are read from the feature set with the same expression in both copies and stay where they were.

## The end-of-slot step

No transaction can record a completed slot. The candidate does it in the Bank:

1. `Bank::freeze` calls `seal_native_payment_slot` after the deferred account changes of the slot (fee distribution, slot history, the incinerator) and before the bank hash is computed. A second `freeze` of the same bank leaves the pool as it is; the candidate's own test requires that (`zolana-native/harness/tests/slot_anchors.rs`, added at `node/candidate/agave-4.3.2.patch:6138`).
2. The function returns at once unless `native_slot_anchors` is active in the bank's feature set.
3. It loads the pool account and returns unless the account exists and is owned by the program.
4. It decodes the account and stops the process if that fails.
5. It returns if the pool is not slot-anchored. Activating the feature never converts an `NPOOL003` pool.
6. It calls `PoolState::with_completed_slot` with the bank's slot, stops the process if that is refused, and stores the encoded result in the account. The account keeps its size and its balance.

Leaders and replaying validators both go through `freeze`, so the checkpoint is part of the state they must agree on. A slot in which no block is produced has no bank and gets no checkpoint. What the function should do instead of stopping the process is the subject of [decision 0041](0041-slot-completion-failure-handling.md).

That is the whole hook: one call and one function of about twenty lines in `runtime/src/bank.rs`, the two crates as dependencies of the runtime crate (`node/candidate/agave-4.3.2.patch:1929-1930`), and the feature in the two feature-set files (`:1710`, `:1721`, `:1732`, `:1779-1786`, `:1790`, `:2186`, `:2197`).

The workspace cannot run this hook: its runtime does not contain it, and this change does not touch `node/agave`. What the workspace can do, and now does in tests, is perform the same step through the protocol crate's public interface:

- `complete_slot_stand_in` in `node/adapter/src/processor/slot_anchor_tests.rs` decodes the pool account, calls `PoolState::complete_slot(slot)` and writes the result back, between two instructions of a test. It is labelled as a stand-in where it is defined and where the file begins.
- The same file runs the program with the state of the feature given, through two test entry points beside the registered one.

These tests show which payments the program accepts for a given pool account and slot. They do not show that any runtime completes a slot or activates the feature. A Bank test of an `NPOOL004` payment is not possible on this runtime without one of two things this change deliberately does not add: the feature in `node/agave`, or a public way to run the program with the feature forced on. The one Bank test added, `slot_anchored_pool_is_refused_and_gets_no_checkpoint_on_this_runtime` in `node/validator-check/tests/bank.rs`, pins the present state instead: with the feature account in genesis, the registered program refuses the pool, and freezing two blocks leaves the pool account byte for byte as it was.

## Options for one copy

### (a) The candidate builds the workspace crates

The candidate series stops carrying its own text of the two crates and compiles `protocol/payments` and `node/adapter` as they are in this repository.

| | |
| --- | --- |
| What changes | The workspace program is written against one runtime release and the candidate against another. Nine call sites of the program name an interface that the two releases spell differently: one compute-meter call, three reads of the sysvar cache, four invocations of the System program (two of which sign for a derived address), and the feature read. All nine are behind `runtime_features.rs` (see "The binding file"). A new revision of the series then removes the twelve source files of the two copies and takes the workspace files in their place, generated by a tool and never edited by hand. The candidate keeps three files of its own: its variant of the binding file, and the two crate manifests. [A draft](../../node/candidate/drafts/one-protocol-copy/README.md) lists the files and the call sites. |
| What breaks | Nothing in the workspace. In the candidate, the protocol library changes from its present text to the workspace's: slot completion reuses the previous root when the tree is unchanged, and the two pool-state rules of the hardening draft apply ([its README](../../node/candidate/drafts/pool-state-hardening/README.md) says when that changes a result). The new revision changes every source identity the reconstruction plan pins for these files, so it needs a build with the candidate's toolchain and its own tests before anything else. The workspace crates would be compiled there under the edition they are written for, with the candidate's dependency versions, which are not the workspace's in every case; whether that compiles and passes is not known until it is tried. |
| What a reviewer reads | One text of the protocol and of the program, in the workspace, with the workspace's tests; the candidate's binding file; and, in the patch, the hook and the feature lines. The 1,807 and 716 source lines of the two copies leave the patch. |
| Files touched | Workspace: none beyond this change, which touched `processor.rs`, `processor/finalization.rs` and `processor/runtime_features.rs`. Candidate: 12 source files removed from what the series carries, 3 kept (binding file, two manifests), and the reconstruction tool, its test, the plan and one source manifest for the new revision. |

The hook and its Bank tests stay where they are, in the candidate, built only by the candidate's toolchain.

### (b) The hook is added to the vendored runtime

The 3.0.14 runtime in `node/agave` gains the feature and the end-of-slot step.

| | |
| --- | --- |
| What changes | `svm-feature-set/src/lib.rs` and `feature-set/src/lib.rs` gain `native_slot_anchors` under the candidate's identifier; `runtime/src/bank.rs` gains the call in `freeze`, after `run_incinerator` at line 2495, and the function; `runtime/Cargo.toml` gains the two crates, which the runtime already reaches through its built-in programs. `runtime_features.rs` becomes the candidate's expression. The candidate's Bank tests of the seal can then be ported to `node/validator-check`, and Bank tests of `NPOOL004` payments written. |
| What breaks | The Bank test added by this change, by design: it pins that this runtime does neither. `SVMFeatureSet::all_enabled` would include the feature, so every mock-context test would run with it active; the `NPOOL003` tests are indifferent to it. Whether an account stored inside `freeze` is covered by the bank hash of this release in the same way as in 4.3.2 has to be shown by a test and is not assumed here. |
| What a reviewer reads | The rule, the feature and the hook in one tree that the workspace's checks build and test. But the tree is the 3.0.14 line, which runs no network that uses `NPOOL004`, and the hook would then exist twice: here and in the candidate. The two copies of the protocol and the program remain unless (a) is also done. |
| Files touched | 4 under `node/agave`, both lock files, `THIRD_PARTY.md`, 1 in `node/adapter`, 1 or 2 test files in `node/validator-check`. |

### (c) The workspace program is retired

`node/adapter` is removed and the candidate's copy becomes the only program.

| | |
| --- | --- |
| What changes | The crate has four dependents in this repository: the built-in registration in `node/agave/builtins`, `node/validator-check`, `node/localnet` and `clients/wallet`, which uses its identifiers and instruction builders. Each needs another source for what it takes from the crate, or is removed with it. |
| What breaks | The six Bank tests and the adapter's own tests go, and with the local network's payment program every fixture that runs a payment on the 3.0.14 local network. The program would then exist only as text inside a patch against an upstream archive that the repository does not contain, built by a toolchain the workspace does not use. The protocol library would still exist twice, because wallets are built from the workspace copy. |
| What a reviewer reads | The program in a reconstructed tree, outside what the published checks build. This is the present difficulty, made general. |
| Files touched | The crate `node/adapter` (8 source files and 1 test file), 4 manifests, `node/agave/builtins`, 18 Rust files outside the crate that name it, and the fixtures that depend on the local network. It becomes reasonable only together with a decision to replace the vendored 3.0.14 tree by a 4.3.2 tree that the workspace builds. |

## Recommendation

Adopt **(a)**, in three steps that can each be reviewed alone.

1. **The rule.** It is in the workspace program with tests; the candidate is unchanged. Done in this change.
2. **The binding file.** The other eight release-specific call sites of the workspace program are behind `runtime_features.rs`. No behaviour changes; the existing and the new tests are the check. Done in this change.
3. **A candidate revision** that drops its two copies, builds the workspace crates and keeps only its binding file and manifests. It is the first step that needs the candidate's build and tests, and the one that carries the faster slot completion and the pool-state rules into the candidate. Not started.

Reasons:

- It is the only option that ends with one text of each rule. (b) adds a second hook, and (c) keeps two protocol libraries.
- It makes the copy that is tested the copy that is built. The workspace copy is the newer one for the library and the one the published checks compile.
- It needs no change to `node/agave`, and no decision about the future of the 3.0.14 line.
- A change such as the two parts of decision 0041 then lands once: the refusal of a payment that would leave an uncompletable tree in the one protocol library, the handling of a refused completion in the one hook.

(b) is not recommended now. It would give the workspace Bank tests of the seal, at the price of maintaining the hook in a runtime line no network uses and keeping it equal to the candidate's by hand. It becomes the right step only if the 3.0.14 line is to remain the reference runtime. (c) is not a step towards one copy by itself.

Until step 3 the two copies remain, and a check that fails when they drift apart is still needed.

## Evidence and its limits

In the workspace, built against the 3.0.14 runtime:

- the adapter's unit tests in `slot_anchor_tests.rs` run real proofs through the finalizer for both pool formats and both states of the feature, including the first and last slot in which a root is accepted, the root of the empty tree, a checkpoint ahead of the executing slot, and the feature check on the inline instruction;
- its unit tests in `runtime_features_tests.rs` observe what the registered program asks of the runtime: the compute units charged to a staging instruction and to a finalization, to the unit, and that the charge comes before any check; the units left after a deposit and its seven invocations of the System program; the marker accounts the program signs for; the slot and the rent taken from the sysvar accounts. They pass unchanged on the program as it was before the binding file;
- the existing adapter and Bank tests, all of which use `NPOOL003`, pass unchanged;
- the Bank test named above pins the refusal and the absence of a checkpoint on this runtime.

Outside the repository, with tooling that is not part of it, so that this result cannot be repeated from this tree:

- **Each of 39 single changes to the program makes at least one unit test fail.** Thirteen are changes to the slot-anchor rule: removing, moving or weakening the feature check, the error codes, the slot passed to `accepted_roots`, the registered program's answer, and each of the two instructions ignoring the feature. Thirteen are changes to the binding file: no charge, one unit more or less, a double charge, a refused charge reported as paid and a paid one as refused, an empty sysvar cache, and an invocation dropped or made twice, without the program's signature or with it given for another address. Thirteen are changes at the call sites that moved: the units charged to a staging instruction and to the inline instruction, the error of a failed charge and whether it ends the instruction, the slot one higher or lower, the rent of a marker, a transfer left out or made when it is not needed, and the program's signature left out of an allocation or an assignment or given for another address.
With a harness that was outside the repository when this record was written and is now in `node/candidate/differential/`. It is not part of the repository's checks, because it compiles `node/agave`:

- **A differential run found no difference between the two programs, and none between the workspace program before and after the binding file.** The candidate's `zolana-native/adapter/src`, taken from the pinned patch chain, was compiled against the same 3.0.14 runtime beside the workspace program, with the nine call sites listed under option (a) rewritten to the older interface and nothing else changed, each program linked to its own copy of the protocol library. The workspace program as it was before its call sites moved into the binding file was compiled as a further build. All were given the same accounts, instruction bytes, slot, compute budget and feature switches, and had to return the same result, leave the same bytes in every account and leave the same number of compute units. The end of a slot was performed on each side through its own protocol copy and had to give the same bytes or the same refusal. Two runs of random sequences compared 324,872 instructions. Most of those are the instructions that stage a payment; 26,870 are finalizations, 7,544 of them altered in one respect: an account, a flag, a byte, the slot or the compute budget. Every build accepted the same 2,230 unaltered finalizations, 1,151 of them against an `NPOOL004` pool with the feature active, and refused the same 1,304 against an `NPOOL004` pool with the feature inactive. With the feature inactive the registered workspace program was run as well and agreed in all 32,469 cases. The end of a slot was compared 16,874 times. Two further runs, one with the pool-state hardening draft applied to the candidate's protocol copy and one with the candidate's program linked to the workspace's protocol crate, compared 65,818 and 66,114 instructions and found no difference either. The same four runs had been made before the call sites moved, without the further build and without the comparison of compute units, and gave the same count for every kind of case. Eight deliberate changes to one build each made a run fail. The harness in the repository builds three of these four programs. The workspace program as it was before the binding file was never committed, so that build, the comparison with it and the one deliberate change made to it are not repeated from this tree. Run from this tree, the four runs compare the same 259,126 and 65,746 instructions, which are the 324,872 above, and the same 65,818 and 66,114, 456,804 in all, with the same count for every kind of case; `expected-figures.txt` beside the harness holds them. Each of the other seven deliberate changes makes a run fail.

Not shown by any of this:

- the candidate's program on the 4.3.2 runtime it is written for, including what that runtime's invocation, metering and sysvar interfaces do;
- the workspace program compiled against the 4.3.2 runtime, and a binding file for that runtime;
- that the nullifier handed to `invoke_as_marker` is the right one: the 3.0.14 runtime does not read it;
- the hook itself, whose steps were transcribed for the differential run and not executed in a Bank;
- activation of the feature by an account, on either runtime;
- an `NPOOL004` payment through a Bank, a block or a network;
- a valid inline `NPOOL004` payment: the inline cases reach the feature check and stop at the envelope;
- a withdrawal to a named recipient in the differential runs or in the adapter's unit tests: only a Bank test reaches the recipient's rent check;
- the pool accounts that only the two pool-state rules refuse: none occurred in the differential runs.

## Not decided here

- Whether the binding file is selected by a build option or kept as a separate file per runtime line.
- Where the candidate's binding file takes the seeds of a marker from. Today the candidate's program writes them out beside the protocol library's own derivation; a function of the protocol library that returns the seeds with the bump would leave one text.
- How the candidate's build takes the workspace files: copied by the reconstruction tool, or carried by a generated patch that a check compares with the workspace byte for byte.
- Whether the candidate also takes the workspace's wallet crates, which have counterparts in the candidate that were not compared.
- The future of the 3.0.14 line.
