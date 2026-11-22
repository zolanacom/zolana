# Program-level differential run

This directory holds the harness behind the comparison that
[decision 0043](../../../docs/decisions/0043-one-protocol-copy.md) reports
under "Evidence and its limits": the native program of the candidate patch
series and the native program of the workspace, run side by side on the same
inputs. It is here so that the figures in that record can be produced again
from this tree.

It is not a member of the Cargo workspace and it is **not part of the
published checks** (`tools/check.sh`, the checks workflow), because it
compiles the vendored runtime in `node/agave`. Run it by hand.

## What it compares

`assemble.py` writes a scratch Cargo workspace with three builds of the native
program, all compiled against the Agave 3.0.14 runtime in `node/agave`:

| Build | Source | Changed for the run |
| --- | --- | --- |
| workspace | `node/adapter/src`, copied | one function body: `slot_anchors` in `processor/runtime_features.rs` reads the harness's switch instead of returning `false` |
| candidate | `zolana-native/adapter/src`, taken from the pinned patch chain of `reconstruction-plan.json` with `git apply`, the way `tools/protocol_copy_guard.py` takes it | the nine call sites that name an interface of the 4.3.2 runtime are rewritten to the 3.0.14 spelling, one of them the feature test, which reads the same switch. That takes eleven textual substitutions of seven kinds, because two of the invocations also derive their signer; the list, with the expected count of each, is `SUBSTITUTIONS` in `assemble.py` |
| registered | the crate `node/adapter` itself, as the runtime registers it | nothing |

The candidate build is linked to the candidate's own protocol library
(`zolana-native/protocol/src` from the same patch chain); the other two to
`protocol/payments`. The assembly stops unless every substitution matches
exactly the recorded number of times, and records the SHA-256 of every input
and output in the scratch workspace's `MANIFEST.json`.

`harness/tests/differential.rs` gives each build the same accounts,
instruction bytes, slot, compute budget and feature switches inside the
runtime's mock invocation context, and requires the same result, the same
bytes in every account and the same number of compute units left. The
registered build has no switch, so it is compared whenever the switch is off.
The end of a slot is performed on each side through its own protocol library
and must give the same bytes or the same refusal.

The inputs are a fixed list of edge cases (400 instructions) followed by
random walks from a seed: payments with real proofs staged and finalized,
slots completed and skipped, the feature switched on, staging accounts closed,
and finalizations altered in one respect (an account, a flag, a byte, the slot
or the compute budget). The same seed gives the same sequence on any machine.

Two variants change what the candidate build is made of:

- `--hardened` applies the
  [pool-state hardening draft](../drafts/pool-state-hardening/README.md) to
  the candidate's protocol library first;
- `--candidate-on-workspace-protocol` links the candidate's program to
  `protocol/payments` instead of its own library.

## What it cannot show

- **Nothing about the 4.3.2 runtime.** All builds run on the 3.0.14 runtime.
  The candidate's program is not run on the runtime it is written for, and
  the nine rewritten call sites are exactly the places where the two runtimes
  differ.
- **Not the hook that completes a slot.** The end of a slot is a transcription
  of the candidate's `seal_native_payment_slot` and the same steps on the
  workspace library; no Bank executes either.
- **Not activation of the feature.** The switch is a thread-local value set by
  the test, not a feature account.
- **Not a network, a block or a Bank.** One instruction at a time in the mock
  context.
- **Not a valid inline `NPOOL004` payment, and not a withdrawal to a named
  recipient.** The inline cases stop at the envelope, and only a Bank test
  reaches the recipient's rent check.
- **Not the pool accounts that only the two pool-state rules refuse.** When the
  two protocol libraries disagree on decoding a pool account, the case is
  counted and not compared; the count was 0 in every run below.
- **Not the workspace program before its runtime call sites moved into the
  binding file.** Decision 0043 also reports a fourth build of that earlier
  text, and an eighth negative control that changes it. That text was never
  committed to this repository, so this harness builds three programs and has
  seven controls.
- **Agreement, not correctness.** Two programs that are wrong in the same way
  agree. The run is a comparison of the cases it generated, not a proof about
  the ones it did not.

## How to run

Needs the pinned Rust toolchain, Python 3, Git, and the workspace's
dependencies fetched once with `sh tools/dev.sh fetch --locked`, as the
top-level README describes. The build is `--offline` and resolves from a copy
of the repository's `Cargo.lock`; every package it uses is one that lock file
already names, and no dependency is added. From the repository root:

```sh
sh node/candidate/differential/run.sh
```

That assembles and runs the four runs of the record, one after another, prints
their figures and compares them with `expected-figures.txt`. Other modes:

```sh
sh node/candidate/differential/run.sh quick      # one short run: seed 1, 3 walks
sh node/candidate/differential/run.sh controls   # the seven negative controls
```

Everything is written under `target/differential/`, which Git ignores, or
under `$DIFFERENTIAL_SCRATCH` if that is set: the assembled workspaces, the
build directory, and `logs/`. The assembled manifests name absolute paths of
the checkout, which is why none of them is kept in the tree. No tracked file
is modified. The first build compiles the vendored runtime and the
proof system; later runs reuse it. `CARGO_BUILD_JOBS` limits the build as
usual. The comparison itself runs on one thread, and the first of the four
runs is by far the longest: measured once on an Apple Silicon laptop, about
21 minutes for it and about 6 for each of the others, after the build.

To run one configuration by hand:

```sh
python3 -B node/candidate/differential/assemble.py --out target/differential/pinned
DIFFERENTIAL_SEED=7 DIFFERENTIAL_WALKS=50 sh tools/dev.sh test --offline \
    --manifest-path target/differential/pinned/Cargo.toml --target-dir target/differential/build \
    -p program-differential --test differential -- --nocapture
```

`DIFFERENTIAL_STEPS` (default 40) sets the length of a walk.

## Expected output

The default command ends with the figures of the four logs and the line
`figures equal expected-figures.txt`. The four runs:

| Log | Candidate build | Seed | Walks | Instructions compared | Of them also in the registered program |
| --- | --- | --- | --- | --- | --- |
| `pinned-candidate-seed1` | pinned patch chain | 1 | 1,000 | 259,126 | 26,343 |
| `pinned-candidate-seed2` | pinned patch chain | 2 | 250 | 65,746 | 6,126 |
| `hardened-candidate-seed3` | with the hardening draft | 3 | 250 | 65,818 | 7,868 |
| `candidate-program-on-workspace-protocol-seed4` | linked to `protocol/payments` | 4 | 250 | 66,114 | 6,554 |

Together 456,804 instructions, with no difference in any of them. The first
two runs are the "two runs of random sequences" of the record:

| Figure in decision 0043 | Value |
| --- | --- |
| instructions compared | 324,872 |
| finalizations | 26,870 |
| finalizations altered in one respect | 7,544 |
| unaltered finalizations accepted by every build | 2,230 |
| of them against an `NPOOL004` pool with the feature active | 1,151 |
| unaltered finalizations refused against an `NPOOL004` pool with the feature inactive | 1,304 |
| cases in which the registered program was run as well | 32,469 |
| ends of a slot compared | 16,874 |

`figures.py` computes these from the logs. `expected-figures.txt` also holds a
digest of each run's whole tally (the count of every pool format, feature
state, instruction and result), so equality with it means the same count for
every kind of case and not only the same totals.

Each log lists that tally. A run fails, and says which case differed, on the
first difference. It also fails if it did not reach the outcomes that make it
evidence: an accepted and a refused finalization against an `NPOOL004` pool
with the feature active, the refusal of such a pool with the feature inactive,
an accepted finalization against an `NPOOL003` pool in both states of the
feature, and a recorded slot.

`run.sh quick` compares 1,098 instructions, the 400 fixed edge cases among
them, 64 also in the registered program.

`run.sh controls` first requires the unchanged assembly to pass, then makes
one textual change to one assembled build at a time and requires the
comparison to fail. It ends with `7 of 7 deliberate differences detected`. The
changes are listed in `negative_controls.py`: the workspace copy asking for
the roots of the next slot, the candidate copy answering an inactive feature
with another error or not checking the feature, and the workspace's binding
file charging one compute unit more, reporting a refused charge as paid,
invoking for a marker without the program's signature, or dropping an
invocation.

## Files

| File | Purpose |
| --- | --- |
| `assemble.py` | Writes one scratch workspace. Standard library and `git apply`. |
| `harness/tests/differential.rs` | The comparison test. |
| `harness/Cargo.toml.in` | Its manifest, as a template with two path placeholders. |
| `run.sh` | The documented command and its two other modes. |
| `figures.py` | The figures of the record, from logs. Standard library. |
| `expected-figures.txt` | What `figures.py` prints for the four runs of the record. |
| `negative_controls.py` | The seven deliberate changes. Standard library. |

A change to `node/adapter/src`, to `protocol/payments` or to the pinned patch
chain can change the figures without being a fault: the walks depend on what
the programs accept. Then the run still has to pass, and
`expected-figures.txt` is replaced by the new output of `figures.py` in the
same change, with decision 0043 left as the record of the run it describes.
