//! Property tests for the pool state transition.
//!
//! Random sequences of payments, completed slots, anchor queries and
//! encode-decode reloads run against a small model. After every step:
//!
//! - backing is conserved: it moves by exactly the public value of an accepted
//!   payment and by nothing else, and stays within its bounds;
//! - the note count never decreases, and grows by two per accepted payment;
//! - the tree root equals that of an independent incremental Merkle tree;
//! - a root is eligible as an anchor only if an earlier slot inside the window
//!   was completed with it, never the tree of the slot still executing;
//! - a note equal to the empty leaf is refused, and the tree an accepted
//!   payment leaves can be recorded by the slot it executed in;
//! - a full tree or a full backing refuses the payment, and every refused
//!   step leaves the state byte for byte unchanged.
//!
//! A failing sequence is reduced to the steps that matter before it is
//! reported. See `docs/protocol-fuzzing.md`.

mod support;

use incrementalmerkletree::{frontier::Frontier, Hashable, Level, Position};
use native_payments::{
    anchors::{AnchorHistory, ANCHOR_WINDOW_SLOTS, MAX_ANCHOR_HISTORY_BYTES, MAX_SLOT_ANCHORS},
    state::{PoolState, MAX_COMMITMENTS, MAX_ROOTS, SLOT_STATE_BYTES, STATE_BYTES},
    verification::VerifiedPayment,
    Error,
};
use orchard::tree::MerkleHashOrchard;
use std::{
    collections::{BTreeSet, VecDeque},
    panic::{catch_unwind, AssertUnwindSafe},
};
use support::{
    hex, reduce_steps,
    reference::{self, Entry, PoolParts},
    report, sparse, Budget, Rng, NETWORK,
};

type Tree = Frontier<MerkleHashOrchard, 32>;

macro_rules! check {
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            return Err(format!($($message)+));
        }
    };
}

/// Where a sequence begins. A start with notes already in the tree is decoded
/// from an assembled encoding, because appending four billion notes is not
/// an option; every note of such a tree is the same leaf.
#[derive(Clone, Debug)]
struct Start {
    slot_anchored: bool,
    note_count: u64,
    backing: u64,
    /// For a slot-anchored pool: a slot already completed with this tree.
    completed_slot: Option<u64>,
}

#[derive(Clone)]
enum Step {
    Pay {
        value: i64,
        commitments: [[u8; 32]; 2],
    },
    Complete {
        slot: u64,
    },
    Query {
        slot: u64,
    },
    Reload,
}

impl std::fmt::Debug for Step {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Step::Pay { value, commitments } => write!(
                formatter,
                "Pay {{ value: {value}, commitments: [{}, {}] }}",
                hex(&commitments[0]),
                hex(&commitments[1])
            ),
            Step::Complete { slot } => write!(formatter, "Complete {{ slot: {slot} }}"),
            Step::Query { slot } => write!(formatter, "Query {{ slot: {slot} }}"),
            Step::Reload => write!(formatter, "Reload"),
        }
    }
}

struct Model {
    slot_anchored: bool,
    backing: u64,
    note_count: u64,
    tree: Tree,
    root: [u8; 32],
    /// Legacy pools: the newest roots, oldest first.
    recent_roots: VecDeque<[u8; 32]>,
    /// Slot-anchored pools: the completed slots still inside the window.
    checkpoints: Vec<Entry>,
    opening_backing: u64,
    deposited: u128,
    withdrawn: u128,
}

#[derive(Default)]
struct Coverage {
    paid: u64,
    refused_full_tree: u64,
    refused_full_backing: u64,
    refused_overdraw: u64,
    refused_commitment: u64,
    refused_empty_leaf: u64,
    completed: u64,
    refused_slot: u64,
    queries: u64,
    reloads: u64,
}

fn open(start: &Start) -> (PoolState, Model) {
    let mut parts = PoolParts {
        network: NETWORK,
        rent_floor: 1_000,
        backing: start.backing,
        count: start.note_count,
        frontier: [[0; 32]; 32],
    };
    // A tree whose every note is the same leaf: the complete subtree of a
    // level then has one root, whichever part of the tree it covers.
    let leaf = MerkleHashOrchard::from_bytes(&[5; 32]).unwrap();
    let mut subtree = leaf;
    let mut ommers = Vec::new();
    for level in 0..32u8 {
        if (start.note_count >> level) & 1 == 1 {
            parts.frontier[usize::from(level)] = subtree.to_bytes();
        }
        if start.note_count > 0 && ((start.note_count - 1) >> level) & 1 == 1 {
            ommers.push(subtree);
        }
        subtree = MerkleHashOrchard::combine(Level::from(level), &subtree, &subtree);
    }
    let tree = if start.note_count == 0 {
        Tree::empty()
    } else {
        let last = Position::from(start.note_count - 1);
        Tree::from_parts(last, leaf, ommers).expect("valid frontier")
    };
    let root = tree.root().to_bytes();
    let checkpoints: Vec<Entry> = start
        .completed_slot
        .filter(|_| start.slot_anchored)
        .map(|slot| Entry {
            slot,
            note_count: start.note_count,
            root,
        })
        .into_iter()
        .collect();
    let fresh = start.note_count == 0 && start.backing == 0 && checkpoints.is_empty();
    let state = match (fresh, start.slot_anchored) {
        (true, true) => PoolState::new_slot_anchored(NETWORK, 1_000).unwrap(),
        (true, false) => PoolState::new(NETWORK, 1_000).unwrap(),
        (false, true) => PoolState::decode(
            &parts.encode_with_history(&reference::encode_history(NETWORK, &checkpoints)),
        )
        .expect("assembled slot-anchored state"),
        (false, false) => {
            PoolState::decode(&parts.encode_with_roots(&[root])).expect("assembled legacy state")
        }
    };
    let model = Model {
        slot_anchored: start.slot_anchored,
        backing: start.backing,
        note_count: start.note_count,
        tree,
        root,
        recent_roots: VecDeque::from([root]),
        checkpoints,
        opening_backing: start.backing,
        deposited: 0,
        withdrawn: 0,
    };
    (state, model)
}

/// The backing after a payment, or the refusal the transition must give.
fn backing_after(backing: u64, note_count: u64, payment: &VerifiedPayment) -> Result<u64, Error> {
    if note_count > MAX_COMMITMENTS - 2 {
        return Err(Error::CapacityExceeded);
    }
    let next = i128::from(backing) - i128::from(payment.public_value_balance);
    if next < 0 {
        return Err(Error::InsufficientBacking);
    }
    if next > i128::from(u64::MAX) {
        return Err(Error::InvalidLength);
    }
    if next > i128::from(i64::MAX) {
        return Err(Error::CapacityExceeded);
    }
    // Both notes are field elements, and neither is the empty leaf.
    if !payment
        .commitments
        .iter()
        .all(|commitment| reference::is_note(*commitment))
    {
        return Err(Error::InvalidEncoding);
    }
    Ok(next as u64)
}

fn payment(value: i64, commitments: [[u8; 32]; 2]) -> VerifiedPayment {
    VerifiedPayment {
        nullifiers: [[3; 32], [4; 32]],
        commitments,
        public_value_balance: value,
    }
}

fn entries(history: &AnchorHistory) -> Vec<Entry> {
    history
        .entries()
        .iter()
        .map(|entry| Entry {
            slot: entry.slot,
            note_count: entry.note_count,
            root: entry.root,
        })
        .collect()
}

/// What must hold between any two steps.
fn check_invariants(state: &PoolState, model: &Model) -> Result<(), String> {
    check!(
        state.backing == model.backing,
        "backing is {} where the payments so far leave {}",
        state.backing,
        model.backing
    );
    check!(
        u128::from(state.backing) + model.withdrawn
            == u128::from(model.opening_backing) + model.deposited,
        "backing is not the deposits less the withdrawals"
    );
    check!(
        state.backing <= i64::MAX as u64,
        "backing exceeds its bound"
    );
    check!(
        state.note_count() == model.note_count,
        "note count is {} after {} accepted notes",
        state.note_count(),
        model.note_count
    );
    check!(
        state.note_count() <= MAX_COMMITMENTS && state.note_count().is_multiple_of(2),
        "note count is odd or beyond the tree"
    );
    check!(
        state.network == NETWORK && state.rent_floor == 1_000,
        "a step changed the network or the rent floor"
    );
    if model.slot_anchored {
        let history = state
            .slot_anchors()
            .ok_or("the pool lost its checkpoints")?;
        check!(
            entries(history) == model.checkpoints,
            "checkpoints differ from the completed slots inside the window"
        );
        check!(
            history.entries().len() <= MAX_SLOT_ANCHORS
                && history.encode().len() <= MAX_ANCHOR_HISTORY_BYTES,
            "more checkpoints than the window holds"
        );
        check!(
            state.roots().is_empty(),
            "a slot-anchored pool served roots without a slot"
        );
    } else {
        let recent: BTreeSet<[u8; 32]> = model.recent_roots.iter().copied().collect();
        check!(
            state.roots() == recent,
            "recent roots differ from the last payments"
        );
        check!(
            state.roots().len() <= MAX_ROOTS,
            "more recent roots than the bound"
        );
        check!(
            state.slot_anchors().is_none(),
            "a legacy pool grew checkpoints"
        );
    }
    Ok(())
}

fn run(start: &Start, steps: &[Step], coverage: &mut Coverage) -> Result<(), String> {
    let (mut state, mut model) = open(start);
    check!(
        state.root() == model.root,
        "the opening root differs from the reference tree"
    );
    check_invariants(&state, &model)?;
    for (index, step) in steps.iter().enumerate() {
        let before = state.encode();
        let size = if model.slot_anchored {
            SLOT_STATE_BYTES
        } else {
            STATE_BYTES
        };
        check!(before.len() == size, "step {index}: the encoded size moved");
        let count_before = state.note_count();
        match step {
            Step::Pay { value, commitments } => {
                let payment = payment(*value, *commitments);
                let expected = backing_after(model.backing, model.note_count, &payment);
                match (state.with_payment(&payment), expected) {
                    (Ok(next), Ok(backing)) => {
                        check!(
                            i128::from(next.backing) - i128::from(state.backing)
                                == -i128::from(*value),
                            "step {index}: backing moved by something other than the payment"
                        );
                        check!(
                            next.note_count() == count_before + 2,
                            "step {index}: a payment did not add exactly two notes"
                        );
                        for commitment in commitments {
                            let leaf = MerkleHashOrchard::from_bytes(commitment).unwrap();
                            check!(model.tree.append(leaf), "the reference tree is full");
                        }
                        model.root = model.tree.root().to_bytes();
                        model.note_count += 2;
                        model.backing = backing;
                        if *value < 0 {
                            model.deposited += u128::from(value.unsigned_abs());
                        } else {
                            model.withdrawn += u128::from(value.unsigned_abs());
                        }
                        check!(
                            next.root() == model.root,
                            "step {index}: the root differs from the reference tree"
                        );
                        if model.slot_anchored {
                            check!(
                                next.slot_anchors() == state.slot_anchors(),
                                "step {index}: a payment changed the checkpoints"
                            );
                            // The slot the payment executed in, or any later
                            // one, can record the tree the payment leaves.
                            check!(
                                reference::tree_can_be_recorded(
                                    &model.checkpoints,
                                    model.note_count,
                                    model.root
                                ),
                                "step {index}: a payment left a tree that the rules for \
                                 checkpoints do not allow"
                            );
                            let newest = model.checkpoints.last().map_or(0, |entry| entry.slot);
                            let mut sealed = next.clone();
                            for slot in [newest, newest.saturating_add(1), u64::MAX] {
                                check!(
                                    sealed.complete_slot(slot) == Ok(()),
                                    "step {index}: a payment left a tree that slot {slot} \
                                     cannot record"
                                );
                            }
                        } else {
                            model.recent_roots.push_back(model.root);
                            if model.recent_roots.len() > MAX_ROOTS {
                                model.recent_roots.pop_front();
                            }
                        }
                        check!(
                            state.encode() == before,
                            "step {index}: applying a payment changed its input state"
                        );
                        state = next;
                        coverage.paid += 1;
                    }
                    (Err(actual), Err(expected)) => {
                        check!(
                            actual == expected,
                            "step {index}: refused with {actual}, expected {expected}"
                        );
                        match expected {
                            Error::CapacityExceeded if model.note_count > MAX_COMMITMENTS - 2 => {
                                coverage.refused_full_tree += 1
                            }
                            Error::CapacityExceeded => coverage.refused_full_backing += 1,
                            Error::InsufficientBacking => coverage.refused_overdraw += 1,
                            Error::InvalidEncoding
                                if commitments.contains(&reference::empty_leaf()) =>
                            {
                                coverage.refused_empty_leaf += 1
                            }
                            _ => coverage.refused_commitment += 1,
                        }
                    }
                    (Ok(_), Err(expected)) => {
                        return Err(format!(
                            "step {index}: accepted a payment that must be refused with {expected}"
                        ))
                    }
                    (Err(actual), Ok(_)) => {
                        return Err(format!(
                            "step {index}: refused a valid payment with {actual}"
                        ))
                    }
                }
            }
            Step::Complete { slot } => {
                let copy = state.with_completed_slot(*slot).map(|copy| copy.encode());
                check!(
                    state.encode() == before,
                    "step {index}: the copying form changed its input state"
                );
                let result = state.complete_slot(*slot);
                let newest = model.checkpoints.last().map(|entry| entry.slot);
                if !model.slot_anchored {
                    check!(
                        result == Err(Error::UnsupportedVersion) && copy.is_err(),
                        "step {index}: a legacy pool completed a slot"
                    );
                } else if newest.is_some_and(|newest| *slot < newest) {
                    check!(
                        result == Err(Error::InvalidContext) && copy.is_err(),
                        "step {index}: completed a slot before the newest checkpoint"
                    );
                    coverage.refused_slot += 1;
                } else {
                    check!(
                        result == Ok(()),
                        "step {index}: refused to complete slot {slot}"
                    );
                    model
                        .checkpoints
                        .retain(|entry| slot - entry.slot < ANCHOR_WINDOW_SLOTS);
                    if newest == Some(*slot) {
                        model.checkpoints.pop();
                    }
                    model.checkpoints.push(Entry {
                        slot: *slot,
                        note_count: model.note_count,
                        root: model.root,
                    });
                    check!(
                        copy == Ok(state.encode()),
                        "step {index}: the two forms of slot completion disagree"
                    );
                    check!(
                        state.root() == model.root,
                        "step {index}: completing a slot changed the tree"
                    );
                    coverage.completed += 1;
                }
            }
            Step::Query { slot } => {
                let result = state.accepted_roots(*slot);
                if !model.slot_anchored {
                    let recent: BTreeSet<[u8; 32]> = model.recent_roots.iter().copied().collect();
                    check!(
                        result == Ok(recent),
                        "step {index}: wrong legacy anchor set"
                    );
                } else if model
                    .checkpoints
                    .last()
                    .is_some_and(|entry| entry.slot > *slot)
                {
                    check!(
                        result == Err(Error::InvalidContext),
                        "step {index}: served anchors for a slot before the newest checkpoint"
                    );
                } else {
                    let eligible = reference::eligible_roots(&model.checkpoints, *slot);
                    let roots = result.map_err(|error| format!("step {index}: {error}"))?;
                    // The present tree is eligible only if an earlier slot
                    // inside the window was completed with exactly this tree.
                    // The root of the empty tree is left to the comparison
                    // below: the first window of the chain accepts it anyway.
                    let recorded = model.checkpoints.iter().any(|entry| {
                        entry.note_count == model.note_count
                            && entry.slot < *slot
                            && slot - entry.slot < ANCHOR_WINDOW_SLOTS
                    });
                    check!(
                        model.root == reference::empty_root()
                            || roots.contains(&model.root) == recorded,
                        "step {index}: slot {slot} accepts the root of a tree that no earlier \
                         completed slot recorded, or refuses one that was"
                    );
                    check!(
                        roots == eligible,
                        "step {index}: the anchors of slot {slot} are not the completed slots \
                         inside the window"
                    );
                }
                coverage.queries += 1;
            }
            Step::Reload => {
                check!(
                    reference::pool_state_is_valid(&before),
                    "step {index}: the transition reached a state the format does not allow"
                );
                let decoded = PoolState::decode(&before).map_err(|error| {
                    format!("step {index}: a reached state does not decode: {error}")
                })?;
                check!(
                    decoded.encode() == before,
                    "step {index}: a reached state decodes to a different state"
                );
                state = decoded;
                coverage.reloads += 1;
            }
        }
        check!(
            state.note_count() >= count_before,
            "step {index}: the note count decreased"
        );
        if !matches!(step, Step::Pay { .. }) {
            check!(
                state.note_count() == count_before && state.backing == model.backing,
                "step {index}: a step other than a payment moved notes or backing"
            );
        }
        check_invariants(&state, &model).map_err(|error| format!("step {index}: {error}"))?;
    }
    Ok(())
}

fn scenario(rng: &mut Rng) -> (Start, Vec<Step>) {
    let slot_anchored = rng.chance(2, 3);
    let start = Start {
        slot_anchored,
        note_count: match rng.below(6) {
            0 => MAX_COMMITMENTS - 2 * rng.below(4),
            1 => 2 * (1 + rng.below((1 << 31) - 1)),
            _ => 0,
        },
        backing: match rng.below(6) {
            0 => i64::MAX as u64 - rng.below(3),
            1 => rng.below(1_000),
            _ => 0,
        },
        completed_slot: (slot_anchored && rng.chance(1, 3)).then(|| rng.below(2_000)),
    };
    let mut backing = start.backing;
    let mut note_count = start.note_count;
    let mut newest = start.completed_slot;
    let first_slot = if rng.chance(1, 2) {
        0
    } else {
        rng.below(2_000)
    };
    let mut steps = Vec::new();
    for _ in 0..4 + rng.index(36) {
        let base = newest.unwrap_or(first_slot);
        match rng.below(10) {
            0..=4 => {
                let room = i64::MAX as u64 - backing;
                let value = match rng.below(13) {
                    0..=4 => -1 - rng.below(1_000) as i64,
                    5 => 1 + rng.below(backing.max(1)) as i64,
                    6 => backing as i64,
                    7 => backing.saturating_add(1).min(i64::MAX as u64) as i64,
                    8 => 0,
                    9 => -(room.max(1) as i64),
                    10 => (-(room as i128) - 1) as i64,
                    11 => i64::MIN,
                    _ => i64::MAX,
                };
                let mut commitments = [rng.field_element(), rng.field_element()];
                // Sometimes a note the pool must refuse: not a field element,
                // or the empty leaf in one position or in both.
                if rng.chance(1, 8) {
                    let at = rng.index(2);
                    match rng.below(4) {
                        0 => commitments[at] = [0xff; 32],
                        1 => {
                            commitments[at] = rng.array();
                            commitments[at][31] = 0xff;
                        }
                        2 => commitments[at] = reference::empty_leaf(),
                        _ => commitments = [reference::empty_leaf(); 2],
                    }
                }
                if let Ok(next) = backing_after(backing, note_count, &payment(value, commitments)) {
                    backing = next;
                    note_count += 2;
                }
                steps.push(Step::Pay { value, commitments });
            }
            5..=7 => {
                let slot = match rng.below(12) {
                    0..=5 => base.saturating_add(1),
                    6 => base,
                    7 => base.saturating_sub(1 + rng.below(3)),
                    8 => u64::MAX - rng.below(2) * rng.below(600),
                    _ => base.saturating_add(rng.pick(&[2, 5, 100, 510, 511, 512, 513, 2_000])),
                };
                if slot_anchored && newest.is_none_or(|newest| slot >= newest) {
                    newest = Some(slot);
                }
                steps.push(Step::Complete { slot });
            }
            8 => steps.push(Step::Query {
                slot: match rng.below(8) {
                    0 => base.saturating_sub(1),
                    1 => rng.below(3_000),
                    _ => base.saturating_add(rng.pick(&[0, 1, 2, 510, 511, 512, 513])),
                },
            }),
            _ => steps.push(Step::Reload),
        }
        // Ask about the anchors straight after most completed slots.
        if matches!(steps.last(), Some(Step::Complete { .. })) && rng.chance(2, 3) {
            let slot = newest.unwrap_or(base);
            steps.push(Step::Query {
                slot: slot.saturating_add(rng.pick(&[0, 1, 1, 511, 512])),
            });
        }
    }
    (start, steps)
}

fn attempt(start: &Start, steps: &[Step], coverage: &mut Coverage) -> Result<(), String> {
    match catch_unwind(AssertUnwindSafe(|| run(start, steps, coverage))) {
        Ok(result) => result,
        Err(_) => Err("the transition panicked".to_string()),
    }
}

/// Sequences in an ordinary test run; each costs a few thousand tree hashes.
const CASES: u64 = 150;

#[test]
fn pool_transition_keeps_its_invariants() {
    let mut budget = Budget::new("pool_transition", CASES);
    let mut coverage = Coverage::default();
    while let Some(mut rng) = budget.next_case() {
        let (start, steps) = scenario(&mut rng);
        let Err(first) = attempt(&start, &steps, &mut coverage) else {
            continue;
        };
        let minimal = reduce_steps(&steps, &|candidate| {
            attempt(&start, candidate, &mut Coverage::default()).is_err()
        });
        let reason = attempt(&start, &minimal, &mut Coverage::default())
            .err()
            .unwrap_or(first);
        panic!(
            "pool transition property failed: {reason}\n  start: {start:?}\n  steps: {minimal:#?}"
        );
    }
    budget.finish(format_args!("{} payments applied", coverage.paid));
    report(format!(
        "pool_transition: {} payments applied; refused: {} full tree, {} full backing, {} \
         overdrawn, {} bad commitment, {} empty leaf; {} slots completed, {} refused as \
         earlier; {} anchor queries; {} reloads",
        coverage.paid,
        coverage.refused_full_tree,
        coverage.refused_full_backing,
        coverage.refused_overdraw,
        coverage.refused_commitment,
        coverage.refused_empty_leaf,
        coverage.completed,
        coverage.refused_slot,
        coverage.queries,
        coverage.reloads
    ));
    if budget.cases_run() >= CASES {
        for reached in [
            coverage.paid,
            coverage.refused_full_tree,
            coverage.refused_full_backing,
            coverage.refused_overdraw,
            coverage.refused_commitment,
            coverage.refused_empty_leaf,
            coverage.completed,
            coverage.refused_slot,
            coverage.queries,
            coverage.reloads,
        ] {
            assert!(reached > 0, "a kind of step was never exercised");
        }
    }
}

/// The limits, without relying on the random sequences to reach them.
#[test]
fn capacity_fails_closed_at_every_limit() {
    let coverage = &mut Coverage::default();
    let leaves = [[1; 32], [2; 32]];
    for slot_anchored in [false, true] {
        for room in [0u64, 2, 4, 6] {
            let start = Start {
                slot_anchored,
                note_count: MAX_COMMITMENTS - room,
                backing: 0,
                completed_slot: slot_anchored.then_some(7),
            };
            let mut steps = vec![Step::Reload];
            for _ in 0..room / 2 + 2 {
                steps.push(Step::Pay {
                    value: -5,
                    commitments: leaves,
                });
                steps.push(Step::Complete { slot: 8 });
                steps.push(Step::Query { slot: 9 });
                steps.push(Step::Reload);
            }
            assert_eq!(run(&start, &steps, coverage), Ok(()));
            // Exactly the payments that fit were applied.
            let (mut state, _) = open(&start);
            for _ in 0..room / 2 {
                state = state.with_payment(&payment(-5, leaves)).unwrap();
            }
            assert_eq!(state.note_count(), MAX_COMMITMENTS);
            assert_eq!(state.backing, 5 * (room / 2));
            let full = state.encode();
            for value in [-5, 0, 5] {
                assert_eq!(
                    state.with_payment(&payment(value, leaves)).err(),
                    Some(Error::CapacityExceeded)
                );
            }
            assert_eq!(state.encode(), full);
        }
        // Backing stops at the largest signed amount and at zero.
        let start = Start {
            slot_anchored,
            note_count: 0,
            backing: i64::MAX as u64 - 1,
            completed_slot: None,
        };
        let pay = |value| Step::Pay {
            value,
            commitments: leaves,
        };
        let steps = [
            pay(-2),
            pay(i64::MIN),
            pay(-1),
            pay(-1),
            pay(0),
            pay(i64::MAX),
            pay(1),
            pay(-1),
            Step::Reload,
        ];
        assert_eq!(run(&start, &steps, coverage), Ok(()));
    }
    assert_eq!(coverage.refused_full_tree, 2 * 4 * 2);
    assert_eq!(coverage.refused_full_backing, 2 * 3);
    assert_eq!(coverage.refused_overdraw, 2);
}

/// Runs long enough to fill and rotate both stores of anchors: more payments
/// than a legacy pool keeps roots, more slots than the window holds.
#[test]
fn long_runs_rotate_the_recent_roots_and_the_slot_window() {
    let coverage = &mut Coverage::default();
    let pay = |seed: u8| Step::Pay {
        value: -1,
        commitments: [[seed & 0x3f; 32], [seed.wrapping_add(1) & 0x3f; 32]],
    };
    let legacy = Start {
        slot_anchored: false,
        note_count: 0,
        backing: 0,
        completed_slot: None,
    };
    let mut steps = Vec::new();
    for index in 0..MAX_ROOTS as u8 + 6 {
        steps.push(pay(index));
        steps.push(Step::Query { slot: 0 });
        if index % 16 == 0 {
            steps.push(Step::Reload);
        }
    }
    assert_eq!(run(&legacy, &steps, coverage), Ok(()));

    let slot_anchored = Start {
        slot_anchored: true,
        ..legacy
    };
    let mut steps = Vec::new();
    for slot in 0..MAX_SLOT_ANCHORS as u64 + 90 {
        if slot % 61 == 5 {
            steps.push(pay(slot as u8));
            steps.push(Step::Query { slot });
        }
        steps.push(Step::Complete { slot });
        steps.push(Step::Query { slot: slot + 1 });
        if slot % 100 == 99 {
            steps.push(Step::Reload);
        }
    }
    steps.push(Step::Query {
        slot: MAX_SLOT_ANCHORS as u64 + 89 + ANCHOR_WINDOW_SLOTS,
    });
    assert_eq!(run(&slot_anchored, &steps, coverage), Ok(()));
    assert_eq!(coverage.completed, MAX_SLOT_ANCHORS as u64 + 90);

    let records: Vec<Record> = (0..MAX_SLOT_ANCHORS as u64 + 90)
        .map(|slot| Record {
            slot,
            note_count: 2 * (slot / 7),
            root: if slot < 7 {
                reference::empty_root()
            } else {
                let mut root = [0; 32];
                root[..8].copy_from_slice(&(slot / 7).to_le_bytes());
                root
            },
        })
        .collect();
    let mut accepted = 0;
    assert_eq!(run_records(&records, &mut accepted), Ok(()));
    assert_eq!(accepted, records.len() as u64);
}

// ---------------------------------------------------------------------------
// The slot anchor history on its own

#[derive(Clone)]
struct Record {
    slot: u64,
    note_count: u64,
    root: [u8; 32],
}

impl std::fmt::Debug for Record {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Record {{ slot: {}, note_count: {}, root: {} }}",
            self.slot,
            self.note_count,
            hex(&self.root)
        )
    }
}

fn run_records(records: &[Record], accepted: &mut u64) -> Result<(), String> {
    let mut history = AnchorHistory::new(NETWORK).map_err(|error| error.to_string())?;
    let mut model: Vec<Entry> = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let next = Entry {
            slot: record.slot,
            note_count: record.note_count,
            root: record.root,
        };
        let allowed = reference::entry_is_valid(&next)
            && model.last().is_none_or(|newest| {
                next.slot >= newest.slot && reference::entries_agree(newest, &next)
            })
            && model
                .iter()
                .all(|entry| entry.root != next.root || entry.note_count == next.note_count);
        let before = history.encode();
        let result = history.record(record.slot, record.note_count, record.root);
        check!(
            result.is_ok() == allowed,
            "step {index}: record returned {result:?}"
        );
        if allowed {
            model.retain(|entry| next.slot - entry.slot < ANCHOR_WINDOW_SLOTS);
            if model.last().is_some_and(|entry| entry.slot == next.slot) {
                model.pop();
            }
            model.push(next);
            *accepted += 1;
        } else {
            check!(
                history.encode() == before,
                "step {index}: a refused record changed the history"
            );
        }
        check!(
            entries(&history) == model,
            "step {index}: the history is not the completed slots inside the window"
        );
        check!(
            reference::history_is_valid(&model),
            "step {index}: the history broke a storage rule"
        );
        let bytes = history.encode();
        check!(
            bytes == reference::encode_history(NETWORK, &model)
                && bytes.len() <= MAX_ANCHOR_HISTORY_BYTES,
            "step {index}: unexpected encoding"
        );
        check!(
            AnchorHistory::decode(NETWORK, &bytes).as_ref() == Ok(&history),
            "step {index}: a reached history does not decode to itself"
        );
        let newest = model.last().map_or(0, |entry| entry.slot);
        for slot in [newest, newest.saturating_add(1), newest.saturating_add(511)] {
            check!(
                history.roots_at(slot) == Ok(reference::eligible_roots(&model, slot)),
                "step {index}: wrong eligible roots at slot {slot}"
            );
        }
        check!(
            newest == 0 || history.roots_at(newest - 1).is_err(),
            "step {index}: served roots for a slot before the newest checkpoint"
        );
    }
    Ok(())
}

#[test]
fn anchor_history_follows_the_slot_rules() {
    let mut budget = Budget::new("anchor_history_records", 20_000);
    let mut accepted = 0;
    while let Some(mut rng) = budget.next_case() {
        let mut records: Vec<Record> = Vec::new();
        // What the newest accepted record holds, as far as the generator can
        // tell; `run_records` decides for itself what must be accepted.
        let mut newest_slot = rng.below(1_000);
        let mut note_count = 0;
        let mut root = reference::empty_root();
        let mut replaced: Vec<[u8; 32]> = Vec::new();
        for _ in 0..1 + rng.index(48) {
            let mut record = Record {
                slot: match rng.below(16) {
                    0 => newest_slot,
                    1 => newest_slot.saturating_sub(1 + rng.below(3)),
                    2 => newest_slot + rng.pick(&[2, 100, 510, 511, 512, 513]),
                    _ => newest_slot + 1,
                },
                note_count,
                root,
            };
            if rng.chance(1, 2) {
                record.note_count += 2 * (1 + rng.below(3));
                record.root = rng.field_element();
            }
            if rng.chance(1, 5) {
                match rng.below(9) {
                    0 => record.note_count ^= 1,
                    1 => record.note_count = record.note_count.saturating_sub(2),
                    2 => record.note_count += 2,
                    3 => record.root = rng.field_element(),
                    4 if !replaced.is_empty() => record.root = rng.pick(&replaced),
                    5 => record.root = [0; 32],
                    6 => record.root = [0xff; 32],
                    7 => record.root = reference::empty_root(),
                    _ => record.note_count = MAX_COMMITMENTS + 2 * rng.below(2),
                }
            }
            let plausible = record.slot >= newest_slot
                && record.note_count >= note_count
                && (record.note_count == note_count) == (record.root == root)
                && !replaced.contains(&record.root)
                && reference::entry_is_valid(&Entry {
                    slot: record.slot,
                    note_count: record.note_count,
                    root: record.root,
                });
            if plausible {
                if record.root != root {
                    replaced.push(root);
                }
                newest_slot = record.slot;
                note_count = record.note_count;
                root = record.root;
            }
            records.push(record);
        }
        let Err(first) = run_records(&records, &mut accepted) else {
            continue;
        };
        let minimal = reduce_steps(&records, &|candidate| {
            run_records(candidate, &mut 0).is_err()
        });
        let reason = run_records(&minimal, &mut 0).err().unwrap_or(first);
        panic!("anchor history property failed: {reason}\n  records: {minimal:#?}");
    }
    budget.finish(format_args!("{accepted} records accepted"));
    assert!(accepted > 0);
}

// ---------------------------------------------------------------------------
// Trees that no completed slot could record
//
// The fuzz targets found two ways to reach a slot-anchored state on which
// slot completion was refused. The first three tests are those inputs as they
// were recorded, each accepting either remedy: the input is refused, or the
// slot completes. The tests after them state the remedy that was chosen.
// `docs/protocol-fuzzing.md` describes both.

/// A slot-anchored state whose newest checkpoint carries the root of the
/// present tree under a smaller note count.
#[test]
fn finding_decoded_state_with_reused_root_completes_a_slot() {
    let mut parts = PoolParts {
        network: NETWORK,
        rent_floor: 0,
        backing: 0,
        count: 4,
        frontier: [[0; 32]; 32],
    };
    parts.frontier[2][0] = 1;
    let root = reference::tree_root(4, &parts.frontier).unwrap();
    let stale = Entry {
        slot: 0,
        note_count: 2,
        root,
    };
    let bytes = parts.encode_with_history(&reference::encode_history(NETWORK, &[stale]));
    let Ok(mut state) = PoolState::decode(&bytes) else {
        return; // Refusing the state is the other acceptable outcome.
    };
    assert_eq!(state.complete_slot(1), Ok(()), "input: {}", sparse(&bytes));
}

/// A slot-anchored state that holds notes while its tree still has the root
/// of the empty tree, which a checkpoint may never record.
#[test]
fn finding_decoded_state_with_empty_root_completes_a_slot() {
    let mut parts = PoolParts {
        network: NETWORK,
        rent_floor: 0,
        backing: 0,
        count: 2,
        frontier: [[0; 32]; 32],
    };
    parts.frontier[1] = MerkleHashOrchard::empty_root(Level::from(1)).to_bytes();
    assert_eq!(
        reference::tree_root(2, &parts.frontier),
        Some(reference::empty_root())
    );
    let bytes = parts.encode_with_history(&reference::encode_history(NETWORK, &[]));
    let Ok(mut state) = PoolState::decode(&bytes) else {
        return; // Refusing the state is the other acceptable outcome.
    };
    assert_eq!(state.complete_slot(0), Ok(()), "input: {}", sparse(&bytes));
}

/// The same state reached through the transition: a payment whose two
/// commitments are the empty leaf, applied to a fresh pool.
#[test]
fn finding_payment_of_empty_leaves_leaves_a_completable_pool() {
    let empty_leaf = MerkleHashOrchard::empty_leaf().to_bytes();
    // No curve point has the empty leaf as its x-coordinate, and the circuit
    // computes a commitment as the x-coordinate of a point, so a payment with
    // a valid proof does not carry this value. The pool does not rely on it.
    assert!(!reference::is_point(empty_leaf));
    let fresh = PoolState::new_slot_anchored(NETWORK, 0).unwrap();
    let Ok(mut state) = fresh.with_payment(&payment(-1, [empty_leaf; 2])) else {
        return; // Refusing the payment is the other acceptable outcome.
    };
    assert_eq!(state.complete_slot(0), Ok(()));
}

/// A slot-anchored pool that has completed slot 1 with two notes in its tree.
fn pool_with_two_recorded_notes() -> PoolState {
    let mut state = PoolState::new_slot_anchored(NETWORK, 1_000)
        .unwrap()
        .with_payment(&payment(-1, [[1; 32], [2; 32]]))
        .unwrap();
    state.complete_slot(1).unwrap();
    state
}

/// The chosen remedy on the transition side: a note equal to the empty leaf
/// is refused in either position and in both formats, and the refusal leaves
/// the state byte for byte as it was.
#[test]
fn a_note_equal_to_the_empty_leaf_is_refused_and_changes_nothing() {
    let empty_leaf = reference::empty_leaf();
    assert_eq!(empty_leaf, MerkleHashOrchard::empty_leaf().to_bytes());
    let legacy = PoolState::new(NETWORK, 1_000)
        .unwrap()
        .with_payment(&payment(-1, [[1; 32], [2; 32]]))
        .unwrap();
    for state in [
        PoolState::new(NETWORK, 1_000).unwrap(),
        legacy,
        PoolState::new_slot_anchored(NETWORK, 1_000).unwrap(),
        pool_with_two_recorded_notes(),
    ] {
        let before = state.encode();
        for commitments in [
            [empty_leaf; 2],
            [empty_leaf, [5; 32]],
            [[5; 32], empty_leaf],
        ] {
            // The value moved does not matter: a deposit, nothing, and a
            // withdrawal the backing covers are refused alike.
            for value in [-7, 0, state.backing as i64] {
                assert_eq!(
                    state.with_payment(&payment(value, commitments)).err(),
                    Some(Error::InvalidEncoding)
                );
            }
        }
        assert_eq!(state.encode(), before);
        assert_eq!(PoolState::decode(&before).unwrap().encode(), before);
        // The neighbouring field elements are ordinary notes.
        let mut above = empty_leaf;
        above[0] += 1;
        let mut below = empty_leaf;
        below[0] -= 1;
        let next = state.with_payment(&payment(-1, [above, below])).unwrap();
        assert_eq!(next.note_count(), state.note_count() + 2);
    }
}

/// The chosen remedy on the decoding side, for the tree that a payment of two
/// empty leaves used to leave: more notes under a root that a checkpoint
/// already holds for fewer. The state is refused wherever the checkpoint that
/// holds the root sits in the history.
#[test]
fn a_stored_tree_whose_root_a_checkpoint_holds_for_another_count_is_refused() {
    let recorded = pool_with_two_recorded_notes();
    let root = recorded.root();
    // Four notes: the two recorded ones and two empty leaves.
    let mut parts = PoolParts {
        network: NETWORK,
        rent_floor: 1_000,
        backing: 1,
        count: 4,
        frontier: [[0; 32]; 32],
    };
    let two_notes = MerkleHashOrchard::combine(
        Level::from(0),
        &MerkleHashOrchard::from_bytes(&[1; 32]).unwrap(),
        &MerkleHashOrchard::from_bytes(&[2; 32]).unwrap(),
    );
    parts.frontier[2] = MerkleHashOrchard::combine(
        Level::from(1),
        &two_notes,
        &MerkleHashOrchard::empty_root(Level::from(1)),
    )
    .to_bytes();
    assert_eq!(reference::tree_root(4, &parts.frontier), Some(root));
    let holder = Entry {
        slot: 1,
        note_count: 2,
        root,
    };
    let first = Entry {
        slot: 0,
        note_count: 0,
        root: reference::empty_root(),
    };
    for history in [vec![holder], vec![first, holder]] {
        let bytes = parts.encode_with_history(&reference::encode_history(NETWORK, &history));
        assert_eq!(
            reference::slot_anchored_tree_is_recordable(&bytes),
            Some(false)
        );
        assert_eq!(
            PoolState::decode(&bytes).err(),
            Some(Error::InvalidEncoding)
        );
    }
    // Two more empty leaves keep the root once more. The checkpoint that holds
    // it is then no longer the newest one, and the state is refused all the same.
    let mut six = PoolParts {
        count: 6,
        frontier: parts.frontier,
        ..parts
    };
    six.frontier[1] = MerkleHashOrchard::empty_root(Level::from(1)).to_bytes();
    assert_eq!(reference::tree_root(6, &six.frontier), Some(root));
    let newest = Entry {
        slot: 2,
        note_count: 4,
        root: [9; 32],
    };
    let bytes = six.encode_with_history(&reference::encode_history(NETWORK, &[holder, newest]));
    assert_eq!(
        reference::slot_anchored_tree_is_recordable(&bytes),
        Some(false)
    );
    assert_eq!(
        PoolState::decode(&bytes).err(),
        Some(Error::InvalidEncoding)
    );
    // The same tree decodes once no checkpoint claims its root for two notes,
    // and the next slot then records it.
    let bytes = parts.encode_with_history(&reference::encode_history(NETWORK, &[first]));
    let mut state = PoolState::decode(&bytes).unwrap();
    assert_eq!(state.complete_slot(2), Ok(()));
    // With the two notes alone the recorded state itself still decodes.
    assert!(PoolState::decode(&recorded.encode()).is_ok());
}

/// The chosen remedy on the decoding side for notes under the root of the
/// empty tree. Only the slot-anchored format completes slots, and only it
/// refuses such a tree.
#[test]
fn a_stored_tree_with_notes_and_the_empty_root_is_refused() {
    for count in [2u64, 4, 6, 1 << 20, MAX_COMMITMENTS] {
        let mut parts = PoolParts {
            network: NETWORK,
            rent_floor: 1_000,
            backing: 0,
            count,
            frontier: [[0; 32]; 32],
        };
        for level in 0..32u8 {
            if (count >> level) & 1 == 1 {
                parts.frontier[usize::from(level)] =
                    MerkleHashOrchard::empty_root(Level::from(level)).to_bytes();
            }
        }
        assert_eq!(
            reference::tree_root(count, &parts.frontier),
            Some(reference::empty_root())
        );
        let first = Entry {
            slot: 0,
            note_count: 0,
            root: reference::empty_root(),
        };
        for history in [vec![], vec![first]] {
            let bytes = parts.encode_with_history(&reference::encode_history(NETWORK, &history));
            assert_eq!(
                reference::slot_anchored_tree_is_recordable(&bytes),
                Some(false)
            );
            assert_eq!(
                PoolState::decode(&bytes).err(),
                Some(Error::InvalidEncoding)
            );
        }
        let legacy = parts.encode_with_roots(&[reference::empty_root()]);
        assert!(PoolState::decode(&legacy).is_ok());
    }
    // A pool without notes has the root of the empty tree and decodes.
    let fresh = PoolState::new_slot_anchored(NETWORK, 1_000).unwrap();
    assert!(PoolState::decode(&fresh.encode()).is_ok());
}

/// What the two rules do not reach. The state keeps the roots of its older
/// checkpoints without the trees they came from, so decoding cannot tell
/// whether such a root is the root of a tree with that note count. A stored
/// checkpoint may therefore claim the root that the next payment will
/// produce. The transition never writes such a state, since a checkpoint is
/// always the root of the tree it was taken from. If one is decoded, the
/// payment applies and slot completion is refused, leaving the state as it
/// was: the caller has to handle that refusal.
#[test]
fn a_checkpoint_that_claims_a_later_root_still_refuses_slot_completion() {
    let mut parts = PoolParts {
        network: NETWORK,
        rent_floor: 1_000,
        backing: 0,
        count: 4,
        frontier: [[0; 32]; 32],
    };
    parts.frontier[2] = [7; 32];
    let notes = [[5; 32], [6; 32]];
    // The tree after the next payment: six notes.
    let mut later = PoolParts {
        count: 6,
        frontier: parts.frontier,
        ..parts
    };
    later.frontier[1] = MerkleHashOrchard::combine(
        Level::from(0),
        &MerkleHashOrchard::from_bytes(&notes[0]).unwrap(),
        &MerkleHashOrchard::from_bytes(&notes[1]).unwrap(),
    )
    .to_bytes();
    let later_root = reference::tree_root(6, &later.frontier).unwrap();
    let claim = Entry {
        slot: 3,
        note_count: 2,
        root: later_root,
    };
    let bytes = parts.encode_with_history(&reference::encode_history(NETWORK, &[claim]));
    let state = PoolState::decode(&bytes).unwrap();
    let mut paid = state.with_payment(&payment(-1, notes)).unwrap();
    assert_eq!(paid.root(), later_root);
    let before = paid.encode();
    assert_eq!(paid.complete_slot(4), Err(Error::InvalidEncoding));
    assert!(paid.with_completed_slot(4).is_err());
    assert_eq!(paid.encode(), before);
    // The state itself, before the payment, completes a slot.
    assert_eq!(PoolState::decode(&bytes).unwrap().complete_slot(4), Ok(()));
}
