//! Compact persisted pool state. The runtime authenticates spent-note accounts separately.

use crate::{
    anchors::{AnchorHistory, MAX_ANCHOR_HISTORY_BYTES},
    verification::VerifiedPayment,
    Error,
};
use incrementalmerkletree::{Hashable, Level};
use orchard::tree::{Anchor, MerkleHashOrchard};
use std::collections::BTreeSet;

/// Two-action payments must leave a representable 32-level frontier.
pub const MAX_COMMITMENTS: u64 = (1u64 << 32) - 2;
/// A bounded burst allowance, not a guarantee that every live proof stays valid.
/// Clients must still synchronize and avoid indefinite proof queues.
pub const MAX_ROOTS: usize = 64;
pub const STATE_BYTES: usize = 8 + 32 + 8 + 8 + 8 + 1 + 32 * 32 + MAX_ROOTS * 32;
/// Fresh-network V4 state: frontier and slot checkpoints, without per-payment roots.
pub const SLOT_STATE_BYTES: usize = 8 + 32 + 8 + 8 + 8 + 32 * 32 + 4 + MAX_ANCHOR_HISTORY_BYTES;

#[derive(Clone, Debug)]
pub struct PoolState {
    pub network: [u8; 32],
    pub rent_floor: u64,
    pub backing: u64,
    count: u64,
    frontier: [Option<MerkleHashOrchard>; 32],
    roots: Vec<[u8; 32]>,
    slot_anchors: Option<AnchorHistory>,
}

impl PoolState {
    pub fn new(network: [u8; 32], rent_floor: u64) -> Result<Self, Error> {
        if network == [0; 32] {
            return Err(Error::InvalidContext);
        }
        Ok(Self {
            network,
            rent_floor,
            backing: 0,
            count: 0,
            frontier: [None; 32],
            roots: vec![Anchor::empty_tree().to_bytes()],
            slot_anchors: None,
        })
    }

    /// Explicitly initialize a fresh V4 pool. This never converts existing state.
    pub fn new_slot_anchored(network: [u8; 32], rent_floor: u64) -> Result<Self, Error> {
        let mut state = Self::new(network, rent_floor)?;
        state.slot_anchors = Some(AnchorHistory::new(network)?);
        Ok(state)
    }

    pub fn uses_slot_anchors(&self) -> bool {
        self.slot_anchors.is_some()
    }

    pub fn slot_anchors(&self) -> Option<&AnchorHistory> {
        self.slot_anchors.as_ref()
    }

    pub fn accepted_roots(&self, execution_slot: u64) -> Result<BTreeSet<[u8; 32]>, Error> {
        match &self.slot_anchors {
            Some(history) => history.roots_at(execution_slot),
            None => Ok(self.roots()),
        }
    }

    /// Called only after all transactions in a completed canonical Bank/block.
    /// The executing slot's intermediate roots never become eligible here.
    pub fn with_completed_slot(&self, slot: u64) -> Result<Self, Error> {
        let mut next = self.clone();
        next.complete_slot(slot)?;
        Ok(next)
    }

    /// The in-place form preserves the same checkpoint rules and leaves this
    /// state unchanged on rejection. Callers must authenticate the completed
    /// block before recording it; this method does not establish finality.
    pub fn complete_slot(&mut self, slot: u64) -> Result<(), Error> {
        let count = self.count;
        // The private frontier only changes when with_payment increases count.
        // Reuse a prior completed root for an unchanged tree; decode still
        // recomputes the frontier root before accepting serialized checkpoints.
        let root = self
            .slot_anchors
            .as_ref()
            .and_then(|history| history.entries().last())
            .filter(|checkpoint| checkpoint.note_count == count)
            .map(|checkpoint| checkpoint.root)
            .unwrap_or_else(|| self.root());
        self.slot_anchors
            .as_mut()
            .ok_or(Error::UnsupportedVersion)?
            .record(slot, count, root)?;
        Ok(())
    }

    /// Legacy roots only. V4 callers must supply an execution slot explicitly.
    pub fn roots(&self) -> BTreeSet<[u8; 32]> {
        if self.uses_slot_anchors() {
            return BTreeSet::new();
        }
        self.roots.iter().copied().collect()
    }
    pub fn note_count(&self) -> u64 {
        self.count
    }

    pub fn root(&self) -> [u8; 32] {
        let mut node = MerkleHashOrchard::empty_leaf();
        for level in 0..32 {
            node = if (self.count >> level) & 1 == 1 {
                MerkleHashOrchard::combine(
                    Level::from(level as u8),
                    &self.frontier[level].expect("validated frontier"),
                    &node,
                )
            } else {
                MerkleHashOrchard::combine(
                    Level::from(level as u8),
                    &node,
                    &MerkleHashOrchard::empty_root(Level::from(level as u8)),
                )
            };
        }
        node.to_bytes()
    }

    /// Apply already-verified effects after the runtime checks both durable nullifiers.
    pub fn with_payment(&self, payment: &VerifiedPayment) -> Result<Self, Error> {
        if self.count > MAX_COMMITMENTS - 2 {
            return Err(Error::CapacityExceeded);
        }
        let mut next = self.clone();
        next.backing = if payment.public_value_balance < 0 {
            self.backing
                .checked_add(payment.public_value_balance.unsigned_abs())
                .ok_or(Error::InvalidLength)?
        } else {
            self.backing
                .checked_sub(payment.public_value_balance as u64)
                .ok_or(Error::InsufficientBacking)?
        };
        if next.backing > i64::MAX as u64 {
            return Err(Error::CapacityExceeded);
        }
        for bytes in payment.commitments {
            // Every unused position of the tree holds the empty leaf. A note
            // equal to it would raise the note count without changing the
            // tree, and one root must not stand for two note counts.
            if bytes == MerkleHashOrchard::empty_leaf().to_bytes() {
                return Err(Error::InvalidEncoding);
            }
            let mut node = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&bytes))
                .ok_or(Error::InvalidEncoding)?;
            for level in 0..32 {
                if (next.count >> level) & 1 == 0 {
                    next.frontier[level] = Some(node);
                    break;
                }
                let left = next.frontier[level].take().ok_or(Error::InvalidEncoding)?;
                node = MerkleHashOrchard::combine(Level::from(level as u8), &left, &node);
            }
            next.count += 1;
        }
        if !next.uses_slot_anchors() {
            next.roots.push(next.root());
            if next.roots.len() > MAX_ROOTS {
                next.roots.remove(0);
            }
        }
        Ok(next)
    }

    pub fn encode(&self) -> Vec<u8> {
        if let Some(history) = &self.slot_anchors {
            let mut bytes = Vec::with_capacity(SLOT_STATE_BYTES);
            bytes.extend_from_slice(b"NPOOL004");
            bytes.extend_from_slice(&self.network);
            for number in [self.rent_floor, self.backing, self.count] {
                bytes.extend_from_slice(&number.to_le_bytes());
            }
            for node in self.frontier {
                bytes.extend_from_slice(&node.map(|node| node.to_bytes()).unwrap_or([0; 32]));
            }
            let history = history.encode();
            bytes.extend_from_slice(&(history.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&history);
            bytes.resize(SLOT_STATE_BYTES, 0);
            return bytes;
        }
        let mut bytes = Vec::with_capacity(STATE_BYTES);
        bytes.extend_from_slice(b"NPOOL003");
        bytes.extend_from_slice(&self.network);
        for number in [self.rent_floor, self.backing, self.count] {
            bytes.extend_from_slice(&number.to_le_bytes());
        }
        bytes.push(self.roots.len() as u8);
        for node in self.frontier {
            bytes.extend_from_slice(&node.map(|n| n.to_bytes()).unwrap_or([0; 32]));
        }
        for root in &self.roots {
            bytes.extend_from_slice(root);
        }
        bytes.resize(STATE_BYTES, 0);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.starts_with(b"NPOOL004") {
            return Self::decode_slot_anchored(bytes);
        }
        if bytes.len() != STATE_BYTES || &bytes[..8] != b"NPOOL003" {
            return Err(Error::InvalidEncoding);
        }
        let mut reader = Reader(&bytes[8..]);
        let network = reader.take()?;
        let rent_floor = u64::from_le_bytes(reader.take()?);
        let backing = u64::from_le_bytes(reader.take()?);
        let count = u64::from_le_bytes(reader.take()?);
        let root_count = reader.take::<1>()?[0] as usize;
        if network == [0; 32]
            || backing > i64::MAX as u64
            || count > MAX_COMMITMENTS
            || count % 2 != 0
            || root_count == 0
            || root_count > MAX_ROOTS
        {
            return Err(Error::InvalidEncoding);
        }
        let mut frontier = [None; 32];
        for (i, node) in frontier.iter_mut().enumerate() {
            let data = reader.take()?;
            if count & (1u64 << i) != 0 {
                *node = Some(
                    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&data))
                        .ok_or(Error::InvalidEncoding)?,
                );
            } else if data != [0; 32] {
                return Err(Error::InvalidEncoding);
            }
        }
        let mut roots = Vec::new();
        for i in 0..MAX_ROOTS {
            let data = reader.take()?;
            if i < root_count {
                if !bool::from(Anchor::from_bytes(data).is_some()) {
                    return Err(Error::InvalidEncoding);
                }
                roots.push(data);
            } else if data != [0; 32] {
                return Err(Error::InvalidEncoding);
            }
        }
        let state = Self {
            network,
            rent_floor,
            backing,
            count,
            frontier,
            roots,
            slot_anchors: None,
        };
        if state.roots.last() != Some(&state.root()) {
            return Err(Error::InvalidEncoding);
        }
        Ok(state)
    }

    fn decode_slot_anchored(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SLOT_STATE_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let mut reader = Reader(&bytes[8..]);
        let network = reader.take()?;
        let rent_floor = u64::from_le_bytes(reader.take()?);
        let backing = u64::from_le_bytes(reader.take()?);
        let count = u64::from_le_bytes(reader.take()?);
        if network == [0; 32]
            || backing > i64::MAX as u64
            || count > MAX_COMMITMENTS
            || !count.is_multiple_of(2)
        {
            return Err(Error::InvalidEncoding);
        }
        let mut frontier = [None; 32];
        for (index, node) in frontier.iter_mut().enumerate() {
            let data = reader.take()?;
            if count & (1u64 << index) != 0 {
                *node = Some(
                    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&data))
                        .ok_or(Error::InvalidEncoding)?,
                );
            } else if data != [0; 32] {
                return Err(Error::InvalidEncoding);
            }
        }
        let history_len = u32::from_le_bytes(reader.take()?) as usize;
        if history_len > MAX_ANCHOR_HISTORY_BYTES {
            return Err(Error::InvalidLength);
        }
        let (history, padding) = reader
            .0
            .split_at_checked(history_len)
            .ok_or(Error::InvalidLength)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::InvalidEncoding);
        }
        let history = AnchorHistory::decode(network, history)?;
        let state = Self {
            network,
            rent_floor,
            backing,
            count,
            frontier,
            roots: Vec::new(),
            slot_anchors: Some(history),
        };
        let root = state.root();
        let checkpoints = state.slot_anchors.as_ref().unwrap().entries();
        if let Some(checkpoint) = checkpoints.last() {
            if checkpoint.note_count > count
                || (checkpoint.note_count == count && checkpoint.root != root)
            {
                return Err(Error::InvalidEncoding);
            }
        }
        // The next completed slot records this tree. Refuse a tree that it
        // could not record: notes under the root of the empty tree, or a root
        // that a checkpoint already holds for another note count.
        if (count != 0 && root == Anchor::empty_tree().to_bytes())
            || checkpoints
                .iter()
                .any(|checkpoint| checkpoint.root == root && checkpoint.note_count != count)
        {
            return Err(Error::InvalidEncoding);
        }
        Ok(state)
    }
}

struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (head, tail) = self.0.split_at_checked(N).ok_or(Error::InvalidLength)?;
        self.0 = tail;
        head.try_into().map_err(|_| Error::InvalidLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reference oracle: the earlier completion algorithm, which cloned the
    // pool and recorded the checkpoint on the copy, kept here for comparison.
    // This oracle deliberately never calls either new completion entry point.
    fn old_completed_slot(pool: &PoolState, slot: u64) -> Result<PoolState, Error> {
        let mut next = pool.clone();
        let count = next.count;
        let root = next
            .slot_anchors
            .as_ref()
            .and_then(|history| history.entries().last())
            .filter(|checkpoint| checkpoint.note_count == count)
            .map(|checkpoint| checkpoint.root)
            .unwrap_or_else(|| next.root());
        next.slot_anchors
            .as_mut()
            .ok_or(Error::UnsupportedVersion)?
            .record(slot, count, root)?;
        Ok(next)
    }

    #[test]
    fn in_place_completion_matches_retained_algorithm_across_rollovers_and_payments() {
        let mut actual = PoolState::new_slot_anchored([42; 32], 1000).unwrap();
        let mut reference = actual.clone();
        for slot in (0..2050).chain([2560, 2561, 3073, 4096]) {
            if [1, 257, 513, 1024, 2048, 2560].contains(&slot) {
                let effects = VerifiedPayment {
                    nullifiers: [[3; 32], [4; 32]],
                    commitments: [[1; 32], [2; 32]],
                    public_value_balance: -1,
                };
                actual = actual.with_payment(&effects).unwrap();
                reference = reference.with_payment(&effects).unwrap();
            }
            reference = old_completed_slot(&reference, slot).unwrap();
            actual.complete_slot(slot).unwrap();
            assert_eq!(actual.encode(), reference.encode(), "slot {slot}");
            assert_eq!(
                actual.accepted_roots(slot + 1).unwrap(),
                reference.accepted_roots(slot + 1).unwrap()
            );
            if slot % 127 == 0 {
                actual = PoolState::decode(&actual.encode()).unwrap();
            }
        }
        // The large final gap expires every older produced-block checkpoint.
        assert_eq!(actual.slot_anchors().unwrap().entries().len(), 1);
        assert_eq!(actual.slot_anchors().unwrap().entries()[0].slot, 4096);
        assert_eq!(actual.note_count(), 12);
        assert_eq!(actual.backing, 6);
    }

    #[test]
    fn in_place_completion_preserves_rejections_candidate_rules_and_immutable_api() {
        let mut pool = PoolState::new_slot_anchored([42; 32], 1000).unwrap();
        pool.complete_slot(1300).unwrap();
        let before = pool.encode();
        assert!(old_completed_slot(&pool, 1299).is_err());
        assert!(pool.complete_slot(1299).is_err());
        assert_eq!(pool.encode(), before);
        pool.complete_slot(1300).unwrap();
        assert_eq!(pool.encode(), before);

        // The shared state API retains the old replaceable current candidate
        // rule. WalletState separately forbids reopening a completed block.
        pool = pool
            .with_payment(&VerifiedPayment {
                nullifiers: [[3; 32], [4; 32]],
                commitments: [[1; 32], [2; 32]],
                public_value_balance: -1,
            })
            .unwrap();
        let expected = old_completed_slot(&pool, 1300).unwrap();
        pool.complete_slot(1300).unwrap();
        assert_eq!(pool.encode(), expected.encode());
        assert!(!pool.accepted_roots(1300).unwrap().contains(&pool.root()));
        assert!(pool.accepted_roots(1301).unwrap().contains(&pool.root()));

        let unchanged = pool.encode();
        let next = pool.with_completed_slot(1301).unwrap();
        assert_eq!(pool.encode(), unchanged);
        assert_eq!(
            next.encode(),
            old_completed_slot(&pool, 1301).unwrap().encode()
        );
        pool.complete_slot(1301).unwrap();
        assert_eq!(pool.encode(), next.encode());

        let mut legacy = PoolState::new([42; 32], 1000).unwrap();
        let before = legacy.encode();
        assert!(old_completed_slot(&legacy, 0).is_err());
        assert!(legacy.complete_slot(0).is_err());
        assert_eq!(legacy.encode(), before);
        assert!(legacy.with_completed_slot(0).is_err());
        assert_eq!(legacy.encode(), before);
    }

    #[test]
    fn v4_empty_checkpoint_reuse_matches_full_frontier_recomputation() {
        let mut pool = PoolState::new_slot_anchored([42; 32], 1000).unwrap();
        let mut reference = pool.clone();
        for slot in (0..650).chain([777, 1289]) {
            if [1, 257, 513].contains(&slot) {
                let effects = VerifiedPayment {
                    nullifiers: [[3; 32], [4; 32]],
                    commitments: [[1; 32], [2; 32]],
                    public_value_balance: -1,
                };
                pool = pool.with_payment(&effects).unwrap();
                reference = reference.with_payment(&effects).unwrap();
            }
            // Independent original operation: recompute all32frontier levels.
            let root = reference.root();
            reference
                .slot_anchors
                .as_mut()
                .unwrap()
                .record(slot, reference.count, root)
                .unwrap();
            pool = pool.with_completed_slot(slot).unwrap();
            assert_eq!(pool.encode(), reference.encode());
            assert_eq!(
                pool.accepted_roots(slot + 1).unwrap(),
                reference.accepted_roots(slot + 1).unwrap()
            );
            assert_eq!(
                pool.slot_anchors().unwrap().entries().last().unwrap().slot,
                slot
            );
            if slot % 127 == 0 {
                pool = PoolState::decode(&pool.encode()).unwrap();
            }
        }
        assert_eq!(pool.slot_anchors().unwrap().entries().len(), 1);
        let before = pool.encode();
        assert!(pool.with_completed_slot(1288).is_err());
        assert_eq!(pool.encode(), before);
    }

    #[test]
    fn v4_decode_authenticates_frontier_before_reusing_completed_root() {
        let pool = PoolState::new_slot_anchored([42; 32], 1000)
            .unwrap()
            .with_payment(&VerifiedPayment {
                nullifiers: [[3; 32], [4; 32]],
                commitments: [[1; 32], [2; 32]],
                public_value_balance: -1,
            })
            .unwrap()
            .with_completed_slot(1)
            .unwrap();
        let mut bytes = pool.encode();
        // Keep the same count and a valid old checkpoint, but replace the
        // occupied level1frontier with a different canonical field element.
        let offset = 8 + 32 + 3 * 8 + 32;
        bytes[offset..offset + 32].copy_from_slice(&MerkleHashOrchard::empty_leaf().to_bytes());
        assert!(PoolState::decode(&bytes).is_err());
        let restored = PoolState::decode(&pool.encode()).unwrap();
        assert_eq!(
            restored.with_completed_slot(2).unwrap().encode(),
            pool.with_completed_slot(2).unwrap().encode()
        );
    }

    #[test]
    fn v4_burst_keeps_completed_root_and_excludes_intermediate_roots() {
        let mut pool = PoolState::new_slot_anchored([42; 32], 1000)
            .unwrap()
            .with_completed_slot(0)
            .unwrap();
        let empty = pool.root();
        let mut intermediate = Vec::new();
        for _ in 0..MAX_ROOTS + 2 {
            pool = pool
                .with_payment(&VerifiedPayment {
                    nullifiers: [[3; 32], [4; 32]],
                    commitments: [[1; 32], [2; 32]],
                    public_value_balance: -1,
                })
                .unwrap();
            intermediate.push(pool.root());
            assert!(pool.accepted_roots(1).unwrap().contains(&empty));
            assert!(!pool.accepted_roots(1).unwrap().contains(&pool.root()));
            let restored = PoolState::decode(&pool.encode()).unwrap();
            assert_eq!(restored.encode(), pool.encode());
        }
        let final_root = pool.root();
        pool = pool.with_completed_slot(1).unwrap();
        assert!(pool.roots().is_empty()); // Fail closed if an old caller omits the slot.
        assert!(!pool.accepted_roots(1).unwrap().contains(&final_root));
        assert!(pool.accepted_roots(2).unwrap().contains(&final_root));
        for root in &intermediate[..intermediate.len() - 1] {
            assert!(!pool.accepted_roots(2).unwrap().contains(root));
        }
        assert_eq!(pool.slot_anchors().unwrap().entries().len(), 2);
        assert_eq!(&pool.encode()[..8], b"NPOOL004");
        assert_eq!(pool.encode().len(), SLOT_STATE_BYTES);
        assert_eq!(
            &PoolState::new([42; 32], 1000).unwrap().encode()[..8],
            b"NPOOL003"
        );
    }

    #[test]
    fn v4_empty_slots_refresh_roots_without_fabricating_skipped_slots() {
        let pool = PoolState::new_slot_anchored([42; 32], 1000)
            .unwrap()
            .with_completed_slot(0)
            .unwrap();
        let pool = pool.with_completed_slot(511).unwrap();
        assert_eq!(pool.note_count(), 0);
        assert_eq!(pool.backing, 0);
        assert_eq!(pool.slot_anchors().unwrap().entries().len(), 2);
        assert!(pool.accepted_roots(512).unwrap().contains(&pool.root()));
        assert!(pool.accepted_roots(1023).unwrap().is_empty());
        let pool = pool.with_completed_slot(1023).unwrap();
        assert_eq!(pool.slot_anchors().unwrap().entries().len(), 1);
        assert!(pool.accepted_roots(1023).unwrap().is_empty());
        assert!(pool.accepted_roots(1024).unwrap().contains(&pool.root()));
        let encoded = pool.encode();
        let restored = PoolState::decode(&encoded).unwrap();
        assert_eq!(
            restored.with_completed_slot(1024).unwrap().encode(),
            pool.with_completed_slot(1024).unwrap().encode()
        );
        let mut malformed = encoded.clone();
        *malformed.last_mut().unwrap() = 1;
        assert!(PoolState::decode(&malformed).is_err());
        let mut wrong_network = encoded;
        wrong_network[8] ^= 1;
        assert!(PoolState::decode(&wrong_network).is_err());
        assert!(pool.with_completed_slot(1000).is_err());
    }

    #[test]
    fn concurrent_anchor_survives_63_updates_then_expires_at_the_exact_bound() {
        let mut pool = PoolState::new([1; 32], 1000).unwrap();
        let anchor = pool.root();
        let effects = VerifiedPayment {
            nullifiers: [[3; 32], [4; 32]],
            commitments: [[1; 32], [2; 32]],
            public_value_balance: -1,
        };
        for _ in 0..MAX_ROOTS - 1 {
            pool = pool.with_payment(&effects).unwrap();
            assert!(PoolState::decode(&pool.encode())
                .unwrap()
                .roots()
                .contains(&anchor));
        }
        pool = pool.with_payment(&effects).unwrap();
        assert!(!pool.roots().contains(&anchor));
        let mut old = pool.encode();
        old[..8].copy_from_slice(b"NPOOL002");
        assert!(PoolState::decode(&old).is_err());
    }

    #[test]
    fn compact_pool_exceeds_old_capacity_and_enforces_tree_limit() {
        let mut pool = PoolState::new([1; 32], 1000).unwrap();
        let effects = VerifiedPayment {
            nullifiers: [[3; 32], [4; 32]],
            commitments: [[1; 32], [2; 32]],
            public_value_balance: -10,
        };
        for index in 0..300u64 {
            // This layer tracks commitments/backing, never the external spent set.
            pool = pool.with_payment(&effects).unwrap();
            let encoded = pool.encode();
            assert_eq!(encoded.len(), STATE_BYTES);
            pool = PoolState::decode(&encoded).unwrap();
            assert_eq!(pool.encode(), encoded);
            assert_eq!(pool.backing, (index + 1) * 10);
            assert_eq!(pool.note_count(), (index + 1) * 2);
        }
        let mut invalid = pool.encode();
        invalid[..8].copy_from_slice(b"NPOOL001");
        assert!(PoolState::decode(&invalid).is_err());
        let mut invalid = PoolState::new([1; 32], 1000).unwrap().encode();
        *invalid.last_mut().unwrap() = 1;
        assert!(PoolState::decode(&invalid).is_err());
        let empty = PoolState::new([1; 32], 1000).unwrap();
        assert!(matches!(
            empty.with_payment(&VerifiedPayment {
                public_value_balance: 1,
                ..effects
            }),
            Err(Error::InsufficientBacking)
        ));

        // Construct a valid frontier just below the protocol tree bound without
        // appending four billion leaves. Every occupied subtree is an empty root,
        // which only the legacy format still decodes.
        let mut almost_full = empty;
        almost_full.count = MAX_COMMITMENTS - 2;
        for (level, node) in almost_full.frontier.iter_mut().enumerate() {
            if almost_full.count & (1 << level) != 0 {
                *node = Some(MerkleHashOrchard::empty_root(Level::from(level as u8)));
            }
        }
        almost_full.roots = vec![almost_full.root()];
        let full = PoolState::decode(&almost_full.encode())
            .unwrap()
            .with_payment(&effects)
            .unwrap();
        assert_eq!(full.note_count(), MAX_COMMITMENTS);
        assert!(PoolState::decode(&full.encode()).is_ok());
        assert!(matches!(
            full.with_payment(&effects),
            Err(Error::CapacityExceeded)
        ));
    }

    #[test]
    fn refuses_empty_leaf_notes_and_trees_no_completed_slot_could_record() {
        let empty_leaf = MerkleHashOrchard::empty_leaf().to_bytes();
        let effects = |commitments| VerifiedPayment {
            nullifiers: [[3; 32], [4; 32]],
            commitments,
            public_value_balance: -1,
        };
        let pool = PoolState::new_slot_anchored([42; 32], 1000)
            .unwrap()
            .with_payment(&effects([[1; 32], [2; 32]]))
            .unwrap()
            .with_completed_slot(1)
            .unwrap();
        let legacy = PoolState::new([42; 32], 1000).unwrap();

        // An empty leaf in either position is refused by both formats, and a
        // refused payment leaves the state as it was.
        let before = [pool.encode(), legacy.encode()];
        for commitments in [
            [empty_leaf; 2],
            [empty_leaf, [5; 32]],
            [[5; 32], empty_leaf],
        ] {
            for state in [&pool, &legacy] {
                let refused = state.with_payment(&effects(commitments));
                assert!(matches!(refused, Err(Error::InvalidEncoding)));
            }
        }
        assert_eq!([pool.encode(), legacy.encode()], before);

        // What a payment of two empty leaves used to leave: four notes under
        // the root that slot 1 recorded for two.
        let mut stale = pool.clone();
        let two_notes = stale.frontier[1].take().unwrap();
        let no_notes = MerkleHashOrchard::empty_root(Level::from(1));
        stale.frontier[2] = Some(MerkleHashOrchard::combine(
            Level::from(1),
            &two_notes,
            &no_notes,
        ));
        stale.count = 4;
        assert_eq!(stale.root(), pool.root());
        let decoded = PoolState::decode(&stale.encode());
        assert!(matches!(decoded, Err(Error::InvalidEncoding)));

        // The same root under six notes, when the checkpoint that holds it is
        // no longer the newest one.
        let mut older = pool
            .with_payment(&effects([[5; 32], [6; 32]]))
            .unwrap()
            .with_completed_slot(2)
            .unwrap();
        older.frontier = stale.frontier;
        older.frontier[1] = Some(no_notes);
        older.count = 6;
        assert_eq!(older.root(), pool.root());
        let decoded = PoolState::decode(&older.encode());
        assert!(matches!(decoded, Err(Error::InvalidEncoding)));

        // Notes under the root of the empty tree, before any completed slot.
        let mut hollow = PoolState::new_slot_anchored([42; 32], 1000).unwrap();
        hollow.frontier[1] = Some(no_notes);
        hollow.count = 2;
        assert_eq!(hollow.root(), Anchor::empty_tree().to_bytes());
        let decoded = PoolState::decode(&hollow.encode());
        assert!(matches!(decoded, Err(Error::InvalidEncoding)));

        // An accepted payment leaves a tree that the next slot records.
        let paid = pool.with_payment(&effects([[5; 32], [6; 32]])).unwrap();
        let paid = PoolState::decode(&paid.encode()).unwrap();
        assert!(paid.with_completed_slot(2).is_ok());
    }
}
