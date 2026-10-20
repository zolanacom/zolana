//! Slot-aged anchor history for a future native payment state version.
//!
//! This module is not wired into NPOOL003 or an activated validator rule. The
//! executing Bank must supply `slot`; RPC finality, wall time and payment count
//! cannot define anchor validity. Record the root after each successful payment
//! and at the end of an otherwise empty produced slot. Queries exclude the
//! current slot's replaceable candidate, accepting only prior completed slots.
//!
//! Encoding is canonical, not authenticated. A caller must bind this state to
//! its own canonical branch and execution commitment before trusting it.

use crate::{state::MAX_COMMITMENTS, Error};
use orchard::tree::Anchor;
use std::collections::BTreeSet;

const MAGIC: &[u8; 8] = b"ZOLANCH1";
const DOMAIN: &[u8; 16] = b"ZolanaSlotRoots1";
pub const ANCHOR_HISTORY_VERSION: u16 = 1;
/// A slot root of age 511 is valid; age 512 is expired.
pub const ANCHOR_WINDOW_SLOTS: u64 = 512;
pub const MAX_SLOT_ANCHORS: usize = ANCHOR_WINDOW_SLOTS as usize;
const HEADER_BYTES: usize = 8 + 2 + 16 + 32 + 2;
const ENTRY_BYTES: usize = 8 + 8 + 32;
pub const MAX_ANCHOR_HISTORY_BYTES: usize = HEADER_BYTES + MAX_SLOT_ANCHORS * ENTRY_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotAnchor {
    pub slot: u64,
    pub note_count: u64,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorHistory {
    network: [u8; 32],
    // Includes at most one replaceable candidate for the current execution slot.
    // Strict slot ordering and the age window bound storage independently of TPS.
    entries: Vec<SlotAnchor>,
}

impl AnchorHistory {
    pub fn new(network: [u8; 32]) -> Result<Self, Error> {
        if network == [0; 32] {
            return Err(Error::InvalidContext);
        }
        Ok(Self {
            network,
            entries: Vec::new(),
        })
    }

    pub fn network(&self) -> [u8; 32] {
        self.network
    }

    pub fn entries(&self) -> &[SlotAnchor] {
        &self.entries
    }

    /// Record authenticated execution effects without authorizing this slot's
    /// intermediate roots. Repeated writes replace only the current candidate.
    /// Every rejected update leaves the original history byte-for-byte intact.
    pub fn record(&mut self, slot: u64, note_count: u64, root: [u8; 32]) -> Result<(), Error> {
        let next = SlotAnchor {
            slot,
            note_count,
            root,
        };
        validate_anchor(&next)?;
        if let Some(previous) = self.entries.last() {
            if slot < previous.slot {
                return Err(Error::InvalidContext);
            }
            validate_progress(previous, &next)?;
        }
        validate_root_reuse(&self.entries, &next)?;
        let first_live = self
            .entries
            .partition_point(|entry| slot - entry.slot >= ANCHOR_WINDOW_SLOTS);
        self.entries.drain(..first_live);
        if self.entries.last().is_some_and(|entry| entry.slot == slot) {
            *self.entries.last_mut().expect("checked candidate") = next;
        } else {
            self.entries.push(next);
        }
        debug_assert!(self.entries.len() <= MAX_SLOT_ANCHORS);
        Ok(())
    }

    /// The caller supplies the deterministic slot of the Bank executing a
    /// payment. A final root from slot S is eligible only in a later slot.
    /// The genesis empty root is eligible from slot zero through slot 511.
    pub fn roots_at(&self, execution_slot: u64) -> Result<BTreeSet<[u8; 32]>, Error> {
        if self
            .entries
            .last()
            .is_some_and(|entry| entry.slot > execution_slot)
        {
            return Err(Error::InvalidContext);
        }
        let mut roots = BTreeSet::new();
        if execution_slot < ANCHOR_WINDOW_SLOTS {
            roots.insert(Anchor::empty_tree().to_bytes());
        }
        roots.extend(
            self.entries
                .iter()
                .filter(|entry| {
                    entry.slot < execution_slot && execution_slot - entry.slot < ANCHOR_WINDOW_SLOTS
                })
                .map(|entry| entry.root),
        );
        Ok(roots)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_BYTES + self.entries.len() * ENTRY_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&ANCHOR_HISTORY_VERSION.to_le_bytes());
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&self.network);
        bytes.extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
        for entry in &self.entries {
            bytes.extend_from_slice(&entry.slot.to_le_bytes());
            bytes.extend_from_slice(&entry.note_count.to_le_bytes());
            bytes.extend_from_slice(&entry.root);
        }
        bytes
    }

    pub fn decode(network: [u8; 32], bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_BYTES || bytes.len() > MAX_ANCHOR_HISTORY_BYTES {
            return Err(Error::InvalidLength);
        }
        let mut input = bytes;
        if &take::<8>(&mut input)? != MAGIC
            || u16::from_le_bytes(take(&mut input)?) != ANCHOR_HISTORY_VERSION
        {
            return Err(Error::UnsupportedVersion);
        }
        if &take::<16>(&mut input)? != DOMAIN {
            return Err(Error::InvalidContext);
        }
        if network == [0; 32] || take::<32>(&mut input)? != network {
            return Err(Error::WrongNetwork);
        }
        let count = u16::from_le_bytes(take(&mut input)?) as usize;
        if count > MAX_SLOT_ANCHORS || input.len() != count * ENTRY_BYTES {
            return Err(Error::InvalidLength);
        }
        let mut history = Self::new(network)?;
        for _ in 0..count {
            let entry = SlotAnchor {
                slot: u64::from_le_bytes(take(&mut input)?),
                note_count: u64::from_le_bytes(take(&mut input)?),
                root: take(&mut input)?,
            };
            validate_anchor(&entry)?;
            if let Some(previous) = history.entries.last() {
                if entry.slot <= previous.slot {
                    return Err(Error::InvalidEncoding);
                }
                validate_progress(previous, &entry)?;
            }
            validate_root_reuse(&history.entries, &entry)?;
            history.entries.push(entry);
        }
        if let (Some(first), Some(last)) = (history.entries.first(), history.entries.last()) {
            if last.slot - first.slot >= ANCHOR_WINDOW_SLOTS {
                return Err(Error::InvalidEncoding);
            }
        }
        Ok(history)
    }
}

fn validate_anchor(anchor: &SlotAnchor) -> Result<(), Error> {
    if anchor.note_count > MAX_COMMITMENTS
        || !anchor.note_count.is_multiple_of(2)
        || anchor.root == [0; 32]
        || !bool::from(Anchor::from_bytes(anchor.root).is_some())
        || (anchor.note_count == 0) != (anchor.root == Anchor::empty_tree().to_bytes())
    {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn validate_progress(previous: &SlotAnchor, next: &SlotAnchor) -> Result<(), Error> {
    if next.note_count < previous.note_count
        || (next.note_count == previous.note_count) != (next.root == previous.root)
    {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn validate_root_reuse(entries: &[SlotAnchor], next: &SlotAnchor) -> Result<(), Error> {
    if entries
        .iter()
        .any(|entry| entry.root == next.root && entry.note_count != next.note_count)
    {
        return Err(Error::InvalidEncoding);
    }
    Ok(())
}

fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], Error> {
    let (head, tail) = input.split_at_checked(N).ok_or(Error::InvalidLength)?;
    *input = tail;
    head.try_into().map_err(|_| Error::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETWORK: [u8; 32] = [42; 32];
    const ENTRY_COUNT_OFFSET: usize = HEADER_BYTES - 2;

    // Canonical nonzero Orchard field encodings, used as synthetic authenticated
    // roots. These storage tests do not assert a Merkle tree has these roots.
    fn root(value: u64) -> [u8; 32] {
        assert_ne!(value, 0);
        let mut bytes = [0; 32];
        bytes[..8].copy_from_slice(&value.to_le_bytes());
        assert!(bool::from(Anchor::from_bytes(bytes).is_some()));
        bytes
    }

    #[test]
    fn high_burst_coalesces_and_preserves_completed_slot_root() {
        let mut history = AnchorHistory::new(NETWORK).unwrap();
        history.record(1, 2, root(1)).unwrap();
        for count in 2..=10_000 {
            history.record(2, count * 2, root(count)).unwrap();
        }
        assert_eq!(history.entries.len(), 2);
        assert!(history.roots_at(2).unwrap().contains(&root(1)));
        assert!(!history.roots_at(2).unwrap().contains(&root(10_000)));
        assert!(!history.roots_at(3).unwrap().contains(&root(9_999)));
        assert!(history.roots_at(3).unwrap().contains(&root(10_000)));
        assert_eq!(history.entries[1].note_count, 20_000);
        assert_eq!(history.encode().len(), HEADER_BYTES + 2 * ENTRY_BYTES);
    }

    #[test]
    fn expiry_is_exact_and_storage_depends_on_slots_not_payments() {
        let mut history = AnchorHistory::new(NETWORK).unwrap();
        history.record(0, 2, root(1)).unwrap();
        assert!(history.roots_at(511).unwrap().contains(&root(1)));
        assert!(!history.roots_at(512).unwrap().contains(&root(1)));
        assert!(history
            .roots_at(511)
            .unwrap()
            .contains(&Anchor::empty_tree().to_bytes()));
        assert!(!history
            .roots_at(512)
            .unwrap()
            .contains(&Anchor::empty_tree().to_bytes()));
        for slot in 1..=1_024 {
            history
                .record(slot, (slot + 1) * 2, root(slot + 1))
                .unwrap();
            assert!(history.entries.len() <= MAX_SLOT_ANCHORS);
        }
        assert_eq!(history.entries.len(), MAX_SLOT_ANCHORS);
        assert_eq!(history.entries.first().unwrap().slot, 513);
        assert_eq!(history.entries.last().unwrap().slot, 1_024);
        assert_eq!(history.roots_at(1_024).unwrap().len(), 511);
        assert!(!history.roots_at(1_024).unwrap().contains(&root(1_025)));
        assert_eq!(history.encode().len(), MAX_ANCHOR_HISTORY_BYTES);
    }

    #[test]
    fn sparse_skipped_slots_expire_and_empty_produced_slots_refresh() {
        let mut history = AnchorHistory::new(NETWORK).unwrap();
        history.record(7, 2, root(1)).unwrap();
        assert!(history.roots_at(518).unwrap().contains(&root(1)));
        assert!(history.roots_at(519).unwrap().is_empty());
        // A produced empty slot authenticates the unchanged root; a skipped slot
        // does not. Its root becomes eligible only in the following slot.
        history.record(520, 2, root(1)).unwrap();
        assert!(history.roots_at(520).unwrap().is_empty());
        assert!(history.roots_at(521).unwrap().contains(&root(1)));
        assert_eq!(history.entries.len(), 1);
        assert_eq!(history.entries[0].slot, 520);
        history.record(u64::MAX, 2, root(1)).unwrap();
        assert!(history.roots_at(u64::MAX).unwrap().is_empty());
    }

    #[test]
    fn canonical_restore_continues_the_same_pending_slot_and_branch() {
        let mut history = AnchorHistory::new(NETWORK).unwrap();
        assert_eq!(
            AnchorHistory::decode(NETWORK, &history.encode()).unwrap(),
            history
        );
        history.record(10, 2, root(1)).unwrap();
        history.record(11, 4, root(2)).unwrap();
        let mut restored = AnchorHistory::decode(NETWORK, &history.encode()).unwrap();
        assert_eq!(restored.encode(), history.encode());
        history.record(11, 6, root(3)).unwrap();
        restored.record(11, 6, root(3)).unwrap();
        assert_eq!(restored, history);
        assert!(restored.roots_at(11).unwrap().contains(&root(1)));
        assert!(!restored.roots_at(11).unwrap().contains(&root(3)));

        let mut competing = restored.clone();
        restored.record(12, 8, root(4)).unwrap();
        competing.record(12, 8, root(5)).unwrap();
        assert_ne!(restored.encode(), competing.encode());
        let branch = AnchorHistory::decode(NETWORK, &restored.encode()).unwrap();
        assert!(branch.roots_at(13).unwrap().contains(&root(4)));
        assert!(!branch.roots_at(13).unwrap().contains(&root(5)));
        assert!(!competing.roots_at(13).unwrap().contains(&root(4)));
    }

    #[test]
    fn invalid_updates_are_atomic_and_slot_regression_fails_closed() {
        let mut history = AnchorHistory::new(NETWORK).unwrap();
        history.record(4, 4, root(1)).unwrap();
        let before = history.encode();
        for (slot, count, candidate) in [
            (3, 6, root(2)),
            (4, 2, root(2)),
            (4, 4, root(2)),
            (4, 6, root(1)),
            (4, 5, root(2)),
            (4, MAX_COMMITMENTS + 2, root(2)),
            (4, 6, [0; 32]),
            (4, 6, [255; 32]),
            (4, 0, root(2)),
        ] {
            assert!(history.record(slot, count, candidate).is_err());
            assert_eq!(history.encode(), before);
        }
        assert!(history.roots_at(3).is_err());
        assert_eq!(history.encode(), before);
        assert!(AnchorHistory::new([0; 32]).is_err());

        history.record(5, 6, root(2)).unwrap();
        let before = history.encode();
        assert!(history.record(6, 8, root(1)).is_err());
        assert_eq!(history.encode(), before);
    }

    #[test]
    fn decode_rejects_wrong_domain_network_trailing_and_noncanonical_entries() {
        let mut history = AnchorHistory::new(NETWORK).unwrap();
        history.record(10, 2, root(1)).unwrap();
        history.record(11, 4, root(2)).unwrap();
        let canonical = history.encode();
        assert_eq!(
            AnchorHistory::decode([43; 32], &canonical),
            Err(Error::WrongNetwork)
        );
        assert_eq!(
            AnchorHistory::decode([0; 32], &canonical),
            Err(Error::WrongNetwork)
        );
        let mut mutations = Vec::new();
        let mut changed = canonical.clone();
        changed[0] ^= 1;
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed[8] = 2;
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed[10] ^= 1;
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed[ENTRY_COUNT_OFFSET..HEADER_BYTES].copy_from_slice(&513u16.to_le_bytes());
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed.push(0);
        mutations.push(changed);
        mutations.push(canonical[..canonical.len() - 1].to_vec());
        let second = HEADER_BYTES + ENTRY_BYTES;
        for slot in [9u64, 10, 522] {
            let mut changed = canonical.clone();
            changed[second..second + 8].copy_from_slice(&slot.to_le_bytes());
            mutations.push(changed);
        }
        let mut changed = canonical.clone();
        changed[second + 8..second + 16].copy_from_slice(&0u64.to_le_bytes());
        mutations.push(changed);
        let mut changed = canonical.clone();
        changed[second + 8..second + 16].copy_from_slice(&2u64.to_le_bytes());
        mutations.push(changed);
        for root_bytes in [[0; 32], [255; 32], root(1)] {
            let mut changed = canonical.clone();
            changed[second + 16..second + ENTRY_BYTES].copy_from_slice(&root_bytes);
            mutations.push(changed);
        }
        for changed in mutations {
            assert!(AnchorHistory::decode(NETWORK, &changed).is_err());
        }
    }
}
