//! Reference statements of the encodings and rules, written from the format
//! descriptions rather than from the decoders. The fuzz targets require every
//! decoder to accept exactly what these accept.

use incrementalmerkletree::{Hashable, Level};
use native_payments::{
    anchors::{ANCHOR_WINDOW_SLOTS, MAX_ANCHOR_HISTORY_BYTES, MAX_SLOT_ANCHORS},
    envelope::{ENVELOPE_HEADER_BYTES, MAX_ENVELOPE_BYTES, MAX_INNER_PAYMENT_BYTES},
    state::{MAX_COMMITMENTS, MAX_ROOTS, SLOT_STATE_BYTES, STATE_BYTES},
    verification::{bundle_version, ACTION_COUNT, MAX_EXPIRY_WINDOW},
    wire::{ACTION_BYTES, HEADER_BYTES},
};
use orchard::{
    note::{ExtractedNoteCommitment, Nullifier},
    primitives::redpallas,
    tree::{Anchor, MerkleHashOrchard},
    value::ValueCommitment,
    Proof,
};
use std::collections::BTreeSet;

pub const ANCHOR_HEADER_BYTES: usize = 8 + 2 + 16 + 32 + 2;
pub const ANCHOR_ENTRY_BYTES: usize = 8 + 8 + 32;
/// Bytes of a pool state before its frontier: tag, network and three numbers.
pub const POOL_PREFIX_BYTES: usize = 8 + 32 + 3 * 8;

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("checked length")
}

fn number(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(array(bytes))
}

pub fn empty_root() -> [u8; 32] {
    Anchor::empty_tree().to_bytes()
}

/// A canonical field element, which is all a tree node or a root has to be.
pub fn is_field_element(bytes: [u8; 32]) -> bool {
    bool::from(Anchor::from_bytes(bytes).is_some())
}

/// A valid encoding of a curve point, the identity included.
pub fn is_point(bytes: [u8; 32]) -> bool {
    bool::from(ValueCommitment::from_bytes(&bytes).is_some())
}

/// What every unused position of the note tree holds.
pub fn empty_leaf() -> [u8; 32] {
    MerkleHashOrchard::empty_leaf().to_bytes()
}

/// A note the pool appends to its tree: a field element other than the empty
/// leaf. A note equal to the empty leaf would add to the note count and leave
/// the tree as it was.
pub fn is_note(bytes: [u8; 32]) -> bool {
    is_field_element(bytes) && bytes != empty_leaf()
}

// ---------------------------------------------------------------------------
// Slot anchors

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub slot: u64,
    pub note_count: u64,
    pub root: [u8; 32],
}

pub fn entry_is_valid(entry: &Entry) -> bool {
    entry.note_count <= MAX_COMMITMENTS
        && entry.note_count.is_multiple_of(2)
        && entry.root != [0; 32]
        && is_field_element(entry.root)
        && (entry.note_count == 0) == (entry.root == empty_root())
}

/// `later` may follow `earlier` in a history, not necessarily directly.
pub fn entries_agree(earlier: &Entry, later: &Entry) -> bool {
    later.note_count >= earlier.note_count
        && (later.note_count == earlier.note_count) == (later.root == earlier.root)
}

/// The rule for a stored history, stated over the whole list at once.
pub fn history_is_valid(entries: &[Entry]) -> bool {
    entries.len() <= MAX_SLOT_ANCHORS
        && entries.iter().all(entry_is_valid)
        && entries.windows(2).all(|pair| pair[0].slot < pair[1].slot)
        && entries.iter().enumerate().all(|(index, later)| {
            entries[..index]
                .iter()
                .all(|earlier| entries_agree(earlier, later))
        })
        && match (entries.first(), entries.last()) {
            (Some(first), Some(last)) => last.slot - first.slot < ANCHOR_WINDOW_SLOTS,
            _ => true,
        }
}

pub fn encode_history(network: [u8; 32], entries: &[Entry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ZOLANCH1");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(b"ZolanaSlotRoots1");
    bytes.extend_from_slice(&network);
    bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.slot.to_le_bytes());
        bytes.extend_from_slice(&entry.note_count.to_le_bytes());
        bytes.extend_from_slice(&entry.root);
    }
    bytes
}

pub fn decode_history(network: [u8; 32], bytes: &[u8]) -> Option<Vec<Entry>> {
    if bytes.len() < ANCHOR_HEADER_BYTES
        || bytes.len() > MAX_ANCHOR_HISTORY_BYTES
        || &bytes[..8] != b"ZOLANCH1"
        || bytes[8..10] != 1u16.to_le_bytes()
        || &bytes[10..26] != b"ZolanaSlotRoots1"
        || network == [0; 32]
        || bytes[26..58] != network
    {
        return None;
    }
    let count = usize::from(u16::from_le_bytes(array(&bytes[58..60])));
    let body = &bytes[ANCHOR_HEADER_BYTES..];
    if body.len() != count * ANCHOR_ENTRY_BYTES {
        return None;
    }
    let entries: Vec<Entry> = body
        .chunks(ANCHOR_ENTRY_BYTES)
        .map(|entry| Entry {
            slot: number(&entry[..8]),
            note_count: number(&entry[8..16]),
            root: array(&entry[16..]),
        })
        .collect();
    history_is_valid(&entries).then_some(entries)
}

/// A completed slot may record a tree of `note_count` notes and this root
/// after the `entries` already stored: on its own it is a valid checkpoint,
/// and it agrees with every stored one, so that no root stands for two note
/// counts and no note count for two roots.
pub fn tree_can_be_recorded(entries: &[Entry], note_count: u64, root: [u8; 32]) -> bool {
    let present = Entry {
        slot: entries.last().map_or(0, |newest| newest.slot),
        note_count,
        root,
    };
    entry_is_valid(&present)
        && entries
            .iter()
            .all(|earlier| entries_agree(earlier, &present))
}

/// Roots a payment executing in `execution_slot` may use: the root of every
/// block completed before that slot and less than a window ago, and the empty
/// tree for the first window of the chain.
pub fn eligible_roots(entries: &[Entry], execution_slot: u64) -> BTreeSet<[u8; 32]> {
    let mut roots: BTreeSet<[u8; 32]> = entries
        .iter()
        .filter(|entry| {
            entry.slot < execution_slot && execution_slot - entry.slot < ANCHOR_WINDOW_SLOTS
        })
        .map(|entry| entry.root)
        .collect();
    if execution_slot < ANCHOR_WINDOW_SLOTS {
        roots.insert(empty_root());
    }
    roots
}

// ---------------------------------------------------------------------------
// Pool state

/// Root of the tree whose completed left subtrees are `frontier`, one for each
/// set bit of `count`; every position after `count` is an empty leaf.
pub fn tree_root(count: u64, frontier: &[[u8; 32]; 32]) -> Option<[u8; 32]> {
    let mut node = MerkleHashOrchard::empty_leaf();
    for (level, stored) in frontier.iter().enumerate() {
        let height = Level::from(level as u8);
        node = if (count >> level) & 1 == 1 {
            let left = Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(stored))?;
            MerkleHashOrchard::combine(height, &left, &node)
        } else {
            MerkleHashOrchard::combine(height, &node, &MerkleHashOrchard::empty_root(height))
        };
    }
    Some(node.to_bytes())
}

pub struct PoolParts {
    pub network: [u8; 32],
    pub rent_floor: u64,
    pub backing: u64,
    pub count: u64,
    pub frontier: [[u8; 32]; 32],
}

impl PoolParts {
    fn prefix(&self, tag: &[u8; 8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(tag);
        bytes.extend_from_slice(&self.network);
        for value in [self.rent_floor, self.backing, self.count] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        bytes
    }

    /// `NPOOL003`: the frontier and up to 64 recent roots.
    pub fn encode_with_roots(&self, roots: &[[u8; 32]]) -> Vec<u8> {
        let mut bytes = self.prefix(b"NPOOL003");
        bytes.push(roots.len() as u8);
        for node in &self.frontier {
            bytes.extend_from_slice(node);
        }
        for root in roots {
            bytes.extend_from_slice(root);
        }
        bytes.resize(STATE_BYTES, 0);
        bytes
    }

    /// `NPOOL004`: the frontier and an embedded slot anchor history.
    pub fn encode_with_history(&self, history: &[u8]) -> Vec<u8> {
        let mut bytes = self.prefix(b"NPOOL004");
        for node in &self.frontier {
            bytes.extend_from_slice(node);
        }
        bytes.extend_from_slice(&(history.len() as u32).to_le_bytes());
        bytes.extend_from_slice(history);
        bytes.resize(SLOT_STATE_BYTES.max(bytes.len()), 0);
        bytes
    }
}

fn pool_parts(bytes: &[u8]) -> Option<PoolParts> {
    let parts = PoolParts {
        network: array(&bytes[8..40]),
        rent_floor: number(&bytes[40..48]),
        backing: number(&bytes[48..56]),
        count: number(&bytes[56..64]),
        frontier: [[0; 32]; 32],
    };
    (parts.network != [0; 32]
        && parts.backing <= i64::MAX as u64
        && parts.count <= MAX_COMMITMENTS
        && parts.count.is_multiple_of(2))
    .then_some(parts)
}

/// An occupied level holds a field element; an unoccupied one holds zeros.
fn read_frontier(parts: &mut PoolParts, bytes: &[u8]) -> bool {
    for (level, node) in bytes.chunks(32).enumerate() {
        let node: [u8; 32] = array(node);
        let valid = if (parts.count >> level) & 1 == 1 {
            is_field_element(node)
        } else {
            node == [0; 32]
        };
        if !valid {
            return false;
        }
        parts.frontier[level] = node;
    }
    true
}

/// For a slot-anchored state that keeps every other rule of the format:
/// whether the next completed slot could record its tree. `None` when another
/// rule is broken.
pub fn slot_anchored_tree_is_recordable(bytes: &[u8]) -> Option<bool> {
    if !bytes.starts_with(b"NPOOL004") || bytes.len() != SLOT_STATE_BYTES {
        return None;
    }
    let mut parts = pool_parts(bytes)?;
    let frontier_end = POOL_PREFIX_BYTES + 32 * 32;
    if !read_frontier(&mut parts, &bytes[POOL_PREFIX_BYTES..frontier_end]) {
        return None;
    }
    let history_length = u32::from_le_bytes(array(&bytes[frontier_end..frontier_end + 4]));
    let rest = &bytes[frontier_end + 4..];
    let (history, padding) = rest.split_at_checked(history_length as usize)?;
    if padding.iter().any(|byte| *byte != 0) {
        return None;
    }
    let entries = decode_history(parts.network, history)?;
    let root = tree_root(parts.count, &parts.frontier)?;
    Some(tree_can_be_recorded(&entries, parts.count, root))
}

pub fn pool_state_is_valid(bytes: &[u8]) -> bool {
    if bytes.starts_with(b"NPOOL004") {
        // The frontier and the checkpoints are well formed, and the tree is
        // one that the next completed slot can record. That covers the two
        // older rules as well: the newest checkpoint is not ahead of the
        // tree, and a checkpoint of the present note count carries its root.
        slot_anchored_tree_is_recordable(bytes) == Some(true)
    } else {
        if bytes.len() != STATE_BYTES || &bytes[..8] != b"NPOOL003" {
            return false;
        }
        let Some(mut parts) = pool_parts(bytes) else {
            return false;
        };
        let root_count = usize::from(bytes[POOL_PREFIX_BYTES]);
        let frontier_start = POOL_PREFIX_BYTES + 1;
        let frontier_end = frontier_start + 32 * 32;
        if root_count == 0
            || root_count > MAX_ROOTS
            || !read_frontier(&mut parts, &bytes[frontier_start..frontier_end])
        {
            return false;
        }
        let roots: Vec<[u8; 32]> = bytes[frontier_end..].chunks(32).map(array).collect();
        roots[..root_count]
            .iter()
            .all(|root| is_field_element(*root))
            && roots[root_count..].iter().all(|root| *root == [0; 32])
            && tree_root(parts.count, &parts.frontier) == Some(roots[root_count - 1])
    }
}

// ---------------------------------------------------------------------------
// Payments and envelopes

pub const PAYMENT_TAG: &[u8; 8] = b"NPAY0001";
pub const WITHDRAWAL_TAG: &[u8; 8] = b"NPAY0002";
pub const FEE_TAG: &[u8; 8] = b"NPAY0003";

pub fn proof_bytes() -> usize {
    Proof::expected_proof_size(ACTION_COUNT)
}

pub fn flag_byte() -> u8 {
    bundle_version()
        .default_flags()
        .to_byte(bundle_version())
        .expect("default flags are representable")
}

/// Bytes a tag adds between the sponsor and the anchor, if the tag is known.
pub fn tag_extra_bytes(bytes: &[u8]) -> Option<usize> {
    match bytes.get(..8)? {
        tag if tag == PAYMENT_TAG => Some(0),
        tag if tag == WITHDRAWAL_TAG => Some(32),
        tag if tag == FEE_TAG => Some(8),
        _ => None,
    }
}

pub fn payment_bytes(extra: usize) -> usize {
    HEADER_BYTES + extra + ACTION_COUNT * ACTION_BYTES + 4 + proof_bytes() + 64
}

pub fn payment_is_valid(network: [u8; 32], bytes: &[u8]) -> bool {
    let Some(extra) = tag_extra_bytes(bytes) else {
        return false;
    };
    if bytes.len() != payment_bytes(extra) || network == [0; 32] || bytes[8..40] != network {
        return false;
    }
    let balance = i64::from_le_bytes(array(&bytes[48..56]));
    if bytes[56..88] == [0; 32] {
        return false;
    }
    let context = match extra {
        // A shielded fee is positive and is the whole public movement.
        8 => {
            let fee = number(&bytes[88..96]);
            fee != 0 && fee <= i64::MAX as u64 && balance == fee as i64
        }
        // A bound recipient exists and receives a positive amount.
        32 => bytes[88..120] != [0; 32] && balance > 0,
        _ => true,
    };
    let mut at = 88 + extra;
    if !context
        || !is_field_element(array(&bytes[at..at + 32]))
        || bytes[at + 32] != flag_byte()
        || usize::from(bytes[at + 33]) != ACTION_COUNT
    {
        return false;
    }
    at += 34;
    for _ in 0..ACTION_COUNT {
        let action = &bytes[at..at + ACTION_BYTES];
        let key: [u8; 32] = array(&action[32..64]);
        let ephemeral: [u8; 32] = array(&action[96..128]);
        let valid = bool::from(Nullifier::from_bytes(&array(&action[..32])).is_some())
            && key != [0; 32]
            && redpallas::VerificationKey::<redpallas::SpendAuth>::try_from(key).is_ok()
            && bool::from(ExtractedNoteCommitment::from_bytes(&array(&action[64..96])).is_some())
            && ephemeral != [0; 32]
            && is_point(ephemeral)
            && is_point(array(&action[788..820]));
        if !valid {
            return false;
        }
        at += ACTION_BYTES;
    }
    u32::from_le_bytes(array(&bytes[at..at + 4])) as usize == proof_bytes()
}

pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    array(
        blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"NativeStageV1!!!")
            .hash(payload)
            .as_bytes(),
    )
}

/// Frames `payload` with the stated header values, whatever they are.
pub fn frame(
    network: [u8; 32],
    expires_at: u64,
    identity: [u8; 32],
    length: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ZOLNPAY1");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(b"ZolanaNativePay!");
    bytes.extend_from_slice(&network);
    bytes.extend_from_slice(&expires_at.to_le_bytes());
    bytes.extend_from_slice(&identity);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn envelope_is_valid(network: [u8; 32], current_slot: u64, bytes: &[u8]) -> bool {
    if bytes.len() <= ENVELOPE_HEADER_BYTES || bytes.len() > MAX_ENVELOPE_BYTES {
        return false;
    }
    let payload = &bytes[ENVELOPE_HEADER_BYTES..];
    let expires_at = number(&bytes[58..66]);
    &bytes[..8] == b"ZOLNPAY1"
        && bytes[8..10] == 1u16.to_le_bytes()
        && &bytes[10..26] == b"ZolanaNativePay!"
        && network != [0; 32]
        && bytes[26..58] == network
        && u32::from_le_bytes(array(&bytes[98..102])) as usize == payload.len()
        && payload.len() <= MAX_INNER_PAYMENT_BYTES
        && bytes[66..98] == payload_digest(payload)
        && payload.starts_with(FEE_TAG)
        && payment_is_valid(network, payload)
        && number(&payload[40..48]) == expires_at
        && expires_at >= current_slot
        && expires_at - current_slot <= MAX_EXPIRY_WINDOW
}
