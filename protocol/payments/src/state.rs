//! Compact persisted pool state. The runtime authenticates spent-note accounts separately.

use crate::{verification::VerifiedPayment, Error};
use incrementalmerkletree::{Hashable, Level};
use orchard::tree::{Anchor, MerkleHashOrchard};
use std::collections::BTreeSet;

/// Two-action payments must leave a representable 32-level frontier.
pub const MAX_COMMITMENTS: u64 = (1u64 << 32) - 2;
/// A bounded burst allowance, not a guarantee that every live proof stays valid.
/// Clients must still synchronize and avoid indefinite proof queues.
pub const MAX_ROOTS: usize = 64;
pub const STATE_BYTES: usize = 8 + 32 + 8 + 8 + 8 + 1 + 32 * 32 + MAX_ROOTS * 32;

#[derive(Clone)]
pub struct PoolState {
    pub network: [u8; 32],
    pub rent_floor: u64,
    pub backing: u64,
    count: u64,
    frontier: [Option<MerkleHashOrchard>; 32],
    roots: Vec<[u8; 32]>,
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
        })
    }

    pub fn roots(&self) -> BTreeSet<[u8; 32]> {
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
        next.roots.push(next.root());
        if next.roots.len() > MAX_ROOTS {
            next.roots.remove(0);
        }
        Ok(next)
    }

    pub fn encode(&self) -> Vec<u8> {
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
        };
        if state.roots.last() != Some(&state.root()) {
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
            commitments: [MerkleHashOrchard::empty_leaf().to_bytes(); 2],
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
        // appending four billion leaves. Every occupied subtree is an empty root.
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
}
