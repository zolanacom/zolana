//! Bounded local-devnet state; every byte is persisted in a runtime account.

use crate::{verification::VerifiedPayment, Error};
use incrementalmerkletree::{Hashable, Level};
use orchard::tree::{Anchor, MerkleHashOrchard};
use std::collections::BTreeSet;

pub const MAX_NULLIFIERS: usize = 256;
pub const MAX_ROOTS: usize = 16;
pub const STATE_BYTES: usize =
    8 + 32 + 8 + 8 + 8 + 4 + 2 + 1 + 32 * 32 + MAX_NULLIFIERS * 32 + MAX_ROOTS * 32;

#[derive(Clone)]
pub struct PoolState {
    pub network: [u8; 32],
    pub rent_floor: u64,
    pub backing: u64,
    count: u64,
    frontier: [Option<MerkleHashOrchard>; 32],
    nullifiers: BTreeSet<[u8; 32]>,
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
            nullifiers: BTreeSet::new(),
            roots: vec![Anchor::empty_tree().to_bytes()],
        })
    }

    pub fn roots(&self) -> BTreeSet<[u8; 32]> {
        self.roots.iter().copied().collect()
    }
    pub fn nullifiers(&self) -> &BTreeSet<[u8; 32]> {
        &self.nullifiers
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

    pub fn with_payment(&self, payment: &VerifiedPayment) -> Result<Self, Error> {
        if self.nullifiers.len() + 2 > MAX_NULLIFIERS {
            return Err(Error::CapacityExceeded);
        }
        let mut next = self.clone();
        for nullifier in payment.nullifiers {
            if !next.nullifiers.insert(nullifier) {
                return Err(Error::SpentNullifier);
            }
        }
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
        bytes.extend_from_slice(b"NPOOL001");
        bytes.extend_from_slice(&self.network);
        for number in [self.rent_floor, self.backing, self.count] {
            bytes.extend_from_slice(&number.to_le_bytes());
        }
        bytes.extend_from_slice(&(self.count as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.nullifiers.len() as u16).to_le_bytes());
        bytes.push(self.roots.len() as u8);
        for node in self.frontier {
            bytes.extend_from_slice(&node.map(|n| n.to_bytes()).unwrap_or([0; 32]));
        }
        for n in &self.nullifiers {
            bytes.extend_from_slice(n);
        }
        bytes.resize(8 + 32 + 24 + 4 + 2 + 1 + 1024 + MAX_NULLIFIERS * 32, 0);
        for root in &self.roots {
            bytes.extend_from_slice(root);
        }
        bytes.resize(STATE_BYTES, 0);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != STATE_BYTES || &bytes[..8] != b"NPOOL001" {
            return Err(Error::InvalidEncoding);
        }
        let mut reader = Reader(&bytes[8..]);
        let network = reader.take()?;
        let rent_floor = u64::from_le_bytes(reader.take()?);
        let backing = u64::from_le_bytes(reader.take()?);
        let count = u64::from_le_bytes(reader.take()?);
        let mask = u32::from_le_bytes(reader.take()?);
        let nf_count = u16::from_le_bytes(reader.take()?) as usize;
        let root_count = reader.take::<1>()?[0] as usize;
        if network == [0; 32]
            || backing > i64::MAX as u64
            || count != nf_count as u64
            || nf_count > MAX_NULLIFIERS
            || root_count == 0
            || root_count > MAX_ROOTS
            || mask as u64 != count
        {
            return Err(Error::InvalidEncoding);
        }
        let mut frontier = [None; 32];
        for (i, node) in frontier.iter_mut().enumerate() {
            let data = reader.take()?;
            if mask & (1u32 << i) != 0 {
                *node = Some(
                    Option::<MerkleHashOrchard>::from(MerkleHashOrchard::from_bytes(&data))
                        .ok_or(Error::InvalidEncoding)?,
                );
            } else if data != [0; 32] {
                return Err(Error::InvalidEncoding);
            }
        }
        let mut nullifiers = BTreeSet::new();
        let mut previous = None;
        for i in 0..MAX_NULLIFIERS {
            let data = reader.take()?;
            if i < nf_count {
                if previous.is_some_and(|prior| prior >= data) || !nullifiers.insert(data) {
                    return Err(Error::InvalidEncoding);
                }
                previous = Some(data);
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
            nullifiers,
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
    fn persisted_pool_conserves_backing_and_stops_at_capacity() {
        let mut pool = PoolState::new([1; 32], 1000).unwrap();
        let commitment = MerkleHashOrchard::empty_leaf().to_bytes();
        for index in 0..128u16 {
            let mut first = [0; 32];
            first[..2].copy_from_slice(&(index * 2).to_be_bytes());
            let mut second = [0; 32];
            second[..2].copy_from_slice(&(index * 2 + 1).to_be_bytes());
            let effects = VerifiedPayment {
                nullifiers: [first, second],
                commitments: [commitment; 2],
                public_value_balance: -10,
            };
            pool = pool.with_payment(&effects).unwrap();
            let encoded = pool.encode();
            pool = PoolState::decode(&encoded).unwrap();
            assert_eq!(pool.encode(), encoded);
            assert_eq!(pool.backing, (index as u64 + 1) * 10);
            assert_eq!(pool.note_count(), (index as u64 + 1) * 2);
            assert!(matches!(
                pool.with_payment(&effects),
                Err(Error::SpentNullifier | Error::CapacityExceeded)
            ));
        }
        let effects = VerifiedPayment {
            nullifiers: [[3; 32], [4; 32]],
            commitments: [commitment; 2],
            public_value_balance: 0,
        };
        assert!(matches!(
            pool.with_payment(&effects),
            Err(Error::CapacityExceeded)
        ));
        let mut invalid = pool.encode();
        invalid[0] ^= 1;
        assert!(PoolState::decode(&invalid).is_err());
        let mut invalid = PoolState::new([1; 32], 1000).unwrap().encode();
        *invalid.last_mut().unwrap() = 1;
        assert!(PoolState::decode(&invalid).is_err());
        let empty = PoolState::new([1; 32], 1000).unwrap();
        let unpaid = VerifiedPayment {
            public_value_balance: 1,
            ..effects
        };
        assert!(matches!(
            empty.with_payment(&unpaid),
            Err(Error::InsufficientBacking)
        ));
    }
}
