//! Internal snapshots are accepted only after wallet-key authenticated decryption.
use super::*;
use super::{SavedNote, StateSnapshot};
use crate::replay::Replay;
use native_payments::native_accounts::{pool_address, Buffer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplaySnapshot {
    pool: Vec<u8>,
    leaves: Vec<[u8; 32]>,
    spent: BTreeSet<[u8; 32]>,
    notes: Vec<SavedNote>,
    buffers: Vec<([u8; 32], Vec<u8>)>,
}

impl Replay {
    pub fn snapshot(&self) -> ReplaySnapshot {
        let snapshot = self.state.snapshot();
        ReplaySnapshot {
            pool: snapshot.pool,
            leaves: snapshot.leaves,
            spent: snapshot.spent,
            notes: snapshot.notes,
            buffers: self
                .buffers
                .iter()
                .map(|(key, value)| (*key, value.bytes().to_vec()))
                .collect(),
        }
    }
    pub fn restore(wallet: &(impl WalletKeys + ?Sized), snapshot: ReplaySnapshot) -> Result<Self> {
        Self::restore_with_key(wallet, snapshot, None)
    }
    pub fn restore_with_key(
        wallet: &(impl WalletKeys + ?Sized),
        snapshot: ReplaySnapshot,
        key: Option<Arc<VerifyingKey>>,
    ) -> Result<Self> {
        let state = WalletState::restore_with_key(
            wallet,
            StateSnapshot {
                pool: snapshot.pool,
                leaves: snapshot.leaves,
                spent: snapshot.spent,
                notes: snapshot.notes,
            },
            key,
        )?;
        let mut buffers = HashMap::new();
        for (key, encoded) in snapshot.buffers {
            let buffer = Buffer::decode(&encoded)?;
            if key == pool_address()
                || key == buffer.sponsor()
                || buffers.insert(key, buffer).is_some()
            {
                return Err("invalid cached staging account".into());
            }
        }
        Ok(Self { state, buffers })
    }
}
