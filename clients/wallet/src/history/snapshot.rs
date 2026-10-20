//! Internal snapshots are accepted only after wallet-key authenticated decryption.
use super::*;
use orchard::{
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    value::NoteValue,
    Address,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReplaySnapshot {
    pool: Vec<u8>,
    leaves: Vec<[u8; 32]>,
    spent: BTreeSet<[u8; 32]>,
    notes: Vec<SavedNote>,
    buffers: Vec<([u8; 32], Vec<u8>)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedNote {
    position: u32,
    recipient: Vec<u8>,
    value: u64,
    rho: [u8; 32],
    rseed: [u8; 32],
    version: u8,
}

impl Replay {
    pub(crate) fn snapshot(&self) -> ReplaySnapshot {
        ReplaySnapshot {
            pool: self.state.pool.encode(),
            leaves: self
                .state
                .leaves
                .iter()
                .map(MerkleHashOrchard::to_bytes)
                .collect(),
            spent: self.state.spent.clone(),
            notes: self
                .state
                .notes
                .iter()
                .map(|owned| SavedNote {
                    position: owned.position,
                    recipient: owned.note.recipient().to_raw_address_bytes().to_vec(),
                    value: owned.note.value().inner(),
                    rho: owned.note.rho().to_bytes(),
                    rseed: *owned.note.rseed().as_bytes(),
                    version: match owned.note.version() {
                        NoteVersion::V2 => 2,
                        NoteVersion::V3 => 3,
                    },
                })
                .collect(),
            buffers: self
                .buffers
                .iter()
                .map(|(key, value)| (key.to_bytes(), value.bytes().to_vec()))
                .collect(),
        }
    }

    #[cfg(test)]
    pub(crate) fn restore(wallet: &WalletKey, snapshot: ReplaySnapshot) -> Result<Self> {
        Self::restore_with_key(wallet, snapshot, None)
    }

    pub(crate) fn restore_with_key(
        wallet: &WalletKey,
        snapshot: ReplaySnapshot,
        key: Option<Arc<VerifyingKey>>,
    ) -> Result<Self> {
        let pool = PoolState::decode(&snapshot.pool)?;
        if pool.network != wallet.network.network
            || snapshot.leaves.len() as u64 != pool.note_count()
            || snapshot.spent.len() as u64 != pool.note_count()
        {
            return Err("cached tree, network or spent set mismatch".into());
        }
        let mut state = match key {
            Some(key) => WalletState::with_key(wallet, pool.rent_floor, key)?,
            None => WalletState::new(wallet, pool.rent_floor)?,
        };
        state.pool = pool;
        state.leaves = snapshot
            .leaves
            .into_iter()
            .map(|leaf| {
                Option::from(MerkleHashOrchard::from_bytes(&leaf))
                    .ok_or_else(|| "invalid cached tree leaf".into())
            })
            .collect::<Result<Vec<_>>>()?;
        state.spent = snapshot.spent;
        let mut positions = BTreeSet::new();
        for saved in snapshot.notes {
            if !positions.insert(saved.position) || saved.value == 0 {
                return Err("invalid cached note position or value".into());
            }
            let raw = saved
                .recipient
                .try_into()
                .map_err(|_| "invalid cached recipient length")?;
            let recipient = Option::<Address>::from(Address::from_raw_address_bytes(&raw))
                .ok_or("invalid cached recipient")?;
            if state.view.scope_for_address(&recipient).is_none() {
                return Err("cached note belongs to another wallet".into());
            }
            let rho =
                Option::<Rho>::from(Rho::from_bytes(&saved.rho)).ok_or("invalid cached rho")?;
            let rseed = Option::<RandomSeed>::from(RandomSeed::from_bytes(saved.rseed, &rho))
                .ok_or("invalid cached note randomness")?;
            let version = match saved.version {
                2 => NoteVersion::V2,
                3 => NoteVersion::V3,
                _ => return Err("invalid cached note version".into()),
            };
            // These components were obtained by validated note decryption before
            // the authenticated cache was written; never import untrusted notes.
            let note = Option::<Note>::from(Note::from_parts(
                recipient,
                NoteValue::from_raw(saved.value),
                rho,
                rseed,
                version,
            ))
            .ok_or("invalid cached note")?;
            let leaf = state
                .leaves
                .get(saved.position as usize)
                .ok_or("cached note is outside the tree")?;
            if leaf.to_bytes() != ExtractedNoteCommitment::from(note.commitment()).to_bytes() {
                return Err("cached note commitment mismatch".into());
            }
            state.notes.push(OwnedNote {
                note,
                position: saved.position,
            });
        }
        if !state.leaves.is_empty() {
            state.witness(0)?;
        }
        state.reconcile(&state.pool)?;
        let mut buffers = HashMap::new();
        for (key, encoded) in snapshot.buffers {
            let key = Pubkey::new_from_array(key);
            let buffer = Buffer::decode(&encoded)?;
            if key == pool_address()
                || key.to_bytes() == buffer.sponsor()
                || buffers.insert(key, buffer).is_some()
            {
                return Err("invalid cached staging account".into());
            }
        }
        Ok(Self { state, buffers })
    }
}
