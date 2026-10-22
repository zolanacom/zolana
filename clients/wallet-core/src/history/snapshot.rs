//! Plaintext state codec; caller must authenticate encrypted checkpoint first.
use super::*;
use orchard::{
    note::{ExtractedNoteCommitment, NoteVersion, RandomSeed, Rho},
    value::NoteValue,
    Address,
};
use serde::{Deserialize, Serialize};

/// Internal plaintext checkpoint data. Hosts must authenticate decryption before
/// importing, and encrypt before exporting to disk/JS. This is not a WASM API.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateSnapshot {
    pub pool: Vec<u8>,
    pub leaves: Vec<[u8; 32]>,
    pub spent: BTreeSet<[u8; 32]>,
    pub notes: Vec<SavedNote>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedNote {
    position: u32,
    recipient: Vec<u8>,
    value: u64,
    rho: [u8; 32],
    rseed: [u8; 32],
    version: u8,
}

impl WalletState {
    pub fn snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            pool: self.pool.encode(),
            leaves: self
                .tree
                .leaves
                .iter()
                .map(MerkleHashOrchard::to_bytes)
                .collect(),
            spent: self.spent.clone(),
            notes: self
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
        }
    }
    pub fn restore_with_key(
        wallet: &(impl WalletKeys + ?Sized),
        snapshot: StateSnapshot,
        key: Option<Arc<VerifyingKey>>,
    ) -> Result<Self> {
        let pool = PoolState::decode(&snapshot.pool)?;
        if pool.network != wallet.network_domain()
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
        state.tree = WitnessTree::from_leaves(
            snapshot
                .leaves
                .into_iter()
                .map(|leaf| {
                    Option::from(MerkleHashOrchard::from_bytes(&leaf))
                        .ok_or_else(|| "invalid cached tree leaf".into())
                })
                .collect::<Result<Vec<_>>>()?,
        )?;
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
                .tree
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
        state.reconcile(&state.pool)?;
        Ok(state)
    }
}
