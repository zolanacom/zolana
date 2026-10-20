//! Reconstruct from successful finalized instructions; never accept an RPC balance assertion.
mod snapshot;
use crate::{keys::WalletKey, Result};
use incrementalmerkletree::{Hashable, Level};
use native_payment_program::{
    nullifiers, pool_address,
    staging::{Buffer, ACCOUNT_BYTES},
};
use native_payments::{
    state::PoolState,
    verification::{
        bundle_version, AuthorizationContext, PaymentVerifier, ValidationView, VerifiedPayment,
        MAX_EXPIRY_WINDOW,
    },
    wire,
};
use orchard::{
    bundle::Authorized,
    circuit::VerifyingKey,
    keys::{FullViewingKey, Scope},
    tree::{MerkleHashOrchard, MerklePath},
    Bundle, Note,
};
pub(crate) use snapshot::ReplaySnapshot;
use solana_pubkey::Pubkey;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

pub struct OwnedNote {
    pub note: Note,
    pub position: u32,
}

pub struct WalletState {
    pub pool: PoolState,
    leaves: Vec<MerkleHashOrchard>,
    notes: Vec<OwnedNote>,
    spent: BTreeSet<[u8; 32]>,
    view: FullViewingKey,
    verifier: PaymentVerifier,
}

impl WalletState {
    pub fn new(wallet: &WalletKey, rent_floor: u64) -> Result<Self> {
        Self::with_key(
            wallet,
            rent_floor,
            Arc::new(VerifyingKey::build(bundle_version().circuit_version())),
        )
    }

    pub(crate) fn with_key(
        wallet: &WalletKey,
        rent_floor: u64,
        key: Arc<VerifyingKey>,
    ) -> Result<Self> {
        Ok(Self {
            pool: PoolState::new(wallet.network.network, rent_floor)?,
            leaves: Vec::new(),
            notes: Vec::new(),
            spent: BTreeSet::new(),
            view: wallet.viewing_key(),
            verifier: PaymentVerifier::with_shared_key(wallet.network.network, key)?,
        })
    }

    pub fn accept(
        &mut self,
        bundle: &Bundle<Authorized, i64>,
        authorization: &AuthorizationContext,
        slot: u64,
    ) -> Result<()> {
        let effects = self.verifier.verify(
            bundle,
            authorization,
            &ValidationView {
                current_slot: slot,
                accepted_anchors: &self.pool.roots(),
                spent_nullifiers: &self.spent,
                authorized_public_value_balance: authorization.public_value_balance,
            },
        )?;
        self.apply_effects(bundle, &effects)
    }

    fn apply_effects(
        &mut self,
        bundle: &Bundle<Authorized, i64>,
        effects: &VerifiedPayment,
    ) -> Result<()> {
        if effects.nullifiers.iter().any(|nf| self.spent.contains(nf)) {
            return Err("verified history payment was already applied".into());
        }
        let next = self.pool.with_payment(effects)?;
        let position = self.pool.note_count();
        let keys = [
            self.view.to_ivk(Scope::External),
            self.view.to_ivk(Scope::Internal),
        ];
        for (index, _, note, _, _) in bundle.decrypt_outputs_with_keys(&keys) {
            if note.value().inner() > 0 {
                self.notes.push(OwnedNote {
                    note,
                    position: u32::try_from(position + index as u64)?,
                });
            }
        }
        self.leaves.extend(
            bundle
                .actions()
                .iter()
                .map(|action| MerkleHashOrchard::from_cmx(action.cmx())),
        );
        self.spent.extend(effects.nullifiers);
        self.pool = next;
        Ok(())
    }

    pub fn reconcile(&self, expected: &PoolState) -> Result<()> {
        if self.pool.encode() != expected.encode()
            || self.leaves.len() as u64 != expected.note_count()
        {
            return Err("history is incomplete or does not match the finalized native pool; an archive RPC is required".into());
        }
        if self.balance()? > expected.backing {
            return Err("wallet notes exceed native backing".into());
        }
        Ok(())
    }

    pub fn unspent(&self) -> Vec<&OwnedNote> {
        self.notes
            .iter()
            .filter(|owned| {
                !self
                    .spent
                    .contains(&owned.note.nullifier(&self.view).to_bytes())
            })
            .collect()
    }

    pub fn balance(&self) -> Result<u64> {
        self.unspent().iter().try_fold(0u64, |sum, owned| {
            sum.checked_add(owned.note.value().inner())
                .ok_or_else(|| "wallet balance overflow".into())
        })
    }

    pub fn max_payment(&self) -> Result<u64> {
        let mut notes = self.unspent();
        notes.sort_by_key(|note| std::cmp::Reverse(note.note.value().inner()));
        notes.iter().take(2).try_fold(0u64, |sum, owned| {
            sum.checked_add(owned.note.value().inner())
                .ok_or_else(|| "wallet balance overflow".into())
        })
    }

    pub fn witness(&self, position: u32) -> Result<MerklePath> {
        let mut index = position as usize;
        if index >= self.leaves.len() {
            return Err("note position is outside the authenticated tree".into());
        }
        let mut nodes = self.leaves.clone();
        let mut siblings = [MerkleHashOrchard::empty_leaf(); 32];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            let empty = MerkleHashOrchard::empty_root(Level::from(level as u8));
            *sibling = nodes.get(index ^ 1).copied().unwrap_or(empty);
            nodes = nodes
                .chunks(2)
                .map(|pair| {
                    MerkleHashOrchard::combine(
                        Level::from(level as u8),
                        &pair[0],
                        pair.get(1).unwrap_or(&empty),
                    )
                })
                .collect();
            index /= 2;
        }
        let path = MerklePath::from_parts(position, siblings);
        if nodes.len() != 1 || nodes[0].to_bytes() != self.pool.root() {
            return Err("witness root does not match native state".into());
        }
        Ok(path)
    }
}

pub struct HistoryInstruction {
    pub accounts: Vec<(Pubkey, bool)>,
    pub data: Vec<u8>,
}

/// Constructed only after complete proof and history verification. Reusable only
/// for other local views at the exact same authenticated pre-payment checkpoint.
pub(crate) struct AcceptedHistoryPayment {
    before: Vec<u8>,
    payment: wire::DecodedPayment,
    effects: VerifiedPayment,
}
impl AcceptedHistoryPayment {
    pub(crate) fn payload_digest(&self) -> Result<[u8; 32]> {
        Ok(native_payments::staging::payload_digest(&wire::encode(
            PoolState::decode(&self.before)?.network,
            &self.payment.context,
            &self.payment.bundle,
        )?))
    }
    pub(crate) fn withdrawal(&self) -> Option<crate::payments::WithdrawalReceipt> {
        crate::payments::withdrawal_receipt(&self.payment)
    }
    pub(crate) fn apply(&self, state: &mut WalletState) -> Result<()> {
        if state.pool.encode() != self.before {
            return Err("shared history checkpoint mismatch".into());
        }
        state.apply_effects(&self.payment.bundle, &self.effects)
    }
}

pub struct Replay {
    pub state: WalletState,
    buffers: HashMap<Pubkey, Buffer>,
}

impl Replay {
    pub fn new(wallet: &WalletKey, rent_floor: u64) -> Result<Self> {
        Ok(Self {
            state: WalletState::new(wallet, rent_floor)?,
            buffers: HashMap::new(),
        })
    }

    pub fn apply(&mut self, ix: &HistoryInstruction, slot: u64) -> Result<()> {
        self.apply_verified(ix, slot).map(|_| ())
    }

    pub(crate) fn from_state(state: WalletState) -> Self {
        Self {
            state,
            buffers: HashMap::new(),
        }
    }

    pub(crate) fn apply_verified(
        &mut self,
        ix: &HistoryInstruction,
        slot: u64,
    ) -> Result<Option<AcceptedHistoryPayment>> {
        let (&opcode, rest) = ix
            .data
            .split_first()
            .ok_or("empty native history instruction")?;
        let accounts = &ix.accounts;
        if opcode == 3 {
            if !rest.is_empty()
                || ![6, 7].contains(&accounts.len())
                || accounts[0].0 != pool_address()
                || accounts[3].0 != solana_sdk_ids::system_program::id()
                || !accounts[2].1
            {
                return Err("invalid native finalization in history".into());
            }
            let buffer = self
                .buffers
                .get_mut(&accounts[1].0)
                .ok_or("missing staging history; an archive RPC is required")?;
            if buffer.sponsor() != accounts[2].0.to_bytes() || slot > buffer.expiry() {
                return Err("history sponsor or expiry mismatch".into());
            }
            let payment = wire::decode(self.state.pool.network, buffer.payload()?)?;
            if payment.context.sponsor != accounts[2].0.to_bytes() {
                return Err("history authorization sponsor mismatch".into());
            }
            match payment.context.withdrawal_recipient {
                None if accounts.len() == 6 => (),
                Some(recipient)
                    if accounts.len() == 7
                        && accounts[6].0.to_bytes() == recipient
                        && accounts[6].0.is_on_curve()
                        && accounts[6].0 != accounts[2].0 => {}
                _ => return Err("history withdrawal recipient/account shape mismatch".into()),
            }
            for (index, action) in payment.bundle.actions().iter().enumerate() {
                if accounts[4 + index].0 != nullifiers::address(&action.nullifier().to_bytes()) {
                    return Err("history nullifier address mismatch".into());
                }
            }
            let before = self.state.pool.encode();
            let effects = self.state.verifier.verify(
                &payment.bundle,
                &payment.context,
                &ValidationView {
                    current_slot: slot,
                    accepted_anchors: &self.state.pool.roots(),
                    spent_nullifiers: &self.state.spent,
                    authorized_public_value_balance: payment.context.public_value_balance,
                },
            )?;
            self.state.apply_effects(&payment.bundle, &effects)?;
            buffer.consume()?;
            return Ok(Some(AcceptedHistoryPayment {
                before,
                payment,
                effects,
            }));
        }
        if accounts.len() != 2
            || !accounts[1].1
            || accounts[0].0 == pool_address()
            || accounts[0].0 == accounts[1].0
        {
            return Err("invalid native staging history".into());
        }
        let key = accounts[0].0;
        if opcode == 0 {
            if rest.len() != 44 || !accounts[0].1 || self.buffers.contains_key(&key) {
                return Err("invalid staging initialization history".into());
            }
            let expiry = u64::from_le_bytes(rest[36..44].try_into()?);
            if expiry < slot || expiry.saturating_sub(slot) > MAX_EXPIRY_WINDOW {
                return Err("invalid staging expiry history".into());
            }
            let buffer = Buffer::initialize(
                &vec![0; ACCOUNT_BYTES],
                accounts[1].0.to_bytes(),
                u32::from_le_bytes(rest[..4].try_into()?),
                rest[4..36].try_into()?,
                expiry,
            )?;
            self.buffers.insert(key, buffer);
            return Ok(None);
        }
        let buffer = self
            .buffers
            .get_mut(&key)
            .ok_or("missing staging history; an archive RPC is required")?;
        if buffer.sponsor() != accounts[1].0.to_bytes() || (opcode != 4 && slot > buffer.expiry()) {
            return Err("staging history sponsor or expiry mismatch".into());
        }
        match opcode {
            1 if rest.len() >= 5 => {
                buffer.write(u32::from_le_bytes(rest[..4].try_into()?), &rest[4..])?
            }
            2 if rest.is_empty() => buffer.seal()?,
            4 if rest.is_empty() => {
                self.buffers.remove(&key);
            }
            _ => return Err("unknown native instruction in history".into()),
        }
        Ok(None)
    }
}

#[cfg(test)]
mod shared_scan_tests {
    use super::*;
    use crate::{
        keys::Network,
        payments::{self, Payment},
    };
    use native_payment_program::instructions;
    use native_payments::staging::{payload_digest, MAX_CHUNK_BYTES};

    #[test]
    fn verified_history_fans_out_only_at_the_identical_checkpoint() {
        let network = Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        };
        let alice = WalletKey::generate(network.clone()).unwrap();
        let bob = WalletKey::generate(network).unwrap();
        let mut primary = Replay::new(&alice, 1000).unwrap();
        let mut same_view = WalletState::new(&alice, 1000).unwrap();
        let mut other_view = WalletState::new(&bob, 1000).unwrap();
        let sponsor = Pubkey::new_unique();
        let buffer = Pubkey::new_unique();
        let bytes = payments::build(
            &alice,
            &primary.state,
            sponsor.to_bytes(),
            100,
            Payment::Deposit {
                amount: 100,
                recipient: &alice.address_text(),
            },
        )
        .unwrap();
        let mut history = vec![instructions::initialize(
            buffer,
            sponsor,
            bytes.len() as u32,
            payload_digest(&bytes),
            100,
        )];
        for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
            history.push(instructions::write(
                buffer,
                sponsor,
                (index * MAX_CHUNK_BYTES) as u32,
                chunk,
            ));
        }
        history.push(instructions::seal(buffer, sponsor));
        let payment = wire::decode(alice.network.network, &bytes).unwrap();
        history.push(instructions::finalize(
            buffer,
            sponsor,
            std::array::from_fn(|i| payment.bundle.actions()[i].nullifier().to_bytes()),
        ));
        let mut accepted = None;
        for (index, ix) in history.into_iter().enumerate() {
            accepted = primary
                .apply_verified(
                    &HistoryInstruction {
                        accounts: ix
                            .accounts
                            .iter()
                            .map(|meta| (meta.pubkey, meta.is_signer))
                            .collect(),
                        data: ix.data,
                    },
                    1,
                )
                .unwrap()
                .or(accepted);
            if index == 2 {
                // A checkpoint may land in the middle of an upload. Resume its
                // bytes and authorization, rather than losing open buffers.
                primary = Replay::restore(&alice, primary.snapshot()).unwrap();
            }
        }
        let accepted = accepted.unwrap();
        accepted.apply(&mut same_view).unwrap();
        accepted.apply(&mut other_view).unwrap();
        assert_eq!(same_view.balance().unwrap(), 100);
        assert_eq!(other_view.balance().unwrap(), 0);
        let restored = Replay::restore(&alice, primary.snapshot()).unwrap();
        assert_eq!(restored.state.balance().unwrap(), 100);
        assert_eq!(restored.state.spent, primary.state.spent);
        assert_eq!(
            restored.state.witness(0).unwrap().auth_path(),
            primary.state.witness(0).unwrap().auth_path()
        );
        assert!(Replay::restore(&bob, primary.snapshot()).is_err());
        let mut corrupted = serde_json::to_value(primary.snapshot()).unwrap();
        corrupted["notes"][0]["value"] = serde_json::json!(101);
        assert!(Replay::restore(&alice, serde_json::from_value(corrupted).unwrap()).is_err());
        same_view.reconcile(&primary.state.pool).unwrap();
        other_view.reconcile(&primary.state.pool).unwrap();
        assert!(accepted.apply(&mut same_view).is_err());
        other_view.pool.backing += 1;
        assert!(accepted.apply(&mut other_view).is_err());
    }
}
