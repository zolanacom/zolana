//! Portable proof-checked note replay and witnesses. Finality belongs to the host.
mod replay_snapshot;
mod snapshot;
use crate::{Result, WalletKeys};
use incrementalmerkletree::{Hashable, Level};
use native_payments::{
    state::PoolState,
    verification::{
        bundle_version, AuthorizationContext, PaymentVerifier, ValidationView, VerifiedPayment,
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
pub use replay_snapshot::ReplaySnapshot;
pub use snapshot::{SavedNote, StateSnapshot};
use std::{collections::BTreeSet, sync::Arc};
pub struct OwnedNote {
    pub note: Note,
    pub position: u32,
}

pub struct WalletState {
    pub pool: PoolState,
    tree: WitnessTree,
    notes: Vec<OwnedNote>,
    spent: BTreeSet<[u8; 32]>,
    view: FullViewingKey,
    verifier: PaymentVerifier,
}

impl WalletState {
    pub fn new(wallet: &(impl WalletKeys + ?Sized), rent_floor: u64) -> Result<Self> {
        Self::with_key(
            wallet,
            rent_floor,
            Arc::new(VerifyingKey::build(bundle_version().circuit_version())),
        )
    }

    /// Explicit fresh-network V4 wallet state; existing wallets are not migrated.
    pub fn new_slot_anchored(wallet: &(impl WalletKeys + ?Sized), rent_floor: u64) -> Result<Self> {
        let mut state = Self::new(wallet, rent_floor)?;
        state.pool = PoolState::new_slot_anchored(wallet.network_domain(), rent_floor)?;
        Ok(state)
    }

    /// Complete one authenticated canonical block, including an empty block.
    /// Calling this does not itself authenticate a block or prove finality.
    pub fn finish_slot(&mut self, slot: u64) -> Result<()> {
        if !self.pool.uses_slot_anchors() {
            return Ok(());
        }
        // Pool decode authenticates completed roots against the frontier, and
        // append-only payments increase count. Keep the independent witness
        // tree comparison on every slot, without rehashing an unchanged frontier.
        let root = self
            .pool
            .slot_anchors()
            .and_then(|history| history.entries().last())
            .filter(|checkpoint| checkpoint.note_count == self.pool.note_count())
            .map(|checkpoint| checkpoint.root)
            .unwrap_or_else(|| self.pool.root());
        if self.tree.len() as u64 != self.pool.note_count() || self.tree.root().to_bytes() != root {
            return Err("cannot checkpoint an inconsistent wallet tree".into());
        }
        if let Some(last) = self
            .pool
            .slot_anchors()
            .and_then(|history| history.entries().last())
        {
            if slot < last.slot || (slot == last.slot && last.note_count != self.pool.note_count())
            {
                return Err("wallet block checkpoint is out of order".into());
            }
        }
        self.pool.complete_slot(slot)?;
        Ok(())
    }

    /// A V4 proof must use the complete last replayed block, never an intermediate root.
    pub fn spendable_anchor(&self) -> Result<[u8; 32]> {
        let root = self.pool.root();
        if let Some(history) = self.pool.slot_anchors() {
            let checkpoint = history
                .entries()
                .last()
                .ok_or("wallet has no completed slot checkpoint")?;
            if checkpoint.note_count != self.pool.note_count() || checkpoint.root != root {
                return Err("finish the complete canonical block before preparing a proof".into());
            }
        }
        Ok(root)
    }

    pub fn ensure_slot_open(&self, slot: u64) -> Result<()> {
        if self
            .pool
            .slot_anchors()
            .and_then(|history| history.entries().last())
            .is_some_and(|checkpoint| checkpoint.slot >= slot)
        {
            return Err("history payment follows an already completed block".into());
        }
        Ok(())
    }

    pub fn with_key(
        wallet: &(impl WalletKeys + ?Sized),
        rent_floor: u64,
        key: Arc<VerifyingKey>,
    ) -> Result<Self> {
        Ok(Self {
            pool: PoolState::new(wallet.network_domain(), rent_floor)?,
            tree: WitnessTree::default(),
            notes: Vec::new(),
            spent: BTreeSet::new(),
            view: wallet.viewing_key()?,
            verifier: PaymentVerifier::with_shared_key(wallet.network_domain(), key)?,
        })
    }

    /// Start an empty replay for an explicitly checked on-chain pool version.
    /// Existing replay/cache state is never converted by this constructor.
    pub fn with_key_for_pool(
        wallet: &(impl WalletKeys + ?Sized),
        pool: &PoolState,
        key: Arc<VerifyingKey>,
    ) -> Result<Self> {
        if pool.network != wallet.network_domain() {
            return Err("fresh replay pool does not match the wallet network".into());
        }
        let mut state = Self::with_key(wallet, pool.rent_floor, key)?;
        if pool.uses_slot_anchors() {
            state.pool = PoolState::new_slot_anchored(pool.network, pool.rent_floor)?;
            // Slot zero is the explicitly pinned empty genesis checkpoint.
            state.finish_slot(0)?;
        }
        Ok(state)
    }

    pub fn accept(
        &mut self,
        bundle: &Bundle<Authorized, i64>,
        authorization: &AuthorizationContext,
        slot: u64,
    ) -> Result<()> {
        self.ensure_slot_open(slot)?;
        let roots = self.pool.accepted_roots(slot)?;
        let effects = self.verifier.verify(
            bundle,
            authorization,
            &ValidationView {
                current_slot: slot,
                accepted_anchors: &roots,
                spent_nullifiers: &self.spent,
                authorized_public_value_balance: authorization.public_value_balance,
            },
        )?;
        self.apply_effects(bundle, &effects)
    }

    /// Shared replay of an already authenticated native instruction. This only
    /// verifies its proof/effects; the host must authenticate canonical success,
    /// public debits, block completeness and final pool reconciliation. It is
    /// deliberately not exported directly through the browser ABI.
    pub fn accept_history_payment(
        &mut self,
        payment: wire::DecodedPayment,
        slot: u64,
    ) -> Result<AcceptedPayment> {
        self.ensure_slot_open(slot)?;
        let before = self.pool.encode();
        let roots = self.pool.accepted_roots(slot)?;
        let effects = self.verifier.verify(
            &payment.bundle,
            &payment.context,
            &ValidationView {
                current_slot: slot,
                accepted_anchors: &roots,
                spent_nullifiers: &self.spent,
                authorized_public_value_balance: payment.context.public_value_balance,
            },
        )?;
        self.apply_effects(&payment.bundle, &effects)?;
        Ok(AcceptedPayment {
            slot,
            before,
            payment,
            effects,
        })
    }

    pub fn spent_nullifiers(&self) -> &BTreeSet<[u8; 32]> {
        &self.spent
    }
    pub fn owned_positions(&self) -> impl Iterator<Item = u32> + '_ {
        self.notes.iter().map(|owned| owned.position)
    }

    fn apply_effects(
        &mut self,
        bundle: &Bundle<Authorized, i64>,
        effects: &VerifiedPayment,
    ) -> Result<()> {
        if effects.nullifiers.iter().any(|nf| self.spent.contains(nf)) {
            return Err("verified history payment was already applied".into());
        }
        if self.tree.len() as u64 != self.pool.note_count()
            || self.tree.root().to_bytes() != self.pool.root()
        {
            return Err("history tree does not match native state".into());
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
        self.tree.append(
            &bundle
                .actions()
                .iter()
                .map(|action| MerkleHashOrchard::from_cmx(action.cmx()))
                .collect::<Vec<_>>(),
        )?;
        self.spent.extend(effects.nullifiers);
        self.pool = next;
        Ok(())
    }

    pub fn reconcile(&self, expected: &PoolState) -> Result<()> {
        if self.pool.encode() != expected.encode()
            || self.tree.len() as u64 != expected.note_count()
            || self.tree.root().to_bytes() != expected.root()
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
        self.witness_at_anchor(position, self.spendable_anchor()?)
    }

    /// Reuse an anchor already validated by the payment builder while it holds
    /// an immutable borrow of this state. Every path still authenticates its
    /// leaf to the independent tree root; no frontier or note can change
    /// between anchor validation and construction of the payment's witnesses.
    pub(crate) fn witness_at_anchor(&self, position: u32, anchor: [u8; 32]) -> Result<MerklePath> {
        if self.tree.len() as u64 != self.pool.note_count() || self.tree.root().to_bytes() != anchor
        {
            return Err("payment witness differs from the checked wallet anchor".into());
        }
        self.tree.witness(position, anchor)
    }
}

/// Rebuildable branch cache over the same authenticated leaves saved in existing
/// wallet snapshots. The root and every witness are still checked against the
/// replayed native pool, rather than trusting a cached or RPC-provided path.
///
/// Appending a payment updates only its changed ancestors, and requesting a path
/// reads and hashes exactly 32 siblings, irrespective of total history length.
/// This cache adds fewer than `leaves.len() + 32` internal nodes; retained leaf
/// history itself is not bounded or pruned by this optimization.
#[derive(Default)]
struct WitnessTree {
    leaves: Vec<MerkleHashOrchard>,
    parents: [Vec<MerkleHashOrchard>; 32],
}

impl WitnessTree {
    fn from_leaves(leaves: Vec<MerkleHashOrchard>) -> Result<Self> {
        if leaves.len() as u64 > native_payments::state::MAX_COMMITMENTS {
            return Err("history tree exceeds native capacity".into());
        }
        let mut tree = Self {
            leaves,
            ..Self::default()
        };
        tree.update_from(0);
        Ok(tree)
    }

    fn len(&self) -> usize {
        self.leaves.len()
    }

    fn root(&self) -> MerkleHashOrchard {
        self.parents[31]
            .first()
            .copied()
            .unwrap_or_else(|| MerkleHashOrchard::empty_root(Level::from(32)))
    }

    fn append(&mut self, leaves: &[MerkleHashOrchard]) -> Result<()> {
        let next_len = self
            .len()
            .checked_add(leaves.len())
            .ok_or("history tree capacity overflow")?;
        if next_len as u64 > native_payments::state::MAX_COMMITMENTS {
            return Err("history tree exceeds native capacity".into());
        }
        if !leaves.is_empty() {
            let start = self.len();
            self.leaves.extend_from_slice(leaves);
            self.update_from(start);
        }
        Ok(())
    }

    fn update_from(&mut self, mut start: usize) {
        for level in 0..32 {
            let (children, parents) = if level == 0 {
                (&self.leaves, &mut self.parents[0])
            } else {
                let (below, above) = self.parents.split_at_mut(level);
                (&below[level - 1], &mut above[0])
            };
            start /= 2;
            let empty = MerkleHashOrchard::empty_root(Level::from(level as u8));
            parents.resize(children.len().div_ceil(2), empty);
            for (index, parent) in parents.iter_mut().enumerate().skip(start) {
                *parent = MerkleHashOrchard::combine(
                    Level::from(level as u8),
                    &children[index * 2],
                    children.get(index * 2 + 1).unwrap_or(&empty),
                );
            }
        }
    }

    fn witness(&self, position: u32, expected_root: [u8; 32]) -> Result<MerklePath> {
        let mut index = position as usize;
        let Some(mut node) = self.leaves.get(index).copied() else {
            return Err("note position is outside the authenticated tree".into());
        };
        let mut siblings = [MerkleHashOrchard::empty_leaf(); 32];
        for (level, sibling) in siblings.iter_mut().enumerate() {
            let empty = MerkleHashOrchard::empty_root(Level::from(level as u8));
            let nodes = if level == 0 {
                &self.leaves
            } else {
                &self.parents[level - 1]
            };
            *sibling = nodes.get(index ^ 1).copied().unwrap_or(empty);
            node = if index & 1 == 0 {
                MerkleHashOrchard::combine(Level::from(level as u8), &node, sibling)
            } else {
                MerkleHashOrchard::combine(Level::from(level as u8), sibling, &node)
            };
            index /= 2;
        }
        if node.to_bytes() != expected_root || self.root().to_bytes() != expected_root {
            return Err("witness root does not match native state".into());
        }
        Ok(MerklePath::from_parts(position, siblings))
    }
}

/// Proof-checked effects bound to one exact pre-payment checkpoint. This is not
/// a consensus certificate and is created only beneath the host's history gate.
pub struct AcceptedPayment {
    slot: u64,
    before: Vec<u8>,
    payment: wire::DecodedPayment,
    effects: VerifiedPayment,
}
impl AcceptedPayment {
    pub fn payload_digest(&self) -> Result<[u8; 32]> {
        Ok(native_payments::staging::payload_digest(&wire::encode(
            PoolState::decode(&self.before)?.network,
            &self.payment.context,
            &self.payment.bundle,
        )?))
    }
    pub fn payment(&self) -> &wire::DecodedPayment {
        &self.payment
    }
    pub fn withdrawal(&self) -> Option<crate::payments::WithdrawalReceipt> {
        crate::payments::withdrawal_receipt(&self.payment)
    }
    pub fn apply(&self, state: &mut WalletState) -> Result<()> {
        state.ensure_slot_open(self.slot)?;
        if state.pool.encode() != self.before {
            return Err("shared history checkpoint mismatch".into());
        }
        state.apply_effects(&self.payment.bundle, &self.effects)
    }
}

#[cfg(test)]
mod witness_tests;
