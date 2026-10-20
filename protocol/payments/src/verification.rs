//! Bounded, deterministic validation; no mutable state or external verifier.

use std::{collections::BTreeSet, sync::Arc};

use orchard::{
    bundle::{Authorization, Authorized, BundleVersion, TxVersion},
    circuit::VerifyingKey,
    Bundle, Proof,
};

use crate::Error;

pub const PROTOCOL_VERSION: u32 = 1;
pub const ACTION_COUNT: usize = 2;
pub const MAX_EXPIRY_WINDOW: u64 = 1_024;

/// This version selects the patched circuit, not historical insecure v1.
pub fn bundle_version() -> BundleVersion {
    BundleVersion::orchard_v2()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationContext {
    pub expires_at: u64,
    pub public_value_balance: i64,
    pub sponsor: [u8; 32],
    /// Present only for recipient-bound withdrawals; never the fee payer role.
    pub withdrawal_recipient: Option<[u8; 32]>,
    /// Exact public relay reimbursement, funded by shielded inputs (V3 only).
    pub shielded_fee: Option<u64>,
}

impl AuthorizationContext {
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(fee) = self.shielded_fee {
            if fee == 0
                || fee > i64::MAX as u64
                || self.public_value_balance != fee as i64
                || self.withdrawal_recipient.is_some()
            {
                return Err(Error::InvalidContext);
            }
        }
        Ok(())
    }
}

/// Authenticated node state, never values asserted by an untrusted RPC caller.
pub struct ValidationView<'a> {
    pub current_slot: u64,
    pub accepted_anchors: &'a BTreeSet<[u8; 32]>,
    pub spent_nullifiers: &'a BTreeSet<[u8; 32]>,
    /// The native-accounting adapter must authorize this movement separately.
    /// Negative values require a real matching public debit; a proof cannot mint.
    pub authorized_public_value_balance: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedPayment {
    pub nullifiers: [[u8; 32]; ACTION_COUNT],
    pub commitments: [[u8; 32]; ACTION_COUNT],
    pub public_value_balance: i64,
}

/// Binds effects to the unique network domain committed by the chain genesis.
/// The caller also verifies the actual genesis fingerprint independently.
pub fn authorization_digest<A: Authorization>(
    genesis: [u8; 32],
    bundle: &Bundle<A, i64>,
    context: &AuthorizationContext,
) -> Result<[u8; 32], Error> {
    context.validate()?;
    if genesis == [0; 32]
        || context.sponsor == [0; 32]
        || context
            .withdrawal_recipient
            .is_some_and(|key| key == [0; 32] || context.public_value_balance <= 0)
    {
        return Err(Error::InvalidContext);
    }
    if bundle.bundle_version() != bundle_version() {
        return Err(Error::UnsupportedVersion);
    }
    let commitment: [u8; 32] = bundle
        .commitment(TxVersion::V5)
        .map_err(|_| Error::UnsupportedVersion)?
        .into();
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(if context.shielded_fee.is_some() {
            b"NativePayAuthV3!"
        } else if context.withdrawal_recipient.is_some() {
            b"NativePayAuthV2!"
        } else {
            b"NativePayAuthV1!"
        })
        .to_state();
    state.update(&genesis);
    state.update(&PROTOCOL_VERSION.to_le_bytes());
    state.update(&commitment);
    state.update(&context.expires_at.to_le_bytes());
    state.update(&context.public_value_balance.to_le_bytes());
    state.update(&context.sponsor);
    if let Some(fee) = context.shielded_fee {
        state.update(&fee.to_le_bytes());
    }
    if let Some(recipient) = context.withdrawal_recipient {
        state.update(&recipient);
    }
    Ok(state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("32-byte digest"))
}

pub struct PaymentVerifier {
    genesis: [u8; 32],
    key: Arc<VerifyingKey>,
}

impl PaymentVerifier {
    pub fn new(genesis: [u8; 32], key: VerifyingKey) -> Result<Self, Error> {
        Self::with_shared_key(genesis, Arc::new(key))
    }

    pub fn with_shared_key(genesis: [u8; 32], key: Arc<VerifyingKey>) -> Result<Self, Error> {
        if genesis == [0; 32] {
            return Err(Error::InvalidContext);
        }
        if key.circuit_version() != bundle_version().circuit_version() {
            return Err(Error::UnsupportedVersion);
        }
        Ok(Self { genesis, key })
    }

    /// Performs cheap policy/signature checks before expensive proof verification.
    /// Commit the returned effects atomically with native accounting in the node.
    pub fn verify(
        &self,
        bundle: &Bundle<Authorized, i64>,
        context: &AuthorizationContext,
        view: &ValidationView<'_>,
    ) -> Result<VerifiedPayment, Error> {
        if bundle.bundle_version() != bundle_version() {
            return Err(Error::UnsupportedVersion);
        }
        if bundle.actions().len() != ACTION_COUNT
            || bundle.authorization().proof().as_ref().len()
                != Proof::expected_proof_size(ACTION_COUNT)
            || *bundle.flags() != bundle_version().default_flags()
        {
            return Err(Error::InvalidShape);
        }
        if context.expires_at < view.current_slot {
            return Err(Error::Expired);
        }
        if context.expires_at.saturating_sub(view.current_slot) > MAX_EXPIRY_WINDOW {
            return Err(Error::InvalidContext);
        }
        if *bundle.value_balance() != context.public_value_balance
            || context.public_value_balance != view.authorized_public_value_balance
        {
            return Err(Error::WrongValueBalance);
        }
        if !view.accepted_anchors.contains(&bundle.anchor().to_bytes()) {
            return Err(Error::UnknownAnchor);
        }
        let nullifiers: [[u8; 32]; ACTION_COUNT] = bundle
            .actions()
            .iter()
            .map(|action| action.nullifier().to_bytes())
            .collect::<Vec<_>>()
            .try_into()
            .expect("checked action count");
        if nullifiers[0] == nullifiers[1] {
            return Err(Error::DuplicateNullifier);
        }
        if nullifiers.iter().any(|n| view.spent_nullifiers.contains(n)) {
            return Err(Error::SpentNullifier);
        }
        let digest = authorization_digest(self.genesis, bundle, context)?;
        for action in bundle.actions().iter() {
            action
                .rk()
                .verify(&digest, action.authorization())
                .map_err(|_| Error::InvalidSpendAuthorization)?;
        }
        bundle
            .binding_validating_key()
            .verify(&digest, bundle.authorization().binding_signature())
            .map_err(|_| Error::InvalidBindingSignature)?;
        bundle
            .verify_proof(&self.key)
            .map_err(|_| Error::InvalidProof)?;
        Ok(VerifiedPayment {
            nullifiers,
            commitments: bundle
                .actions()
                .iter()
                .map(|action| action.cmx().to_bytes())
                .collect::<Vec<_>>()
                .try_into()
                .expect("checked action count"),
            public_value_balance: *bundle.value_balance(),
        })
    }
}
