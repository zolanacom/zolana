//! The existing native payment selection, construction and authorization path.
use crate::{history::WalletState, Result, WalletKeys};
use native_payments::{
    verification::{authorization_digest, bundle_version, AuthorizationContext},
    wire,
};
use orchard::{
    builder::{Builder, BundleType},
    circuit::ProvingKey,
    keys::{FullViewingKey, Scope, SpendAuthorizingKey},
    tree::Anchor,
    value::NoteValue,
};
#[derive(Clone, Copy)]
pub enum Payment<'a> {
    Deposit {
        amount: u64,
        recipient: &'a str,
    },
    Send {
        amount: u64,
        recipient: &'a str,
    },
    ShieldedSend {
        amount: u64,
        recipient: &'a str,
        fee: u64,
    },
    Withdraw {
        amount: u64,
    },
    WithdrawTo {
        amount: u64,
        recipient: [u8; 32],
    },
}

/// Reject address/amount/balance mistakes before reserving a sponsor attempt or
/// constructing the expensive proving key. Proof building still checks spends.
pub fn validate(
    wallet: &(impl WalletKeys + ?Sized),
    state: &WalletState,
    payment: &Payment<'_>,
) -> Result<()> {
    if state.pool.network != wallet.network_domain() {
        return Err("wallet and payment state are on different networks".into());
    }
    let (amount, spends) = match payment {
        Payment::Deposit { amount, recipient } => {
            wallet.decode_address(recipient)?;
            (*amount, false)
        }
        Payment::Send { amount, recipient } => {
            wallet.decode_address(recipient)?;
            (*amount, true)
        }
        Payment::ShieldedSend {
            amount,
            recipient,
            fee,
        } => {
            wallet.decode_address(recipient)?;
            if *amount == 0 || *fee == 0 {
                return Err("payment and shielded fee must be positive".into());
            }
            (
                amount
                    .checked_add(*fee)
                    .ok_or("payment plus fee overflow")?,
                true,
            )
        }
        Payment::Withdraw { amount } => (*amount, true),
        Payment::WithdrawTo { amount, recipient } => {
            if !solana_pubkey::Pubkey::new_from_array(*recipient).is_on_curve() {
                return Err("withdrawal recipient must be a public signing address".into());
            }
            (*amount, true)
        }
    };
    i64::try_from(amount)?;
    if amount == 0 {
        return Err("payment amount must be positive".into());
    }
    if spends && amount > state.max_payment()? {
        return Err(
            "insufficient value in two notes; consolidate smaller notes before this payment".into(),
        );
    }
    Ok(())
}

/// Reuse the expensive circuit key across independent payments in a wallet session.
pub struct PaymentProver(ProvingKey);

/// Fixed public phase marks. The caller owns its clock; no key, note or packet
/// contents are provided to the optional observer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentBuildPhase {
    Validation,
    Anchor,
    Keys,
    Inputs,
    Bundle,
    Authorization,
    Proof,
    Signatures,
    Encoding,
}

impl PaymentBuildPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validation => "validation",
            Self::Anchor => "anchor",
            Self::Keys => "keys",
            Self::Inputs => "inputs",
            Self::Bundle => "bundle",
            Self::Authorization => "authorization",
            Self::Proof => "proof",
            Self::Signatures => "signatures",
            Self::Encoding => "encoding",
        }
    }
}

impl Default for PaymentProver {
    fn default() -> Self {
        Self::new()
    }
}

impl PaymentProver {
    pub fn new() -> Self {
        Self(ProvingKey::build(bundle_version().circuit_version()))
    }

    /// Clone public verification material without generating a second circuit key.
    /// No wallet, witness or payment randomness is retained in this key.
    pub fn verifying_key(&self) -> std::sync::Arc<orchard::circuit::VerifyingKey> {
        std::sync::Arc::new(self.0.verifying_key())
    }

    pub fn build(
        &self,
        wallet: &(impl WalletKeys + ?Sized),
        state: &WalletState,
        sponsor: [u8; 32],
        expires_at: u64,
        payment: Payment<'_>,
    ) -> Result<Vec<u8>> {
        self.build_with_metrics(wallet, state, sponsor, expires_at, payment, |_| {})
    }

    /// The same construction path with a mark after each successful phase.
    /// Observers must not panic and cannot supply or alter payment state.
    pub fn build_with_metrics(
        &self,
        wallet: &(impl WalletKeys + ?Sized),
        state: &WalletState,
        sponsor: [u8; 32],
        expires_at: u64,
        payment: Payment<'_>,
        mut observed: impl FnMut(PaymentBuildPhase),
    ) -> Result<Vec<u8>> {
        validate(wallet, state, &payment)?;
        if state.pool.network != wallet.network_domain() {
            return Err("wallet and payment state are on different networks".into());
        }
        let (amount, public_balance, destination, spends) = match payment {
            Payment::Deposit { amount, recipient } => (
                amount,
                -i64::try_from(amount)?,
                Some(wallet.decode_address(recipient)?),
                false,
            ),
            Payment::Send { amount, recipient } => {
                (amount, 0, Some(wallet.decode_address(recipient)?), true)
            }
            Payment::ShieldedSend {
                amount,
                recipient,
                fee,
            } => (
                amount,
                i64::try_from(fee)?,
                Some(wallet.decode_address(recipient)?),
                true,
            ),
            Payment::Withdraw { amount } => (amount, i64::try_from(amount)?, None, true),
            Payment::WithdrawTo { amount, .. } => (amount, i64::try_from(amount)?, None, true),
        };
        if amount == 0 {
            return Err("payment amount must be positive".into());
        }
        observed(PaymentBuildPhase::Validation);
        let version = bundle_version();
        let anchor_bytes = state.spendable_anchor()?;
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(anchor_bytes))
            .ok_or("invalid native root")?;
        observed(PaymentBuildPhase::Anchor);
        // The seed validation in spending_key() also derives viewing material.
        // Do it once for this construction, rather than again for each input,
        // the change address, and the spend signature. Nothing is cached after
        // this call or exposed to the observer.
        let spending_key = if spends {
            Some(wallet.spending_key()?)
        } else {
            None
        };
        let viewing_key = spending_key.as_ref().map(FullViewingKey::from);
        observed(PaymentBuildPhase::Keys);
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            version,
            version.default_flags(),
            anchor,
        )?;
        let spend_amount = if let Payment::ShieldedSend { fee, .. } = payment {
            amount.checked_add(fee).ok_or("payment plus fee overflow")?
        } else {
            amount
        };
        if spends {
            let mut notes = state.unspent();
            notes.sort_by_key(|note| std::cmp::Reverse(note.note.value().inner()));
            let mut total = 0u64;
            for owned in notes.into_iter().take(2) {
                builder.add_spend(
                    viewing_key.as_ref().expect("spend key prepared").clone(),
                    owned.note,
                    state.witness_at_anchor(owned.position, anchor_bytes)?,
                )?;
                total = total
                    .checked_add(owned.note.value().inner())
                    .ok_or("note value overflow")?;
                if total >= spend_amount {
                    break;
                }
            }
            if total < spend_amount {
                return Err(
                "insufficient value in two notes; consolidate smaller notes before this payment"
                    .into(),
            );
            }
            if total > spend_amount {
                builder.add_output(
                    None,
                    viewing_key
                        .as_ref()
                        .expect("spend key prepared")
                        .address_at(0u32, Scope::Internal),
                    NoteValue::from_raw(total - spend_amount),
                    [0; 512],
                )?;
            }
        }
        if let Some(address) = destination {
            builder.add_output(None, address, NoteValue::from_raw(amount), [0; 512])?;
        }
        observed(PaymentBuildPhase::Inputs);
        let mut rng = rand::rng();
        let (bundle, _) = builder
            .build::<i64>(&mut rng)?
            .ok_or("missing payment bundle")?;
        if *bundle.value_balance() != public_balance {
            return Err("constructed public value does not match requested payment".into());
        }
        observed(PaymentBuildPhase::Bundle);
        let context = AuthorizationContext {
            expires_at,
            public_value_balance: public_balance,
            sponsor,

            shielded_fee: match payment {
                Payment::ShieldedSend { fee, .. } => Some(fee),
                _ => None,
            },
            withdrawal_recipient: match payment {
                Payment::WithdrawTo { recipient, .. } => Some(recipient),
                _ => None,
            },
        };
        let digest = authorization_digest(wallet.network_domain(), &bundle, &context)?;
        let signing: Vec<_> = spending_key
            .as_ref()
            .map(SpendAuthorizingKey::from)
            .into_iter()
            .collect();
        observed(PaymentBuildPhase::Authorization);
        let bundle = bundle.create_proof(&self.0, &mut rng)?;
        observed(PaymentBuildPhase::Proof);
        let bundle = bundle.apply_signatures(&mut rng, digest, &signing)?;
        observed(PaymentBuildPhase::Signatures);
        let encoded = wire::encode(wallet.network_domain(), &context, &bundle)?;
        observed(PaymentBuildPhase::Encoding);
        Ok(encoded)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalReceipt {
    pub recipient: String,
    pub amount: u64,
    pub sponsor: String,
}
pub fn withdrawal_receipt(payment: &wire::DecodedPayment) -> Option<WithdrawalReceipt> {
    payment
        .context
        .withdrawal_recipient
        .map(|recipient| WithdrawalReceipt {
            recipient: solana_pubkey::Pubkey::new_from_array(recipient).to_string(),
            amount: payment.context.public_value_balance as u64,
            sponsor: solana_pubkey::Pubkey::new_from_array(payment.context.sponsor).to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_keys::FixtureKeys;
    use native_payments::state::PoolState;
    use std::{cell::Cell, sync::Arc};

    struct CountingKeys<'a> {
        inner: &'a FixtureKeys,
        calls: Cell<usize>,
    }

    impl WalletKeys for CountingKeys<'_> {
        fn network_domain(&self) -> [u8; 32] {
            self.inner.network_domain()
        }
        fn genesis_hash(&self) -> &str {
            self.inner.genesis_hash()
        }
        fn spending_key(&self) -> Result<orchard::keys::SpendingKey> {
            self.calls.set(self.calls.get() + 1);
            self.inner.spending_key()
        }
    }

    #[test]
    fn one_key_expansion_preserves_shielded_fee_change_and_public_phase_marks() {
        // Synthetic host only: successful canonical execution is assumed by
        // these in-memory state updates, never established by a proof alone.
        let network = [71; 32];
        let genesis = bs58::encode([72; 32]).into_string();
        let alice = FixtureKeys::new(network, genesis.clone(), [7; 32]);
        let bob = FixtureKeys::new(network, genesis, [8; 32]);
        let keys = CountingKeys {
            inner: &alice,
            calls: Cell::new(0),
        };
        let prover = PaymentProver::new();
        let key = prover.verifying_key();
        let pool = PoolState::new_slot_anchored(network, 1).unwrap();
        let mut a = WalletState::with_key_for_pool(&alice, &pool, Arc::clone(&key)).unwrap();
        let mut b = WalletState::with_key_for_pool(&bob, &pool, key).unwrap();
        let payer = [73; 32];
        let funding = prover
            .build(
                &keys,
                &a,
                payer,
                100,
                Payment::Deposit {
                    amount: 13,
                    recipient: &alice.address_text(),
                },
            )
            .unwrap();
        assert_eq!(keys.calls.get(), 0, "a deposit requires no spending key");
        let funding = wire::decode(network, &funding).unwrap();
        for state in [&mut a, &mut b] {
            state.accept(&funding.bundle, &funding.context, 1).unwrap();
            state.finish_slot(1).unwrap();
        }
        let before = a.pool.encode();
        let mut phases = Vec::new();
        let payment = prover
            .build_with_metrics(
                &keys,
                &a,
                payer,
                100,
                Payment::ShieldedSend {
                    amount: 4,
                    recipient: &bob.address_text(),
                    fee: 3,
                },
                |phase| phases.push(phase.as_str()),
            )
            .unwrap();
        assert_eq!(
            keys.calls.get(),
            1,
            "inputs, change and signatures reuse one key"
        );
        assert_eq!(a.pool.encode(), before, "construction cannot mutate replay");
        assert_eq!(
            phases,
            [
                "validation",
                "anchor",
                "keys",
                "inputs",
                "bundle",
                "authorization",
                "proof",
                "signatures",
                "encoding",
            ]
        );
        let payment = wire::decode(network, &payment).unwrap();
        assert_eq!(payment.context.shielded_fee, Some(3));
        assert_eq!(payment.context.public_value_balance, 3);
        assert_eq!(payment.context.sponsor, payer);
        assert_eq!(payment.bundle.actions().len(), 2);
        for state in [&mut a, &mut b] {
            state.accept(&payment.bundle, &payment.context, 2).unwrap();
            state.finish_slot(2).unwrap();
        }
        assert_eq!(a.balance().unwrap(), 6, "change remains owned by Alice");
        assert_eq!(
            b.balance().unwrap(),
            4,
            "recipient can decrypt the exact amount"
        );

        keys.calls.set(0);
        phases.clear();
        assert!(prover
            .build_with_metrics(
                &keys,
                &a,
                payer,
                100,
                Payment::ShieldedSend {
                    amount: 0,
                    recipient: &bob.address_text(),
                    fee: 3,
                },
                |phase| phases.push(phase.as_str()),
            )
            .is_err());
        assert_eq!(
            keys.calls.get(),
            0,
            "invalid input must fail before key preparation"
        );
        assert!(phases.is_empty());
    }
}
