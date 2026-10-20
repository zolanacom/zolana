use crate::{
    history::WalletState,
    keys::{decode_address, WalletKey},
    Result,
};
use native_payments::{
    verification::{authorization_digest, bundle_version, AuthorizationContext},
    wire,
};
use orchard::{
    builder::{Builder, BundleType},
    circuit::ProvingKey,
    keys::SpendAuthorizingKey,
    tree::Anchor,
    value::NoteValue,
};
use std::time::Instant;

#[derive(Clone, Copy)]
pub enum Payment<'a> {
    Deposit { amount: u64, recipient: &'a str },
    Send { amount: u64, recipient: &'a str },
    Withdraw { amount: u64 },
    WithdrawTo { amount: u64, recipient: [u8; 32] },
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

/// Reject address/amount/balance mistakes before reserving a sponsor attempt or
/// constructing the expensive proving key. Proof building still checks spends.
pub fn validate(wallet: &WalletKey, state: &WalletState, payment: &Payment<'_>) -> Result<()> {
    if state.pool.network != wallet.network.network {
        return Err("wallet and payment state are on different networks".into());
    }
    let (amount, spends) = match payment {
        Payment::Deposit { amount, recipient } => {
            decode_address(&wallet.network, recipient)?;
            (*amount, false)
        }
        Payment::Send { amount, recipient } => {
            decode_address(&wallet.network, recipient)?;
            (*amount, true)
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

pub fn build(
    wallet: &WalletKey,
    state: &WalletState,
    sponsor: [u8; 32],
    expires_at: u64,
    payment: Payment<'_>,
) -> Result<Vec<u8>> {
    Ok(build_with_timings(wallet, state, sponsor, expires_at, payment)?.0)
}

/// Local durations only: no note, witness, seed or proof data enters telemetry.
#[derive(serde::Serialize)]
pub struct BuildTimings {
    pub proof_key_ms: u128,
    pub proof_build_ms: u128,
}

pub fn build_with_timings(
    wallet: &WalletKey,
    state: &WalletState,
    sponsor: [u8; 32],
    expires_at: u64,
    payment: Payment<'_>,
) -> Result<(Vec<u8>, BuildTimings)> {
    let started = Instant::now();
    let prover = PaymentProver::new();
    let proof_key_ms = started.elapsed().as_millis();
    let started = Instant::now();
    let bytes = prover.build(wallet, state, sponsor, expires_at, payment)?;
    Ok((
        bytes,
        BuildTimings {
            proof_key_ms,
            proof_build_ms: started.elapsed().as_millis(),
        },
    ))
}

/// Reuse the expensive circuit key across independent payments in a wallet session.
pub struct PaymentProver(ProvingKey);

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
        wallet: &WalletKey,
        state: &WalletState,
        sponsor: [u8; 32],
        expires_at: u64,
        payment: Payment<'_>,
    ) -> Result<Vec<u8>> {
        validate(wallet, state, &payment)?;
        if state.pool.network != wallet.network.network {
            return Err("wallet and payment state are on different networks".into());
        }
        let (amount, public_balance, destination, spends) = match payment {
            Payment::Deposit { amount, recipient } => (
                amount,
                -i64::try_from(amount)?,
                Some(decode_address(&wallet.network, recipient)?),
                false,
            ),
            Payment::Send { amount, recipient } => (
                amount,
                0,
                Some(decode_address(&wallet.network, recipient)?),
                true,
            ),
            Payment::Withdraw { amount } => (amount, i64::try_from(amount)?, None, true),
            Payment::WithdrawTo { amount, .. } => (amount, i64::try_from(amount)?, None, true),
        };
        if amount == 0 {
            return Err("payment amount must be positive".into());
        }
        let version = bundle_version();
        let anchor = Option::<Anchor>::from(Anchor::from_bytes(state.pool.root()))
            .ok_or("invalid native root")?;
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            version,
            version.default_flags(),
            anchor,
        )?;
        if spends {
            let mut notes = state.unspent();
            notes.sort_by_key(|note| std::cmp::Reverse(note.note.value().inner()));
            let mut total = 0u64;
            for owned in notes.into_iter().take(2) {
                builder.add_spend(
                    wallet.viewing_key(),
                    owned.note,
                    state.witness(owned.position)?,
                )?;
                total = total
                    .checked_add(owned.note.value().inner())
                    .ok_or("note value overflow")?;
                if total >= amount {
                    break;
                }
            }
            if total < amount {
                return Err(
                "insufficient value in two notes; consolidate smaller notes before this payment"
                    .into(),
            );
            }
            if total > amount {
                builder.add_output(
                    None,
                    wallet.change_address(),
                    NoteValue::from_raw(total - amount),
                    [0; 512],
                )?;
            }
        }
        if let Some(address) = destination {
            builder.add_output(None, address, NoteValue::from_raw(amount), [0; 512])?;
        }
        let mut rng = rand::rng();
        let (bundle, _) = builder
            .build::<i64>(&mut rng)?
            .ok_or("missing payment bundle")?;
        if *bundle.value_balance() != public_balance {
            return Err("constructed public value does not match requested payment".into());
        }
        let context = AuthorizationContext {
            expires_at,
            public_value_balance: public_balance,
            sponsor,

            withdrawal_recipient: match payment {
                Payment::WithdrawTo { recipient, .. } => Some(recipient),
                _ => None,
            },
        };
        let digest = authorization_digest(wallet.network.network, &bundle, &context)?;
        let signing = if spends {
            vec![SpendAuthorizingKey::from(&wallet.spending_key())]
        } else {
            Vec::new()
        };
        let bundle = bundle
            .create_proof(&self.0, &mut rng)?
            .apply_signatures(&mut rng, digest, &signing)?;
        Ok(wire::encode(wallet.network.network, &context, &bundle)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{history::WalletState, keys::Network};
    use solana_signer::Signer;

    #[test]
    fn withdrawal_recipient_is_authorized_and_cannot_be_downgraded_to_sponsor() {
        let wallet = WalletKey::generate(Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        })
        .unwrap();
        let sponsor = solana_keypair::Keypair::new().pubkey().to_bytes();
        let mut state = WalletState::new(&wallet, 1000).unwrap();
        let prover = PaymentProver::new();
        let deposit = prover
            .build(
                &wallet,
                &state,
                sponsor,
                100,
                Payment::Deposit {
                    amount: 5_000_000,
                    recipient: &wallet.address_text(),
                },
            )
            .unwrap();
        assert_eq!(&deposit[..8], b"NPAY0001");
        let decoded = wire::decode(wallet.network.network, &deposit).unwrap();
        state.accept(&decoded.bundle, &decoded.context, 1).unwrap();
        let recipient = wallet.public_keypair().pubkey().to_bytes();
        let bytes = prover
            .build(
                &wallet,
                &state,
                sponsor,
                100,
                Payment::WithdrawTo {
                    amount: 1_000_000,
                    recipient,
                },
            )
            .unwrap();
        assert_eq!(&bytes[..8], b"NPAY0002");
        assert_eq!(bytes.len(), deposit.len() + 32);
        let original = wire::decode(wallet.network.network, &bytes).unwrap();
        let changed = AuthorizationContext {
            withdrawal_recipient: Some(solana_keypair::Keypair::new().pubkey().to_bytes()),
            ..original.context
        };
        assert!(state.accept(&original.bundle, &changed, 1).is_err());
        let stripped = AuthorizationContext {
            withdrawal_recipient: None,
            ..original.context
        };
        let downgraded = wire::encode(wallet.network.network, &stripped, &original.bundle).unwrap();
        assert_eq!(&downgraded[..8], b"NPAY0001");
        let decoded = wire::decode(wallet.network.network, &downgraded).unwrap();
        assert!(state.accept(&decoded.bundle, &decoded.context, 1).is_err());
        let zero = AuthorizationContext {
            withdrawal_recipient: Some([0; 32]),
            ..original.context
        };
        assert!(wire::encode(wallet.network.network, &zero, &original.bundle).is_err());
        state
            .accept(&original.bundle, &original.context, 1)
            .unwrap();
        assert_eq!(state.balance().unwrap(), 4_000_000);
        assert!(state
            .accept(&original.bundle, &original.context, 1)
            .is_err());
    }

    #[test]
    fn independent_wallets_discover_change_spends_and_recover_without_a_note_cache() {
        let network = Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        };
        let alice = WalletKey::generate(network.clone()).unwrap();
        let bob = WalletKey::generate(network).unwrap();
        let sponsor = [6; 32];
        let prover = PaymentProver::new();
        let mut a = WalletState::with_key(&alice, 1000, prover.verifying_key()).unwrap();
        let mut b = WalletState::with_key(&bob, 1000, prover.verifying_key()).unwrap();
        let mut transcript = Vec::new();
        for (wallet, state_is_alice, payment) in [
            (
                &alice,
                true,
                Payment::Deposit {
                    amount: 100,
                    recipient: &alice.address_text(),
                },
            ),
            (
                &alice,
                true,
                Payment::Send {
                    amount: 40,
                    recipient: &bob.address_text(),
                },
            ),
            (&bob, false, Payment::Withdraw { amount: 15 }),
        ] {
            let state = if state_is_alice { &a } else { &b };
            let bytes = prover.build(wallet, state, sponsor, 100, payment).unwrap();
            let decoded = wire::decode(wallet.network.network, &bytes).unwrap();
            a.accept(&decoded.bundle, &decoded.context, 1).unwrap();
            b.accept(&decoded.bundle, &decoded.context, 1).unwrap();
            transcript.push(bytes);
        }
        assert_eq!(a.balance().unwrap(), 60);
        assert_eq!(b.balance().unwrap(), 25);
        assert_eq!(a.pool.backing, 85);
        let replay = crate::history::Replay::from_state(b);
        let restored = crate::history::Replay::restore_with_key(
            &bob,
            replay.snapshot(),
            Some(prover.verifying_key()),
        )
        .unwrap();
        assert_eq!(restored.state.balance().unwrap(), 25);
        restored.state.reconcile(&a.pool).unwrap();
        assert!(crate::history::Replay::restore_with_key(
            &alice,
            replay.snapshot(),
            Some(prover.verifying_key()),
        )
        .is_err());
        let mut recovered = WalletState::new(&bob, 1000).unwrap();
        for bytes in &transcript {
            let decoded = wire::decode(bob.network.network, bytes).unwrap();
            recovered
                .accept(&decoded.bundle, &decoded.context, 1)
                .unwrap();
        }
        recovered.reconcile(&a.pool).unwrap();
        assert_eq!(recovered.balance().unwrap(), 25);
        assert_eq!(recovered.max_payment().unwrap(), 25);
        assert!(WalletState::new(&bob, 1000)
            .unwrap()
            .reconcile(&a.pool)
            .is_err());
        let replay = wire::decode(bob.network.network, &transcript[1]).unwrap();
        assert!(recovered
            .accept(&replay.bundle, &replay.context, 1)
            .is_err());
        assert!(build(
            &bob,
            &recovered,
            sponsor,
            100,
            Payment::Withdraw { amount: 26 }
        )
        .is_err());
        assert!(build(
            &bob,
            &recovered,
            sponsor,
            100,
            Payment::Send {
                amount: 0,
                recipient: &alice.address_text()
            }
        )
        .is_err());
    }
}
