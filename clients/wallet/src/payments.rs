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

pub enum Payment<'a> {
    Deposit { amount: u64, recipient: &'a str },
    Send { amount: u64, recipient: &'a str },
    Withdraw { amount: u64 },
}

pub fn build(
    wallet: &WalletKey,
    state: &WalletState,
    sponsor: [u8; 32],
    expires_at: u64,
    payment: Payment<'_>,
) -> Result<Vec<u8>> {
    PaymentProver::new().build(wallet, state, sponsor, expires_at, payment)
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

    pub fn build(
        &self,
        wallet: &WalletKey,
        state: &WalletState,
        sponsor: [u8; 32],
        expires_at: u64,
        payment: Payment<'_>,
    ) -> Result<Vec<u8>> {
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

    #[test]
    fn independent_wallets_discover_change_spends_and_recover_without_a_note_cache() {
        let network = Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        };
        let alice = WalletKey::generate(network.clone()).unwrap();
        let bob = WalletKey::generate(network).unwrap();
        let sponsor = [6; 32];
        let mut a = WalletState::new(&alice, 1000).unwrap();
        let mut b = WalletState::new(&bob, 1000).unwrap();
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
            let bytes = build(wallet, state, sponsor, 100, payment).unwrap();
            let decoded = wire::decode(wallet.network.network, &bytes).unwrap();
            a.accept(&decoded.bundle, &decoded.context, 1).unwrap();
            b.accept(&decoded.bundle, &decoded.context, 1).unwrap();
            transcript.push(bytes);
        }
        assert_eq!(a.balance().unwrap(), 60);
        assert_eq!(b.balance().unwrap(), 25);
        assert_eq!(a.pool.backing, 85);
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
