use crate::{history::WalletState, keys::WalletKey, Result};
#[cfg(test)]
use native_payments::{verification::AuthorizationContext, wire};
use std::time::Instant;

mod preparation;
pub use preparation::{cached_prover, PreparationTimings, ProverPreparation};

pub use native_wallet_core::payments::{withdrawal_receipt, WithdrawalReceipt};
pub use native_wallet_core::payments::{Payment, PaymentProver};

pub fn validate(wallet: &WalletKey, state: &WalletState, payment: &Payment<'_>) -> Result<()> {
    native_wallet_core::payments::validate(wallet, state, payment)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{history::WalletState, keys::Network};
    use solana_signer::Signer;

    #[test]
    fn shielded_fee_is_paid_from_notes_and_cannot_be_redirected_or_downgraded() {
        let network = Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        };
        let alice = WalletKey::generate(network.clone()).unwrap();
        let bob = WalletKey::generate(network).unwrap();
        let relay = [6; 32];
        let prover = PaymentProver::new();
        let mut a = WalletState::with_key(&alice, 1000, prover.verifying_key()).unwrap();
        let mut b = WalletState::with_key(&bob, 1000, prover.verifying_key()).unwrap();
        let deposit = prover
            .build(
                &alice,
                &a,
                relay,
                100,
                Payment::Deposit {
                    amount: 1000,
                    recipient: &alice.address_text(),
                },
            )
            .unwrap();
        let decoded = wire::decode(alice.network.network, &deposit).unwrap();
        a.accept(&decoded.bundle, &decoded.context, 1).unwrap();
        b.accept(&decoded.bundle, &decoded.context, 1).unwrap();
        for (amount, fee) in [
            (1000, 1),
            (0, 1),
            (1, 0),
            (u64::MAX, 1),
            (1, i64::MAX as u64),
        ] {
            assert!(validate(
                &alice,
                &a,
                &Payment::ShieldedSend {
                    amount,
                    recipient: &bob.address_text(),
                    fee
                }
            )
            .is_err());
        }
        let bytes = prover
            .build(
                &alice,
                &a,
                relay,
                100,
                Payment::ShieldedSend {
                    amount: 100,
                    recipient: &bob.address_text(),
                    fee: 30,
                },
            )
            .unwrap();
        assert_eq!(&bytes[..8], b"NPAY0003");
        assert_eq!(bytes.len(), 9230);
        let original = wire::decode(alice.network.network, &bytes).unwrap();
        assert_eq!(original.context.public_value_balance, 30);
        assert!(withdrawal_receipt(&original).is_none());
        for context in [
            AuthorizationContext {
                sponsor: [7; 32],
                ..original.context
            },
            AuthorizationContext {
                expires_at: 99,
                ..original.context
            },
            AuthorizationContext {
                shielded_fee: None,
                ..original.context
            },
        ] {
            assert!(a.accept(&original.bundle, &context, 1).is_err());
        }
        for context in [
            AuthorizationContext {
                shielded_fee: Some(0),
                ..original.context
            },
            AuthorizationContext {
                shielded_fee: Some(31),
                ..original.context
            },
            AuthorizationContext {
                withdrawal_recipient: Some([8; 32]),
                ..original.context
            },
        ] {
            assert!(wire::encode(alice.network.network, &context, &original.bundle).is_err());
        }
        let mut malformed = bytes.clone();
        malformed[88..96].copy_from_slice(&31u64.to_le_bytes());
        assert!(wire::decode(alice.network.network, &malformed).is_err());
        for length in [0, 8, 9222, 9229, 9231, 16384] {
            let mut truncated = bytes.clone();
            truncated.resize(length, 0);
            assert!(wire::decode(alice.network.network, &truncated).is_err());
        }
        a.accept(&original.bundle, &original.context, 1).unwrap();
        b.accept(&original.bundle, &original.context, 1).unwrap();
        assert_eq!(a.balance().unwrap(), 870);
        assert_eq!(b.balance().unwrap(), 100);
        assert_eq!(a.pool.backing, 970);
        assert!(a.accept(&original.bundle, &original.context, 1).is_err());
        let restored = crate::history::Replay::restore_with_key(
            &alice,
            crate::history::Replay::from_state(a).snapshot(),
            Some(prover.verifying_key()),
        )
        .unwrap();
        assert_eq!(restored.state.balance().unwrap(), 870);
        restored.state.reconcile(&b.pool).unwrap();
    }

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
