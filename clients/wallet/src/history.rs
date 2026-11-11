//! Native wallet aliases for the shared checked replay and witness engine.
//! RPC canonical-success validation remains in rpc.rs before applying history.
pub use native_wallet_core::history::{OwnedNote, WalletState};
pub use native_wallet_core::replay::Replay;
pub type HistoryInstruction = native_wallet_core::replay::HistoryInstruction<solana_pubkey::Pubkey>;
#[cfg(test)]
use crate::keys::WalletKey;
#[cfg(test)]
use native_payments::{state::PoolState, wire};
#[cfg(test)]
use native_wallet_core::history::AcceptedPayment as AcceptedHistoryPayment;
pub(crate) use native_wallet_core::history::ReplaySnapshot;
#[cfg(test)]
use solana_pubkey::Pubkey;
#[cfg(test)]
use std::sync::Arc;
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
    fn v4_block_finish_guards_proving_and_restores_slot_anchors_and_nullifiers() {
        let network = Network {
            network: [43; 32],
            genesis_hash: bs58::encode([44; 32]).into_string(),
        };
        let alice = WalletKey::generate(network).unwrap();
        let prover = payments::PaymentProver::new();
        let mut state = WalletState::with_key(&alice, 1000, prover.verifying_key()).unwrap();
        state.pool = PoolState::new_slot_anchored(alice.network.network, 1000).unwrap();
        assert!(state.spendable_anchor().is_err());
        state.finish_slot(0).unwrap();
        let sponsor = Pubkey::new_unique();
        let funding = prover
            .build(
                &alice,
                &state,
                sponsor.to_bytes(),
                100,
                Payment::Deposit {
                    amount: 100,
                    recipient: &alice.address_text(),
                },
            )
            .unwrap();
        let funding = wire::decode(alice.network.network, &funding).unwrap();
        state.accept(&funding.bundle, &funding.context, 1).unwrap();
        assert!(state.spendable_anchor().is_err());
        assert!(state.witness(0).is_err());
        state.finish_slot(1).unwrap();
        assert!(state.spendable_anchor().is_ok());

        let bytes = prover
            .build(
                &alice,
                &state,
                sponsor.to_bytes(),
                100,
                Payment::ShieldedSend {
                    amount: 10,
                    recipient: &alice.address_text(),
                    fee: 2,
                },
            )
            .unwrap();
        let payment = wire::decode(alice.network.network, &bytes).unwrap();
        state.accept(&payment.bundle, &payment.context, 2).unwrap();
        assert!(state.spendable_anchor().is_err());
        state.finish_slot(2).unwrap();
        let before = state.pool.encode();
        assert!(state.accept(&payment.bundle, &payment.context, 2).is_err());
        assert_eq!(state.pool.encode(), before);
        state.finish_slot(3).unwrap(); // An empty produced block still refreshes the checkpoint.
        let replay = Replay::from_state(state);
        let mut restored =
            Replay::restore_with_key(&alice, replay.snapshot(), Some(prover.verifying_key()))
                .unwrap();
        assert_eq!(restored.state.pool.encode(), replay.state.pool.encode());
        assert_eq!(
            restored.state.spent_nullifiers(),
            replay.state.spent_nullifiers()
        );
        assert_eq!(restored.state.balance().unwrap(), 98);
        assert!(restored.state.spendable_anchor().is_ok());
        assert!(restored
            .state
            .accept(&payment.bundle, &payment.context, 4)
            .is_err());
        restored.finish_slot(600).unwrap(); // Skipped slots are not fabricated.
        assert_eq!(
            restored
                .state
                .pool
                .slot_anchors()
                .unwrap()
                .entries()
                .iter()
                .map(|entry| entry.slot)
                .collect::<Vec<_>>(),
            vec![600]
        );
        assert!(restored.state.pool.accepted_roots(600).unwrap().is_empty());
        assert!(restored
            .state
            .pool
            .accepted_roots(601)
            .unwrap()
            .contains(&restored.state.pool.root()));
        assert!(restored.finish_slot(599).is_err());
    }

    fn history(ix: solana_instruction::Instruction) -> HistoryInstruction {
        HistoryInstruction {
            accounts: ix
                .accounts
                .iter()
                .map(|meta| (meta.pubkey, meta.is_signer))
                .collect(),
            data: ix.data,
        }
    }

    fn stage_history(replay: &mut Replay, sponsor: Pubkey, bytes: &[u8]) -> AcceptedHistoryPayment {
        let buffer = Pubkey::new_unique();
        replay
            .apply(
                &history(instructions::initialize(
                    buffer,
                    sponsor,
                    bytes.len() as u32,
                    payload_digest(bytes),
                    100,
                )),
                1,
            )
            .unwrap();
        for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
            replay
                .apply(
                    &history(instructions::write(
                        buffer,
                        sponsor,
                        (index * MAX_CHUNK_BYTES) as u32,
                        chunk,
                    )),
                    1,
                )
                .unwrap();
        }
        replay
            .apply(&history(instructions::seal(buffer, sponsor)), 1)
            .unwrap();
        let payment = wire::decode(replay.state.pool.network, bytes).unwrap();
        replay
            .apply_verified(
                &history(instructions::finalize(
                    buffer,
                    sponsor,
                    std::array::from_fn(|i| payment.bundle.actions()[i].nullifier().to_bytes()),
                )),
                1,
            )
            .unwrap()
            .unwrap()
    }

    #[test]
    fn inline_history_recovers_receipts_nullifiers_and_immediately_spendable_notes() {
        let network = Network {
            network: [19; 32],
            genesis_hash: bs58::encode([18; 32]).into_string(),
        };
        let alice = WalletKey::generate(network.clone()).unwrap();
        let bob = WalletKey::generate(network.clone()).unwrap();
        let charlie = WalletKey::generate(network).unwrap();
        let prover = payments::PaymentProver::new();
        let key = prover.verifying_key();
        let mut replay =
            Replay::from_state(WalletState::with_key(&alice, 1000, Arc::clone(&key)).unwrap());
        let mut bob_state = WalletState::with_key(&bob, 1000, Arc::clone(&key)).unwrap();
        let mut charlie_state = WalletState::with_key(&charlie, 1000, Arc::clone(&key)).unwrap();
        let sponsor = Pubkey::new_unique();
        let funding = prover
            .build(
                &alice,
                &replay.state,
                sponsor.to_bytes(),
                100,
                Payment::Deposit {
                    amount: 100,
                    recipient: &alice.address_text(),
                },
            )
            .unwrap();
        let accepted = stage_history(&mut replay, sponsor, &funding);
        accepted.apply(&mut bob_state).unwrap();
        accepted.apply(&mut charlie_state).unwrap();

        let bytes = prover
            .build(
                &alice,
                &replay.state,
                sponsor.to_bytes(),
                100,
                Payment::ShieldedSend {
                    amount: 25,
                    recipient: &bob.address_text(),
                    fee: 3,
                },
            )
            .unwrap();
        let ix = history(instructions::inline(alice.network.network, &bytes).unwrap());
        let before = replay.state.pool.encode();
        let spent_before = replay.state.spent_nullifiers().clone();
        let buffer_count = replay.staging_count();
        let mut invalid = Vec::new();
        for index in 0..5 {
            let mut accounts = ix.accounts.clone();
            accounts[index].0 = Pubkey::new_unique();
            invalid.push(HistoryInstruction {
                accounts,
                data: ix.data.clone(),
            });
        }
        let mut unsigned = ix.accounts.clone();
        unsigned[1].1 = false;
        invalid.push(HistoryInstruction {
            accounts: unsigned,
            data: ix.data.clone(),
        });
        let mut extra = ix.accounts.clone();
        extra.push((Pubkey::new_unique(), false));
        invalid.push(HistoryInstruction {
            accounts: extra,
            data: ix.data.clone(),
        });
        let mut trailing = ix.data.clone();
        trailing.push(0);
        invalid.push(HistoryInstruction {
            accounts: ix.accounts.clone(),
            data: trailing,
        });
        let mut wrong_domain = ix.data.clone();
        // Opcode, envelope magic, version, then its domain.
        wrong_domain[1 + 8 + 2] ^= 1;
        invalid.push(HistoryInstruction {
            accounts: ix.accounts.clone(),
            data: wrong_domain,
        });
        for invalid in invalid {
            assert!(replay.apply_verified(&invalid, 2).is_err());
            assert_eq!(replay.state.pool.encode(), before);
            assert_eq!(replay.state.spent_nullifiers(), &spent_before);
            assert_eq!(replay.state.balance().unwrap(), 100);
            assert_eq!(replay.staging_count(), buffer_count);
        }
        assert!(replay.apply_verified(&ix, 101).is_err());
        // An interruption before replaying the instruction resumes from the
        // authenticated checkpoint, without any staged bytes for this payment.
        replay =
            Replay::restore_with_key(&alice, replay.snapshot(), Some(Arc::clone(&key))).unwrap();
        let accepted = replay.apply_verified(&ix, 2).unwrap().unwrap();
        assert_eq!(accepted.payload_digest().unwrap(), payload_digest(&bytes));
        accepted.apply(&mut bob_state).unwrap();
        accepted.apply(&mut charlie_state).unwrap();
        assert_eq!(replay.state.balance().unwrap(), 72);
        assert_eq!(bob_state.balance().unwrap(), 25);
        assert_eq!(replay.staging_count(), buffer_count);
        let accepted_pool = replay.state.pool.encode();
        assert!(replay.apply_verified(&ix, 2).is_err());
        assert_eq!(replay.state.pool.encode(), accepted_pool);

        replay =
            Replay::restore_with_key(&alice, replay.snapshot(), Some(Arc::clone(&key))).unwrap();
        let mut bob_replay = Replay::restore_with_key(
            &bob,
            Replay::from_state(bob_state).snapshot(),
            Some(Arc::clone(&key)),
        )
        .unwrap();
        let payment = wire::decode(alice.network.network, &bytes).unwrap();
        for action in payment.bundle.actions() {
            assert!(replay
                .state
                .spent_nullifiers()
                .contains(&action.nullifier().to_bytes()));
            assert!(bob_replay
                .state
                .spent_nullifiers()
                .contains(&action.nullifier().to_bytes()));
        }
        assert!(replay.apply_verified(&ix, 3).is_err());
        assert!(bob_replay.apply_verified(&ix, 3).is_err());
        assert_eq!(replay.state.balance().unwrap(), 72);
        assert_eq!(bob_replay.state.balance().unwrap(), 25);
        for owned in replay.state.unspent() {
            replay.state.witness(owned.position).unwrap();
        }

        // The received note and its rebuilt witness can fund the very next
        // native payment; this is replay/proof correctness, not a latency test.
        let forward = prover
            .build(
                &bob,
                &bob_replay.state,
                sponsor.to_bytes(),
                100,
                Payment::ShieldedSend {
                    amount: 10,
                    recipient: &charlie.address_text(),
                    fee: 2,
                },
            )
            .unwrap();
        let forward = history(instructions::inline(bob.network.network, &forward).unwrap());
        let accepted = bob_replay.apply_verified(&forward, 3).unwrap().unwrap();
        accepted.apply(&mut replay.state).unwrap();
        accepted.apply(&mut charlie_state).unwrap();
        assert_eq!(replay.state.balance().unwrap(), 72);
        assert_eq!(bob_replay.state.balance().unwrap(), 13);
        assert_eq!(charlie_state.balance().unwrap(), 10);
        assert_eq!(charlie_state.pool.backing, 95);
        replay.state.reconcile(&bob_replay.state.pool).unwrap();
        charlie_state.reconcile(&bob_replay.state.pool).unwrap();
    }

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
        assert_eq!(
            restored.state.spent_nullifiers(),
            primary.state.spent_nullifiers()
        );
        assert_eq!(
            restored.state.witness(0).unwrap().auth_path(),
            primary.state.witness(0).unwrap().auth_path()
        );
        assert!(Replay::restore(&bob, primary.snapshot()).is_err());
        let mut corrupted = serde_json::to_value(primary.snapshot()).unwrap();
        corrupted["notes"][0]["value"] = serde_json::json!(101);
        assert!(Replay::restore(&alice, serde_json::from_value(corrupted).unwrap()).is_err());
        let mut corrupted = serde_json::to_value(primary.snapshot()).unwrap();
        corrupted["leaves"][0] = serde_json::to_value([0u8; 32]).unwrap();
        assert!(Replay::restore(&alice, serde_json::from_value(corrupted).unwrap()).is_err());
        let unowned_position = (0..primary.state.pool.note_count() as usize)
            .find(|position| {
                !primary
                    .state
                    .owned_positions()
                    .any(|owned| owned as usize == *position)
            })
            .unwrap();
        let mut corrupted = serde_json::to_value(primary.snapshot()).unwrap();
        corrupted["leaves"][unowned_position] = serde_json::to_value([0u8; 32]).unwrap();
        assert!(Replay::restore(&alice, serde_json::from_value(corrupted).unwrap()).is_err());
        let mut corrupted = serde_json::to_value(primary.snapshot()).unwrap();
        corrupted["leaves"].as_array_mut().unwrap().pop();
        assert!(Replay::restore(&alice, serde_json::from_value(corrupted).unwrap()).is_err());
        same_view.reconcile(&primary.state.pool).unwrap();
        other_view.reconcile(&primary.state.pool).unwrap();
        assert!(accepted.apply(&mut same_view).is_err());
        other_view.pool.backing += 1;
        assert!(accepted.apply(&mut other_view).is_err());
    }
}
