//! Synthetic in-memory host only. No RPC, live money, or finality assertion.
use crate::{
    history::WalletState,
    payments::{Payment, PaymentProver},
    replay::{HistoryInstruction, Replay},
    test_keys::FixtureKeys,
    WalletKeys,
};
use native_payments::{
    envelope, native_accounts,
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::PoolState,
    wire,
};
use std::sync::Arc;

fn inline(network: [u8; 32], payload: &[u8]) -> HistoryInstruction {
    let payment = wire::decode(network, payload).unwrap();
    let mut data = vec![5];
    data.extend_from_slice(&envelope::encode(network, payload).unwrap());
    let mut accounts = vec![
        (native_accounts::pool_address(), false),
        (payment.context.sponsor, true),
        (native_accounts::SYSTEM_ID, false),
    ];
    accounts.extend(payment.bundle.actions().iter().map(|action| {
        (
            native_accounts::nullifier_address(&action.nullifier().to_bytes()),
            false,
        )
    }));
    HistoryInstruction { accounts, data }
}
fn staged(replay: &mut Replay, sponsor: [u8; 32], payload: &[u8]) {
    let buffer = [0x77; 32];
    let mut init = vec![0];
    init.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    init.extend_from_slice(&payload_digest(payload));
    init.extend_from_slice(&100u64.to_le_bytes());
    replay
        .apply(
            &HistoryInstruction {
                accounts: vec![(buffer, true), (sponsor, true)],
                data: init,
            },
            1,
        )
        .unwrap();
    // Authenticate/restore the exact legacy staging bytes at an interrupted write.
    for (index, chunk) in payload.chunks(MAX_CHUNK_BYTES).enumerate() {
        let mut data = vec![1];
        data.extend_from_slice(&((index * MAX_CHUNK_BYTES) as u32).to_le_bytes());
        data.extend_from_slice(chunk);
        replay
            .apply(
                &HistoryInstruction {
                    accounts: vec![(buffer, false), (sponsor, true)],
                    data,
                },
                1,
            )
            .unwrap();
    }
    replay
        .apply(
            &HistoryInstruction {
                accounts: vec![(buffer, false), (sponsor, true)],
                data: vec![2],
            },
            1,
        )
        .unwrap();
    let payment = wire::decode(replay.state.pool.network, payload).unwrap();
    let mut accounts = vec![
        (native_accounts::pool_address(), false),
        (buffer, false),
        (sponsor, true),
        (native_accounts::SYSTEM_ID, false),
    ];
    accounts.extend(payment.bundle.actions().iter().map(|action| {
        (
            native_accounts::nullifier_address(&action.nullifier().to_bytes()),
            false,
        )
    }));
    replay
        .apply(
            &HistoryInstruction {
                accounts,
                data: vec![3],
            },
            1,
        )
        .unwrap();
}

#[test]
fn shared_engine_staged_funding_inline_sends_restore_and_immediate_respend() {
    let domain = [33; 32];
    let genesis = bs58::encode([34; 32]).into_string();
    let alice = FixtureKeys::new(domain, genesis.clone(), [7; 32]);
    let bob = FixtureKeys::new(domain, genesis.clone(), [8; 32]);
    let charlie = FixtureKeys::new(domain, genesis, [9; 32]);
    let prover = PaymentProver::new();
    let key = prover.verifying_key();
    let expected = PoolState::new_slot_anchored(domain, 1).unwrap();
    let state = |keys: &FixtureKeys| {
        WalletState::with_key_for_pool(keys, &expected, Arc::clone(&key)).unwrap()
    };
    let mut a = Replay::from_state(state(&alice));
    let mut b = Replay::from_state(state(&bob));
    let mut c = Replay::from_state(state(&charlie));
    let sponsor = [0x53; 32];
    let funding = prover
        .build(
            &alice,
            &a.state,
            sponsor,
            100,
            Payment::Deposit {
                amount: 100,
                recipient: &alice.address_text(),
            },
        )
        .unwrap();
    // The test host assumes successful canonical native execution. Proof alone
    // does not supply the corresponding real public debit or chain finality.
    for replay in [&mut a, &mut b, &mut c] {
        staged(replay, sponsor, &funding);
        replay.finish_slot(1).unwrap();
    }
    assert_eq!(a.state.balance().unwrap(), 100);
    let send = prover
        .build(
            &alice,
            &a.state,
            sponsor,
            100,
            Payment::ShieldedSend {
                amount: 40,
                recipient: &bob.address_text(),
                fee: 3,
            },
        )
        .unwrap();
    let instruction = inline(domain, &send);
    let mut malformed = inline(domain, &send);
    malformed.accounts[1].1 = false;
    let before = a.state.pool.encode();
    assert!(a.apply(&malformed, 2).is_err());
    assert_eq!(a.state.pool.encode(), before);
    let accepted = a.apply_verified(&instruction, 2).unwrap().unwrap();
    accepted.apply(&mut b.state).unwrap();
    accepted.apply(&mut c.state).unwrap();
    for replay in [&mut a, &mut b, &mut c] {
        assert!(replay.state.spendable_anchor().is_err());
        replay.finish_slot(2).unwrap();
    }
    let encoded = serde_json::to_vec(&b.snapshot()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        5
    );
    b = Replay::restore_with_key(
        &bob,
        serde_json::from_slice(&encoded).unwrap(),
        Some(Arc::clone(&key)),
    )
    .unwrap();
    assert_eq!(b.state.balance().unwrap(), 40);
    for owned in b.state.unspent() {
        b.state.witness(owned.position).unwrap();
    }
    assert!(Replay::restore_with_key(
        &alice,
        serde_json::from_slice(&encoded).unwrap(),
        Some(Arc::clone(&key))
    )
    .is_err());
    let mut corrupt: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    corrupt["notes"][0]["value"] = 41.into();
    assert!(Replay::restore_with_key(
        &bob,
        serde_json::from_value(corrupt).unwrap(),
        Some(Arc::clone(&key))
    )
    .is_err());
    let before = b.state.pool.encode();
    assert!(b.apply(&instruction, 3).is_err());
    assert_eq!(b.state.pool.encode(), before);
    let onward = prover
        .build(
            &bob,
            &b.state,
            sponsor,
            100,
            Payment::ShieldedSend {
                amount: 20,
                recipient: &charlie.address_text(),
                fee: 3,
            },
        )
        .unwrap();
    let accepted = b
        .apply_verified(&inline(domain, &onward), 3)
        .unwrap()
        .unwrap();
    accepted.apply(&mut a.state).unwrap();
    accepted.apply(&mut c.state).unwrap();
    for replay in [&mut a, &mut b, &mut c] {
        replay.finish_slot(3).unwrap();
    }
    for replay in [&a, &b, &c] {
        replay.state.reconcile(&b.state.pool).unwrap();
    }
    assert_eq!(
        (
            a.state.balance().unwrap(),
            b.state.balance().unwrap(),
            c.state.balance().unwrap()
        ),
        (57, 17, 20)
    );
    assert_eq!(b.state.pool.backing, 94);
    assert_eq!(b.state.pool.note_count(), 6);
    assert_eq!(b.state.spent_nullifiers().len(), 6);
    assert_eq!(bob.network_domain(), domain);
}
