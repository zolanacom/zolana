//! Two wallets, a deposit and a private send with a shielded fee.
//!
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example private_payment
//!
//! Offline. This program plays the chain: it hands each payment to both
//! wallets as if it had been finalized. A real client must take payments from
//! verified finalized history instead (see the integration guidelines).
use native_payments::{envelope, staging::payload_digest, state::PoolState, wire};
use native_wallet_core::{
    history::WalletState,
    payments::{Payment, PaymentProver},
};
use std::sync::Arc;
use zolana_sdk_examples::{hex, DemoWallet, GENESIS, NETWORK};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let alice = DemoWallet::new(NETWORK, GENESIS, [7; 32]);
    let bob = DemoWallet::new(NETWORK, GENESIS, [8; 32]);
    let prover = PaymentProver::new();
    let key = prover.verifying_key();

    // Every wallet replays the same public history into its own view of the
    // pool: the note tree, the spent nullifiers and the notes it can decrypt.
    let pool = PoolState::new_slot_anchored(NETWORK, 1)?;
    let mut a = WalletState::with_key_for_pool(&alice, &pool, Arc::clone(&key))?;
    let mut b = WalletState::with_key_for_pool(&bob, &pool, key)?;
    // The public account that funds the deposit and later receives the fee.
    let relay = [0x53; 32];

    // Slot 1: 100 units enter the pool as a note for Alice.
    let deposit = Payment::Deposit {
        amount: 100,
        recipient: &alice.address()?,
    };
    let deposit = wire::decode(NETWORK, &prover.build(&alice, &a, relay, 100, deposit)?)?;
    for state in [&mut a, &mut b] {
        state.accept(&deposit.bundle, &deposit.context, 1)?; // verifies the proof
        state.finish_slot(1)?; // a root becomes spendable once its slot is complete
    }
    let (alice_has, bob_has) = (a.balance()?, b.balance()?);
    println!("after the deposit: alice {alice_has}, bob {bob_has}");

    // Slot 2: Alice pays Bob 40. The fee of 3 leaves the pool to the relay;
    // it is public. The recipient and the amount are not.
    let send = Payment::ShieldedSend {
        amount: 40,
        recipient: &bob.address()?,
        fee: 3,
    };
    let payload = prover.build(&alice, &a, relay, 100, send)?;
    let tag = std::str::from_utf8(&payload[..8])?;
    println!("payment: {} bytes, tag {tag}", payload.len());

    // A shielded-fee payment fits one transaction inside this frame. Its id is
    // the digest of the payment bytes, which is what a client tracks.
    let frame = envelope::encode(NETWORK, &payload)?;
    let opened = envelope::decode(NETWORK, 2, &frame)?;
    assert_eq!(opened.payment_id, payload_digest(&payload));
    let id = hex(&opened.payment_id);
    println!("envelope: {} bytes, payment id {id}", frame.len());

    let payment = &opened.payment;
    for state in [&mut a, &mut b] {
        state.accept(&payment.bundle, &payment.context, 2)?;
        state.finish_slot(2)?;
    }
    let (alice_has, bob_has) = (a.balance()?, b.balance()?);
    println!("after the send: alice {alice_has}, bob {bob_has}");
    let (notes, backing) = (a.pool.note_count(), a.pool.backing);
    println!("pool: {notes} notes, backing {backing}");
    assert_eq!(a.pool.encode(), b.pool.encode()); // both views agree

    // The same payment a second time spends the same notes and is refused.
    let again = a.accept(&payment.bundle, &payment.context, 3).unwrap_err();
    println!("the same payment again: {again}");
    Ok(())
}
