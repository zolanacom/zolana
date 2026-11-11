//! Explicitly invoked, native-only disposable transcript generator.
//! The published backup/password belong solely to fake network [7;32].
use super::*;
use std::{fs::OpenOptions, io::Write};

#[cfg(not(target_arch = "wasm32"))]
#[test]
#[ignore = "writes one public disposable offline diagnostic fixture, no network"]
fn generate_disposable_real_wallet_transcript() {
    let mut alice = BrowserVault::create(&network_json(), PASSWORD.to_vec()).unwrap();
    let bob = BrowserVault::create(&network_json(), PASSWORD.to_vec()).unwrap();
    let initial = PoolState::new_slot_anchored([7; 32], 1).unwrap();
    let mut replay = with_prover(|p| {
        WalletState::with_key_for_pool(&alice, &initial, p.verifying_key())
            .map(Replay::from_state)
            .map_err(err)
    })
    .unwrap();
    let mut blocks = Vec::new();
    for (index, amount) in [2, 3].into_iter().enumerate() {
        let payload = with_prover(|p| {
            p.build(
                &alice,
                &replay.state,
                sponsor().pubkey().to_bytes(),
                100,
                Payment::Deposit {
                    amount,
                    recipient: &alice.identity()?.private_address,
                },
            )
            .map_err(err)
        })
        .unwrap();
        // Deposits use the existing staged transport. The inline envelope is
        // reserved for the shielded-fee payment version, not public deposits.
        let buffer = Keypair::new_from_array([29 + index as u8; 32]);
        let instructions = staged(&payload, &buffer);
        let slot = index as u64 + 1;
        blocks.push(block(
            slot,
            vec![transaction(&signed(&instructions, Some(&buffer)))],
        ));
        replay_instructions(&mut replay, &instructions, slot);
    }
    assert_eq!(replay.state.balance().unwrap(), 5);
    assert_eq!(replay.state.max_payment().unwrap(), 5);
    let mut values: Vec<_> = replay
        .state
        .unspent()
        .iter()
        .map(|n| n.note.value().inner())
        .collect();
    values.sort_unstable();
    assert_eq!(values, vec![2, 3]);
    let pool = replay.state.pool.encode();
    let checkpoint = sync(&mut alice, &pool, 2, &[], &blocks);
    let status: Value = serde_json::from_str(&alice.payment_status().unwrap()).unwrap();
    assert_eq!(status["verified"], true);
    assert_eq!(status["balance"], "5");
    assert_eq!(status["max_payment"], "5");
    assert!(!checkpoint.is_empty());
    // Generator validates the funded transcript only. The browser performs the
    // sole measured shielded send via the unchanged BrowserVault build API.
    let fixture = json!({
        "format":"zolana091-real-wallet-offline-transcript-v1", "fixture_only":true,
        "network":serde_json::from_str::<Value>(&network_json()).unwrap(),
        "password":std::str::from_utf8(PASSWORD).unwrap(),
        "encrypted_backup":alice.encrypted_backup(),
        "recipient":bob.identity().unwrap().private_address,
        "pool_response":serde_json::from_str::<Value>(&pool_reply(&pool,2)).unwrap(),
        "target_header":serde_json::from_str::<Value>(&header(2)).unwrap(),
        "canonical_blocks":blocks,
        "quote":serde_json::from_str::<Value>(&quote()).unwrap(),
        "amount":1,"maximum_fee":3,"expiry":3,
        "expected":{"balance":"5","max_payment":"5","funding_values":[2,3],"target_slot":2}
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/offline-transcript-fixture.json");
    let bytes = serde_json::to_vec_pretty(&fixture).unwrap();
    assert!(bytes.len() < 128 * 1024);
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    output.write_all(&bytes).unwrap();
    output.sync_all().unwrap();
    alice.lock();
    println!(
        "Generated public fake-network transcript: {} bytes, two notes [2,3], verified balance 5",
        bytes.len()
    );
}
