//! Verification-key reuse and finalized-header bound regressions.
use super::*;

#[test]
fn empty_header_bound_covers_maximum_canonical_fields() {
    let longest_hash = bs58::encode([255u8; 32]).into_string();
    assert_eq!(longest_hash.len(), 44);
    hash(&longest_hash).unwrap();
    let block = Block {
        slot: u64::MAX,
        parent_slot: u64::MAX,
        blockhash: longest_hash.clone(),
        previous_blockhash: longest_hash,
        block_height: u64::MAX,
        transactions: Vec::new(),
    };
    assert!(serde_json::to_vec(&block).unwrap().len() < 512);
    assert!(hash(&"1".repeat(45)).is_err());
    assert!(hash(&"?".repeat(44)).is_err());
}

#[test]
fn fresh_and_restored_sync_use_cached_vk_without_constructing_prover() {
    // A fresh OS thread makes the worker-local cache/prover precondition
    // independent of the Rust test runner's reused threads.
    std::thread::spawn(|| {
        assert!(PROVER.with(|slot| slot.borrow().is_none()));
        let network = json!({"network":vec![7u8;32],"genesis_hash":"1".repeat(32)}).to_string();
        let mut vault =
            BrowserVault::create(&network, b"disposable VK-only sync fixture".to_vec()).unwrap();
        let mut pool = PoolState::new_slot_anchored([7; 32], 1).unwrap();
        pool.complete_slot(0).unwrap();
        pool.complete_slot(1).unwrap();
        let pool_reply = json!({"context":{"slot":1},"value":{
            "owner":Pubkey::new_from_array(native_accounts::PROGRAM_ID).to_string(),
            "lamports":1,"data":[STANDARD.encode(pool.encode()),"base64"]}})
        .to_string();
        let block_hash = bs58::encode([31u8; 32]).into_string();
        let header = json!({"blockhash":block_hash,"blockHeight":1}).to_string();
        vault.begin_sync(&pool_reply, &header, &[], "null").unwrap();
        let key = replay_verifying_key();
        assert!(Arc::ptr_eq(&key, &replay_verifying_key()));
        assert_eq!(
            key.circuit_version(),
            native_payments::verification::bundle_version().circuit_version()
        );
        vault
            .apply_canonical_blocks(
                &json!([{
                    "slot":1,"parent_slot":0,"blockhash":block_hash,
                    "previous_blockhash":"1".repeat(32),"block_height":1,"transactions":[]
                }])
                .to_string(),
            )
            .unwrap();
        let checkpoint = vault.finish_sync().unwrap();
        assert!(PROVER.with(|slot| slot.borrow().is_none()));
        vault
            .begin_sync(&pool_reply, &header, &checkpoint, &header)
            .unwrap();
        vault.finish_sync().unwrap();
        assert!(Arc::ptr_eq(&key, &replay_verifying_key()));
        assert!(PROVER.with(|slot| slot.borrow().is_none()));
        let status: Value = serde_json::from_str(&vault.payment_status().unwrap()).unwrap();
        assert_eq!(status["balance"], "0");
        assert_eq!(status["verified"], true);
    })
    .join()
    .unwrap();
}

#[test]
fn replay_key_is_cached_when_prover_was_prepared_first() {
    std::thread::spawn(|| {
        assert!(REPLAY_KEY.with(|slot| slot.borrow().is_none()));
        prepare_wallet_prover().unwrap();
        assert!(PROVER.with(|slot| slot.borrow().is_some()));
        let key = replay_verifying_key();
        assert!(Arc::ptr_eq(&key, &replay_verifying_key()));
        assert_eq!(
            key.circuit_version(),
            native_payments::verification::bundle_version().circuit_version()
        );
        assert!(PROVER.with(|slot| slot.borrow().is_some()));
    })
    .join()
    .unwrap();
}
