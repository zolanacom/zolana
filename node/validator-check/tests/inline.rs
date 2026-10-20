//! Native execution tests only: inline proofs still exceed the live Agave packet
//! limit. These tests establish neither network admission nor consensus finality.

use native_payment_program::{
    id, instructions, nullifiers, pool_address, staging::ACCOUNT_BYTES, ACTIVATION_ID,
    INLINE_PAYMENT_ACTIVATION_ID, SHIELDED_FEE_ACTIVATION_ID,
};
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::{PoolState, STATE_BYTES},
    wire,
};
use native_wallet::{
    history::WalletState,
    keys::{Network, WalletKey},
    payments::{Payment, PaymentProver},
};
use payment_lab::proof_smoke::FIXTURE_GENESIS;
use solana_account::{AccountSharedData, ReadableAccount};
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_feature_gate_interface::{create_account, Feature};
use solana_genesis_config::GenesisConfig;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_runtime::{bank::Bank, bank_forks::BankForks};
use solana_signer::Signer;
use solana_system_interface::instruction as system;
use solana_transaction::{Transaction, TransactionVerificationMode};

fn genesis(relay: &Keypair) -> GenesisConfig {
    let mut config = GenesisConfig::default();
    config.accounts.insert(
        relay.pubkey(),
        AccountSharedData::new(10_000_000_000, 0, &solana_sdk_ids::system_program::id()).into(),
    );
    let floor = config.rent.minimum_balance(STATE_BYTES);
    let mut pool = AccountSharedData::new(floor, STATE_BYTES, &id());
    pool.set_data_from_slice(&PoolState::new(FIXTURE_GENESIS, floor).unwrap().encode());
    config.accounts.insert(pool_address(), pool.into());
    for feature in [
        ACTIVATION_ID,
        INLINE_PAYMENT_ACTIVATION_ID,
        SHIELDED_FEE_ACTIVATION_ID,
    ] {
        config.accounts.insert(
            feature,
            create_account(
                &Feature {
                    activated_at: Some(0),
                },
                1_000_000,
            )
            .into(),
        );
    }
    config
}

fn transaction(
    bank: &Bank,
    relay: &Keypair,
    instructions: &[Instruction],
    extra: &[&Keypair],
) -> Transaction {
    let mut signers = vec![relay];
    signers.extend_from_slice(extra);
    Transaction::new_signed_with_payer(
        instructions,
        Some(&relay.pubkey()),
        &signers,
        bank.last_blockhash(),
    )
}

fn stage(bank: &Bank, relay: &Keypair, bytes: &[u8], transcript: &mut Vec<Transaction>) -> Pubkey {
    let buffer = Keypair::new();
    let create = transaction(
        bank,
        relay,
        &[
            system::create_account(
                &relay.pubkey(),
                &buffer.pubkey(),
                bank.get_minimum_balance_for_rent_exemption(ACCOUNT_BYTES),
                ACCOUNT_BYTES as u64,
                &id(),
            ),
            instructions::initialize(
                buffer.pubkey(),
                relay.pubkey(),
                bytes.len() as u32,
                payload_digest(bytes),
                100,
            ),
        ],
        &[&buffer],
    );
    bank.process_transaction(&create).unwrap();
    transcript.push(create);
    for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        let tx = transaction(
            bank,
            relay,
            &[instructions::write(
                buffer.pubkey(),
                relay.pubkey(),
                (index * MAX_CHUNK_BYTES) as u32,
                chunk,
            )],
            &[],
        );
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let seal = transaction(
        bank,
        relay,
        &[instructions::seal(buffer.pubkey(), relay.pubkey())],
        &[],
    );
    bank.process_transaction(&seal).unwrap();
    transcript.push(seal);
    buffer.pubkey()
}

fn staged_finalization(bank: &Bank, relay: &Keypair, buffer: Pubkey, bytes: &[u8]) -> Transaction {
    let decoded = wire::decode(FIXTURE_GENESIS, bytes).unwrap();
    let nfs = std::array::from_fn(|i| decoded.bundle.actions()[i].nullifier().to_bytes());
    let mut list = vec![ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)];
    list.extend(instructions::finalize_and_close(
        buffer,
        relay.pubkey(),
        nfs,
        None,
    ));
    transaction(bank, relay, &list, &[])
}

fn inline_transaction(bank: &Bank, relay: &Keypair, bytes: &[u8], units: u32) -> Transaction {
    transaction(
        bank,
        relay,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(units),
            instructions::inline(FIXTURE_GENESIS, bytes).unwrap(),
        ],
        &[],
    )
}

fn markers(bytes: &[u8]) -> [Pubkey; 2] {
    let decoded = wire::decode(FIXTURE_GENESIS, bytes).unwrap();
    std::array::from_fn(|i| {
        nullifiers::address(&decoded.bundle.actions()[i].nullifier().to_bytes())
    })
}

fn apply_history(states: &mut [&mut WalletState], bytes: &[u8], bank: &Bank) {
    let decoded = wire::decode(FIXTURE_GENESIS, bytes).unwrap();
    let pool = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    for state in states {
        state
            .accept(&decoded.bundle, &decoded.context, bank.slot())
            .unwrap();
        state.reconcile(&pool).unwrap();
    }
}

#[test]
fn inline_execution_recipient_and_change_respend_atomicity_gates_and_replay() {
    let relay = Keypair::new();
    let config = genesis(&relay);
    let forks = BankForks::new_rw_arc(Bank::new_for_tests(&config));
    let bank = forks.read().unwrap().root_bank();
    let replay_forks = BankForks::new_rw_arc(Bank::new_for_tests(&config));
    let replay = replay_forks.read().unwrap().root_bank();
    let network = Network {
        network: FIXTURE_GENESIS,
        genesis_hash: config.hash().to_string(),
    };
    let alice = WalletKey::generate(network.clone()).unwrap();
    let bob = WalletKey::generate(network.clone()).unwrap();
    let charlie = WalletKey::generate(network).unwrap();
    let floor = config.rent.minimum_balance(STATE_BYTES);
    let mut alice_state = WalletState::new(&alice, floor).unwrap();
    let mut bob_state = WalletState::new(&bob, floor).unwrap();
    let mut charlie_state = WalletState::new(&charlie, floor).unwrap();
    let prover = PaymentProver::new();
    let mut transcript = Vec::new();

    let deposit = prover
        .build(
            &alice,
            &alice_state,
            relay.pubkey().to_bytes(),
            100,
            Payment::Deposit {
                amount: 1_000,
                recipient: &alice.address_text(),
            },
        )
        .unwrap();
    let buffer = stage(&bank, &relay, &deposit, &mut transcript);
    let funding = staged_finalization(&bank, &relay, buffer, &deposit);
    bank.process_transaction(&funding).unwrap();
    transcript.push(funding);
    apply_history(
        &mut [&mut alice_state, &mut bob_state, &mut charlie_state],
        &deposit,
        &bank,
    );

    let first = prover
        .build(
            &alice,
            &alice_state,
            relay.pubkey().to_bytes(),
            100,
            Payment::ShieldedSend {
                amount: 100,
                recipient: &bob.address_text(),
                fee: 2,
            },
        )
        .unwrap();
    let first_tx = inline_transaction(&bank, &relay, &first, 1_400_000);
    assert!(1 + first_tx.signatures.len() * 64 + first_tx.message_data().len() > 1232);
    assert!(bank
        .verify_transaction(
            first_tx.clone().into(),
            TransactionVerificationMode::FullVerification
        )
        .is_err());

    // Both gates are independently required. Fund each disabled Bank with the
    // same proof using its own recent blockhash (feature accounts change genesis).
    for feature in [INLINE_PAYMENT_ACTIVATION_ID, SHIELDED_FEE_ACTIVATION_ID] {
        let mut off_config = config.clone();
        off_config.accounts.remove(&feature);
        let off_forks = BankForks::new_rw_arc(Bank::new_for_tests(&off_config));
        let off = off_forks.read().unwrap().root_bank();
        let buffer = stage(&off, &relay, &deposit, &mut Vec::new());
        let funding = staged_finalization(&off, &relay, buffer, &deposit);
        off.process_transaction(&funding).unwrap();
        let pool_before = off.get_account(&pool_address());
        let relay_before = off.get_balance(&relay.pubkey());
        let attempt = inline_transaction(&off, &relay, &first, 1_400_000);
        assert!(off.process_transaction(&attempt).is_err());
        assert_eq!(off.get_account(&pool_address()), pool_before);
        assert_eq!(off.get_balance(&relay.pubkey()), relay_before);
        for marker in markers(&first) {
            assert!(off.get_account(&marker).is_none());
        }
    }

    let before_pool = bank.get_account(&pool_address());
    let before_relay = bank.get_balance(&relay.pubkey());
    let original_ix = instructions::inline(FIXTURE_GENESIS, &first).unwrap();
    assert_eq!(original_ix.accounts.len(), 5);
    assert!(original_ix.data.len() <= 10 * 1024);
    // Fail each account binding without changing valid proof bytes.
    for mutation in 0..4 {
        let mut invalid = original_ix.clone();
        match mutation {
            0 => invalid.accounts[0].pubkey = Pubkey::new_unique(),
            1 => invalid.accounts[3].pubkey = Pubkey::new_unique(),
            2 => invalid.accounts[4].pubkey = invalid.accounts[3].pubkey,
            _ => invalid.accounts[3].is_writable = false,
        }
        let tx = transaction(
            &bank,
            &relay,
            &[
                ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
                invalid,
            ],
            &[],
        );
        assert!(bank.process_transaction(&tx).is_err());
        transcript.push(tx);
        assert_eq!(bank.get_account(&pool_address()), before_pool);
        assert_eq!(bank.get_balance(&relay.pubkey()), before_relay);
    }
    // Rebuild the envelope after changing an authorization-bound expiry. This
    // tests the payment signature rather than merely an envelope checksum.
    let decoded = wire::decode(FIXTURE_GENESIS, &first).unwrap();
    let mut changed = decoded.context;
    changed.expires_at -= 1;
    let invalid_bytes = wire::encode(FIXTURE_GENESIS, &changed, &decoded.bundle).unwrap();
    let invalid = inline_transaction(&bank, &relay, &invalid_bytes, 1_400_000);
    assert!(bank.process_transaction(&invalid).is_err());
    transcript.push(invalid);
    let mut corrupt_signature = first.clone();
    *corrupt_signature.last_mut().unwrap() ^= 1;
    let invalid = inline_transaction(&bank, &relay, &corrupt_signature, 1_400_000);
    assert!(bank.process_transaction(&invalid).is_err());
    transcript.push(invalid);
    assert_eq!(bank.get_account(&pool_address()), before_pool);
    assert_eq!(bank.get_balance(&relay.pubkey()), before_relay);

    let rollback = transaction(
        &bank,
        &relay,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            original_ix,
            system::transfer(&relay.pubkey(), &Pubkey::new_unique(), u64::MAX),
        ],
        &[],
    );
    assert!(bank.process_transaction(&rollback).is_err());
    transcript.push(rollback);
    assert_eq!(bank.get_account(&pool_address()), before_pool);
    assert_eq!(bank.get_balance(&relay.pubkey()), before_relay);
    for marker in markers(&first) {
        assert!(bank.get_account(&marker).is_none());
    }

    bank.process_transaction(&first_tx).unwrap();
    transcript.push(first_tx);
    assert_eq!(
        bank.get_balance(&relay.pubkey()),
        before_relay + 2 - 2 * config.rent.minimum_balance(nullifiers::MARKER_BYTES)
    );
    apply_history(
        &mut [&mut alice_state, &mut bob_state, &mut charlie_state],
        &first,
        &bank,
    );
    assert_eq!(alice_state.balance().unwrap(), 898);
    assert_eq!(bob_state.balance().unwrap(), 100);

    // A distinct transaction carrying the same proof must fail because of the
    // permanent spent set, not just Solana's signature deduplication cache.
    let duplicate = inline_transaction(&bank, &relay, &first, 1_399_999);
    assert!(bank.process_transaction(&duplicate).is_err());
    transcript.push(duplicate);
    let already_paid = bank.get_account(&pool_address());
    let duplicate_buffer = stage(&bank, &relay, &first, &mut transcript);
    let staged_duplicate = staged_finalization(&bank, &relay, duplicate_buffer, &first);
    assert!(bank.process_transaction(&staged_duplicate).is_err());
    transcript.push(staged_duplicate);
    assert_eq!(bank.get_account(&pool_address()), already_paid);
    assert!(bank.get_account(&duplicate_buffer).is_some());

    // Prepare spending Alice's newly returned change before Bob's next payment
    // advances the tree. The eventual submission must accept this retained root.
    let change = prover
        .build(
            &alice,
            &alice_state,
            relay.pubkey().to_bytes(),
            100,
            Payment::ShieldedSend {
                amount: 20,
                recipient: &charlie.address_text(),
                fee: 2,
            },
        )
        .unwrap();
    let forwarded = prover
        .build(
            &bob,
            &bob_state,
            relay.pubkey().to_bytes(),
            100,
            Payment::ShieldedSend {
                amount: 40,
                recipient: &charlie.address_text(),
                fee: 2,
            },
        )
        .unwrap();
    // Bob spends the just-received note through the same inline execution path.
    let forward_tx = inline_transaction(&bank, &relay, &forwarded, 1_400_000);
    bank.process_transaction(&forward_tx).unwrap();
    transcript.push(forward_tx);
    apply_history(
        &mut [&mut alice_state, &mut bob_state, &mut charlie_state],
        &forwarded,
        &bank,
    );
    let change_tx = inline_transaction(&bank, &relay, &change, 1_400_000);
    bank.process_transaction(&change_tx).unwrap();
    transcript.push(change_tx);
    apply_history(
        &mut [&mut alice_state, &mut bob_state, &mut charlie_state],
        &change,
        &bank,
    );
    assert_eq!(alice_state.balance().unwrap(), 876);
    assert_eq!(bob_state.balance().unwrap(), 58);
    assert_eq!(charlie_state.balance().unwrap(), 60);
    let pool = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(pool.backing, 994);
    assert_eq!(pool.note_count(), 8);
    for wallet in [&alice, &bob, &charlie] {
        assert_eq!(bank.get_balance(&wallet.fee_keypair().pubkey()), 0);
        assert_eq!(bank.get_balance(&wallet.public_keypair().pubkey()), 0);
    }

    // Exercise the reverse replay direction using a new valid payment: the old
    // staging path spends first, and the inline path cannot spend it again.
    let staged = prover
        .build(
            &bob,
            &bob_state,
            relay.pubkey().to_bytes(),
            100,
            Payment::ShieldedSend {
                amount: 1,
                recipient: &charlie.address_text(),
                fee: 2,
            },
        )
        .unwrap();
    let staged_buffer = stage(&bank, &relay, &staged, &mut transcript);
    let staged_tx = staged_finalization(&bank, &relay, staged_buffer, &staged);
    bank.process_transaction(&staged_tx).unwrap();
    transcript.push(staged_tx);
    apply_history(
        &mut [&mut alice_state, &mut bob_state, &mut charlie_state],
        &staged,
        &bank,
    );
    let before_duplicate = bank.get_account(&pool_address());
    let relay_before_duplicate = bank.get_balance(&relay.pubkey());
    let duplicate = inline_transaction(&bank, &relay, &staged, 1_400_000);
    assert!(bank.process_transaction(&duplicate).is_err());
    transcript.push(duplicate);
    assert_eq!(bank.get_account(&pool_address()), before_duplicate);
    assert_eq!(bank.get_balance(&relay.pubkey()), relay_before_duplicate);
    assert_eq!(alice_state.balance().unwrap(), 876);
    assert_eq!(bob_state.balance().unwrap(), 55);
    assert_eq!(charlie_state.balance().unwrap(), 61);
    let pool = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(pool.backing, 992);
    assert_eq!(pool.note_count(), 10);

    // Re-execute every original signed byte sequence in an independent Bank,
    // including failed attempts, and compare all durable effects and bank hashes.
    for tx in &transcript {
        let _ = replay.process_transaction(tx);
    }
    for key in [pool_address(), relay.pubkey(), duplicate_buffer] {
        assert_eq!(bank.get_account(&key), replay.get_account(&key));
    }
    for bytes in [&deposit, &first, &forwarded, &change, &staged] {
        for marker in markers(bytes) {
            assert_eq!(bank.get_account(&marker), replay.get_account(&marker));
            assert_eq!(bank.get_account(&marker).unwrap().owner(), &id());
        }
    }
    bank.freeze();
    replay.freeze();
    assert_eq!(bank.hash(), replay.hash());
    let child = Bank::new_from_parent(bank, &relay.pubkey(), 1);
    assert_eq!(
        child.get_account(&pool_address()),
        replay.get_account(&pool_address())
    );
}
