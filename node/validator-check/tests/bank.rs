use native_payment_program::{
    id, instructions, pool_address, staging::ACCOUNT_BYTES, ACTIVATION_ID,
};
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::{PoolState, STATE_BYTES},
    wire,
};
use payment_lab::proof_smoke::{build_fixture_for, withdrawal_fixture, FIXTURE_GENESIS};
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
use solana_transaction::Transaction;

fn genesis(sponsor: &Keypair, enabled: bool) -> GenesisConfig {
    let mut genesis = GenesisConfig::default();
    genesis.accounts.insert(
        sponsor.pubkey(),
        AccountSharedData::new(10_000_000_000, 0, &solana_sdk_ids::system_program::id()).into(),
    );
    let floor = genesis.rent.minimum_balance(STATE_BYTES);
    let mut pool = AccountSharedData::new(floor, STATE_BYTES, &id());
    pool.set_data_from_slice(&PoolState::new(FIXTURE_GENESIS, floor).unwrap().encode());
    genesis.accounts.insert(pool_address(), pool.into());
    if enabled {
        genesis.accounts.insert(
            ACTIVATION_ID,
            create_account(
                &Feature {
                    activated_at: Some(0),
                },
                1_000_000,
            )
            .into(),
        );
    }
    genesis
}

fn transaction(
    bank: &Bank,
    sponsor: &Keypair,
    instructions: &[Instruction],
    extra: &[&Keypair],
) -> Transaction {
    let mut signers = vec![sponsor];
    signers.extend_from_slice(extra);
    Transaction::new_signed_with_payer(
        instructions,
        Some(&sponsor.pubkey()),
        &signers,
        bank.last_blockhash(),
    )
}

fn stage_transactions(bank: &Bank, sponsor: &Keypair, bytes: &[u8]) -> (Pubkey, Vec<Transaction>) {
    let buffer = Keypair::new();
    let mut txs = vec![transaction(
        bank,
        sponsor,
        &[
            system::create_account(
                &sponsor.pubkey(),
                &buffer.pubkey(),
                bank.get_minimum_balance_for_rent_exemption(ACCOUNT_BYTES),
                ACCOUNT_BYTES as u64,
                &id(),
            ),
            instructions::initialize(
                buffer.pubkey(),
                sponsor.pubkey(),
                bytes.len() as u32,
                payload_digest(bytes),
                100,
            ),
        ],
        &[&buffer],
    )];
    for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        txs.push(transaction(
            bank,
            sponsor,
            &[instructions::write(
                buffer.pubkey(),
                sponsor.pubkey(),
                (index * MAX_CHUNK_BYTES) as u32,
                chunk,
            )],
            &[],
        ));
    }
    txs.push(transaction(
        bank,
        sponsor,
        &[instructions::seal(buffer.pubkey(), sponsor.pubkey())],
        &[],
    ));
    (buffer.pubkey(), txs)
}

fn finalize(bank: &Bank, sponsor: &Keypair, buffer: Pubkey) -> Transaction {
    transaction(
        bank,
        sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instructions::finalize(buffer, sponsor.pubkey()),
        ],
        &[],
    )
}

#[test]
fn native_registration_funded_payments_atomic_rollback_and_bank_replay() {
    let sponsor = Keypair::new();
    let fixture = build_fixture_for(sponsor.pubkey().to_bytes()).unwrap();
    let genesis_config = genesis(&sponsor, true);
    let forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
    let bank = forks.read().unwrap().root_bank();
    let replay_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis_config));
    let independent = replay_forks.read().unwrap().root_bank();
    let inactive = Bank::new_for_tests(&genesis(&sponsor, false));
    assert!(bank.get_account(&id()).unwrap().executable());
    assert!(inactive.get_account(&id()).is_none());
    let mut transcript = Vec::new();

    let bytes = wire::encode(FIXTURE_GENESIS, &fixture.funding_context, &fixture.funding).unwrap();
    let (buffer, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let before_deposit = bank.get_account(&pool_address()).unwrap();
    let mut readonly = instructions::finalize(buffer, sponsor.pubkey());
    readonly.accounts[1].is_writable = false;
    let failed_deposit = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            readonly,
        ],
        &[],
    );
    assert!(bank.process_transaction(&failed_deposit).is_err());
    assert_eq!(bank.get_account(&pool_address()).unwrap(), before_deposit);
    transcript.push(failed_deposit);
    let funded = finalize(&bank, &sponsor, buffer);
    bank.process_transaction(&funded).unwrap();
    transcript.push(funded);
    let state = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(state.backing, 100);
    assert_eq!(bank.get_balance(&pool_address()), state.rent_floor + 100);

    let bytes = wire::encode(FIXTURE_GENESIS, &fixture.context, &fixture.bundle).unwrap();
    let (buffer, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let before = bank.get_account(&pool_address()).unwrap();
    let before_buffer = bank.get_account(&buffer).unwrap();
    // The payment succeeds, then the following instruction fails: Bank must roll back both.
    let mut fail = instructions::finalize(buffer, sponsor.pubkey());
    fail.data = vec![255];
    let failed = transaction(
        &bank,
        &sponsor,
        &[
            ComputeBudgetInstruction::set_compute_unit_limit(1_400_000),
            instructions::finalize(buffer, sponsor.pubkey()),
            fail,
        ],
        &[],
    );
    assert!(bank.process_transaction(&failed).is_err());
    assert_eq!(bank.get_account(&pool_address()).unwrap(), before);
    assert_eq!(bank.get_account(&buffer).unwrap(), before_buffer);
    transcript.push(failed);
    let paid = finalize(&bank, &sponsor, buffer);
    bank.process_transaction(&paid).unwrap();
    transcript.push(paid);
    let state = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(state.note_count(), 4);
    assert_eq!(state.backing, 100);

    let (repeated, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let attempted = finalize(&bank, &sponsor, repeated);
    assert!(bank.process_transaction(&attempted).is_err());
    transcript.push(attempted);
    let (withdrawal, context) = withdrawal_fixture(&fixture).unwrap();
    let bytes = wire::encode(FIXTURE_GENESIS, &context, &withdrawal).unwrap();
    let (buffer, txs) = stage_transactions(&bank, &sponsor, &bytes);
    for tx in txs {
        bank.process_transaction(&tx).unwrap();
        transcript.push(tx);
    }
    let withdrawn = finalize(&bank, &sponsor, buffer);
    bank.process_transaction(&withdrawn).unwrap();
    transcript.push(withdrawn);
    let state = PoolState::decode(bank.get_account(&pool_address()).unwrap().data()).unwrap();
    assert_eq!(state.backing, 60);
    assert_eq!(bank.get_balance(&pool_address()), state.rent_floor + 60);
    for tx in &transcript {
        let _ = independent.process_transaction(tx);
    }
    assert_eq!(
        bank.get_account(&pool_address()),
        independent.get_account(&pool_address())
    );
    assert_eq!(
        bank.get_account(&sponsor.pubkey()),
        independent.get_account(&sponsor.pubkey())
    );
    bank.freeze();
    independent.freeze();
    assert_eq!(bank.hash(), independent.hash());
    let next = Bank::new_from_parent(bank, &sponsor.pubkey(), 1);
    assert_eq!(
        next.get_account(&pool_address()),
        independent.get_account(&pool_address())
    );
}
