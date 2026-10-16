use native_payment_program::{
    id, instructions, pool_address,
    staging::{Buffer, ACCOUNT_BYTES},
    Entrypoint,
};
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::{PoolState, STATE_BYTES},
    wire,
};
use payment_lab::proof_smoke::{build_fixture_for, FIXTURE_GENESIS};
use solana_account::{
    create_account_shared_data_for_test, AccountSharedData, ReadableAccount, WritableAccount,
};
use solana_instruction::{error::InstructionError, Instruction};
use solana_program_runtime::{
    invoke_context::mock_process_instruction, loaded_programs::ProgramCacheEntry,
};
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_sdk_ids::{native_loader, system_program, sysvar};
use std::sync::Arc;

type Accounts = Vec<(Pubkey, AccountSharedData)>;

fn execute(
    accounts: &mut Accounts,
    instruction: Instruction,
    result: Result<(), InstructionError>,
    budget: u64,
) {
    let output = mock_process_instruction(
        &id(),
        None,
        &instruction.data,
        accounts.clone(),
        instruction.accounts,
        result,
        Entrypoint::vm,
        |context| {
            context.mock_set_remaining(budget);
            context.program_cache_for_tx_batch.replenish(
                system_program::id(),
                Arc::new(ProgramCacheEntry::new_builtin(
                    0,
                    0,
                    solana_system_program::system_processor::Entrypoint::vm,
                )),
            );
        },
        |_| {},
    );
    for ((_, account), next) in accounts.iter_mut().zip(output) {
        *account = next;
    }
}

fn setup(sponsor: Pubkey) -> Accounts {
    let rent = Rent::default();
    let pool_floor = rent.minimum_balance(STATE_BYTES);
    let mut pool = AccountSharedData::new(pool_floor, STATE_BYTES, &id());
    pool.set_data_from_slice(
        &PoolState::new(FIXTURE_GENESIS, pool_floor)
            .unwrap()
            .encode(),
    );
    let mut system = AccountSharedData::new(1, 0, &native_loader::id());
    system.set_executable(true);
    vec![
        (pool_address(), pool),
        (
            sponsor,
            AccountSharedData::new(10_000_000_000, 0, &system_program::id()),
        ),
        (system_program::id(), system),
        (
            sysvar::clock::id(),
            create_account_shared_data_for_test(&solana_clock::Clock {
                slot: 1,
                ..Default::default()
            }),
        ),
    ]
}

fn stage(accounts: &mut Accounts, sponsor: Pubkey, bytes: &[u8], seed: u8) -> Pubkey {
    let key = Pubkey::new_from_array([seed; 32]);
    accounts.push((
        key,
        AccountSharedData::new(
            Rent::default().minimum_balance(ACCOUNT_BYTES),
            ACCOUNT_BYTES,
            &id(),
        ),
    ));
    execute(
        accounts,
        instructions::initialize(key, sponsor, bytes.len() as u32, payload_digest(bytes), 100),
        Ok(()),
        1_400_000,
    );
    for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        execute(
            accounts,
            instructions::write(key, sponsor, (index * MAX_CHUNK_BYTES) as u32, chunk),
            Ok(()),
            1_400_000,
        );
    }
    execute(
        accounts,
        instructions::seal(key, sponsor),
        Ok(()),
        1_400_000,
    );
    key
}

fn account(accounts: &Accounts, key: Pubkey) -> &AccountSharedData {
    &accounts.iter().find(|(k, _)| *k == key).unwrap().1
}
fn state(accounts: &Accounts) -> PoolState {
    PoolState::decode(account(accounts, pool_address()).data()).unwrap()
}

#[test]
fn real_funded_deposit_and_private_spend_execute_in_native_runtime() {
    let sponsor = Pubkey::new_from_array([83; 32]);
    let fixture = build_fixture_for(sponsor.to_bytes()).unwrap();
    let mut accounts = setup(sponsor);
    let initial = account(&accounts, sponsor).lamports();
    let funding =
        wire::encode(FIXTURE_GENESIS, &fixture.funding_context, &fixture.funding).unwrap();
    let mut unfunded = accounts.clone();
    unfunded
        .iter_mut()
        .find(|(key, _)| *key == sponsor)
        .unwrap()
        .1
        .set_lamports(50);
    let unpaid = stage(&mut unfunded, sponsor, &funding, 89);
    execute(
        &mut unfunded,
        instructions::finalize(unpaid, sponsor),
        Err(InstructionError::Custom(1)),
        1_400_000,
    );
    assert_eq!(state(&unfunded).backing, 0);
    assert_eq!(state(&unfunded).note_count(), 0);
    assert_eq!(
        account(&unfunded, pool_address()).lamports(),
        state(&unfunded).rent_floor
    );
    let buffer = stage(&mut accounts, sponsor, &funding, 91);
    execute(
        &mut accounts,
        instructions::finalize(buffer, sponsor),
        Ok(()),
        1_400_000,
    );
    assert_eq!(state(&accounts).backing, 100);
    assert_eq!(state(&accounts).note_count(), 2);
    assert_eq!(account(&accounts, sponsor).lamports(), initial - 100);
    assert_eq!(
        account(&accounts, pool_address()).lamports(),
        state(&accounts).rent_floor + 100
    );
    assert!(state(&accounts)
        .roots()
        .contains(&fixture.bundle.anchor().to_bytes()));

    // Persist and restore all account bytes in a fresh invocation environment.
    let mut replay = accounts.clone();
    let payment = wire::encode(FIXTURE_GENESIS, &fixture.context, &fixture.bundle).unwrap();
    let mut corrupt_payment = payment.clone();
    let last_proof_byte = corrupt_payment.len() - 65;
    corrupt_payment[last_proof_byte] ^= 1;
    let invalid_buffer = stage(&mut accounts, sponsor, &corrupt_payment, 90);
    let before_invalid = account(&accounts, pool_address()).clone();
    execute(
        &mut accounts,
        instructions::finalize(invalid_buffer, sponsor),
        Err(InstructionError::InvalidInstructionData),
        1_400_000,
    );
    assert_eq!(account(&accounts, pool_address()), &before_invalid);
    let buffer = stage(&mut accounts, sponsor, &payment, 92);
    execute(
        &mut accounts,
        instructions::finalize(buffer, sponsor),
        Err(InstructionError::ComputationalBudgetExceeded),
        10_000,
    );
    assert_eq!(state(&accounts).note_count(), 2);
    execute(
        &mut accounts,
        instructions::finalize(buffer, sponsor),
        Ok(()),
        1_400_000,
    );
    let second = stage(&mut replay, sponsor, &payment, 92);
    execute(
        &mut replay,
        instructions::finalize(second, sponsor),
        Ok(()),
        1_400_000,
    );
    assert_eq!(
        account(&accounts, pool_address()).data(),
        account(&replay, pool_address()).data()
    );
    assert_eq!(state(&accounts).backing, 100);
    assert_eq!(state(&accounts).note_count(), 4);
    assert_eq!(account(&accounts, sponsor).lamports(), initial - 100);
    assert!(Buffer::decode(account(&accounts, buffer).data())
        .unwrap()
        .payload()
        .is_err());

    let before = account(&accounts, pool_address()).clone();
    execute(
        &mut accounts,
        instructions::finalize(buffer, sponsor),
        Err(InstructionError::InvalidAccountData),
        1_400_000,
    );
    let replay_buffer = stage(&mut accounts, sponsor, &payment, 93);
    execute(
        &mut accounts,
        instructions::finalize(replay_buffer, sponsor),
        Err(InstructionError::InvalidInstructionData),
        1_400_000,
    );
    assert_eq!(account(&accounts, pool_address()), &before);

    let mut corrupt = funding.clone();
    let index = corrupt.len() - 65;
    corrupt[index] ^= 1;
    let bad = stage(&mut accounts, sponsor, &corrupt, 94);
    let balance = account(&accounts, sponsor).lamports();
    execute(
        &mut accounts,
        instructions::finalize(bad, sponsor),
        Err(InstructionError::InvalidInstructionData),
        1_400_000,
    );
    assert_eq!(account(&accounts, pool_address()), &before);
    assert_eq!(account(&accounts, sponsor).lamports(), balance);
    assert!(Buffer::decode(account(&accounts, bad).data())
        .unwrap()
        .payload()
        .is_ok());
    let refund = account(&accounts, bad).lamports();
    execute(
        &mut accounts,
        instructions::close(bad, sponsor),
        Ok(()),
        1_400_000,
    );
    assert_eq!(account(&accounts, bad).lamports(), 0);
    assert_eq!(account(&accounts, sponsor).lamports(), balance + refund);

    let (withdrawal, context) = payment_lab::proof_smoke::withdrawal_fixture(&fixture).unwrap();
    let bytes = wire::encode(FIXTURE_GENESIS, &context, &withdrawal).unwrap();
    let exit = stage(&mut accounts, sponsor, &bytes, 95);
    let balance = account(&accounts, sponsor).lamports();
    execute(
        &mut accounts,
        instructions::finalize(exit, sponsor),
        Ok(()),
        1_400_000,
    );
    assert_eq!(state(&accounts).backing, 60);
    assert_eq!(state(&accounts).note_count(), 6);
    assert_eq!(account(&accounts, sponsor).lamports(), balance + 40);
    assert_eq!(
        account(&accounts, pool_address()).lamports(),
        state(&accounts).rent_floor + 60
    );

    // A pool account cannot be treated as a staging account to refund its backing.
    let protected = account(&accounts, pool_address()).clone();
    execute(
        &mut accounts,
        instructions::close(pool_address(), sponsor),
        Err(InstructionError::InvalidArgument),
        1_400_000,
    );
    assert_eq!(account(&accounts, pool_address()), &protected);
    let other = Pubkey::new_from_array([88; 32]);
    accounts.push((
        other,
        AccountSharedData::new(1_000_000, 0, &system_program::id()),
    ));
    execute(
        &mut accounts,
        instructions::close(replay_buffer, other),
        Err(InstructionError::MissingRequiredSignature),
        1_400_000,
    );
    assert_eq!(account(&accounts, pool_address()), &protected);
}
