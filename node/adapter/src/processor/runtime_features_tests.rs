//! What the program asks of the runtime through `runtime_features`, observed
//! from outside the program in the mock invocation context of the runtime:
//! the compute units charged, the slot and the rent that are read, and the
//! invocations of the System program with and without the program's
//! signature.
//!
//! Every case runs `Entrypoint`, the program as the runtime registers it,
//! against an `NPOOL003` pool. The fixtures and helpers are those of
//! `slot_anchor_tests`.

use super::slot_anchor_tests::{
    account, account_mut, nullifiers_of, setup, stage, Accounts, PAYMENTS, SPONSOR,
};
use crate::{
    id, instructions, nullifiers, pool_address, staging::ACCOUNT_BYTES, Entrypoint,
    FINALIZE_COMPUTE_UNITS,
};
use native_payments::{staging::payload_digest, state::PoolState, verification::MAX_EXPIRY_WINDOW};
use solana_account::{create_account_shared_data_for_test, AccountSharedData, ReadableAccount};
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_program_runtime::{
    invoke_context::mock_process_instruction, loaded_programs::ProgramCacheEntry,
    solana_sbpf::vm::ContextObject,
};
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_sdk_ids::{system_program, sysvar};
use solana_system_program::system_processor::DEFAULT_COMPUTE_UNITS as SYSTEM_PROGRAM_UNITS;
use std::{cell::Cell, sync::Arc};

/// Run `instruction` with `budget` compute units, require `result`, and
/// return the units that remain afterwards.
fn run(
    accounts: &mut Accounts,
    instruction: &Instruction,
    budget: u64,
    result: Result<(), InstructionError>,
) -> u64 {
    let remaining = Cell::new(u64::MAX);
    let output = mock_process_instruction(
        &id(),
        None,
        &instruction.data,
        accounts.clone(),
        instruction.accounts.clone(),
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
        |context| remaining.set(context.get_remaining()),
    );
    for ((_, account), next) in accounts.iter_mut().zip(output) {
        *account = next;
    }
    remaining.get()
}

/// The instruction is refused with `error`, changes no account, and leaves
/// `remaining` compute units.
fn refused(
    accounts: &Accounts,
    instruction: &Instruction,
    budget: u64,
    error: InstructionError,
    remaining: u64,
) {
    let mut attempt = accounts.clone();
    assert_eq!(
        run(&mut attempt, instruction, budget, Err(error)),
        remaining
    );
    assert_eq!(&attempt, accounts);
}

/// An unused staging account and the instruction that initializes it.
fn initialization(accounts: &mut Accounts, seed: u8, expiry: u64) -> Instruction {
    let key = Pubkey::new_from_array([seed; 32]);
    accounts.push((
        key,
        AccountSharedData::new(
            Rent::default().minimum_balance(ACCOUNT_BYTES),
            ACCOUNT_BYTES,
            &id(),
        ),
    ));
    let bytes = &PAYMENTS.deposit;
    instructions::initialize(
        key,
        SPONSOR,
        bytes.len() as u32,
        payload_digest(bytes),
        expiry,
    )
}

fn marker_addresses(bytes: &[u8]) -> [Pubkey; 2] {
    nullifiers_of(bytes).map(|nullifier| nullifiers::address(&nullifier))
}

#[test]
fn staging_instruction_is_charged_ten_thousand_units() {
    let mut accounts = setup(false, 1);
    let initialize = initialization(&mut accounts, 91, 100);
    // One unit short: refused, and the units that were there are spent.
    refused(
        &accounts,
        &initialize,
        9_999,
        InstructionError::ComputationalBudgetExceeded,
        0,
    );
    // Exactly the charge is enough, and nothing remains.
    let mut exact = accounts.clone();
    assert_eq!(run(&mut exact, &initialize, 10_000, Ok(())), 0);
    // A larger budget loses the same ten thousand units and no more.
    assert_eq!(
        run(&mut accounts, &initialize, 1_400_000, Ok(())),
        1_390_000
    );
    assert_eq!(accounts, exact);
}

#[test]
fn finalization_is_charged_its_fixed_cost_before_any_check() {
    let mut accounts = setup(false, 1);
    // A finalization without a single account is refused for its accounts
    // only when its fixed cost could be charged, and the cost is then gone.
    let bare = Instruction {
        program_id: id(),
        accounts: Vec::new(),
        data: vec![3],
    };
    refused(
        &accounts,
        &bare,
        FINALIZE_COMPUTE_UNITS - 1,
        InstructionError::ComputationalBudgetExceeded,
        0,
    );
    refused(
        &accounts,
        &bare,
        FINALIZE_COMPUTE_UNITS,
        InstructionError::MissingRequiredSignature,
        0,
    );
    refused(
        &accounts,
        &bare,
        FINALIZE_COMPUTE_UNITS + 7,
        InstructionError::MissingRequiredSignature,
        7,
    );
    // The inline instruction is charged the same.
    let inline = Instruction {
        program_id: id(),
        accounts: Vec::new(),
        data: vec![5],
    };
    refused(
        &accounts,
        &inline,
        FINALIZE_COMPUTE_UNITS - 1,
        InstructionError::ComputationalBudgetExceeded,
        0,
    );
    refused(
        &accounts,
        &inline,
        FINALIZE_COMPUTE_UNITS + 7,
        InstructionError::MissingRequiredSignature,
        7,
    );
    // A valid payment one unit short of the fixed cost is refused as well.
    let deposit = stage(&mut accounts, &PAYMENTS.deposit, 91);
    refused(
        &accounts,
        &deposit,
        FINALIZE_COMPUTE_UNITS - 1,
        InstructionError::ComputationalBudgetExceeded,
        0,
    );
}

#[test]
fn deposit_invokes_the_system_program_seven_times_and_each_is_metered_once() {
    // A deposit moves coins into the pool with one transfer. Each of its two
    // spent markers is funded with one transfer, allocated and assigned.
    let cost = FINALIZE_COMPUTE_UNITS + 7 * SYSTEM_PROGRAM_UNITS;
    let mut accounts = setup(false, 1);
    let deposit = stage(&mut accounts, &PAYMENTS.deposit, 91);
    // One unit short, the last invocation cannot be charged and the
    // instruction fails. The mock context shows the accounts as the failed
    // instruction left them, which a Bank discards: the second marker is
    // funded and allocated but not assigned, and the pool's data, written
    // last, is untouched.
    let mut short = accounts.clone();
    assert_eq!(
        run(
            &mut short,
            &deposit,
            cost - 1,
            Err(InstructionError::ComputationalBudgetExceeded)
        ),
        0
    );
    let [first, second] = marker_addresses(&PAYMENTS.deposit);
    assert_eq!(account(&short, first).owner(), &id());
    assert_eq!(account(&short, second).owner(), &system_program::id());
    assert_eq!(
        account(&short, second).data().len(),
        nullifiers::MARKER_BYTES
    );
    assert_eq!(
        account(&short, pool_address()).data(),
        account(&accounts, pool_address()).data()
    );
    let mut exact = accounts.clone();
    assert_eq!(run(&mut exact, &deposit, cost, Ok(())), 0);
    assert_eq!(
        run(&mut accounts, &deposit, 1_400_000, Ok(())),
        1_400_000 - cost
    );
    assert_eq!(accounts, exact);

    // A marker that already holds its rent is not funded again: one
    // invocation fewer, and the sponsor pays for one marker only.
    let marker_rent = Rent::default().minimum_balance(nullifiers::MARKER_BYTES);
    let mut funded = setup(false, 1);
    let deposit = stage(&mut funded, &PAYMENTS.deposit, 91);
    *account_mut(&mut funded, first) =
        AccountSharedData::new(marker_rent, 0, &system_program::id());
    let before = account(&funded, SPONSOR).lamports();
    assert_eq!(
        run(&mut funded, &deposit, 1_400_000, Ok(())),
        1_400_000 - cost + SYSTEM_PROGRAM_UNITS
    );
    assert_eq!(
        account(&funded, SPONSOR).lamports(),
        before - 100 - marker_rent
    );
    for marker in [first, second] {
        assert_eq!(account(&funded, marker).lamports(), marker_rent);
        assert_eq!(account(&funded, marker).owner(), &id());
    }
}

#[test]
fn program_signs_for_each_spent_marker_and_the_sponsor_pays() {
    let mut accounts = setup(false, 1);
    let deposit = stage(&mut accounts, &PAYMENTS.deposit, 91);
    let sponsor = account(&accounts, SPONSOR).lamports();
    let pool = account(&accounts, pool_address()).lamports();
    let marker_rent = Rent::default().minimum_balance(nullifiers::MARKER_BYTES);
    let markers = marker_addresses(&PAYMENTS.deposit);
    for marker in markers {
        assert_eq!(account(&accounts, marker), &AccountSharedData::default());
    }
    run(&mut accounts, &deposit, 1_400_000, Ok(()));
    // Allocation and assignment need the signature of the marker's address,
    // which no transaction can carry: only the program can have given it.
    for (marker, nullifier) in markers.into_iter().zip(nullifiers_of(&PAYMENTS.deposit)) {
        let created = account(&accounts, marker);
        assert_eq!(created.owner(), &id());
        assert_eq!(created.data(), nullifiers::encode(&nullifier));
        assert_eq!(created.lamports(), marker_rent);
    }
    // The transfers are the sponsor's: 100 into the pool, the rent of two
    // markers, and nothing taken from or given to anyone else.
    assert_eq!(
        account(&accounts, SPONSOR).lamports(),
        sponsor - 100 - 2 * marker_rent
    );
    assert_eq!(account(&accounts, pool_address()).lamports(), pool + 100);
    assert_eq!(
        PoolState::decode(account(&accounts, pool_address()).data())
            .unwrap()
            .backing,
        100
    );

    // Without the sponsor's signature on the instruction nothing is invoked:
    // the program lends its own signature to the markers only.
    let mut unsigned = setup(false, 1);
    let mut deposit = stage(&mut unsigned, &PAYMENTS.deposit, 91);
    let position = deposit
        .accounts
        .iter()
        .position(|meta| meta.pubkey == SPONSOR)
        .unwrap();
    deposit.accounts[position] = AccountMeta::new(SPONSOR, false);
    refused(
        &unsigned,
        &deposit,
        1_400_000,
        InstructionError::MissingRequiredSignature,
        1_400_000 - FINALIZE_COMPUTE_UNITS,
    );
}

#[test]
fn slot_is_the_one_of_the_clock_sysvar() {
    let slot = 7_000;
    let invalid = InstructionError::InvalidInstructionData;
    let mut accounts = setup(false, slot);
    // A staging account may expire in the executing slot at the earliest and
    // `MAX_EXPIRY_WINDOW` slots after it at the latest.
    let past = initialization(&mut accounts, 91, slot - 1);
    refused(&accounts, &past, 10_000, invalid.clone(), 0);
    let beyond = initialization(&mut accounts, 92, slot + MAX_EXPIRY_WINDOW + 1);
    refused(&accounts, &beyond, 10_000, invalid, 0);
    let now = initialization(&mut accounts, 93, slot);
    run(&mut accounts, &now, 10_000, Ok(()));
    let last = initialization(&mut accounts, 94, slot + MAX_EXPIRY_WINDOW);
    run(&mut accounts, &last, 10_000, Ok(()));
}

#[test]
fn marker_rent_is_the_one_of_the_rent_sysvar() {
    let dearer = Rent {
        lamports_per_byte_year: Rent::default().lamports_per_byte_year * 3,
        ..Rent::default()
    };
    let marker_rent = dearer.minimum_balance(nullifiers::MARKER_BYTES);
    assert_ne!(
        marker_rent,
        Rent::default().minimum_balance(nullifiers::MARKER_BYTES)
    );
    let mut accounts = setup(false, 1);
    *account_mut(&mut accounts, sysvar::rent::id()) = create_account_shared_data_for_test(&dearer);
    let deposit = stage(&mut accounts, &PAYMENTS.deposit, 91);
    let before = account(&accounts, SPONSOR).lamports();
    run(&mut accounts, &deposit, 1_400_000, Ok(()));
    for marker in marker_addresses(&PAYMENTS.deposit) {
        assert_eq!(account(&accounts, marker).lamports(), marker_rent);
    }
    assert_eq!(
        account(&accounts, SPONSOR).lamports(),
        before - 100 - 2 * marker_rent
    );
}
