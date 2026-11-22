//! The slot-anchor rule of an `NPOOL004` pool, run through the finalizer with
//! real proofs in the mock invocation context of the runtime.
//!
//! Two things the runtime does on a network that uses this pool format are
//! replaced here by test stand-ins, because the Agave 3.0.14 runtime this
//! workspace builds against does neither (decision 0043):
//!
//! - **The feature.** `SlotAnchorsActive` and `SlotAnchorsInactive` are the
//!   program with the state of `native_slot_anchors` given. `Entrypoint`, the
//!   program as the runtime registers it, is run beside them wherever the
//!   feature is inactive.
//! - **The end of a slot.** `complete_slot_stand_in` records a completed slot
//!   in the pool account through the protocol crate, as the runtime does once
//!   per block after the last transaction. No transaction can do this.
//!
//! What these tests show is therefore which payments the program accepts and
//! refuses for a given pool account and slot. They do not show that any
//! runtime completes slots, or activates the feature.

use super::process_gated;
use crate::{
    id, instructions, nullifiers, pool_address,
    staging::{Buffer, ACCOUNT_BYTES},
    Entrypoint,
};
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::{PoolState, SLOT_STATE_BYTES, STATE_BYTES},
    wire,
};
use orchard::tree::Anchor;
use payment_lab::proof_smoke::{build_fixture_for_network, withdrawal_fixture, FIXTURE_GENESIS};
use solana_account::{
    create_account_shared_data_for_test, AccountSharedData, ReadableAccount, WritableAccount,
};
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_program_runtime::{
    declare_process_instruction,
    invoke_context::{mock_process_instruction, BuiltinFunctionWithContext},
    loaded_programs::ProgramCacheEntry,
};
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_sdk_ids::{native_loader, system_program, sysvar};
use std::sync::{Arc, LazyLock};

declare_process_instruction!(SlotAnchorsActive, 0, |invoke_context| {
    process_gated(invoke_context, true)
});
declare_process_instruction!(SlotAnchorsInactive, 0, |invoke_context| {
    process_gated(invoke_context, false)
});

#[derive(Clone, Copy, Debug)]
enum Program {
    /// The registered program: the feature as the runtime reports it.
    Registered,
    Active,
    Inactive,
}

impl Program {
    fn builtin(self) -> BuiltinFunctionWithContext {
        let registered: BuiltinFunctionWithContext = Entrypoint::vm;
        let active: BuiltinFunctionWithContext = SlotAnchorsActive::vm;
        let inactive: BuiltinFunctionWithContext = SlotAnchorsInactive::vm;
        match self {
            Program::Registered => registered,
            Program::Active => active,
            Program::Inactive => inactive,
        }
    }
}

pub(super) type Accounts = Vec<(Pubkey, AccountSharedData)>;

pub(super) const SPONSOR: Pubkey = Pubkey::new_from_array([83; 32]);
/// The latest expiry a payment first accepted in slot 1 may carry.
const EXPIRES_AT: u64 = 1025;

/// Three real payments that follow one another: a deposit of 100 into the
/// empty tree, a private payment that spends it, and a withdrawal of 40 that
/// spends an output of the private payment.
pub(super) struct Payments {
    pub(super) deposit: Vec<u8>,
    pub(super) payment: Vec<u8>,
    pub(super) withdrawal: Vec<u8>,
}

pub(super) static PAYMENTS: LazyLock<Payments> = LazyLock::new(|| {
    let fixture =
        build_fixture_for_network(SPONSOR.to_bytes(), FIXTURE_GENESIS, 1, EXPIRES_AT).unwrap();
    let (withdrawal, context) = withdrawal_fixture(&fixture).unwrap();
    Payments {
        deposit: wire::encode(FIXTURE_GENESIS, &fixture.funding_context, &fixture.funding).unwrap(),
        payment: wire::encode(FIXTURE_GENESIS, &fixture.context, &fixture.bundle).unwrap(),
        withdrawal: wire::encode(FIXTURE_GENESIS, &context, &withdrawal).unwrap(),
    }
});

fn anchor(bytes: &[u8]) -> [u8; 32] {
    wire::decode(FIXTURE_GENESIS, bytes)
        .unwrap()
        .bundle
        .anchor()
        .to_bytes()
}

fn execute(
    accounts: &mut Accounts,
    program: Program,
    instruction: Instruction,
    result: Result<(), InstructionError>,
) {
    let output = mock_process_instruction(
        &id(),
        None,
        &instruction.data,
        accounts.clone(),
        instruction.accounts,
        result,
        program.builtin(),
        |context| {
            context.mock_set_remaining(1_400_000);
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

fn clock(slot: u64) -> AccountSharedData {
    create_account_shared_data_for_test(&solana_clock::Clock {
        slot,
        ..Default::default()
    })
}

pub(super) fn setup(slot_anchored: bool, slot: u64) -> Accounts {
    let rent = Rent::default();
    let bytes = if slot_anchored {
        SLOT_STATE_BYTES
    } else {
        STATE_BYTES
    };
    let floor = rent.minimum_balance(bytes);
    let state = if slot_anchored {
        PoolState::new_slot_anchored(FIXTURE_GENESIS, floor).unwrap()
    } else {
        PoolState::new(FIXTURE_GENESIS, floor).unwrap()
    };
    let mut pool = AccountSharedData::new(floor, bytes, &id());
    pool.set_data_from_slice(&state.encode());
    let mut system = AccountSharedData::new(1, 0, &native_loader::id());
    system.set_executable(true);
    vec![
        (
            sysvar::rent::id(),
            create_account_shared_data_for_test(&rent),
        ),
        (pool_address(), pool),
        (
            SPONSOR,
            AccountSharedData::new(10_000_000_000, 0, &system_program::id()),
        ),
        (system_program::id(), system),
        (sysvar::clock::id(), clock(slot)),
    ]
}

pub(super) fn account_mut(accounts: &mut Accounts, key: Pubkey) -> &mut AccountSharedData {
    &mut accounts.iter_mut().find(|(k, _)| *k == key).unwrap().1
}
pub(super) fn account(accounts: &Accounts, key: Pubkey) -> &AccountSharedData {
    &accounts.iter().find(|(k, _)| *k == key).unwrap().1
}
fn pool(accounts: &Accounts) -> PoolState {
    PoolState::decode(account(accounts, pool_address()).data()).unwrap()
}

fn set_slot(accounts: &mut Accounts, slot: u64) {
    *account_mut(accounts, sysvar::clock::id()) = clock(slot);
}

fn slot(accounts: &Accounts) -> u64 {
    account(accounts, sysvar::clock::id())
        .deserialize_data::<solana_clock::Clock>()
        .unwrap()
        .slot
}

/// Test stand-in for the runtime's end-of-slot step: records `slot` as
/// completed in the pool account, with the tree the slot's transactions left.
fn complete_slot_stand_in(accounts: &mut Accounts, slot: u64) {
    let pool = account_mut(accounts, pool_address());
    let mut state = PoolState::decode(pool.data()).unwrap();
    state.complete_slot(slot).unwrap();
    pool.set_data_from_slice(&state.encode());
}

pub(super) fn nullifiers_of(bytes: &[u8]) -> [[u8; 32]; 2] {
    let payment = wire::decode(FIXTURE_GENESIS, bytes).unwrap();
    std::array::from_fn(|index| {
        payment
            .bundle
            .actions()
            .get(index)
            .unwrap()
            .nullifier()
            .to_bytes()
    })
}

/// Stage `bytes` in the current slot and return the finalize instruction.
/// The staging instructions do not read the pool or the feature.
pub(super) fn stage(accounts: &mut Accounts, bytes: &[u8], seed: u8) -> Instruction {
    for nullifier in nullifiers_of(bytes) {
        let address = nullifiers::address(&nullifier);
        if !accounts.iter().any(|(key, _)| *key == address) {
            accounts.push((address, AccountSharedData::default()));
        }
    }
    let key = Pubkey::new_from_array([seed; 32]);
    accounts.push((
        key,
        AccountSharedData::new(
            Rent::default().minimum_balance(ACCOUNT_BYTES),
            ACCOUNT_BYTES,
            &id(),
        ),
    ));
    let expiry = slot(accounts) + 100;
    execute(
        accounts,
        Program::Registered,
        instructions::initialize(
            key,
            SPONSOR,
            bytes.len() as u32,
            payload_digest(bytes),
            expiry,
        ),
        Ok(()),
    );
    for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
        execute(
            accounts,
            Program::Registered,
            instructions::write(key, SPONSOR, (index * MAX_CHUNK_BYTES) as u32, chunk),
            Ok(()),
        );
    }
    execute(
        accounts,
        Program::Registered,
        instructions::seal(key, SPONSOR),
        Ok(()),
    );
    instructions::finalize(key, SPONSOR, nullifiers_of(bytes))
}

/// The instruction is refused with `error` and changes no account.
fn refused(
    accounts: &Accounts,
    program: Program,
    instruction: &Instruction,
    error: InstructionError,
) {
    let mut attempt = accounts.clone();
    execute(&mut attempt, program, instruction.clone(), Err(error));
    assert_eq!(&attempt, accounts, "{program:?}");
}

#[test]
fn inactive_feature_refuses_a_slot_anchored_pool_and_nothing_else_changes() {
    let payments = &*PAYMENTS;
    let mut accounts = setup(true, 1);
    let deposit = stage(&mut accounts, &payments.deposit, 91);
    // The registered program on this runtime, and the program told that the
    // feature is inactive, refuse the pool itself, whatever the payment.
    for program in [Program::Registered, Program::Inactive] {
        refused(
            &accounts,
            program,
            &deposit,
            InstructionError::InvalidAccountData,
        );
    }
    // The refusal comes straight after the pool decodes, before its balance
    // is looked at: an underfunded pool is still refused as account data.
    let mut underfunded = accounts.clone();
    let lamports = account(&underfunded, pool_address()).lamports();
    account_mut(&mut underfunded, pool_address()).set_lamports(lamports - 1);
    refused(
        &underfunded,
        Program::Inactive,
        &deposit,
        InstructionError::InvalidAccountData,
    );
    refused(
        &underfunded,
        Program::Active,
        &deposit,
        InstructionError::InsufficientFunds,
    );
    // It does not come before the checks that precede decoding.
    let mut foreign = accounts.clone();
    account_mut(&mut foreign, pool_address()).set_owner(system_program::id());
    for program in [Program::Inactive, Program::Active] {
        refused(
            &foreign,
            program,
            &deposit,
            InstructionError::InvalidAccountOwner,
        );
    }
    // The same staged payment is accepted once the feature is active.
    execute(&mut accounts, Program::Active, deposit, Ok(()));
    assert_eq!(pool(&accounts).note_count(), 2);
}

#[test]
fn legacy_pool_gives_the_same_bytes_whatever_the_feature() {
    let payments = &*PAYMENTS;
    let mut results = Vec::new();
    for program in [Program::Registered, Program::Inactive, Program::Active] {
        let mut accounts = setup(false, 1);
        // NPOOL003 accepts the newest root at once: all three payments fit
        // into one slot, and no slot is ever completed.
        for (seed, bytes) in [
            (91, &payments.deposit),
            (92, &payments.payment),
            (93, &payments.withdrawal),
        ] {
            let instruction = stage(&mut accounts, bytes, seed);
            execute(&mut accounts, program, instruction, Ok(()));
        }
        let state = pool(&accounts);
        assert!(!state.uses_slot_anchors());
        assert_eq!(account(&accounts, pool_address()).data().len(), STATE_BYTES);
        assert_eq!(&account(&accounts, pool_address()).data()[..8], b"NPOOL003");
        assert_eq!((state.note_count(), state.backing), (6, 60));
        results.push(accounts);
    }
    assert_eq!(results[0], results[1]);
    assert_eq!(results[0], results[2]);
}

#[test]
fn active_feature_accepts_only_roots_of_completed_earlier_slots() {
    let payments = &*PAYMENTS;
    let program = Program::Active;
    let invalid = InstructionError::InvalidInstructionData;
    let mut accounts = setup(true, 1);
    let initial = account(&accounts, SPONSOR).lamports();
    let marker_rent = Rent::default().minimum_balance(nullifiers::MARKER_BYTES);

    // Slot 1. The deposit names the root of the empty tree, which needs no
    // checkpoint in the first 512 slots.
    let deposit = stage(&mut accounts, &payments.deposit, 91);
    execute(&mut accounts, program, deposit, Ok(()));
    let after_deposit = pool(&accounts);
    assert!(after_deposit.uses_slot_anchors());
    assert_eq!(
        account(&accounts, pool_address()).data().len(),
        SLOT_STATE_BYTES
    );
    assert_eq!(
        (after_deposit.note_count(), after_deposit.backing),
        (2, 100)
    );
    // The program records no checkpoint and keeps no per-payment roots.
    assert!(after_deposit.slot_anchors().unwrap().entries().is_empty());
    assert!(after_deposit.roots().is_empty());
    assert_eq!(anchor(&payments.payment), after_deposit.root());

    // Still slot 1. The private payment names the tree the deposit left,
    // which belongs to the executing slot.
    let payment = stage(&mut accounts, &payments.payment, 92);
    refused(&accounts, program, &payment, invalid.clone());
    // Recording slot 1 does not make its root usable inside slot 1.
    complete_slot_stand_in(&mut accounts, 1);
    assert_eq!(
        pool(&accounts).slot_anchors().unwrap().entries()[0].root,
        anchor(&payments.payment)
    );
    refused(&accounts, program, &payment, invalid.clone());

    // Slot 2. The root of completed slot 1 is accepted.
    set_slot(&mut accounts, 2);
    execute(&mut accounts, program, payment, Ok(()));
    assert_eq!(pool(&accounts).note_count(), 4);
    assert_eq!(pool(&accounts).slot_anchors().unwrap().entries().len(), 1);

    // The withdrawal names the tree of slot 2: refused in slot 2, accepted
    // in slot 3 once slot 2 is completed.
    let withdrawal = stage(&mut accounts, &payments.withdrawal, 93);
    refused(&accounts, program, &withdrawal, invalid.clone());
    complete_slot_stand_in(&mut accounts, 2);
    set_slot(&mut accounts, 3);
    execute(&mut accounts, program, withdrawal, Ok(()));

    let state = pool(&accounts);
    assert_eq!((state.note_count(), state.backing), (6, 60));
    assert_eq!(
        account(&accounts, pool_address()).lamports(),
        state.rent_floor + 60
    );
    assert_eq!(
        account(&accounts, SPONSOR).lamports(),
        initial - 100 + 40 - 6 * marker_rent
    );

    // The same three payments leave the same tree in a legacy pool.
    let mut legacy = setup(false, 1);
    for (seed, bytes) in [
        (91, &payments.deposit),
        (92, &payments.payment),
        (93, &payments.withdrawal),
    ] {
        let instruction = stage(&mut legacy, bytes, seed);
        execute(&mut legacy, program, instruction, Ok(()));
    }
    assert_eq!(pool(&legacy).root(), state.root());
    assert_eq!(
        account(&legacy, SPONSOR).lamports(),
        account(&accounts, SPONSOR).lamports()
    );

    // A spent note stays spent: the deposit's markers are permanent.
    let again = stage(&mut accounts, &payments.deposit, 94);
    refused(&accounts, program, &again, invalid);
}

#[test]
fn root_expires_after_511_slots_and_a_repeated_checkpoint_renews_it() {
    let payments = &*PAYMENTS;
    let program = Program::Active;
    let invalid = InstructionError::InvalidInstructionData;
    let mut accounts = setup(true, 1);
    let deposit = stage(&mut accounts, &payments.deposit, 91);
    execute(&mut accounts, program, deposit, Ok(()));
    complete_slot_stand_in(&mut accounts, 1);

    // Age 511: the last slot in which the root of slot 1 is accepted.
    let mut last = accounts.clone();
    set_slot(&mut last, 512);
    let payment = stage(&mut last, &payments.payment, 92);
    execute(&mut last, program, payment, Ok(()));
    assert_eq!(pool(&last).note_count(), 4);

    // Age 512: expired, although the payment itself has not expired.
    set_slot(&mut accounts, 513);
    let payment = stage(&mut accounts, &payments.payment, 92);
    refused(&accounts, program, &payment, invalid.clone());

    // A block without payments repeats the root. Its checkpoint replaces the
    // expired one and is usable from the next slot.
    complete_slot_stand_in(&mut accounts, 513);
    let entries = pool(&accounts).slot_anchors().unwrap().entries().to_vec();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        (entries[0].slot, entries[0].note_count, entries[0].root),
        (513, 2, anchor(&payments.payment))
    );
    refused(&accounts, program, &payment, invalid);
    set_slot(&mut accounts, 514);
    execute(&mut accounts, program, payment, Ok(()));
    assert_eq!(pool(&accounts).note_count(), 4);
}

#[test]
fn empty_tree_root_needs_a_checkpoint_from_slot_512_on() {
    let payments = &*PAYMENTS;
    let program = Program::Active;
    assert_eq!(anchor(&payments.deposit), Anchor::empty_tree().to_bytes());

    let mut early = setup(true, 511);
    let deposit = stage(&mut early, &payments.deposit, 91);
    execute(&mut early, program, deposit, Ok(()));

    let mut late = setup(true, 512);
    let deposit = stage(&mut late, &payments.deposit, 91);
    refused(
        &late,
        program,
        &deposit,
        InstructionError::InvalidInstructionData,
    );
    // An empty block in slot 511 records the root of the empty tree.
    complete_slot_stand_in(&mut late, 511);
    execute(&mut late, program, deposit, Ok(()));
    assert_eq!(pool(&late).note_count(), 2);
}

#[test]
fn checkpoint_of_a_later_slot_is_refused_as_account_data() {
    let payments = &*PAYMENTS;
    let mut accounts = setup(true, 5);
    let deposit = stage(&mut accounts, &payments.deposit, 91);
    complete_slot_stand_in(&mut accounts, 10);
    // A pool that holds a checkpoint of slot 10 cannot be executing slot 5.
    refused(
        &accounts,
        Program::Active,
        &deposit,
        InstructionError::InvalidAccountData,
    );
    set_slot(&mut accounts, 10);
    execute(&mut accounts, Program::Active, deposit, Ok(()));
}

#[test]
fn inline_instruction_reads_the_same_feature() {
    // Opcode 5 shares the finalizer. The bytes after the opcode are not an
    // envelope, so the instruction is refused either way; the error tells
    // whether the pool was let through to the envelope check.
    let markers = [[61; 32], [62; 32]].map(Pubkey::new_from_array);
    let instruction = Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(pool_address(), false),
            AccountMeta::new(SPONSOR, true),
            AccountMeta::new_readonly(system_program::id(), false),
            AccountMeta::new(markers[0], false),
            AccountMeta::new(markers[1], false),
        ],
        data: vec![5, 0, 0, 0],
    };
    for (slot_anchored, program, error) in [
        (
            true,
            Program::Registered,
            InstructionError::InvalidAccountData,
        ),
        (
            true,
            Program::Inactive,
            InstructionError::InvalidAccountData,
        ),
        (
            true,
            Program::Active,
            InstructionError::InvalidInstructionData,
        ),
        (
            false,
            Program::Registered,
            InstructionError::InvalidInstructionData,
        ),
        (
            false,
            Program::Inactive,
            InstructionError::InvalidInstructionData,
        ),
        (
            false,
            Program::Active,
            InstructionError::InvalidInstructionData,
        ),
    ] {
        let mut accounts = setup(slot_anchored, 1);
        for marker in markers {
            accounts.push((marker, AccountSharedData::default()));
        }
        refused(&accounts, program, &instruction, error);
    }
}

#[test]
fn staged_account_of_the_fixture_is_consumed_once() {
    // Guards the helpers above: a finalized staging account cannot be reused,
    // so every acceptance in this file is of a freshly staged payment.
    let payments = &*PAYMENTS;
    let mut accounts = setup(true, 1);
    let deposit = stage(&mut accounts, &payments.deposit, 91);
    execute(&mut accounts, Program::Active, deposit.clone(), Ok(()));
    let buffer = deposit.accounts[1].pubkey;
    assert!(Buffer::decode(account(&accounts, buffer).data())
        .unwrap()
        .payload()
        .is_err());
    refused(
        &accounts,
        Program::Active,
        &deposit,
        InstructionError::InvalidAccountData,
    );
}
