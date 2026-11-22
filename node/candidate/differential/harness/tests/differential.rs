//! The comparison test of node/candidate/differential. It is not a member of
//! the workspace and is built only in the scratch workspace that assemble.py
//! writes; see the README beside it.
//!
//! Runs three builds of the native program on the same accounts, instruction
//! bytes, slot, compute budget and feature switches, inside the mock invocation
//! context of the vendored Agave 3.0.14 runtime, and requires the same result,
//! the same bytes of every account and the same number of compute units left
//! after each instruction:
//!
//! - `workspace_program`: the repository's node/adapter/src, verbatim except
//!   the body of `slot_anchors` in processor/runtime_features.rs, which reads
//!   the harness's switch;
//! - `candidate_program`: the candidate's zolana-native/adapter/src from the
//!   pinned patch chain, verbatim except the runtime call sites that
//!   assemble.py lists, linked against the candidate's own protocol copy;
//! - `registered_program`: the repository's crate itself, compared whenever
//!   the switch is off (it has no way to turn it on).
//!
//! The end of a slot is a stand-in on both sides: the body of the candidate's
//! `seal_native_payment_slot` transcribed against the candidate's protocol
//! copy, and the same steps against the workspace's protocol crate.

use candidate_payments::state::PoolState as CandidatePool;
use native_payments::{
    staging::{payload_digest, MAX_CHUNK_BYTES},
    state::{PoolState, SLOT_STATE_BYTES, STATE_BYTES},
    wire,
};
use payment_lab::proof_smoke::{
    build_fixture_for_network, withdrawal_fixture, DepositProver, FIXTURE_GENESIS,
};
use solana_account::{
    create_account_shared_data_for_test, AccountSharedData, ReadableAccount, WritableAccount,
};
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_program_runtime::{
    invoke_context::BuiltinFunctionWithContext,
    loaded_programs::ProgramCacheEntry,
    solana_sbpf::vm::ContextObject,
    with_mock_invoke_context_with_feature_set,
};
use solana_pubkey::Pubkey;
use solana_rent::Rent;
use solana_sdk_ids::{native_loader, system_program, sysvar};
use solana_svm_feature_set::SVMFeatureSet;
use solana_svm_timings::ExecuteTimings;
use solana_transaction_context::{IndexOfAccount, InstructionAccount};
use std::{cell::Cell, collections::BTreeMap, sync::Arc};
use workspace_program::{id, instructions, nullifiers, pool_address, staging::ACCOUNT_BYTES};

type Accounts = Vec<(Pubkey, AccountSharedData)>;
type Outcome = (Result<(), InstructionError>, Vec<AccountSharedData>);

thread_local! {
    /// Compute units left by the last `run` on this thread.
    static REMAINING: Cell<u64> = const { Cell::new(0) };
}

fn remaining() -> u64 {
    REMAINING.with(Cell::get)
}

const SPONSOR: Pubkey = Pubkey::new_from_array([83; 32]);

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
    fn chance(&mut self, numerator: u64, denominator: u64) -> bool {
        self.below(denominator) < numerator
    }
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

fn run(
    builtin: BuiltinFunctionWithContext,
    accounts: &Accounts,
    instruction: &Instruction,
    budget: u64,
    features: &SVMFeatureSet,
) -> Outcome {
    let mut transaction_accounts = accounts.clone();
    let mut instruction_accounts = Vec::with_capacity(instruction.accounts.len());
    for meta in &instruction.accounts {
        let index = transaction_accounts
            .iter()
            .position(|(key, _)| *key == meta.pubkey)
            .expect("every instruction account is a transaction account")
            as IndexOfAccount;
        instruction_accounts.push(InstructionAccount::new(
            index,
            meta.is_signer,
            meta.is_writable,
        ));
    }
    transaction_accounts.push((id(), AccountSharedData::new(0, 0, &native_loader::id())));
    let program_index = (transaction_accounts.len() - 1) as IndexOfAccount;
    with_mock_invoke_context_with_feature_set!(
        invoke_context,
        transaction_context,
        features,
        transaction_accounts
    );
    let mut cache = ProgramCacheForTxBatch::default();
    cache.replenish(id(), Arc::new(ProgramCacheEntry::new_builtin(0, 0, builtin)));
    cache.replenish(
        system_program::id(),
        Arc::new(ProgramCacheEntry::new_builtin(
            0,
            0,
            solana_system_program::system_processor::Entrypoint::vm,
        )),
    );
    invoke_context.program_cache_for_tx_batch = &mut cache;
    invoke_context.mock_set_remaining(budget);
    invoke_context
        .transaction_context
        .configure_next_instruction_for_tests(program_index, instruction_accounts, &instruction.data)
        .unwrap();
    let result = invoke_context.process_instruction(&mut 0, &mut ExecuteTimings::default());
    REMAINING.with(|cell| cell.set(invoke_context.get_remaining()));
    let mut output = transaction_context.deconstruct_without_keys().unwrap();
    output.pop();
    (result, output)
}

#[derive(Default)]
struct Tally {
    cases: u64,
    with_registered: u64,
    by_kind: BTreeMap<String, u64>,
    seals: BTreeMap<String, u64>,
    /// Pool accounts that only the workspace's decoder refuses: the two
    /// rules of the pool-state hardening, when the candidate copy lacks them.
    hardening_only: u64,
}

/// Whether the two protocol copies disagree on decoding this pool account.
/// The only disagreement allowed is the workspace refusing what the candidate
/// copy accepts, which is what the pool-state hardening adds.
fn decoders_disagree(pool: &AccountSharedData) -> bool {
    let ours = PoolState::decode(pool.data()).is_ok();
    let theirs = CandidatePool::decode(pool.data()).is_ok();
    assert!(ours == theirs || (!ours && theirs), "the candidate copy refuses a pool the workspace accepts");
    ours != theirs
}

struct Case<'a> {
    accounts: &'a Accounts,
    instruction: &'a Instruction,
    gate: bool,
    budget: u64,
    features: &'a SVMFeatureSet,
    label: &'a str,
}

/// One instruction through every build. Panics on any difference.
fn compare(case: &Case, tally: &mut Tally) -> Outcome {
    differential_gate::set(case.gate);
    let workspace: BuiltinFunctionWithContext = workspace_program::Entrypoint::vm;
    let candidate: BuiltinFunctionWithContext = candidate_program::Entrypoint::vm;
    let registered: BuiltinFunctionWithContext = registered_program::Entrypoint::vm;
    let ours = run(workspace, case.accounts, case.instruction, case.budget, case.features);
    let units = remaining();
    if case.accounts.iter().any(|(key, pool)| *key == pool_address() && decoders_disagree(pool)) {
        tally.hardening_only += 1;
        return ours;
    }
    let theirs = run(candidate, case.accounts, case.instruction, case.budget, case.features);
    assert_eq!(ours.0, theirs.0, "result differs: {}", case.label);
    for (index, (a, b)) in ours.1.iter().zip(&theirs.1).enumerate() {
        assert_eq!(a, b, "account {index} differs: {}", case.label);
    }
    assert_eq!(ours.1.len(), theirs.1.len());
    assert_eq!(units, remaining(), "units left differ: {}", case.label);
    if !case.gate {
        let real = run(registered, case.accounts, case.instruction, case.budget, case.features);
        assert_eq!(ours, real, "registered program differs: {}", case.label);
        assert_eq!(units, remaining(), "units left differ in the registered program: {}", case.label);
        tally.with_registered += 1;
    }
    tally.cases += 1;
    let format = match case.accounts.iter().find(|(key, _)| *key == pool_address()) {
        Some((_, pool)) if pool.data().starts_with(b"NPOOL004") => "NPOOL004",
        Some((_, pool)) if pool.data().starts_with(b"NPOOL003") => "NPOOL003",
        _ => "other pool",
    };
    let result = match &ours.0 {
        Ok(()) => "accepted".to_string(),
        Err(error) => format!("{error:?}"),
    };
    let gate = if case.gate { "on" } else { "off" };
    *tally
        .by_kind
        .entry(format!("{format} | feature {gate} | {} | {result}", case.label))
        .or_default() += 1;
    ours
}

fn apply(accounts: &mut Accounts, outcome: Outcome) {
    for ((_, account), next) in accounts.iter_mut().zip(outcome.1) {
        *account = next;
    }
}

fn clock(slot: u64) -> AccountSharedData {
    create_account_shared_data_for_test(&solana_clock::Clock {
        slot,
        ..Default::default()
    })
}

fn setup(slot_anchored: bool, slot: u64) -> Accounts {
    let rent = Rent::default();
    let bytes = if slot_anchored { SLOT_STATE_BYTES } else { STATE_BYTES };
    let floor = rent.minimum_balance(bytes);
    let state = if slot_anchored {
        PoolState::new_slot_anchored(FIXTURE_GENESIS, floor).unwrap()
    } else {
        PoolState::new(FIXTURE_GENESIS, floor).unwrap()
    };
    let candidate = if slot_anchored {
        CandidatePool::new_slot_anchored(FIXTURE_GENESIS, floor).unwrap()
    } else {
        CandidatePool::new(FIXTURE_GENESIS, floor).unwrap()
    };
    assert_eq!(state.encode(), candidate.encode());
    let mut pool = AccountSharedData::new(floor, bytes, &id());
    pool.set_data_from_slice(&state.encode());
    let mut system = AccountSharedData::new(1, 0, &native_loader::id());
    system.set_executable(true);
    vec![
        (sysvar::rent::id(), create_account_shared_data_for_test(&rent)),
        (pool_address(), pool),
        (SPONSOR, AccountSharedData::new(10_000_000_000, 0, &system_program::id())),
        (system_program::id(), system),
        (sysvar::clock::id(), clock(slot)),
        // A spare ordinary account, for cases that pass a seventh account.
        (Pubkey::new_from_array([84; 32]), AccountSharedData::new(1_000_000, 0, &system_program::id())),
    ]
}

fn account_mut(accounts: &mut Accounts, key: Pubkey) -> &mut AccountSharedData {
    &mut accounts.iter_mut().find(|(k, _)| *k == key).unwrap().1
}
fn account(accounts: &Accounts, key: Pubkey) -> &AccountSharedData {
    &accounts.iter().find(|(k, _)| *k == key).unwrap().1
}

/// The candidate's end-of-slot step: the body of `seal_native_payment_slot`
/// with the Bank's account replaced by the one in hand and each `expect`
/// replaced by a returned error.
fn candidate_seal(pool: &mut AccountSharedData, slot: u64, feature: bool) -> Result<(), String> {
    if !feature {
        return Ok(());
    }
    if pool.owner() != &candidate_program::id() {
        return Ok(());
    }
    let state = CandidatePool::decode(pool.data()).map_err(|error| format!("decode {error:?}"))?;
    if !state.uses_slot_anchors() {
        return Ok(());
    }
    let completed = state
        .with_completed_slot(slot)
        .map_err(|error| format!("checkpoint {error:?}"))?;
    pool.set_data_from_slice(&completed.encode());
    Ok(())
}

/// The same steps on the workspace's protocol crate, completing in place.
fn workspace_seal(pool: &mut AccountSharedData, slot: u64, feature: bool) -> Result<(), String> {
    if !feature {
        return Ok(());
    }
    if pool.owner() != &id() {
        return Ok(());
    }
    let mut state = PoolState::decode(pool.data()).map_err(|error| format!("decode {error:?}"))?;
    if !state.uses_slot_anchors() {
        return Ok(());
    }
    state
        .complete_slot(slot)
        .map_err(|error| format!("checkpoint {error:?}"))?;
    pool.set_data_from_slice(&state.encode());
    Ok(())
}

/// Both stand-ins on the pool account. Returns whether the slot was recorded.
fn seal(accounts: &mut Accounts, slot: u64, feature: bool, tally: &mut Tally) -> bool {
    let before = account(accounts, pool_address()).clone();
    if decoders_disagree(&before) {
        tally.hardening_only += 1;
        return false;
    }
    let mut ours = before.clone();
    let mut theirs = before.clone();
    let a = workspace_seal(&mut ours, slot, feature);
    let b = candidate_seal(&mut theirs, slot, feature);
    assert_eq!(a, b, "end-of-slot result differs at slot {slot}");
    assert_eq!(ours, theirs, "end-of-slot bytes differ at slot {slot}");
    let kind = match &a {
        Ok(()) if ours == before => "left unchanged".to_string(),
        Ok(()) => "recorded".to_string(),
        Err(error) => {
            assert_eq!(ours, before);
            format!("refused ({error})")
        }
    };
    *tally.seals.entry(kind).or_default() += 1;
    let recorded = a.is_ok();
    *account_mut(accounts, pool_address()) = ours;
    recorded
}

struct Payment {
    name: &'static str,
    bytes: Vec<u8>,
}

fn nullifiers_of(bytes: &[u8]) -> [[u8; 32]; 2] {
    let payment = wire::decode(FIXTURE_GENESIS, bytes).unwrap();
    std::array::from_fn(|index| payment.bundle.actions().get(index).unwrap().nullifier().to_bytes())
}

fn encode(
    context: &native_payments::verification::AuthorizationContext,
    bundle: &orchard::Bundle<orchard::bundle::Authorized, i64>,
) -> Vec<u8> {
    wire::encode(FIXTURE_GENESIS, context, bundle).unwrap()
}

fn payments() -> Vec<Payment> {
    let fixture = build_fixture_for_network(SPONSOR.to_bytes(), FIXTURE_GENESIS, 1, 1025).unwrap();
    let (withdrawal, withdrawal_context) = withdrawal_fixture(&fixture).unwrap();
    let empty = *fixture.funding.anchor();
    let after_deposit = *fixture.bundle.anchor();
    let after_payment = *withdrawal.anchor();
    // A canonical field element that is the root of no tree in these runs.
    let foreign = fixture.bundle.actions().get(0).unwrap().cmx().to_bytes();
    let prover = DepositProver::default();
    let mut list = vec![
        Payment { name: "deposit, empty root", bytes: encode(&fixture.funding_context, &fixture.funding) },
        Payment { name: "payment, root after deposit", bytes: encode(&fixture.context, &fixture.bundle) },
        Payment { name: "withdrawal, root after payment", bytes: encode(&withdrawal_context, &withdrawal) },
    ];
    for (name, anchor, amount, expires_at) in [
        ("second deposit, empty root", empty.to_bytes(), 7, 1025),
        ("second deposit, root after deposit", after_deposit.to_bytes(), 5, 1025),
        ("second deposit, root after payment", after_payment.to_bytes(), 3, 1025),
        ("second deposit, foreign root", foreign, 2, 1025),
        ("late deposit, root after deposit", after_deposit.to_bytes(), 11, 2000),
        ("late deposit, empty root", empty.to_bytes(), 13, 2000),
    ] {
        let (bundle, context) = prover
            .build(SPONSOR.to_bytes(), FIXTURE_GENESIS, expires_at, anchor, amount)
            .unwrap();
        list.push(Payment { name, bytes: encode(&context, &bundle) });
    }
    list
}

struct Walk<'a> {
    accounts: Accounts,
    slot: u64,
    gate: bool,
    features: SVMFeatureSet,
    next_buffer: u16,
    tally: &'a mut Tally,
}

impl Walk<'_> {
    fn case(&mut self, instruction: &Instruction, label: &str, budget: u64) -> Outcome {
        compare(
            &Case { accounts: &self.accounts, instruction, gate: self.gate, budget, features: &self.features, label },
            self.tally,
        )
    }

    fn set_slot(&mut self, slot: u64) {
        self.slot = slot;
        *account_mut(&mut self.accounts, sysvar::clock::id()) = clock(slot);
    }

    /// Stage through every build; `None` when staging is refused.
    fn stage(&mut self, bytes: &[u8], expiry: u64) -> Option<Instruction> {
        for nullifier in nullifiers_of(bytes) {
            let address = nullifiers::address(&nullifier);
            assert_eq!(address, candidate_program::nullifiers::address(&nullifier));
            if !self.accounts.iter().any(|(key, _)| *key == address) {
                self.accounts.push((address, AccountSharedData::default()));
            }
        }
        self.next_buffer += 1;
        let mut seed = [200u8; 32];
        seed[..2].copy_from_slice(&self.next_buffer.to_le_bytes());
        let key = Pubkey::new_from_array(seed);
        self.accounts.push((
            key,
            AccountSharedData::new(Rent::default().minimum_balance(ACCOUNT_BYTES), ACCOUNT_BYTES, &id()),
        ));
        let initialize = instructions::initialize(key, SPONSOR, bytes.len() as u32, payload_digest(bytes), expiry);
        assert_eq!(
            initialize.data,
            candidate_program::instructions::initialize(key, SPONSOR, bytes.len() as u32, payload_digest(bytes), expiry).data
        );
        let outcome = self.case(&initialize, "initialize", 1_400_000);
        let accepted = outcome.0.is_ok();
        apply(&mut self.accounts, outcome);
        if !accepted {
            return None;
        }
        for (index, chunk) in bytes.chunks(MAX_CHUNK_BYTES).enumerate() {
            let write = instructions::write(key, SPONSOR, (index * MAX_CHUNK_BYTES) as u32, chunk);
            let outcome = self.case(&write, "write", 1_400_000);
            assert!(outcome.0.is_ok());
            apply(&mut self.accounts, outcome);
        }
        let outcome = self.case(&instructions::seal(key, SPONSOR), "seal", 1_400_000);
        assert!(outcome.0.is_ok());
        apply(&mut self.accounts, outcome);
        let finalize = instructions::finalize(key, SPONSOR, nullifiers_of(bytes));
        let theirs = candidate_program::instructions::finalize(key, SPONSOR, nullifiers_of(bytes));
        assert_eq!((&finalize.data, &finalize.accounts), (&theirs.data, &theirs.accounts));
        Some(finalize)
    }

    /// Finalize unchanged; the accounts move on to whatever every build left.
    fn finalize(&mut self, instruction: &Instruction) -> bool {
        let outcome = self.case(instruction, "finalize", 1_400_000);
        let accepted = outcome.0.is_ok();
        if accepted {
            apply(&mut self.accounts, outcome);
        } else {
            let unchanged: Vec<_> = self.accounts.iter().map(|(_, account)| account.clone()).collect();
            assert_eq!(outcome.1, unchanged, "a refused finalization changed an account");
        }
        accepted
    }

    /// One altered copy of the case; never carried into the walk.
    fn mutated(&mut self, instruction: &Instruction, rng: &mut Rng) {
        let saved = self.accounts.clone();
        let saved_slot = self.slot;
        let mut instruction = instruction.clone();
        let mut budget = 1_400_000;
        let buffer = instruction.accounts[1].pubkey;
        let marker = instruction.accounts[4].pubkey;
        let label = match rng.below(20) {
            0 | 1 => {
                let pool = account_mut(&mut self.accounts, pool_address());
                let length = pool.data().len() as u64;
                let range = if rng.chance(1, 2) { 1200.min(length) } else { length };
                let at = rng.below(range) as usize;
                pool.data_as_mut_slice()[at] ^= 1 << rng.below(8);
                "finalize, one pool bit flipped"
            }
            2 => {
                let pool = account_mut(&mut self.accounts, pool_address());
                let slot_anchored = pool.data().starts_with(b"NPOOL004");
                let other = setup(!slot_anchored, 0);
                let fresh = account(&other, pool_address()).clone();
                *pool = fresh;
                "finalize, pool replaced by a fresh one of the other format"
            }
            3 => {
                let pool = account_mut(&mut self.accounts, pool_address());
                let lamports = pool.lamports();
                pool.set_lamports(rng.pick(&[0, lamports - 1, lamports + 1]));
                "finalize, pool balance altered"
            }
            4 => {
                account_mut(&mut self.accounts, pool_address()).set_owner(system_program::id());
                "finalize, pool owned by the System program"
            }
            5 | 6 | 7 => {
                let staged = account_mut(&mut self.accounts, buffer);
                let length = staged.data().len() as u64;
                // The payload is at the front of the account after its header.
                let range = if rng.chance(3, 4) { 96 + 9000.min(length - 96) } else { length };
                let at = rng.below(range) as usize;
                staged.data_as_mut_slice()[at] ^= 1 << rng.below(8);
                "finalize, one staged bit flipped"
            }
            8 => {
                instruction.accounts[2].is_signer = false;
                "finalize, sponsor does not sign"
            }
            9 => {
                account_mut(&mut self.accounts, SPONSOR).set_owner(id());
                "finalize, sponsor owned by the program"
            }
            10 => {
                let target = account_mut(&mut self.accounts, marker);
                target.set_owner(id());
                target.set_data_from_slice(&[9; 40]);
                target.set_lamports(1_000_000);
                "finalize, first marker already owned by the program"
            }
            11 => {
                account_mut(&mut self.accounts, marker).set_lamports(rng.pick(&[1, 500_000, 5_000_000]));
                "finalize, first marker funded beforehand"
            }
            12 => {
                instruction.accounts.swap(4, 5);
                "finalize, markers exchanged"
            }
            13 => {
                instruction.accounts[rng.pick(&[0usize, 1, 2, 4, 5])].is_writable = false;
                "finalize, one account read-only"
            }
            14 => {
                instruction.accounts.pop();
                "finalize, five accounts"
            }
            15 => {
                instruction.accounts.push(AccountMeta::new(Pubkey::new_from_array([84; 32]), false));
                "finalize, seven accounts"
            }
            16 => {
                instruction.data.push(rng.below(256) as u8);
                "finalize, trailing instruction byte"
            }
            17 => {
                instruction.data[0] = rng.pick(&[5u8, 6, 255]);
                instruction.accounts.remove(1);
                "other opcode with the inline account list"
            }
            18 => {
                budget = rng.pick(&[0, 9_999, 1_099_999, 1_100_000]);
                "finalize, small compute budget"
            }
            _ => {
                let slot = rng.pick(&[0, self.slot.saturating_sub(1), self.slot + 1, self.slot + 511, self.slot + 512, self.slot + 2000]);
                self.set_slot(slot);
                "finalize, another slot"
            }
        };
        let outcome = self.case(&instruction, label, budget);
        // A pool the case altered is also taken to the end of a slot.
        if label.contains("pool") {
            let mut altered = self.accounts.clone();
            apply(&mut altered, outcome);
            let slot = self.slot;
            let gate = self.gate;
            seal(&mut altered, slot, gate, self.tally);
        }
        self.accounts = saved;
        self.set_slot(saved_slot);
    }
}

fn walk(payments: &[Payment], rng: &mut Rng, tally: &mut Tally, steps: u64) {
    let slot_anchored = rng.chance(2, 3);
    let start = rng.pick(&[0u64, 1, 1, 1, 2, 300, 511, 512, 700, 980]);
    let features = SVMFeatureSet {
        native_inline_payments: rng.chance(1, 2),
        native_shielded_fees: rng.chance(1, 2),
        native_recipient_withdrawals: rng.chance(1, 2),
        ..SVMFeatureSet::all_enabled()
    };
    let mut walk = Walk {
        accounts: setup(slot_anchored, start),
        slot: start,
        gate: rng.chance(3, 4),
        features,
        next_buffer: 0,
        tally,
    };
    // Most walks follow the order in which the three linked payments can be
    // accepted; the rest pick freely.
    let mut script: Vec<usize> = if rng.chance(3, 4) { vec![2, 1, 0] } else { Vec::new() };
    for _ in 0..steps {
        match rng.below(20) {
            0..=8 => {
                let index = match script.pop() {
                    Some(index) if rng.chance(4, 5) => index,
                    Some(index) => {
                        script.push(index);
                        rng.below(payments.len() as u64) as usize
                    }
                    None => rng.below(payments.len() as u64) as usize,
                };
                let payment = &payments[index];
                let expiry = walk.slot + rng.pick(&[0u64, 1, 100, 100, 100, 1024, 1025]);
                let Some(instruction) = walk.stage(&payment.bytes, expiry) else {
                    if index < 3 {
                        script.push(index);
                    }
                    continue;
                };
                if rng.chance(2, 5) {
                    walk.mutated(&instruction, rng);
                }
                let accepted = walk.finalize(&instruction);
                let _ = payment.name;
                if !accepted && index < 3 && script.last() != Some(&index) {
                    script.push(index);
                }
            }
            9..=13 => {
                // A produced block ends: its slot is recorded, the next begins.
                let (slot, gate) = (walk.slot, walk.gate);
                seal(&mut walk.accounts, slot, gate, walk.tally);
                let step = if rng.chance(1, 6) { rng.pick(&[2u64, 100, 510, 511, 512, 513]) } else { 1 };
                walk.set_slot(slot + step);
            }
            14 | 15 => {
                // Slots without a block: nothing is recorded.
                let step = rng.pick(&[1u64, 1, 2, 7, 255, 510, 511, 512, 513]);
                walk.set_slot(walk.slot + step);
            }
            16 => {
                // Recording out of order is refused by both and changes nothing.
                let mut copy = walk.accounts.clone();
                let slot = rng.pick(&[walk.slot.saturating_sub(1), walk.slot.saturating_sub(600), 0]);
                let gate = walk.gate;
                seal(&mut copy, slot, gate, walk.tally);
            }
            17 => {
                // The feature becomes active. It is never switched off again.
                walk.gate = true;
            }
            18 => {
                // Close a staging account, or an account that is not one.
                let target = walk.accounts[rng.below(walk.accounts.len() as u64) as usize].0;
                if target != SPONSOR {
                    let outcome = walk.case(&instructions::close(target, SPONSOR), "close", 1_400_000);
                    if outcome.0.is_ok() {
                        apply(&mut walk.accounts, outcome);
                    }
                }
            }
            _ => {
                let mut instruction = instructions::close(pool_address(), SPONSOR);
                instruction.data = vec![rng.below(8) as u8; rng.below(4) as usize];
                let _ = walk.case(&instruction, "short or unknown instruction", 1_400_000);
            }
        }
    }
}

/// The edges of the rule, in a fixed order, with the expected decision stated.
fn edges(payments: &[Payment], tally: &mut Tally) {
    fn start(slot_anchored: bool, slot: u64, gate: bool, tally: &mut Tally) -> Walk<'_> {
        Walk {
            accounts: setup(slot_anchored, slot),
            slot,
            gate,
            features: SVMFeatureSet::all_enabled(),
            next_buffer: 0,
            tally,
        }
    }
    let (deposit, payment, withdrawal) = (&payments[0].bytes, &payments[1].bytes, &payments[2].bytes);
    let late = &payments.iter().find(|p| p.name == "late deposit, root after deposit").unwrap().bytes;
    fn attempt(walk: &mut Walk, bytes: &[u8], expected: bool) {
        let expiry = walk.slot + 100;
        let instruction = walk.stage(bytes, expiry).unwrap();
        assert_eq!(walk.finalize(&instruction), expected, "slot {}", walk.slot);
    }
    fn end_slot(walk: &mut Walk, next: u64) {
        let (slot, gate) = (walk.slot, walk.gate);
        assert!(seal(&mut walk.accounts, slot, gate, walk.tally));
        walk.set_slot(next);
    }

    // Feature off: the pool is refused; nothing is recorded at the end of a slot.
    let mut walk = start(true, 1, false, &mut *tally);
    attempt(&mut walk, deposit, false);
    end_slot(&mut walk, 2);
    assert!(PoolState::decode(account(&walk.accounts, pool_address()).data()).unwrap().slot_anchors().unwrap().entries().is_empty());
    // The feature becomes active: the same pool now takes payments.
    walk.gate = true;
    attempt(&mut walk, deposit, true);

    // Feature on: only roots of completed earlier slots.
    let mut walk = start(true, 1, true, &mut *tally);
    attempt(&mut walk, deposit, true);
    attempt(&mut walk, payment, false);
    let (slot, gate) = (walk.slot, walk.gate);
    seal(&mut walk.accounts, slot, gate, walk.tally);
    attempt(&mut walk, payment, false);
    walk.set_slot(2);
    attempt(&mut walk, payment, true);
    attempt(&mut walk, withdrawal, false);
    end_slot(&mut walk, 3);
    attempt(&mut walk, withdrawal, true);

    // Age 511 is the last accepted, age 512 is refused; an empty block renews.
    for (slot, expected) in [(512, true), (513, false)] {
        let mut walk = start(true, 1, true, &mut *tally);
        attempt(&mut walk, deposit, true);
        end_slot(&mut walk, slot);
        attempt(&mut walk, payment, expected);
        if !expected {
            end_slot(&mut walk, 514);
            attempt(&mut walk, payment, true);
        }
    }
    // The same root is still usable after slot 976 by a payment that expires
    // later, as long as blocks keep being completed.
    let mut walk = start(true, 1, true, &mut *tally);
    attempt(&mut walk, deposit, true);
    for next in [400, 800, 1200, 1201] {
        end_slot(&mut walk, next);
    }
    attempt(&mut walk, late, true);

    // The root of the empty tree: without a checkpoint until slot 511 only.
    let mut walk = start(true, 511, true, &mut *tally);
    attempt(&mut walk, deposit, true);
    let mut walk = start(true, 512, true, &mut *tally);
    attempt(&mut walk, deposit, false);
    let mut walk = start(true, 511, true, &mut *tally);
    end_slot(&mut walk, 512);
    attempt(&mut walk, deposit, true);

    // A checkpoint ahead of the executing slot.
    let mut walk = start(true, 10, true, &mut *tally);
    end_slot(&mut walk, 5);
    attempt(&mut walk, deposit, false);

    // A legacy pool takes all three in one slot, feature on or off, and its
    // slots are never recorded.
    for gate in [false, true] {
        let mut walk = start(false, 1, gate, &mut *tally);
        attempt(&mut walk, deposit, true);
        attempt(&mut walk, payment, true);
        attempt(&mut walk, withdrawal, true);
        let before = account(&walk.accounts, pool_address()).clone();
        end_slot(&mut walk, 2);
        assert_eq!(account(&walk.accounts, pool_address()), &before);
    }
}

#[test]
fn identifiers_and_addresses_are_the_same() {
    assert_eq!(workspace_program::ID, candidate_program::ID);
    assert_eq!(workspace_program::ID, registered_program::ID);
    assert_eq!(workspace_program::pool_address(), candidate_program::pool_address());
    assert_eq!(workspace_program::ACTIVATION_ID, candidate_program::ACTIVATION_ID);
    assert_eq!(workspace_program::WITHDRAWAL_ACTIVATION_ID, candidate_program::WITHDRAWAL_ACTIVATION_ID);
    assert_eq!(workspace_program::SHIELDED_FEE_ACTIVATION_ID, candidate_program::SHIELDED_FEE_ACTIVATION_ID);
    assert_eq!(workspace_program::INLINE_PAYMENT_ACTIVATION_ID, candidate_program::INLINE_PAYMENT_ACTIVATION_ID);
    assert_eq!(workspace_program::SLOT_ANCHOR_ACTIVATION_ID, candidate_program::SLOT_ANCHOR_ACTIVATION_ID);
    assert_eq!(registered_program::SLOT_ANCHOR_ACTIVATION_ID, candidate_program::SLOT_ANCHOR_ACTIVATION_ID);
    assert_eq!(workspace_program::FINALIZE_COMPUTE_UNITS, candidate_program::FINALIZE_COMPUTE_UNITS);
    assert_eq!(workspace_program::nullifiers::MARKER_BYTES, candidate_program::nullifiers::MARKER_BYTES);
    assert_eq!(workspace_program::staging::ACCOUNT_BYTES, candidate_program::staging::ACCOUNT_BYTES);
}

#[test]
fn every_build_decides_alike() {
    let seed = std::env::var("DIFFERENTIAL_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let walks: u64 = std::env::var("DIFFERENTIAL_WALKS").ok().and_then(|v| v.parse().ok()).unwrap_or(200);
    let steps: u64 = std::env::var("DIFFERENTIAL_STEPS").ok().and_then(|v| v.parse().ok()).unwrap_or(40);
    let payments = payments();
    let mut rng = Rng(seed);
    let mut tally = Tally::default();
    edges(&payments, &mut tally);
    println!("fixed edge cases: {} instructions compared", tally.cases);
    for _ in 0..walks {
        walk(&payments, &mut rng, &mut tally, steps);
    }
    println!("seed {seed}, {walks} walks of {steps} steps");
    println!(
        "{} instructions gave the same result, the same account bytes and the same compute units left in the workspace build and the candidate build; {} of them, with the feature off, also in the registered workspace program",
        tally.cases, tally.with_registered
    );
    let accepted: u64 = tally.by_kind.iter().filter(|(kind, _)| kind.contains("| finalize | accepted")).map(|(_, count)| count).sum();
    println!("finalizations accepted by every build: {accepted}");
    println!("pool accounts refused by the workspace decoder only, not compared: {}", tally.hardening_only);
    for (kind, count) in &tally.by_kind {
        println!("{count:>7}  {kind}");
    }
    println!("end-of-slot stand-ins, same result and bytes on both protocol copies:");
    for (kind, count) in &tally.seals {
        println!("{count:>7}  {kind}");
    }
    // The run is only evidence if it reached the interesting outcomes.
    let has = |needle: &str| tally.by_kind.keys().any(|kind| kind.contains(needle));
    assert!(has("NPOOL004 | feature on | finalize | accepted"));
    assert!(has("NPOOL004 | feature on | finalize | InvalidInstructionData"));
    assert!(has("NPOOL004 | feature off | finalize | InvalidAccountData"));
    assert!(has("NPOOL003 | feature on | finalize | accepted"));
    assert!(has("NPOOL003 | feature off | finalize | accepted"));
    assert!(tally.seals.get("recorded").copied().unwrap_or(0) > 0);
}
