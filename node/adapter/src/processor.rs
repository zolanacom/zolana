use crate::{id, nullifiers, pool_address, staging::Buffer, FINALIZE_COMPUTE_UNITS};
use native_payments::{
    state::PoolState,
    verification::{bundle_version, PaymentVerifier, ValidationView, MAX_EXPIRY_WINDOW},
    wire,
};
use orchard::circuit::VerifyingKey;
use solana_instruction::error::InstructionError as Error;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_sdk_ids::system_program;
use std::{
    collections::BTreeSet,
    sync::{Arc, LazyLock},
};

static KEY: LazyLock<Arc<VerifyingKey>> =
    LazyLock::new(|| Arc::new(VerifyingKey::build(bundle_version().circuit_version())));

pub fn process(context: &mut InvokeContext) -> Result<(), Error> {
    let instruction = context
        .transaction_context
        .get_current_instruction_context()?
        .get_instruction_data()
        .to_vec();
    let (&opcode, rest) = instruction
        .split_first()
        .ok_or(Error::InvalidInstructionData)?;
    context
        .consume_checked(if opcode == 3 {
            FINALIZE_COMPUTE_UNITS
        } else {
            10_000
        })
        .map_err(|_| Error::ComputationalBudgetExceeded)?;
    if context.get_stack_height() != 1 {
        return Err(Error::InvalidInstructionData);
    }
    let slot = context.get_sysvar_cache().get_clock()?.slot;
    if opcode == 3 {
        if !rest.is_empty() {
            return Err(Error::InvalidInstructionData);
        }
        return finalize(context, slot);
    }
    let instruction_context = context
        .transaction_context
        .get_current_instruction_context()?;
    if instruction_context.get_number_of_instruction_accounts() != 2
        || !instruction_context.is_instruction_account_signer(1)?
    {
        return Err(Error::MissingRequiredSignature);
    }
    let sponsor = *instruction_context.get_key_of_instruction_account(1)?;
    let buffer_key = *instruction_context.get_key_of_instruction_account(0)?;
    if buffer_key == pool_address() || buffer_key == sponsor {
        return Err(Error::InvalidArgument);
    }
    let mut account = instruction_context.try_borrow_instruction_account(0)?;
    if account.get_owner() != &id() {
        return Err(Error::InvalidAccountOwner);
    }
    let mut buffer = if opcode == 0 {
        if rest.len() != 44 || !instruction_context.is_instruction_account_signer(0)? {
            return Err(Error::InvalidInstructionData);
        }
        let expiry = u64::from_le_bytes(rest[36..44].try_into().unwrap());
        if expiry < slot || expiry.saturating_sub(slot) > MAX_EXPIRY_WINDOW {
            return Err(Error::InvalidInstructionData);
        }
        Buffer::initialize(
            account.get_data(),
            sponsor.to_bytes(),
            u32::from_le_bytes(rest[..4].try_into().unwrap()),
            rest[4..36].try_into().unwrap(),
            expiry,
        )?
    } else {
        Buffer::decode(account.get_data())?
    };
    if buffer.sponsor() != sponsor.to_bytes() {
        return Err(Error::MissingRequiredSignature);
    }
    if opcode != 4 && slot > buffer.expiry() {
        return Err(Error::InvalidInstructionData);
    }
    match opcode {
        0 => {}
        1 => {
            if rest.len() < 5 {
                return Err(Error::InvalidInstructionData);
            }
            buffer.write(
                u32::from_le_bytes(rest[..4].try_into().unwrap()),
                &rest[4..],
            )?;
        }
        2 => {
            if !rest.is_empty() {
                return Err(Error::InvalidInstructionData);
            }
            buffer.seal()?;
        }
        4 => {
            if !rest.is_empty() {
                return Err(Error::InvalidInstructionData);
            }
            let lamports = account.get_lamports();
            account.checked_sub_lamports(lamports)?;
            account.set_data_length(0)?;
            drop(account);
            instruction_context
                .try_borrow_instruction_account(1)?
                .checked_add_lamports(lamports)?;
            return Ok(());
        }
        _ => return Err(Error::InvalidInstructionData),
    }
    account.set_data_from_slice(buffer.bytes())
}

fn finalize(context: &mut InvokeContext, slot: u64) -> Result<(), Error> {
    let (state, mut buffer, sponsor) = {
        let instruction = context
            .transaction_context
            .get_current_instruction_context()?;
        if ![6, 7].contains(&instruction.get_number_of_instruction_accounts())
            || !instruction.is_instruction_account_signer(2)?
        {
            return Err(Error::MissingRequiredSignature);
        }
        if instruction.get_key_of_instruction_account(0)? != &pool_address()
            || instruction.get_key_of_instruction_account(3)? != &system_program::id()
        {
            return Err(Error::InvalidArgument);
        }
        let sponsor = *instruction.get_key_of_instruction_account(2)?;
        if instruction.get_key_of_instruction_account(1)? == &pool_address()
            || instruction.get_key_of_instruction_account(1)? == &sponsor
        {
            return Err(Error::InvalidArgument);
        }
        let pool = instruction.try_borrow_instruction_account(0)?;
        let staged = instruction.try_borrow_instruction_account(1)?;
        let public = instruction.try_borrow_instruction_account(2)?;
        if pool.get_owner() != &id()
            || staged.get_owner() != &id()
            || public.get_owner() != &system_program::id()
            || !public.get_data().is_empty()
        {
            return Err(Error::InvalidAccountOwner);
        }
        let state = PoolState::decode(pool.get_data()).map_err(|_| Error::InvalidAccountData)?;
        if pool.get_lamports()
            < state
                .rent_floor
                .checked_add(state.backing)
                .ok_or(Error::ArithmeticOverflow)?
        {
            return Err(Error::InsufficientFunds);
        }
        (state, Buffer::decode(staged.get_data())?, sponsor)
    };
    if buffer.sponsor() != sponsor.to_bytes() || slot > buffer.expiry() {
        return Err(Error::InvalidArgument);
    }
    let payment = wire::decode(state.network, buffer.payload()?)
        .map_err(|_| Error::InvalidInstructionData)?;
    if payment.context.shielded_fee.is_some() && !context.get_feature_set().native_shielded_fees {
        return Err(Error::InvalidInstructionData);
    }
    if payment.context.sponsor != sponsor.to_bytes() {
        return Err(Error::MissingRequiredSignature);
    }
    let recipient_index = {
        let instruction = context
            .transaction_context
            .get_current_instruction_context()?;
        match payment.context.withdrawal_recipient {
            None => {
                if instruction.get_number_of_instruction_accounts() != 6 {
                    return Err(Error::InvalidArgument);
                }
                2
            }
            Some(key) => {
                if !context.get_feature_set().native_recipient_withdrawals
                    || instruction.get_number_of_instruction_accounts() != 7
                {
                    return Err(Error::InvalidInstructionData);
                }
                if instruction.get_key_of_instruction_account(6)?.to_bytes() != key
                    || !instruction.is_instruction_account_writable(6)?
                {
                    return Err(Error::InvalidArgument);
                }
                let recipient = instruction.try_borrow_instruction_account(6)?;
                // Keep the explicit ordinary-account constraint even on this
                // Agave release, which deprecates the executable accessor.
                #[allow(deprecated)]
                let executable = recipient.is_executable();
                if recipient.get_owner() != &system_program::id()
                    || !recipient.get_data().is_empty()
                    || executable
                    || !solana_pubkey::Pubkey::new_from_array(key).is_on_curve()
                    || key == sponsor.to_bytes()
                {
                    return Err(Error::InvalidAccountOwner);
                }
                let final_balance = recipient
                    .get_lamports()
                    .checked_add(payment.context.public_value_balance as u64)
                    .ok_or(Error::ArithmeticOverflow)?;
                if final_balance < context.get_sysvar_cache().get_rent()?.minimum_balance(0) {
                    return Err(Error::AccountNotRentExempt);
                }
                6
            }
        }
    };
    let nullifiers: [[u8; 32]; 2] = std::array::from_fn(|index| {
        payment
            .bundle
            .actions()
            .get(index)
            .unwrap()
            .nullifier()
            .to_bytes()
    });
    if nullifiers[0] == nullifiers[1] {
        return Err(Error::InvalidInstructionData);
    }
    {
        let instruction = context
            .transaction_context
            .get_current_instruction_context()?;
        for (index, nullifier) in nullifiers.iter().enumerate() {
            let account_index = (4 + index) as u16;
            if instruction.get_key_of_instruction_account(account_index)?
                != &nullifiers::address(nullifier)
            {
                return Err(Error::InvalidArgument);
            }
            if !instruction.is_instruction_account_writable(account_index)? {
                return Err(Error::InvalidArgument);
            }
            let marker = instruction.try_borrow_instruction_account(account_index)?;
            // Any native-owned account at this address fails closed, including
            // malformed markers. Only this finalizer can sign for the PDA.
            if marker.get_owner() == &id() {
                return Err(Error::InvalidInstructionData);
            }
            if marker.get_owner() != &system_program::id() || !marker.get_data().is_empty() {
                return Err(Error::InvalidAccountData);
            }
        }
    }
    let roots = state.roots();
    // Public movement is executed below, atomically with these verified effects.
    let effects = PaymentVerifier::with_shared_key(state.network, Arc::clone(&KEY))
        .map_err(|_| Error::InvalidAccountData)?
        .verify(
            &payment.bundle,
            &payment.context,
            &ValidationView {
                current_slot: slot,
                accepted_anchors: &roots,
                // Both proof-derived accounts were authenticated above. Neither
                // exists in the native spent set. No RPC-supplied state is used.
                spent_nullifiers: &BTreeSet::new(),
                authorized_public_value_balance: payment.context.public_value_balance,
            },
        )
        .map_err(|_| Error::InvalidInstructionData)?;
    let next = state
        .with_payment(&effects)
        .map_err(|_| Error::InvalidInstructionData)?;
    buffer.consume()?;
    if effects.public_value_balance < 0 {
        context.native_invoke(
            solana_system_interface::instruction::transfer(
                &sponsor,
                &pool_address(),
                effects.public_value_balance.unsigned_abs(),
            ),
            &[],
        )?;
    } else if effects.public_value_balance > 0 {
        let instruction = context
            .transaction_context
            .get_current_instruction_context()?;
        instruction
            .try_borrow_instruction_account(0)?
            .checked_sub_lamports(effects.public_value_balance as u64)?;
        instruction
            .try_borrow_instruction_account(recipient_index)?
            .checked_add_lamports(effects.public_value_balance as u64)?;
    }
    for (index, nullifier) in effects.nullifiers.iter().enumerate() {
        let address = nullifiers::address(nullifier);
        let existing = context
            .transaction_context
            .get_current_instruction_context()?
            .try_borrow_instruction_account((4 + index) as u16)?
            .get_lamports();
        let rent = context
            .get_sysvar_cache()
            .get_rent()?
            .minimum_balance(nullifiers::MARKER_BYTES);
        // Allocate/assign rather than create_account: an unsolicited transfer to
        // an unused PDA must not make an otherwise valid note unspendable.
        if existing < rent {
            context.native_invoke(
                solana_system_interface::instruction::transfer(&sponsor, &address, rent - existing),
                &[],
            )?;
        }
        context.native_invoke(
            solana_system_interface::instruction::allocate(
                &address,
                nullifiers::MARKER_BYTES as u64,
            ),
            &[address],
        )?;
        context.native_invoke(
            solana_system_interface::instruction::assign(&address, &id()),
            &[address],
        )?;
        context
            .transaction_context
            .get_current_instruction_context()?
            .try_borrow_instruction_account((4 + index) as u16)?
            .set_data_from_slice(&nullifiers::encode(nullifier))?;
    }
    let instruction = context
        .transaction_context
        .get_current_instruction_context()?;
    instruction
        .try_borrow_instruction_account(0)?
        .set_data_from_slice(&next.encode())?;
    instruction
        .try_borrow_instruction_account(1)?
        .set_data_from_slice(buffer.bytes())?;
    Ok(())
}
