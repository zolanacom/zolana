//! Transaction finalization phases for staged and inline native payments.
//!
//! Account-role and spend-marker checks and proof verification precede writes.
//! The Bank commits public transfers, permanent nullifiers, pool state and staged-payload
//! consumption together. Helpers release each account borrow before the next
//! phase or a native System Program invocation.

use super::KEY;
use crate::{id, nullifiers, pool_address, staging::Buffer};
use native_payments::{
    state::PoolState,
    verification::{AuthorizationContext, PaymentVerifier, ValidationView, VerifiedPayment},
    wire,
};
use solana_instruction::error::InstructionError as Error;
use solana_program_runtime::invoke_context::InvokeContext;
use solana_pubkey::Pubkey;
use solana_sdk_ids::system_program;
use std::{collections::BTreeSet, sync::Arc};

pub(super) fn finalize(
    context: &mut InvokeContext,
    slot: u64,
    inline: Option<&[u8]>,
) -> Result<(), Error> {
    let sponsor_index = if inline.is_some() { 1 } else { 2 };
    let system_index = if inline.is_some() { 2 } else { 3 };
    let nullifier_start = if inline.is_some() { 3 } else { 4 };
    let (state, mut buffer, sponsor) =
        load_accounts(context, inline.is_some(), sponsor_index, system_index)?;
    let payment = if let Some(bytes) = inline {
        native_payments::envelope::decode(state.network, slot, bytes)
            .map_err(|_| Error::InvalidInstructionData)?
            .payment
    } else {
        let staged = buffer.as_ref().ok_or(Error::InvalidAccountData)?;
        if staged.sponsor() != sponsor.to_bytes() || slot > staged.expiry() {
            return Err(Error::InvalidArgument);
        }
        wire::decode(state.network, staged.payload()?).map_err(|_| Error::InvalidInstructionData)?
    };
    if payment.context.shielded_fee.is_some() && !context.get_feature_set().native_shielded_fees {
        return Err(Error::InvalidInstructionData);
    }
    if payment.context.sponsor != sponsor.to_bytes() {
        return Err(Error::MissingRequiredSignature);
    }
    let recipient_index = validate_recipient(
        context,
        &payment.context,
        inline.is_some(),
        &sponsor,
        sponsor_index,
    )?;
    // Both decoders enforce the protocol's two-action shape before this phase.
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
    validate_nullifiers(context, &nullifiers, nullifier_start)?;
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
    if let Some(staged) = buffer.as_mut() {
        staged.consume()?;
    }
    apply_effects(
        context,
        &effects,
        &sponsor,
        recipient_index,
        nullifier_start,
    )?;
    let instruction = context
        .transaction_context
        .get_current_instruction_context()?;
    instruction
        .try_borrow_instruction_account(0)?
        .set_data_from_slice(&next.encode())?;
    if let Some(staged) = buffer {
        instruction
            .try_borrow_instruction_account(1)?
            .set_data_from_slice(staged.bytes())?;
    }
    Ok(())
}

/// Capture authenticated input accounts without retaining runtime borrows.
fn load_accounts(
    context: &mut InvokeContext,
    inline: bool,
    sponsor_index: u16,
    system_index: u16,
) -> Result<(PoolState, Option<Buffer>, Pubkey), Error> {
    let instruction = context
        .transaction_context
        .get_current_instruction_context()?;
    let count = instruction.get_number_of_instruction_accounts();
    if (if inline {
        count != 5
    } else {
        ![6, 7].contains(&count)
    }) || !instruction.is_instruction_account_signer(sponsor_index)?
    {
        return Err(Error::MissingRequiredSignature);
    }
    if instruction.get_key_of_instruction_account(0)? != &pool_address()
        || instruction.get_key_of_instruction_account(system_index)? != &system_program::id()
    {
        return Err(Error::InvalidArgument);
    }
    let sponsor = *instruction.get_key_of_instruction_account(sponsor_index)?;
    if !inline
        && (instruction.get_key_of_instruction_account(1)? == &pool_address()
            || instruction.get_key_of_instruction_account(1)? == &sponsor)
    {
        return Err(Error::InvalidArgument);
    }
    let pool = instruction.try_borrow_instruction_account(0)?;
    let public = instruction.try_borrow_instruction_account(sponsor_index)?;
    if pool.get_owner() != &id()
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
    let buffer = if !inline {
        let staged = instruction.try_borrow_instruction_account(1)?;
        if staged.get_owner() != &id() {
            return Err(Error::InvalidAccountOwner);
        }
        Some(Buffer::decode(staged.get_data())?)
    } else {
        None
    };
    Ok((state, buffer, sponsor))
}

/// Resolve the destination under the existing withdrawal feature and rent rules.
fn validate_recipient(
    context: &mut InvokeContext,
    authorization: &AuthorizationContext,
    inline: bool,
    sponsor: &Pubkey,
    sponsor_index: u16,
) -> Result<u16, Error> {
    let instruction = context
        .transaction_context
        .get_current_instruction_context()?;
    Ok(match authorization.withdrawal_recipient {
        None => {
            if instruction.get_number_of_instruction_accounts() != if inline { 5 } else { 6 } {
                return Err(Error::InvalidArgument);
            }
            sponsor_index
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
                .checked_add(authorization.public_value_balance as u64)
                .ok_or(Error::ArithmeticOverflow)?;
            if final_balance < context.get_sysvar_cache().get_rent()?.minimum_balance(0) {
                return Err(Error::AccountNotRentExempt);
            }
            6
        }
    })
}

/// Reject spent or malformed proof-derived accounts before verifying the proof.
fn validate_nullifiers(
    context: &mut InvokeContext,
    nullifiers: &[[u8; 32]; 2],
    nullifier_start: u16,
) -> Result<(), Error> {
    let instruction = context
        .transaction_context
        .get_current_instruction_context()?;
    for (index, nullifier) in nullifiers.iter().enumerate() {
        let account_index = nullifier_start + index as u16;
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
    Ok(())
}

/// Apply the verified public balance and permanent marker effects in order.
fn apply_effects(
    context: &mut InvokeContext,
    effects: &VerifiedPayment,
    sponsor: &Pubkey,
    recipient_index: u16,
    nullifier_start: u16,
) -> Result<(), Error> {
    if effects.public_value_balance < 0 {
        context.native_invoke(
            solana_system_interface::instruction::transfer(
                sponsor,
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
            .try_borrow_instruction_account(nullifier_start + index as u16)?
            .get_lamports();
        // Zero-lamport accounts are purged even when rent is free.
        let rent = context
            .get_sysvar_cache()
            .get_rent()?
            .minimum_balance(nullifiers::MARKER_BYTES)
            .max(1);
        // Allocate/assign rather than create_account: an unsolicited transfer to
        // an unused PDA must not make an otherwise valid note unspendable.
        if existing < rent {
            context.native_invoke(
                solana_system_interface::instruction::transfer(sponsor, &address, rent - existing),
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
            .try_borrow_instruction_account(nullifier_start + index as u16)?
            .set_data_from_slice(&nullifiers::encode(nullifier))?;
    }
    Ok(())
}
