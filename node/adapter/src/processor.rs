use crate::{id, pool_address, staging::Buffer, FINALIZE_COMPUTE_UNITS};
use native_payments::verification::{bundle_version, MAX_EXPIRY_WINDOW};
use orchard::circuit::VerifyingKey;
use solana_instruction::error::InstructionError as Error;
use solana_program_runtime::invoke_context::InvokeContext;
use std::sync::{Arc, LazyLock};

mod finalization;
mod runtime_features;
#[cfg(test)]
mod runtime_features_tests;
#[cfg(test)]
mod slot_anchor_tests;
use finalization::finalize;

static KEY: LazyLock<Arc<VerifyingKey>> =
    LazyLock::new(|| Arc::new(VerifyingKey::build(bundle_version().circuit_version())));

/// Build the finalizer's existing process-wide public key before serving payments.
pub(crate) fn prepare_verifying_key() {
    LazyLock::force(&KEY);
}

pub fn process(context: &mut InvokeContext) -> Result<(), Error> {
    let slot_anchors = runtime_features::slot_anchors(context);
    process_gated(context, slot_anchors)
}

/// The program, with the state of the `native_slot_anchors` feature given by
/// the caller. `process` is the only caller outside tests.
fn process_gated(context: &mut InvokeContext, slot_anchors: bool) -> Result<(), Error> {
    let instruction = context
        .transaction_context
        .get_current_instruction_context()?
        .get_instruction_data()
        .to_vec();
    let (&opcode, rest) = instruction
        .split_first()
        .ok_or(Error::InvalidInstructionData)?;
    runtime_features::consume_compute_units(
        context,
        if opcode == 3 || opcode == 5 {
            FINALIZE_COMPUTE_UNITS
        } else {
            10_000
        },
    )
    .map_err(|_| Error::ComputationalBudgetExceeded)?;
    if context.get_stack_height() != 1 {
        return Err(Error::InvalidInstructionData);
    }
    let slot = runtime_features::sysvars(context).get_clock()?.slot;
    if opcode == 3 {
        if !rest.is_empty() {
            return Err(Error::InvalidInstructionData);
        }
        return finalize(context, slot, None, slot_anchors);
    }
    if opcode == 5 {
        if !context.get_feature_set().native_inline_payments {
            return Err(Error::InvalidInstructionData);
        }
        return finalize(context, slot, Some(rest), slot_anchors);
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

#[cfg(test)]
mod startup_verifier_tests {
    use super::*;

    #[test]
    fn startup_verifier_reuses_finalizer_key() {
        crate::prepare_verifying_key();
        let finalizer_key = Arc::clone(&KEY);
        crate::prepare_verifying_key();
        assert!(Arc::ptr_eq(&finalizer_key, LazyLock::force(&KEY)));
        assert_eq!(
            finalizer_key.circuit_version(),
            bundle_version().circuit_version()
        );
    }
}
