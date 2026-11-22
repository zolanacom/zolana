//! Everything this program asks of the runtime in words that differ between
//! runtime releases.
//!
//! The program is written against the Agave 3.0.14 runtime in `node/agave`.
//! A later release reaches the same four things by other names: the compute
//! meter, the sysvar cache, an invocation of another program, and the
//! `native_slot_anchors` feature. Each has one function here, and the rest of
//! the program calls these functions and never the runtime's own names for
//! them. This file is then the only one that differs between two runtime
//! releases; the checks, their order and their errors are in the files that
//! call it. See decision 0043.
//!
//! No function here decides anything. Each passes its arguments to the
//! runtime and returns the runtime's answer unchanged, with one exception:
//! `slot_anchors`, described where it is defined.

use solana_instruction::{error::InstructionError, Instruction};
use solana_program_runtime::{invoke_context::InvokeContext, sysvar_cache::SysvarCache};
use solana_pubkey::Pubkey;

/// Charge `units` to the compute budget of the executing transaction. An
/// error means the budget did not hold them; what remained is then spent.
pub(super) fn consume_compute_units(
    context: &InvokeContext,
    units: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    context.consume_checked(units)
}

/// The sysvars of the executing slot, as the runtime cached them.
pub(super) fn sysvars<'a>(context: &'a InvokeContext) -> &'a SysvarCache {
    context.get_sysvar_cache()
}

/// Invoke `instruction` from this program with the signatures the executing
/// instruction already carries and no other.
pub(super) fn invoke(
    context: &mut InvokeContext,
    instruction: Instruction,
) -> Result<(), InstructionError> {
    context.native_invoke(instruction, &[])
}

/// Invoke `instruction` from this program, which signs for the spent marker
/// of `nullifier`. `marker` is that marker's address,
/// `nullifiers::address(nullifier)`.
///
/// This runtime is told the address a program signs for. A runtime that is
/// told the seeds instead derives them here from `nullifier`, which is why
/// both are passed; this release does not read the second.
pub(super) fn invoke_as_marker(
    context: &mut InvokeContext,
    instruction: Instruction,
    marker: &Pubkey,
    _nullifier: &[u8; 32],
) -> Result<(), InstructionError> {
    context.native_invoke(instruction, &[*marker])
}

/// Whether `native_slot_anchors` is active for the executing transaction.
///
/// `native_slot_anchors` is the feature at `SLOT_ANCHOR_ACTIVATION_ID`. A
/// runtime that knows the feature reports it through its feature set, beside
/// the three switches the finalizer already reads there. The Agave 3.0.14
/// runtime in `node/agave` has no such switch, and no account can activate a
/// feature it does not list, so for that runtime the answer is always "not
/// active": a slot-anchored pool is refused exactly as it is where the
/// feature exists and is inactive. Nothing else in the program asks whether
/// slot anchors are active.
pub(super) fn slot_anchors(_context: &InvokeContext) -> bool {
    false
}
