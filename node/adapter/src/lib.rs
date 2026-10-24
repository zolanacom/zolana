//! Metered native payment entrypoint for the local development network.
#![forbid(unsafe_code)]

pub mod instructions;
pub mod nullifiers;
mod processor;
pub mod staging;

/// Prepare the same public verifying key used by payment finalization.
/// This performs no transaction execution or account/state access.
pub fn prepare_verifying_key() {
    processor::prepare_verifying_key();
}

use solana_program_runtime::declare_process_instruction;
use solana_pubkey::Pubkey;

// Fixed public development identifiers; no associated private signing keys.
pub const ID: Pubkey = Pubkey::new_from_array(native_payments::native_accounts::PROGRAM_ID);
pub const ACTIVATION_ID: Pubkey = Pubkey::new_from_array([
    192, 47, 61, 8, 73, 55, 102, 89, 124, 17, 171, 200, 51, 88, 71, 95, 72, 43, 189, 112, 141, 91,
    229, 76, 97, 21, 3, 87, 217, 161, 55, 209,
]);
pub const FINALIZE_COMPUTE_UNITS: u64 = 1_100_000;
pub const WITHDRAWAL_ACTIVATION_ID: Pubkey = Pubkey::new_from_array([
    193, 47, 61, 8, 73, 55, 102, 89, 124, 17, 171, 200, 51, 88, 71, 95, 72, 43, 189, 112, 141, 91,
    229, 76, 97, 21, 3, 87, 217, 161, 55, 209,
]);

pub const SHIELDED_FEE_ACTIVATION_ID: Pubkey = Pubkey::new_from_array([
    194, 47, 61, 8, 73, 55, 102, 89, 124, 17, 171, 200, 51, 88, 71, 95, 72, 43, 189, 112, 141, 91,
    229, 76, 97, 21, 3, 87, 217, 161, 55, 209,
]);

/// Execution candidate only: ordinary Agave ingress still enforces its MTU.
pub const INLINE_PAYMENT_ACTIVATION_ID: Pubkey = Pubkey::new_from_array([
    195, 47, 61, 8, 73, 55, 102, 89, 124, 17, 171, 200, 51, 88, 71, 95, 72, 43, 189, 112, 141, 91,
    229, 76, 97, 21, 3, 87, 217, 161, 55, 209,
]);

pub fn id() -> Pubkey {
    ID
}
pub fn pool_address() -> Pubkey {
    Pubkey::new_from_array(native_payments::native_accounts::pool_address())
}

declare_process_instruction!(Entrypoint, 0, |invoke_context| {
    processor::process(invoke_context)
});
