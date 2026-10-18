//! Metered native payment entrypoint for the local development network.
#![forbid(unsafe_code)]

pub mod instructions;
pub mod nullifiers;
mod processor;
pub mod staging;

use solana_program_runtime::declare_process_instruction;
use solana_pubkey::Pubkey;

// Fixed public development identifiers; no associated private signing keys.
pub const ID: Pubkey = Pubkey::new_from_array([
    91, 34, 9, 203, 140, 74, 92, 11, 167, 20, 210, 73, 64, 155, 3, 220, 25, 87, 194, 52, 122, 28,
    170, 241, 29, 131, 42, 88, 76, 107, 13, 190,
]);
pub const ACTIVATION_ID: Pubkey = Pubkey::new_from_array([
    192, 47, 61, 8, 73, 55, 102, 89, 124, 17, 171, 200, 51, 88, 71, 95, 72, 43, 189, 112, 141, 91,
    229, 76, 97, 21, 3, 87, 217, 161, 55, 209,
]);
pub const FINALIZE_COMPUTE_UNITS: u64 = 1_100_000;
pub const WITHDRAWAL_ACTIVATION_ID: Pubkey = Pubkey::new_from_array([
    193, 47, 61, 8, 73, 55, 102, 89, 124, 17, 171, 200, 51, 88, 71, 95, 72, 43, 189, 112, 141, 91,
    229, 76, 97, 21, 3, 87, 217, 161, 55, 209,
]);

pub fn id() -> Pubkey {
    ID
}
pub fn pool_address() -> Pubkey {
    Pubkey::find_program_address(&[b"native-payment-pool-v1"], &ID).0
}

declare_process_instruction!(Entrypoint, 0, |invoke_context| {
    processor::process(invoke_context)
});
