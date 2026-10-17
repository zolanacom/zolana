//! Permanent replay protection, authenticated by proof-derived PDA addresses.
use crate::{id, pool_address};
use solana_pubkey::Pubkey;

pub const MARKER_BYTES: usize = 40;

pub fn address(nullifier: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(
        &[
            b"native-payment-spent-v1",
            pool_address().as_ref(),
            nullifier,
        ],
        &id(),
    )
    .0
}

pub fn encode(nullifier: &[u8; 32]) -> [u8; MARKER_BYTES] {
    let mut bytes = [0; MARKER_BYTES];
    bytes[..8].copy_from_slice(b"NSPENT01");
    bytes[8..].copy_from_slice(nullifier);
    bytes
}
