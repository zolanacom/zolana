//! Permanent replay protection, authenticated by proof-derived PDA addresses.
use solana_pubkey::Pubkey;

pub const MARKER_BYTES: usize = 40;

pub fn address(nullifier: &[u8; 32]) -> Pubkey {
    Pubkey::new_from_array(native_payments::native_accounts::nullifier_address(
        nullifier,
    ))
}

pub fn encode(nullifier: &[u8; 32]) -> [u8; MARKER_BYTES] {
    let mut bytes = [0; MARKER_BYTES];
    bytes[..8].copy_from_slice(b"NSPENT01");
    bytes[8..].copy_from_slice(nullifier);
    bytes
}
