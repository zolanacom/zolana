//! Compute the on-chain addresses of the pool and of a nullifier account.
//!
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example nullifier_address
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example nullifier_address -- <64 hex digits>
//!
//! Offline. No proof is built.
use native_payments::native_accounts::{nullifier_address, pool_address, PROGRAM_ID};
use zolana_sdk_examples::hex;

fn base58(bytes: &[u8; 32]) -> String {
    bs58::encode(bytes).into_string()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The native payment program has a fixed id with no private key.
    println!("program id        {}", base58(&PROGRAM_ID));
    // The single pool account is derived from the program id and one seed.
    let pool = pool_address();
    println!("pool account      {}", base58(&pool));

    // A nullifier is the 32-byte public value a payment reveals for a note it
    // spends. Pass one as hex, or use the placeholder below.
    let nullifier: [u8; 32] = match std::env::args().nth(1) {
        Some(text) => parse_hex(&text)?,
        None => [0x11; 32],
    };
    // Spending creates a 40-byte account at this address. A payment whose
    // nullifier account already exists fails, so a note is spent at most once.
    let address = nullifier_address(&nullifier);
    println!("nullifier         {}", hex(&nullifier));
    println!("nullifier account {}", base58(&address));

    // To ask a node whether a note is spent, look this address up with
    // getAccountInfo: an existing account owned by the program means spent.
    assert_eq!(address, nullifier_address(&nullifier));
    assert_ne!(address, nullifier_address(&[0x12; 32]));
    Ok(())
}

fn parse_hex(text: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if text.len() != 64 || !text.is_ascii() {
        return Err("a nullifier is 64 hex digits".into());
    }
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}
