//! Derive a wallet from a seed: the encrypted recovery file and the shielded address.
//!
//!     sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example wallet_address
//!
//! Offline. The seed and password below are public: never reuse them.
use native_wallet_core::{decode_address, encode_address};
use native_wallet_seed::{decrypt, encrypt, Network, FORMAT};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zolana_sdk_examples::{GENESIS, NETWORK};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A network is a 32-byte domain plus the base58 hash of its genesis block.
    // Seed files and addresses are bound to both.
    let network = Network {
        network: NETWORK,
        genesis_hash: GENESIS.to_owned(),
    };
    // A wallet is one 32-byte seed. Real wallets draw it from the OS random source.
    let seed = [7u8; 32];
    let password = b"disposable example password";

    // 1. The recovery file: the seed under XChaCha20-Poly1305, with the key
    //    derived from the password. This JSON is the only thing a user backs up.
    let backup = encrypt(&seed, password, &network)?;
    println!("recovery file: format {FORMAT}, {} bytes", backup.len());
    let restored = decrypt(&backup, password, &network)?;
    assert_eq!(*restored, seed);
    let refused = decrypt(&backup, b"another password", &network).unwrap_err();
    println!("wrong password: {refused}");

    // 2. The seed is the Orchard spending key. Not every 32 bytes are valid.
    let spending = Option::<SpendingKey>::from(SpendingKey::from_bytes(*restored))
        .ok_or("seed is not a valid spending key")?;
    // 3. The viewing key finds and decrypts the wallet's notes. It never leaves
    //    the device either; only the address derived from it is shared.
    let viewing = FullViewingKey::from(&spending);
    // Payments are received at external address 0. Change goes to the
    // internal scope of the same wallet.
    let address = viewing.address_at(0u32, Scope::External);
    let text = encode_address(network.network, &network.genesis_hash, &address);
    println!("private address: {text}");

    // 4. Decoding checks the prefix, the checksum and the network binding.
    let decoded = decode_address(network.network, &network.genesis_hash, &text)?;
    assert_eq!(
        decoded.to_raw_address_bytes(),
        address.to_raw_address_bytes()
    );
    let other_network = decode_address([8; 32], &network.genesis_hash, &text)
        .err()
        .ok_or("an address must not decode on another network")?;
    println!("same text on another network: {other_network}");
    Ok(())
}
