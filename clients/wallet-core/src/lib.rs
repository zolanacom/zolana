//! Shared native/browser proof construction and checked note replay.
//!
//! No RPC, filesystem, thread management or host clock belongs here. Successful
//! finalized transaction execution and canonical history coverage remain host
//! responsibilities. Nothing in this crate is directly exported as a WASM ABI.
#![forbid(unsafe_code)]
pub mod canonical;
#[cfg(test)]
mod canonical_tests;
pub mod history;
#[cfg(test)]
mod parity_tests;
pub mod payments;
pub mod replay;
use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    Address,
};
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Implemented inside each owning wallet. Secret material stays inside Rust;
/// browser implementations must refuse access while their vault is locked.
pub trait WalletKeys {
    fn network_domain(&self) -> [u8; 32];
    fn genesis_hash(&self) -> &str;
    fn spending_key(&self) -> Result<SpendingKey>;
    fn viewing_key(&self) -> Result<FullViewingKey> {
        Ok(FullViewingKey::from(&self.spending_key()?))
    }
    fn change_address(&self) -> Result<Address> {
        Ok(self.viewing_key()?.address_at(0u32, Scope::Internal))
    }
    fn decode_address(&self, text: &str) -> Result<Address> {
        decode_address(self.network_domain(), self.genesis_hash(), text)
    }
}

// Existing native batch APIs iterate slices of wallet references. Forward
// references without requiring adapters to copy or unwrap an owning key.
impl<T: WalletKeys + ?Sized> WalletKeys for &T {
    fn network_domain(&self) -> [u8; 32] {
        T::network_domain(*self)
    }
    fn genesis_hash(&self) -> &str {
        T::genesis_hash(*self)
    }
    fn spending_key(&self) -> Result<SpendingKey> {
        T::spending_key(*self)
    }
    fn viewing_key(&self) -> Result<FullViewingKey> {
        T::viewing_key(*self)
    }
    fn change_address(&self) -> Result<Address> {
        T::change_address(*self)
    }
    fn decode_address(&self, text: &str) -> Result<Address> {
        T::decode_address(*self, text)
    }
}
fn network_tag(network: [u8; 32], genesis: &str) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"NPayWalletAddrV1")
        .to_state();
    state.update(&network);
    state.update(genesis.as_bytes());
    state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("32-byte address domain")
}
pub fn encode_address(network: [u8; 32], genesis: &str, address: &Address) -> String {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&network_tag(network, genesis));
    bytes.extend_from_slice(&address.to_raw_address_bytes());
    let checksum = blake2b_simd::blake2b(&bytes);
    bytes.extend_from_slice(&checksum.as_bytes()[..4]);
    format!("npriv1{}", bs58::encode(bytes).into_string())
}
pub fn decode_address(network: [u8; 32], genesis: &str, text: &str) -> Result<Address> {
    if text.len() > 140 {
        return Err("invalid receiving address length".into());
    }
    let bytes = bs58::decode(
        text.strip_prefix("npriv1")
            .ok_or("invalid receiving address prefix")?,
    )
    .into_vec()?;
    if bytes.len() != 80
        || bytes[0] != 1
        || bytes[1..33] != network_tag(network, genesis)
        || blake2b_simd::blake2b(&bytes[..76]).as_bytes()[..4] != bytes[76..]
    {
        return Err("receiving address checksum or network mismatch".into());
    }
    Option::from(Address::from_raw_address_bytes(
        &bytes[33..76].try_into().expect("checked length"),
    ))
    .ok_or_else(|| "invalid shielded address encoding".into())
}

#[cfg(test)]
pub(crate) mod test_keys {
    use super::*;
    pub struct FixtureKeys {
        pub domain: [u8; 32],
        pub genesis: String,
        seed: [u8; 32],
    }
    impl FixtureKeys {
        pub fn new(domain: [u8; 32], genesis: String, seed: [u8; 32]) -> Self {
            Self {
                domain,
                genesis,
                seed,
            }
        }
        pub fn address_text(&self) -> String {
            encode_address(
                self.domain,
                &self.genesis,
                &self
                    .viewing_key()
                    .unwrap()
                    .address_at(0u32, Scope::External),
            )
        }
    }
    impl WalletKeys for FixtureKeys {
        fn network_domain(&self) -> [u8; 32] {
            self.domain
        }
        fn genesis_hash(&self) -> &str {
            &self.genesis
        }
        fn spending_key(&self) -> Result<SpendingKey> {
            Option::from(SpendingKey::from_bytes(self.seed))
                .ok_or_else(|| "invalid disposable key".into())
        }
    }
}
