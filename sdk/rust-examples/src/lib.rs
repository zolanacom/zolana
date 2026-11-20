//! Runnable examples for the Zolana crates that build without the validator.
//!
//! Everything here is offline: no RPC, no ledger and no funds. The keys are
//! public disposable fixtures. Start with `sdk/README.md`.
#![forbid(unsafe_code)]

use native_wallet_core::{encode_address, Result, WalletKeys};
use orchard::keys::{Scope, SpendingKey};

/// Example network identity: a 32-byte domain and a base58 genesis hash.
/// These are the public fixture values of `browser-vault-check`, not a network.
pub const NETWORK: [u8; 32] = [7; 32];
pub const GENESIS: &str = "11111111111111111111111111111111";

/// A disposable wallet: one 32-byte seed bound to one network.
///
/// `WalletKeys` is the seam between a host wallet and `native-wallet-core`.
/// A real wallet keeps the seed encrypted at rest (see `wallet_address`).
pub struct DemoWallet {
    network: [u8; 32],
    genesis: String,
    seed: [u8; 32],
}

impl DemoWallet {
    pub fn new(network: [u8; 32], genesis: &str, seed: [u8; 32]) -> Self {
        Self {
            network,
            genesis: genesis.to_owned(),
            seed,
        }
    }

    /// The private receiving address (`npriv1…`): external scope, index 0.
    pub fn address(&self) -> Result<String> {
        let address = self.viewing_key()?.address_at(0u32, Scope::External);
        Ok(encode_address(self.network, &self.genesis, &address))
    }
}

impl WalletKeys for DemoWallet {
    fn network_domain(&self) -> [u8; 32] {
        self.network
    }
    fn genesis_hash(&self) -> &str {
        &self.genesis
    }
    fn spending_key(&self) -> Result<SpendingKey> {
        // Not every 32-byte string is a valid Orchard spending key.
        Option::from(SpendingKey::from_bytes(self.seed)).ok_or_else(|| "invalid seed".into())
    }
}

/// Lowercase hex, for printing public values.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
