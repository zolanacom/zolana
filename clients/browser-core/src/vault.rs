//! Opaque, platform-neutral creation/recovery seam for the native seed format.
//!
//! No raw seed, viewing key or plaintext note export exists. This module does
//! not perform network requests, authenticate a gateway, or hold payment state.
//! Network configuration must be authenticated separately by the application.
//! JavaScript callers must wipe their password Uint8Array after each call; Rust
//! consumes its own copy into Zeroizing immediately. This does not claim that
//! an origin compromise, browser extension or process-memory inspection is safe.
use crate::error::{BrowserError, ErrorCode, Result};
use native_wallet_seed::{self as codec, Network};
use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    Address,
};
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

const MAX_NETWORK_BYTES: usize = 1024;
const FIXTURE_PASSWORD: &[u8] = b"disposable browser vault reference password";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkInput {
    network: [u8; 32],
    genesis_hash: String,
}
fn network_from_json(raw: &str) -> Result<Network> {
    if raw.is_empty() || raw.len() > MAX_NETWORK_BYTES {
        return Err(BrowserError::new(
            ErrorCode::Configuration,
            "bounded network identity required",
        ));
    }
    let parsed: NetworkInput = serde_json::from_str(raw)
        .map_err(|_| BrowserError::new(ErrorCode::Configuration, "invalid network identity"))?;
    let network = Network {
        network: parsed.network,
        genesis_hash: parsed.genesis_hash,
    };
    network.validate()?;
    Ok(network)
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct PublicIdentity {
    pub format: &'static str,
    pub network: Network,
    pub private_address: String,
    pub public_address: String,
    pub fee_address: String,
}

// Shared native/browser address codec; network and genesis bind the domain.
fn encode_address(network: &Network, address: &Address) -> String {
    native_wallet_core::encode_address(network.network, &network.genesis_hash, address)
}
fn decode_address(network: &Network, text: &str) -> Result<Address> {
    native_wallet_core::decode_address(network.network, &network.genesis_hash, text)
        .map_err(|error| error.to_string().into())
}
fn public_authority(seed: &[u8; 32], network: &Network, personal: &[u8; 16]) -> String {
    let signing = authority(seed, network, personal);
    bs58::encode(signing.verifying_key().to_bytes()).into_string()
}
fn authority(seed: &[u8; 32], network: &Network, personal: &[u8; 16]) -> ed25519_dalek::SigningKey {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personal)
        .key(seed)
        .to_state();
    state.update(&network.network);
    state.update(network.genesis_hash.as_bytes());
    let secret = Zeroizing::new(
        <[u8; 32]>::try_from(state.finalize().as_bytes()).expect("32-byte authority"),
    );
    // solana-keypair 3.0 uses the same ed25519-dalek SigningKey::from seed.
    ed25519_dalek::SigningKey::from_bytes(&secret)
}
fn identity(seed: &[u8; 32], network: &Network) -> Result<PublicIdentity> {
    let spending = Option::<SpendingKey>::from(SpendingKey::from_bytes(*seed))
        .ok_or_else(|| BrowserError::new(ErrorCode::Backup, "invalid spending seed"))?;
    let viewing = FullViewingKey::from(&spending);
    let address = viewing.address_at(0u32, Scope::External);
    let private_address = encode_address(network, &address);
    if decode_address(network, &private_address)?.to_raw_address_bytes()
        != address.to_raw_address_bytes()
    {
        return Err("receiving address roundtrip mismatch".into());
    }
    Ok(PublicIdentity {
        format: "zolana-browser-vault-identity-v1",
        network: network.clone(),
        private_address,
        public_address: public_authority(seed, network, b"NPayPublicKeyV1!"),
        fee_address: public_authority(seed, network, b"NPayFeeKeyV1!!!!"),
    })
}

/// A wasm-bindgen owned handle. Its generated free() drops the Zeroizing seed.
/// Locking also destroys this module's seed buffer; ciphertext remains usable.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct BrowserVault {
    seed: Option<Zeroizing<[u8; 32]>>,
    network: Network,
    encrypted: Vec<u8>,
    pub(crate) session: Option<crate::session::Session>,
}
impl BrowserVault {
    pub(crate) fn network(&self) -> &Network {
        &self.network
    }
    pub(crate) fn unlocked_seed(&self) -> Result<&[u8; 32]> {
        self.seed
            .as_deref()
            .ok_or_else(|| BrowserError::new(ErrorCode::Locked, "wallet is locked"))
    }
    pub(crate) fn fee_authority(&self) -> Result<ed25519_dalek::SigningKey> {
        Ok(authority(
            self.unlocked_seed()?,
            &self.network,
            b"NPayFeeKeyV1!!!!",
        ))
    }
    pub fn create(network_json: &str, password: Vec<u8>) -> Result<Self> {
        let password = Zeroizing::new(password);
        codec::validate_password(&password)?;
        let network = network_from_json(network_json)?;
        let seed = loop {
            let candidate = Zeroizing::new(rand::random::<[u8; 32]>());
            if bool::from(SpendingKey::from_bytes(*candidate).is_some()) {
                break candidate;
            }
        };
        let encrypted = codec::encrypt(&seed, &password, &network)?;
        Ok(Self {
            seed: Some(seed),
            network,
            encrypted,
            session: None,
        })
    }
    pub fn restore(network_json: &str, encrypted: Vec<u8>, password: Vec<u8>) -> Result<Self> {
        let password = Zeroizing::new(password);
        let network = network_from_json(network_json)?;
        let seed = codec::decrypt(&encrypted, &password, &network)?;
        if !bool::from(SpendingKey::from_bytes(*seed).is_some()) {
            return Err(BrowserError::new(
                ErrorCode::Backup,
                "invalid spending seed",
            ));
        }
        Ok(Self {
            seed: Some(seed),
            network,
            encrypted,
            session: None,
        })
    }
    pub fn unlock(&mut self, password: Vec<u8>) -> Result<()> {
        let password = Zeroizing::new(password);
        // An unsuccessful unlock never leaves an earlier unlocked seed active.
        self.lock();
        let seed = codec::decrypt(&self.encrypted, &password, &self.network)?;
        if !bool::from(SpendingKey::from_bytes(*seed).is_some()) {
            return Err(BrowserError::new(
                ErrorCode::Backup,
                "invalid spending seed",
            ));
        }
        self.seed = Some(seed);
        Ok(())
    }
    pub fn identity(&self) -> Result<PublicIdentity> {
        identity(self.unlocked_seed()?, &self.network)
    }
    pub fn encrypted_backup(&self) -> Vec<u8> {
        self.encrypted.clone()
    }
    pub fn lock(&mut self) {
        self.session.take();
        self.seed.take();
    }
    pub fn is_locked(&self) -> bool {
        self.seed.is_none()
    }
}

impl native_wallet_core::WalletKeys for BrowserVault {
    fn network_domain(&self) -> [u8; 32] {
        self.network.network
    }
    fn genesis_hash(&self) -> &str {
        &self.network.genesis_hash
    }
    fn spending_key(&self) -> native_wallet_core::Result<SpendingKey> {
        let seed = self
            .unlocked_seed()
            .map_err(|error| -> Box<dyn std::error::Error> { error.into() })?;
        Option::from(SpendingKey::from_bytes(*seed)).ok_or_else(|| "invalid spending seed".into())
    }
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl BrowserVault {
    #[wasm_bindgen(js_name = create)]
    pub fn js_create(
        network_json: &str,
        password: Vec<u8>,
    ) -> std::result::Result<BrowserVault, JsValue> {
        Self::create(network_json, password).map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name = restore)]
    pub fn js_restore(
        network_json: &str,
        encrypted: Vec<u8>,
        password: Vec<u8>,
    ) -> std::result::Result<BrowserVault, JsValue> {
        Self::restore(network_json, encrypted, password).map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name = unlock)]
    pub fn js_unlock(&mut self, password: Vec<u8>) -> std::result::Result<(), JsValue> {
        self.unlock(password).map_err(BrowserError::into_js)
    }
    #[wasm_bindgen(js_name = identity)]
    pub fn js_identity(&self) -> std::result::Result<String, JsValue> {
        serde_json::to_string(&self.identity().map_err(BrowserError::into_js)?)
            .map_err(|_| BrowserError::from("cannot encode public identity").into_js())
    }
    #[wasm_bindgen(js_name = encrypted_backup)]
    pub fn js_encrypted_backup(&self) -> Vec<u8> {
        self.encrypted_backup()
    }
    #[wasm_bindgen(js_name = lock)]
    pub fn js_lock(&mut self) {
        self.lock();
    }
    #[wasm_bindgen(js_name = is_locked)]
    pub fn js_is_locked(&self) -> bool {
        self.is_locked()
    }
}

fn fixture_network() -> Network {
    Network {
        network: [7; 32],
        genesis_hash: "1".repeat(32),
    }
}

/// Public, disposable vector for comparison with the existing native wallet.
/// No caller-controlled seed or password input exists on this reference path.
pub fn reference_json() -> Result<String> {
    let network = fixture_network();
    let seed = Zeroizing::new([7u8; 32]);
    let identity = identity(&seed, &network)?;
    let encrypted = codec::encrypt(&seed, FIXTURE_PASSWORD, &network)?;
    Ok(
        serde_json::json!({"format":"zolana-browser-vault-reference-v1","fixture_only":true,
        "identity":identity,"encrypted_backup":encrypted,"rounds":codec::ROUNDS})
        .to_string(),
    )
}

/// Exercise creation, exact-byte backup restore, lock and refusal boundaries in
/// a worker without user secrets or network access. This is not a payment test.
pub fn acceptance_json() -> Result<String> {
    let timer = super::Timer::start();
    let network = fixture_network();
    let network_json =
        serde_json::to_string(&network).map_err(|_| "cannot encode fixture network")?;
    let mut wallet = BrowserVault::create(&network_json, FIXTURE_PASSWORD.to_vec())?;
    let first = wallet.identity()?;
    let backup = wallet.encrypted_backup();
    wallet.lock();
    if !wallet.is_locked() || wallet.identity().is_ok() {
        return Err("lock did not revoke identity access".into());
    }
    if wallet
        .unlock(b"wrong disposable fixture password".to_vec())
        .is_ok()
        || !wallet.is_locked()
    {
        return Err("wrong password unlocked the vault".into());
    }
    wallet.unlock(FIXTURE_PASSWORD.to_vec())?;
    if wallet.identity()? != first {
        return Err("unlock changed public identity".into());
    }
    drop(wallet);
    let restored = BrowserVault::restore(&network_json, backup.clone(), FIXTURE_PASSWORD.to_vec())?;
    if restored.identity()? != first || restored.encrypted_backup() != backup {
        return Err("restore changed identity or ciphertext".into());
    }
    let wrong = Network {
        network: [8; 32],
        ..network.clone()
    };
    let wrong_json = serde_json::to_string(&wrong).map_err(|_| "cannot encode fixture network")?;
    if BrowserVault::restore(&wrong_json, backup.clone(), FIXTURE_PASSWORD.to_vec()).is_ok() {
        return Err("wrong network restored a vault".into());
    }
    let mut changed: serde_json::Value =
        serde_json::from_slice(&backup).map_err(|_| "invalid fixture backup")?;
    changed["ciphertext"][0] = serde_json::json!(
        changed["ciphertext"][0]
            .as_u64()
            .ok_or("invalid fixture ciphertext")?
            ^ 1
    );
    if BrowserVault::restore(
        &network_json,
        serde_json::to_vec(&changed).map_err(|_| "cannot encode fixture mutation")?,
        FIXTURE_PASSWORD.to_vec(),
    )
    .is_ok()
    {
        return Err("modified ciphertext restored a vault".into());
    }
    if decode_address(&wrong, &first.private_address).is_ok() {
        return Err("wrong address network was accepted".into());
    }
    let other_genesis = Network {
        genesis_hash: bs58::encode([8; 32]).into_string(),
        ..network
    };
    if decode_address(&other_genesis, &first.private_address).is_ok() {
        return Err("wrong address genesis was accepted".into());
    }
    let reference: serde_json::Value =
        serde_json::from_str(&reference_json()?).map_err(|_| "invalid public reference")?;
    Ok(
        serde_json::json!({"format":"zolana-browser-vault-acceptance-v1","fixture_only":true,
        "ok":true,"rounds":codec::ROUNDS,"elapsed_ms":timer.ms(),"reference":reference,
        "checks":["generated_native_format_backup","lock_revoked_access","wrong_password_rejected",
            "unlock_restored_identity","exact_ciphertext_restore","wrong_network_rejected",
            "ciphertext_tamper_rejected","address_network_genesis_bound"]})
        .to_string(),
    )
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn vault_acceptance() -> std::result::Result<String, JsValue> {
    acceptance_json().map_err(BrowserError::into_js)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_vault_creation_recovery_and_refusal_boundaries() {
        let report: serde_json::Value = serde_json::from_str(&acceptance_json().unwrap()).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["rounds"], 600_000);
        assert_eq!(report["checks"].as_array().unwrap().len(), 8);
        assert_ne!(
            report["reference"]["identity"]["public_address"],
            report["reference"]["identity"]["fee_address"]
        );
    }
    #[test]
    fn malformed_network_password_and_backup_fail_closed() {
        let raw = serde_json::to_string(&fixture_network()).unwrap();
        let short = BrowserVault::create(&raw, b"short".to_vec());
        assert_eq!(
            short.err().expect("short password rejected").code(),
            "password"
        );
        let invalid_network = BrowserVault::create("{}", FIXTURE_PASSWORD.to_vec());
        assert_eq!(
            invalid_network
                .err()
                .expect("invalid network rejected")
                .code(),
            "configuration"
        );
        assert!(BrowserVault::create(&" ".repeat(1025), FIXTURE_PASSWORD.to_vec()).is_err());
        let mut value = serde_json::to_value(fixture_network()).unwrap();
        value["extra"] = true.into();
        assert!(BrowserVault::create(&value.to_string(), FIXTURE_PASSWORD.to_vec()).is_err());
        let oversized = BrowserVault::restore(&raw, vec![0; 4097], FIXTURE_PASSWORD.to_vec());
        assert_eq!(
            oversized.err().expect("oversized backup rejected").code(),
            "backup"
        );
    }
}
