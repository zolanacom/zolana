use crate::Result;
use orchard::{
    keys::{FullViewingKey, Scope, SpendingKey},
    Address,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub network: [u8; 32],
    pub genesis_hash: String,
}

impl Network {
    pub fn load(path: &Path) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        if !matches!(value["pool_format"].as_str(), Some("NPOOL003" | "NPOOL004"))
            || value["program"] != native_payment_program::id().to_string()
            || value["pool"] != native_payment_program::pool_address().to_string()
        {
            return Err(
                "network configuration does not describe this native payment protocol".into(),
            );
        }
        let network: Self = serde_json::from_value(value)?;
        network.validate()?;
        Ok(network)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.network == [0; 32] || bs58::decode(&self.genesis_hash).into_vec()?.len() != 32 {
            return Err("invalid network domain or genesis fingerprint".into());
        }
        Ok(())
    }
}

fn seed_network(network: &Network) -> native_wallet_seed::Network {
    native_wallet_seed::Network {
        network: network.network,
        genesis_hash: network.genesis_hash.clone(),
    }
}

pub struct WalletKey {
    seed: Zeroizing<[u8; 32]>,
    pub network: Network,
}

impl native_wallet_core::WalletKeys for WalletKey {
    fn network_domain(&self) -> [u8; 32] {
        self.network.network
    }
    fn genesis_hash(&self) -> &str {
        &self.network.genesis_hash
    }
    fn spending_key(&self) -> native_wallet_core::Result<SpendingKey> {
        Ok(WalletKey::spending_key(self))
    }
}

impl WalletKey {
    pub fn generate(network: Network) -> Result<Self> {
        network.validate()?;
        loop {
            let seed = rand::random::<[u8; 32]>();
            if bool::from(SpendingKey::from_bytes(seed).is_some()) {
                return Ok(Self {
                    seed: Zeroizing::new(seed),
                    network,
                });
            }
        }
    }

    pub fn spending_key(&self) -> SpendingKey {
        Option::from(SpendingKey::from_bytes(*self.seed)).expect("validated spending seed")
    }

    pub fn viewing_key(&self) -> FullViewingKey {
        FullViewingKey::from(&self.spending_key())
    }
    pub fn receiving_address(&self) -> Address {
        self.viewing_key().address_at(0u32, Scope::External)
    }
    pub fn change_address(&self) -> Address {
        self.viewing_key().address_at(0u32, Scope::Internal)
    }

    /// Independent Ed25519 authority recoverable from the same encrypted seed.
    /// Network/genesis separation prevents cross-chain public key reuse.
    pub fn public_keypair(&self) -> solana_keypair::Keypair {
        let mut hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"NPayPublicKeyV1!")
            .key(&self.seed[..])
            .to_state();
        hash.update(&self.network.network);
        hash.update(self.network.genesis_hash.as_bytes());
        let secret =
            Zeroizing::new(<[u8; 32]>::try_from(hash.finalize().as_bytes()).expect("32 bytes"));
        solana_keypair::Keypair::new_from_array(*secret)
    }

    /// A separate fee authority keeps the existing recipient-bound protocol
    /// unchanged and prevents withdrawal credits from masking fee expenditure.
    pub fn fee_keypair(&self) -> solana_keypair::Keypair {
        let mut hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"NPayFeeKeyV1!!!!")
            .key(&self.seed[..])
            .to_state();
        hash.update(&self.network.network);
        hash.update(self.network.genesis_hash.as_bytes());
        let secret =
            Zeroizing::new(<[u8; 32]>::try_from(hash.finalize().as_bytes()).expect("32 bytes"));
        solana_keypair::Keypair::new_from_array(*secret)
    }

    pub(crate) fn scan_cache_key(&self) -> Zeroizing<[u8; 32]> {
        let mut hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"NPayCacheKeyV1!!")
            .key(&self.seed[..])
            .to_state();
        hash.update(&self.network.network);
        hash.update(self.network.genesis_hash.as_bytes());
        Zeroizing::new(hash.finalize().as_bytes().try_into().expect("32-byte key"))
    }

    pub fn save(&self, path: &Path, password: &[u8]) -> Result<()> {
        let encoded =
            native_wallet_seed::encrypt(&self.seed, password, &seed_network(&self.network))?;
        write_private_new(path, &encoded)
    }

    pub fn open(path: &Path, password: &[u8], expected: &Network) -> Result<Self> {
        validate_password(password)?;
        let bytes = read_private(path, 4096)?;
        Self::open_encrypted(&bytes, password, expected)
    }

    /// Authenticate exactly the bytes installed into a fresh wallet path.
    /// Copying the same authenticated ciphertext creates no new encryption and
    /// never reuses a nonce to encrypt a different plaintext. No KDF is reduced.
    pub fn restore(
        backup: &Path,
        path: &Path,
        password: &[u8],
        expected: &Network,
    ) -> Result<Self> {
        let bytes = read_private(backup, 4096)?;
        let wallet = Self::open_encrypted(&bytes, password, expected)?;
        write_private_new(path, &bytes)?;
        Ok(wallet)
    }

    fn open_encrypted(bytes: &[u8], password: &[u8], expected: &Network) -> Result<Self> {
        let seed = native_wallet_seed::decrypt(bytes, password, &seed_network(expected))?;
        if !bool::from(SpendingKey::from_bytes(*seed).is_some()) {
            return Err("invalid spending seed".into());
        }
        Ok(Self {
            seed,
            network: expected.clone(),
        })
    }

    pub fn address_text(&self) -> String {
        encode_address(&self.network, &self.receiving_address())
    }
}

pub(crate) fn derive(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    native_wallet_seed::derive(password, salt)
}

pub(crate) fn validate_password(password: &[u8]) -> Result<()> {
    native_wallet_seed::validate_password(password)?;
    Ok(())
}

pub fn read_password(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = read_private(path, 1024)?;
    validate_password(&bytes)?;
    Ok(bytes)
}

/// A bounded pipe avoids writing a web session password to a named disk file.
pub fn read_password_input(input: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    input.take(1025).read_to_end(&mut bytes)?;
    validate_password(&bytes)?;
    Ok(bytes)
}

pub fn read_private(path: &Path, maximum: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(
            "secret file must be a regular file readable only by its owner (mode 0600 or 0400)"
                .into(),
        );
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("secret file exceeds its size bound".into());
    }
    Ok(bytes)
}

pub fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}

pub fn encode_address(network: &Network, address: &Address) -> String {
    native_wallet_core::encode_address(network.network, &network.genesis_hash, address)
}
pub fn decode_address(network: &Network, text: &str) -> Result<Address> {
    native_wallet_core::decode_address(network.network, &network.genesis_hash, text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_signer::Signer;

    #[test]
    fn browser_vault_fixed_fixture_public_identity_reference() {
        // Public disposable fixture shared with the browser-vault parity test.
        // Print only public identity: never a seed, password or private key.
        let network = Network {
            network: [7; 32],
            genesis_hash: "1".repeat(32),
        };
        assert!(bool::from(SpendingKey::from_bytes([7; 32]).is_some()));
        let wallet = WalletKey {
            seed: Zeroizing::new([7; 32]),
            network: network.clone(),
        };
        println!(
            "{}",
            serde_json::json!({
                "fixture":"synthetic-public-vault-identity-v1", "network":network,
                "address":wallet.address_text(), "public_key":wallet.public_keypair().pubkey().to_string(),
                "fee_address":wallet.fee_keypair().pubkey().to_string(),
            })
        );
    }

    #[test]
    fn shared_seed_codec_opens_original_native_reference_envelope() {
        use chacha20poly1305::{
            aead::{Aead, Payload},
            KeyInit, XChaCha20Poly1305, XNonce,
        };
        #[derive(Serialize)]
        struct LegacyEnvelope {
            format: String,
            network: Network,
            rounds: u32,
            salt: [u8; 16],
            nonce: [u8; 24],
            ciphertext: Vec<u8>,
        }
        let network = Network {
            network: [71; 32],
            genesis_hash: bs58::encode([72; 32]).into_string(),
        };
        let original = WalletKey::generate(network.clone()).unwrap();
        let password = b"independent native compatibility fixture";
        let mut envelope = LegacyEnvelope {
            format: "native-wallet-seed-v1".into(),
            network: network.clone(),
            rounds: 600_000,
            salt: [3; 16],
            nonce: [4; 24],
            ciphertext: Vec::new(),
        };
        let aad = serde_json::to_vec(&(
            &envelope.format,
            &envelope.network,
            envelope.rounds,
            envelope.salt,
            envelope.nonce,
        ))
        .unwrap();
        let mut key = Zeroizing::new([0; 32]);
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, &envelope.salt, 600_000, &mut key[..]);
        envelope.ciphertext = XChaCha20Poly1305::new_from_slice(&key[..])
            .unwrap()
            .encrypt(
                &XNonce::from(envelope.nonce),
                Payload {
                    msg: &original.seed[..],
                    aad: &aad,
                },
            )
            .unwrap();
        let encoded = serde_json::to_vec_pretty(&envelope).unwrap();
        let restored = WalletKey::open_encrypted(&encoded, password, &network).unwrap();
        assert_eq!(restored.address_text(), original.address_text());
        assert_eq!(
            restored.public_keypair().pubkey(),
            original.public_keypair().pubkey()
        );
        assert_eq!(
            restored.fee_keypair().pubkey(),
            original.fee_keypair().pubkey()
        );
        assert_eq!(
            *native_wallet_seed::decrypt(&encoded, password, &seed_network(&network)).unwrap(),
            *original.seed
        );
    }

    #[test]
    fn authenticated_restore_installs_exact_ciphertext_and_never_publishes_invalid_seed() {
        let dir = tempfile::tempdir().unwrap();
        let network = Network {
            network: [31; 32],
            genesis_hash: bs58::encode([32; 32]).into_string(),
        };
        let wallet = WalletKey::generate(network.clone()).unwrap();
        let backup = dir.path().join("backup");
        let password = b"authenticated backup restore password";
        wallet.save(&backup, password).unwrap();
        let original = fs::read(&backup).unwrap();
        let target = dir.path().join("wallet");
        let restored = WalletKey::restore(&backup, &target, password, &network).unwrap();
        assert_eq!(restored.address_text(), wallet.address_text());
        assert_eq!(
            restored.fee_keypair().pubkey(),
            wallet.fee_keypair().pubkey()
        );
        assert_eq!(fs::read(&target).unwrap(), original);
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(WalletKey::restore(&backup, &target, password, &network).is_err());
        assert_eq!(fs::read(&target).unwrap(), original);
        let rejected = dir.path().join("rejected");
        assert!(
            WalletKey::restore(&backup, &rejected, b"a different wrong password", &network)
                .is_err()
        );
        assert!(!rejected.exists());
        let mut wrong = network.clone();
        wrong.network[0] ^= 1;
        assert!(WalletKey::restore(&backup, &rejected, password, &wrong).is_err());
        assert!(!rejected.exists());
        let mut envelope: serde_json::Value = serde_json::from_slice(&original).unwrap();
        envelope["ciphertext"][0] =
            serde_json::json!(envelope["ciphertext"][0].as_u64().unwrap() ^ 1);
        let corrupt = dir.path().join("corrupt");
        write_private_new(&corrupt, &serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(WalletKey::restore(&corrupt, &rejected, password, &network).is_err());
        assert!(!rejected.exists());
        assert_eq!(fs::read(&backup).unwrap(), original);
    }

    #[test]
    fn explicit_pool_profiles_preserve_the_serialized_network_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("network.json");
        let network = Network {
            network: [43; 32],
            genesis_hash: bs58::encode([44; 32]).into_string(),
        };
        for format in ["NPOOL003", "NPOOL004"] {
            let mut profile = serde_json::to_value(&network).unwrap();
            profile["pool_format"] = format.into();
            profile["program"] = native_payment_program::id().to_string().into();
            profile["pool"] = native_payment_program::pool_address().to_string().into();
            fs::write(&path, serde_json::to_vec(&profile).unwrap()).unwrap();
            let restored = Network::load(&path).unwrap();
            assert_eq!(restored, network);
            let identity = serde_json::to_value(&restored).unwrap();
            assert_eq!(identity.as_object().unwrap().len(), 2);
            assert!(identity.get("pool_format").is_none());
        }
    }

    #[test]
    fn encrypted_seed_restores_independent_network_bound_public_signing_authority() {
        let dir = tempfile::tempdir().unwrap();
        let network = Network {
            network: [5; 32],
            genesis_hash: bs58::encode([7; 32]).into_string(),
        };
        let wallet = WalletKey::generate(network.clone()).unwrap();
        let path = dir.path().join("backup");
        wallet
            .save(&path, b"public authority test password")
            .unwrap();
        let restored = WalletKey::open(&path, b"public authority test password", &network).unwrap();
        let key = restored.public_keypair();
        let fee = restored.fee_keypair();
        assert_eq!(fee.pubkey(), wallet.fee_keypair().pubkey());
        assert_ne!(fee.pubkey(), key.pubkey());
        assert!(fee
            .sign_message(b"user paid fees")
            .verify(fee.pubkey().as_ref(), b"user paid fees"));
        assert_eq!(key.pubkey(), wallet.public_keypair().pubkey());
        assert!(key
            .sign_message(b"user-controlled native account")
            .verify(key.pubkey().as_ref(), b"user-controlled native account"));
        let mut other = restored;
        other.network.network[0] ^= 1;
        assert_ne!(other.public_keypair().pubkey(), key.pubkey());
        assert_ne!(other.fee_keypair().pubkey(), fee.pubkey());
    }

    #[test]
    fn piped_passwords_are_bounded_even_without_end_of_input() {
        assert!(read_password_input(&b"too short"[..]).is_err());
        assert_eq!(read_password_input(&[b'x'; 1024][..]).unwrap().len(), 1024);
        assert!(read_password_input(std::io::repeat(b'x')).is_err());
    }

    #[test]
    fn seed_only_recovery_rejects_wrong_password_network_and_tampering() {
        let network = Network {
            network: [3; 32],
            genesis_hash: bs58::encode([5; 32]).into_string(),
        };
        let wallet = WalletKey::generate(network.clone()).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("encrypted-seed.json");
        wallet.save(&path, b"a unique local test password").unwrap();
        assert!(wallet.save(&path, b"a unique local test password").is_err());
        let restored = WalletKey::open(&path, b"a unique local test password", &network).unwrap();
        assert_eq!(restored.address_text(), wallet.address_text());
        assert!(WalletKey::open(&path, b"wrong local test password", &network).is_err());
        let other = Network {
            network: [4; 32],
            ..network.clone()
        };
        assert!(WalletKey::open(&path, b"a unique local test password", &other).is_err());
        assert!(decode_address(&other, &wallet.address_text()).is_err());
        let same_domain_other_genesis = Network {
            genesis_hash: bs58::encode([6; 32]).into_string(),
            ..network.clone()
        };
        assert!(decode_address(&same_domain_other_genesis, &wallet.address_text()).is_err());
        assert_eq!(
            decode_address(&network, &wallet.address_text())
                .unwrap()
                .to_raw_address_bytes(),
            wallet.receiving_address().to_raw_address_bytes()
        );
        let mut data: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        data["ciphertext"][0] = serde_json::json!(data["ciphertext"][0].as_u64().unwrap() ^ 1);
        fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(WalletKey::open(&path, b"a unique local test password", &network).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, 4096).is_err());
    }
}
