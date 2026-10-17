use crate::Result;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
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

const ROUNDS: u32 = 600_000;
const FORMAT: &str = "native-wallet-seed-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub network: [u8; 32],
    pub genesis_hash: String,
}

impl Network {
    pub fn load(path: &Path) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_slice(&fs::read(path)?)?;
        if value["pool_format"] != "NPOOL003"
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

    fn validate(&self) -> Result<()> {
        if self.network == [0; 32] || bs58::decode(&self.genesis_hash).into_vec()?.len() != 32 {
            return Err("invalid network domain or genesis fingerprint".into());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    network: Network,
    rounds: u32,
    salt: [u8; 16],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl Envelope {
    fn aad(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.format,
            &self.network,
            self.rounds,
            self.salt,
            self.nonce,
        ))?)
    }
}

pub struct WalletKey {
    seed: Zeroizing<[u8; 32]>,
    pub network: Network,
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

    pub fn save(&self, path: &Path, password: &[u8]) -> Result<()> {
        validate_password(password)?;
        let mut envelope = Envelope {
            format: FORMAT.to_owned(),
            network: self.network.clone(),
            rounds: ROUNDS,
            salt: rand::random(),
            nonce: rand::random(),
            ciphertext: Vec::new(),
        };
        let key = derive(password, &envelope.salt);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| "key initialization failed")?;
        envelope.ciphertext = cipher
            .encrypt(
                &XNonce::from(envelope.nonce),
                Payload {
                    msg: &self.seed[..],
                    aad: &envelope.aad()?,
                },
            )
            .map_err(|_| "seed encryption failed")?;
        write_private_new(path, &serde_json::to_vec_pretty(&envelope)?)
    }

    pub fn open(path: &Path, password: &[u8], expected: &Network) -> Result<Self> {
        validate_password(password)?;
        let bytes = read_private(path, 4096)?;
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        if envelope.format != FORMAT
            || envelope.rounds != ROUNDS
            || envelope.ciphertext.len() != 48
            || &envelope.network != expected
        {
            return Err("seed format or network mismatch".into());
        }
        expected.validate()?;
        let key = derive(password, &envelope.salt);
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| "key initialization failed")?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    &XNonce::from(envelope.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &envelope.aad()?,
                    },
                )
                .map_err(|_| "password is incorrect or encrypted seed was modified")?,
        );
        let seed: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| "invalid seed length")?;
        if !bool::from(SpendingKey::from_bytes(seed).is_some()) {
            return Err("invalid spending seed".into());
        }
        Ok(Self {
            seed: Zeroizing::new(seed),
            network: expected.clone(),
        })
    }

    pub fn address_text(&self) -> String {
        encode_address(&self.network, &self.receiving_address())
    }
}

fn derive(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, salt, ROUNDS, &mut output[..]);
    output
}

fn validate_password(password: &[u8]) -> Result<()> {
    if !(12..=1024).contains(&password.len()) {
        return Err("password file must contain 12 to 1024 bytes".into());
    }
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
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(
            "secret file must be a regular file readable only by its owner (mode 0600 or 0400)"
                .into(),
        );
    }
    let mut bytes = Zeroizing::new(Vec::new());
    fs::File::open(path)?
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
    Ok(())
}

pub fn encode_address(network: &Network, address: &Address) -> String {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&network_tag(network));
    bytes.extend_from_slice(&address.to_raw_address_bytes());
    let checksum = blake2b_simd::blake2b(&bytes);
    bytes.extend_from_slice(&checksum.as_bytes()[..4]);
    format!("npriv1{}", bs58::encode(bytes).into_string())
}

pub fn decode_address(network: &Network, text: &str) -> Result<Address> {
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
        || bytes[1..33] != network_tag(network)
        || blake2b_simd::blake2b(&bytes[..76]).as_bytes()[..4] != bytes[76..]
    {
        return Err("receiving address checksum or network mismatch".into());
    }
    Option::from(Address::from_raw_address_bytes(
        &bytes[33..76].try_into().unwrap(),
    ))
    .ok_or_else(|| "invalid shielded address encoding".into())
}

fn network_tag(network: &Network) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"NPayWalletAddrV1")
        .to_state();
    state.update(&network.network);
    state.update(network.genesis_hash.as_bytes());
    state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("32-byte address domain")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut data: Envelope = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        data.ciphertext[0] ^= 1;
        fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(WalletKey::open(&path, b"a unique local test password", &network).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(&path, 4096).is_err());
    }
}
