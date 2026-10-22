//! Platform-neutral codec for the existing native encrypted seed envelope.
//!
//! No filesystem, Orchard, RPC, password persistence or wallet migration. This
//! codec authenticates exactly 32 seed bytes; callers validate their key scheme.
//! Production encryption always obtains a fresh salt and nonce from the OS/
//! browser-compatible rand backend. Deterministic nonce injection is test-only.
#![forbid(unsafe_code)]

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

pub const FORMAT: &str = "native-wallet-seed-v1";
pub const ROUNDS: u32 = 600_000;
pub const MAX_ENCRYPTED_BYTES: usize = 4096;

/// Field order and representation are part of the existing envelope's AAD.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Network {
    pub network: [u8; 32],
    pub genesis_hash: String,
}

impl Network {
    pub fn validate(&self) -> Result<()> {
        if self.network == [0; 32]
            || !(32..=44).contains(&self.genesis_hash.len())
            || bs58::decode(&self.genesis_hash)
                .into_vec()
                .map_or(true, |bytes| bytes.len() != 32)
        {
            return Err(Error::InvalidNetwork);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidPassword,
    InvalidNetwork,
    EnvelopeTooLarge,
    InvalidEnvelope,
    FormatOrNetworkMismatch,
    Authentication,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPassword => "password file must contain 12 to 1024 bytes",
            Self::InvalidNetwork => "invalid network domain or genesis fingerprint",
            Self::EnvelopeTooLarge => "encrypted seed exceeds its size bound",
            Self::InvalidEnvelope => "invalid encrypted seed envelope",
            Self::FormatOrNetworkMismatch => "seed format or network mismatch",
            Self::Authentication => "password is incorrect or encrypted seed was modified",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

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
        serde_json::to_vec(&(
            &self.format,
            &self.network,
            self.rounds,
            self.salt,
            self.nonce,
        ))
        .map_err(|_| Error::InvalidEnvelope)
    }
}

pub fn validate_password(password: &[u8]) -> Result<()> {
    if !(12..=1024).contains(&password.len()) {
        return Err(Error::InvalidPassword);
    }
    Ok(())
}

/// Fixed legacy KDF, also reused by the existing native operator-vault codec.
/// This deliberately exposes no tunable work factor or encryption nonce.
pub fn derive(password: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut output = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(password, salt, ROUNDS, &mut output[..]);
    output
}

pub fn encrypt(seed: &[u8; 32], password: &[u8], network: &Network) -> Result<Vec<u8>> {
    validate_password(password)?;
    network.validate()?;
    let envelope = Envelope {
        format: FORMAT.to_owned(),
        network: network.clone(),
        rounds: ROUNDS,
        salt: rand::random(),
        nonce: rand::random(),
        ciphertext: Vec::new(),
    };
    encrypt_envelope(seed, password, envelope)
}

fn encrypt_envelope(seed: &[u8; 32], password: &[u8], mut envelope: Envelope) -> Result<Vec<u8>> {
    let key = derive(password, &envelope.salt);
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| Error::InvalidEnvelope)?;
    envelope.ciphertext = cipher
        .encrypt(
            &XNonce::from(envelope.nonce),
            Payload {
                msg: seed,
                aad: &envelope.aad()?,
            },
        )
        .map_err(|_| Error::InvalidEnvelope)?;
    let encoded = serde_json::to_vec_pretty(&envelope).map_err(|_| Error::InvalidEnvelope)?;
    if encoded.len() > MAX_ENCRYPTED_BYTES {
        return Err(Error::EnvelopeTooLarge);
    }
    Ok(encoded)
}

/// Authenticate a bounded encrypted native backup without altering its bytes.
/// The returned zeroizing seed is not yet an Orchard SpendingKey validation.
pub fn decrypt(bytes: &[u8], password: &[u8], expected: &Network) -> Result<Zeroizing<[u8; 32]>> {
    validate_password(password)?;
    if bytes.len() > MAX_ENCRYPTED_BYTES {
        return Err(Error::EnvelopeTooLarge);
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::InvalidEnvelope)?;
    if envelope.format != FORMAT
        || envelope.rounds != ROUNDS
        || envelope.ciphertext.len() != 48
        || &envelope.network != expected
    {
        return Err(Error::FormatOrNetworkMismatch);
    }
    expected.validate()?;
    let key = derive(password, &envelope.salt);
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| Error::InvalidEnvelope)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &envelope.aad()?,
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let seed: [u8; 32] = plain
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidEnvelope)?;
    Ok(Zeroizing::new(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &[u8] = b"native codec fixture password";
    const SEED: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    const SALT: [u8; 16] = [
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    ];
    const NONCE: [u8; 24] = [
        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
        55,
    ];
    // Independently generated by tests/fixture_reference.py using OpenSSL-backed
    // cryptography, after verifying the published HChaCha20 block test vector.
    const CIPHERTEXT: [u8; 48] = [
        245, 128, 94, 189, 91, 104, 255, 177, 72, 142, 15, 241, 102, 217, 98, 20, 231, 170, 153,
        34, 209, 21, 197, 162, 224, 85, 97, 137, 9, 239, 78, 50, 190, 77, 32, 120, 69, 110, 142,
        22, 156, 165, 114, 17, 246, 105, 102, 149,
    ];
    // Frozen compact serde tuple used by the pre-extraction native implementation.
    const AAD: &str =
        concat!("[\"native-wallet-seed-v1\",{\"network\":[7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,",
        "7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7],\"genesis_hash\":\"11111111111111111111111111111111\"},",
        "600000,[16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],",
        "[32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55]]");

    fn network() -> Network {
        Network {
            network: [7; 32],
            genesis_hash: "1".repeat(32),
        }
    }
    fn deterministic() -> Vec<u8> {
        encrypt_envelope(
            &SEED,
            PASSWORD,
            Envelope {
                format: FORMAT.into(),
                network: network(),
                rounds: ROUNDS,
                salt: SALT,
                nonce: NONCE,
                ciphertext: Vec::new(),
            },
        )
        .unwrap()
    }
    fn mutated(bytes: &[u8], update: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        update(&mut value);
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn frozen_aad_and_independent_legacy_cipher_reference_match_exact_bytes() {
        let encoded = deterministic();
        let envelope: Envelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(envelope.aad().unwrap(), AAD.as_bytes());
        assert_eq!(envelope.ciphertext, CIPHERTEXT);
        let fixed_key: String = derive(PASSWORD, &SALT)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            fixed_key,
            "38719be52e3a28e54fbde58c22b0c4d4ce0e9a476b8032cbb58149cf45a82679"
        );
        // Old implementation independently assembled the same JSON and invoked
        // the cipher. Deliberately do not call the codec's derive/AAD methods.
        let mut key = Zeroizing::new([0; 32]);
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(PASSWORD, &SALT, 600_000, &mut key[..]);
        let ciphertext = XChaCha20Poly1305::new_from_slice(&key[..])
            .unwrap()
            .encrypt(
                &XNonce::from(NONCE),
                Payload {
                    msg: &SEED,
                    aad: AAD.as_bytes(),
                },
            )
            .unwrap();
        assert_eq!(envelope.ciphertext, ciphertext);
        assert_eq!(*decrypt(&encoded, PASSWORD, &network()).unwrap(), SEED);
        assert_eq!(serde_json::to_vec_pretty(&envelope).unwrap(), encoded);
    }

    #[test]
    fn production_encryption_uses_fresh_salt_nonce_and_reciprocal_decode() {
        let first = encrypt(&SEED, PASSWORD, &network()).unwrap();
        let second = encrypt(&SEED, PASSWORD, &network()).unwrap();
        let a: Envelope = serde_json::from_slice(&first).unwrap();
        let b: Envelope = serde_json::from_slice(&second).unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(first, second);
        assert_eq!(*decrypt(&first, PASSWORD, &network()).unwrap(), SEED);
        assert_eq!(*decrypt(&second, PASSWORD, &network()).unwrap(), SEED);
    }

    #[test]
    fn wrong_password_domain_genesis_and_ciphertext_are_rejected() {
        let bytes = deterministic();
        assert_eq!(
            decrypt(&bytes, b"wrong fixture password", &network()).unwrap_err(),
            Error::Authentication
        );
        let mut wrong = network();
        wrong.network[0] ^= 1;
        assert_eq!(
            decrypt(&bytes, PASSWORD, &wrong).unwrap_err(),
            Error::FormatOrNetworkMismatch
        );
        wrong = network();
        wrong.genesis_hash = bs58::encode([8; 32]).into_string();
        assert_eq!(
            decrypt(&bytes, PASSWORD, &wrong).unwrap_err(),
            Error::FormatOrNetworkMismatch
        );
        for field in ["ciphertext", "salt", "nonce"] {
            let bad = mutated(&bytes, |value| {
                value[field][0] = serde_json::json!(value[field][0].as_u64().unwrap() ^ 1)
            });
            assert_eq!(
                decrypt(&bad, PASSWORD, &network()).unwrap_err(),
                Error::Authentication
            );
        }
    }

    #[test]
    fn kdf_parameters_format_lengths_and_unknown_fields_cannot_be_downgraded() {
        let bytes = deterministic();
        for rounds in [0, 1, 599_999, 600_001, u32::MAX] {
            let bad = mutated(&bytes, |value| value["rounds"] = rounds.into());
            assert_eq!(
                decrypt(&bad, PASSWORD, &network()).unwrap_err(),
                Error::FormatOrNetworkMismatch
            );
        }
        for update in [
            ("format", serde_json::json!("native-wallet-seed-v0")),
            ("ciphertext", serde_json::json!(vec![0u8; 47])),
            ("extra", serde_json::json!(true)),
            ("salt", serde_json::json!(vec![0u8; 15])),
            ("nonce", serde_json::json!(vec![0u8; 23])),
        ] {
            assert!(decrypt(
                &mutated(&bytes, |value| value[update.0] = update.1),
                PASSWORD,
                &network()
            )
            .is_err());
        }
        let duplicate = String::from_utf8(bytes).unwrap().replacen(
            "{",
            "{\"format\":\"native-wallet-seed-v1\",",
            1,
        );
        assert_eq!(
            decrypt(duplicate.as_bytes(), PASSWORD, &network()).unwrap_err(),
            Error::InvalidEnvelope
        );
    }

    #[test]
    fn byte_inputs_and_passwords_are_bounded_before_crypto() {
        assert_eq!(
            decrypt(&[b' '; 4097], PASSWORD, &network()).unwrap_err(),
            Error::EnvelopeTooLarge
        );
        assert_eq!(
            decrypt(&[], PASSWORD, &network()).unwrap_err(),
            Error::InvalidEnvelope
        );
        for password in [&b"short"[..], &[0; 1025][..]] {
            assert_eq!(
                encrypt(&SEED, password, &network()).unwrap_err(),
                Error::InvalidPassword
            );
            assert_eq!(
                decrypt(&[], password, &network()).unwrap_err(),
                Error::InvalidPassword
            );
        }
        assert!(validate_password(&[0; 12]).is_ok());
        assert!(validate_password(&[0; 1024]).is_ok());
        let invalid = Network {
            network: [0; 32],
            ..network()
        };
        assert_eq!(
            encrypt(&SEED, PASSWORD, &invalid).unwrap_err(),
            Error::InvalidNetwork
        );
    }
}
