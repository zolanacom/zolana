//! Genesis-bound encrypted operator roles. Never exports cold roles as hot files.
use crate::{
    keys::{derive, read_private, validate_password, write_private_new, Network},
    Result,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use solana_keypair::Keypair;
use solana_signer::Signer;
use std::{collections::BTreeMap, path::Path};
use zeroize::Zeroizing;

const FORMAT: &str = "native-operator-vault-v1";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    network: Network,
    roles: BTreeMap<String, String>,
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
            &self.roles,
            self.rounds,
            self.salt,
            self.nonce,
        ))?)
    }
}

pub type Roles = BTreeMap<String, Keypair>;
pub fn public_roles(keys: &Roles) -> BTreeMap<String, String> {
    keys.iter()
        .map(|(name, key)| (name.clone(), key.pubkey().to_string()))
        .collect()
}
pub fn save(path: &Path, network: &Network, keys: &Roles, password: &[u8]) -> Result<()> {
    network.validate()?;
    validate_password(password)?;
    if keys.is_empty() || keys.len() > 32 {
        return Err("invalid operator role count".into());
    }
    let mut e = Envelope {
        format: FORMAT.into(),
        network: network.clone(),
        roles: public_roles(keys),
        rounds: 600_000,
        salt: rand::random(),
        nonce: rand::random(),
        ciphertext: vec![],
    };
    let secrets: Zeroizing<Vec<u8>> =
        Zeroizing::new(keys.values().flat_map(|key| key.to_bytes()).collect());
    let key = derive(password, &e.salt);
    e.ciphertext = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| "cipher initialization")?
        .encrypt(
            &XNonce::from(e.nonce),
            Payload {
                msg: &secrets,
                aad: &e.aad()?,
            },
        )
        .map_err(|_| "operator encryption failed")?;
    write_private_new(path, &serde_json::to_vec_pretty(&e)?)
}
pub fn open(path: &Path, network: &Network, password: &[u8]) -> Result<Roles> {
    network.validate()?;
    validate_password(password)?;
    let e: Envelope = serde_json::from_slice(&read_private(path, 32_768)?)?;
    if e.format != FORMAT
        || e.network != *network
        || e.rounds != 600_000
        || e.roles.is_empty()
        || e.roles.len() > 32
        || e.ciphertext.len() != e.roles.len() * 64 + 16
    {
        return Err("operator vault format/network mismatch".into());
    }
    let key = derive(password, &e.salt);
    let raw = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(&key[..])
            .map_err(|_| "cipher initialization")?
            .decrypt(
                &XNonce::from(e.nonce),
                Payload {
                    msg: &e.ciphertext,
                    aad: &e.aad()?,
                },
            )
            .map_err(|_| "incorrect operator password or modified vault")?,
    );
    e.roles
        .into_iter()
        .zip(raw.chunks_exact(64))
        .map(|((name, expected), secret)| {
            let key = Keypair::try_from(secret)?;
            if key.pubkey().to_string() != expected {
                return Err("operator role mismatch".into());
            }
            Ok((name, key))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_roles_bind_metadata_network_password_and_refuse_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault");
        let network = Network {
            network: [7; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        };
        let roles = Roles::from([
            ("sponsor".into(), Keypair::new()),
            ("treasury".into(), Keypair::new()),
        ]);
        let password = b"operator test password";
        save(&path, &network, &roles, password).unwrap();
        assert!(save(&path, &network, &roles, password).is_err());
        assert_eq!(
            public_roles(&open(&path, &network, password).unwrap()),
            public_roles(&roles)
        );
        assert!(open(&path, &network, b"different password").is_err());
        let mut other = network.clone();
        other.network[0] ^= 1;
        assert!(open(&path, &other, password).is_err());
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw
            .windows(64)
            .any(|part| part == roles["sponsor"].to_bytes()));
        let mut e: Envelope = serde_json::from_slice(&raw).unwrap();
        e.roles
            .insert("sponsor".into(), Keypair::new().pubkey().to_string());
        std::fs::write(&path, serde_json::to_vec(&e).unwrap()).unwrap();
        assert!(open(&path, &network, password).is_err());
    }
}
