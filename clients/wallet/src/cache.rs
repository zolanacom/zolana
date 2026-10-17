//! Disposable encrypted scan checkpoints; seed recovery never requires this file.
use crate::{
    history::ReplaySnapshot,
    keys::{Network, WalletKey},
    Result,
};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"NSCAN001";
const MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Checkpoint {
    pub network: Network,
    pub address: String,
    pub slot: u64,
    pub block_hash: Option<String>,
    pub block_height: u64,
    pub accepted: BTreeSet<String>,
    pub replay: ReplaySnapshot,
}

pub(crate) fn read(path: &Path, wallet: &WalletKey) -> Result<Checkpoint> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.permissions().mode() & 0o077 != 0
        || meta.len() > (MAX_BYTES + 48) as u64
    {
        return Err("scan cache must be a bounded owner-only regular file".into());
    }
    let mut encoded = Vec::new();
    (&mut file)
        .take((MAX_BYTES + 49) as u64)
        .read_to_end(&mut encoded)?;
    if encoded.len() < 48 || encoded.len() > MAX_BYTES + 48 || &encoded[..8] != MAGIC {
        return Err("invalid scan cache envelope".into());
    }
    let key = wallet.scan_cache_key();
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| "cache key initialization failed")?;
    let nonce: [u8; 24] = encoded[8..32].try_into()?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &encoded[32..],
                    aad: MAGIC,
                },
            )
            .map_err(|_| "scan cache authentication failed")?,
    );
    let checkpoint: Checkpoint = serde_json::from_slice(&plain)?;
    if checkpoint.network != wallet.network
        || checkpoint.address != wallet.address_text()
        || (checkpoint.slot == 0) != checkpoint.block_hash.is_none()
        || checkpoint.block_hash.as_ref().is_some_and(|hash| {
            bs58::decode(hash)
                .into_vec()
                .map_or(true, |bytes| bytes.len() != 32)
        })
    {
        return Err("scan cache network, wallet or checkpoint mismatch".into());
    }
    Ok(checkpoint)
}

pub(crate) fn write(path: &Path, wallet: &WalletKey, checkpoint: &Checkpoint) -> Result<()> {
    let plain = Zeroizing::new(serde_json::to_vec(checkpoint)?);
    if plain.len() > MAX_BYTES {
        return Err("scan cache exceeds its size bound".into());
    }
    let nonce: [u8; 24] = rand::random();
    let key = wallet.scan_cache_key();
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| "cache key initialization failed")?;
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plain,
                aad: MAGIC,
            },
        )
        .map_err(|_| "scan cache encryption failed")?;
    let temporary = path.with_extension(format!("cache-{:032x}.tmp", rand::random::<u128>()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(MAGIC)?;
        file.write_all(&nonce)?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if temporary.exists() {
        let _ = fs::remove_file(temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::Replay;

    fn fixture() -> (WalletKey, Checkpoint) {
        let network = Network {
            network: [19; 32],
            genesis_hash: bs58::encode([18; 32]).into_string(),
        };
        let wallet = WalletKey::generate(network.clone()).unwrap();
        let checkpoint = Checkpoint {
            network,
            address: wallet.address_text(),
            slot: 42,
            block_hash: Some(bs58::encode([17; 32]).into_string()),
            block_height: 40,
            accepted: BTreeSet::from(["private-cache-test-marker".into()]),
            replay: Replay::new(&wallet, 1000).unwrap().snapshot(),
        };
        (wallet, checkpoint)
    }

    #[test]
    fn encrypted_checkpoint_is_bound_to_wallet_network_and_complete_ciphertext() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.scan-cache");
        let (wallet, checkpoint) = fixture();
        write(&path, &wallet, &checkpoint).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(!original
            .windows(checkpoint.address.len())
            .any(|bytes| bytes == checkpoint.address.as_bytes()));
        assert!(!original
            .windows(25)
            .any(|bytes| bytes == b"private-cache-test-marker"));
        let decoded = read(&path, &wallet).unwrap();
        assert_eq!(decoded.slot, 42);
        assert_eq!(decoded.accepted, checkpoint.accepted);
        let mut other = WalletKey::generate(wallet.network.clone()).unwrap();
        assert!(read(&path, &other).is_err());
        other.network.network[0] ^= 1;
        assert!(read(&path, &other).is_err());
        let mut modified = original.clone();
        let last = modified.len() - 1;
        modified[last] ^= 1;
        fs::write(&path, modified).unwrap();
        assert!(read(&path, &wallet).is_err());
        fs::write(&path, &original[..40]).unwrap();
        assert!(read(&path, &wallet).is_err());
        write(&path, &wallet, &checkpoint).unwrap();
        assert!(read(&path, &wallet).is_ok());
        assert_ne!(original, fs::read(&path).unwrap());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
        // A bare wallet filename still needs the current directory synced.
        let bare = tempfile::NamedTempFile::new_in(".").unwrap();
        let relative = Path::new(bare.path().file_name().unwrap());
        write(relative, &wallet, &checkpoint).unwrap();
        assert_eq!(read(relative, &wallet).unwrap().slot, 42);
    }

    #[test]
    fn unsafe_files_and_inconsistent_authenticated_metadata_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wallet.scan-cache");
        let link = directory.path().join("link");
        let (wallet, mut checkpoint) = fixture();
        write(&path, &wallet, &checkpoint).unwrap();
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read(&link, &wallet).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&path, &wallet).is_err());
        write(&path, &wallet, &checkpoint).unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len((MAX_BYTES + 49) as u64)
            .unwrap();
        assert!(read(&path, &wallet).is_err());
        checkpoint.block_hash = None;
        write(&path, &wallet, &checkpoint).unwrap();
        assert!(read(&path, &wallet).is_err());
        checkpoint.slot = 0;
        checkpoint.address.push('x');
        write(&path, &wallet, &checkpoint).unwrap();
        assert!(read(&path, &wallet).is_err());
    }
}
