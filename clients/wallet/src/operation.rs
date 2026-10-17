//! A process-lifetime exclusive lock for one wallet path and its recovery files.
use crate::Result;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub struct WalletOperation {
    _lock: File,
    pub(crate) pending: PathBuf,
    pub(crate) staging: PathBuf,
    pub(crate) scan_cache: PathBuf,
}

impl WalletOperation {
    pub fn acquire(wallet: &Path) -> Result<Self> {
        let suffix = |kind| PathBuf::from(format!("{}.{kind}", wallet.display()));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(suffix("lock"))?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 || meta.len() != 0 {
            return Err("wallet lock must be an empty owner-only regular file".into());
        }
        file.try_lock().map_err(|e| {
            format!("cannot lock wallet operation; another process may be using it: {e}")
        })?;
        Ok(Self {
            _lock: file,
            pending: suffix("pending.json"),
            staging: suffix("staging.json"),
            scan_cache: suffix("scan-cache"),
        })
    }

    pub fn ensure_resolved(&self) -> Result<()> {
        if self.pending.exists() {
            return Err("an unresolved payment exists; run resolve before sending again".into());
        }
        if self.staging.exists() {
            return Err(
                "an unfinished staging upload exists; run reclaim before sending again".into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::symlink};

    #[test]
    fn operation_lock_excludes_other_handles_and_releases_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("wallet");
        let first = WalletOperation::acquire(&path).unwrap();
        assert!(WalletOperation::acquire(&path).is_err());
        drop(first);
        assert!(WalletOperation::acquire(&path).is_ok());
        let lock = root.path().join("wallet.lock");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(WalletOperation::acquire(&path).is_err());
    }

    #[test]
    fn lock_does_not_follow_symlinks_or_reuse_nonempty_files() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("wallet");
        let target = root.path().join("private");
        fs::write(&target, b"preserve").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, root.path().join("wallet.lock")).unwrap();
        assert!(WalletOperation::acquire(&path).is_err());
        fs::remove_file(root.path().join("wallet.lock")).unwrap();
        fs::rename(&target, root.path().join("wallet.lock")).unwrap();
        assert!(WalletOperation::acquire(&path).is_err());
        assert_eq!(
            fs::read(root.path().join("wallet.lock")).unwrap(),
            b"preserve"
        );
    }
}
