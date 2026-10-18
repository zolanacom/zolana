//! Operator capability for loopback raw RPC. Never exported in tester profiles.
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use subtle::ConstantTimeEq;

pub const HEADER: &str = "x-native-operator";
pub fn read_token(path: &Path) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.len() != 64
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "raw RPC credential must be an owner-only 64-byte regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(65).read_to_end(&mut bytes)?;
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid raw RPC credential",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid raw RPC credential"))
}
pub fn token_matches(expected: &str, supplied: &[u8]) -> bool {
    supplied.len() == 64 && expected.as_bytes().ct_eq(supplied).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };
    #[test]
    fn private_capability_refuses_missing_shared_symlinked_and_malformed_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        assert!(read_token(&path).is_err());
        fs::write(&path, "a".repeat(64)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let token = read_token(&path).unwrap();
        assert!(token_matches(&token, token.as_bytes()));
        assert!(!token_matches(&token, b"bad"));
        assert!(!token_matches(&token, "b".repeat(64).as_bytes()));
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_token(&link).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        for text in [
            "a".repeat(63),
            "a".repeat(65),
            "x".repeat(64),
            "A".repeat(64),
        ] {
            fs::write(&path, text).unwrap();
            assert!(read_token(&path).is_err());
        }
        assert!(read_token(dir.path()).is_err());
    }
}
