//! Operator capability for loopback raw RPC. Never exported in tester profiles.
use std::{
    fs::OpenOptions,
    io::{self, Read},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
use subtle::ConstantTimeEq;

pub const HEADER: &str = "x-native-operator";
/// Validated operator material. It deliberately has no Debug implementation.
pub struct Credential {
    pub token: String,
    sockets: Option<std::collections::BTreeMap<u16, std::path::PathBuf>>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    token: String,
    sockets: std::collections::BTreeMap<u16, std::path::PathBuf>,
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "invalid private RPC transport material",
    )
}
/// Read bounded, private material without following a final symlink.
pub fn read_material(path: &Path) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.len() == 0
        || meta.len() > 4096
    {
        return Err(invalid());
    }
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(invalid());
    }
    Ok(bytes)
}
pub fn read_credential(path: &Path) -> io::Result<Credential> {
    let bytes = read_material(path)?;
    let (token, sockets) = if bytes.len() == 64 {
        (String::from_utf8(bytes).map_err(|_| invalid())?, None)
    } else {
        let doc: Document = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if doc.format != "native-rpc-unix-v1"
            || doc.sockets.is_empty()
            || doc.sockets.len() > 8
            || doc.sockets.contains_key(&0)
        {
            return Err(invalid());
        }
        for path in doc.sockets.values() {
            private_parent(path)?;
        }
        (doc.token, Some(doc.sockets))
    };
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(Credential { token, sockets })
}
pub fn read_token(path: &Path) -> io::Result<String> {
    Ok(read_credential(path)?.token)
}
impl Credential {
    /// Structured credentials can never fall back to TCP, even for an unknown port.
    pub fn socket(&self, port: u16) -> io::Result<Option<&Path>> {
        self.sockets
            .as_ref()
            .map(|paths| paths.get(&port).map(|p| p.as_path()).ok_or_else(invalid))
            .transpose()
    }
}
/// The socket lives in a canonical directory accessible only by this operator UID.
pub fn private_parent(path: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let parent = path.parent().ok_or_else(invalid)?;
    if !path.is_absolute()
        || path.as_os_str().as_bytes().len() >= 104
        || std::fs::canonicalize(parent)? != parent
    {
        return Err(invalid());
    }
    // A shared writable ancestor could let another UID rename the private
    // directory between a client's check and connect. Sticky directories keep
    // the child owner's rename protection (for example the system temp root).
    for ancestor in parent.ancestors() {
        let meta = std::fs::symlink_metadata(ancestor)?;
        if !meta.is_dir()
            || (meta.uid() != 0 && meta.uid() != unsafe { libc::geteuid() })
            || (meta.mode() & 0o022 != 0 && meta.mode() & 0o1000 == 0)
        {
            return Err(invalid());
        }
    }
    let meta = std::fs::symlink_metadata(parent)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(invalid());
    }
    Ok(())
}
/// Validate the filesystem boundary before an operator client connects.
pub fn check_socket(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    private_parent(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_socket()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        return Err(invalid());
    }
    Ok(())
}
/// Holds an exclusive lifetime lock and removes only the socket inode it created.
pub struct SocketGuard {
    path: std::path::PathBuf,
    inode: u64,
    device: u64,
    _lock: std::fs::File,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        if let Ok(meta) = std::fs::symlink_metadata(&self.path) {
            if meta.ino() == self.inode && meta.dev() == self.device {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}
pub fn bind_socket(path: &Path) -> io::Result<(std::os::unix::net::UnixListener, SocketGuard)> {
    use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
    private_parent(path)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path.with_extension("lock"))?;
    let meta = lock.metadata()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(invalid());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            check_socket(path)?;
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        "private RPC socket is live",
                    ))
                }
                Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                    std::fs::remove_file(path)?
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    let guard = SocketGuard {
        path: path.into(),
        inode: meta.ino(),
        device: meta.dev(),
        _lock: lock,
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    Ok((listener, guard))
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
    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::Builder::new()
            .prefix("rpc-")
            .tempdir_in("/private/tmp")
            .unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    #[test]
    fn socket_lifetime_lock_stale_recovery_and_inode_safe_cleanup() {
        let dir = private_dir();
        let path = dir.path().join("rpc.sock");
        let (listener, guard) = bind_socket(&path).unwrap();
        check_socket(&path).unwrap();
        assert!(bind_socket(&path).is_err());
        drop(listener);
        drop(guard);
        assert!(!path.exists());
        // SIGKILL leaves a socket pathname, but closes its listener and lock.
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (listener, guard) = bind_socket(&path).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"retain replacement").unwrap();
        drop(listener);
        drop(guard);
        assert_eq!(fs::read(&path).unwrap(), b"retain replacement");
        assert!(bind_socket(&path).is_err());
        fs::remove_file(&path).unwrap();
        symlink(dir.path().join("absent"), &path).unwrap();
        assert!(bind_socket(&path).is_err());
    }
    #[test]
    fn writable_ancestor_cannot_replace_the_private_socket_directory() {
        let dir = private_dir();
        let shared = dir.path().join("shared");
        let inner = shared.join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&inner, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(private_parent(&inner.join("rpc.sock")).is_err());
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o1777)).unwrap();
        private_parent(&inner.join("rpc.sock")).unwrap();
    }
    #[test]
    fn structured_credentials_pin_routes_and_refuse_permissions_or_transport_downgrade() {
        let dir = private_dir();
        let key = dir.path().join("key");
        let path = dir.path().join("rpc.sock");
        let doc = serde_json::json!({"format":"native-rpc-unix-v1","token":"a".repeat(64),"sockets":{"18899":path}});
        fs::write(&key, serde_json::to_vec(&doc).unwrap()).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let c = read_credential(&key).unwrap();
        assert_eq!(c.socket(18899).unwrap(), Some(path.as_path()));
        assert!(c.socket(19899).is_err());
        assert!(check_socket(&path).is_err());
        let (listener, guard) = bind_socket(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(check_socket(&path).is_err());
        drop(listener);
        drop(guard);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(read_credential(&key).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for bad in [
            serde_json::json!({"format":"native-rpc-unix-v1","token":"a".repeat(64)}),
            serde_json::json!({"format":"native-rpc-unix-v1","token":"a".repeat(64),"sockets":{}}),
        ] {
            fs::write(&key, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(read_credential(&key).is_err());
        }
    }
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
