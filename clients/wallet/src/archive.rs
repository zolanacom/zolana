//! Immutable, bounded public recovery history. Checksums are not consensus proofs.
use crate::{keys::Network, Result};
use serde::{Deserialize, Serialize};
use solana_transaction_status_client_types::{EncodedTransactionWithStatusMeta, UiConfirmedBlock};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const FORMAT: &str = "native-payment-history-v1";
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_SEGMENT: usize = 32 * 1024 * 1024;
const MAX_BLOCK: usize = 8 * 1024 * 1024;
const MAX_BLOCKS: usize = 1024;
const MAX_SEGMENTS: usize = 16384;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoryBlock {
    pub slot: u64,
    pub parent_slot: u64,
    pub blockhash: String,
    pub previous_blockhash: String,
    pub block_height: u64,
    pub transactions: Vec<EncodedTransactionWithStatusMeta>,
}
impl HistoryBlock {
    pub fn from_rpc(slot: u64, block: UiConfirmedBlock) -> Result<Self> {
        Ok(Self {
            slot,
            parent_slot: block.parent_slot,
            blockhash: block.blockhash,
            previous_blockhash: block.previous_blockhash,
            block_height: block
                .block_height
                .ok_or("archived block height is unavailable")?,
            transactions: block
                .transactions
                .ok_or("full transaction history is unavailable")?,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Segment {
    first_slot: u64,
    last_slot: u64,
    count: usize,
    digest: String,
}
impl Segment {
    fn filename(&self, index: usize) -> String {
        format!("segment-{index:08}-{}.json", self.digest)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    network: Network,
    segments: Vec<Segment>,
}

#[derive(Clone)]
pub(crate) struct Archive {
    root: PathBuf,
    manifest: Manifest,
}
impl Archive {
    pub fn open(root: &Path, network: &Network) -> Result<Self> {
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("history directory must be a real directory".into());
        }
        let manifest: Manifest =
            serde_json::from_slice(&read_bounded(&root.join("manifest.json"), MAX_MANIFEST)?)?;
        if manifest.format != FORMAT
            || manifest.network != *network
            || manifest.segments.len() > MAX_SEGMENTS
        {
            return Err("history format, network or segment bound mismatch".into());
        }
        let mut previous = 0;
        for segment in &manifest.segments {
            if segment.first_slot <= previous
                || segment.last_slot < segment.first_slot
                || segment.count == 0
                || segment.count > MAX_BLOCKS
                || segment.digest.len() != 64
                || !segment
                    .digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("invalid history segment descriptor".into());
            }
            previous = segment.last_slot;
        }
        Ok(Self {
            root: root.to_owned(),
            manifest,
        })
    }
    pub fn tip(&self) -> u64 {
        self.manifest
            .segments
            .last()
            .map_or(0, |segment| segment.last_slot)
    }
    pub fn reader(&self) -> Reader<'_> {
        Reader {
            archive: self,
            index: 0,
            pending: Vec::new().into_iter(),
            previous: 0,
            hash: None,
            failed: false,
        }
    }
}

pub(crate) struct Reader<'a> {
    archive: &'a Archive,
    index: usize,
    pending: std::vec::IntoIter<HistoryBlock>,
    previous: u64,
    hash: Option<String>,
    failed: bool,
}
impl Reader<'_> {
    fn next_block(&mut self) -> Result<Option<HistoryBlock>> {
        if self.pending.len() == 0 {
            let Some(segment) = self.archive.manifest.segments.get(self.index) else {
                return Ok(None);
            };
            let bytes = read_bounded(
                &self.archive.root.join(segment.filename(self.index)),
                MAX_SEGMENT,
            )?;
            if digest(&bytes) != segment.digest {
                return Err("history segment checksum mismatch".into());
            }
            let blocks: Vec<HistoryBlock> = serde_json::from_slice(&bytes)?;
            if blocks.len() != segment.count
                || blocks.first().map(|block| block.slot) != Some(segment.first_slot)
                || blocks.last().map(|block| block.slot) != Some(segment.last_slot)
            {
                return Err("history segment count or boundary mismatch".into());
            }
            self.pending = blocks.into_iter();
            self.index += 1;
        }
        let block = self.pending.next().ok_or("empty history segment")?;
        if block.slot <= self.previous
            || block.parent_slot != self.previous
            || self
                .hash
                .as_ref()
                .is_some_and(|hash| hash != &block.previous_blockhash)
            || !valid_hash(&block.blockhash)
            || !valid_hash(&block.previous_blockhash)
            || serde_json::to_vec(&block)?.len() > MAX_BLOCK
        {
            return Err("history block chain is incomplete or discontinuous".into());
        }
        self.previous = block.slot;
        self.hash = Some(block.blockhash.clone());
        Ok(Some(block))
    }
}
impl Iterator for Reader<'_> {
    type Item = Result<HistoryBlock>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        match self.next_block() {
            Ok(Some(block)) => Some(Ok(block)),
            Ok(None) => None,
            Err(error) => {
                self.failed = true;
                Some(Err(error))
            }
        }
    }
}

pub(crate) struct Writer {
    _lock: File,
    pub archive: Archive,
    segments: Vec<Segment>,
    pending: Vec<HistoryBlock>,
    bytes: usize,
    pub bytes_written: usize,
}
impl Writer {
    pub fn open(root: &Path, network: &Network) -> Result<Self> {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0
        {
            return Err("history writer needs an owner-only real directory".into());
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(root.join(".writer.lock"))?;
        let meta = lock.metadata()?;
        if !meta.is_file() || meta.len() != 0 || meta.permissions().mode() & 0o077 != 0 {
            return Err("invalid history writer lock".into());
        }
        lock.try_lock()
            .map_err(|_| "another history writer is active")?;
        let archive = if root.join("manifest.json").try_exists()? {
            Archive::open(root, network)?
        } else {
            Archive {
                root: root.to_owned(),
                manifest: Manifest {
                    format: FORMAT.into(),
                    network: network.clone(),
                    segments: Vec::new(),
                },
            }
        };
        Ok(Self {
            _lock: lock,
            segments: archive.manifest.segments.clone(),
            archive,
            pending: Vec::new(),
            bytes: 2,
            bytes_written: 0,
        })
    }
    pub fn push(&mut self, block: HistoryBlock) -> Result<()> {
        let bytes = serde_json::to_vec(&block)?.len() + 1;
        if bytes > MAX_BLOCK {
            return Err("native history block exceeds storage bound".into());
        }
        if self.pending.len() == MAX_BLOCKS || self.bytes + bytes > MAX_SEGMENT {
            self.flush()?;
        }
        self.bytes += bytes;
        self.pending.push(block);
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        if self.segments.len() == MAX_SEGMENTS {
            return Err("history segment capacity reached".into());
        }
        let bytes = serde_json::to_vec(&self.pending)?;
        if bytes.len() > MAX_SEGMENT {
            return Err("history segment exceeds storage bound".into());
        }
        let segment = Segment {
            first_slot: self.pending[0].slot,
            last_slot: self.pending.last().unwrap().slot,
            count: self.pending.len(),
            digest: digest(&bytes),
        };
        let path = self
            .archive
            .root
            .join(segment.filename(self.segments.len()));
        let temporary = self
            .archive
            .root
            .join(format!(".segment-{:032x}.tmp", rand::random::<u128>()));
        let mut created = false;
        let published = (|| -> Result<bool> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)?;
            created = true;
            file.write_all(&bytes)?;
            file.sync_all()?;
            // Publish a fully synced immutable payload in one step. Crashes
            // during writing leave only unreferenced temporary files.
            match fs::hard_link(&temporary, &path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if read_bounded(&path, MAX_SEGMENT)? != bytes {
                        return Err(
                            "interrupted history segment differs; refusing overwrite".into()
                        );
                    }
                    Ok(false)
                }
                Err(error) => Err(error.into()),
            }
        })();
        if created {
            let _ = fs::remove_file(&temporary);
        }
        if published? {
            self.bytes_written += bytes.len();
        }
        self.segments.push(segment);
        self.pending.clear();
        self.bytes = 2;
        Ok(())
    }
    // Caller must first verify the complete extension against finalized RPC state.
    pub fn commit(mut self) -> Result<usize> {
        self.flush()?;
        let manifest = Manifest {
            segments: self.segments,
            ..self.archive.manifest.clone()
        };
        let bytes = serde_json::to_vec(&manifest)?;
        if bytes.len() > MAX_MANIFEST {
            return Err("history manifest exceeds storage bound".into());
        }
        let temporary = self
            .archive
            .root
            .join(format!(".manifest-{:032x}.tmp", rand::random::<u128>()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, self.archive.root.join("manifest.json"))?;
            File::open(&self.archive.root)?.sync_all()?;
            Ok(())
        })();
        if temporary.exists() {
            let _ = fs::remove_file(temporary);
        }
        result?;
        Ok(self.bytes_written)
    }
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > maximum as u64 {
        return Err("history file type or size bound mismatch".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > maximum {
        return Err("history file exceeds size bound".into());
    }
    Ok(bytes)
}
pub(crate) fn valid_hash(hash: &str) -> bool {
    hash.len() <= 44
        && bs58::decode(hash)
            .into_vec()
            .is_ok_and(|bytes| bytes.len() == 32)
}
fn digest(bytes: &[u8]) -> String {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"NPayArchiveV1")
        .hash(bytes)
        .to_hex()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network() -> Network {
        Network {
            network: [9; 32],
            genesis_hash: bs58::encode([8; 32]).into_string(),
        }
    }
    fn block(slot: u64, parent: u64) -> HistoryBlock {
        HistoryBlock {
            slot,
            parent_slot: parent,
            blockhash: bs58::encode([slot as u8; 32]).into_string(),
            previous_blockhash: bs58::encode([parent as u8; 32]).into_string(),
            block_height: slot,
            transactions: Vec::new(),
        }
    }

    #[test]
    fn immutable_segments_resume_after_interruption_without_publishing_partial_history() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("history");
        let network = network();
        let mut first = Writer::open(&path, &network).unwrap();
        assert!(Writer::open(&path, &network).is_err());
        first.push(block(1, 0)).unwrap();
        first.flush().unwrap();
        assert!(Archive::open(&path, &network).is_err());
        first.commit().unwrap();
        let manifest = fs::read(path.join("manifest.json")).unwrap();
        let mut interrupted = Writer::open(&path, &network).unwrap();
        interrupted.push(block(3, 1)).unwrap();
        interrupted.flush().unwrap();
        drop(interrupted);
        fs::write(
            path.join(".segment-interrupted.tmp"),
            b"incomplete unrelated write",
        )
        .unwrap();
        assert_eq!(fs::read(path.join("manifest.json")).unwrap(), manifest);
        assert_eq!(
            Archive::open(&path, &network)
                .unwrap()
                .reader()
                .collect::<Result<Vec<_>>>()
                .unwrap()
                .len(),
            1
        );
        let mut resumed = Writer::open(&path, &network).unwrap();
        resumed.push(block(3, 1)).unwrap();
        assert_eq!(
            resumed.commit().unwrap(),
            0,
            "reuse the identical already-synced orphan"
        );
        let archive = Archive::open(&path, &network).unwrap();
        assert_eq!(archive.tip(), 3);
        assert_eq!(
            archive.reader().collect::<Result<Vec<_>>>().unwrap().len(),
            2
        );
    }

    #[test]
    fn damaged_missing_symlinked_or_mismatched_history_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("history");
        let network = network();
        let mut writer = Writer::open(&path, &network).unwrap();
        writer.push(block(1, 0)).unwrap();
        writer.commit().unwrap();
        let archive = Archive::open(&path, &network).unwrap();
        let mut wrong = network.clone();
        wrong.network[0] ^= 1;
        assert!(Archive::open(&path, &wrong).is_err());
        let segment = path.join(archive.manifest.segments[0].filename(0));
        let original = fs::read(&segment).unwrap();
        fs::write(&segment, b"modified").unwrap();
        assert!(archive.reader().next().unwrap().is_err());
        fs::remove_file(&segment).unwrap();
        assert!(archive.reader().next().unwrap().is_err());
        let target = root.path().join("original");
        fs::write(&target, original).unwrap();
        std::os::unix::fs::symlink(&target, &segment).unwrap();
        assert!(archive.reader().next().unwrap().is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Writer::open(&path, &network).is_err());
        let manifest = path.join("manifest.json");
        OpenOptions::new()
            .write(true)
            .open(&manifest)
            .unwrap()
            .set_len((MAX_MANIFEST + 1) as u64)
            .unwrap();
        assert!(Archive::open(&path, &network).is_err());
    }

    #[test]
    fn checksums_do_not_allow_discontinuous_or_unbounded_descriptors() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("history");
        let network = network();
        let mut writer = Writer::open(&path, &network).unwrap();
        writer.push(block(1, 0)).unwrap();
        writer.push(block(3, 2)).unwrap();
        writer.commit().unwrap();
        let archive = Archive::open(&path, &network).unwrap();
        let mut reader = archive.reader();
        assert!(reader.next().unwrap().is_ok());
        assert!(reader.next().unwrap().is_err());
        assert!(reader.next().is_none());
        let mut manifest = archive.manifest;
        manifest.segments[0].digest = "../".repeat(22);
        fs::write(
            path.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert!(Archive::open(&path, &network).is_err());
    }
}
