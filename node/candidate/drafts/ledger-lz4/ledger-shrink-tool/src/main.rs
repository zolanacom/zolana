//! zolana-ledger-shrink: offline, content-verified LZ4 rewrite of a STOPPED blockstore.
//!
//! What it does (`shrink`):
//!   1. opens the RocksDB directory read-only and records, for every column family,
//!      the number of entries and a SHA-256 over every key and value;
//!   2. opens it read-write with automatic compactions disabled and LZ4 selected for
//!      the chosen column families, then runs one forced full manual compaction per
//!      chosen column family (no compaction filter is installed, nothing is deleted);
//!   3. reopens read-only, recomputes the same digests and requires them to be
//!      identical for EVERY column family, and requires every SST file of the chosen
//!      column families to carry the LZ4 table property;
//!   4. writes a JSON receipt and exits 0 only if all of that held.
//!
//! It never creates a database, never drops a column family and never deletes a key.
//! The column-family tuning mirrors Agave 4.3.2 `get_cf_options`
//! (ledger/src/blockstore_db.rs:1200-1234) so files it writes have the usual shape.
use rocksdb::{
    BottommostLevelCompaction, ColumnFamilyDescriptor, CompactOptions, DBCompressionType,
    IteratorMode, Options, DB,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

const VERSION: &str = "zolana-ledger-shrink-0.1.0";
const MAX_WRITE_BUFFER_SIZE: u64 = 256 * 1024 * 1024;
/// Column families rewritten by default. All are keyed by slot and never use a
/// compaction filter (ledger/src/blockstore_db.rs:1316-1339).
const DEFAULT_TARGETS: [&str; 7] = [
    "data_shred",
    "code_shred",
    "index",
    "meta",
    "alt_data_shred",
    "alt_index",
    "alt_meta",
];

type Failure = Box<dyn std::error::Error>;

fn fail<T>(message: impl Into<String>) -> Result<T, Failure> {
    Err(message.into().into())
}

fn cf_options(compression: DBCompressionType) -> Options {
    let mut options = Options::default();
    options.set_max_write_buffer_number(8);
    options.set_write_buffer_size(MAX_WRITE_BUFFER_SIZE as usize);
    let trigger = 4u64;
    let total = MAX_WRITE_BUFFER_SIZE * trigger;
    options.set_level_zero_file_num_compaction_trigger(trigger as i32);
    options.set_max_bytes_for_level_base(total);
    options.set_target_file_size_base(total / 10);
    // Maintenance access: nothing may be rewritten except by the explicit request below.
    options.set_disable_auto_compactions(true);
    options.set_compression_type(compression);
    options
}

fn db_options(threads: i32, subcompactions: u32) -> Options {
    let mut options = Options::default();
    options.create_if_missing(false);
    options.create_missing_column_families(false);
    #[allow(deprecated)]
    {
        options.set_max_background_compactions(threads);
        options.set_max_background_flushes(2);
    }
    options.set_max_total_wal_size(4 * 1024 * 1024 * 1024);
    options.set_disable_auto_compactions(true);
    if subcompactions > 1 {
        options.set_max_subcompactions(subcompactions);
    }
    options.set_max_log_file_size(50 * 1024 * 1024);
    options.set_keep_log_file_num(10);
    options.set_max_open_files(-1);
    options
}

fn column_families(path: &Path) -> Result<Vec<String>, Failure> {
    Ok(DB::list_cf(&Options::default(), path)?)
}

fn descriptors(names: &[String], lz4: &[String]) -> Vec<ColumnFamilyDescriptor> {
    names
        .iter()
        .map(|name| {
            let compression = if lz4.contains(name) {
                DBCompressionType::Lz4
            } else {
                DBCompressionType::None
            };
            ColumnFamilyDescriptor::new(name, cf_options(compression))
        })
        .collect()
}

/// Reads the `rocksdb.compression` table property from an SST file.
/// In the properties block the key is prefix-compressed against
/// `rocksdb.comparator`: shared=12, unshared=7 ("ression"), then the value length.
fn sst_compression(path: &Path) -> String {
    let Ok(raw) = fs::read(path) else {
        return "unreadable".into();
    };
    let needle = b"ression";
    let mut at = raw.len();
    while at > needle.len() + 3 {
        at -= 1;
        if raw[at..].starts_with(needle) && raw[at - 3] == 12 && raw[at - 2] == 7 {
            let length = raw[at - 1] as usize;
            let start = at + needle.len();
            if length > 0 && start + length <= raw.len() {
                return String::from_utf8_lossy(&raw[start..start + length]).to_string();
            }
        }
    }
    "unknown".into()
}

fn directory_bytes(path: &Path) -> u64 {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.metadata().ok())
                .filter(|meta| meta.is_file())
                .map(|meta| meta.len())
                .sum()
        })
        .unwrap_or(0)
}

#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct FileSummary {
    files: u64,
    bytes: u64,
    entries: u64,
    by_compression: BTreeMap<String, u64>,
}

fn file_summary(db: &DB, path: &Path) -> Result<BTreeMap<String, FileSummary>, Failure> {
    let mut result: BTreeMap<String, FileSummary> = BTreeMap::new();
    for file in db.live_files()? {
        let entry = result.entry(file.column_family_name.clone()).or_default();
        entry.files += 1;
        entry.bytes += file.size as u64;
        entry.entries += file.num_entries;
        let kind = sst_compression(&path.join(file.name.trim_start_matches('/')));
        *entry.by_compression.entry(kind).or_default() += file.size as u64;
    }
    Ok(result)
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct ContentDigest {
    entries: u64,
    key_bytes: u64,
    value_bytes: u64,
    sha256: String,
}

fn digest_one(db: &DB, name: &str) -> Result<ContentDigest, String> {
    let handle = db
        .cf_handle(name)
        .ok_or_else(|| format!("column family {name} disappeared"))?;
    let mut hasher = Sha256::new();
    let (mut entries, mut key_bytes, mut value_bytes) = (0u64, 0u64, 0u64);
    for item in db.iterator_cf(handle, IteratorMode::Start) {
        let (key, value) = item.map_err(|error| format!("read error in {name}: {error}"))?;
        hasher.update((key.len() as u64).to_le_bytes());
        hasher.update(&key);
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(&value);
        entries += 1;
        key_bytes += key.len() as u64;
        value_bytes += value.len() as u64;
    }
    Ok(ContentDigest {
        entries,
        key_bytes,
        value_bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}

/// Digest every column family, a few at a time (bounded parallelism).
fn digest_all(db: &DB, names: &[String]) -> Result<BTreeMap<String, ContentDigest>, Failure> {
    let mut result = BTreeMap::new();
    for chunk in names.chunks(4) {
        let partial: Vec<(String, Result<ContentDigest, String>)> = std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|name| (name.clone(), scope.spawn(move || digest_one(db, name))))
                .collect();
            handles
                .into_iter()
                .map(|(name, handle)| {
                    let outcome = handle
                        .join()
                        .unwrap_or_else(|_| Err("digest thread panicked".to_string()));
                    (name, outcome)
                })
                .collect()
        });
        for (name, outcome) in partial {
            result.insert(name, outcome?);
        }
    }
    Ok(result)
}

fn open_read_only(path: &Path, names: &[String], lz4: &[String]) -> Result<DB, Failure> {
    Ok(DB::open_cf_descriptors_read_only(
        &db_options(2, 1),
        path,
        descriptors(names, lz4),
        false,
    )?)
}

fn checked_database(raw: &str) -> Result<PathBuf, Failure> {
    let path = PathBuf::from(raw);
    let meta = fs::symlink_metadata(&path)?;
    if !path.is_absolute()
        || !meta.is_dir()
        || meta.file_type().is_symlink()
        || path.canonicalize()? != path
        || path.file_name().and_then(|name| name.to_str()) != Some("rocksdb")
        || !path.join("CURRENT").is_file()
    {
        return fail("--db must be the real absolute path of an existing `rocksdb` directory");
    }
    Ok(path)
}

fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_files(map: &BTreeMap<String, FileSummary>) -> String {
    let rows: Vec<String> = map
        .iter()
        .map(|(name, summary)| {
            let kinds: Vec<String> = summary
                .by_compression
                .iter()
                .map(|(kind, bytes)| format!("{}:{}", json_string(kind), bytes))
                .collect();
            format!(
                "{}:{{\"files\":{},\"bytes\":{},\"entries\":{},\"bytes_by_compression\":{{{}}}}}",
                json_string(name),
                summary.files,
                summary.bytes,
                summary.entries,
                kinds.join(",")
            )
        })
        .collect();
    format!("{{{}}}", rows.join(","))
}

fn json_digests(map: &BTreeMap<String, ContentDigest>) -> String {
    let rows: Vec<String> = map
        .iter()
        .map(|(name, digest)| {
            format!(
                "{}:{{\"entries\":{},\"key_bytes\":{},\"value_bytes\":{},\"sha256\":{}}}",
                json_string(name),
                digest.entries,
                digest.key_bytes,
                digest.value_bytes,
                json_string(&digest.sha256)
            )
        })
        .collect();
    format!("{{{}}}", rows.join(","))
}

fn write_new(path: &Path, text: &str) -> Result<(), Failure> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(text.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

struct Arguments {
    db: PathBuf,
    receipt: Option<PathBuf>,
    targets: Vec<String>,
    threads: i32,
    subcompactions: u32,
    digest: bool,
}

fn parse(args: &[String]) -> Result<Arguments, Failure> {
    let (mut db, mut receipt, mut targets) = (None, None, Vec::new());
    let (mut threads, mut subcompactions, mut digest) = (4i32, 4u32, false);
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        if flag == "--digest" {
            digest = true;
            index += 1;
            continue;
        }
        let Some(value) = args.get(index + 1) else {
            return fail(format!("{flag} needs a value"));
        };
        match flag {
            "--db" => db = Some(checked_database(value)?),
            "--receipt" => receipt = Some(PathBuf::from(value)),
            "--cf" => targets.push(value.clone()),
            "--threads" => threads = value.parse()?,
            "--subcompactions" => subcompactions = value.parse()?,
            other => return fail(format!("unknown argument {other}")),
        }
        index += 2;
    }
    if !(1..=32).contains(&threads) || !(1..=32).contains(&subcompactions) {
        return fail("--threads and --subcompactions must be between 1 and 32");
    }
    Ok(Arguments {
        db: db.ok_or("--db is required")?,
        receipt,
        targets,
        threads,
        subcompactions,
        digest,
    })
}

fn support() -> Result<(), Failure> {
    let base = std::env::temp_dir().join(format!("zolana-ledger-shrink-support-{}", std::process::id()));
    fs::create_dir(&base)?;
    let mut lz4 = false;
    let mut rows = Vec::new();
    for (name, kind) in [
        ("none", DBCompressionType::None),
        ("lz4", DBCompressionType::Lz4),
        ("lz4hc", DBCompressionType::Lz4hc),
        ("snappy", DBCompressionType::Snappy),
        ("zlib", DBCompressionType::Zlib),
        ("zstd", DBCompressionType::Zstd),
        ("bz2", DBCompressionType::Bz2),
    ] {
        let directory = base.join(name);
        let mut options = Options::default();
        options.create_if_missing(true);
        options.set_compression_type(kind);
        let linked = match DB::open(&options, &directory) {
            Ok(db) => db.put(b"k", vec![0u8; 8192]).is_ok() && db.flush().is_ok(),
            Err(_) => false,
        };
        if name == "lz4" {
            lz4 = linked;
        }
        rows.push(format!("{}:{}", json_string(name), linked));
    }
    fs::remove_dir_all(&base)?;
    println!("{{\"tool\":{},\"linked\":{{{}}}}}", json_string(VERSION), rows.join(","));
    if !lz4 {
        return fail("LZ4 is not linked into this build");
    }
    Ok(())
}

fn inspect(arguments: &Arguments) -> Result<(), Failure> {
    let names = column_families(&arguments.db)?;
    let db = open_read_only(&arguments.db, &names, &[])?;
    let files = file_summary(&db, &arguments.db)?;
    let digests = if arguments.digest {
        Some(digest_all(&db, &names)?)
    } else {
        None
    };
    println!(
        "{{\"tool\":{},\"mode\":\"inspect\",\"db\":{},\"directory_bytes\":{},\"column_families\":{},\"files\":{},\"content\":{}}}",
        json_string(VERSION),
        json_string(&arguments.db.to_string_lossy()),
        directory_bytes(&arguments.db),
        names.len(),
        json_files(&files),
        digests.as_ref().map(json_digests).unwrap_or_else(|| "null".into()),
    );
    Ok(())
}

fn shrink(arguments: &Arguments) -> Result<(), Failure> {
    let receipt = arguments.receipt.as_ref().ok_or("--receipt is required for shrink")?;
    if !receipt.is_absolute() || fs::symlink_metadata(receipt).is_ok() {
        return fail("--receipt must be a new absolute file path");
    }
    if receipt.starts_with(&arguments.db) {
        return fail("--receipt must be outside the database directory");
    }
    // New SST files must keep the ledger owner; RocksDB creates them as this process.
    let owner = fs::metadata(&arguments.db)?.uid();
    let me = unsafe { libc::geteuid() };
    if me != owner {
        return fail(format!(
            "run as the ledger owner (uid {owner}); this process is uid {me}. Nothing was changed."
        ));
    }
    unsafe { libc::umask(0o077) };

    let names = column_families(&arguments.db)?;
    let wanted: Vec<String> = if arguments.targets.is_empty() {
        DEFAULT_TARGETS.iter().map(|name| name.to_string()).collect()
    } else {
        arguments.targets.clone()
    };
    if arguments.targets.iter().any(|name| !names.contains(name)) {
        return fail("an explicitly requested column family does not exist in this database");
    }
    let targets: Vec<String> = wanted.into_iter().filter(|name| names.contains(name)).collect();
    if targets.is_empty() {
        return fail("none of the target column families exist in this database");
    }
    // Columns whose Agave options install a slot-purging compaction filter are refused:
    // this tool must never be able to drop a row (blockstore_db.rs:1333-1338).
    for forbidden in ["transaction_status", "transaction_memos", "address_signatures"] {
        if targets.iter().any(|name| name == forbidden) {
            return fail(format!("{forbidden} is not an allowed target"));
        }
    }

    let started = Instant::now();
    let bytes_before = directory_bytes(&arguments.db);
    eprintln!("[1/4] reading every column family (before) ...");
    let (files_before, content_before) = {
        let db = open_read_only(&arguments.db, &names, &[])?;
        (file_summary(&db, &arguments.db)?, digest_all(&db, &names)?)
    };
    let before_seconds = started.elapsed().as_secs_f64();

    eprintln!("[2/4] forced LZ4 rewrite of {targets:?} ...");
    let compaction_started = Instant::now();
    let mut per_cf = Vec::new();
    {
        let db = DB::open_cf_descriptors(
            &db_options(arguments.threads, arguments.subcompactions),
            &arguments.db,
            descriptors(&names, &targets),
        )?;
        for name in &targets {
            let handle = db.cf_handle(name).ok_or("target column family missing after open")?;
            let begun = Instant::now();
            let mut options = CompactOptions::default();
            options.set_exclusive_manual_compaction(true);
            // Without Force, files already on the last level are left untouched
            // (rocksdb/include/rocksdb/options.h:2287-2290).
            options.set_bottommost_level_compaction(BottommostLevelCompaction::Force);
            db.compact_range_cf_opt(handle, None::<&[u8]>, None::<&[u8]>, &options);
            per_cf.push(format!("{}:{:.2}", json_string(name), begun.elapsed().as_secs_f64()));
        }
        db.flush_wal(true)?;
    }
    let compaction_seconds = compaction_started.elapsed().as_secs_f64();

    eprintln!("[3/4] reading every column family (after) ...");
    let verify_started = Instant::now();
    let (files_after, content_after) = {
        let db = open_read_only(&arguments.db, &names, &targets)?;
        (file_summary(&db, &arguments.db)?, digest_all(&db, &names)?)
    };
    let after_seconds = verify_started.elapsed().as_secs_f64();
    let bytes_after = directory_bytes(&arguments.db);

    let identical = content_before == content_after;
    // The rocksdb crate discards the CompactRange status (c.cc rocksdb_compact_range_cf_opt
    // returns void), so success is established here from the files themselves.
    let mut uncompressed = Vec::new();
    for name in &targets {
        if let Some(summary) = files_after.get(name) {
            for (kind, bytes) in &summary.by_compression {
                if kind != "LZ4" {
                    uncompressed.push(format!("{name}:{kind}:{bytes}"));
                }
            }
        }
    }
    let complete = uncompressed.is_empty();
    eprintln!("[4/4] writing receipt ...");
    let text = format!(
        "{{\"tool\":{},\"mode\":\"shrink\",\"db\":{},\"owner_uid\":{},\"targets\":[{}],\"threads\":{},\"subcompactions\":{},\
\"directory_bytes_before\":{},\"directory_bytes_after\":{},\"content_identical\":{},\"all_target_files_lz4\":{},\
\"not_lz4\":[{}],\"seconds\":{{\"read_before\":{:.2},\"compaction\":{:.2},\"read_after\":{:.2},\"per_column_family\":{{{}}}}},\
\"files_before\":{},\"files_after\":{},\"content_before\":{},\"content_after\":{}}}",
        json_string(VERSION),
        json_string(&arguments.db.to_string_lossy()),
        owner,
        targets.iter().map(|name| json_string(name)).collect::<Vec<_>>().join(","),
        arguments.threads,
        arguments.subcompactions,
        bytes_before,
        bytes_after,
        identical,
        complete,
        uncompressed.iter().map(|row| json_string(row)).collect::<Vec<_>>().join(","),
        before_seconds,
        compaction_seconds,
        after_seconds,
        per_cf.join(","),
        json_files(&files_before),
        json_files(&files_after),
        json_digests(&content_before),
        json_digests(&content_after),
    );
    write_new(receipt, &text)?;
    println!("{text}");
    if !identical {
        return fail("CONTENT DIFFERS after the rewrite: do not start the validator; restore the backup");
    }
    if !complete {
        return fail("some target files are not LZ4; content is intact, rerun the same command");
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let outcome = match args.first().map(String::as_str) {
        Some("support") if args.len() == 1 => support(),
        Some("inspect") => parse(&args[1..]).and_then(|arguments| inspect(&arguments)),
        Some("shrink") => parse(&args[1..]).and_then(|arguments| shrink(&arguments)),
        _ => fail(
            "usage: zolana-ledger-shrink support\n       zolana-ledger-shrink inspect --db /abs/.../rocksdb [--digest]\n       zolana-ledger-shrink shrink --db /abs/.../rocksdb --receipt /abs/new.json [--cf NAME ...] [--threads N] [--subcompactions N]",
        ),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("zolana-ledger-shrink: {error}");
            ExitCode::FAILURE
        }
    }
}
