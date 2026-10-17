#!/usr/bin/env python3
"""Losslessly park stopped disposable ledgers; verify each file before removing its plain copy."""
import argparse
from compression import zstd
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil

from localnet import PROJECT, load


def digest(path, compressed=False):
    opener = zstd.open if compressed else open
    with opener(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def manifest_write(path, value):
    temp = path.with_suffix(".tmp")
    with temp.open("w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def park(path):
    load(path.parent)
    if not path.name.startswith("ledger-") or path.name.endswith(".parked"):
        raise RuntimeError("select an unparked managed ledger")
    parked = path.with_name(path.name + ".parked")
    if parked.exists():
        raise RuntimeError("parked destination already exists")
    # RocksDB uses POSIX record locks; Agave additionally owns ledger.lock.
    with (path / "rocksdb/LOCK").open("r+") as database, (path / "ledger.lock").open("a+") as ledger_lock:
        fcntl.lockf(database, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(ledger_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path.rename(parked)
        manifest = {"original_name": path.name, "files": {}}
        meta = parked / "PARKED.json"
        manifest_write(meta, manifest)
        files = [p for p in parked.rglob("*") if p.is_file() and p.stat().st_size >= 1024 * 1024 and p.suffix not in [".zst", ".gz"]]
        # WALs are repetitive and provide room before compressing SST files.
        files.sort(key=lambda p: (p.suffix != ".log", -p.stat().st_size))
        saved = 0
        for source in files:
            original_size = source.stat().st_size
            target = source.with_name(source.name + ".parked.zst")
            with source.open("rb") as src, zstd.open(target, "wb", level=3) as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            with target.open("rb") as persisted:
                os.fsync(persisted.fileno())
            checksum = digest(source)
            if digest(target, compressed=True) != checksum:
                raise RuntimeError("archive verification failed; original file retained")
            manifest["files"][str(source.relative_to(parked))] = {"size": original_size, "sha256": checksum, "mode": source.stat().st_mode & 0o777}
            manifest_write(meta, manifest)
            saved += original_size - target.stat().st_size
            source.unlink()
        print(json.dumps({"parked": str(parked.relative_to(PROJECT)), "verified_files": len(files), "bytes_freed": saved}), flush=True)


def restore(path):
    meta = path / "PARKED.json"
    manifest = json.loads(meta.read_text())
    destination = path.with_name(manifest["original_name"])
    if destination.exists() or destination.parent != path.parent or not destination.name.startswith("ledger-"):
        raise RuntimeError("invalid or occupied restore destination")
    needed = sum(row["size"] for row in manifest["files"].values())
    if shutil.disk_usage(path).free < needed + 512 * 1024 * 1024:
        raise RuntimeError("insufficient free space to verify restoration")
    for name, row in manifest["files"].items():
        source = path / name
        if not source.is_relative_to(path) or ".." in Path(name).parts:
            raise RuntimeError("invalid archived path")
        compressed = source.with_name(source.name + ".parked.zst")
        if not source.exists():
            with zstd.open(compressed, "rb") as src, source.open("xb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            os.chmod(source, row["mode"])
        if source.stat().st_size != row["size"] or digest(source) != row["sha256"]:
            raise RuntimeError("restoration hash mismatch; archive retained")
        compressed.unlink(missing_ok=True)
    meta.unlink()
    path.rename(destination)
    print(f"Verified and restored {destination.relative_to(PROJECT)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["park", "restore"])
    parser.add_argument("ledger", type=Path)
    args = parser.parse_args()
    selected = args.ledger.resolve()
    if not selected.is_relative_to(PROJECT / ".data"):
        raise RuntimeError("only project-local disposable ledgers are supported")
    (park if args.command == "park" else restore)(selected)
