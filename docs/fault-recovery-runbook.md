# Local crash and competing-fork acceptance

Run from the repository root with Rust 1.92 and Python 3.14. Stop other local fixtures using ports 18899/19899 first. Build the binaries and select a new directory under ignored `.data/`:

```sh
CARGO_BUILD_JOBS=2 sh tools/dev.sh build --offline --locked --no-default-features -p agave-validator -p native-localnet --bin agave-validator --bin native-localnet
python3 -B tools/fault_localnet.py --root .data/fault-run
```

The runner creates a fresh disposable 80%/20% stake genesis and random encrypted Alice/Bob wallets. Fixture validator/sponsor keys are public test keys; wallet secrets and seed backups stay in ignored files. The result journal is `<root>/fault-result.json`. Failed runs keep their logs and payment receipts; use a fresh directory for a new attempt. Cleanup heals both gates and stops owned children on success or failure.

The explicit `NATIVE_LOCAL_SHRED_FAULT` hook controls Agave's existing `turbine_disabled` flag. It requires loopback gossip, TVU, TPU and RPC, a control file beside the ledger, a disposable NPOOL003 fixture and a matching expected genesis hash. Ordinary local starts strip the environment variable. UDP/QUIC turbine and repair shred reception are gated; gossip and transaction traffic remain available. This is a block-propagation partition, not full network isolation. Acknowledgments bind each control state to the validator process ID.

The partition case stages two real proofs spending the same private note, waits for both sealed buffers to finalize on both peers, and delivers the conflicting transactions directly to each local TPU. The majority candidate must finalize, while the minority must execute a distinct unfinalized candidate with a unique nullifier. Rejoin must restore exact canonical native state, remove the orphan-only nullifier, restore the sealed minority buffer and reject its conflicting spend. No tower reset, ledger truncation or consensus threshold change is permitted.

Crash injection authenticates genesis and identity over RPC, then sends SIGKILL only through the runner's own live child handle with a matching saved PID. Cases cover minority catch-up after a payment during its absence, majority death after payment execution before finalization, and simultaneous loss of both processes. Majority recovery uses the existing verified coordinated checkpoint path. If needed, ordinary guarded replay first completes a crash tail before offline checkpoint selection. A pending wallet intent must resolve against finalized history before another payment is allowed.

Acceptance requires fresh finalized roots, identical pool and permanent-nullifier accounts, exact backing and wallet balances, spent-proof rejection while the authorization remains live, finalized staging cleanup and seed-only wallet restoration. This process test does not simulate power failure, disk corruption, a Byzantine validator or general long-offline recovery.

## Preserving large stopped ledgers

Python 3.14 supplies the `compression.zstd` module used by the optional archive helper:

```sh
python3 -B tools/park_ledger.py park .data/fixture/ledger-0
python3 -B tools/park_ledger.py restore .data/fixture/ledger-0.parked
```

Parking acquires both ledger and RocksDB locks, renames the stopped directory, compresses large files and verifies decompressed SHA-256 before removing each plain copy. The manifest records original size, digest and mode. Restoration checks available space and every restored file before returning the original directory name. Keep the complete parked directory. Restoring may require several GiB of free space.

The previous `.data/wn1/ledger-0` and `ledger-1` were parked to preserve their history after disk space ran low. Their keys, towers, wallets and network configuration remain alongside them. Completed large JSON evidence was separately retained as lossless `.json.gz` files. Neither earlier unexpected process exit is counted as an intentional crash acceptance result.
