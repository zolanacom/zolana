# Opt-in LOCAL-058 resume-only service source

LOCAL-058 adds a service lifetime to the isolated SDK4 candidate. It changes
only `Cargo.lock`, `zolana-fast-check/Cargo.toml`, `zolana-fast-check/src/main.rs`
and the new `zolana-fast-check/src/service.rs`. The frozen LOCAL-056 and
LOCAL-057 patches and sources remain unchanged.

Prepare it from the already local pinned upstream archive:

```sh
python3 tools/prepare_native_candidate.py \
  --archive /absolute/path/agave-a203300.tar.gz \
  --output /absolute/path/new-LOCAL-058-directory \
  --native-service-058 --manifest
```

This explicitly applies the exact frozen LOCAL-056 patch, then the pinned
LOCAL-057 and LOCAL-058 deltas. Each transition checks changed files' exact
before/after bytes and hashes; the new service module must be absent before
its transition. The output must not exist. No download, dependency resolution,
build, wallet access, ledger creation or service start occurs during preparation.
The default path remains LOCAL-056; `--native-fee-057` still selects LOCAL-057.
The revision flags are mutually exclusive.

The LOCAL-058 delta SHA-256 is
`b0e7f7e930c5be4020217cd39cc654ea8070312a87639169d38912cd493b7407`.
Its `LOCAL-058-source.json` manifest SHA-256 is
`727c5dc94fb20cb5f3cd512360ea4f7492664b9ee9101afa59772fed00e24a2c`.
The 337,354-byte lock SHA-256 is
`36a97da6d6f94eae278de847aea50c2adba39aaf54a329cae6f813adbcf4ebec`.
The only dependency change is the driver's direct use of `signal-hook`, already
present in the pinned dependency graph. The Linux locked build verified the
lock without changing its bytes.

The new runner invocation is strictly resume-only:

```sh
zolana-fast-check --resume-root /original/absolute/fixture/root --service
```

It rejects fresh-genesis and benchmark options, including explicit `--samples`
and `--hold-seconds`. The original locked root must contain valid private resume
metadata, identity/voting keys, signed vote histories and ledgers for the original
NPOOL004 network. Existing genesis, root-hash ancestry, account-layout and voting
safety checks are reused. The service neither funds accounts nor submits sample
transactions, and it never replaces the original resume manifest.

Only after restoration checks does it publish `external_mac_fixture_ready` over
the owned stdout pipe and private JSONL log. The existing data shape is retained,
with `service_mode: true` and `hold_seconds: 0`. It waits for SIGTERM or SIGINT,
closes validators while preserving original ledgers and signed histories, and
then releases the fixture process lock. A stop received during startup suppresses
readiness once startup returns. Forced SIGKILL remains a crash and requires
original-ledger recovery; this mode does not alter that recovery protocol.

This runner is not an isolation boundary. Its raw RPC and native ingress are
still private-loopback TCP endpoints. A separately reviewed supervisor must pin
the binary/configuration and expected network/identities, enforce the dedicated
UID and root-owned code, isolate networking, supervise readiness/health and
expose only invited TLS access. It must never fall back to fresh initialization.

Local source reproduction matches all 1,901 file/symlink contents and the vendor
provenance guard passes. Seven Python preparation tests pass. On the Linux
build host, Rust 1.97.1 ran all three parser/signal tests successfully, including
actual SIGTERM/SIGINT delivery to the test process, and the locked offline runner
build passed. The tests and build used eight bounded jobs, `nice -n 10`, the
existing compile cache and a separate LOCAL-058 source/output directory.
No validator was started by these checks.

The resulting `zolana-fast-check` executable is 91,522,904
bytes, SHA-256
`7c7035063c02750d65ae189e75b1e7cabd1e05f33c07151e577ffa5c3ebaf630`.
The test log SHA-256 is
`0717f14b011549882d31367bd7cb9664642356928ec9a7d7983a1315aa916a52`;
the build log SHA-256 is
`09800e23a40bb1aebeb45b005b3d820c5b3e38073cdea9e374e02b3106f597fe`.
This establishes the focused source/build checks only. It does not establish
live validator service recovery, namespace isolation, payment finality, public
activation or production readiness.
