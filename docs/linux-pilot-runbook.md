# Linux pilot candidate

Linux is the intended long-term host target. The earlier Mac recommendation
minimized deployment changes to the already tested installation; it was not a
chain requirement. Existing macOS bindings, user wallets and funded rehearsals
remain unchanged. `pilot_linux.py` is a separate candidate, not accepted Linux
operation. No host is purchased or contacted by these tools.

## Hardware and placement

Start evaluation on dedicated Ubuntu 24.04 LTS x86-64 hardware, a recent
high-clock AMD CPU with AVX2/SHA support, 16 physical cores, 128 GB RAM and two
enterprise NVMe drives of about 2 TB each. This is a provisional pilot sizing
target, not a measured minimum or promise of long-term capacity. Measure native
proof latency, validator RSS, retained history growth, disk write rate, restart
time and concurrent payment throughput before a long commitment. Builds can
detect CPU features on the builder; validate on the actual intended host and do
not assume arbitrary x86-64 machines can execute the artifacts.

Our low-load private chain is not Solana mainnet. Upstream
[Agave requirements](https://docs.anza.xyz/operations/requirements) are context, not this pilot's
measured requirements. More users, application activity and history can require
more RAM/storage or a different node layout. A large server does not remove the
need for independent validators and recovery hosts.

The first candidate still runs both validators on one host with loopback peer
transport. Split-validator networking is separate work. Keep recovery/history,
full canonical archival RPC, and observer/pager/watchdog in independent failure
domains before tester activation. RAID/mirrors do not replace off-host backups.
Key custody and payment for hosting are separate from native test-unit
funding; there is no need to buy ZOL or SOL to run this fresh private pilot.

No provider or price is pinned by this recipe. Inventory, final RAM and disk
options, recurring billing, OS access and terms must be checked at purchase.

## Native build, without touching the Mac target

Use a separate unprivileged Ubuntu builder, a trusted clean committed source
checkout, native Rust 1.92.0, and already reviewed/cached Cargo dependencies in
`.tools/cargo`. The builder needs Git, Python 3, build-essential, pkg-config,
libssl-dev, libudev-dev, zlib1g-dev, llvm, clang, libclang-dev, cmake,
libprotobuf-dev and protobuf-compiler (see the preserved Agave README). Preparing
packages/toolchains/cache is a separate explicit network operation. This tool
never installs them or downloads dependencies. Do not copy a Mac's compiled
target directory or cached native executables into a Linux release.

On that Linux builder, with fresh absolute directories **outside the checkout**:

```sh
python3 -B tools/pilot_linux.py build --output /srv/zolana-build-candidate
python3 -B tools/pilot_linux.py prepare --build-dir /srv/zolana-build-candidate --output /srv/zolana-linux-bundle
python3 -B tools/pilot_linux.py check --bundle /srv/zolana-linux-bundle --manifest-sha256 REVIEWED_BUNDLE_DIGEST
```

The recipe uses offline/locked Cargo, two low-priority jobs by default, a separate target
directory and the existing optimized development profile. It builds all four
native executables and records original source commit, lockfile hash and binary
hashes. Failed builds keep logs/artifacts, never a completion receipt. The
28-file allowlist contains code, binaries, notices and the build receipt only.
Missing/changed/extra/linked files, Mach-O/ARM binaries, different receipts and
source changes fail closed. ELF headers establish file identity only; ABI,
dynamic linkage and CPU execution must still be accepted on real Linux.
This is not a hermetic or path-remapped production release, and hashes do not
establish publisher authenticity. Obtain the bundle digest independently.

On a separately provisioned dedicated host with adequate CPU/RAM, `build
--jobs 8` explicitly permits up to eight native compiler jobs; the actual count
is bound into the build receipt. Counts outside two through eight fail before
compiler invocation or output creation. This does not start Mac compilation
or increase validator/prover runtime thread counts.

## Installation and disabled service review

There is deliberately no automatic Linux root installer in this first candidate.
The existing `pilot_install.py` remains macOS-only. Review a fresh root-controlled
copy of the exact Linux bundle at `/opt/zolana`, root-owned real ancestors, code
0444, executables 0555 and manifest 0444. Extra modules are refused. Do not copy
developer `.data`, keys, invitation codes, passwords or ledgers into it. Never
overwrite an existing funded installation or edit its pins to make it start.

Provision a dedicated `zolanapilot` user/group with no login, shell
`/usr/sbin/nologin` or `/sbin/nologin`, and home `/nonexistent`. Use persistent
`/opt/zolana/.data`, mode 0700, owned by that UID/GID. Generate a new network,
private Unix RPC, cohort, HTTPS listeners and reviewed finite funding ceremony
there, as that identity, at final paths. Existing cohort/runtime tools are used
unchanged, preserving their journaling, native fees, admission, recovery and
anti-reset checks. The original binding must identify `linux-x86_64` and the
actual service UID/GID; copying/editing a Darwin binding is forbidden.

Render the exact candidate unit locally:

```sh
python3 -B tools/pilot_linux.py render --binding-sha256 ORIGINAL_LINUX_BINDING --manifest-sha256 REVIEWED_BUNDLE_DIGEST --output /absolute/private/zolana-pilot.service
```

It has no `[Install]` section and does not create an approval file, contact
systemd or start any process. Service execution additionally requires an
independently reviewed, root-owned 0444 `/etc/zolana-pilot/activation.json`, under
root-controlled real directories, containing exactly:

```json
{
  "format": "zolana-linux-activation-v1",
  "binding_sha256": "ORIGINAL_LINUX_BINDING",
  "manifest_sha256": "REVIEWED_BUNDLE_DIGEST"
}
```

Do not approve/start the intended tester installation until Linux acceptance
below passes. Host acceptance itself uses separately reviewed disposable test
installation/approval digests and valueless test keys, never a bypass of this gate.
The entry point verifies sealed code, exact approval, service identity and
private state, establishes its own process group without forking, then invokes
the original pinned supervisor. Linux candidates are additional provenance;
they never silently replace/rebind an existing runtime.

The candidate unit uses
[systemd cgroup cleanup](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html), a
90-second stop allowance, bounded failure restarts and owner-only writable
state. Filesystem protection, no privilege escalation and an empty capability
set are explicit. Public listeners must use unprivileged ports with separately
reviewed direct TLS/firewall routing; this service cannot bind port 443 itself.
Keep raw RPC exclusively on private Unix sockets; no forwarded-IP trust or
public raw RPC fallback. No aggressive syscall/JIT restrictions or memory cap
are claimed compatible before real validator acceptance.

## Required Linux evidence

1. Native clean build, binary linkage/CPU probes and `systemd-analyze verify`
   on the intended Ubuntu/systemd version. Unit text tests on macOS cannot
   establish systemd semantics, sandbox compatibility or startup readiness.
2. Root-controlled installation; real foreign-UID key/socket denial, wrong
   approval/hash refusal, service UID permissions and zero raw TCP listeners.
3. Fresh bounded pilot funding and all ten onboarding/payment/withdrawal/seed
   recovery cases. Record CPU/RAM/disk usage under sustained load.
4. Actual systemd supervisor SIGKILL (including a child that creates another
   session), cgroup emptiness, durable same-binding restart, and real host reboot
   with exact original wallets, balances, claims, ledger/tower and nullifiers.
5. Independent retained history/canonical RPC recovery, trusted HTTPS and client
   delivery, off-host alerts with human receipt, and external-device acceptance.
