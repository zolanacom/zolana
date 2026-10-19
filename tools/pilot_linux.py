#!/usr/bin/env python3
"""Linux candidate build, integrity checks and gated systemd entry point.

Never installs packages, creates users, funds a network or enables a service.
"""
import argparse
import os
from pathlib import Path
import platform
import pwd
import stat
import struct
import subprocess
import sys

import pilot_cohort as cohort
import pilot_runtime as runtime
from wallet_release import create, decode, encode, fsync_dir, hex64, read, sha

PROJECT = Path(__file__).resolve().parents[1]
PREFIX = Path('/opt/zolana')
ACCOUNT = 'zolanapilot'
APPROVAL = Path('/etc/zolana-pilot/activation.json')
TARGET = 'x86_64-unknown-linux-gnu'
FILES = (tuple('tools/' + n for n in runtime.CODE) +
         ('tools/pilot_linux.py', 'tools/pilot_provision.py') +
         tuple('target/debug/' + n for n in runtime.BINARIES) +
         ('LICENSE', 'THIRD_PARTY.md', 'node/agave/LICENSE'))
RECEIPT = 'LINUX-BUILD.json'


def linux():
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('requires native Linux x86-64; macOS/cross-builds are not accepted')


def elf(raw):
    # File identity only, not execution, ABI/linkage or CPU compatibility evidence.
    if (len(raw) < 64 or raw[:7] != b'\x7fELF\x02\x01\x01' or
            struct.unpack_from('<HHI', raw, 16) not in ((2, 62, 1), (3, 62, 1)) or
            struct.unpack_from('<H', raw, 52)[0] != 64):
        raise ValueError('requires ELF64 little-endian x86-64 executable')


def git(*args):
    return subprocess.check_output(['git', *args], cwd=PROJECT, text=True).strip()


def build(output):
    linux()  # Refuse before mkdir, subprocess or touching the existing target.
    if os.getuid() == 0:
        raise ValueError('build as an unprivileged builder, never the service account')
    output = Path(output).absolute()
    if output.resolve() != output or output == PROJECT or PROJECT in output.parents:
        raise ValueError('use a new separate real build directory outside the checkout')
    version = subprocess.check_output(['rustc', '-Vv'], cwd=PROJECT, text=True)
    fields = dict(line.split(': ', 1) for line in version.splitlines() if ': ' in line)
    if fields.get('release') != '1.92.0' or fields.get('host') != TARGET:
        raise ValueError('pinned native Rust 1.92.0 required')
    if git('status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('review and commit the source before building')
    commit = git('rev-parse', 'HEAD')
    lock = sha(cohort.code_bytes(PROJECT / 'Cargo.lock', 4 * 1024 * 1024))
    output.mkdir(mode=0o700)
    env = dict(os.environ, CARGO_HOME=str(PROJECT / '.tools/cargo'),
               CARGO_TARGET_DIR=str(output / 'target'), CARGO_BUILD_JOBS='2',
               RAYON_NUM_THREADS='2', CARGO_NET_OFFLINE='true', CXXFLAGS='-g0',
               CFLAGS='-g0', RUSTFLAGS='-Ctarget-cpu=x86-64-v2')
    # Do not inherit a Mac toolchain, native flags, wrapper or build-injection flags.
    for name in ('DYLD_FALLBACK_LIBRARY_PATH', 'LIBCLANG_PATH', 'PROTOC', 'PROTOC_INCLUDE',
                 'CARGO_ENCODED_RUSTFLAGS', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER',
                 'CC', 'CXX', 'AR'):
        env.pop(name, None)
    command = ['nice', '-n', '15', 'cargo', 'build', '--offline', '--locked',
               '--target', TARGET, '--no-default-features', '-j', '2',
               '-p', 'native-wallet', '-p', 'native-localnet', '-p', 'agave-validator']
    for name in runtime.BINARIES:
        command += ['--bin', name]
    with (output / 'build.log').open('xb') as log:
        os.chmod(output / 'build.log', 0o600)
        subprocess.run(command, cwd=PROJECT, env=env, stdout=log,
                       stderr=subprocess.STDOUT, check=True)
    if (git('rev-parse', 'HEAD') != commit or git('status', '--porcelain', '--untracked-files=normal') or
            sha(cohort.code_bytes(PROJECT / 'Cargo.lock', 4 * 1024 * 1024)) != lock):
        raise ValueError('source changed during build; keep artifacts for review')
    binaries = {}
    for name in runtime.BINARIES:
        raw = cohort.code_bytes(output / 'target' / TARGET / 'debug' / name, 256 * 1024 * 1024)
        elf(raw)
        binaries[name] = dict(size=len(raw), sha256=sha(raw))
    receipt = dict(format='zolana-linux-build-v1', target=TARGET, rustc_release='1.92.0',
                   source_commit=commit, cargo_lock_sha256=lock, offline=True, jobs=2,
                   profile='dev', binaries=binaries, runtime_tested=False)
    create(output / RECEIPT, encode(receipt)); fsync_dir(output)
    return dict(build_complete=True, runtime_tested=False, services_started=0)


def validate_receipt(raw, binaries):
    value = decode(raw)
    keys = {'format', 'target', 'rustc_release', 'source_commit', 'cargo_lock_sha256',
            'offline', 'jobs', 'profile', 'binaries', 'runtime_tested'}
    if (not isinstance(value, dict) or set(value) != keys or
            value['format'] != 'zolana-linux-build-v1' or value['target'] != TARGET or
            value['rustc_release'] != '1.92.0' or value['profile'] != 'dev' or
            value['offline'] is not True or type(value['jobs']) is not int or value['jobs'] != 2 or
            value['runtime_tested'] is not False or not hex64(value['cargo_lock_sha256']) or
            not isinstance(value['source_commit'], str) or len(value['source_commit']) != 40 or
            any(c not in '0123456789abcdef' for c in value['source_commit']) or value['binaries'] != binaries):
        raise ValueError('Linux build receipt differs from original binaries/recipe')
    return value


def prepare(build_dir, output):
    linux()
    build_dir, output = Path(build_dir).absolute(), Path(output).absolute()
    receipt_raw = read(build_dir / RECEIPT, 8192, secret=True)
    data = {}
    binaries = {}
    for name in FILES:
        source = (build_dir / 'target' / TARGET / 'debug' / Path(name).name
                  if name.startswith('target/') else PROJECT / name)
        raw = cohort.code_bytes(source, 256 * 1024 * 1024)
        if name.startswith('target/'):
            elf(raw); binaries[Path(name).name] = dict(size=len(raw), sha256=sha(raw))
        data[name] = raw
    receipt = validate_receipt(receipt_raw, binaries)
    if (git('rev-parse', 'HEAD') != receipt['source_commit'] or
            git('status', '--porcelain', '--untracked-files=normal') or
            sha(cohort.code_bytes(PROJECT / 'Cargo.lock', 4 * 1024 * 1024)) != receipt['cargo_lock_sha256']):
        raise ValueError('bundle source differs from the reviewed Linux build')
    data[RECEIPT] = receipt_raw
    output.mkdir(mode=0o700)
    entries = {}
    for name, raw in data.items():
        dest = output / name; dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        create(dest, raw)
        entries[name] = dict(size=len(raw), sha256=sha(raw),
                             mode=0o555 if name.startswith('target/') else 0o444)
    manifest = dict(format='zolana-linux-pilot-v1', platform='linux-x86_64', prefix=str(PREFIX),
                    account=ACCOUNT, activation_enabled=False, files=entries)
    create(output / 'MANIFEST.json', encode(manifest)); fsync_dir(output)
    return dict(manifest_sha256=sha(encode(manifest)), files=len(entries), services_started=0)


def verify(bundle, expected, installed=False):
    bundle = Path(bundle).absolute()
    if bundle.resolve() != bundle:
        raise ValueError('real bundle path required')
    raw = cohort.code_bytes(bundle / 'MANIFEST.json', 32768)
    if not hex64(expected) or sha(raw) != expected:
        raise ValueError('reviewed bundle digest changed')
    value = decode(raw)
    if (not isinstance(value, dict) or set(value) != {'format', 'platform', 'prefix', 'account', 'activation_enabled', 'files'} or
            value['format'] != 'zolana-linux-pilot-v1' or value['platform'] != 'linux-x86_64' or
            value['prefix'] != str(PREFIX) or value['account'] != ACCOUNT or value['activation_enabled'] is not False or
            set(value['files']) != {*FILES, RECEIPT}):
        raise ValueError('Linux bundle contract differs')
    inventory(bundle, {*value['files'], 'MANIFEST.json'}, skip_state=installed)
    binaries = {}
    for name, item in value['files'].items():
        raw = cohort.code_bytes(bundle / name, 256 * 1024 * 1024)
        if item != dict(size=len(raw), sha256=sha(raw), mode=0o555 if name.startswith('target/') else 0o444):
            raise ValueError('Linux bundle bytes differ')
        if name.startswith('target/'):
            elf(raw); binaries[Path(name).name] = dict(size=len(raw), sha256=sha(raw))
        if installed:
            sealed(bundle / name, item['mode'])
    validate_receipt(cohort.code_bytes(bundle / RECEIPT, 8192), binaries)
    return value


def inventory(base, allowed, skip_state=False):
    expected_dirs = {str(Path(name).parent) for name in allowed}
    for name in list(expected_dirs):
        expected_dirs.update(str(p) for p in Path(name).parents)
    for parent, dirs, files in os.walk(base, followlinks=False):
        if skip_state and Path(parent) == base and '.data' in dirs:
            if (base / '.data').is_symlink():
                raise ValueError('linked pilot state directory')
            dirs.remove('.data')
        for name in dirs + files:
            path = Path(parent) / name; meta = path.lstat()
            relative = str(path.relative_to(base))
            if (stat.S_ISLNK(meta.st_mode) or
                    relative not in allowed and relative not in expected_dirs or
                    not (stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode))):
                raise ValueError('unexpected Linux installation content')


def unit(binding, manifest):
    if not hex64(binding) or not hex64(manifest):
        raise ValueError('exact reviewed runtime and bundle digests required')
    return f'''# Candidate only. No Install section; explicit review/start required.
[Unit]
Description=Zolana invite pilot (Linux candidate)
Wants=network-online.target
After=network-online.target
ConditionPathExists={APPROVAL}
StartLimitIntervalSec=300
StartLimitBurst=3

[Service]
Type=exec
User={ACCOUNT}
Group={ACCOUNT}
WorkingDirectory={PREFIX}
ExecStart=/usr/bin/python3 -B -E -s {PREFIX}/tools/pilot_linux.py run --binding-sha256 {binding} --manifest-sha256 {manifest}
Restart=on-failure
RestartSec=30
KillMode=control-group
SendSIGKILL=yes
TimeoutStopSec=90
UMask=0077
Nice=15
LimitNOFILE=1048576
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths={PREFIX}/.data
Environment=RAYON_NUM_THREADS=2 RUST_LOG=warn PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1
Environment=PATH=/usr/bin:/bin
StandardOutput=append:{PREFIX}/.data/host.stdout.log
StandardError=append:{PREFIX}/.data/host.stderr.log
'''.encode()


def sealed(path, mode=None):
    path = Path(path)
    if path.resolve() != path:
        raise ValueError('sealed path must be real')
    for parent in path.parents:
        m = parent.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022:
            raise ValueError('root-controlled real ancestors required')
    m = path.lstat()
    if not stat.S_ISREG(m.st_mode) or m.st_uid != 0 or m.st_mode & 0o022 or (mode is not None and stat.S_IMODE(m.st_mode) != mode):
        raise ValueError('immutable root-owned file required')


def session():
    # systemd does not promise the supervisor is already a process-group leader.
    # Keep the same PID so systemd tracks the main process; no fork or shell.
    if os.getpgrp() != os.getpid():
        os.setsid()
    if os.getpgrp() != os.getpid():
        raise ValueError('private supervisor process group required')


def run(binding, manifest):
    linux()
    if os.getuid() == 0 or PROJECT != PREFIX or PROJECT.resolve() != PROJECT:
        raise ValueError('only the separately installed unprivileged Linux pilot may run')
    user = pwd.getpwuid(os.getuid())
    import grp
    if (user.pw_name != ACCOUNT or user.pw_gid != os.getgid() or grp.getgrgid(os.getgid()).gr_name != ACCOUNT or
            user.pw_shell not in ('/usr/sbin/nologin', '/sbin/nologin') or user.pw_dir != '/nonexistent'):
        raise ValueError('dedicated no-login Linux service identity required')
    sealed(PROJECT / 'MANIFEST.json', 0o444)
    sealed(APPROVAL, 0o444)
    approval = decode(cohort.code_bytes(APPROVAL, 4096))
    if (not hex64(binding) or not hex64(manifest) or approval !=
            dict(format='zolana-linux-activation-v1', binding_sha256=binding, manifest_sha256=manifest)):
        raise ValueError('explicit approval must match both original digests')
    state = PROJECT / '.data'; m = state.lstat()
    if state.resolve() != state or not stat.S_ISDIR(m.st_mode) or m.st_uid != os.getuid() or m.st_gid != os.getgid() or stat.S_IMODE(m.st_mode) != 0o700:
        raise ValueError('original owner-only persistent state required')
    verify(PROJECT, manifest, installed=True)
    session()
    runtime.supervise(state / 'pilot', binding)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('build', 'prepare', 'check', 'render', 'run'))
    p.add_argument('--build-dir', type=Path); p.add_argument('--output', type=Path)
    p.add_argument('--bundle', type=Path); p.add_argument('--manifest-sha256'); p.add_argument('--binding-sha256')
    a = p.parse_args()
    if a.action == 'build': result = build(a.output)
    elif a.action == 'prepare': result = prepare(a.build_dir, a.output)
    elif a.action == 'check':
        verify(a.bundle, a.manifest_sha256)
        result = dict(bundle_verified=True, runtime_tested=False, services_started=0)
    elif a.action == 'render':
        create(a.output, unit(a.binding_sha256, a.manifest_sha256))
        result = dict(unit_written=True, activation_enabled=False, services_started=0)
    else:
        run(a.binding_sha256, a.manifest_sha256)
        result = dict(phase='stopped')
    print(encode(result).decode(), end='')


if __name__ == '__main__':
    try: main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError):
        raise SystemExit('Linux candidate stopped; preserve artifacts/state. No install or reset was attempted.')
