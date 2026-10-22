#!/usr/bin/env python3
"""Finite LOCAL075 offline release/crash acceptance; original wallets stay untouched.

The input archive is checked against an independently fixed public-profile pin.
Only disposable rehearsal publisher keys are generated. No RPC, browser action,
HTTP request, validator/service control, payment or external message is performed.
A private fixture-only loopback wallet listener tests inherited installation locks.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time

PROFILE_SHA = '1095b9cb3dd35b9599f4f939c8fc1c86c343ec4168223e00d98414b330316e05'
VERIFIER_SHA = '67c14f78a5faac7e5170bfac3520ef2506ab5daf6f2ab9b0843c72e7406fec40'
BUILDER_SHA = '79eb52a0ea54e715fb72d34302195f7f691c0374f7f20f654979f0767fca2e2a'
CHANNEL = 'local075-disposable-rehearsal'
POINTS = ('planned', 'extracting', 'published', 'activated')


class Deadline(BaseException):
    pass


def check(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def profile_pin(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise argparse.ArgumentTypeError('use an independently reviewed lowercase64-hex profile SHA-256')
    return value


def verifier(stage):
    path = stage / 'verifier' / 'wallet_release.py'
    code = path.read_bytes()
    check(not path.is_symlink() and len(code) <= 128 * 1024 and sha(code) == VERIFIER_SHA,
          'frozen independently reviewed verifier differs')
    spec = importlib.util.spec_from_file_location('local075_frozen_release', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(code, str(path), 'exec'), module.__dict__)
    module.directory(stage)
    module.parents(stage)
    check(sha(module.read(path, 128 * 1024, True)) == VERIFIER_SHA,
          'private frozen verifier changed')
    return module


def worker(stage, number, point, profile_sha256=PROFILE_SHA):
    profile_sha256 = profile_pin(profile_sha256)
    release = verifier(stage)
    control = release.decode(release.read(stage / 'control.json', 8192, True))
    check(control['format'] == 'zolana075-offline-release-acceptance-v1'
          and control['harness_sha256'] == sha(Path(__file__).read_bytes())
          and control['profile_sha256'] == profile_sha256,
          'original finite worker context required')
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(Deadline('worker90s limit')))
    signal.alarm(90)

    def checkpoint(current):
        if current == point:
            release.create(stage / ('checkpoint-' + str(number) + '.json'),
                           release.encode(dict(point=point, pid=os.getpid())))
            os.kill(os.getpid(), signal.SIGSTOP)

    installation = release.Installation(stage / 'installation', checkpoint)
    try:
        installation.install(stage / ('wallet-' + str(number) + '.tar.gz'),
                             stage / ('release-' + str(number) + '.json'))
    finally:
        installation.close()


def rehearse(archive, stage, profile_sha256=PROFILE_SHA):
    profile_sha256 = profile_pin(profile_sha256)
    source = Path(__file__).resolve().with_name('wallet_release.py')
    source_bytes = source.read_bytes()
    check(not source.is_symlink() and len(source_bytes) <= 128 * 1024
          and sha(source_bytes) == VERIFIER_SHA,
          'independently reviewed verifier source changed')
    spec = importlib.util.spec_from_file_location('local075_source_release', source)
    release = importlib.util.module_from_spec(spec)
    exec(compile(source_bytes, str(source), 'exec'), release.__dict__)
    archive = Path(archive).absolute()
    input_bytes = release.read(archive, release.ARCHIVE_LIMIT)
    files, manifest = release.unpack(input_bytes)
    check(sha(files['wallet-profile.json']) == profile_sha256,
          'archive differs from independently reviewed public074 profile')
    check(manifest['platform'] == release.host(), 'use the actual matching host-platform archive')
    stage = Path(stage).absolute()
    check(not stage.resolve().is_relative_to(Path(__file__).resolve().parents[1]),
          'keep the frozen verifier, installation and fixture stage outside the checkout')
    check(not os.path.lexists(stage), 'use a new private acceptance stage; retain failed attempts')
    release.parents(stage)
    stage.mkdir(mode=0o700)
    stage = stage.resolve()
    (stage / 'verifier').mkdir(mode=0o700)
    release.create(stage / 'verifier/wallet_release.py', source_bytes)
    release = verifier(stage)
    release.create(stage / 'control.json', release.encode(dict(
        format='zolana075-offline-release-acceptance-v1',
        harness_sha256=sha(Path(__file__).read_bytes()), verifier_sha256=VERIFIER_SHA,
        profile_sha256=profile_sha256, input_archive_sha256=sha(input_bytes))))
    release.create(stage / 'wallet-1.tar.gz', input_bytes)
    children, groups = [], []
    key_directory = None
    result = dict(format='zolana075-offline-release-acceptance-v1', status='running',
                  stage=str(stage), verifier_sha256=VERIFIER_SHA, profile_sha256=profile_sha256,
                  input_archive_sha256=sha(input_bytes), validators_started=0,
                  rpc_requests=0, http_requests=0, browser_actions=0,
                  financial_operations=0, original_wallets_or_services_opened=False,
                  production_publisher_key_created=False)

    def record(name, value):
        release.create(stage / name, release.encode(value))

    def command(args, password=None, success=True, seconds=45):
        completed = subprocess.run(list(map(str, args)), input=password, capture_output=True,
                                   timeout=seconds)
        if (completed.returncode == 0) != success:
            record('command-failure-' + str(time.time_ns()) + '.json', dict(
                argv=list(map(str, args)), returncode=completed.returncode,
                expected_success=success, stderr=completed.stderr[:8192].decode(errors='replace')))
            raise ValueError('bounded acceptance command unexpectedly accepted/rejected')
        return completed

    def tool(*args, success=True):
        return command([sys.executable, '-I', '-B', stage / 'verifier/wallet_release.py', *args],
                       success=success)

    def wait_until(predicate, seconds=20):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(.05)
        raise TimeoutError('bounded fixture condition timed out')

    def bundle():
        value = release.decode(release.read(stage / 'installation/state.json', 16384, True))
        return stage / 'installation/releases' / release.version(value['active']['release']) / 'bundle'

    def stop_group(group):
        try:
            os.killpg(group, signal.SIGTERM)
        except ProcessLookupError:
            return
        end = time.monotonic() + 3
        while time.monotonic() < end:
            try:
                os.killpg(group, 0)
            except ProcessLookupError:
                return
            time.sleep(.05)
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def port_unused(port):
        with socket.socket() as listener:
            try:
                listener.bind(('127.0.0.1', port))
                return True
            except OSError:
                return False

    def expired(*_):
        raise Deadline('finite offline release acceptance240s limit')

    signal.signal(signal.SIGALRM, expired)
    signal.signal(signal.SIGTERM, expired)
    signal.alarm(240)
    started = time.monotonic()
    try:
        # Disposable publisher material is outside every bundle and deleted in
        # finally. Retained public fingerprints/signatures still verify receipts.
        key_directory = tempfile.TemporaryDirectory(prefix='rehearsal-keys-', dir=stage)
        key_root = Path(key_directory.name)
        for name in ('publisher', 'wrong-publisher'):
            key = release.crypto(['genpkey', '-algorithm', 'EC', '-pkeyopt',
                                  'ec_paramgen_curve:P-256', '-pkeyopt',
                                  'ec_param_enc:named_curve'], b'')
            release.create(key_root / (name + '.pem'), key)
            public = release.crypto(['pkey', '-pubout'], key)
            release.create(stage / (name + '.pub'), public)
        public = release.read(stage / 'publisher.pub', 16384, True)
        publisher_pin = sha(release.public_der(public))
        result['disposable_publisher_public_der_sha256'] = publisher_pin
        tool('init', '--root', stage / 'installation', '--public-key', stage / 'publisher.pub',
             '--key-sha256', publisher_pin, '--profile-sha256', profile_sha256,
             '--channel', CHANNEL, '--minimum-sequence', 1)
        # Reuse the canonical deterministic builder, not an alternate installer.
        builder = Path(__file__).resolve().with_name('package_wallet.py')
        builder_bytes = builder.read_bytes()
        check(not builder.is_symlink() and sha(builder_bytes) == BUILDER_SHA,
              'reviewed deterministic archive builder changed')
        builder_spec = importlib.util.spec_from_file_location('local075_archive_builder', builder)
        builder_module = importlib.util.module_from_spec(builder_spec)
        exec(compile(builder_bytes, str(builder), 'exec'), builder_module.__dict__)
        package_archive = builder_module.archive
        for number in range(1, 6):
            if number > 1:
                changed = dict(files)
                changed['README.txt'] += ('\nLOCAL075 isolated signed update ' + str(number) + '\n').encode()
                changed_manifest = release.decode(files['MANIFEST.json'])
                changed_manifest['files']['README.txt'] = dict(size=len(changed['README.txt']),
                                                               sha256=sha(changed['README.txt']))
                changed['MANIFEST.json'] = release.encode(changed_manifest)
                release.create(stage / ('wallet-' + str(number) + '.tar.gz'),
                               package_archive(changed, {'bin/native-wallet': 0o755,
                                                         'start-wallet.command': 0o755}))
            tool('sign', '--archive', stage / ('wallet-' + str(number) + '.tar.gz'),
                 '--private-key', key_root / 'publisher.pem', '--channel', CHANNEL,
                 '--sequence', number, '--output', stage / ('release-' + str(number) + '.json'))
        # Negative verification never launches downloaded code or reads a wallet.
        tampered = bytearray(input_bytes)
        tampered[len(tampered) // 2] ^= 1
        release.create(stage / 'tampered.tar.gz', bytes(tampered))
        tool('verify', '--root', stage / 'installation', '--archive', stage / 'tampered.tar.gz',
             '--release', stage / 'release-1.json', success=False)
        tool('sign', '--archive', stage / 'wallet-1.tar.gz', '--private-key',
             key_root / 'wrong-publisher.pem', '--channel', CHANNEL, '--sequence', 1,
             '--output', stage / 'wrong-publisher.json')
        tool('verify', '--root', stage / 'installation', '--archive', stage / 'wallet-1.tar.gz',
             '--release', stage / 'wrong-publisher.json', success=False)
        tool('init', '--root', stage / 'wrong-profile-installation', '--public-key',
             stage / 'publisher.pub', '--key-sha256', publisher_pin,
             '--profile-sha256', '0' * 64, '--channel', CHANNEL, '--minimum-sequence', 1)
        tool('verify', '--root', stage / 'wrong-profile-installation', '--archive',
             stage / 'wallet-1.tar.gz', '--release', stage / 'release-1.json', success=False)
        result['preexecution_rejections'] = ['tampered-archive', 'wrong-publisher', 'wrong-profile-policy']
        tool('verify', '--root', stage / 'installation', '--archive', stage / 'wallet-1.tar.gz',
             '--release', stage / 'release-1.json')
        tool('install', '--root', stage / 'installation', '--archive', stage / 'wallet-1.tar.gz',
             '--release', stage / 'release-1.json')
        tool('run', '--root', stage / 'installation', '--', '--verify')
        # New fixture identity only. init/address/restore are offline commands;
        # no imported UI action, sponsor, faucet, invitation or RPC is used.
        data = stage / 'fixture-data'
        directory = data / 'wallet-ui'
        directory.mkdir(mode=0o700, parents=True)
        data.chmod(0o700)
        password = ('Local075-fixture-' + secrets.token_urlsafe(24)).encode()
        wallet, backup = directory / 'wallet.json', directory / 'recovery.json'
        binary, profile = bundle() / 'bin/native-wallet', bundle() / 'wallet-profile.json'
        identity = json.loads(command([binary, 'init', '--network', profile, '--wallet', wallet,
                                      '--backup', backup, '--password-file', '-'], password).stdout)
        address = identity['address']
        release.create(directory / 'backup-confirmed', b'')
        for name in ('pending.json', 'staging.json'):
            release.create(Path(str(wallet) + '.' + name),
                           release.encode(dict(local075_synthetic_preservation_sentinel=True,
                                               never_submit_or_resolve=True)))
        preserved = [wallet, backup, directory / 'backup-confirmed',
                     Path(str(wallet) + '.pending.json'), Path(str(wallet) + '.staging.json')]
        baseline = {p.name: sha(p.read_bytes()) for p in preserved}
        record('fixture-before.json', dict(address=address, encrypted_files=baseline))
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        log_path = stage / 'owned-wallet-runner.log'
        with log_path.open('xb') as log:
            runner = subprocess.Popen([sys.executable, '-I', '-B',
                str(stage / 'verifier/wallet_release.py'), 'run', '--root', str(stage / 'installation'),
                '--', '--no-browser', '--duration', '60', '--port', str(port), '--data-dir', str(data)],
                stdout=log, stderr=log, start_new_session=True)
        children.append(runner)
        groups.append(runner.pid)
        expected_line = ('Local wallet: http://127.0.0.1:' + str(port) + ' ').encode()
        wait_until(lambda: runner.poll() is None and expected_line in log_path.read_bytes())
        # No HTTP request is needed: the owned launcher's flushed bind-ready line
        # and the inherited installation lock establish this specific assertion.
        runner.kill()
        runner.wait(timeout=5)
        tool('install', '--root', stage / 'installation', '--archive', stage / 'wallet-2.tar.gz',
             '--release', stage / 'release-2.json', success=False)
        check(not port_unused(port), 'owned helper must remain after trusted parent SIGKILL')
        result['inherited_installation_lock_survived_runner_sigkill'] = True
        stop_group(runner.pid)
        wait_until(lambda: port_unused(port))
        groups.remove(runner.pid)
        outcomes = []
        for number, point in enumerate(POINTS, 2):
            with (stage / ('install-crash-' + str(number) + '.log')).open('xb') as log:
                child = subprocess.Popen([sys.executable, '-I', '-B', str(Path(__file__).resolve()),
                    '--worker', '--stage', str(stage), '--sequence', str(number), '--checkpoint', point,
                    '--profile-sha256', profile_sha256],
                    stdout=log, stderr=log, start_new_session=True)
            children.append(child)
            groups.append(child.pid)
            wait_until(lambda: (stage / ('checkpoint-' + str(number) + '.json')).exists(), 30)
            marker = release.decode(release.read(stage / ('checkpoint-' + str(number) + '.json'), 8192, True))
            check(marker == dict(point=point, pid=child.pid), 'exact owned stopped installer required')
            child.kill()
            child.wait(timeout=5)
            groups.remove(child.pid)
            state = release.decode(release.read(stage / 'installation/state.json', 16384, True))
            check(state['sequence'] == (number if point == 'activated' else number - 1),
                  'SIGKILL changed unexpected activation boundary')
            if point != 'activated':
                tool('run', '--root', stage / 'installation', '--', '--verify', success=False)
            tool('install', '--root', stage / 'installation', '--archive', stage / ('wallet-' + str(number) + '.tar.gz'),
                 '--release', stage / ('release-' + str(number) + '.json'))
            tool('run', '--root', stage / 'installation', '--', '--verify')
            check(('LOCAL075 isolated signed update ' + str(number)).encode() in
                  (bundle() / 'README.txt').read_bytes(), 'signed changed contents were not activated')
            identity = json.loads(command([bundle() / 'bin/native-wallet', 'address', '--network',
                bundle() / 'wallet-profile.json', '--wallet', wallet, '--password-file', '-'], password).stdout)
            check(identity['address'] == address and {p.name: sha(p.read_bytes()) for p in preserved} == baseline,
                  'fresh fixture identity/ciphertext/recovery/synthetic journal changed')
            outcomes.append(dict(point=point, actual_sigkill=True, recovered_sequence=number,
                                 fixture_files_unchanged=True))
            record('checkpoint-result-' + str(number) + '.json', outcomes[-1])
        tool('verify', '--root', stage / 'installation', '--archive', stage / 'wallet-1.tar.gz',
             '--release', stage / 'release-1.json', success=False)
        result['preexecution_rejections'].append('signed-release-rollback')
        restored_dir = stage / 'offline-restored-fixture'
        restored_dir.mkdir(mode=0o700)
        restored = json.loads(command([bundle() / 'bin/native-wallet', 'restore', '--network',
            bundle() / 'wallet-profile.json', '--wallet', restored_dir / 'wallet.json',
            '--backup', backup, '--password-file', '-'], password).stdout)
        check(restored['address'] == address, 'offline encrypted backup restored a different identity')
        check({p.name: sha(p.read_bytes()) for p in preserved} == baseline,
              'offline restore modified original fixture bytes')
        password = b''
        result.update(status='passed', crash_checkpoints=outcomes, final_sequence=5,
                      fixture_wallet_and_recovery_unchanged=True,
                      synthetic_pending_and_staging_unchanged=True,
                      offline_encrypted_restore_same_address=True,
                      no_rpc_or_http_requests=True, fixture_listener_closed=port_unused(port),
                      signed_contents_changed_and_activated=True,
                      publisher_trust_scope='disposable isolated rehearsal, not production custody or delivery',
                      apple_signing_or_notarization=False)
    except BaseException as error:
        result.update(status='failed', error_type=type(error).__name__)
        raise
    finally:
        signal.alarm(30)
        errors = []
        for group in list(groups):
            try:
                stop_group(group)
            except OSError:
                errors.append('owned_group_cleanup_failed')
        for child in children:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)
        if key_directory is not None:
            key_directory.cleanup()
        result.update(seconds=time.monotonic() - started,
                      all_owned_direct_children_stopped=all(c.poll() is not None for c in children),
                      disposable_private_keys_removed=True, cleanup_errors=errors)
        record('result.json', result)
        signal.alarm(0)
    check(not errors, 'owned fixture cleanup failed; preserve receipts')
    print(json.dumps(dict(status='passed', stage=str(stage), result_sha256=sha((stage / 'result.json').read_bytes()),
                          validators_started=0, rpc_requests=0, financial_operations=0)), flush=True)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    p.add_argument('--archive', type=Path)
    p.add_argument('--stage', type=Path, required=True)
    p.add_argument('--profile-sha256', type=profile_pin, default=PROFILE_SHA,
                   help='independently reviewed public profile pin; defaults to the original074 profile')
    p.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--sequence', type=int, choices=range(2, 6), help=argparse.SUPPRESS)
    p.add_argument('--checkpoint', choices=POINTS, help=argparse.SUPPRESS)
    args = p.parse_args()
    os.umask(0o077)
    if args.worker:
        check(args.archive is None and args.sequence is not None and args.checkpoint is not None,
              'exact finite worker arguments required')
        worker(args.stage.absolute(), args.sequence, args.checkpoint, args.profile_sha256)
    else:
        check(args.archive is not None and args.sequence is None and args.checkpoint is None,
              'explicit --archive and new --stage required')
        rehearse(args.archive, args.stage, args.profile_sha256)


if __name__ == '__main__':
    main()
