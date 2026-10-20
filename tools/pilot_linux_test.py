"""Portable candidate checks; synthetic ELF headers are never executed."""
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pilot_linux as linux
from wallet_release import create, decode, encode, sha


def executable():
    raw = bytearray(64)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', raw, 16, 3, 62, 1)
    struct.pack_into('<H', raw, 52, 64)
    return bytes(raw)


class LinuxTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='linux-pilot-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.source = self.base / 'source'; self.source.mkdir(mode=0o700)
        self.build = self.base / 'build'; self.build.mkdir(mode=0o700)
        self.bundle = self.base / 'bundle'
        binaries = {}
        for name in linux.FILES:
            path = (self.build / 'target' / linux.TARGET / 'debug' / Path(name).name
                    if name.startswith('target/') else self.source / name)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = executable() if name.startswith('target/') else ('fixture ' + name).encode()
            create(path, raw)
            if name.startswith('target/'):
                binaries[Path(name).name] = dict(size=len(raw), sha256=sha(raw))
        create(self.source / 'Cargo.lock', b'fixture lock')
        self.receipt = dict(format='zolana-linux-build-v1', target=linux.TARGET, rustc_release='1.92.0',
                            source_commit='b' * 40, cargo_lock_sha256=sha(b'fixture lock'),
                            offline=True, jobs=2, profile='dev', binaries=binaries, runtime_tested=False)
        create(self.build / linux.RECEIPT, encode(self.receipt))

    def prepare(self):
        def git(*args):
            return 'b' * 40 if args == ('rev-parse', 'HEAD') else ''
        with patch.object(linux, 'linux'), patch.object(linux, 'PROJECT', self.source), patch.object(linux, 'git', git):
            return linux.prepare(self.build, self.bundle)

    def test_bundle_matches_binaries_and_preserves_not_tested_status(self):
        result = self.prepare()
        self.assertEqual(result['services_started'], 0)
        manifest = linux.verify(self.bundle, result['manifest_sha256'])
        self.assertFalse(manifest['activation_enabled'])
        self.assertEqual(set(manifest['files']), {*linux.FILES, linux.RECEIPT})
        self.assertFalse(decode((self.bundle / linux.RECEIPT).read_bytes())['runtime_tested'])

    def test_macho_arm_elf_and_truncated_headers_refused(self):
        linux.elf(executable())
        for raw in (b'\xcf\xfa\xed\xfe' + bytes(80), executable()[:63], b'not an ELF file',
                    executable()[:18] + b'\xb7\x00' + executable()[20:]):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                linux.elf(raw)

    def test_build_and_prepare_refuse_darwin_before_side_effects(self):
        with patch.object(linux.platform, 'system', return_value='Darwin'), patch.object(linux.subprocess, 'check_output') as child:
            with self.assertRaises(ValueError): linux.build(self.base / 'never-built')
            with self.assertRaises(ValueError): linux.prepare(self.build, self.bundle)
            with self.assertRaises(ValueError): linux.run('a' * 64, 'b' * 64)
        child.assert_not_called()
        self.assertFalse((self.base / 'never-built').exists()); self.assertFalse(self.bundle.exists())

    def test_invalid_jobs_refused_before_compiler_or_output(self):
        with patch.object(linux, 'linux'), patch.object(linux.subprocess, 'check_output') as compiler:
            for jobs in (True, 0, 1, 9, '8'):
                with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                    linux.build(self.base / 'never-built', jobs)
        compiler.assert_not_called(); self.assertFalse((self.base / 'never-built').exists())

    def test_eight_job_receipt_retains_real_count_and_bounds(self):
        for jobs in (2, 4, 8):
            value = dict(self.receipt, jobs=jobs)
            self.assertEqual(linux.validate_receipt(encode(value), value['binaries'])['jobs'], jobs)
        for jobs in (1, 9):
            with self.assertRaises(ValueError):
                linux.validate_receipt(encode(dict(self.receipt, jobs=jobs)), self.receipt['binaries'])

    def test_failed_linux_compiler_keeps_log_without_completion_or_bundle(self):
        output = self.base / 'compiler-failure'
        def failed(command, **kwargs):
            self.assertIn('--offline', command); self.assertIn('--locked', command)
            self.assertEqual(kwargs['env']['CARGO_TARGET_DIR'], str(output / 'target'))
            self.assertNotEqual(kwargs['env']['CARGO_TARGET_DIR'], str(self.source / 'target'))
            kwargs['stdout'].write(b'fixture compiler failure\n')
            raise subprocess.CalledProcessError(1, command)
        def git(*args):
            return 'b' * 40 if args == ('rev-parse', 'HEAD') else ''
        with patch.object(linux, 'linux'), patch.object(linux, 'PROJECT', self.source), \
                patch.object(linux, 'git', git), \
                patch.object(linux.subprocess, 'check_output', return_value='release: 1.92.0\nhost: ' + linux.TARGET), \
                patch.object(linux.subprocess, 'run', side_effect=failed):
            with self.assertRaises(subprocess.CalledProcessError): linux.build(output)
        self.assertEqual((output / 'build.log').read_bytes(), b'fixture compiler failure\n')
        self.assertFalse((output / linux.RECEIPT).exists()); self.assertFalse(self.bundle.exists())

    def test_source_change_during_linux_compile_cannot_publish_a_receipt(self):
        output = self.base / 'changed-source'
        changed = [False]
        def git(*args):
            if args == ('rev-parse', 'HEAD'): return ('c' if changed[0] else 'b') * 40
            return ''
        def compile(*args, **kwargs): changed[0] = True
        with patch.object(linux, 'linux'), patch.object(linux, 'PROJECT', self.source), \
                patch.object(linux, 'git', git), \
                patch.object(linux.subprocess, 'check_output', return_value='release: 1.92.0\nhost: ' + linux.TARGET), \
                patch.object(linux.subprocess, 'run', side_effect=compile):
            with self.assertRaises(ValueError): linux.build(output)
        self.assertTrue((output / 'build.log').exists())
        self.assertFalse((output / linux.RECEIPT).exists())

    def test_tamper_extra_link_and_wrong_digest_refused(self):
        result = self.prepare(); digest = result['manifest_sha256']
        with self.assertRaises(ValueError): linux.verify(self.bundle, '0' * 64)
        path = self.bundle / 'LICENSE'; original = path.read_bytes()
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError): linux.verify(self.bundle, digest)
        path.write_bytes(original)
        extra = self.bundle / 'tools/extra.py'; create(extra, b'injected')
        with self.assertRaises(ValueError): linux.verify(self.bundle, digest)
        extra.unlink(); path.unlink(); path.symlink_to(self.source / 'LICENSE')
        with self.assertRaises((ValueError, OSError)): linux.verify(self.bundle, digest)

    def test_receipt_cannot_claim_runtime_acceptance_or_different_build(self):
        for name, value in (('runtime_tested', True), ('target', 'aarch64-apple-darwin'), ('jobs', True), ('offline', False)):
            changed = dict(self.receipt, **{name: value})
            with self.subTest(name=name), self.assertRaises(ValueError):
                linux.validate_receipt(encode(changed), self.receipt['binaries'])
        with self.assertRaises(ValueError): linux.validate_receipt(encode(self.receipt), {})

    def test_changed_source_or_wrong_platform_binary_prevents_bundle(self):
        with patch.object(linux, 'linux'), patch.object(linux, 'PROJECT', self.source), patch.object(linux, 'git', return_value='c' * 40):
            with self.assertRaises(ValueError): linux.prepare(self.build, self.bundle)
        self.assertFalse(self.bundle.exists())
        binary = self.build / 'target' / linux.TARGET / 'debug/native-wallet'
        binary.write_bytes(b'Mac binary')
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.bundle.exists())

    def test_incomplete_bundle_never_passes_and_original_output_not_overwritten(self):
        def crash(*args, **kwargs):
            create(*args, **kwargs)
            raise RuntimeError('interrupted bundle write')
        with patch.object(linux, 'create', crash):
            with self.assertRaises(RuntimeError): self.prepare()
        self.assertFalse((self.bundle / 'MANIFEST.json').exists())
        before = {str(p): p.read_bytes() for p in self.bundle.rglob('*') if p.is_file()}
        with self.assertRaises(FileExistsError): self.prepare()
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.bundle.rglob('*') if p.is_file()})

    def test_service_requires_approval_and_cgroup_cleanup_without_enabling(self):
        text = linux.unit('a' * 64, 'b' * 64).decode()
        for required in ('KillMode=control-group', 'SendSIGKILL=yes', 'NoNewPrivileges=yes',
                         'ReadWritePaths=/opt/zolana/.data', 'UMask=0077',
                         'ConditionPathExists=/etc/zolana-pilot/activation.json',
                         'User=zolanapilot', '--binding-sha256 ' + 'a' * 64,
                         '--manifest-sha256 ' + 'b' * 64):
            self.assertIn(required, text)
        self.assertNotIn('[Install]', text); self.assertNotIn('ExecStart=/bin/sh', text)
        for value in ('', 'a' * 63, 'a' * 64 + '\nExecStart=/bin/false'):
            with self.assertRaises(ValueError): linux.unit(value, 'b' * 64)

    def test_real_session_preserves_pid_and_child_group_then_owned_sigkill(self):
        script = '''import json,os,subprocess,sys
from pilot_linux import session
before=os.getpid();session()
child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
print(json.dumps([before,os.getpid(),os.getpgrp(),os.getpgid(child.pid)]),flush=True)
sys.stdin.read(1)
child.terminate();child.wait(timeout=5)
'''
        env = dict(os.environ, PYTHONPATH=str(linux.PROJECT / 'tools'))
        p = subprocess.Popen([sys.executable, '-B', '-c', script], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        try:
            values = json.loads(p.stdout.readline())
            self.assertEqual(values, [p.pid] * 4)
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate(timeout=10); self.assertEqual(p.returncode, -signal.SIGKILL)
        finally:
            if p.poll() is None:
                p.stdin.write('q'); p.stdin.flush(); p.communicate(timeout=10)

    def test_developer_tree_cannot_be_used_as_installed_service(self):
        with patch.object(linux, 'linux'), patch.object(linux.runtime, 'supervise') as supervisor:
            with self.assertRaises(ValueError): linux.run('a' * 64, 'b' * 64)
        supervisor.assert_not_called()

    def test_installed_entry_refuses_wrong_approval_and_private_state(self):
        # Root metadata is mocked here; actual root/UID denial remains a Linux gate.
        from types import SimpleNamespace
        approval = self.base / 'approval.json'
        private = self.base / '.data'; private.mkdir(mode=0o700)
        user = SimpleNamespace(pw_name=linux.ACCOUNT, pw_gid=os.getgid(),
                               pw_shell='/usr/sbin/nologin', pw_dir='/nonexistent')
        create(approval, encode(dict(format='zolana-linux-activation-v1',
                                    binding_sha256='a' * 64, manifest_sha256='c' * 64)))
        with patch.object(linux, 'linux'), patch.object(linux, 'PROJECT', self.base), \
                patch.object(linux, 'PREFIX', self.base), patch.object(linux, 'APPROVAL', approval), \
                patch.object(linux.pwd, 'getpwuid', return_value=user), \
                patch('grp.getgrgid', return_value=SimpleNamespace(gr_name=linux.ACCOUNT)), \
                patch.object(linux, 'sealed'), patch.object(linux, 'verify') as verify, \
                patch.object(linux.runtime, 'supervise') as supervisor:
            with self.assertRaises(ValueError): linux.run('a' * 64, 'b' * 64)
            verify.assert_not_called(); supervisor.assert_not_called()
            approval.write_bytes(encode(dict(format='zolana-linux-activation-v1',
                                            binding_sha256='a' * 64, manifest_sha256='b' * 64)))
            private.chmod(0o755)
            with self.assertRaises(ValueError): linux.run('a' * 64, 'b' * 64)
            verify.assert_not_called(); supervisor.assert_not_called()


if __name__ == '__main__': unittest.main()
