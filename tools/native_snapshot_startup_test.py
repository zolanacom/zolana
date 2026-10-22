"""No services or wallets: seal rejection and unchanged supervisor safety checks."""
import ast
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import native_snapshot_startup as startup


class SnapshotStartupTests(unittest.TestCase):
    def test_supervisor_changes_only_the_verified_runner_path(self):
        old = ast.parse(Path(startup.__file__).with_name('native_validator_startup.py').read_text())
        new = ast.parse(Path(startup.__file__).read_text())
        original = next(n for n in old.body if isinstance(n, ast.FunctionDef) and n.name == 'validator')
        actual = next(n for n in new.body if isinstance(n, ast.FunctionDef) and n.name == 'validator')
        expected = copy.deepcopy(original)
        changes = 0
        old_path = ast.dump(ast.parse("PREFIX/'bin/zolana-fast-check'", mode='eval').body)
        for n in ast.walk(expected):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == 'str' and len(n.args) == 1:
                if ast.dump(n.args[0]) == old_path:
                    n.args[0] = ast.Name(id='RUNNER_PATH', ctx=ast.Load())
                    changes += 1
        self.assertEqual(changes, 1)
        self.assertEqual(ast.dump(actual), ast.dump(expected))
        self.assertEqual(startup.BASE_SHA256, '5f102297516b40ff8299def02e6a993e4277e3f80bc6ed958102b5781b106a7a')

    def runner(self, directory, raw=b'local immutable executable fixture\n'):
        path = Path(directory) / 'runner'
        if path.exists():
            path.chmod(0o600)
        path.write_bytes(raw)
        path.chmod(0o555)
        return path, hashlib.sha256(raw).hexdigest()

    def test_only_exact_readonly_owned_runner_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(startup, 'root_ancestors'):
            path, digest = self.runner(directory)
            startup.sealed_runner(path, digest, owner=os.getuid())
            for bad in ('', 'g'*64, '0'*64):
                with self.assertRaises(ValueError):
                    startup.sealed_runner(path, bad, owner=os.getuid())
            with self.assertRaises(ValueError):
                startup.sealed_runner(path, digest, owner=os.getuid()+1)
            path.chmod(0o755)
            with self.assertRaises(ValueError):
                startup.sealed_runner(path, digest, owner=os.getuid())

    def test_empty_oversized_and_symlink_runner_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(startup, 'root_ancestors'), \
                patch.object(startup, 'MAX_RUNNER_BYTES', 32):
            for raw in (b'', b'x'*33):
                path, digest = self.runner(directory, raw)
                with self.assertRaises(ValueError):
                    startup.sealed_runner(path, digest, owner=os.getuid())
            path, digest = self.runner(directory, b'fixture')
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                startup.sealed_runner(link, digest, owner=os.getuid())

    def test_uninstalled_wrapper_cannot_load_original_runtime(self):
        self.assertEqual(startup.INSTALLED_PATH, Path('/etc/zolana-native-072/validator-startup.py'))
        self.assertEqual(startup.RUNNER_PATH, Path('/opt/zolana-native-072/bin/zolana-fast-check'))
        with patch('sys.argv', ['wrapper', '--sha256', '0'*64, '--runner-sha256', '1'*64]), \
                patch.object(startup, 'load_original') as load:
            with self.assertRaisesRegex(ValueError, 'fixed sealed installation path'):
                startup.main()
            load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
