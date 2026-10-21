"""Metadata and AST checks only: no validators, RPC, service calls or key reads."""
import ast
import builtins
import copy
import hashlib
import os
from pathlib import Path
import symtable
import tempfile
import unittest
from unittest.mock import patch

import native_validator_startup as startup

ROOT = Path(__file__).resolve().parents[1]


class StartupTests(unittest.TestCase):
    def test_validator_changes_only_the_original_startup_deadline(self):
        original_path = ROOT/'tools/native_linux_service.py'
        original_raw = original_path.read_bytes()
        self.assertEqual(hashlib.sha256(original_raw).hexdigest(), startup.BASE_SHA256)
        original = next(node for node in ast.parse(original_raw).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'validator')
        candidate = next(node for node in ast.parse(Path(startup.__file__).read_text()).body
                         if isinstance(node, ast.FunctionDef) and node.name == 'validator')
        expected = copy.deepcopy(original)
        changes = 0
        for node in ast.walk(expected):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'deadline'):
                self.assertIsInstance(node.value, ast.BinOp)
                self.assertEqual(ast.dump(node.value.left),
                                 ast.dump(ast.parse('time.monotonic()', mode='eval').body))
                self.assertEqual(node.value.right.value, 180)
                node.value.right.value = 600
                changes += 1
        self.assertEqual(changes, 1)
        self.assertEqual(ast.dump(candidate), ast.dump(expected))

    def test_all_original_runtime_globals_are_explicitly_bound(self):
        text = Path(startup.__file__).read_text()
        namespace = symtable.symtable(text, startup.__file__, 'exec').lookup('validator').get_namespace()
        known = set(vars(startup)) | set(startup.ORIGINAL_EXPORTS) | set(vars(builtins))
        pending = [namespace]
        while pending:
            table = pending.pop()
            for symbol in table.get_symbols():
                if symbol.is_global() and symbol.is_referenced():
                    self.assertIn(symbol.get_name(), known)
            pending.extend(table.get_children())
        original = ast.parse((ROOT/'tools/native_linux_service.py').read_text())
        defined = {node.name for node in original.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
        defined |= {target.id for node in original.body if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)}
        self.assertLessEqual(set(startup.ORIGINAL_EXPORTS), defined)

    def source(self, directory, raw=b'public test source\n'):
        path = Path(directory)/'source.py'
        if path.exists():
            path.chmod(0o644)
        path.write_bytes(raw)
        path.chmod(0o444)
        return path, hashlib.sha256(raw).hexdigest()

    def test_sealed_source_requires_exact_digest_and_readonly_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            path, digest = self.source(folder)
            with patch.object(startup, 'root_ancestors'):
                self.assertEqual(startup.sealed_source(path, digest, owner=os.getuid()), path.read_bytes())
                for invalid in ('', 'g'*64, '0'*64):
                    with self.assertRaises(ValueError):
                        startup.sealed_source(path, invalid, owner=os.getuid())
                with self.assertRaises(ValueError):
                    startup.sealed_source(path, digest, owner=os.getuid()+1)
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    startup.sealed_source(path, digest, owner=os.getuid())

    def test_sealed_source_refuses_empty_oversized_and_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(startup, 'root_ancestors'):
                for raw in (b'', b'x'*(startup.MAX_SOURCE_BYTES+1)):
                    path, digest = self.source(folder, raw)
                    with self.assertRaises(ValueError):
                        startup.sealed_source(path, digest, owner=os.getuid())
                path, digest = self.source(folder)
                link = Path(folder)/'link.py'
                link.symlink_to(path)
                with self.assertRaises(OSError):
                    startup.sealed_source(link, digest, owner=os.getuid())

    def test_original_source_is_verified_before_import(self):
        with patch.object(startup, 'sealed_source', side_effect=ValueError('source rejected')) as sealed:
            with self.assertRaisesRegex(ValueError, 'source rejected'):
                startup.load_original()
            sealed.assert_called_once_with(startup.BASE_PATH, startup.BASE_SHA256)

    def test_main_rejects_a_noninstalled_wrapper_before_loading_the_base(self):
        self.assertEqual(startup.INSTALLED_PATH, Path('/etc/zolana-native-065/validator-startup.py'))
        with patch('sys.argv', ['validator-startup.py', '--sha256', '0'*64]), \
                patch.object(startup, 'load_original') as load:
            with self.assertRaisesRegex(ValueError, 'fixed sealed installation path'):
                startup.main()
            load.assert_not_called()


if __name__ == '__main__':
    unittest.main()
