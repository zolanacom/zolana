import os
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
from unittest.mock import patch

from restart_tail_service import copy_owned


class IsolatedLedgerCopyTests(unittest.TestCase):
    def test_snapshot_account_links_resolve_inside_copy_and_cannot_write_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'ledger-0';destination=root/'copy'
            (source/'accounts').mkdir(parents=True);(source/'snapshots/8').mkdir(parents=True)
            original=source/'accounts/data';original.write_bytes(b'original')
            (source/'snapshots/8/account_path_0').symlink_to(source/'accounts')
            def clone(args,**kwargs):
                self.assertEqual(args[:2],['/bin/cp','-cRP'])
                shutil.copytree(source,destination,symlinks=True)
            with patch('restart_tail_service.subprocess.run',side_effect=clone):copy_owned(source,destination)
            linked=destination/'snapshots/8/account_path_0'
            self.assertEqual(linked.resolve(),destination/'accounts')
            (linked/'data').write_bytes(b'changed copy')
            self.assertEqual(original.read_bytes(),b'original')
            self.assertNotEqual(original.stat().st_ino,(linked/'data').stat().st_ino)

    def test_escaping_snapshot_link_is_rejected_before_copying_anything(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();source=root/'ledger-0';source.mkdir()
            (source/'account_path_0').symlink_to(root/'outside')
            with patch('restart_tail_service.subprocess.run') as run:
                with self.assertRaisesRegex(ValueError,'escapes'):copy_owned(source,root/'copy')
                run.assert_not_called()

    def test_only_stale_top_level_admin_socket_is_excluded_and_original_is_preserved(self):
        for name in ['admin.rpc','unexpected.sock']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root=Path(directory).resolve();source=root/'ledger-0';source.mkdir();destination=root/'copy'
                (source/'genesis.bin').write_bytes(b'original')
                with socket.socket(socket.AF_UNIX) as endpoint:
                    endpoint.bind(str(source/name))
                def clone(args,**kwargs):
                    self.assertEqual(args[:2],['/bin/cp','-cRP'])
                    shutil.copy2(args[2],args[3])
                with patch('restart_tail_service.subprocess.run',side_effect=clone) as run:
                    if name=='admin.rpc':
                        copy_owned(source,destination)
                        self.assertEqual((destination/'genesis.bin').read_bytes(),b'original')
                        self.assertFalse((destination/name).exists())
                        self.assertTrue((source/name).is_socket())
                    else:
                        with self.assertRaisesRegex(ValueError,'special file'):copy_owned(source,destination)
                        run.assert_not_called()


if __name__=='__main__':unittest.main()
