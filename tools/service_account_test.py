import hashlib
import json
import os
from pathlib import Path
import plistlib
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import service_account as service
from localnet import offset,port,digest


class ServiceIsolationTests(unittest.TestCase):
    def test_launchd_uses_a_nonlogin_uid_isolated_python_and_owned_process_group(self):
        config=service.launch_config()
        self.assertEqual(config['UserName'],'_nativepay')
        self.assertEqual(config['GroupName'],'_nativepay')
        self.assertEqual(config['ProgramArguments'][:2],['/usr/bin/python3','-I'])
        self.assertEqual(config['ProgramArguments'][-1],'run')
        self.assertEqual(config['Umask'],63)
        self.assertFalse(config['AbandonProcessGroup'])
        self.assertTrue(config['KeepAlive'])
        self.assertEqual(config['ProcessType'],'Interactive')
        self.assertEqual(config['EnvironmentVariables']['PATH'],'/usr/bin:/bin')
        self.assertNotIn('PYTHONPATH',config['EnvironmentVariables'])
        self.assertEqual(plistlib.loads(plistlib.dumps(config)),config)
    def test_restart_fingerprints_work_on_the_system_python(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'checkpoint'
            data=b'checkpoint\x00' * 200000
            path.write_bytes(data)
            self.assertEqual(digest(path),hashlib.sha256(data).hexdigest())
    def test_service_ports_leave_the_existing_demo_and_inspection_ports_unchanged(self):
        self.assertEqual(port(0),18899);self.assertEqual(port(1),19899)
        self.assertEqual([port(i,offset({'local_port_offset':5000})) for i in [0,1]],[23899,24899])
        for value in [1,True,'5000',-5000,60000]:
            with self.assertRaises(ValueError):offset({'local_port_offset':value})
    def test_bundle_is_exact_digest_bound_and_rejects_replacement_or_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.mkdir();output=root/'bundle'
            for name in service.FILES:
                p=source/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('fixture '+name)
            report=service.prepare(source,output)
            self.assertFalse(report['keys_generated']);self.assertFalse(report['installed'])
            service.verify_bundle(output,report['manifest_sha256'])
            binary=output/'target/debug/agave-validator';binary.chmod(0o600);binary.write_text('replaced')
            with self.assertRaises(ValueError):service.verify_bundle(output,report['manifest_sha256'])
            binary.unlink();binary.symlink_to(source/'target/debug/agave-validator')
            with self.assertRaises(OSError):service.verify_bundle(output,report['manifest_sha256'])
            with self.assertRaises(ValueError):service.prepare(source,output)
    def test_manifest_cannot_add_arbitrary_privileged_install_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);manifest={'format':'native-service-bundle-v1','files':{'../../other':{'size':1,'sha256':'a'*64}}}
            (root/'MANIFEST.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):service.verify_bundle(root)
            with self.assertRaises(ValueError):service.verify_bundle(root,'b'*64)
    def test_desktop_owned_service_code_is_not_a_trusted_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'runtime.py';path.write_text('pass');path.chmod(0o444)
            if os.getuid()!=0:
                with self.assertRaises(ValueError):service.trusted(path)
    def test_nonadministrator_cannot_install_or_run_privileged_acceptance(self):
        with patch.object(service.os,'geteuid',return_value=501),patch.object(service.sys,'platform','darwin'):
            with self.assertRaises(PermissionError):service.install(Path('unused'),'a'*64,501)
            with self.assertRaises(PermissionError):service.update(Path('unused'),'a'*64)
            with self.assertRaises(PermissionError):service.acceptance()
    def test_public_health_provision_is_exact_and_rejects_occupied_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);config={'uid':os.getuid(),'gid':os.getgid()}
            with patch.object(service,'INSTALL',root),patch.object(service.os,'chown'):
                self.assertTrue(service.provision_health(config));self.assertFalse(service.provision_health(config))
                service.check_health_directory(root,config)
                (root/'health').chmod(0o777)
                with self.assertRaises(ValueError):service.provision_health(config)
                (root/'health').rmdir();(root/'health').symlink_to(root)
                with self.assertRaises(ValueError):service.provision_health(config)
                (root/'health').unlink()
                with patch.object(service.os,'chown',side_effect=OSError('provision failed')):
                    with self.assertRaises(OSError):service.provision_health(config)
                self.assertFalse((root/'health').exists())
    def test_failed_upgrade_removes_only_new_health_directory_and_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source';source.mkdir()
            for name in service.FILES:
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('fixture '+name)
            installed=root/'installed';bundle=root/'bundle';service.prepare(source,installed)
            legacy=json.loads((installed/'MANIFEST.json').read_text());legacy['format']='native-service-bundle-v6'
            legacy['files']={n:v for n,v in legacy['files'].items() if n in service.V6_FILES}
            for name in set(service.FILES)-set(service.V6_FILES):(installed/name).unlink()
            manifest=installed/'MANIFEST.json';manifest.chmod(0o600);manifest.write_text(json.dumps(legacy))
            before=manifest.read_bytes();report=service.prepare(source,bundle)
            (installed/'.data').mkdir();private=installed/'.data/original';private.write_text('preserve')
            config={'uid':os.getuid(),'gid':os.getgid()}
            with patch.object(service,'INSTALL',installed),patch.object(service,'require_root'),patch.object(service,'trusted'),patch.object(service.os,'chown'),patch.object(service,'verify_install',side_effect=[config,ValueError('new seal failed')]),patch.object(service.subprocess,'run',return_value=SimpleNamespace(returncode=113)),patch.object(service,'command') as command:
                with self.assertRaisesRegex(ValueError,'new seal failed'):service.update(bundle,report['manifest_sha256'])
                command.assert_not_called()
            self.assertFalse((installed/'health').exists());self.assertFalse((installed/'tools/operator_health.py').exists())
            self.assertEqual(manifest.read_bytes(),before);self.assertEqual(private.read_text(),'preserve')
    def test_reviewed_update_preserves_private_state_and_rolls_back_failed_verification(self):
        for fail in [False,True]:
            with self.subTest(failed_verification=fail),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);source=root/'source';source.mkdir()
                file='tools/service_account.py';(source/'tools').mkdir();(source/file).write_bytes(b'old code')
                installed=root/'installed';bundle=root/'bundle'
                with patch.object(service,'FILES',(file,)):
                    service.prepare(source,installed)
                    (installed/'.data').mkdir();key=installed/'.data/original.key';key.write_bytes(b'original secret')
                    original_manifest=(installed/'MANIFEST.json').read_bytes()
                    (source/file).write_bytes(b'reviewed replacement')
                    report=service.prepare(source,bundle)
                    checks=[{},ValueError('new seal invalid')] if fail else [{},{}]
                    with patch.object(service,'INSTALL',installed),patch.object(service,'provision_health',return_value=False),patch.object(service,'require_root'),patch.object(service,'trusted'),patch.object(service,'verify_install',side_effect=checks),patch.object(service.subprocess,'run',return_value=SimpleNamespace(returncode=0)),patch.object(service,'command') as command:
                        if fail:
                            with self.assertRaises(ValueError):service.update(bundle,report['manifest_sha256'])
                            self.assertEqual((installed/file).read_bytes(),b'old code')
                            self.assertEqual((installed/'MANIFEST.json').read_bytes(),original_manifest)
                        else:
                            result=service.update(bundle,report['manifest_sha256'])
                            self.assertEqual(result['updated_files'],[file])
                            self.assertEqual((installed/file).read_bytes(),b'reviewed replacement')
                        self.assertEqual(key.read_bytes(),b'original secret')
                        self.assertEqual([call.args[0][1] for call in command.call_args_list],['bootout','bootstrap'])
    def test_reviewed_inventory_upgrade_keeps_paused_service_paused_and_rolls_back_new_files(self):
        for version,inventory in [(1,service.LEGACY_FILES),(2,service.V2_FILES),(3,service.V3_FILES),(4,service.V4_FILES),(5,service.V5_FILES),(6,service.V6_FILES)]:
            for fail in (False,True):
                with self.subTest(failed_verification=fail),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);source=root/'source';source.mkdir()
                    for name in service.FILES:
                        path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('fixture '+name).encode())
                    installed=root/'installed';bundle=root/'bundle'
                    service.prepare(source,installed)
                    legacy=json.loads((installed/'MANIFEST.json').read_text());legacy['format']='native-service-bundle-v%d'%version
                    legacy['files']={n:v for n,v in legacy['files'].items() if n in inventory}
                    for name in set(service.FILES)-set(inventory):(installed/name).unlink()
                    manifest=installed/'MANIFEST.json';manifest.chmod(0o600);manifest.write_text(json.dumps(legacy))
                    report=service.prepare(source,bundle)
                    checks=[{},ValueError('new seal invalid')] if fail else [{},{}]
                    with patch.object(service,'INSTALL',installed),patch.object(service,'provision_health',return_value=False),patch.object(service,'require_root'),patch.object(service,'trusted'),patch.object(service,'verify_install',side_effect=checks),patch.object(service.subprocess,'run',return_value=SimpleNamespace(returncode=113)),patch.object(service,'command') as command:
                        if fail:
                            with self.assertRaises(ValueError):service.update(bundle,report['manifest_sha256'])
                        else:self.assertTrue(service.update(bundle,report['manifest_sha256'])['service_left_paused'])
                        command.assert_not_called()
                    self.assertEqual(service.verify_bundle(installed)['format'],'native-service-bundle-v%d'%version if fail else 'native-service-bundle-v7')
                    self.assertEqual((installed/'tools/history_retention.py').exists(),version>=3 or not fail)
                    self.assertEqual((installed/'tools/gateway_history.py').exists(),version>=4 or not fail)
                    self.assertEqual((installed/'tools/gateway_archival.py').exists(),version>=5 or not fail)
                    self.assertEqual((installed/'tools/history_replica.py').exists(),version>=6 or not fail)
                    self.assertEqual((installed/'tools/operator_health.py').exists(),not fail)
                    self.assertEqual((installed/'target/debug/native-faucet').exists(),version>=2 or not fail)


if __name__=='__main__':unittest.main()
