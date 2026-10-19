import os
from pathlib import Path
import plistlib
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pilot_install as install
from wallet_release import create,encode,read,sha


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name).resolve()
        # Small stand-ins exercise the exact allowlist and copy engine without
        # duplicating 100 MB per negative-case test. A real bundle is tested live.
        self.source=self.base/'source';self.source.mkdir(mode=0o700)
        for name in install.FILES:
            path=self.source/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);create(path,('input '+name).encode())
        with patch.object(install,'PROJECT',self.source):self.receipt=install.prepare(self.base/'bundle')
        self.bundle=self.base/'bundle';self.digest=self.receipt['manifest_sha256'];self.prefix=self.base/'installed'
    def stage(self,hook=lambda _:None):return install.stage(self.bundle,self.digest,self.prefix,os.getuid(),os.getgid(),True,hook)
    def test_complete_and_repeat_preserve_original_private_state(self):
        first=self.stage();self.assertEqual(first['phase'],'installed-disabled');self.assertEqual(first['services_started'],0)
        create(self.prefix/'.data/wallet.key',b'original test bytes')
        self.assertEqual(self.stage(),first);self.assertEqual(read(self.prefix/'.data/wallet.key',64),b'original test bytes')
        for name in install.FILES:self.assertEqual((self.prefix/name).stat().st_mode&0o777,0o555 if name.startswith('target/') else 0o444)
        self.assertFalse(Path('/Library/LaunchDaemons/local.zolana.pilot.plist').exists())
    def test_changed_added_linked_inputs_fail_before_install(self):
        for mode in ('extra','link','changed'):
            path=self.bundle/('extra.key' if mode=='extra' else 'LICENSE')
            original=None if mode=='extra' else path.read_bytes()
            try:
                if mode=='link':path.unlink();path.symlink_to(self.source/'LICENSE')
                else:path.write_bytes(b'changed')
                with self.assertRaises((ValueError,OSError)):self.stage()
                self.assertFalse(self.prefix.exists())
            finally:
                path.unlink()
                if original is not None:create(path,original)
    def test_installed_tampering_extra_module_and_state_links_fail_closed(self):
        self.stage();path=self.prefix/'tools/extra.py';path.write_text('unexpected import')
        with self.assertRaises(ValueError):self.stage()
        path.unlink();path=self.prefix/'LICENSE';path.chmod(0o600);path.write_text('tampered')
        with self.assertRaises(ValueError):self.stage()
    def test_sigkill_during_copy_resumes_same_bytes_without_state_reset(self):
        script='''import os,signal,sys
from pathlib import Path
import pilot_install as i
def kill(stage):
 if stage=='copy-tools/pilot_runtime.py':os.kill(os.getpid(),signal.SIGKILL)
i.stage(Path(sys.argv[1]),sys.argv[2],Path(sys.argv[3]),os.getuid(),os.getgid(),True,kill)
'''
        child=subprocess.run([sys.executable,'-B','-c',script,str(self.bundle),self.digest,str(self.prefix)],cwd=install.PROJECT/'tools',capture_output=True,timeout=15)
        self.assertEqual(child.returncode,-9);self.assertFalse((self.prefix/'INSTALLED.json').exists())
        self.assertTrue((self.prefix/'tools/pilot_runtime.py.installing').exists())
        self.stage();self.stage()
        self.assertEqual((self.prefix/'tools/pilot_runtime.py').read_bytes(),(self.bundle/'tools/pilot_runtime.py').read_bytes())
    def test_partial_changed_copy_is_retained_for_review(self):
        def interrupted(_):raise RuntimeError('power loss')
        with self.assertRaises(RuntimeError):self.stage(interrupted)
        path=next(self.prefix.rglob('*.installing'));path.write_text('partial altered bytes')
        with self.assertRaises(ValueError):self.stage()
        self.assertEqual(path.read_text(),'partial altered bytes')
    def test_manager_is_disabled_bound_and_keeps_group_cleanup(self):
        p=plistlib.loads(install.launchd('a'*64))
        self.assertTrue(p['Disabled']);self.assertFalse(p['AbandonProcessGroup']);self.assertFalse(p['RunAtLoad'])
        self.assertTrue(p['KeepAlive']['UnsuccessfulExit']);self.assertEqual(p['UserName'],'_zolanapilot')
        self.assertEqual(p['ProgramArguments'][-1],'a'*64);self.assertEqual(p['EnvironmentVariables']['RAYON_NUM_THREADS'],'2')
        with self.assertRaises(ValueError):install.launchd('unknown')
    def test_wrong_identity_prefix_digest_and_competing_installer_refused(self):
        with self.assertRaises(ValueError):install.stage(self.bundle,self.digest,self.prefix,0,0,True)
        with self.assertRaises(ValueError):install.stage(self.bundle,'0'*64,self.prefix,os.getuid(),os.getgid(),True)
        with install.native_lock(self.prefix.with_name(self.prefix.name+'.install.lock')):
            with self.assertRaises(BlockingIOError):self.stage()


if __name__=='__main__':unittest.main()
