from pathlib import Path
import unittest
from unittest.mock import patch
import pilot_host as host
import pilot_cohort_test as fixtures
from wallet_release import encode,read


class HostTests(unittest.TestCase):
    setUp=fixtures.PilotTests.setUp
    def test_review_packet_is_bound_secret_free_and_disabled(self):
        output=self.base/'packet';receipt=host.prepare(self.value,output)
        self.assertFalse(receipt['activation_enabled']);self.assertEqual(receipt['hosts_contacted'],0)
        self.assertEqual(host.verify(output,receipt['manifest_sha256']),self.value)
        report=host.check(output,receipt['manifest_sha256'])
        self.assertFalse(report['activation_allowed']);self.assertFalse(report['ready_for_external_testers'])
        self.assertIn('profile-is-local-rehearsal-only',report['blockers'])
        self.assertNotIn(b'only-disposable-test-password',b''.join(p.read_bytes() for p in output.iterdir()))
        with self.assertRaises(FileExistsError):host.prepare(self.value,output)

    def test_changed_or_added_packet_files_are_rejected(self):
        for case in ('changed','added','symlink'):
            output=self.base/case;digest=host.prepare(self.value,output)['manifest_sha256']
            if case=='changed':(output/'SETUP.txt').write_text('enable service')
            elif case=='added':(output/'secret.key').write_text('not allowed')
            else:
                (output/'SETUP.txt').unlink();(output/'SETUP.txt').symlink_to(self.password)
            with self.assertRaises((ValueError,OSError)):host.verify(output,digest)

    def test_platform_and_public_profile_requirements_never_activate(self):
        output=self.base/'packet';digest=host.prepare(self.value,output)['manifest_sha256']
        with patch('pilot_host.platform.system',return_value='Linux'),patch('pilot_host.platform.machine',return_value='x86_64'):
            self.assertIn('current-primary-runtime-platform-incompatible',host.check(output,digest)['blockers'])
        profile=dict(rpc=dict(transport='https',url='https://rpc.example.org'),faucet=dict(transport='https',url='https://faucet.example.org'))
        self.assertTrue(host.external_profile(profile))
        for address in ('https://127.0.0.1:443','https://10.0.0.1:443','https://service.invalid'):
            self.assertFalse(host.external_profile({**profile,'rpc':dict(transport='https',url=address)}))
        plan=host.host_plan(self.value)
        self.assertEqual(len({h['failure_domain'] for h in plan['hosts']}),3)
        self.assertFalse(plan['consensus']['independent_validator_hosts'])

    def test_interrupted_packet_without_manifest_cannot_be_used_or_overwritten(self):
        import subprocess,sys
        from wallet_release import create
        valuefile=self.base/'plan.json';create(valuefile,encode(self.value));output=self.base/'partial'
        script='''import os,signal,sys
from pathlib import Path
from unittest.mock import patch
import pilot_host as h
from wallet_release import decode,read
original=h.create
def crash(path,raw):
    original(path,raw)
    if path.name=='host-plan.json':os.kill(os.getpid(),signal.SIGKILL)
with patch.object(h,'create',side_effect=crash):h.prepare(decode(read(Path(sys.argv[1]),32768)),Path(sys.argv[2]))
'''
        child=subprocess.run([sys.executable,'-B','-c',script,str(valuefile),str(output)],cwd=host.cohort.PROJECT/'tools',capture_output=True,timeout=15)
        self.assertEqual(child.returncode,-9);self.assertFalse((output/'MANIFEST.json').exists())
        original=read(output/'host-plan.json',16384)
        with self.assertRaises(OSError):host.check(output,'0'*64)
        with self.assertRaises(FileExistsError):host.prepare(self.value,output)
        self.assertEqual(original,read(output/'host-plan.json',16384))


if __name__=='__main__':unittest.main()
