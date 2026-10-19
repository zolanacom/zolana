import copy
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from apple_notary_handoff import Handoff
from package_wallet import archive
import wallet_apple as apple
from wallet_build_test import receipt
import wallet_release as release
from wallet_release_test import make_key,payload

ID='1f33be4d-a12e-49df-9712-082b36ab9394'
OTHER='2f33be4d-a12e-49df-9712-082b36ab9394'


class AppleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='native-apple-unit-',dir='/private/tmp');cls.root=Path(cls.temp.name)
        c=cls.root/'fixture.c';c.write_text('int main(void) { return 0; }\n');binary=cls.root/'native'
        subprocess.run(['/usr/bin/clang','-O2','-g0','-Wl,-no_uuid',str(c),'-o',str(binary)],check=True,capture_output=True)
        cls.original=binary.read_bytes();files=payload();files['bin/native-wallet']=cls.original;files['BUILD.json']=release.encode(receipt(cls.original))
        manifest=release.decode(files['MANIFEST.json']);manifest['binary_kind']='path-remapped-development';manifest['files']={n:{'size':len(raw),'sha256':release.sha(raw)} for n,raw in files.items() if n!='MANIFEST.json'};files['MANIFEST.json']=release.encode(manifest)
        cls.archive=cls.root/'wallet.tar.gz';release.create(cls.archive,archive(files,{k:0o755 for k in release.EXECUTABLES}));cls.key,cls.pub,cls.pin=make_key(cls.root)
        cls.signed=cls.root/'release.json';release.attest(cls.archive,cls.key,'apple-local-unit',1,cls.signed)
        cls.trust=cls.root/'trust';release.initialize(cls.trust,cls.pub,cls.pin,'apple-local-unit',release.sha(files['wallet-profile.json']),1)
        cls.prepared=cls.root/'prepared';cls.work,cls.receipt=apple.prepare(cls.archive,cls.signed,cls.trust,cls.prepared)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.local=tempfile.TemporaryDirectory(prefix='apple-case-',dir=self.root);self.addCleanup(self.local.cleanup);self.case=Path(self.local.name)
    def cloned(self):
        root=self.case/'prepared';shutil.copytree(self.prepared,root);state=json.loads((root/'state.json').read_text());work=root/'attempts'/state['attempt'];return root,work
    def handoff(self,root=None):
        value=Handoff(root or self.case/'handoff','a'*64);self.addCleanup(value.close);return value

    def test_actual_hardened_signature_keeps_code_and_has_no_entitlement_exceptions(self):
        apple.verify(self.prepared);binary=(self.work/'payload/native-wallet/bin/native-wallet').read_bytes()
        self.assertNotEqual(binary,self.original);self.assertEqual(apple.code_identity(binary),apple.code_identity(self.original))
        sig=apple.signature(self.work/'payload/native-wallet/bin/native-wallet',apple.IDENTIFIER,True)
        self.assertTrue(sig['hardened_runtime']);self.assertEqual(sig['entitlements'],{});self.assertFalse(sig['secure_timestamp']);self.assertIsNone(sig['team_identifier'])
        self.assertFalse(self.receipt['notarized']);self.assertFalse(self.receipt['release_ready'])

    def test_modified_code_and_resigned_modified_code_cannot_match_original_build(self):
        root,work=self.cloned();binary=work/'payload/native-wallet/bin/native-wallet';raw=bytearray(binary.read_bytes());raw[4096]^=1;binary.write_bytes(raw)
        with self.assertRaises(ValueError):apple.signature(binary,apple.IDENTIFIER,True)
        with self.assertRaises(ValueError):apple.verify(root)
        subprocess.run(['/usr/bin/codesign','--force','--sign','-','--options','runtime','--timestamp=none','--identifier',apple.IDENTIFIER,'--entitlements',str(work/'empty-entitlements.plist'),str(binary)],check=True,capture_output=True)
        apple.signature(binary,apple.IDENTIFIER,True)
        self.assertNotEqual(apple.code_identity(binary.read_bytes()),apple.code_identity(self.original))

    def test_wrong_identifier_missing_runtime_and_extra_entitlements_are_denied(self):
        _,work=self.cloned();binary=work/'payload/native-wallet/bin/native-wallet';empty=work/'empty-entitlements.plist'
        for identifier,runtime,entitlements in [('dev.nativepay.other',True,{}),(apple.IDENTIFIER,False,{}),(apple.IDENTIFIER,True,{'com.apple.security.get-task-allow':True})]:
            empty.write_bytes(plistlib.dumps(entitlements));argv=['/usr/bin/codesign','--force','--sign','-','--timestamp=none','--identifier',identifier,'--entitlements',str(empty)]
            if runtime:argv+=['--options','runtime']
            subprocess.run([*argv,str(binary)],check=True,capture_output=True)
            with self.subTest(identifier=identifier,runtime=runtime,entitlements=entitlements),self.assertRaises(ValueError):apple.signature(binary,apple.IDENTIFIER,True)

    def test_macho_malformed_bounds_and_signature_relocation_are_denied(self):
        for offset,value in [(0,0),(4,0),(16,5000),(20,2**31)]:
            raw=bytearray(self.original);struct.pack_into('<I',raw,offset,value)
            with self.assertRaises(ValueError):apple.code_identity(raw)
        with self.assertRaises(ValueError):apple.code_identity(self.original[:-1])

    def test_image_and_payload_tampering_are_rejected(self):
        root,work=self.cloned();image=work/'wallet-rehearsal.dmg';raw=bytearray(image.read_bytes());raw[512]^=1;image.write_bytes(raw)
        with self.assertRaisesRegex(ValueError,'image changed'):apple.verify(root)
        root2=self.case/'prepared2';shutil.copytree(self.prepared,root2);state=json.loads((root2/'state.json').read_text());work2=root2/'attempts'/state['attempt']
        (work2/'payload/native-wallet/assets/app.js').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'payload changed'):apple.verify(root2)

    def test_readonly_mount_matches_payload_and_is_detached_without_changing_image(self):
        root,work=self.cloned();image=work/'wallet-rehearsal.dmg';original=image.read_bytes()
        with apple.mounted_payload(root) as bundle:
            self.assertEqual((bundle/'bin/native-wallet').read_bytes(),(work/'payload/native-wallet/bin/native-wallet').read_bytes())
            with self.assertRaises(OSError):(bundle/'LICENSE').write_bytes(b'cannot change readonly image')
        self.assertEqual(image.read_bytes(),original);self.assertEqual(apple.image_mounts(image),[])
        self.assertEqual(json.loads((root/'mount-state.json').read_text())['phase'],'detached')

    def test_interrupted_preparation_rebuilds_only_derived_attempt_and_resume_is_idempotent(self):
        root=self.case/'interrupted'
        def stop(point):
            if point=='payload_signed':raise RuntimeError('local interruption')
        with self.assertRaises(RuntimeError):apple.prepare(self.archive,self.signed,self.trust,root,hook=stop)
        original_attempts=set(p.name for p in (root/'attempts').iterdir());self.assertEqual(len(original_attempts),1)
        apple.prepare(self.archive,self.signed,self.trust,root,True)
        self.assertTrue(original_attempts<set(p.name for p in (root/'attempts').iterdir()))
        with patch('wallet_apple.command',wraps=apple.command) as commands:apple.prepare(self.archive,self.signed,self.trust,root,True)
        self.assertFalse(any('--sign' in c.args[0] or 'create' in c.args[0] for c in commands.call_args_list))

    def test_initialized_corruption_route_changes_symlinks_and_concurrent_access_fail_closed(self):
        root,_=self.cloned()
        with apple.workspace(root),self.assertRaises(BlockingIOError):apple.verify(root)
        state=json.loads((root/'state.json').read_text());state['binding']['archive_sha256']='f'*64;(root/'state.json').write_bytes(release.encode(state))
        with self.assertRaisesRegex(ValueError,'route changed'):apple.prepare(self.archive,self.signed,self.trust,root,True)
        (root/'state.json').unlink()
        with self.assertRaises(OSError):apple.verify(root)
        with self.assertRaisesRegex(ValueError,'new Apple'):apple.prepare(self.archive,self.signed,self.trust,root)

    def test_notary_private_identity_timestamp_and_upload_commands_never_execute(self):
        with patch('subprocess.run') as run:
            for argv in ([],['/usr/bin/codesign','--sign'],['/usr/bin/xcrun','notarytool','submit','image'],['/usr/bin/codesign','--sign','Developer ID Application: Test','binary'],['/usr/bin/codesign','--sign','-','--timestamp','binary']):
                with self.assertRaises(ValueError):apple.command(argv)
            run.assert_not_called()
        plan=apple.notary_plan('a'*64);self.assertFalse(plan['release_ready']);self.assertFalse(plan['network_commands_executed']);self.assertTrue(all(s['execution_enabled'] is False for s in plan['steps']))
        submit=next(s for s in plan['steps'] if s['name']=='submit');self.assertNotIn('--wait',submit['argv']);self.assertIn('--keychain-profile',submit['argv']);self.assertTrue(plan['rebuild_publisher_signature_after_stapling'])

    def test_rehearsal_claims_cannot_be_upgraded_by_rehashing_local_receipt(self):
        root,work=self.cloned();receipt=json.loads((work/'REHEARSAL.json').read_text());receipt['notarized']=True
        (work/'REHEARSAL.json').write_bytes(release.encode(receipt));state=json.loads((root/'state.json').read_text());state['receipt_sha256']=release.sha(release.encode(receipt));(root/'state.json').write_bytes(release.encode(state))
        with self.assertRaisesRegex(ValueError,'evidence changed'):apple.verify(root)

    def test_mount_reconciliation_never_detaches_an_unexpected_attachment(self):
        root,work=self.cloned()
        with patch('wallet_apple.image_mounts',return_value=[('/dev/disk999s1','/unexpected')]),patch('wallet_apple.command') as command:
            with self.assertRaisesRegex(ValueError,'unexpected attachment'):apple._recover_mount(root,work)
            command.assert_not_called()

    def test_unknown_submission_survives_restart_and_never_silently_resubmits(self):
        h=self.handoff();self.assertFalse(h.begin_submission()['execution_enabled']);h.close();h=self.handoff()
        with self.assertRaisesRegex(ValueError,'reconcile'):h.begin_submission()
        with self.assertRaises(ValueError):h.attach_submission(ID,'b'*64)
        h.attach_submission(ID,'a'*64);h.close();h=self.handoff();self.assertEqual(h.state['submission_id'],ID)
        with self.assertRaises(ValueError):h.attach_submission(OTHER,'a'*64)

    def test_notary_rejection_and_wrong_result_identity_remain_blocked_after_restart(self):
        h=self.handoff();h.begin_submission();h.attach_submission(ID,'a'*64)
        for identifier,digest,status in [(OTHER,'a'*64,'Accepted'),(ID,'b'*64,'Accepted'),(ID,'a'*64,'unknown')]:
            with self.assertRaises(ValueError):h.result(identifier,digest,status)
        h.result(ID,'a'*64,'Invalid');h.close();h=self.handoff()
        with self.assertRaises(ValueError):h.result(ID,'a'*64,'Accepted')
        with self.assertRaises(ValueError):h.begin_submission()
        self.assertEqual(h.state['phase'],'rejected')

    def test_staple_and_assessment_failure_recovery_are_never_claimed_as_notarization(self):
        h=self.handoff();h.begin_submission();h.attach_submission(ID,'a'*64);h.result(ID,'a'*64,'Accepted');h.staple(ID,'a'*64,False);h.close();h=self.handoff()
        self.assertEqual(h.state['phase'],'staple_failed')
        h.staple(ID,'a'*64,True,'c'*64);h.assess('c'*64,False);h.close();h=self.handoff();self.assertEqual(h.state['phase'],'assessment_failed')
        with self.assertRaises(ValueError):h.assess('d'*64,True)
        h.assess('c'*64,True);self.assertEqual(h.state['phase'],'assessed');self.assertFalse(h.state['notarized']);self.assertFalse(h.state['release_ready']);self.assertFalse(h.state['network_commands_executed'])

    def test_notary_corrupt_state_changed_artifact_and_uncertain_write_require_original_restart(self):
        h=self.handoff();root=h.root;real=release.atomic
        def uncertain(path,value):real(path,value);raise OSError('uncertain fsync')
        with patch('apple_notary_handoff.atomic',side_effect=uncertain),self.assertRaises(OSError):h.begin_submission()
        with self.assertRaisesRegex(ValueError,'reopen'):h.begin_submission()
        h.close();h=self.handoff(root);self.assertEqual(h.state['phase'],'submission_unknown');h.close()
        with self.assertRaises(ValueError):Handoff(root,'f'*64)
        (root/'state.json').write_bytes(b'corrupt')
        with self.assertRaises(ValueError):Handoff(root,'a'*64)
