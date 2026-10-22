"""Developer ID pipeline fixtures; no actual Developer ID/timestamp/Apple call."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from wallet_build_test import receipt as build_receipt
from wallet_release_test import payload
import wallet_release as release
import wallet_apple_release as apple

CERT='A'*40
TEAM='ZOLANATEST'
BUNDLE='dev.zolana.wallet'


class VerifiedFixture:
    files=None
    def __init__(self,root):self.trust={'fixture':True};self.closed=False
    def verify(self,archive,descriptor):
        return {'release':{'archive_sha256':'1'*64},'descriptor_sha256':'2'*64},copy.deepcopy(self.files),None,None
    def close(self):self.closed=True


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='apple081-unit-',dir='/private/tmp');cls.base=Path(cls.temp.name)
        c=cls.base/'fixture.c';c.write_text('int main(void) { return 0; }\n');binary=cls.base/'fixture-native'
        subprocess.run(['/usr/bin/clang','-O2','-g0','-Wl,-no_uuid',str(c),'-o',str(binary)],capture_output=True,check=True)
        files=payload();files['bin/native-wallet']=binary.read_bytes();files['BUILD.json']=release.encode(build_receipt(files['bin/native-wallet']))
        # Modern authenticated resources absent from the frozen037 allowlist.
        files['runtime/wallet_session.py']=b'# public session worker\n';files['assets/zolana-mark.svg']=b'<svg/>\n'
        m=release.decode(files['MANIFEST.json']);m['binary_kind']='path-remapped-development';m['files']={n:dict(size=len(v),sha256=release.sha(v)) for n,v in files.items() if n!='MANIFEST.json'};files['MANIFEST.json']=release.encode(m);VerifiedFixture.files=files
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def setUp(self):
        self.temp_case=tempfile.TemporaryDirectory(prefix='case-',dir=self.base);self.addCleanup(self.temp_case.cleanup);self.case=Path(self.temp_case.name);self.events=[]
        self.addCleanup(patch.stopall)
        patch.object(apple,'Installation',VerifiedFixture).start();patch.object(apple,'preflight_identity',return_value=None).start()
        patch.object(apple,'command',side_effect=self.command).start();patch.object(apple,'signature',side_effect=self.signature).start()
    def signature(self,path,identifier,team,runtime,certificate=None):
        return dict(identifier=identifier,team_identifier=team,certificate_sha1=certificate,signature='Developer ID Application',secure_timestamp=True,hardened_runtime=runtime,entitlements={} if runtime else None)
    def command(self,argv,timeout=180):
        self.events.append(argv)
        if argv[:2]==['/usr/bin/hdiutil','create']:Path(argv[-1]).write_bytes(b'unit-only synthetic DMG')
        return subprocess.CompletedProcess(argv,0,b'',b'')
    def prepare(self,root=None,resume=False,hook=None,**kwargs):
        return apple.prepare(self.case/'archive',self.case/'release',self.case/'trust',root or self.case/'stage',kwargs.get('certificate',CERT),kwargs.get('team',TEAM),kwargs.get('bundle',BUNDLE),resume,hook)
    def test_end_to_end_explicit_commands_inventory_provenance_and_idempotent_resume(self):
        image,r=self.prepare();self.assertTrue(image.exists());self.assertFalse(r['notarized']);self.assertFalse(r['release_ready']);self.assertFalse(r['python_runtime_bundled'])
        self.assertEqual(r['input_binding']['certificate_sha1'],CERT);self.assertEqual(r['team_identifier'],TEAM)
        signatures=[v for v in self.events if v[0]=='/usr/bin/codesign' and '--sign' in v]
        self.assertEqual(len(signatures),2);self.assertTrue(all('--timestamp' in v and CERT in v and '-' not in v for v in signatures));self.assertIn('--options',signatures[0]);self.assertNotIn('--deep',signatures[0])
        work=image.parent;files=apple.tree_files(work/'payload/native-wallet');self.assertIn('runtime/wallet_session.py',files);self.assertIn('assets/zolana-mark.svg',files)
        self.assertEqual(files['BUILD.json'],VerifiedFixture.files['BUILD.json']);self.assertEqual(release.decode(files['MANIFEST.json'])['binary_kind'],'apple-developer-id')
        self.events.clear();self.prepare(resume=True);self.assertFalse(any('--sign' in v or 'create' in v for v in self.events))
        apple.verify_prepared(self.case/'stage',release.sha((work/'SIGNED-PREPARATION.json').read_bytes()))
    def test_missing_identity_before_any_workspace_or_sign(self):
        with patch.object(apple,'preflight_identity',side_effect=ValueError('missing identity')),self.assertRaisesRegex(ValueError,'missing'):self.prepare()
        self.assertFalse((self.case/'stage').exists());self.assertEqual(self.events,[])
    def test_bad_identity_team_bundle_and_changed_resume_inputs_fail_closed(self):
        for kwargs in ({'certificate':'-'},{'team':'bad'},{'bundle':'--evil'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):self.prepare(**kwargs)
        self.prepare()
        with self.assertRaisesRegex(ValueError,'changed'):self.prepare(resume=True,team='OTHERTEAM1')
        self.assertTrue((self.case/'stage/state.json').exists())
    def test_signing_failure_and_interrupted_copy_retain_attempts_then_resume_same_binding(self):
        def failure(argv,timeout=180):
            if argv[0]=='/usr/bin/codesign' and '--sign' in argv:raise ValueError('fixture signing failure')
            return self.command(argv,timeout)
        with patch.object(apple,'command',side_effect=failure),self.assertRaisesRegex(ValueError,'signing failure'):self.prepare()
        root=self.case/'stage';old={p.name for p in (root/'attempts').iterdir()};self.assertEqual(len(old),1)
        with self.assertRaises(ValueError):apple.verify_prepared(root)
        self.prepare(resume=True);self.assertTrue(old<{p.name for p in (root/'attempts').iterdir()})
        def stop(phase):
            if phase=='payload_signed':raise RuntimeError('fixture process interruption')
        other=self.case/'other'
        with self.assertRaises(RuntimeError):self.prepare(other,hook=stop)
        self.prepare(other,resume=True)
    def test_signature_identity_mismatch_is_not_accepted(self):
        image,r=self.prepare()
        with patch.object(apple,'signature',return_value=dict(team_identifier='OTHERTEAM1')),self.assertRaises(ValueError):apple.verify_prepared(self.case/'stage')
    def test_receipt_image_resource_source_and_unknown_inventory_tamper_rejected(self):
        for n in ('image','resource','source','unknown','receipt'):
            root=self.case/n;image,r=self.prepare(root);work=image.parent
            if n=='image':image.write_bytes(b'changed')
            elif n=='resource':(work/'payload/native-wallet/assets/app.js').write_bytes(b'changed')
            elif n=='source':(work/'SOURCE-MANIFEST.json').write_bytes(b'{}')
            elif n=='unknown':(work/'payload/native-wallet/unknown.py').write_bytes(b'x')
            else:
                p=work/'SIGNED-PREPARATION.json';v=release.decode(p.read_bytes());v['notarized']=True;p.write_bytes(release.encode(v));s=release.decode((root/'state.json').read_bytes());s['receipt_sha256']=release.sha(p.read_bytes());release.atomic(root/'state.json',s)
            with self.subTest(n=n),self.assertRaises(ValueError):apple.verify_prepared(root)
    def test_explicit_receipt_digest_and_no_self_upgrade_or_notary_claim(self):
        image,r=self.prepare()
        with self.assertRaisesRegex(ValueError,'digest'):apple.verify_prepared(self.case/'stage','f'*64)
        self.assertFalse(r['notarized']);self.assertFalse(r['release_ready']);self.assertNotIn('submission_id',r)


class CommandGuardTests(unittest.TestCase):
    def test_unreviewed_commands_ad_hoc_no_timestamp_and_entitlements_are_denied(self):
        with patch.object(subprocess,'run') as run:
            for argv in ([],['/bin/sh','anything'],['/usr/bin/security','dump-keychain'],['/usr/bin/xcrun','notarytool'],['/usr/bin/codesign','--force','--sign','-','--timestamp=none','/tmp/native'],['/usr/bin/hdiutil','detach','/dev/disk2'],['/usr/bin/codesign','--verify','--strict','-R=always','/tmp/native'],['/usr/bin/codesign','--verify','--strict','-R='+apple.developer_id_requirement(BUNDLE,TEAM).replace('anchor apple generic','always'),'/tmp/native']):
                with self.subTest(argv=argv),self.assertRaises(ValueError):apple.command(argv)
            run.assert_not_called()
    def test_exact_factory_commands_are_allowed_without_executing_in_fixture(self):
        with tempfile.TemporaryDirectory(prefix='apple081-argv-',dir='/private/tmp') as tmp:
            root=Path(tmp);entitlements=root/'empty.plist';release.create(entitlements,b'<?xml version="1.0"?><plist version="1.0"><dict/></plist>')
            vectors=[['/usr/bin/codesign','--display','--extract-certificates',str(root/'cert'),str(root/'native')],['/usr/bin/security','find-identity','-v','-p','codesigning'],apple.sign_args(root/'native',CERT,BUNDLE,entitlements),apple.sign_args(root/'wallet.dmg',CERT,BUNDLE+'.image'),['/usr/bin/codesign','--verify','--strict',str(root/'native')],['/usr/bin/codesign','--verify','--strict','-R='+apple.developer_id_requirement(BUNDLE,TEAM),str(root/'native')],['/usr/bin/codesign','--display','--verbose=4',str(root/'native')],['/usr/bin/codesign','--display','--entitlements','-','--xml',str(root/'native')],['/usr/bin/hdiutil','create','-srcfolder',str(root/'payload'),'-volname','Zolana Wallet Pilot','-fs','HFS+','-format','UDZO','-nospotlight',str(root/'wallet.dmg')],['/usr/bin/hdiutil','verify',str(root/'wallet.dmg')]]
            with patch.object(subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as run:
                for vector in vectors:apple.command(vector)
                self.assertEqual(run.call_count,len(vectors))
            entitlements.write_bytes(b'<?xml version="1.0"?><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>')
            with patch.object(subprocess,'run') as run,self.assertRaises(ValueError):apple.command(apple.sign_args(root/'native',CERT,BUNDLE,entitlements))
            run.assert_not_called()
    def test_signature_checker_rejects_ad_hoc_wrong_team_identifier_missing_timestamp_and_runtime(self):
        good=b'Identifier=dev.zolana.wallet\nAuthority=Developer ID Application: Fixture\nAuthority=Developer ID Certification Authority\nTeamIdentifier=ZOLANATEST\nTimestamp=Oct 22 2026\nCodeDirectory v=20500 flags=0x10000(runtime)\n'
        for raw in (good.replace(b'ZOLANATEST',b'OTHERTEAM1'),good.replace(b'Timestamp=',b'NoTimestamp='),good.replace(b'0x10000',b'0x0'),good.replace(b'Identifier=dev.zolana.wallet',b'Identifier=other'),good+b'Signature=adhoc\n'):
            def cmd(argv,timeout=180):return subprocess.CompletedProcess(argv,0,b'<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict/></plist>',raw)
            with self.subTest(raw=raw),patch.object(apple,'command',side_effect=cmd),self.assertRaises(ValueError):apple.signature(Path('/tmp/native'),BUNDLE,TEAM,True,CERT)
    def test_custom_chain_named_developer_id_cannot_skip_apple_requirement(self):
        events=[]
        def command(argv,timeout=180):
            events.append(argv)
            if any(v.startswith('-R=') for v in argv):raise ValueError('fixture chain rejected by macOS')
            raise AssertionError('identity parsing must not run after chain rejection')
        with patch.object(apple,'command',side_effect=command),self.assertRaisesRegex(ValueError,'chain rejected'):
            apple.signature(Path('/tmp/native'),BUNDLE,TEAM,True,CERT)
        self.assertEqual(events,[['/usr/bin/codesign','--verify','--strict','-R='+apple.developer_id_requirement(BUNDLE,TEAM),'/tmp/native']])
        requirement=events[0][3]
        self.assertIn('anchor apple generic',requirement);self.assertIn('1.2.840.113635.100.6.2.6',requirement);self.assertIn('1.2.840.113635.100.6.1.13',requirement)
    def test_public_leaf_certificate_is_verified_not_only_same_team(self):
        info=b'Identifier=dev.zolana.wallet\nAuthority=Developer ID Application: Fixture\nTeamIdentifier=ZOLANATEST\nTimestamp=Oct 22 2026\nCodeDirectory v=20500 flags=0x10000(runtime)\n'
        der=b'unit public leaf DER fixture'
        fingerprint=hashlib.sha1(der).hexdigest().upper()
        def command(argv,timeout=180):
            if '--extract-certificates' in argv:release.create(Path(argv[3]+'0'),der)
            raw=b'<?xml version="1.0"?><plist version="1.0"><dict/></plist>'
            return subprocess.CompletedProcess(argv,0,raw,info)
        with patch.object(apple,'command',side_effect=command):
            self.assertEqual(apple.signature(Path('/tmp/native'),BUNDLE,TEAM,True,fingerprint)['certificate_sha1'],fingerprint)
            with self.assertRaisesRegex(ValueError,'leaf certificate differs'):apple.signature(Path('/tmp/native'),BUNDLE,TEAM,True,'F'*40)
            with self.assertRaisesRegex(ValueError,'fingerprint required'):apple.signature(Path('/tmp/native'),BUNDLE,TEAM,True)
    def test_preflight_selects_only_explicit_developer_id_fingerprint(self):
        output=f'  1) {CERT} "Developer ID Application: Unit Fixture ({TEAM})"\n  1 valid identities found\n'.encode()
        with patch.object(apple,'command',return_value=subprocess.CompletedProcess([],0,output,b'')):apple.preflight_identity(CERT)
        for raw in (output.replace(b'Developer ID Application:',b'Apple Development:'),output+output,output.replace(CERT.encode(),b'B'*40)):
            with patch.object(apple,'command',return_value=subprocess.CompletedProcess([],0,raw,b'')),self.assertRaises(ValueError):apple.preflight_identity(CERT)


if __name__=='__main__':unittest.main()
