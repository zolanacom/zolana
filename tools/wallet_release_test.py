import base64
import copy
import io
import contextlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from package_wallet import archive
import wallet_release as release


def make_key(root,name='publisher'):
    private=root/(name+'.pem');public=root/(name+'.pub')
    raw=release.crypto(['genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:P-256','-pkeyopt','ec_param_enc:named_curve'],b'')
    release.create(private,raw)
    der=release.crypto(['pkey','-pubout','-outform','DER'],raw)
    release.create(public,release.public_pem(der))
    return private,public,release.sha(der)


def payload():
    profile=dict(format='native-wallet-profile-v1',label='Offline release test',network=[7]*32,genesis_hash='1'*32)
    files={name:b'not executed\n' for name in release.REQUIRED}
    files['notices/test-dependency-1.0/LICENSE']=b'Preserved notice\n'
    files['notices/test-dependency-1.0/NOTICE']=b''
    files['wallet-profile.json']=release.encode(profile)
    files['MANIFEST.json']=release.encode(dict(format='native-wallet-bundle-v1',platform=release.host(),source_commit='c'*40,source_dirty=True,binary_kind='local-development',
        files={name:dict(size=len(raw),sha256=release.sha(raw)) for name,raw in files.items()}))
    return files


class ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys=tempfile.TemporaryDirectory();cls.private,cls.public,cls.pin=make_key(Path(cls.keys.name))
    @classmethod
    def tearDownClass(cls):cls.keys.cleanup()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.files=payload();self.profile=release.sha(self.files['wallet-profile.json']);self.install_root=self.root/'install'
        release.initialize(self.install_root,self.public,self.pin,'invited-rehearsal',self.profile,1)
    def sign(self,number=1,files=None,name=None):
        name=name or 'release-'+str(number);path=self.root/(name+'.tar.gz');descriptor=self.root/(name+'.json')
        release.create(path,archive(files or self.files,{k:0o755 for k in release.EXECUTABLES}))
        release.attest(path,self.private,'invited-rehearsal',number,descriptor)
        return path,descriptor
    def opened(self,hook=None):
        obj=release.Installation(self.install_root,hook);self.addCleanup(obj.close);return obj
    def mutate(self,files,name,raw):
        files=copy.deepcopy(files);files[name]=raw
        manifest=release.decode(files['MANIFEST.json']);manifest['files'][name]={'size':len(raw),'sha256':release.sha(raw)};files['MANIFEST.json']=release.encode(manifest)
        return files
    def resign_raw(self,path,value,number=None):
        raw=release.encode(value)
        with tempfile.TemporaryDirectory() as temp:
            key=Path(temp)/'key';release.create(key,release.read(self.private,16384,True))
            sig=release.crypto(['dgst','-sha256','-sign',str(key)],release.DOMAIN+raw)
        path.write_bytes(raw);Path(str(path)+'.sig').write_bytes(sig)

    def test_signature_verification_and_install_never_execute_downloaded_code(self):
        paths=self.sign();obj=self.opened()
        with patch('subprocess.run',wraps=subprocess.run) as calls:
            self.assertEqual(obj.verify(*paths)[0]['release']['sequence'],1);bundle=obj.install(*paths)
            self.assertTrue(all(call.args[0][0]=='/usr/bin/openssl' for call in calls.call_args_list))
        self.assertEqual(bundle,obj.current());self.assertEqual(obj.state['sequence'],1)
        self.assertEqual((bundle/'bin/native-wallet').stat().st_mode&0o777,0o500)

    def test_brand_assets_are_optional_for_old_releases_and_authenticated_for_new_ones(self):
        release.inventory(self.files)
        files=self.mutate(self.files,'assets/zolana-mark.svg',b'<svg xmlns="http://www.w3.org/2000/svg"/>')
        files=self.mutate(files,'assets/favicon.svg',b'<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>')
        paths=self.sign(files=files);obj=self.opened();bundle=obj.install(*paths)
        self.assertEqual((bundle/'assets/zolana-mark.svg').read_bytes(),files['assets/zolana-mark.svg'])
        files['assets/favicon.svg']+=b'changed'
        with self.assertRaisesRegex(ValueError,'digest mismatch'):release.inventory(files)

    def test_changed_archive_or_descriptor_or_signature_or_wrong_key_is_denied(self):
        archive_path,descriptor=self.sign();obj=self.opened();original=archive_path.read_bytes()
        archive_path.write_bytes(original+b'changed')
        with self.assertRaisesRegex(ValueError,'download differs'):obj.verify(archive_path,descriptor)
        archive_path.write_bytes(original);raw=descriptor.read_bytes();value=release.decode(raw);value['sequence']=2;descriptor.write_bytes(release.encode(value))
        with self.assertRaisesRegex(ValueError,'cryptographic'):obj.verify(archive_path,descriptor)
        descriptor.write_bytes(raw);sig=Path(str(descriptor)+'.sig');original=sig.read_bytes();sig.write_bytes(bytes([original[0]^1])+original[1:])
        with self.assertRaises(ValueError):obj.verify(archive_path,descriptor)
        sig.write_bytes(original);other,_,_=make_key(self.root,'other');sig.write_bytes(release.crypto(['dgst','-sha256','-sign',str(other)],release.DOMAIN+raw))
        with self.assertRaisesRegex(ValueError,'cryptographic'):obj.verify(archive_path,descriptor)
        self.assertIsNone(obj.state['pending'])

    def test_publisher_pin_is_external_and_init_never_overwrites_existing_state(self):
        with self.assertRaisesRegex(ValueError,'independent pin'):release.initialize(self.root/'wrong',self.public,'f'*64,'invited-rehearsal',self.profile,1)
        with self.assertRaisesRegex(ValueError,'new directory'):release.initialize(self.install_root,self.public,self.pin,'invited-rehearsal',self.profile,1)
        with self.assertRaises(ValueError):release.public_der(release.read(self.private,16384,True))

    def test_exact_profile_platform_channel_and_initial_minimum_are_pinned(self):
        paths=self.sign();obj=self.opened();original=release.decode(paths[1].read_bytes())
        for field,new in [('profile_sha256','e'*64),('platform','linux-x86_64' if release.host()!='linux-x86_64' else 'darwin-arm64'),('channel','other')]:
            value={**original,field:new};self.resign_raw(paths[1],value)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'pinned policy'):obj.verify(*paths)
        self.resign_raw(paths[1],original);obj.close()
        fresh=self.root/'minimum';release.initialize(fresh,self.public,self.pin,'invited-rehearsal',self.profile,2)
        obj=release.Installation(fresh);self.addCleanup(obj.close)
        with self.assertRaisesRegex(ValueError,'pinned policy'):obj.verify(*paths)

    def test_rollback_and_same_sequence_equivocation_survive_restart(self):
        old=self.sign(1);new=self.sign(2);obj=self.opened();obj.install(*new);obj.close();obj=self.opened()
        with self.assertRaisesRegex(ValueError,'rollback'):obj.install(*old)
        obj.close();obj=self.opened()
        changed=self.sign(2,self.mutate(self.files,'README.txt',b'other'),'equivocation')
        with self.assertRaisesRegex(ValueError,'equivocation'):obj.install(*changed)
        obj.close();obj=self.opened()
        self.assertEqual(obj.install(*new),obj.current())

    def test_interrupted_stages_recover_only_original_release_without_wallet_access(self):
        first=self.sign(1);second=self.sign(2,self.mutate(self.files,'README.txt',b'Updated approved wallet README'));third=self.sign(3)
        wallet=self.root/'wallet-state';wallet.mkdir(mode=0o700);secret=wallet/'wallet.json.pending.json';secret.write_bytes(b'preserved-unknown-payment')
        obj=self.opened();obj.install(*first);original=obj.state['active'];obj.close()
        for point in ('planned','extracting','published'):
            def stop(stage):
                if stage==point:raise RuntimeError('interruption')
            obj=self.opened(stop)
            with self.assertRaises(RuntimeError):obj.install(*second)
            self.assertEqual(obj.state['active'],original);obj.close();obj=self.opened()
            with self.assertRaisesRegex(ValueError,'interrupted release'):obj.install(*third)
            self.assertEqual(obj.state['pending']['release']['sequence'],2);obj.close()
        obj=self.opened();obj.install(*second);self.assertEqual(obj.state['sequence'],2);self.assertIsNone(obj.state['pending'])
        self.assertEqual((obj.current()/'README.txt').read_bytes(),b'Updated approved wallet README')
        self.assertEqual(secret.read_bytes(),b'preserved-unknown-payment')

    def test_activation_uncertainty_leaves_recoverable_old_or_new_commit(self):
        first=self.sign(1);second=self.sign(2);obj=self.opened();obj.install(*first);obj.close();real=release.atomic
        for after in (False,True):
            obj=self.opened()
            def uncertain(path,value):
                if value.get('sequence')==2:
                    if after:real(path,value)
                    raise OSError('simulated uncertain fsync')
                return real(path,value)
            with patch('wallet_release.atomic',side_effect=uncertain),self.assertRaises(OSError):obj.install(*second)
            with self.assertRaisesRegex(ValueError,'must reopen'):obj.current()
            obj.close();obj=self.opened();self.assertIn(obj.state['sequence'],(1,2));obj.install(*second);self.assertEqual(obj.state['sequence'],2);obj.close()
            if not after:
                # Independent intact installation exercises the other commit outcome.
                self.install_root=self.root/'second-install';release.initialize(self.install_root,self.public,self.pin,'invited-rehearsal',self.profile,1)
                obj=self.opened();obj.install(*first);obj.close()

    def test_initialized_state_deletion_corruption_and_trust_edits_fail_closed(self):
        for name in ('state.json','initialized','trust.json'):
            path=self.install_root/name;original=path.read_bytes();path.unlink()
            with self.subTest(name=name),self.assertRaises((ValueError,OSError)):self.opened()
            release.create(path,b'broken')
            with self.assertRaises(ValueError):self.opened()
            path.write_bytes(original)
        path=self.install_root/'trust.json';value=release.decode(path.read_bytes());value['minimum_sequence']=2;path.write_bytes(release.encode(value))
        with self.assertRaisesRegex(ValueError,'policy changed'):self.opened()

    def test_unsafe_files_symlinks_and_concurrent_installers_are_rejected(self):
        obj=self.opened()
        with self.assertRaises(BlockingIOError):release.Installation(self.install_root)
        obj.close();path=self.install_root/'state.json';path.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'unsafe'):self.opened()
        path.chmod(0o600);raw=path.read_bytes();path.unlink();external=self.root/'external';release.create(external,raw);path.symlink_to(external)
        with self.assertRaises(OSError):self.opened()

    def test_installed_tampering_and_changed_profile_are_denied_before_launch(self):
        obj=self.opened();bundle=obj.install(*self.sign());path=bundle/'assets/app.js';path.chmod(0o600);path.write_bytes(b'changed');path.chmod(0o400)
        with self.assertRaisesRegex(ValueError,'digest mismatch'):obj.current()
        path.chmod(0o600);path.write_bytes(self.files['assets/app.js'])
        with self.assertRaisesRegex(ValueError,'unsafe installed'):obj.current()

    def test_unknown_members_links_traversal_duplicates_and_file_directory_conflicts_are_denied(self):
        valid=archive(self.files,{k:0o755 for k in release.EXECUTABLES});release.unpack(valid)
        for name,kind in [('native-wallet/../../escape',tarfile.REGTYPE),('/absolute',tarfile.REGTYPE),('native-wallet/link',tarfile.SYMTYPE),('native-wallet/link',tarfile.LNKTYPE),('native-wallet/fifo',tarfile.FIFOTYPE),('native-wallet/LICENSE',tarfile.REGTYPE),('native-wallet/assets',tarfile.REGTYPE)]:
            result=io.BytesIO()
            with tarfile.open(fileobj=result,mode='w:gz') as out:
                with tarfile.open(fileobj=io.BytesIO(valid),mode='r:gz') as src:
                    for member in src:out.addfile(member,src.extractfile(member))
                item=tarfile.TarInfo(name);item.type=kind;item.mode=0o644;item.size=0
                if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):item.linkname='../../external'
                out.addfile(item,io.BytesIO())
            with self.subTest(name=name,kind=kind),self.assertRaises(ValueError):release.unpack(result.getvalue())

    def test_bounded_inputs_duplicate_json_and_unallowlisted_content_are_denied(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):release.decode(b'{"format":1,"format":2}')
        with self.assertRaises(ValueError):release.decode(b'{"n":NaN}')
        extra=self.mutate(self.files,'secret.json',b'never export')
        with self.assertRaisesRegex(ValueError,'allowlist'):release.unpack(archive(extra,{k:0o755 for k in release.EXECUTABLES}))
        with patch('wallet_release.CONTENT_LIMIT',1),self.assertRaises(ValueError):release.unpack(archive(self.files,{k:0o755 for k in release.EXECUTABLES}))

    def test_run_holds_lock_uses_isolated_python_and_refuses_nested_wallet_data(self):
        obj=self.opened();obj.install(*self.sign());obj.close()
        with patch('sys.argv',['release','run','--root',str(self.install_root),'--','--data-dir',str(self.install_root/'state')]),self.assertRaisesRegex(ValueError,'separate'):release.main()
        real=subprocess.run
        def run(command,*args,**kwargs):
            if command[0]==release.OPENSSL:return real(command,*args,**kwargs)
            self.assertEqual(command[1:3],['-I','-B'])
            self.assertEqual(len(kwargs['pass_fds']),1)
            with self.assertRaises(BlockingIOError):release.Installation(self.install_root)
            return subprocess.CompletedProcess(command,0)
        with patch('sys.argv',['release','run','--root',str(self.install_root),'--','--verify']),patch('subprocess.run',side_effect=run):release.main()

    def test_encrypted_signer_key_and_wrong_password_do_not_expose_secret(self):
        password=self.root/'password';release.create(password,b'local-signer-test-password\n')
        encrypted=release.crypto(['pkey','-aes-256-cbc','-passout','file:'+str(password)],release.read(self.private,16384,True))
        key=self.root/'encrypted.pem';release.create(key,encrypted)
        paths=self.sign();out=self.root/'encrypted-release.json'
        release.attest(paths[0],key,'invited-rehearsal',2,out,password)
        obj=self.opened();self.assertEqual(obj.verify(paths[0],out)[0]['release']['sequence'],2)
        self.assertNotIn(b'local-signer-test-password',out.read_bytes())
        password.write_bytes(b'wrong-password\n')
        with self.assertRaisesRegex(ValueError,'cryptographic'):release.attest(paths[0],key,'invited-rehearsal',3,self.root/'rejected.json',password)
        self.assertFalse((self.root/'rejected.json').exists())

    def test_unsafe_parent_and_extra_installed_directories_are_rejected(self):
        shared=self.root/'shared';shared.mkdir(mode=0o777);shared.chmod(0o777)
        with self.assertRaisesRegex(ValueError,'parent'):release.initialize(shared/'installation',self.public,self.pin,'invited-rehearsal',self.profile,1)
        obj=self.opened();bundle=obj.install(*self.sign());(bundle/'extra').mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError,'directory inventory'):obj.current()

    def test_default_data_directory_overlap_and_abbreviated_override_are_refused(self):
        # The initial policy must also hold when --data-dir is omitted.
        data_base=self.root/('Library/Application Support' if release.platform.system()=='Darwin' else '.local/share')/'Zolana Test Wallet'/('1'*32)
        data_base.mkdir(mode=0o700,parents=True)
        self.install_root=data_base/'installation';release.initialize(self.install_root,self.public,self.pin,'invited-rehearsal',self.profile,1)
        obj=self.opened();obj.install(*self.sign());obj.close()
        with patch('pathlib.Path.home',return_value=self.root),patch('sys.argv',['release','run','--root',str(self.install_root),'--','--verify']),self.assertRaisesRegex(ValueError,'separate'):release.main()
        from wallet_launch import main
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as failed:main(['--data-d',str(self.install_root/'state')])
        self.assertEqual(failed.exception.code,2)


if __name__=='__main__':unittest.main()
