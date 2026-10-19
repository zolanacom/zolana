import copy
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import sys
import time
import unittest
from unittest.mock import patch

import wallet_build as build
import wallet_release as release
from package_wallet import archive
from wallet_release_test import make_key,payload


def receipt(binary):
    return dict(format='native-wallet-build-v1',recipe=build.RECIPE,binary_sha256=release.sha(binary),binary_size=len(binary),source_sha256='a'*64,
        cargo_lock_sha256='b'*64,source_commit='c'*40,source_dirty=True,rustc_release='1.92.0',rustc_commit='d'*40,target='aarch64-apple-darwin',
        profile='wallet-release',jobs=1,offline=True,path_audit=build.path_audit(binary,{}),
        linkage=dict(system_only=True,libraries=['/usr/lib/libSystem.B.dylib'],rpaths=0,debug_segments=0,uuid_commands=0,native_signature='toolchain-ad-hoc'),
        probes=dict(rust_file_macro=True,rust_panic_location=True,native_file_macro=True,probe_binary_paths_clean=True),canonical_prefixes=build.CANONICAL)


class WalletBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name).resolve()

    def test_environment_uses_encoded_remaps_spaces_and_bounded_isolated_settings(self):
        with patch.dict(os.environ,{'RUSTFLAGS':'unreviewed','RUSTC_WRAPPER':'unreviewed','CFLAGS':'unreviewed','CARGO_PROFILE_WALLET_RELEASE_DEBUG':'2'}):
            env,roots,rust,native=build.environment(self.root/'build space',self.root/'build space/source',self.root/'cargo cache',self.root/'compiler')
        self.assertEqual(env['CARGO_ENCODED_RUSTFLAGS'].split('\x1f'),rust)
        self.assertEqual(shlex.split(env['CFLAGS']),native);self.assertEqual(env['CFLAGS'],env['CXXFLAGS'])
        self.assertEqual(env['CARGO_BUILD_JOBS'],'1');self.assertEqual(env['NUM_JOBS'],'1');self.assertEqual(env['CMAKE_BUILD_PARALLEL_LEVEL'],'1')
        self.assertEqual(env['CARGO_NET_OFFLINE'],'true');self.assertNotIn('RUSTC_WRAPPER',env);self.assertNotIn('RUSTFLAGS',env);self.assertNotIn('CARGO_PROFILE_WALLET_RELEASE_DEBUG',env)
        mappings=[f for f in rust if f.startswith('--remap-path-prefix=')]
        self.assertEqual([len(f.split('=',2)[1]) for f in mappings],sorted(len(f.split('=',2)[1]) for f in mappings))
        self.assertTrue(any('cargo cache=/native/cargo' in f for f in mappings))

    def fixture_sources(self):
        names=['Cargo.toml','Cargo.lock','rust-toolchain.toml','clients/wallet/src/main.rs']
        for name in names:
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('test source '+name)
        return names

    def test_source_snapshot_is_content_bound_and_excludes_ignored_private_state(self):
        names=self.fixture_sources();secret=self.root/'.data';secret.mkdir();(secret/'secret').write_text('never copy')
        dangling=self.root/'clients/upstream-doc.md';dangling.symlink_to('missing-upstream-doc.md');names.append('clients/upstream-doc.md')
        with patch('wallet_build.PROJECT',self.root),patch('wallet_build.git',return_value=('\0'.join(names)+'\0').encode()):
            records,digest=build.sources();build.snapshot(self.root/'snapshot',records)
            self.assertFalse((self.root/'snapshot/.data').exists());self.assertEqual(build.sha(build.encode(records)),digest)
            self.assertTrue((self.root/'snapshot/clients/upstream-doc.md').is_symlink())
            (self.root/'Cargo.lock').write_text('changed')
            with self.assertRaisesRegex(ValueError,'changed'):build.snapshot(self.root/'changed-snapshot',records)

    def test_source_symlink_cannot_import_untracked_private_or_external_files(self):
        names=self.fixture_sources();private=self.root/'.data';private.mkdir();(private/'secret').write_text('never copy')
        link=self.root/'clients/private';link.symlink_to('../.data/secret')
        with patch('wallet_build.PROJECT',self.root),patch('wallet_build.git',return_value=('\0'.join([*names,'clients/private'])+'\0').encode()):
            with self.assertRaisesRegex(ValueError,'source inventory'):build.sources()
            link.unlink();link.symlink_to('/etc/passwd')
            with self.assertRaisesRegex(ValueError,'absolute'):build.sources()

    def test_ascii_utf16_known_and_generic_paths_fail_without_printing_the_path(self):
        for codec in ('utf-8','utf-16-le','utf-16-be'):
            for text in ('/'+'Users'+'/private-owner/source.rs','/private/tmp/private-build/file.c','/'+'home'+'/build-owner/file.rs'):
                with self.subTest(codec=codec,text=text),self.assertRaises(ValueError) as failed:build.path_audit(text.encode(codec),{})
                self.assertNotIn(text,str(failed.exception))
        with self.assertRaisesRegex(ValueError,'checkout'):build.path_audit(b'prefix /custom/workspace/file.rs',{'checkout':Path('/custom/workspace')})
        self.assertTrue(build.path_audit(b'/native/cargo/src/example.rs /native/src/main.rs',{})['known_roots_absent'])

    def test_real_rust_panic_and_native_file_macros_are_remapped_including_spaces(self):
        compiler,_=build.toolchain();output=self.root/'build with spaces';output.mkdir(mode=0o700);source=output/'source';source.mkdir()
        env,roots,rust,native=build.environment(output,source,self.root/'cargo cache',compiler)
        result=build.probes(output,env,roots,rust,native,compiler)
        self.assertTrue(all(result.values()))

    def test_receipt_binds_binary_recipe_bounds_and_literal_boolean_claims(self):
        binary=b'clean development binary';value=receipt(binary);release.build_metadata(value,binary)
        for field,new in [('binary_sha256','f'*64),('binary_size',1),('jobs',2),('offline',1),('target','different'),('profile','dev')]:
            altered={**value,field:new}
            with self.subTest(field=field),self.assertRaises(ValueError):release.build_metadata(altered,binary)
        for field in ('path_audit','probes'):
            altered=copy.deepcopy(value);key=next(k for k,v in altered[field].items() if v is True);altered[field][key]=1
            with self.assertRaises(ValueError):release.build_metadata(altered,binary)
        altered=copy.deepcopy(value);altered['linkage']['libraries']=['@rpath/untrusted.dylib']
        with self.assertRaises(ValueError):release.build_metadata(altered,binary)

    def test_signed_remapped_package_requires_valid_matching_receipt(self):
        files=payload();binary=files['bin/native-wallet'];files['BUILD.json']=release.encode(receipt(binary))
        manifest=release.decode(files['MANIFEST.json']);manifest['binary_kind']='path-remapped-development';manifest['files']['BUILD.json']={'size':len(files['BUILD.json']),'sha256':release.sha(files['BUILD.json'])};files['MANIFEST.json']=release.encode(manifest)
        release.inventory(files);path=self.root/'wallet.tar.gz';release.create(path,archive(files,{k:0o755 for k in release.EXECUTABLES}))
        key,pub,pin=make_key(self.root);signed=self.root/'release.json';release.attest(path,key,'local-remapped',1,signed)
        release.initialize(self.root/'install',pub,pin,'local-remapped',release.sha(files['wallet-profile.json']),1)
        obj=release.Installation(self.root/'install');self.addCleanup(obj.close);self.assertTrue((obj.install(path,signed)/'BUILD.json').exists())
        missing=dict(files);del missing['BUILD.json'];del manifest['files']['BUILD.json'];missing['MANIFEST.json']=release.encode(manifest)
        with self.assertRaisesRegex(ValueError,'missing'):release.inventory(missing)
        manifest['binary_kind']='local-development';files['MANIFEST.json']=release.encode({**manifest,'files':{**manifest['files'],'BUILD.json':{'size':len(files['BUILD.json']),'sha256':release.sha(files['BUILD.json'])}}})
        with self.assertRaisesRegex(ValueError,'cannot claim'):release.inventory(files)

    def test_stale_source_receipt_is_rejected_before_running_any_native_binary(self):
        from package_wallet import main
        binary=self.root/'not-executable';release.create(binary,b'clean binary');metadata=self.root/'BUILD.json';release.create(metadata,release.encode(receipt(binary.read_bytes())))
        args=['package','--network',str(self.root/'unused-profile'),'--label','test','--rpc','http://127.0.0.1:12345','--transport','loopback-http','--output',str(self.root/'unused.tar.gz'),'--binary',str(binary),'--build-receipt',str(metadata)]
        with patch('sys.argv',args),patch('wallet_build.sources',return_value=({'Cargo.lock':{'sha256':'b'*64}},'f'*64)),patch('subprocess.run') as run:
            with self.assertRaisesRegex(ValueError,'native source inputs'):main()
            run.assert_not_called()

    def test_interrupted_compiler_group_is_stopped_and_private_log_is_retained(self):
        script=self.root/'supervisor.py';marker=self.root/'child.pid'
        child='import os,time; from pathlib import Path; Path('+repr(str(marker))+').write_text(str(os.getpid())); time.sleep(30)'
        script.write_text('import signal,sys\nfrom pathlib import Path\nsys.path.insert(0,'+repr(str(Path(build.__file__).parent))+')\nfrom wallet_build import run_compiler\n'
            'def stop(*_): raise InterruptedError()\nsignal.signal(signal.SIGTERM,stop)\ntry:\n run_compiler([sys.executable,"-c",'+repr(child)+'],Path('+repr(str(self.root))+'),None,Path('+repr(str(self.root/'interrupted.log'))+'),60)\n'
            'except InterruptedError: pass\n')
        supervisor=subprocess.Popen([sys.executable,'-B',str(script)])
        try:
            deadline=time.monotonic()+5
            while not marker.exists() and time.monotonic()<deadline:time.sleep(.02)
            self.assertTrue(marker.exists());pid=int(marker.read_text());supervisor.terminate();supervisor.wait(timeout=5)
            self.assertEqual(supervisor.returncode,0)
            with self.assertRaises(ProcessLookupError):os.kill(pid,0)
            self.assertTrue((self.root/'interrupted.log').exists())
        finally:
            if supervisor.poll() is None:
                supervisor.kill();supervisor.wait(timeout=5)
                if marker.exists():
                    try:os.killpg(int(marker.read_text()),9)
                    except ProcessLookupError:pass


if __name__=='__main__':unittest.main()
