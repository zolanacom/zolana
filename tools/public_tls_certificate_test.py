"""Focused TLS byte verification and isolated atomic-publisher fixtures; no host use."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import public_tls_certificate as public
from local_test_tls import create

OPENSSL=shutil.which('openssl')
# Synthetic global-unicast literal for certificate fixtures; never contacted.
IP='1.2.3.4'
OTHER_IP='1.2.3.5'
NONCANONICAL_IP='1.02.3.4'


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name).resolve();cls.root.chmod(0o700)
        cls.tls=cls.root/'tls';create(cls.tls);cls.trust=cls.root/'trust';cls.trust.mkdir()
        shutil.copyfile(cls.tls/'ca.crt',cls.trust/'ca.pem')
        cls.runopenssl('rehash',cls.trust)
        ext=cls.tls/'public.cnf';ext.write_text('basicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:'+IP+'\n')
        cls.runopenssl('x509','-req','-in',cls.tls/'server.csr','-CA',cls.tls/'ca.crt','-CAkey',cls.tls/'ca.key',
            '-set_serial','55','-out',cls.tls/'public.crt','-days','2','-sha256','-extfile',ext)
        cls.fullchain=(cls.tls/'public.crt').read_bytes()+(cls.tls/'ca.crt').read_bytes()
        (cls.tls/'index.txt.attr').write_text('unique_subject = no\n')
        cfg=cls.tls/'expired-public.cnf';cfg.write_text((cls.tls/'expired-ca.cnf').read_text().replace('IP:127.0.0.1','IP:'+IP))
        cls.runopenssl('ca','-batch','-config',cfg,'-in',cls.tls/'server.csr','-out',cls.tls/'expired-public.crt',
            '-startdate','20000101000000Z','-enddate','20010101000000Z','-notext')
    @classmethod
    def runopenssl(cls,*args):subprocess.run([OPENSSL,*map(str,args)],check=True,capture_output=True,timeout=20)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def setUp(self):
        self.work=tempfile.TemporaryDirectory(dir=self.root);self.base=Path(self.work.name).resolve()
        self.cert=self.base/'server.crt';self.key=self.base/'server.key'
        self.cert.write_bytes(self.fullchain);self.key.write_bytes((self.tls/'server.key').read_bytes())
        self.cert.chmod(0o600);self.key.chmod(0o600)
        self.openssl=patch.object(public,'OPENSSL',OPENSSL);self.openssl.start();self.addCleanup(self.openssl.stop);self.addCleanup(self.work.cleanup)
    def context(self,**kw):return public.verified_context(self.cert,self.key,IP,os.getuid(),trust_directory=self.trust,**kw)
    def test_exact_chain_ip_key_context_and_metadata(self):
        context,metadata=self.context()
        self.assertIsInstance(context,ssl.SSLContext);self.assertEqual(context.minimum_version,ssl.TLSVersion.TLSv1_2)
        self.assertEqual(set(metadata),{'certificate_sha256','key_sha256','public_ip','not_after','not_after_unix','minimum_validity'})
        self.assertEqual(metadata['certificate_sha256'],hashlib.sha256(self.fullchain).hexdigest())
        self.assertEqual(metadata['key_sha256'],hashlib.sha256(self.key.read_bytes()).hexdigest());self.assertTrue(metadata['not_after'].endswith('Z'))
    def test_wrong_ip_untrusted_expired_and_near_expiry_fail(self):
        with self.assertRaises(ValueError):public.verified_context(self.cert,self.key,OTHER_IP,os.getuid(),trust_directory=self.trust)
        empty=self.base/'untrusted';empty.mkdir()
        with self.assertRaises(ValueError):public.verified_context(self.cert,self.key,IP,os.getuid(),trust_directory=empty)
        with self.assertRaises(ValueError):self.context(minimum_validity=3*86400)
        self.cert.write_bytes((self.tls/'expired-public.crt').read_bytes())
        with self.assertRaises(ValueError):self.context()
    def test_wrong_key_owner_mode_symlink_and_oversize_fail(self):
        original=self.key.read_bytes();self.key.write_bytes((self.tls/'rotated.key').read_bytes())
        with self.assertRaises(ValueError):self.context()
        self.key.write_bytes(original)
        with self.assertRaises(ValueError):public.verified_context(self.cert,self.key,IP,os.getuid()+1,trust_directory=self.trust)
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):self.context()
        self.key.chmod(0o600);link=self.base/'linked.crt';link.symlink_to(self.cert)
        with self.assertRaises(ValueError):public.verified_context(link,self.key,IP,os.getuid(),trust_directory=self.trust)
        self.cert.write_bytes(b'x'*(public.CERTIFICATE_LIMIT+1))
        with self.assertRaises(ValueError):self.context()
    def test_loaded_context_uses_captured_bytes_not_later_file_content(self):
        original=public._bytes_context
        def changed(certificate,key,*args):
            self.cert.write_bytes(b'changed after capture');self.key.write_bytes(b'changed after capture')
            return original(certificate,key,*args)
        with patch.object(public,'_bytes_context',side_effect=changed):
            context,metadata=self.context()
        self.assertIsInstance(context,ssl.SSLContext);self.assertEqual(metadata['certificate_sha256'],hashlib.sha256(self.fullchain).hexdigest())
    def test_invalid_public_ip_and_boolean_inputs_fail(self):
        for address in ('224.0.0.1','127.0.0.1','0.0.0.0',NONCANONICAL_IP):
            with self.assertRaises(ValueError):public.verified_context(self.cert,self.key,address,os.getuid(),trust_directory=self.trust)
        with self.assertRaises(ValueError):self.context(minimum_validity=True)
        with self.assertRaises(ValueError):public.verified_context(self.cert,self.key,IP,True,trust_directory=self.trust)
    def test_manifest_is_exact_and_sequences_not_booleans(self):
        good=dict(format=public.FORMAT,sequence=1,certificate_sha256='a'*64,key_sha256='b'*64)
        self.assertEqual(public.manifest(json.dumps(good).encode()),good)
        for change in ({'sequence':True},{'sequence':0},{'key_sha256':'g'*64},{'extra':1}):
            with self.assertRaises(ValueError):public.manifest(json.dumps(dict(good,**change)).encode())
        with self.assertRaises(ValueError):public.manifest(json.dumps(good).replace('"sequence": 1','"sequence": 1,"sequence": 2').encode())


class PublisherTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.root.chmod(0o755)
        self.patchroot=patch.object(public,'TLS_ROOT',self.root);self.patchroot.start();self.addCleanup(self.patchroot.stop)
        # Isolated non-root filesystem fixture: production root UID/ancestry
        # guard is not executed or represented as a live privileged acceptance.
        def local_directory(path):
            self.assertTrue(Path(path).is_dir());self.assertFalse(Path(path).is_symlink())
        self.patchdir=patch.object(public,'_root_directory',side_effect=local_directory);self.patchdir.start();self.addCleanup(self.patchdir.stop)
        original_read=public._read;original_write=public._write_new
        self.readpatch=patch.object(public,'_read',side_effect=lambda path,uid,*a,**kw:original_read(path,os.getuid() if uid==0 else uid,*a,**kw))
        self.writepatch=patch.object(public,'_write_new',side_effect=lambda path,raw,mode,uid:original_write(path,raw,mode,os.getuid() if uid==0 else uid))
        self.readpatch.start();self.writepatch.start();self.addCleanup(self.readpatch.stop);self.addCleanup(self.writepatch.stop)
    def publish(self,n):
        cert=b'fixture-certificate-'+bytes([n]);key=b'fixture-key-'+bytes([n]);metadata=dict(certificate_sha256=public.sha(cert),key_sha256=public.sha(key))
        return public._publish(cert,key,metadata,expected_uid=os.getuid())
    def test_atomic_sequence_idempotence_and_old_bundles_preserved(self):
        first,changed=self.publish(1);self.assertTrue(changed);raw=(self.root/'current.json').read_bytes()
        same,changed=self.publish(1);self.assertFalse(changed);self.assertEqual(first,same);self.assertEqual((self.root/'current.json').read_bytes(),raw)
        oldkey=(self.root/'bundles/1/server.key').read_bytes();second,changed=self.publish(2)
        self.assertTrue(changed);self.assertEqual(second['sequence'],2);self.assertEqual((self.root/'bundles/1/server.key').read_bytes(),oldkey)
        self.assertEqual((self.root/'current.json').stat().st_mode&0o777,0o444)
        self.assertEqual((self.root/'bundles/2/server.key').stat().st_mode&0o777,0o600)
        self.assertEqual((self.root/'bundles/2').stat().st_mode&0o777,0o755)
    def test_interrupted_publish_keeps_old_manifest_and_skips_retained_orphan(self):
        self.publish(1);before=(self.root/'current.json').read_bytes()
        with patch.object(public.os,'replace',side_effect=OSError('fixture interrupted before atomic publish')):
            with self.assertRaises(OSError):self.publish(2)
        self.assertEqual((self.root/'current.json').read_bytes(),before);self.assertTrue((self.root/'bundles/2/server.key').exists())
        after,changed=self.publish(2);self.assertTrue(changed);self.assertEqual(after['sequence'],3)
        self.assertTrue((self.root/'bundles/1/server.key').exists());self.assertTrue((self.root/'bundles/2/server.key').exists())
    def test_metadata_mismatch_fails_without_publication(self):
        with self.assertRaises(ValueError):public._publish(b'cert',b'key',dict(certificate_sha256='a'*64,key_sha256='b'*64),expected_uid=os.getuid())
        self.assertFalse((self.root/'current.json').exists())
    def test_explicit_unchanged_reload_retries_but_default_is_noop(self):
        metadata=dict(certificate_sha256='a'*64,key_sha256='b'*64)
        value=dict(format=public.FORMAT,sequence=1,**metadata)
        # Mock privilege/source verification only in this private fixture; the
        # real atomic publisher is exercised separately, never fixed /etc paths.
        from types import SimpleNamespace
        mode=SimpleNamespace(st_mode=0o100600,st_uid=0,st_nlink=1)
        with patch.object(public.sys,'platform','linux'),patch.object(public.os,'getuid',return_value=0),\
                patch.object(public.os,'geteuid',return_value=0),patch.object(public.os,'fstat',return_value=mode),\
                patch.object(public,'_mkdir'),patch.object(public,'_lineage_bytes',return_value=(b'cert',b'key')),\
                patch.object(public,'_bytes_context',return_value=(None,metadata)),\
                patch.object(public,'_publish',return_value=(value,False)),\
                patch.object(public,'_restart_active',return_value=True) as restart:
            first=public.deploy(False,IP);self.assertFalse(first['changed']);self.assertFalse(first['restarted_gateway']);restart.assert_not_called()
            retry=public.deploy(True,IP);self.assertFalse(retry['changed']);self.assertTrue(retry['restarted_gateway']);restart.assert_called_once_with()
            with patch.dict(public.os.environ,{public.PUBLIC_IP_SETTING:IP}):self.assertFalse(public.deploy()['changed'])
            with patch.dict(public.os.environ,clear=True),self.assertRaises(ValueError):public.deploy()
            for address in ('127.0.0.1',NONCANONICAL_IP):
                with self.assertRaises(ValueError):public.deploy(False,address)
    def test_root_guard_and_restart_only_fixed_active_gateway(self):
        with patch.object(public.os,'getuid',return_value=501),patch.object(public.sys,'platform','linux'):
            with self.assertRaises(ValueError):public.deploy()
        calls=[];shows=[]
        def run(args,**kw):
            calls.append(args)
            if 'show' in args:
                shows.append(args);invocation=('a' if len(shows)==1 else 'b')*32
                return subprocess.CompletedProcess(args,0,stdout='ActiveState=active\nSubState=running\nMainPID=1234\nInvocationID='+invocation+'\n',stderr='')
            return subprocess.CompletedProcess(args,0,stdout='',stderr='')
        with patch.object(public.subprocess,'run',side_effect=run):self.assertTrue(public._restart_active())
        self.assertEqual(calls[1],['/usr/bin/systemctl','try-restart','zolana-native-060-gateway.service'])
        self.assertFalse(any('validator' in arg for call in calls for arg in call))
        with patch.object(public.subprocess,'run',return_value=subprocess.CompletedProcess([],0,stdout='ActiveState=inactive\nSubState=dead\nMainPID=0\nInvocationID=\n',stderr='')) as run:
            self.assertFalse(public._restart_active());self.assertEqual(run.call_count,1)


if __name__=='__main__':unittest.main()
