import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from rpc_isolation import validate
from service_tls import listener,operator_token,private_bytes


class IsolationPolicyTests(unittest.TestCase):
    def test_marker_policy_and_credential_must_all_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);key=root/'rpc-access.key';marker=root/'raw-rpc-required.json';config={'raw_rpc_isolation':True}
            for data in [None,b'a'*63,b'G'*64]:
                if data is not None:key.write_bytes(data);key.chmod(0o600)
                with self.assertRaises((ValueError,OSError)):validate(root,config)
            key.write_bytes(b'a'*64);key.chmod(0o600)
            marker.write_text(json.dumps({'format':'native-raw-rpc-v1','credential_sha256':hashlib.sha256(key.read_bytes()).hexdigest()}));marker.chmod(0o600)
            self.assertEqual(validate(root,config),key)
            with self.assertRaises(ValueError):validate(root,{})
            key.write_bytes(b'b'*64)
            with self.assertRaises(ValueError):validate(root,config)
            key.write_bytes(b'a'*64);key.chmod(0o644)
            with self.assertRaises(ValueError):validate(root,config)
            key.chmod(0o600);link=root/'link';link.symlink_to(key)
            with self.assertRaises(OSError):operator_token(link)
            self.assertIsNone(validate(Path(directory)/'legacy',{}))
            with self.assertRaises(ValueError):validate(Path(directory)/'legacy',{'raw_rpc_isolation':False})
            marker.unlink();marker.symlink_to(root/'absent-marker')
            with self.assertRaises(ValueError):validate(root,{})
    def test_https_never_falls_back_to_cleartext_or_mismatched_audience(self):
        for endpoint,cert,key in [('https://127.0.0.1:9443',None,None),('http://127.0.0.1:9443','cert','key'),('https://127.0.0.1:9444','cert','key'),('https://0.0.0.0:9443','cert','key')]:
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):listener(endpoint,9443,object,object(),cert,key)

    def test_real_tls_keys_and_certificates_fail_before_listener_binding(self):
        import ssl
        from local_test_tls import create
        from service_tls import context
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'tls';create(root)
            self.assertEqual(context(root/'server.crt',root/'server.key').minimum_version,ssl.TLSVersion.TLSv1_2)
            for key in [root/'missing.key',root/'rotated.key']:
                with patch('service_tls.TLSServer') as bind:
                    with self.assertRaises((OSError,ValueError)):listener('https://127.0.0.1:18897',18897,object,object(),root/'server.crt',key)
                    bind.assert_not_called()
            (root/'server.key').chmod(0o644)
            with self.assertRaises(ValueError):context(root/'server.crt',root/'server.key')


if __name__=='__main__':unittest.main()
