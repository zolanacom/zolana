"""Public-ingress metadata/FD/application invariants; no host services or wallets."""
import json
import os
from pathlib import Path
import socket
import ssl
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import public_pilot_ingress as public

# Synthetic global-unicast literal for configuration fixtures; never contacted.
IP='1.2.3.4'
NONCANONICAL_IP='1.02.3.4'


class IngressGuards(unittest.TestCase):
    def ingress(self):
        value=public.PublicPilotIngress.__new__(public.PublicPilotIngress)
        value.config=dict(format='zolana-public-pilot-ingress-v1',public_ip=IP,bind_ip='0.0.0.0')
        value.config_sha256='c'*64;value.sequence=3;value.certificate_sha256='a'*64;value.key_sha256='b'*64
        value.cert=Path('/etc/zolana-native-074/tls/bundles/3/server.crt');value.key=value.cert.with_name('server.key')
        value.context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);return value

    def test_static_config_and_rolling_manifest_are_exact(self):
        good=self.ingress().config;public.configuration(good)
        for change in ({'extra':1},{'bind_ip':'127.0.0.1'},{'public_ip':'127.0.0.1'},{'public_ip':'224.0.0.1'},{'public_ip':NONCANONICAL_IP}):
            with self.subTest(change=change),self.assertRaises(ValueError):public.configuration(dict(good,**change))
        manifest=dict(format='zolana-public-tls-bundle-v1',sequence=3,certificate_sha256='a'*64,key_sha256='b'*64)
        public.certificate_manifest(manifest)
        for change in ({'sequence':True},{'sequence':0},{'sequence':'../3'},{'extra':1},{'key_sha256':'g'*64}):
            with self.subTest(change=change),self.assertRaises(ValueError):public.certificate_manifest(dict(manifest,**change))
        with self.assertRaises(ValueError):public.decode(b'{"sequence":1,"sequence":2}')

    def test_certificate_load_uses_derived_paths_fixed_owner_and_os_roots(self):
        config=json.dumps(self.ingress().config).encode();manifest=json.dumps(dict(format='zolana-public-tls-bundle-v1',sequence=3,certificate_sha256='a'*64,key_sha256='b'*64)).encode()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        metadata=dict(certificate_sha256='a'*64,key_sha256='b'*64,public_ip=IP)
        with patch.object(public,'root_sealed',side_effect=lambda p:config if p==public.CONFIG else manifest), \
                patch.object(Path,'resolve',lambda self,*a,**k:self), \
                patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)), \
                patch.object(public,'verified_context',return_value=(context,metadata)) as verify:
            value=public.PublicPilotIngress(public.sha(config))
        verify.assert_called_once_with(value.cert,value.key,IP,expected_uid=994,minimum_validity=3600,trust_directory='/etc/ssl/certs')
        self.assertEqual(value.cert,public.BUNDLES/'3/server.crt');self.assertEqual(value.key,public.BUNDLES/'3/server.key')
        self.assertNotIn('key_sha256',value.evidence());self.assertIs(value.context,context)
        with patch.object(public,'root_sealed',return_value=config),self.assertRaises(ValueError):public.PublicPilotIngress('0'*64)

    def test_exact_four_descriptors_and_binds_no_fallback(self):
        ingress=self.ingress();names=['public-faucet','rpc','public-rpc','faucet'];streams={}
        class Stream:
            family=socket.AF_INET
            def __init__(self,fileno):self.fd=fileno;self.closed=False;streams[fileno]=self
            def getsockopt(self,level,name):return socket.SOCK_STREAM if name==socket.SO_TYPE else 1
            def getsockname(self):
                name=names[self.fd-3];remote=name.startswith('public-');channel=name.removeprefix('public-')
                return ('0.0.0.0' if remote else '127.0.0.1',(public.PUBLIC_PORTS if remote else public.LOCAL_PORTS)[channel])
            def fileno(self):return self.fd
            def close(self):self.closed=True
        env=dict(LISTEN_PID=str(os.getpid()),LISTEN_FDS='4',LISTEN_FDNAMES=':'.join(names))
        with patch.object(public.os,'set_inheritable') as inherit:
            adopted=ingress.activated_sockets(env,Stream)
        self.assertEqual(set(adopted),public.NAMES);self.assertEqual(inherit.call_count,4)
        for change in ({'LISTEN_PID':'1'},{'LISTEN_FDS':'2'},{'LISTEN_FDNAMES':'rpc:faucet:public-rpc:rpc'}):
            with self.subTest(change=change),self.assertRaises(ValueError):ingress.activated_sockets(dict(env,**change),Stream)
        with patch.object(public,'check_activated_socket',side_effect=ValueError('wrong bind')),self.assertRaises(ValueError):ingress.activated_sockets(env,Stream)
        self.assertTrue(streams[3].closed)

    def test_both_listener_pairs_share_original_apps_and_partial_failure_closes(self):
        ingress=self.ingress();base=SimpleNamespace(GWROOT=Path('/original/gateway'));rpc=object();faucet=object()
        channels={'rpc':(object(),rpc),'faucet':(object(),faucet)};streams={n:object() for n in public.NAMES};created=[]
        class Server:
            def __init__(self):self.closed=False;created.append(self)
            def server_close(self):self.closed=True
        with patch.object(public,'listener',side_effect=lambda *a,**k:Server()) as local, \
                patch.object(public.direct_tls,'configured_listener',side_effect=lambda *a,**k:Server()) as remote:
            servers=ingress.listeners(base,channels,streams)
        self.assertEqual(len(servers),4)
        self.assertEqual([c.args[3] for c in local.call_args_list],[rpc,faucet])
        self.assertEqual([c.args[3] for c in remote.call_args_list],[rpc,faucet])
        self.assertEqual([c.args[:2] for c in remote.call_args_list],[('https://'+IP,443),('https://'+IP+':8444',8444)])
        self.assertTrue(all(c.kwargs['tls_context'] is ingress.context for c in remote.call_args_list))
        created.clear()
        with patch.object(public,'listener',side_effect=lambda *a,**k:Server()), \
                patch.object(public.direct_tls,'configured_listener',side_effect=ValueError('denied')),self.assertRaises(ValueError):ingress.listeners(base,channels,streams)
        self.assertEqual(len(created),1);self.assertTrue(created[0].closed)


if __name__=='__main__':unittest.main()
