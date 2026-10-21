import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import compact_history_collector as collector


class CollectorTests(unittest.TestCase):
    def fixture(self, root):
        network={'network':[7]*32,'genesis_hash':'1'*32}
        raw=json.dumps(dict(network,pool_format='NPOOL004',fixture_keys_are_public=True)).encode()
        class Base:
            def real_directory(self, path, uid, mode):
                if path != root or uid != os.geteuid() or mode != 0o700:raise ValueError('bad root')
            def endpoint(self, value):
                if value != '127.0.0.1:18899':raise ValueError('bad endpoint')
                return value
            def sealed(self, path, maximum):
                if path != collector.OPERATOR or maximum != 32768:raise ValueError('bad profile')
                return raw
        return Base(),dict(gateway_uid=os.geteuid(),network=network),dict(network=network,pool_format='NPOOL004',peers=[{'rpc':'127.0.0.1:18899'}]),raw

    def test_factory_is_offline_binds_public_paths_and_preserves_profile_on_restart(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve()/'history';root.mkdir(mode=0o700)
            base,config,ready,raw=self.fixture(root)
            with patch.object(collector,'ROOT',root),patch.object(collector,'Retention') as retention:
                collector.make_collector(base,config,ready,root,collector.BINARY)
                self.assertEqual((root/'network.json').read_bytes(),raw)
                self.assertEqual(retention.call_args.args[:3],(root,collector.BINARY,'http://127.0.0.1:18899'))
                self.assertEqual(retention.call_args.kwargs,dict(interval=60,primary=root/'recovery-history',mirror=root/'recovery-history-mirror'))
                collector.make_collector(base,config,ready,root,collector.BINARY)
                (root/'network.json').write_bytes(b'changed')
                with self.assertRaisesRegex(ValueError,'profile changed'):
                    collector.make_collector(base,config,ready,root,collector.BINARY)
                self.assertEqual((root/'network.json').read_bytes(),b'changed')

    def test_factory_rejects_rebinding_network_and_invited_or_wallet_profiles(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve()/'history';root.mkdir(mode=0o700)
            base,config,ready,raw=self.fixture(root)
            with patch.object(collector,'ROOT',root),patch.object(collector,'Retention') as retention:
                for changed_root,changed_binary,changed_ready in [(root/'other',collector.BINARY,ready),
                        (root,Path('/other/binary'),ready),(root,collector.BINARY,dict(ready,pool_format='NPOOL003'))]:
                    with self.assertRaises(ValueError):collector.make_collector(base,config,changed_ready,changed_root,changed_binary)
                for fields in ({'invite_required':True},{'key_mode':'user-wallet-v1'},{'network':[8]*32}):
                    with patch.object(base,'sealed',return_value=json.dumps(dict(json.loads(raw),**fields)).encode()):
                        with self.assertRaises(ValueError):collector.make_collector(base,config,ready,root,collector.BINARY)
                retention.assert_not_called();self.assertFalse((root/'network.json').exists())

    def test_queries_are_fixed_bounded_and_reject_ambiguous_or_wrong_responses(self):
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def read(self,maximum):self.maximum=maximum;return self.raw
        response=Response();response.raw=b'{"jsonrpc":"2.0","id":1,"result":12}'
        with patch('compact_history_collector.urllib.request.build_opener') as build:
            opener=build.return_value;opener.open.return_value=response
            self.assertEqual(collector.query('http://127.0.0.1:18899','getSlot',[{'commitment':'finalized'}]),12)
            request=opener.open.call_args.args[0]
            self.assertEqual(json.loads(request.data)['method'],'getSlot');self.assertEqual(opener.open.call_args.kwargs,{'timeout':2})
            self.assertEqual(response.maximum,4097)
            for method,params in [('sendTransaction',[]),('getSlot',[]),('getFirstAvailableBlock',[{}])]:
                with self.assertRaises(ValueError):collector.query('http://127.0.0.1:18899',method,params)
            for value in ({'jsonrpc':'2.0','id':True,'result':12},{'jsonrpc':'2.0','id':1,'result':True},
                    {'jsonrpc':'2.0','id':1,'result':-1},{'jsonrpc':'2.0','id':1,'result':12,'error':None}):
                response.raw=json.dumps(value).encode()
                with self.assertRaises(ValueError):collector.query('http://127.0.0.1:18899','getFirstAvailableBlock',[])
            response.raw=b' '*4097
            with self.assertRaisesRegex(ValueError,'exceeds'):collector.query('http://127.0.0.1:18899','getFirstAvailableBlock',[])


if __name__=='__main__':unittest.main()
