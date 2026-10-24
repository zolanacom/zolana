"""Independent cached-read boundaries; synthetic public fixtures, no host or wallets."""
import base64
import copy
from email.message import Message
import io
import json
import time
import types
import unittest
from unittest.mock import patch

import testnet_gateway as gateway
import wallet_sync_snapshot as snapshot
from wallet_sync_snapshot_test import Fixture


PROOF = base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()


class CacheBoundaryTests(unittest.TestCase):
    def fixture(self):
        f = Fixture()
        f.app._finalized_blocks = gateway._FinalizedBlockCache()
        f.page()  # Real snapshot validation populates only eligible finalized blocks.
        return f

    def request(self, f, *, access=PROOF, refusal=None, acknowledgment=21):
        seen = []
        class Faucet:
            def ingress(self, channel, peer, units=1):
                seen.append(('ingress', channel, peer))
            def command(self, command, proof, extra=()):
                seen.append((command, copy.deepcopy(proof), list(extra)))
                if proof != {'signature': 'valid'}: raise ValueError('fixture invalid proof')
                if refusal is not None: raise ValueError(refusal)
                return {'authorized': True, 'units': acknowledgment}
        f.app.faucet, f.app.authorize_many = Faucet(), True
        handler = object.__new__(gateway.Handler)
        handler.server = types.SimpleNamespace(authority='127.0.0.1:18898', app=f.app)
        handler.client_address, handler.path = ('127.0.0.1', 3456), '/'
        body = json.dumps({'jsonrpc': '2.0', 'id': 'original', 'method': 'getWalletSyncSnapshot', 'params': [f.saved]}).encode()
        handler.rfile, handler.wfile, handler.headers = io.BytesIO(body), io.BytesIO(), Message()
        for k,v in {'Host':'127.0.0.1:18898','Content-Type':'application/json','Content-Length':str(len(body))}.items(): handler.headers[k]=v
        if access is not None: handler.headers['X-Testnet-Access']=access
        codes=[];handler.send_response=codes.append;handler.send_header=lambda *_:None;handler.end_headers=lambda:None
        original_get=f.app._finalized_blocks.get
        hits=[]
        def get(key):
            # Even a public cache lookup must be downstream of fresh exact prepayment.
            self.assertTrue(any(x[0]=='authorize-many' and x[2]==['--units','21'] for x in seen))
            hits.append(key);return original_get(key)
        with patch.object(f.app._finalized_blocks,'get',side_effect=get): handler.do_POST()
        return codes[0],json.loads(handler.wfile.getvalue()),seen,hits

    def test_each_warm_snapshot_prepays_fresh21_before_any_cache_lookup(self):
        f=self.fixture();start=len(f.calls)
        for _ in range(2):
            code,body,seen,hits=self.request(f)
            self.assertEqual(code,200);self.assertEqual(body['id'],'original')
            self.assertEqual([x for x in seen if x[0]=='authorize-many'],[('authorize-many',{'signature':'valid'},['--units','21'])])
            self.assertTrue(any(key is not None for key in hits))
        self.assertEqual([c['method'] for c in f.calls[start:]],['getGenesisHash','getAccountInfo','getBlocksWithLimit']*2)

    def test_missing_invalid_revoked_quota_and_incomplete_prepay_never_touch_cache(self):
        f=self.fixture()
        for kwargs,expected in [({'access':None},403),({'access':base64.urlsafe_b64encode(b'{"signature":"bad"}').decode()},403),
                                ({'refusal':'fixture revoked member'},403),({'refusal':'request quota exhausted'},429),
                                ({'acknowledgment':20},403)]:
            start=len(f.calls)
            with self.subTest(kwargs=kwargs):
                code,_,_,hits=self.request(f,**kwargs)
                self.assertEqual(code,expected);self.assertEqual(hits,[]);self.assertEqual(len(f.calls),start)

    def test_metadata_and_history_cache_hits_share_original_response_byte_budget(self):
        f=self.fixture();cache=f.app._finalized_blocks
        header=cache.get((f.saved,'header'));full=cache.get((f.slots[0],'full'))
        budget=[0];limit=len(header)+len(full)-1;start=len(f.calls)
        with patch.object(gateway,'RESPONSE_LIMIT',limit):
            f.app._upstream_reads([{'method':'getBlock','params':[f.saved,dict(snapshot.HEADER)]}],
                time.monotonic()+15,snapshot_pool=f.pool_address,single_requests=True,response_budget=budget)
            self.assertEqual(budget[0],len(header))
            with self.assertRaises(gateway.HistoryTooLarge):
                f.app._upstream_reads([{'method':'getBlock','params':[f.slots[0],dict(snapshot.FULL)]}],
                    time.monotonic()+15,history=True,single_requests=True,response_budget=budget)
        self.assertGreater(budget[0],limit);self.assertEqual(len(f.calls),start)

    def test_cache_hit_must_fit_deadline_before_and_after_lookup(self):
        f=self.fixture();cache=f.app._finalized_blocks;start=len(f.calls)
        call=[{'method':'getBlock','params':[f.slots[0],dict(snapshot.FULL)]}]
        with patch.object(cache,'get',side_effect=AssertionError('expired read touched cache')):
            with self.assertRaisesRegex(ValueError,'deadline'):
                f.app._upstream_reads(call,time.monotonic()-1,history=True,single_requests=True,response_budget=[0])
        raw=cache.get((f.slots[0],'full'));clock=[10]
        def slow_get(_):clock[0]=12;return raw
        with patch.object(gateway.time,'monotonic',side_effect=lambda:clock[0]),patch.object(cache,'get',side_effect=slow_get):
            with self.assertRaisesRegex(ValueError,'deadline'):
                f.app._upstream_reads(call,11,history=True,single_requests=True,response_budget=[0])
        self.assertEqual(len(f.calls),start)

    def test_cache_hits_are_reparsed_with_original_rpc_identity_checks(self):
        f=self.fixture();cache=f.app._finalized_blocks;slot=f.slots[0]
        response=json.loads(cache.get((slot,'full')));response['id']=1
        # Deliberately corrupt only this fixture-owned cache: no mutable parsed object is shared.
        cache.put((slot,'full'),json.dumps(response).encode(),response['result'])
        start=len(f.calls)
        with self.assertRaises(ValueError):
            f.app._upstream_reads([{'method':'getBlock','params':[slot,dict(snapshot.FULL)]}],
                time.monotonic()+15,history=True,single_requests=True,response_budget=[0])
        self.assertEqual(len(f.calls),start)


if __name__=='__main__':unittest.main()
