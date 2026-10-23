import base64
import copy
import gzip
import hashlib
import json
from pathlib import Path
import random
import tempfile
import time
import unittest
from unittest.mock import patch

from gateway_history import History
from gateway_history_codec import (FORMAT, MAX_HEADERS, U64_MAX, hash_text,
                                   pack_blocks, unpack_blocks, varint)
from history_retention_test import NETWORK, archive, block, segment, write
from testnet_gateway import Gateway
import testnet_gateway_test as gateway_tests


class CompactCodecTests(unittest.TestCase):
    def test_cross_language_golden_preserves_all_headers_and_sparse_json(self):
        path = Path(__file__).parent/'fixtures/gateway_history_compact_v1.json'
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '420c6724af2c6a4b1a5f916fbddb02e45d5102af458926c787d280a6a38d93ed')
        fixture = json.loads(raw)
        value = fixture['v3_result']
        self.assertEqual(pack_blocks(fixture['v2_blocks']),
                         (value['compact_headers'], value['transactions']))
        self.assertEqual(unpack_blocks(value['compact_headers'], value['transactions']),
                         fixture['v2_blocks'])

    def test_random_skipped_slots_and_nonconsecutive_heights_roundtrip_exactly(self):
        rng = random.Random(231)
        slot, height, previous, blocks = 800, 900, '1'*32, []
        for index in range(512):
            parent = slot
            slot += rng.randrange(1, 100000)
            height += rng.randrange(1, 100000)
            current = hash_text(rng.randbytes(32))
            blocks.append({'slot':slot, 'parent_slot':parent, 'blockhash':current,
                           'previous_blockhash':previous, 'block_height':height,
                           'transactions': [] if index % 7 else [{'public':index, 'payload':['☃', None, False, {'units':str(U64_MAX)}]}]})
            previous = current
        packed, transactions = pack_blocks(blocks)
        self.assertEqual(unpack_blocks(packed, transactions), blocks)

    def test_first_height_zero_and_u64_boundaries_are_lossless(self):
        first = dict(block(1), block_height=0)
        last = dict(block(U64_MAX, 1), block_height=U64_MAX)
        headers, transactions = pack_blocks([first, last])
        self.assertEqual(unpack_blocks(headers, transactions), [first, last])
        headers, transactions = pack_blocks([])
        self.assertEqual(unpack_blocks(headers, transactions), [])

    def test_encoder_never_hides_invalid_parent_hash_height_or_boolean(self):
        valid = [block(1), block(2)]
        for key, value in [('parent_slot',0), ('previous_blockhash','2'*32),
                           ('block_height',1), ('slot',True), ('blockhash','0'*32)]:
            invalid = copy.deepcopy(valid)
            invalid[1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                pack_blocks(invalid)
        with self.assertRaises(ValueError):pack_blocks([block(1)]*(MAX_HEADERS+1))

    def test_truncation_trailing_overlong_zero_and_overflow_streams_fail_closed(self):
        headers, tx = pack_blocks([block(1), block(2)])
        data = base64.b64decode(headers['data_base64'])
        corrupt = [data[:-1], data+b'\0', b'\x81\0'+data[1:], b'\0'+data[1:],
                   b'\xff'*9+b'\x02'+data[1:], data[:34]+b'\1\0'+data[36:]]
        for raw in corrupt:
            with self.subTest(raw=raw[:12]), self.assertRaises(ValueError):
                unpack_blocks(dict(headers,data_base64=base64.b64encode(raw).decode()),tx)
        one, tx = pack_blocks([block(1)])
        with self.assertRaises(ValueError):
            unpack_blocks(dict(one,parent_slot=U64_MAX),tx)
        # The second height addition exceeds u64, despite both integers being valid.
        raw = varint(1)+varint(U64_MAX)+bytes(32)+varint(1)+varint(1)+bytes(32)
        with self.assertRaises(ValueError):
            unpack_blocks(dict(headers,data_base64=base64.b64encode(raw).decode()),[])

    def test_schema_base64_and_transaction_table_are_strict_and_bounded(self):
        headers, _ = pack_blocks([block(1), block(2)])
        for bad in [dict(headers,count=True),dict(headers,count=MAX_HEADERS+1),
                    dict(headers,unknown=1),dict(headers,data_base64='????'),
                    dict(headers,data_base64=headers['data_base64']+'='),
                    dict(headers,data_base64='A'*300)]:
            with self.subTest(bad=bad), self.assertRaises(ValueError):unpack_blocks(bad,[])
        for sparse in [[[0,[]]], [[True,[1]]], [[2,[1]]], [[1,[1]],[0,[2]]],
                       [[0,[1]],[0,[2]]], [[0,{}]], [{'index':0}], [None]]:
            with self.subTest(sparse=sparse), self.assertRaises(ValueError):unpack_blocks(headers,sparse)
        empty, _ = pack_blocks([])
        for bad in [dict(empty,parent_slot=0),dict(empty,previous_blockhash='1'*32),
                    dict(empty,data_base64='AA==')]:
            with self.assertRaises(ValueError):unpack_blocks(bad,[])


class CompactPageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()/'history'; self.root.mkdir(mode=0o700)
        self.descriptors = [segment(self.root,[block(i) for i in range(start,start+1024)],index)
                            for index,start in enumerate((1,1025,2049,3073,4097))]
        archive(self.root,self.descriptors)
        self.reader = History(self.root,NETWORK)

    def pages(self, request, maximum=4096):
        old, old_count = self.reader.page_counted(request,max_blocks=maximum)
        new, new_count = self.reader.page_compact_counted(request,max_blocks=maximum)
        old, new = json.loads(old), json.loads(new)
        self.assertEqual(new_count,old_count)
        result = new['result']; decoded = dict(result)
        decoded['blocks'] = unpack_blocks(decoded.pop('compact_headers'),decoded.pop('transactions'))
        self.assertEqual(decoded,old['result'])
        return result

    def test_checkpoint_metadata_all_headers_and_restart_prefix_match_v2_exactly(self):
        first = self.pages({'id':'same','params':[0,5120,None]})
        self.assertEqual(first['compact_headers']['count'],4096)
        self.assertFalse(first['complete'])
        extra = segment(self.root,[block(5121)],5)
        archive(self.root,self.descriptors+[extra]); self.reader=History(self.root,NETWORK)
        last = self.pages({'id':'same','params':[4096,5121,first['checkpoint']]})
        self.assertEqual(last['retained_tip'],5120)
        self.assertEqual(last['next_slot'],5120);self.assertTrue(last['complete'])

    def test_sparse_packets_dense_byte_budget_and_empty_archive_keep_same_count(self):
        archive(self.root,[segment(self.root,[dict(block(i),transactions=[{'data':'x'*(6*1024*1024)}]) for i in (1,2,3)])])
        self.reader=History(self.root,NETWORK)
        first=self.pages({'id':1,'params':[0,3,None]})
        self.assertEqual(first['compact_headers']['count'],2)
        self.assertEqual([r[0] for r in first['transactions']],[0,1]);self.assertFalse(first['complete'])
        self.pages({'id':1,'params':[2,3,first['checkpoint']]})
        archive(self.root,[])
        raw,count=self.reader.page_compact_counted({'id':1,'params':[0,3,None]})
        self.assertIsNone(json.loads(raw)['result']);self.assertEqual(count,0)

    def test_corruption_cross_segment_hash_and_encoding_deadline_never_return_partial(self):
        first=self.pages({'id':1,'params':[0,5120,None]})
        name=next(self.root.glob('segment-*.json'));raw=name.read_bytes();write(name,raw[:-1])
        with self.assertRaisesRegex(ValueError,'checksum'):
            self.reader.page_compact_counted({'id':1,'params':[0,5120,first['checkpoint']]})
        archive(self.root,[segment(self.root,[block(1)],0),
                           segment(self.root,[dict(block(2),previous_blockhash=hash_text(bytes([1])*32))],1)])
        self.reader=History(self.root,NETWORK)
        with self.assertRaisesRegex(ValueError,'continuity'):
            self.reader.page_compact_counted({'id':1,'params':[0,2,None]})
        archive(self.root,[segment(self.root,[block(1)],0)]);self.reader=History(self.root,NETWORK)
        def late(blocks):
            result=pack_blocks(blocks);time.sleep(.02);return result
        with patch('gateway_history_codec.pack_blocks',side_effect=late):
            with self.assertRaisesRegex(ValueError,'bound'):
                self.reader.page_compact_counted({'id':1,'params':[0,1,None]},deadline=time.monotonic()+.01)


class CompactGatewayTests(unittest.TestCase):
    request = gateway_tests.GatewayTests.request

    def test_v3_uses_same_fresh_authorization_header_billing_gzip_and_never_raw_forward(self):
        proof=base64.urlsafe_b64encode(b'{"signature":"valid"}').decode()
        req={'jsonrpc':'2.0','id':1,'method':'getWalletRetainedHistoryV3','params':[0,40000,None,32768]}
        body=json.dumps({'jsonrpc':'2.0','id':1,'result':{'public_fixture':'x'*10000}}).encode()
        code,_,calls=self.request(req,proof,retained_count=32768,app_body=body,
                                  authorize_many=True,compact_headers_per_unit=256,
                                  headers={'Accept-Encoding':'gzip'})
        self.assertEqual(code,200);self.assertEqual(self.last_headers['Content-Encoding'],'gzip')
        self.assertEqual([c[0] for c in calls],['ingress','authorize','retained-v3','authorize-many'])
        self.assertEqual(calls[-1][2],['--units','127'])
        self.assertNotIn('forward',[c[0] for c in calls])
        self.assertEqual(self.request(req)[0],403)
        self.assertEqual(self.request(req,proof,headers={'Origin':'https://untrusted.example'})[0],403)
        code,_,calls=self.request(req,proof,retained_count=32768,authorize_many=True,
                                  compact_headers_per_unit=256,authorize_limit=127)
        self.assertEqual(code,429);self.assertNotIn('forward',[c[0] for c in calls])
        self.assertEqual(self.request(dict(req,params=[0,1,None,65536]),proof)[0],403)

    def test_real_gateway_v3_uses_same_pinned_history_or_null_without_a_reader(self):
        gateway=object.__new__(Gateway);gateway.history=None
        req={'jsonrpc':'2.0','id':'same','method':'getWalletRetainedHistoryV3','params':[0,1,None]}
        self.assertEqual(json.loads(gateway.retained_history_v3(req,time.monotonic()+5)[0])['result'],None)
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();archive(root,[segment(root,[block(1)])]);gateway.history=History(root,NETWORK)
            raw,count=gateway.retained_history_v3(req,time.monotonic()+5)
            v=json.loads(raw)['result'];self.assertEqual(count,1)
            self.assertEqual(unpack_blocks(v['compact_headers'],v['transactions']),[block(1)])


if __name__=='__main__':unittest.main()
