import json
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import gateway_history
from gateway_history import History, parameters, PAGE_BLOCKS_V2
from history_retention_test import NETWORK, archive, block, segment, write


class RetainedPageTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name).resolve()/'history'
        self.root.mkdir(mode=0o700)
        archive(self.root,[segment(self.root,[block(i) for i in range(1,21)])])
        self.reader=History(self.root,NETWORK)

    def page(self,after=0,target=20,token=None,reader=None):
        return json.loads((reader or self.reader).page({'id':'same','params':[after,target,token]}))['result']

    def test_pages_are_bounded_and_checkpoint_survives_publication_and_reader_restart(self):
        first=self.page();self.assertEqual([b['slot'] for b in first['blocks']],list(range(1,17)))
        self.assertFalse(first['complete'])
        data=json.loads((self.root/'manifest.json').read_bytes())
        data['segments'].append(segment(self.root,[block(21)],1));archive(self.root,data['segments'])
        restarted=History(self.root,dict(reversed(list(NETWORK.items()))))
        last=self.page(16,21,first['checkpoint'],restarted)
        self.assertEqual([b['slot'] for b in last['blocks']],[17,18,19,20])
        self.assertEqual(last['retained_tip'],20);self.assertTrue(last['complete'])
        self.assertEqual(self.page(20,21)['blocks'][0]['slot'],21)

    def test_empty_initial_archive_uses_canonical_rpc_without_fabricating_a_prefix(self):
        old=self.page()['checkpoint'];archive(self.root,[])
        self.assertIsNone(self.page())
        with self.assertRaisesRegex(ValueError,'checkpoint unavailable'):self.page(16,20,old)

    def test_target_clamps_archive_and_cached_wallet_beyond_archive_needs_no_file_payload(self):
        result=self.page(target=5);self.assertEqual(result['next_slot'],5);self.assertTrue(result['complete'])
        with patch('gateway_history.read',side_effect=AssertionError('must not read old payload')):
            self.assertEqual(self.page(50,100)['blocks'],[])

    def test_missing_corrupt_permissions_symlinks_network_and_changed_prefix_fail_closed(self):
        first=self.page();name=next(self.root.glob('segment-*.json'));raw=name.read_bytes()
        write(name,raw[:-1])
        with self.assertRaisesRegex(ValueError,'checksum'):self.page()
        write(name,raw);name.chmod(0o644)
        with self.assertRaises(ValueError):self.page()
        name.chmod(0o600);name.unlink()
        with self.assertRaises(FileNotFoundError):self.page()
        name.symlink_to(self.root/'outside')
        with self.assertRaises((OSError,ValueError)):self.page()
        name.unlink();write(name,raw)
        archive(self.root,[segment(self.root,[dict(block(i),blockhash='2'*32) for i in range(1,21)])])
        with self.assertRaisesRegex(ValueError,'checkpoint changed'):self.page(16,20,first['checkpoint'])
        with self.assertRaises(ValueError):History(self.root,dict(NETWORK,genesis_hash='wrong'))

    def test_rehashed_discontinuous_record_and_wrong_genesis_parent_are_rejected(self):
        for bad in [dict(block(2),parent_slot=0),dict(block(1),previous_blockhash='2'*32)]:
            records=[block(i) for i in range(1,21)];records[bad['slot']-1]=bad
            archive(self.root,[segment(self.root,records)])
            with self.assertRaises(ValueError):self.page()

    def test_uncommitted_payloads_are_ignored_and_deadlines_fail_without_partial_reply(self):
        write(self.root/'uncommitted.tmp',b'partial')
        self.assertEqual(self.page()['next_slot'],16)
        with patch('gateway_history.time.monotonic',side_effect=[0,16]):
            with self.assertRaisesRegex(ValueError,'deadline'):self.page()

    def test_response_budget_carries_the_next_record_to_a_later_page(self):
        records=[dict(block(i),transactions=[{'bounded_test_data':'x'*(6*1024*1024)}]) for i in range(1,4)]
        archive(self.root,[segment(self.root,records)])
        first=self.page(target=3)
        self.assertEqual([b['slot'] for b in first['blocks']],[1,2]);self.assertFalse(first['complete'])
        last=self.page(2,3,first['checkpoint'])
        self.assertEqual([b['slot'] for b in last['blocks']],[3]);self.assertTrue(last['complete'])
        archive(self.root,[])
        with self.assertRaisesRegex(ValueError,'checkpoint unavailable'):self.page(2,3,first['checkpoint'])

    def test_schema_rejects_paths_booleans_overflows_and_unbounded_snapshots(self):
        for params in [[True,1,None],[0,2**64,None],[0,1,{'segments':True,'sha256':'a'*64}],
                       [0,1,{'segments':16385,'sha256':'a'*64}],[0,1,{'segments':1,'sha256':'../bad'}]]:
            with self.assertRaises(ValueError):parameters({'params':params})

    def test_v2_preserves_every_header_across_segments_and_pins_restart_prefix(self):
        descriptors=[]
        for index, start in enumerate(range(1,4101,1024)):
            descriptors.append(segment(self.root,[block(i) for i in range(start,min(start+1024,4101))],index))
        archive(self.root,descriptors)
        request={'id':'same','params':[0,4100,None]}
        raw,count=self.reader.page_counted(request,max_blocks=PAGE_BLOCKS_V2)
        first=json.loads(raw)['result']
        self.assertEqual(count,4096);self.assertEqual([b['slot'] for b in first['blocks']],list(range(1,4097)))
        self.assertFalse(first['complete']);self.assertEqual(first['next_slot'],4096)
        self.assertEqual(len(self.page(target=4100)['blocks']),16)  # V1 stays unchanged.
        descriptors.append(segment(self.root,[block(4101)],len(descriptors)));archive(self.root,descriptors)
        restarted=History(self.root,NETWORK)
        raw,count=restarted.page_counted({'id':'next','params':[4096,4101,first['checkpoint']]},max_blocks=4096)
        last=json.loads(raw)['result']
        self.assertEqual(count,4);self.assertEqual([b['slot'] for b in last['blocks']],[4097,4098,4099,4100])
        self.assertEqual(last['retained_tip'],4100);self.assertTrue(last['complete'])

    def test_v2_keeps_raw_byte_budget_deadline_and_empty_archive_count(self):
        records=[dict(block(i),transactions=[{'bounded_test_data':'x'*(6*1024*1024)}]) for i in range(1,4)]
        archive(self.root,[segment(self.root,records)])
        raw,count=self.reader.page_counted({'id':1,'params':[0,3,None]},max_blocks=4096)
        first=json.loads(raw)['result']
        self.assertEqual(count,2);self.assertFalse(first['complete']);self.assertLessEqual(len(raw),16*1024*1024)
        with patch('gateway_history.time.monotonic',return_value=16):
            with self.assertRaisesRegex(ValueError,'deadline'):
                self.reader.page_counted({'id':1,'params':[0,3,None]},max_blocks=4096,deadline=15)
        for maximum in (True,0,17,4097):
            with self.assertRaisesRegex(ValueError,'page bound'):
                self.reader.page_counted({'id':1,'params':[0,3,None]},max_blocks=maximum)
        archive(self.root,[])
        raw,count=self.reader.page_counted({'id':1,'params':[0,3,None]},max_blocks=4096)
        self.assertIsNone(json.loads(raw)['result']);self.assertEqual(count,0)

    def test_v2_changed_checksum_or_rehashed_gap_never_returns_partial_page(self):
        first=json.loads(self.reader.page_counted({'id':1,'params':[0,20,None]},max_blocks=4096)[0])['result']
        archive(self.root,[segment(self.root,[dict(block(i),parent_slot=0) if i==18 else block(i) for i in range(1,21)])])
        with self.assertRaisesRegex(ValueError,'checkpoint changed'):
            self.reader.page_counted({'id':1,'params':[0,20,first['checkpoint']]},max_blocks=4096)
        with self.assertRaisesRegex(ValueError,'continuity'):
            self.reader.page_counted({'id':1,'params':[0,20,None]},max_blocks=4096)

    def test_prewarmed_hits_still_read_and_hash_source_without_reencoding_records(self):
        self.assertEqual(len(self.reader._cache),1)
        original=gateway_history.read
        with (patch.object(self.reader,'_validate_segment',side_effect=AssertionError('unexpected reparse')),
                patch('gateway_history.read',wraps=original) as reads,
                patch('gateway_history.encode',wraps=gateway_history.encode) as encoded):
            raw,count=self.reader.page_counted({'id':'same','params':[0,20,None]},max_blocks=4096)
            value=json.loads(raw)
            self.assertEqual(count,20);self.assertEqual(value['result']['blocks'],[block(i) for i in range(1,21)])
            self.assertEqual(len(reads.call_args_list),1)
            self.assertFalse(any(isinstance(call.args[0],dict) and 'parent_slot' in call.args[0] for call in encoded.call_args_list))
            self.assertEqual(raw,gateway_history.encode(value))

    def test_cached_corruption_permissions_and_missing_payload_fail_closed(self):
        self.assertTrue(self.reader._cache)
        name=next(self.root.glob('segment-*.json'));raw=name.read_bytes();before=name.stat()
        write(name,raw.replace(b'"slot": 1',b'"slot": 9',1))
        os.utime(name,ns=(before.st_atime_ns,before.st_mtime_ns))
        with self.assertRaisesRegex(ValueError,'checksum'):self.page()
        write(name,raw);name.chmod(0o640)
        with self.assertRaises(ValueError):self.page()
        name.chmod(0o600);name.unlink()
        with self.assertRaises(FileNotFoundError):self.page()

    def test_lru_segment_and_header_caps_and_uncached_dense_fallback_preserve_pages(self):
        descriptors=[segment(self.root,[block(i),block(i+1)],index) for index,i in enumerate((1,3,5))]
        archive(self.root,descriptors)
        with patch('gateway_history.CACHE_SEGMENTS',2):
            reader=History(self.root,NETWORK)
            self.assertEqual(len(reader._cache),2)
            self.assertEqual(self.page(4,6,reader=reader)['blocks'],[block(5),block(6)])
            self.assertFalse(any(key[0].startswith('segment-00000000-') for key in reader._cache))
            self.assertEqual(self.page(0,2,reader=reader)['blocks'],[block(1),block(2)])
            self.assertEqual(len(reader._cache),2);self.assertEqual(reader._cache_headers,4)
        with patch('gateway_history.CACHE_HEADERS',3):
            reader=History(self.root,NETWORK)
            self.assertLessEqual(reader._cache_headers,3)
            self.assertEqual(self.page(0,6,reader=reader)['next_slot'],6)
            self.assertLessEqual(reader._cache_headers,3)
        with patch('gateway_history.CACHE_BYTES',128):
            reader=History(self.root,NETWORK)
            self.assertEqual(self.page(0,6,reader=reader)['next_slot'],6)
            self.assertFalse(reader._cache);self.assertEqual(reader._cache_bytes,0)

    def test_prewarm_source_budget_is_bounded_and_append_reuses_only_validated_prefix(self):
        first=segment(self.root,[block(1),block(2)],0)
        second=segment(self.root,[block(3),block(4)],1);archive(self.root,[first,second])
        first_size=(self.root/('segment-00000000-'+first['digest']+'.json')).stat().st_size
        with patch('gateway_history.CACHE_BYTES',first_size+1),patch('gateway_history.read',wraps=gateway_history.read) as reads:
            reader=History(self.root,NETWORK)
            self.assertEqual(sum(len(call.args[0].read_bytes()) for call in reads.call_args_list),first_size)
            self.assertEqual(len(reader._cache),1)
        reader=History(self.root,NETWORK);page=self.page(0,4,reader=reader)
        third=segment(self.root,[block(5),block(6)],2);archive(self.root,[first,second,third])
        self.assertEqual(self.page(4,6,page['checkpoint'],reader)['blocks'],[])
        appended=self.page(4,6,reader=reader)
        self.assertEqual(appended['blocks'],[block(5),block(6)])
        restarted=History(self.root,NETWORK)
        self.assertEqual(self.page(4,6,reader=restarted),appended)

    def test_changed_manifest_parent_cannot_reuse_cached_segment_validation(self):
        first=segment(self.root,[block(1),block(2)],0)
        second=segment(self.root,[block(3),block(4)],1);archive(self.root,[first,second])
        reader=History(self.root,NETWORK)
        archive(self.root,[segment(self.root,[block(1)],0),second])
        with self.assertRaisesRegex(ValueError,'continuity'):self.page(1,4,reader=reader)

    def test_concurrent_cache_eviction_keeps_bounded_metadata_and_exact_response_bytes(self):
        descriptors=[segment(self.root,[block(i)],index) for index,i in enumerate(range(1,5))]
        archive(self.root,descriptors)
        with patch('gateway_history.CACHE_SEGMENTS',1):
            reader=History(self.root,NETWORK)
            with ThreadPoolExecutor(max_workers=4) as workers:
                results=list(workers.map(lambda i:self.page(i-1,i,reader=reader),[1,2,3,4]*3))
            self.assertEqual([v['blocks'] for v in results],[[block(i)] for i in [1,2,3,4]*3])
            self.assertEqual(len(reader._cache),1);self.assertEqual(reader._cache_headers,1)
            self.assertEqual(reader._cache_bytes,sum(entry[2] for entry in reader._cache.values()))


    def test_wide_opt_in_preserves_legacy4096_boundary_and_checkpoint(self):
        descriptors=[]
        for index,start in enumerate(range(1,32770,1024)):
            descriptors.append(segment(self.root,[block(i) for i in range(start,min(start+1024,32770))],index))
        archive(self.root,descriptors);reader=History(self.root,NETWORK)
        request={'id':1,'params':[0,32769,None]}
        small,count=reader.page_counted(request,max_blocks=4096)
        self.assertEqual(count,4096)
        wide,count=reader.page_counted(request,max_blocks=32768);wide=json.loads(wide)['result']
        self.assertEqual(count,32768);self.assertEqual(wide['next_slot'],32768);self.assertFalse(wide['complete'])
        self.assertEqual(wide['checkpoint'],json.loads(small)['result']['checkpoint'])
        last,count=reader.page_counted({'id':2,'params':[32768,32769,wide['checkpoint']]},max_blocks=32768)
        self.assertEqual(count,1);self.assertTrue(json.loads(last)['result']['complete'])
        with self.assertRaisesRegex(ValueError,'page bound'):reader.page_counted(request,max_blocks=32769)

if __name__=='__main__':unittest.main()
