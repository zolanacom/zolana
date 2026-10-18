import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gateway_history import History, parameters
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


if __name__=='__main__':unittest.main()
