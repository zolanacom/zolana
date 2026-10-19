import ast
import copy
import json
from pathlib import Path
import unittest

tree=ast.parse(Path(__file__).with_name('restart_tail_acceptance.py').read_text())
namespace={'json':json}
exec(compile(ast.Module(body=[v for v in tree.body if isinstance(v,ast.FunctionDef) and v.name=='admission_reads_preserved'],type_ignores=[]),'admission-audit','exec'),namespace)
preserved=namespace['admission_reads_preserved']


class AdmissionReadAuditTests(unittest.TestCase):
    def state(self):
        return {'policy':{'limit':100},'last_time':125,'global_rpc':{'period':2,'count':5},
            'global_faucet':{'period':1,'count':2},'admissions':{'period':0,'count':2},
            'edge':[{'channel':'rpc','peer':'global','bucket':{'period':2,'count':5}}],
            'invitations':[{'id':'original','member':{'claim':'original-claim','faucet':{'period':1,'count':1},'rpc':{'period':2,'count':5}}}]}
    def test_read_quota_and_clock_can_advance(self):
        a=self.state();b=copy.deepcopy(a);b['last_time']=126
        b['global_rpc']['count']+=1;b['edge'][0]['bucket']['count']+=1;b['invitations'][0]['member']['rpc']['count']+=1
        self.assertTrue(preserved(a,b))
    def test_expired_ingress_bucket_can_roll_to_next_window(self):
        a=self.state();b=copy.deepcopy(a);b['last_time']=180;b['edge']=[]
        b['global_rpc']={'period':3,'count':1};b['invitations'][0]['member']['rpc']={'period':3,'count':1}
        self.assertTrue(preserved(a,b))
    def test_policy_membership_and_faucet_budget_changes_are_rejected(self):
        a=self.state()
        for key in ['policy','claim','faucet','global_faucet','admissions']:
            b=copy.deepcopy(a)
            if key=='policy':b[key]['limit']+=1
            elif key=='claim':b['invitations'][0]['member'][key]='changed'
            elif key=='faucet':b['invitations'][0]['member'][key]['count']+=1
            else:b[key]['count']+=1
            self.assertFalse(preserved(a,b),key)
    def test_active_rpc_budget_cannot_be_reset(self):
        a=self.state();b=copy.deepcopy(a);b['global_rpc']['count']=0
        self.assertFalse(preserved(a,b))
        b=copy.deepcopy(a);b['invitations'][0]['member']['rpc']['count']=0
        self.assertFalse(preserved(a,b))
    def test_active_edge_budget_cannot_disappear(self):
        a=self.state();b=copy.deepcopy(a);b['edge']=[]
        self.assertFalse(preserved(a,b))
    def test_clock_cannot_move_backwards(self):
        a=self.state();b=copy.deepcopy(a);b['last_time']-=1
        self.assertFalse(preserved(a,b))


if __name__=='__main__':unittest.main()
