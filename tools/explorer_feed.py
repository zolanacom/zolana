"""Service-owned finalized metadata projection; never exports raw RPC or keys."""
import copy
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import threading
import time

from explorer_model import (FEED_V2, MAX_BYTES, MAX_BLOCKS, MAX_RETAINED_BLOCKS,
                            MAX_RETAINED_TRANSACTIONS, block, natural, validate)
from operator_health import atomic,directory

BLOCK_CONFIG={'encoding':'base64','transactionDetails':'full','rewards':False,'commitment':'finalized','maxSupportedTransactionVersion':0}
FINALIZED={'commitment':'finalized'}
MAX_BACKFILL_SLOTS=16384
RECOVERY_TIMEOUT=180


def read(path,owner,network):
    path=Path(path);directory(path.parent,owner,0o755)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as stream:
        m=os.fstat(stream.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=owner or m.st_nlink!=1 or stat.S_IMODE(m.st_mode)!=0o644 or not 0<m.st_size<=MAX_BYTES:raise ValueError('unsafe public explorer projection')
        raw=stream.read(MAX_BYTES+1)
        if len(raw)!=m.st_size:raise ValueError('explorer projection changed while reading')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('duplicate explorer field')
            result[k]=v
        return result
    return validate(json.loads(raw,object_pairs_hook=unique),network)


class Feed:
    def __init__(self,path,network,rpc,interval=5,clock=time.time):
        self.path=Path(path);directory(self.path.parent,os.getuid(),0o755);self.network=network;self.rpc=rpc;self.interval=interval;self.clock=clock;self.stop=threading.Event();self.failed=False;self.prepared=False;self.thread=None;self.instance=secrets.token_hex(16)
        self.fd=os.open(self.path.with_name('.explorer.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            m=os.fstat(self.fd)
            if not stat.S_ISREG(m.st_mode) or m.st_uid!=os.getuid() or m.st_nlink!=1 or stat.S_IMODE(m.st_mode)!=0o600:raise ValueError('unsafe explorer publisher lock')
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.state=read(self.path,os.getuid(),network) if os.path.lexists(self.path) else None
        except BaseException:os.close(self.fd);self.fd=None;raise

    def publish(self,value):
        if self.failed or self.fd is None:raise ValueError('restart original explorer publisher after uncertain storage')
        def drop_oldest():
            if len(value['blocks'])==1:raise ValueError('explorer projection exceeds storage capacity')
            oldest=value['blocks'].pop(0)
            if oldest['transactions']:
                if value['format']!=FEED_V2:raise ValueError('retention requires current explorer format')
                value['retained_blocks'].append(oldest)
        while len(value['blocks'])>MAX_BLOCKS:
            drop_oldest()
        while len((json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode())>MAX_BYTES:
            drop_oldest()
        validate(value,self.network)
        try:atomic(self.path,value,0o644)
        except BaseException:self.failed=True;raise
        self.state=value

    def finalized(self,seconds):
        deadline=time.monotonic()+seconds
        def call(method,params=None):
            if self.stop.is_set():raise InterruptedError('explorer stopping')
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('explorer sample deadline')
            return self.rpc(method,params or [],timeout=min(remaining,5))
        if call('getGenesisHash')!=self.network['genesis_hash']:raise ValueError('explorer RPC genesis mismatch')
        tip=call('getSlot',[FINALIZED])
        if not natural(tip) or tip==0:raise ValueError('finalized explorer history is not ready')
        return call,tip

    def checkpoint(self,call,tip):
        if self.state is None:return None
        previous=self.state['blocks'][-1]
        if tip<self.state['observed_finalized_slot']:raise ValueError('explorer finalized slot regressed')
        if self.canonical(call,previous['slot'])!=previous:raise ValueError('original explorer checkpoint is not canonical')
        return previous

    @staticmethod
    def canonical(call,slot):
        return block(slot,call('getBlock',[slot,BLOCK_CONFIG]))

    def prepare(self,backfill_from_slot=None):
        if self.prepared:return
        if backfill_from_slot is not None and (not natural(backfill_from_slot) or backfill_from_slot==0 or self.state is None):
            raise ValueError('backfill requires a positive slot and an original explorer checkpoint')
        if self.state is not None:
            first=self.state['blocks'][0]
            floor=self.state.get('retained_from_slot',first['slot'])
            retained=self.state.get('retained_blocks',[])
            backfill=backfill_from_slot is not None and backfill_from_slot<floor
            if backfill and first['slot']-backfill_from_slot>MAX_BACKFILL_SLOTS:
                raise ValueError('explorer backfill exceeds slot bound')
            if retained or backfill_from_slot is not None:
                call,tip=self.finalized(RECOVERY_TIMEOUT)
                self.checkpoint(call,tip)
                for old in retained:
                    if self.canonical(call,old['slot'])!=old:raise ValueError('retained explorer block is not canonical')
                if backfill:
                    if self.canonical(call,first['slot'])!=first:raise ValueError('explorer backfill anchor is not canonical')
                    self.backfill(call,tip,first,retained,backfill_from_slot)
                else:
                    self.checkpoint(call,tip)
        self.prepared=True

    def backfill(self,call,tip,first,retained,start):
        by_slot={item['slot']:item for item in retained}
        transactions=sum(item['transaction_count'] for item in retained)
        child=first
        while child['slot']>start:
            parent_slot=child['parent_slot']
            if parent_slot<start:raise ValueError('explorer backfill start is not a canonical slot')
            parent=self.canonical(call,parent_slot)
            if parent['blockhash']!=child['previous_blockhash'] or parent['block_height']+1!=child['block_height']:
                raise ValueError('explorer backfill ancestry changed')
            if parent_slot in by_slot:
                if parent!=by_slot[parent_slot]:raise ValueError('retained explorer block is not canonical')
            elif parent['transactions']:
                by_slot[parent_slot]=parent
                transactions+=parent['transaction_count']
                if len(by_slot)>MAX_RETAINED_BLOCKS or transactions>MAX_RETAINED_TRANSACTIONS:
                    raise ValueError('explorer backfill exceeds retained capacity')
            child=parent
        self.checkpoint(call,tip)
        value=copy.deepcopy(self.state)
        value.update(format=FEED_V2,retained_from_slot=start,
                     retained_blocks=[by_slot[slot] for slot in sorted(by_slot)],
                     instance=self.instance,sequence=value['sequence']+1,
                     published_at=self.clock(),phase='syncing',observed_finalized_slot=tip)
        self.publish(value)

    def sample(self):
        if self.failed:raise ValueError('explorer publisher storage failed')
        self.prepare()
        sampled=self.clock()
        call,tip=self.finalized(10)
        previous=self.checkpoint(call,tip)
        cursor=previous['slot'] if previous else max(0,tip-1024)
        if tip-cursor>100000:raise ValueError('explorer needs explicit bounded backfill')
        slots=call('getBlocks',[cursor+1,tip,FINALIZED]) if cursor<tip else []
        if not isinstance(slots,list) or len(slots)>100000 or any(not natural(s) or not cursor<s<=tip for s in slots) or any(a>=b for a,b in zip(slots,slots[1:])):raise ValueError('invalid finalized explorer range')
        rows=copy.deepcopy(self.state['blocks']) if self.state else []
        for slot in slots[:32]:
            value=self.canonical(call,slot)
            if rows and (value['parent_slot']!=rows[-1]['slot'] or value['previous_blockhash']!=rows[-1]['blockhash'] or value['block_height']!=rows[-1]['block_height']+1):raise ValueError('explorer canonical ancestry changed')
            rows.append(value)
        if not rows or (cursor<tip and not slots):raise ValueError('finalized explorer range incomplete')
        voting=call('getVoteAccounts',[FINALIZED]);validators=[]
        if not isinstance(voting,dict):raise ValueError('invalid public voting observation')
        for group in ('current','delinquent'):
            if not isinstance(voting.get(group),list) or len(voting[group])+len(validators)>128:raise ValueError('voting observation exceeds bound')
            for v in voting[group]:validators.append({'identity':v['nodePubkey'],'vote_account':v['votePubkey'],'last_vote':v['lastVote'],'activated_stake':str(v['activatedStake']),'delinquent':group=='delinquent'})
        value={'format':FEED_V2,'network':self.network,'instance':self.instance,'sequence':1 if self.state is None else self.state['sequence']+1,'published_at':self.clock(),'sampled_at':sampled,'phase':'live' if rows[-1]['slot']==tip else 'syncing','observed_finalized_slot':tip,'blocks':rows,'validators':validators,
               'retained_from_slot':self.state.get('retained_from_slot',rows[0]['slot']) if self.state else rows[0]['slot'],
               'retained_blocks':list(self.state.get('retained_blocks',[])) if self.state else []}
        self.publish(value);return value

    def start(self):
        def run():
            while not self.stop.is_set():
                try:
                    value=self.sample();delay=.1 if value['phase']=='syncing' else self.interval
                except Exception:
                    if self.failed:return
                    if self.state and self.prepared:
                        value=copy.deepcopy(self.state);value.update(phase='unavailable',published_at=self.clock(),sequence=value['sequence']+1)
                        try:self.publish(value)
                        except Exception:return
                    delay=self.interval
                self.stop.wait(delay)
        self.thread=threading.Thread(target=run,name='public-explorer-feed',daemon=True)
        try:self.thread.start()
        except BaseException:self.thread=None;self.close();raise
        return self

    def close(self,*,pause=True):
        if self.fd is None:return
        self.stop.set()
        try:
            if self.thread:
                self.thread.join(timeout=7)
                if self.thread.is_alive():raise RuntimeError('explorer publisher did not stop')
            if pause and self.state and self.prepared and not self.failed:
                value=copy.deepcopy(self.state);value.update(phase='paused',published_at=self.clock(),sequence=value['sequence']+1);self.publish(value)
        finally:
            if self.fd is not None:os.close(self.fd);self.fd=None
