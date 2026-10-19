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

from explorer_model import MAX_BYTES,MAX_BLOCKS,block,natural,validate
from operator_health import atomic,directory


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
        self.path=Path(path);directory(self.path.parent,os.getuid(),0o755);self.network=network;self.rpc=rpc;self.interval=interval;self.clock=clock;self.stop=threading.Event();self.failed=False;self.thread=None;self.instance=secrets.token_hex(16)
        self.fd=os.open(self.path.with_name('.explorer.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:
            m=os.fstat(self.fd)
            if not stat.S_ISREG(m.st_mode) or m.st_uid!=os.getuid() or m.st_nlink!=1 or stat.S_IMODE(m.st_mode)!=0o600:raise ValueError('unsafe explorer publisher lock')
            fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.state=read(self.path,os.getuid(),network) if os.path.lexists(self.path) else None
        except BaseException:os.close(self.fd);self.fd=None;raise

    def publish(self,value):
        if self.failed or self.fd is None:raise ValueError('restart original explorer publisher after uncertain storage')
        validate(value,self.network)
        while len((json.dumps(value,sort_keys=True,allow_nan=False)+'\n').encode())>MAX_BYTES:
            if len(value['blocks'])==1:raise ValueError('explorer block exceeds public projection capacity')
            value['blocks'].pop(0)
        try:atomic(self.path,value,0o644)
        except BaseException:self.failed=True;raise
        self.state=value

    def sample(self):
        if self.failed:raise ValueError('explorer publisher storage failed')
        deadline=time.monotonic()+10
        def call(method,params=None):
            if self.stop.is_set():raise InterruptedError('explorer stopping')
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('explorer sample deadline')
            return self.rpc(method,params or [],timeout=min(remaining,5))
        sampled=self.clock()
        if call('getGenesisHash')!=self.network['genesis_hash']:raise ValueError('explorer RPC genesis mismatch')
        tip=call('getSlot',[{'commitment':'finalized'}])
        if not natural(tip) or tip==0:raise ValueError('finalized explorer history is not ready')
        previous=self.state['blocks'][-1] if self.state else None
        config={'encoding':'base64','transactionDetails':'full','rewards':False,'commitment':'finalized','maxSupportedTransactionVersion':0}
        if previous:
            if tip<previous['slot']:raise ValueError('explorer finalized slot regressed')
            canonical=block(previous['slot'],call('getBlock',[previous['slot'],config]))
            if canonical!=previous:raise ValueError('original explorer checkpoint is not canonical')
        cursor=previous['slot'] if previous else max(0,tip-1024)
        if tip-cursor>100000:raise ValueError('explorer needs explicit bounded backfill')
        slots=call('getBlocks',[cursor+1,tip,{'commitment':'finalized'}]) if cursor<tip else []
        if not isinstance(slots,list) or len(slots)>100000 or any(not natural(s) or not cursor<s<=tip for s in slots) or any(a>=b for a,b in zip(slots,slots[1:])):raise ValueError('invalid finalized explorer range')
        rows=copy.deepcopy(self.state['blocks']) if self.state else []
        for slot in slots[:32]:
            value=block(slot,call('getBlock',[slot,config]))
            if rows and (value['parent_slot']!=rows[-1]['slot'] or value['previous_blockhash']!=rows[-1]['blockhash'] or value['block_height']!=rows[-1]['block_height']+1):raise ValueError('explorer canonical ancestry changed')
            rows.append(value)
        if not rows or (cursor<tip and not slots):raise ValueError('finalized explorer range incomplete')
        voting=call('getVoteAccounts',[{'commitment':'finalized'}]);validators=[]
        if not isinstance(voting,dict):raise ValueError('invalid public voting observation')
        for group in ('current','delinquent'):
            if not isinstance(voting.get(group),list) or len(voting[group])+len(validators)>128:raise ValueError('voting observation exceeds bound')
            for v in voting[group]:validators.append({'identity':v['nodePubkey'],'vote_account':v['votePubkey'],'last_vote':v['lastVote'],'activated_stake':str(v['activatedStake']),'delinquent':group=='delinquent'})
        value={'format':'native-explorer-feed-v1','network':self.network,'instance':self.instance,'sequence':1 if self.state is None else self.state['sequence']+1,'published_at':self.clock(),'sampled_at':sampled,'phase':'live' if rows[-1]['slot']==tip else 'syncing','observed_finalized_slot':tip,'blocks':rows[-MAX_BLOCKS:],'validators':validators}
        self.publish(value);return value

    def start(self):
        def run():
            while not self.stop.is_set():
                try:
                    value=self.sample();delay=.1 if value['phase']=='syncing' else self.interval
                except Exception:
                    if self.failed:return
                    if self.state:
                        value=copy.deepcopy(self.state);value.update(phase='unavailable',published_at=self.clock(),sequence=value['sequence']+1)
                        try:self.publish(value)
                        except Exception:return
                    delay=self.interval
                self.stop.wait(delay)
        self.thread=threading.Thread(target=run,name='public-explorer-feed',daemon=True)
        try:self.thread.start()
        except BaseException:self.thread=None;self.close();raise
        return self

    def close(self):
        if self.fd is None:return
        self.stop.set()
        try:
            if self.thread:
                self.thread.join(timeout=7)
                if self.thread.is_alive():raise RuntimeError('explorer publisher did not stop')
            if self.state and not self.failed:
                value=copy.deepcopy(self.state);value.update(phase='paused',published_at=self.clock(),sequence=value['sequence']+1);self.publish(value)
        finally:
            if self.fd is not None:os.close(self.fd);self.fd=None
