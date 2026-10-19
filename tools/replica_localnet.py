#!/usr/bin/env python3
"""Finite real-payment, snapshot-peer and independently replicated history acceptance."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

from archive_localnet import ArchiveExperiment
from fault_localnet import WALLET, atomic_json
from history_replica import fetch, initialize
from history_retention import Retention, atomic, directory, manifest
from local_test_tls import create
from localnet import PROJECT, rpc, stop


class ReplicaExperiment(ArchiveExperiment):
    def __init__(self, root, independent):
        super().__init__(root);self.env['RAYON_NUM_THREADS']='2'
        self.independent=Path(independent).absolute()
        if self.independent.exists():raise ValueError('preserve existing replica evidence')
        directory(self.independent.parent);self.independent.mkdir(mode=0o700)
        self.tls=self.independent/'tls';create(self.tls);(self.tls/'ca.crt').chmod(0o600)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));self.replica_port=probe.getsockname()[1]
        self.receiver=None;self.worker=None;self.exports=0;self.starts=0;self.source_unavailable=False
    def receiver_start(self):
        self.starts+=1
        stdout=self.independent/('receiver-'+str(self.starts)+'.stdout.log')
        stderr=self.independent/('receiver-'+str(self.starts)+'.stderr.log')
        for p in [stdout,stderr]:p.touch(mode=0o600)
        with stdout.open('wb') as out,stderr.open('wb') as err:
            self.receiver=subprocess.Popen([sys.executable,str(PROJECT/'tools/history_replica.py'),'serve',
                '--root',str(self.independent/'receiver'),'--port',str(self.replica_port),
                '--cert',str(self.tls/'server.crt'),'--key',str(self.tls/'server.key'),'--duration','540'],
                stdout=out,stderr=err,env=self.env)
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            if self.receiver.poll() is not None:raise RuntimeError('replica receiver failed: '+stderr.read_text()[-1000:])
            if stdout.stat().st_size:return
            time.sleep(.05)
        raise TimeoutError('independent replica listener deadline')
    def receiver_stop(self):
        if self.receiver is not None and self.receiver.poll() is None:
            self.receiver.terminate();self.receiver.wait(timeout=10)
    def collector(self):
        return Retention(self.root,WALLET,'http://127.0.0.1:18899',lambda method,params:rpc(18899,method,params),
            primary=self.root/'retention-source',mirror=self.root/'source-history-mirror',interval=5)
    def setup_replica(self):
        network={k:json.loads((self.root/'network.json').read_bytes())[k] for k in ['network','genesis_hash']}
        initialize(self.independent/'receiver',network,self.independent/'sender.key')
        self.receiver_start()
        self.options=dict(network=network,url='https://127.0.0.1:'+str(self.replica_port),
            credential_file=self.independent/'sender.key',ca_file=self.tls/'ca.crt')
        atomic(self.root/'history-replica.key',(self.independent/'sender.key').read_bytes())
        atomic(self.root/'history-replica-ca.crt',(self.tls/'ca.crt').read_bytes())
        atomic(self.root/'history-replica.json',json.dumps({'format':'native-history-replication-v1','url':self.options['url'],
            'ca_sha256':hashlib.sha256((self.tls/'ca.crt').read_bytes()).hexdigest()}).encode())
        self.worker=self.collector();self.worker.start()
    def outage(self):
        self.worker.close();committed=self.independent/'receiver/committed/manifest.json';before=committed.read_bytes()
        self.receiver_stop();blocked=self.collector()
        try:
            blocked.collect()
        except ValueError as error:
            if str(error)!='retention_replica_unavailable_or_unverified':raise
        else:raise RuntimeError('collector reported success with required receiver offline')
        if blocked.healthy() or committed.read_bytes()!=before:raise RuntimeError('replica outage changed commit or reported healthy')
        blocked.close();self.event('required_replica_outage_blocks_health_preserves_remote_commit')
        self.receiver_start();self.worker=self.collector();self.worker.start()
        self.event('required_replica_restart_recovers_original_policy_and_prefix')
    def export(self):
        self.exports+=1
        if self.worker is None:self.setup_replica()
        if self.exports==2:self.outage()
        if self.source_unavailable:
            for name in ['retention-source','source-history-mirror']:
                (self.root/(name+'-held-030')).rename(self.root/name)
            self.source_unavailable=False;self.worker=self.collector();self.worker.start()
            self.event('source_history_returns_without_resetting_replica')
        target=rpc(18899,'getSlot',[{'commitment':'finalized'}]);deadline=time.monotonic()+100
        while True:
            with self.worker.lock:info=dict(self.worker.info)
            if not self.worker.healthy():raise RuntimeError('required replica retention failed: '+str(info))
            if info['phase']=='ready' and info['finalized_slot']>=target:break
            if time.monotonic()>=deadline:raise TimeoutError('verified replica did not reach live checkpoint')
            time.sleep(.2)
        if info['replica']['manifest_sha256']!=info['manifest_sha256'] or not info['replica']['durable']:
            raise RuntimeError('ready preceded exact durable remote checkpoint')
        if self.exports==3:
            self.worker.close()
            for name in ['retention-source','source-history-mirror']:(self.root/name).rename(self.root/(name+'-held-030'))
            self.source_unavailable=True
            self.event('both_source_history_stores_unavailable_before_replica_download')
        downloaded=fetch(self.root/'recovery-history',**self.options)
        self.event('tls_replica_history_downloaded',result=downloaded,source_unavailable=self.source_unavailable)
        return downloaded
    def event(self,kind,**fields):
        if kind=='fresh_seed_recovers_on_snapshot_rpc':
            if not self.source_unavailable:raise RuntimeError('source histories were available during fresh-seed recovery')
            self.result['fresh_seed_recovered_with_both_source_histories_unavailable']=True
        if kind=='device_local_ui_uses_snapshot_peer_history':self.worker.close()
        super().event(kind,**fields)
    def close(self):
        errors=[]
        if self.worker is not None:
            try:self.worker.close()
            except Exception as error:errors.append(type(error).__name__)
        try:self.receiver_stop()
        except Exception as error:errors.append(type(error).__name__)
        for i in [1,0]:
            if self.children[i] is not None and self.children[i].poll() is None:
                try:stop(self.root,i)
                except Exception as error:errors.append(type(error).__name__)
        self.result['validators_stopped']=all(p is None or p.poll() is not None for p in self.children)
        self.result['replica_receiver_stopped']=self.receiver is None or self.receiver.poll() is not None
        if errors:self.result.update(status='failed',cleanup_errors=errors)
        if self.root.exists():atomic_json(self.root/'archive-result.json',self.result)
        if errors:raise RuntimeError('owned replica acceptance cleanup failed: '+str(errors))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--replica-root',type=Path,required=True);args=parser.parse_args();root=args.root.absolute()
    if root.parent!=PROJECT/'.data' or root.exists():parser.error('use a new short direct child of .data')
    if len(bytes(root/'ledger-recovered-1/admin.rpc'))>=104:parser.error('use a shorter root for snapshot Unix sockets')
    if subprocess.run(['/usr/bin/pgrep','-x','agave-validator'],capture_output=True).returncode!=1:
        raise ValueError('existing validators must stay paused before this finite fixture')
    for port in [18899,19899]:
        with socket.socket() as probe:
            probe.settimeout(.2)
            if probe.connect_ex(('127.0.0.1',port))==0:raise ValueError('fixture RPC port already owned')
    trial=ReplicaExperiment(root,args.replica_root)
    def end(*_):raise TimeoutError('ten-minute real replica/payment acceptance deadline')
    signal.signal(signal.SIGALRM,end);signal.alarm(600)
    try:
        trial.run();trial.result['required_replication_and_restart_recovery']=True
    except BaseException as error:trial.result.update(status='failed',error=type(error).__name__+': '+str(error));raise
    finally:signal.alarm(0);trial.close()


if __name__=='__main__':main()
