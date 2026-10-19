#!/usr/bin/env python3
"""Finite real-process TLS replica crash rehearsal; never starts a validator."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

from history_retention import atomic, capture, directory, manifest, read
from history_replica import Handler, Receiver, fetch, identity, immutable, initialize, replicate
from local_test_tls import create
from service_tls import TLSServer, context


def record(path, value):atomic(path, json.dumps(value, sort_keys=True, indent=2).encode())


def gated(root, tls, gate, port):
    class Probe(Receiver):
        def hold(self, phase):
            control=json.loads(read(gate/'control.json',4096))
            if control['mode']!=phase:return
            nonce=control['nonce'];record(gate/(nonce+'.hit.json'),{'phase':phase,'pid':os.getpid()})
            end=time.monotonic()+20
            while time.monotonic()<end:
                if (gate/(nonce+'.release')).exists():return
                time.sleep(.05)
            raise ValueError('finite acceptance gate expired')
        def upload(self,*args):
            value=super().upload(*args);self.hold('upload');return value
        def commit(self,*args):
            self.hold('before_commit');value=super().commit(*args);self.hold('after_commit');return value
    app=Probe(root)
    listener=TLSServer(('127.0.0.1',port),Handler,context(tls/'server.crt',tls/'server.key'))
    listener.app=app;listener.authority='127.0.0.1:'+str(port)
    def end(*_):raise TimeoutError('finite replica acceptance session')
    signal.signal(signal.SIGTERM,end);signal.signal(signal.SIGINT,end);signal.signal(signal.SIGALRM,end);signal.alarm(300)
    record(gate/'receiver-ready.json',{'pid':os.getpid(),'port':port})
    try:listener.serve_forever(poll_interval=.1)
    except TimeoutError:pass
    finally:signal.alarm(0);listener.server_close();app.close()


class TransportTrial:
    def __init__(self, fixture, root):
        self.fixture=directory(fixture);self.root=Path(root).absolute()
        if self.root.exists():raise ValueError('preserve existing replica acceptance evidence')
        directory(self.root.parent);self.root.mkdir(mode=0o700)
        self.receiver=None;self.uploaders=[];self.result={'status':'running','events':[]}
        self.gate=directory(self.root/'gates',create=True)
        self.tls=self.root/'tls';create(self.tls);(self.tls/'ca.crt').chmod(0o600)
        self.network=identity(self.fixture/'network.json')
        self.reference=self.root/'reference-history'
        capture(self.fixture/'recovery-history',self.reference,self.network)
        self.raw,self.files,_=manifest(self.reference,self.network)
        if len(self.files)<4:raise ValueError('need four real retained segments for independent crash boundaries')
        self.source=directory(self.root/'source',create=True)
        self.replica=self.root/'receiver';self.key=self.root/'sender.key'
        initialize(self.replica,self.network,self.key)
        with socket.socket() as probe:probe.bind(('127.0.0.1',0));self.port=probe.getsockname()[1]
        self.options=dict(network=self.network,url='https://127.0.0.1:'+str(self.port),credential_file=self.key,ca_file=self.tls/'ca.crt')
        record(self.root/'network.json',self.network);self.disarm()
    def event(self,kind,**fields):
        self.result['events'].append(dict(kind=kind,**fields));record(self.root/'replica-transport-result.json',self.result);print(kind,flush=True)
    def prefix(self,count):
        value=json.loads(self.raw);value['segments']=value['segments'][:count]
        for name,_ in self.files[:count]:immutable(self.source/name,read(self.reference/name,32*1024*1024))
        record(self.source/'manifest.json',value)
    def start(self):
        self.receiver=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),'serve-gated','--root',str(self.replica),
            '--tls',str(self.tls),'--gate',str(self.gate),'--port',str(self.port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        end=time.monotonic()+15
        while time.monotonic()<end:
            if self.receiver.poll() is not None:raise RuntimeError('receiver startup failed: '+self.receiver.communicate()[1].decode()[-1000:])
            ready=self.gate/'receiver-ready.json'
            if ready.exists() and json.loads(ready.read_bytes())['pid']==self.receiver.pid:return
            time.sleep(.05)
        raise TimeoutError('replica receiver startup deadline')
    def stop(self,crash=False):
        if self.receiver is not None and self.receiver.poll() is None:
            self.receiver.kill() if crash else self.receiver.terminate()
            self.receiver.communicate(timeout=10)
            if crash and self.receiver.returncode!=-9:raise RuntimeError('receiver was not SIGKILLed')
    def arm(self,mode):
        nonce=os.urandom(12).hex();record(self.gate/'control.json',{'mode':mode,'nonce':nonce});return nonce
    def disarm(self):record(self.gate/'control.json',{'mode':'none','nonce':'none'})
    def uploader(self):
        child=subprocess.Popen([sys.executable,str(Path(__file__).with_name('history_replica.py')),'push',
            '--network',str(self.root/'network.json'),'--source',str(self.source),'--url',self.options['url'],
            '--credential-file',str(self.key),'--ca-file',str(self.tls/'ca.crt')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.uploaders.append(child);return child
    def reached(self,nonce,child):
        end=time.monotonic()+15;path=self.gate/(nonce+'.hit.json')
        while time.monotonic()<end:
            if path.exists():return
            if child.poll() is not None:raise RuntimeError('uploader exited before gate: '+child.communicate()[1].decode()[-1000:])
            time.sleep(.05)
        raise TimeoutError('real TLS crash gate not reached')
    def committed(self):return read(self.replica/'committed/manifest.json',4*1024*1024)
    def run(self):
        self.prefix(1);self.start();first=replicate(self.source,**self.options)
        self.event('initial_tls_replica_committed',checkpoint=first['manifest_sha256'])
        old=self.committed();self.prefix(2);nonce=self.arm('upload');child=self.uploader();self.reached(nonce,child)
        child.kill();child.communicate(timeout=10)
        if child.returncode!=-9 or self.committed()!=old:raise RuntimeError('uploader crash replaced committed history')
        record(self.gate/(nonce+'.release'),{});self.disarm()
        recovered=replicate(self.source,**self.options)
        if recovered['segments']!=2:raise RuntimeError('uploader retry did not complete exact candidate')
        self.event('uploader_sigkill_retries_identical_durable_payload',exit_code=child.returncode)
        old=self.committed();self.prefix(3);nonce=self.arm('before_commit');child=self.uploader();self.reached(nonce,child)
        self.stop(crash=True);child.communicate(timeout=10)
        if child.returncode==0 or self.committed()!=old:raise RuntimeError('receiver crash published incomplete history')
        self.disarm();self.start();recovered=replicate(self.source,**self.options)
        if recovered['segments']!=3:raise RuntimeError('receiver restart did not recover staged history')
        self.event('receiver_sigkill_before_publication_keeps_old_commit',exit_code=-9)
        self.prefix(4);nonce=self.arm('after_commit');child=self.uploader();self.reached(nonce,child)
        published=self.committed()
        if published!=(self.source/'manifest.json').read_bytes():raise RuntimeError('ack-loss gate preceded durable commit')
        self.stop(crash=True);child.communicate(timeout=10)
        if child.returncode==0:raise RuntimeError('lost replica reply unexpectedly returned success')
        self.disarm();self.start();recovered=replicate(self.source,**self.options)
        if recovered['uploaded_bytes']!=0 or self.committed()!=published:raise RuntimeError('lost-ack retry changed committed history')
        self.event('receiver_sigkill_after_commit_recovers_lost_ack_without_reupload',exit_code=-9)
        self.source.rename(self.root/'source-unavailable')
        restored=fetch(self.root/'recovered-history',**self.options)
        if restored['manifest_sha256']!=hashlib.sha256(published).hexdigest():raise RuntimeError('source outage recovery changed checkpoint')
        self.event('source_history_unavailable_replica_downloads_exact_committed_prefix',segments=restored['segments'])
        for name,_ in self.files[:4]:
            if (self.root/'recovered-history'/name).read_bytes()!=(self.reference/name).read_bytes():raise RuntimeError('restored payload changed')
        self.result.update(status='passed',validators_started=0,real_sigkills=3,no_wallet_or_raw_rpc_keys_copied=True)
        self.event('replica_transport_acceptance_passed')
    def close(self):
        self.disarm()
        for child in self.uploaders:
            if child.poll() is None:child.kill()
            child.communicate(timeout=10)
        self.stop()
        self.result['receiver_stopped']=self.receiver is None or self.receiver.poll() is not None
        record(self.root/'replica-transport-result.json',self.result)


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
    run=sub.add_parser('run');run.add_argument('--fixture',type=Path,required=True);run.add_argument('--root',type=Path,required=True)
    serve=sub.add_parser('serve-gated');serve.add_argument('--root',type=Path,required=True)
    serve.add_argument('--tls',type=Path,required=True);serve.add_argument('--gate',type=Path,required=True);serve.add_argument('--port',type=int,required=True)
    args=parser.parse_args()
    if args.command=='serve-gated':return gated(args.root,args.tls,args.gate,args.port)
    trial=TransportTrial(args.fixture,args.root)
    def end(*_):raise TimeoutError('three-minute replica crash acceptance deadline')
    signal.signal(signal.SIGALRM,end);signal.alarm(180)
    try:trial.run()
    except BaseException as error:trial.result.update(status='failed',error=type(error).__name__+': '+str(error));raise
    finally:signal.alarm(0);trial.close()


if __name__=='__main__':main()
