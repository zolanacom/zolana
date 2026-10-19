#!/usr/bin/env python3
"""Bounded real native payments through reviewed direct HTTPS on loopback only."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from unittest.mock import patch

import pilot_localnet as pilot
from fault_localnet import atomic_json
from local_test_tls import create as create_tls
from wallet_release import create,encode,sha


class DirectPilot(pilot.Pilot):
    def __init__(self,*args):
        super().__init__(*args);self.edge_children=[];self.edge_starts=0;self.edge_kills=0

    def start_http(self):
        root=self.faucet_root.parent
        # Admission is handled by the real native faucet. This acceptance runner
        # drives its grant worker explicitly, retaining the existing crash gate.
        faucet_script='''import sys
from pathlib import Path
from service_tls import listener
from test_faucet import Faucet,Handler
app=Faucet(Path(sys.argv[1]),Path(sys.argv[2]))
info=app.command('access-info')
server=listener(info['faucet_audience'],13781,Handler,app,Path(sys.argv[3]),Path(sys.argv[4]),Path(sys.argv[5]),sys.argv[6])
server.serve_forever()
'''
        for channel,port in [('faucet',13781),('rpc',18898)]:
            config=self.bindings[channel]
            args=([sys.executable,'-B','-c',faucet_script,str(self.faucet_root),str(self.password_file),
                   str(self.tls/'server.crt'),str(self.tls/'server.key'),str(config),sha(config.read_bytes())] if channel=='faucet' else
                  [sys.executable,'-B',str(pilot.PROJECT/'tools/testnet_gateway.py'),'--root',str(self.faucet_root),
                   '--password-file',str(self.password_file),'--port',str(port),'--tls-cert',str(self.tls/'server.crt'),
                   '--tls-key',str(self.tls/'server.key'),'--listener-config',str(config),'--listener-sha256',sha(config.read_bytes())])
            with (self.evidence/f'{channel}-{self.edge_starts}.log').open('wb') as log:
                child=subprocess.Popen(args,cwd=pilot.PROJECT/'tools',stdout=log,stderr=log,env=self.env)
            self.edge_children.append(child);self.edge_starts+=1
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                if child.poll() is not None:raise RuntimeError('direct TLS child exited; inspect private acceptance log')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.05)
            else:raise RuntimeError('direct TLS child did not bind')
        self.event('reviewed_tls_children_started',starts=self.edge_starts)

    def stop_http(self):
        for child in reversed(self.edge_children):
            if child.poll() is None:
                child.kill();child.wait(timeout=15)
                if child.returncode!=-9:raise RuntimeError('direct TLS child did not receive SIGKILL')
                self.edge_kills+=1
        self.edge_children=[]

    def close(self):
        try:self.stop_http()
        finally:super().close()

    def run(self):
        sources={name:sha((pilot.PROJECT/'tools'/name).read_bytes()) for name in
                 ('direct_tls.py','direct_tls_localnet.py','service_tls.py','test_faucet.py','testnet_gateway.py','pilot_localnet.py')}
        self.tls=self.evidence/'tls';create_tls(self.tls);self.bindings={}
        for channel,port in [('faucet',13781),('rpc',18898)]:
            value=dict(format='zolana-direct-tls-v1',audience=f'https://127.0.0.1:{port}',bind_ip='127.0.0.1',port=port,
                       certificate_sha256=sha((self.tls/'server.crt').read_bytes()),key_sha256=sha((self.tls/'server.key').read_bytes()))
            path=self.evidence/(channel+'-listener.json');create(path,encode(value));self.bindings[channel]=path
        original=pilot.cohort_plan
        def secured(source,tester,*args,**kwargs):
            tester=dict(tester,rpc=dict(transport='https',url='https://127.0.0.1:18898'),
                        faucet=dict(transport='https',url='https://127.0.0.1:13781'),local_tls_ca_pem=(self.tls/'ca.crt').read_text())
            return original(source,tester,*args,**kwargs)
        with patch.object(pilot,'cohort_plan',side_effect=secured):super().run()
        if any(sha((pilot.PROJECT/'tools'/name).read_bytes())!=digest for name,digest in sources.items()):
            raise RuntimeError('direct TLS source changed during live acceptance')
        self.result.update(direct_https=True,direct_tls_source_sha256=sources,tls_child_starts=self.edge_starts,
                           tls_child_sigkills_before_final_cleanup=self.edge_kills,external_connections=0)
        self.event('direct_https_payment_and_restart_acceptance_passed')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True)
    args=parser.parse_args();root=args.root.absolute();evidence=args.evidence.absolute()
    if root.parent!=pilot.PROJECT/'.data' or os.path.lexists(root):parser.error('use a new short direct .data child; never reset existing state')
    evidence.mkdir(mode=0o700,parents=True,exist_ok=False);trial=DirectPilot(root,evidence,None,None)
    def interrupted(*_):raise KeyboardInterrupt('bounded local direct TLS test interrupted')
    signal.signal(signal.SIGTERM,interrupted)
    try:trial.run()
    except BaseException as error:trial.result.update(status='failed',error=str(error));raise
    finally:
        try:trial.close()
        finally:
            if root.exists():atomic_json(root/'direct-tls-result.json',trial.result)


if __name__=='__main__':main()
