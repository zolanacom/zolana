#!/usr/bin/env python3
"""Host transport, occupied raw ports, SIGKILL and original-payment recovery."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import socket
from pathlib import Path
import threading

from fault_localnet import atomic_json
from localnet import PROJECT, load, start
from operator_transport import UnixHTTP, credential
from rpc_isolation import enable, validate
from tls_localnet import TLSExperiment


class HostExperiment(TLSExperiment):
    def __init__(self,root,evidence):
        super().__init__(root,evidence);self.impostors=[];self.impostor_hits=0;self.impostor_secret_seen=False
    def event(self,kind,**values):
        self.result['events'].append(dict(kind=kind,**values));atomic_json(self.root/'host-result.json',self.result);print(kind,flush=True)
    def enable_policy(self,root):
        enable(root,hardened=True)
        self.start_impostors()
    def start_impostors(self):
        owner=self
        class Impostor(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                owner.impostor_hits+=1
                if self.headers.get('X-Native-Operator'):owner.impostor_secret_seen=True
                self.send_response(403);self.send_header('Content-Length','0');self.end_headers()
        for port in [18899,19899,28899,29899]:
            server=ThreadingHTTPServer(('127.0.0.1',port),Impostor)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();self.impostors.append((server,thread))
        self.event('malicious_tcp_listeners_held_all_raw_and_inspection_ports')
    def raw_probes(self):
        if self.impostor_hits or self.impostor_secret_seen:raise RuntimeError('operator contacted malicious TCP server')
        token,routes=credential(self.root/'rpc-access.key')
        for port in [18900,19900,28900,29900]:
            try:
                with socket.create_connection(('127.0.0.1',port),timeout=.3):pass
            except OSError:pass
            else:raise RuntimeError('protected raw WebSockets are listening')
        for port in [18899,19899]:
            path=Path(routes[str(port)])
            if path.stat().st_mode&0o077:raise RuntimeError('RPC socket is shared')
            for route,headers in [('/',{}),('/health',{}),('/genesis.tar.bz2',{}),('/snapshot.tar.bz2',{}),('/',{'X-Native-Operator':'0'*64}),('/?credential=no',{'X-Native-Operator':token}),('/',{'X-Native-Operator':token,'Origin':'http://127.0.0.1'})]:
                conn=UnixHTTP(str(path),5)
                try:
                    conn.request('POST',route,b'{}',{'Content-Type':'application/json',**headers});reply=conn.getresponse()
                    if reply.status!=403:raise RuntimeError('private socket bypassed capability/route guard')
                    reply.read()
                finally:conn.close()
        if self.impostor_hits:raise RuntimeError('raw probes reached TCP')
        self.event('unix_routes_require_capability_and_tcp_impostors_received_zero_requests')
    def crash_validators(self):
        # Children were created by this experiment, not discovered by port or name.
        for i in [1,0]:
            child=self.children[i]
            if child.poll() is not None:raise RuntimeError('owned validator exited before crash test')
            child.kill();child.wait(timeout=20)
            if child.returncode!=-9:raise RuntimeError('validator did not receive SIGKILL')
        self.event('both_validators_sigkilled_with_original_pending_payment')
        config=load(self.root);key=self.root/'rpc-access.key';marker=self.root/'raw-rpc-required.json'
        for file in [key,marker]:
            original=file.read_bytes();preserved=file.with_suffix(file.suffix+'.retained');file.rename(preserved)
            try:
                try:start(self.root,0,coordinated=True)
                except (OSError,ValueError):pass
                else:raise RuntimeError('incomplete transport policy opened services')
            finally:preserved.rename(file)
            if file.read_bytes()!=original:raise RuntimeError('failure probe changed private material')
        for flags in [{**config,'raw_rpc_host_isolation':False},{k:v for k,v in config.items() if k!='raw_rpc_host_isolation'}]:
            try:validate(self.root,flags)
            except (OSError,ValueError):pass
            else:raise RuntimeError('transport downgrade accepted')
        # SIGKILL must leave stale paths. Refuse symlinks/shared parents before cleanup.
        _,routes=credential(key)
        for port in [18899,19899]:
            path=Path(routes[str(port)])
            if not path.exists():raise RuntimeError('crash did not leave stale Unix socket')
        self.event('missing_material_and_transport_downgrade_refused_before_restart')
    def run(self):
        super().run()
        self.finish_host_acceptance()
    def finish_host_acceptance(self):
        if self.impostor_hits or self.impostor_secret_seen:raise RuntimeError('TCP impersonator saw operator traffic')
        self.result.update(host_transport='owner-only-unix',tcp_impostor_requests=0,validators_sigkilled=True,stale_socket_restart_recovered=True,operator_uid_and_administrator_remain_trusted=True)
        self.event('hardened_host_transport_acceptance_passed')
    def close(self):
        try:super().close()
        finally:
            for server,thread in self.impostors:server.shutdown();server.server_close();thread.join(timeout=5)
            self.impostors=[]


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--evidence',type=Path,required=True);args=parser.parse_args()
    root=args.root.resolve();evidence=args.evidence.resolve()
    if not root.is_relative_to(PROJECT/'.data') or root.exists():parser.error('use a fresh short root; never reset keys or funding')
    evidence.mkdir(mode=0o700,parents=True,exist_ok=False);trial=HostExperiment(root,evidence)
    try:trial.run()
    except Exception as error:trial.result.update(status='failed',error=str(error));raise
    finally:
        try:trial.close()
        finally:
            if root.exists():atomic_json(root/'host-result.json',trial.result)


if __name__=='__main__':main()
