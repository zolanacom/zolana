#!/usr/bin/env python3
"""Install a durable operator-RPC policy on a stopped local rehearsal only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
from service_tls import operator_token, private_bytes
from wallet_localnet import private_new


def validate(root,config):
    marker=root/'raw-rpc-required.json'
    required=config.get('raw_rpc_isolation') is True
    if os.path.lexists(marker) or 'raw_rpc_isolation' in config:
        if not required: raise ValueError('raw RPC marker requires its original enabled network policy')
        policy=json.loads(private_bytes(marker,1024))
        token=operator_token(root/'rpc-access.key')
        if policy!={'format':'native-raw-rpc-v1','credential_sha256':hashlib.sha256(token.encode()).hexdigest()}:
            raise ValueError('raw RPC policy/credential mismatch; preserve original files')
        return root/'rpc-access.key'
    return None


def enable(root):
    from localnet import PROJECT, load
    root=root.resolve()
    if not root.is_relative_to(PROJECT/'.data'): raise ValueError('local .data rehearsal required')
    config=load(root)
    if config.get('key_mode')!='local-testnet-rehearsal-v1': raise ValueError('private rehearsal required')
    if config.get('raw_rpc_isolation') or any((root/n).exists() for n in ['rpc-access.key','raw-rpc-required.json']): raise ValueError('never reset an existing RPC policy')
    for port in [18899,19899,18900,19900]:
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);probe.bind(('127.0.0.1',port))
    token=secrets.token_hex(32)
    policy={'format':'native-raw-rpc-v1','credential_sha256':hashlib.sha256(token.encode()).hexdigest()}
    private_new(root/'raw-rpc-required.json',json.dumps(policy).encode())
    private_new(root/'rpc-access.key',token.encode())
    config['raw_rpc_isolation']=True
    path=root/'network.json';temporary=root/'.network-rpc-setup'
    private_new(temporary,json.dumps(config,indent=2).encode());os.replace(temporary,path)
    descriptor=os.open(root,os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    validate(root,config)
    return {'raw_rpc_isolation':True,'websockets_disabled':True,'credential_exported':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);args=parser.parse_args()
    print(json.dumps(enable(args.root)))


if __name__=='__main__':main()
