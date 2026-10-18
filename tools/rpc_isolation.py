#!/usr/bin/env python3
"""Install a durable operator-RPC policy on a stopped local rehearsal only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
from service_tls import private_bytes
from wallet_localnet import private_new


def validate(root,config):
    from localnet import offset
    shift=offset(config)
    marker=root/'raw-rpc-required.json'
    required=config.get('raw_rpc_isolation') is True
    if os.path.lexists(marker) or os.path.lexists(root/'rpc-access.key') or 'raw_rpc_isolation' in config or 'raw_rpc_host_isolation' in config:
        if not required: raise ValueError('raw RPC marker requires its original enabled network policy')
        policy=json.loads(private_bytes(marker,1024))
        from operator_transport import credential
        token,sockets=credential(root/'rpc-access.key')
        hardened=sockets is not None
        if hardened != (config.get('raw_rpc_host_isolation') is True) or (not hardened and 'raw_rpc_host_isolation' in config):
            raise ValueError('private RPC transport cannot be downgraded')
        material=private_bytes(root/'rpc-access.key',4096) if hardened else token.encode()
        if policy!={'format':'native-raw-rpc-unix-v1' if hardened else 'native-raw-rpc-v1','credential_sha256':hashlib.sha256(material).hexdigest()}:
            raise ValueError('raw RPC policy/credential mismatch; preserve original files')
        if hardened:
            expected={str(p):str(root/f'rpc-{p}.sock') for p in [18899+shift,19899+shift,28899+shift,29899+shift]}
            if sockets!=expected:raise ValueError('private RPC routes changed')
        return root/'rpc-access.key'
    return None


def enable(root, hardened=False):
    from localnet import PROJECT, load
    root=root.resolve()
    if not root.is_relative_to(PROJECT/'.data'): raise ValueError('local .data rehearsal required')
    config=load(root)
    from localnet import offset
    shift=offset(config)
    if config.get('key_mode')!='local-testnet-rehearsal-v1': raise ValueError('private rehearsal required')
    if config.get('raw_rpc_isolation') or any((root/n).exists() for n in ['rpc-access.key','raw-rpc-required.json']): raise ValueError('never reset an existing RPC policy')
    for port in [18899+shift,19899+shift,18900+shift,19900+shift]:
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);probe.bind(('127.0.0.1',port))
    token=secrets.token_hex(32)
    material=token.encode()
    if hardened:
        sockets={str(p):str(root/f'rpc-{p}.sock') for p in [18899+shift,19899+shift,28899+shift,29899+shift]}
        from operator_transport import private_parent
        for path in sockets.values():private_parent(path)
        material=json.dumps({'format':'native-rpc-unix-v1','token':token,'sockets':sockets},sort_keys=True).encode()
        config['raw_rpc_host_isolation']=True
    policy={'format':'native-raw-rpc-unix-v1' if hardened else 'native-raw-rpc-v1','credential_sha256':hashlib.sha256(material).hexdigest()}
    private_new(root/'raw-rpc-required.json',json.dumps(policy).encode())
    private_new(root/'rpc-access.key',material)
    config['raw_rpc_isolation']=True
    path=root/'network.json';temporary=root/'.network-rpc-setup'
    private_new(temporary,json.dumps(config,indent=2).encode());os.replace(temporary,path)
    descriptor=os.open(root,os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
    validate(root,config)
    return {'raw_rpc_host_isolation':hardened,'raw_rpc_isolation':True,'websockets_disabled':True,'credential_exported':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--hardened-host',action='store_true');args=parser.parse_args()
    print(json.dumps(enable(args.root,args.hardened_host)))


if __name__=='__main__':main()
