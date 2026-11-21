#!/usr/bin/env python3
"""Isolated LOCAL-063 history overlay on the retained LOCAL-060 rehearsal.

Never provisions, funds, issues invitations, rewrites a seal or creates genesis.
The accepted /opt058 bundle and /etc058 bindings remain authoritative and intact.
"""
import argparse
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode=True
PREFIX=Path('/opt/zolana-native-063')
CONFIG=Path('/etc/zolana-native-063/config.json')
OLD_PREFIX=Path('/opt/zolana-native-058')
OLD_CONFIG=Path('/etc/zolana-native-058/config.json')
OLD_BINDING=Path('/etc/zolana-native-058/cohort-060-rehearsal/binding.json')
BASE_SHA='b043578eb7e8128bd79785100b0df68351fe36948633786a12a4dfdb8ee31397'
FILES={'tools/native_history_candidate.py','tools/testnet_gateway.py','tools/native_cohort_fault.py'}
UNIT='zolana-native-063-gateway.service'
SOCKETS={'rpc':'zolana-native-063-rpc.socket','faucet':'zolana-native-063-faucet.socket'}
OLD_UNITS=('zolana-native-060-rehearsal-gateway.service','zolana-native-060-rehearsal-rpc.socket',
           'zolana-native-060-rehearsal-faucet.socket')
PREVIOUS_UNITS=('zolana-native-061-gateway.service','zolana-native-061-rpc.socket',
                'zolana-native-061-faucet.socket','zolana-native-062-gateway.service',
                'zolana-native-062-rpc.socket','zolana-native-062-faucet.socket')
BASE_MODULE='native_linux_service.py'
HEX=re.compile('[a-f0-9]{64}')


def digest(raw):return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate candidate JSON field')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite candidate JSON')))


def root_ancestors(path):
    path=Path(path)
    if not path.is_absolute() or path.resolve()!=path:raise ValueError('candidate paths must be absolute and real')
    for parent in path.parents:
        meta=parent.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=0 or meta.st_mode&0o022 or parent.resolve()!=parent:
            raise ValueError('candidate ancestors must be immutable real root-owned directories')


def sealed(path,maximum=1024*1024):
    root_ancestors(path)
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as source:
        meta=os.fstat(source.fileno())
        if (not stat.S_ISREG(meta.st_mode) or meta.st_uid!=0 or stat.S_IMODE(meta.st_mode)!=0o444
                or not 1<=meta.st_size<=maximum):raise ValueError('candidate file must be bounded root-owned mode444')
        raw=source.read(maximum+1)
        if len(raw)!=meta.st_size:raise ValueError('candidate file changed while reading')
        return raw


def described(environment=None):
    """This overlay is sealed as exactly three modules, so it reads the deployment description itself.

    With ZOLANA_DEPLOYMENT unset the built-in names and pin stand. Otherwise the
    description must be a sealed file whose SHA-256 is ZOLANA_DEPLOYMENT_SHA256.
    """
    global PREFIX,CONFIG,OLD_PREFIX,OLD_CONFIG,OLD_BINDING,BASE_SHA,UNIT,SOCKETS,OLD_UNITS,PREVIOUS_UNITS,BASE_MODULE
    environment=os.environ if environment is None else environment
    path,expected=(environment.get(name) for name in ('ZOLANA_DEPLOYMENT','ZOLANA_DEPLOYMENT_SHA256'))
    if path is None and expected is None:return False
    if path is None or expected is None or HEX.fullmatch(expected) is None:
        raise ValueError('a deployment description needs its absolute path and its SHA-256')
    raw=sealed(Path(path),65536)
    if digest(raw)!=expected:raise ValueError('deployment description differs from its SHA-256')
    value=decode(raw);service,candidate=value['service'],value['history_candidate']
    rehearsal=value['cohort']['rehearsal'];stem=rehearsal['unit_stem']
    units=[candidate['unit'],candidate['sockets']['rpc'],candidate['sockets']['faucet'],*candidate['previous_units']]
    texts=[candidate['prefix'],candidate['config'],service['prefix'],service['etc'],rehearsal['directory'],stem,
        service['module'],*units]
    if (any(not isinstance(item,str) or not item for item in texts) or len(set(units))!=len(units)
            or any(not Path(item).is_absolute() for item in texts[:4]) or '/' in rehearsal['directory']
            or not isinstance(candidate['base_config_sha256'],str) or HEX.fullmatch(candidate['base_config_sha256']) is None
            or re.fullmatch(r'[a-z][a-z0-9_]{2,63}\.py',service['module']) is None):
        raise ValueError('deployment description does not name this history candidate and its base')
    PREFIX=Path(candidate['prefix']);CONFIG=Path(candidate['config']);OLD_PREFIX=Path(service['prefix'])
    OLD_CONFIG=Path(service['etc'])/'config.json';OLD_BINDING=Path(service['etc'])/rehearsal['directory']/'binding.json'
    BASE_SHA=candidate['base_config_sha256'];UNIT=units[0];SOCKETS={'rpc':units[1],'faucet':units[2]}
    OLD_UNITS=(stem+'-gateway.service',stem+'-rpc.socket',stem+'-faucet.socket')
    PREVIOUS_UNITS=tuple(units[3:]);BASE_MODULE=service['module']
    return True


def validate_config(value):
    keys={'format','manifest_sha256','base_config_sha256','rehearsal_binding_sha256'}
    if (not isinstance(value,dict) or set(value)!=keys or value['format']!='zolana-native-history-candidate-v1'
            or any(not isinstance(value[key],str) or HEX.fullmatch(value[key]) is None for key in keys-{'format'})
            or value['base_config_sha256']!=BASE_SHA):
        raise ValueError('explicit candidate manifest and unchanged original configuration/binding pins required')
    return value


def check_entry(entry,raw):
    if (not isinstance(entry,dict) or set(entry)!={'sha256','size','mode'} or type(entry['size']) is not int
            or entry['size']!=len(raw) or type(entry['mode']) is not int or entry['mode']!=0o444
            or not isinstance(entry['sha256'],str) or HEX.fullmatch(entry['sha256']) is None
            or digest(raw)!=entry['sha256']):raise ValueError('candidate artifact identity mismatch')


def verify_candidate(config):
    raw=sealed(PREFIX/'MANIFEST.json',65536)
    if digest(raw)!=config['manifest_sha256']:raise ValueError('candidate manifest digest mismatch')
    manifest=decode(raw)
    if (not isinstance(manifest,dict) or set(manifest)!={'format','files'}
            or manifest['format']!='zolana-native-history-candidate-bundle-v1'
            or not isinstance(manifest['files'],dict) or set(manifest['files'])!=FILES):
        raise ValueError('candidate inventory must contain exactly its three production modules')
    tools=PREFIX/'tools';root_ancestors(tools/'native_history_candidate.py')
    if {path.name for path in tools.iterdir()}!={Path(name).name for name in FILES}:
        raise ValueError('unmanifested candidate module or bytecode cache')
    for name in sorted(FILES):check_entry(manifest['files'][name],sealed(PREFIX/name))
    return manifest


def load_module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def load_runtime(expected):
    if sys.platform!='linux':raise ValueError('candidate service requires Linux')
    if not isinstance(expected,str) or HEX.fullmatch(expected) is None:raise ValueError('explicit candidate config SHA-256 required')
    raw=sealed(CONFIG,65536)
    if digest(raw)!=expected:raise ValueError('candidate configuration digest mismatch')
    candidate=validate_config(decode(raw));verify_candidate(candidate)
    if Path(__file__).resolve()!=PREFIX/'tools/native_history_candidate.py':
        raise ValueError('candidate must execute from its sealed fixed prefix')
    # Authenticate both bootstrap modules before executing either. load_base then
    # re-verifies the entire accepted bundle, including its binaries and imports.
    old_raw=sealed(OLD_CONFIG,65536)
    if digest(old_raw)!=BASE_SHA:raise ValueError('original base configuration changed')
    original=decode(old_raw);old_manifest=sealed(OLD_PREFIX/'MANIFEST.json')
    if digest(old_manifest)!=original.get('manifest_sha256'):raise ValueError('original manifest changed')
    inventory=decode(old_manifest)
    if (not isinstance(inventory,dict) or inventory.get('format')!='zolana-native-service-bundle-v1'
            or not isinstance(inventory.get('files'),dict)):raise ValueError('original bundle inventory missing')
    for name in ('tools/native_cohort_service.py','tools/'+BASE_MODULE):
        check_entry(inventory['files'].get(name),sealed(OLD_PREFIX/name))
    binding_raw=sealed(OLD_BINDING,65536)
    if digest(binding_raw)!=candidate['rehearsal_binding_sha256']:raise ValueError('original rehearsal binding changed')
    for name in ('testnet_gateway','native_cohort_fault','native_linux_service'):
        if name in sys.modules:raise ValueError('runtime module was imported before candidate verification: '+name)
    cohort=load_module('zolana_history_original_cohort',OLD_PREFIX/'tools/native_cohort_service.py')
    base,config,config_sha=cohort.load_base()
    if config_sha!=BASE_SHA:raise ValueError('loaded original configuration differs')
    cohort.select_mode(True)
    cohort.load_binding(base,config,config_sha)  # No activation, journal or profile mutation.
    # load_base puts old tools first. Insert the verified overlay afterwards and
    # retain the original base object for the candidate gate's helper imports.
    sys.modules['native_linux_service']=base
    sys.path.insert(0,str(PREFIX/'tools'))
    overlays={}
    for name in ('testnet_gateway','native_cohort_fault'):
        loaded=importlib.import_module(name)
        if Path(loaded.__file__).resolve()!=PREFIX/'tools'/(name+'.py'):
            raise ValueError('candidate overlay resolved outside its sealed prefix')
        overlays[name]=str(Path(loaded.__file__))
    evidence=dict(format='zolana-native-history-candidate-check-v1',candidate_config_sha256=expected,
        candidate_manifest_sha256=candidate['manifest_sha256'],base_config_sha256=config_sha,
        rehearsal_binding_sha256=digest(binding_raw),runtime_modules=overlays,
        original_root=str(cohort.ROOT),original_audiences=dict(cohort.PORTS),services_started=0)
    return cohort,base,config,config_sha,evidence


def units(cohort,expected):
    if not isinstance(expected,str) or HEX.fullmatch(expected) is None:raise ValueError('explicit config digest required')
    original=cohort.units(True)
    names=dict(zip(OLD_UNITS,(UNIT,SOCKETS['rpc'],SOCKETS['faucet'])))
    if set(original)!=set(names):raise ValueError('original fixed rehearsal unit set changed')
    conflicts=OLD_UNITS+PREVIOUS_UNITS
    result={}
    for name,text in original.items():
        for before,after in names.items():text=text.replace(before,after)
        text=text.replace('[Unit]\n','[Unit]\nConflicts='+' '.join(conflicts)+'\nAfter='+' '.join(conflicts)+'\n',1)
        text=text.replace('LOCAL-060','LOCAL-063 candidate')
        if name==OLD_UNITS[0]:
            old='ExecStart=/usr/bin/python3 -I -B '+str(OLD_PREFIX/'tools/native_cohort_service.py')+' gateway --rehearsal'
            if old not in text:raise ValueError('original fixed service entrypoint changed')
            text=text.replace(old,'ExecStart=/usr/bin/python3 -I -B '+str(PREFIX/'tools/native_history_candidate.py')+
                              ' gateway --config-sha256 '+expected)
            text=text.replace('WorkingDirectory='+str(OLD_PREFIX)+'\n','WorkingDirectory='+str(PREFIX)+'\n')
        result[names[name]]=text
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('check','gateway','render'))
    parser.add_argument('--config-sha256',required=True);parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    described()
    cohort,base,config,config_sha,evidence=load_runtime(args.config_sha256)
    if args.command=='render':
        if args.output is None:parser.error('render requires a fresh output directory')
        args.output.mkdir(mode=0o700)
        for name,text in units(cohort,args.config_sha256).items():(args.output/name).write_text(text)
    print(json.dumps(evidence,sort_keys=True),flush=True)
    if args.command=='gateway':cohort.gateway(base,config,config_sha)


if __name__=='__main__':main()
