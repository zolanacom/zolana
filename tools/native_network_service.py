#!/usr/bin/env python3
"""The sealed validator and gateway services for any deployment description.

native_linux_service.py is the accepted service source. Two startup wrappers and
their tests bind its exact bytes, so it cannot take its names from anywhere but
itself. This entry point runs that same source with every installation name,
path, account, port and validator count replaced by a value from the deployment
description (tools/deployment.py).

REPLACEMENTS is the whole difference. Each entry must match the accepted source
exactly the stated number of times, and the source must have the accepted
SHA-256, or nothing runs. With the built-in description the result behaves as
native_linux_service.py does and renders the same units.

Used exactly like native_linux_service.py: check, validator, gateway, render.
A deployment selects it with service.module in its description.
"""
import hashlib
from pathlib import Path
import types


def load_description():
    # Python -I excludes siblings/PYTHONPATH. Execute the deployment description
    # module from beside this entrypoint, without a bytecode cache; the sealed
    # bundle check in load_config covers this file, that module and the source.
    path=Path(__file__).resolve().with_name('deployment.py');module=types.ModuleType('zolana_deployment')
    module.__file__=str(path);exec(compile(path.read_bytes(),str(path),'exec'),module.__dict__)
    return module


description=load_description()
DEPLOYMENT=description.active()
SERVICE=DEPLOYMENT['service']
VALIDATORS=DEPLOYMENT['validators']
SOCKET_UNITS=SERVICE['sockets']['rpc']+' '+SERVICE['sockets']['faucet']
MODULE=Path(__file__).name
ACCEPTED_SOURCE='native_linux_service.py'

# (text in the accepted source, its replacement, how many times it occurs)
REPLACEMENTS=(
    # Installation roots, loopback ports and unit names.
    ("PREFIX = Path('/opt/zolana-native-058')","PREFIX = Path(SERVICE['prefix'])",1),
    ("ETC = Path('/etc/zolana-native-058')","ETC = Path(SERVICE['etc'])",1),
    ("STATE = Path('/var/lib/zolana-native-058')","STATE = Path(SERVICE['state'])",1),
    ("RUN = Path('/run/zolana-native-058')","RUN = Path(SERVICE['run'])",1),
    ("PORTS = {'rpc':38443, 'faucet':38444}","PORTS = dict(SERVICE['ports'])",1),
    ("UNITS = {'validator':'zolana-native-058-validator.service', 'gateway':'zolana-native-058-gateway.service'}",
     "UNITS = dict(SERVICE['units'])",1),
    ("public.get('rpc',{}).get('url')!='https://127.0.0.1:38443'",
     "public.get('rpc',{}).get('url')!='https://127.0.0.1:'+str(PORTS['rpc'])",1),
    ("public.get('faucet',{}).get('url')!='https://127.0.0.1:38444'",
     "public.get('faucet',{}).get('url')!='https://127.0.0.1:'+str(PORTS['faucet'])",1),
    # Validator count.
    ("len(identities)!=3 or","len(identities)!=VALIDATORS or",1),
    ("len(set(identities))!=3)","len(set(identities))!=VALIDATORS)",1),
    ("len(layout)!=3:raise","len(layout)!=VALIDATORS:raise",1),
    ("len(peers)!=3 or","len(peers)!=VALIDATORS or",1),
    ("for k in ('rpc','native_ingress')})!=6:","for k in ('rpc','native_ingress')})!=2*VALIDATORS:",1),
    ("len(nodes)!=3:raise","len(nodes)!=VALIDATORS:raise",1),
    ("if len(addresses)!=3 or len(set(addresses))!=3:raise",
     "if len(addresses)!=VALIDATORS or len(set(addresses))!=VALIDATORS:raise",1),
    ("if len(complete)==3:return","if len(complete)==VALIDATORS:return",1),
    # Validator source line and network identity.
    ("original.get('upstream_commit')!='a203300045b405f86c9c84308b2eae76af69ac3b'",
     "original.get('upstream_commit')!=DEPLOYMENT['network']['upstream_commit']",1),
    ("config=validate_config(json.loads(raw));verify_bundle(config)",
     "config=validate_config(json.loads(raw));description.check_network(DEPLOYMENT,config['network']);"
     "sealed_description();verify_bundle(config)",1),
    # Service accounts.
    ("pwd.getpwnam('zolana058v' if role=='validator' else 'zolana058g')","pwd.getpwnam(SERVICE['users'][role])",1),
    ("\\nUser=zolana058'+('v' if role=='validator' else 'g')+'\\nGroup=zolana058'+('v' if role=='validator' else 'g')+'\\n'+",
     "\\nUser='+SERVICE['users'][role]+'\\nGroup='+SERVICE['users'][role]+'\\n'+",1),
    ("'SupplementaryGroups=zolana058link\\nWorkingDirectory='",
     "'SupplementaryGroups='+SERVICE['link_group']+'\\n'+description.unit_environment()+'WorkingDirectory='",1),
    # Rendered units and the files a sealed bundle must hold.
    ("'\\nRequires=zolana-native-058-rpc.socket zolana-native-058-faucet.socket\\n'+","'\\nRequires='+SOCKET_UNITS+'\\n'+",1),
    ("' zolana-native-058-rpc.socket zolana-native-058-faucet.socket\\n'+","' '+SOCKET_UNITS+'\\n'+",1),
    ("('Sockets=zolana-native-058-rpc.socket zolana-native-058-faucet.socket\\n' if","('Sockets='+SOCKET_UNITS+'\\n' if",1),
    ("output['zolana-native-058-'+name+'.socket']","output[SERVICE['sockets'][name]]",1),
    ("Description=Zolana LOCAL-058 '+","Description=Zolana '+SERVICE['label']+' '+",2),
    ("str(PREFIX/'tools/native_linux_service.py')","str(PREFIX/'tools'/SERVICE['module'])",1),
    ("required={'tools/native_linux_service.py','tools/service_tls.py'}|",
     "required={'tools/native_linux_service.py','tools/'+MODULE,'tools/deployment.py','tools/service_tls.py'}|",1),
    ("raise ValueError('LOCAL-058 service requires Linux')","raise ValueError(SERVICE['label']+' service requires Linux')",1),
)


def sealed_description():
    if description.active(sealed=True)!=DEPLOYMENT:raise ValueError('deployment description changed or is not sealed')


def accepted_source():
    path=Path(__file__).resolve().with_name(ACCEPTED_SOURCE);raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=description.DEFAULT['service']['module_sha256']:
        raise ValueError('accepted service source differs from its SHA-256')
    text=raw.decode()
    for old,new,count in REPLACEMENTS:
        if text.count(old)!=count or '\n' in old or '\n' in new:raise ValueError('accepted service source no longer matches: '+old)
        text=text.replace(old,new)
    return path,text


# The accepted source defines the service in this module's own namespace and,
# when this file is the program, ends by running its main().
exec(compile(accepted_source()[1],str(accepted_source()[0]),'exec'),globals())
