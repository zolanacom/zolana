"""Four exact host sockets for the original060 apps inside their private namespace."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import stat

import deployment
import direct_tls
from public_tls_certificate import verified_context
from service_tls import check_activated_socket,listener

DEPLOYMENT=deployment.active()
PUBLIC_TLS=DEPLOYMENT['public_tls']
CONFIG=Path(PUBLIC_TLS['ingress_config'])
MANIFEST=Path(PUBLIC_TLS['root'])/'current.json'
BUNDLES=Path(PUBLIC_TLS['root'])/'bundles'
LOCAL_PORTS=deployment.cohort_mode(DEPLOYMENT)['ports']
PUBLIC_PORTS=dict(PUBLIC_TLS['ports'])
NAMES={'rpc','faucet','public-rpc','public-faucet'}


def sha(raw):return hashlib.sha256(raw).hexdigest()


def hex64(v):return isinstance(v,str) and len(v)==64 and set(v)<=set('0123456789abcdef')


def decode(raw):
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value:raise ValueError('duplicate public ingress field')
            value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite public ingress JSON')))


def root_sealed(path,maximum=8192):
    if not path.is_absolute() or path.resolve()!=path:raise ValueError('fixed real root-owned ingress path required')
    for parent in path.parents:
        m=parent.lstat()
        if parent.resolve()!=parent or not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:
            raise ValueError('immutable root-owned ingress ancestors required')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK),'rb') as source:
        m=os.fstat(source.fileno())
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=0 or stat.S_IMODE(m.st_mode)!=0o444 or not 0<m.st_size<=maximum:
            raise ValueError('bounded root444 ingress configuration required')
        raw=source.read(maximum+1)
    if len(raw)!=m.st_size:raise ValueError('ingress configuration changed during read')
    return raw


def configuration(value):
    if (not isinstance(value,dict) or set(value)!={'format','public_ip','bind_ip'}
            or value['format']!='zolana-public-pilot-ingress-v1'
            or not isinstance(value['public_ip'],str) or not isinstance(value['bind_ip'],str)):
        raise ValueError('exact public pilot IPv4 ingress configuration required')
    address=ipaddress.IPv4Address(value['public_ip'])
    if (str(address)!=value['public_ip'] or not address.is_global or address.is_multicast
            or value['bind_ip'] not in ('0.0.0.0',str(address))):
        raise ValueError('explicit public IPv4 and exact public/all-interface bind required')
    return value


def certificate_manifest(value):
    if (not isinstance(value,dict) or set(value)!={'format','sequence','certificate_sha256','key_sha256'}
            or value['format']!='zolana-public-tls-bundle-v1' or type(value['sequence']) is not int
            or not 1<=value['sequence']<=2**63-1
            or not all(hex64(value[k]) for k in ('certificate_sha256','key_sha256'))):
        raise ValueError('exact root-reviewed rolling TLS manifest required')
    return value


class PublicPilotIngress:
    def __init__(self,expected_config_sha256):
        data=root_sealed(CONFIG)
        if not hex64(expected_config_sha256) or sha(data)!=expected_config_sha256:
            raise ValueError('public ingress configuration pin changed')
        self.config=configuration(decode(data));self.config_sha256=expected_config_sha256
        manifest=certificate_manifest(decode(root_sealed(MANIFEST)))
        self.sequence=manifest['sequence'];folder=BUNDLES/str(self.sequence)
        for parent in (folder,*folder.parents):
            m=parent.lstat()
            if parent.resolve()!=parent or not stat.S_ISDIR(m.st_mode) or m.st_uid!=0 or m.st_mode&0o022:
                raise ValueError('immutable root-owned versioned certificate directories required')
        self.cert,self.key=folder/'server.crt',folder/'server.key'
        self.context,metadata=verified_context(self.cert,self.key,self.config['public_ip'],
            expected_uid=PUBLIC_TLS['service_uid'],minimum_validity=PUBLIC_TLS['minimum_validity_seconds'],
            trust_directory='/etc/ssl/certs')
        if (metadata['certificate_sha256']!=manifest['certificate_sha256']
                or metadata['key_sha256']!=manifest['key_sha256'] or metadata['public_ip']!=self.config['public_ip']):
            raise ValueError('rolling public certificate bundle differs from root manifest')
        self.certificate_sha256=metadata['certificate_sha256'];self.key_sha256=metadata['key_sha256']

    def activated_sockets(self,environment=None,factory=socket.socket):
        environment=os.environ if environment is None else environment
        names=environment.get('LISTEN_FDNAMES','').split(':')
        if (environment.get('LISTEN_PID')!=str(os.getpid()) or environment.get('LISTEN_FDS')!='4'
                or len(names)!=4 or set(names)!=NAMES):
            raise ValueError('exact four named TLS descriptors for this gateway PID required')
        streams={}
        try:
            for index,name in enumerate(names):
                stream=factory(fileno=3+index);streams[name]=stream
                public=name.startswith('public-');channel=name.removeprefix('public-')
                check_activated_socket(stream,(PUBLIC_PORTS if public else LOCAL_PORTS)[channel],
                    self.config['bind_ip'] if public else '127.0.0.1')
                os.set_inheritable(stream.fileno(),False)
            return streams
        except BaseException:
            for stream in streams.values():stream.close()
            raise

    def listeners(self,base,channels,streams):
        if set(channels)!=set(LOCAL_PORTS) or set(streams)!=NAMES:
            raise ValueError('same two pilot applications and exact four sockets required')
        servers=[]
        try:
            for name,(handler,app) in channels.items():
                port=LOCAL_PORTS[name]
                servers.append(listener('https://127.0.0.1:'+str(port),port,handler,app,
                    base.GWROOT/'server.crt',base.GWROOT/'server.key',activated_socket=streams[name]))
                port=PUBLIC_PORTS[name];endpoint='https://'+self.config['public_ip']+(':'+str(port) if port!=443 else '')
                binding=dict(format='zolana-direct-tls-v1',audience=endpoint,bind_ip=self.config['bind_ip'],port=port,
                    certificate_sha256=self.certificate_sha256,key_sha256=self.key_sha256)
                servers.append(direct_tls.configured_listener(endpoint,port,handler,app,self.cert,self.key,binding,
                    activated_socket=streams['public-'+name],tls_context=self.context))
            return servers
        except BaseException:
            for server in servers:server.server_close()
            raise

    def evidence(self):
        return dict(format='zolana-public-pilot-ingress-ready-v1',config_sha256=self.config_sha256,
            public_ip=self.config['public_ip'],ports=PUBLIC_PORTS,certificate_sequence=self.sequence,
            certificate_sha256=self.certificate_sha256)
