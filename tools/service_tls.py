"""Verified local TLS listeners; no cleartext sibling or global trust-store changes."""
import os
from pathlib import Path
import ssl
import stat
import urllib.parse
from test_faucet import BoundedServer


def private_bytes(path, maximum, secret=True):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        meta=os.fstat(source.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid!=os.getuid() or (secret and meta.st_mode&0o077) or not 1<=meta.st_size<=maximum:
            raise ValueError('TLS/operator file must be bounded, regular and owned; secrets must be owner-only')
        data=source.read(maximum+1)
        if len(data)>maximum: raise ValueError('TLS/operator file exceeds limit')
        return data


def operator_token(path):
    token=private_bytes(path,64)
    if len(token)!=64 or any(c not in b'0123456789abcdef' for c in token): raise ValueError('invalid raw RPC credential')
    return token.decode()


def context(cert,key):
    private_bytes(cert,32768,secret=False); private_bytes(key,32768)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(['http/1.1'])
    ctx.load_cert_chain(cert,key,password=lambda:'')
    return ctx


class TLSServer(BoundedServer):
    def __init__(self,address,handler,ctx):
        self.tls_context=ctx
        super().__init__(address,handler)
    def process_request_thread(self,request,address):
        try:
            request.settimeout(3)
            secure=self.tls_context.wrap_socket(request,server_side=True)
            secure.settimeout(10)
        except (ssl.SSLError,OSError):
            request.close();self.slots.release();return
        super().process_request_thread(secure,address)


def listener(endpoint,port,handler,app,cert=None,key=None):
    parsed=urllib.parse.urlsplit(endpoint)
    if parsed.hostname!='127.0.0.1' or parsed.port!=port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError('listener must match its exact pinned loopback audience')
    tls=parsed.scheme=='https'
    if tls!=(cert is not None and key is not None) or (not tls and (cert is not None or key is not None)) or parsed.scheme not in ['http','https']:
        raise ValueError('HTTPS requires both certificate and private key; no HTTP fallback')
    server=TLSServer(('127.0.0.1',port),handler,context(cert,key)) if tls else BoundedServer(('127.0.0.1',port),handler)
    server.authority,server.app=f'127.0.0.1:{port}',app
    return server
