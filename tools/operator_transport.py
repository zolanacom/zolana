"""Private raw RPC transport. Structured credentials never select a TCP fallback."""
import http.client
import json
import os
from pathlib import Path
import re
import socket
import stat
import urllib.parse
import urllib.request
from service_tls import private_bytes


def private_parent(path):
    path=Path(path)
    parent=path.parent
    if not path.is_absolute() or len(os.fsencode(path))>=104 or parent.resolve()!=parent:
        raise ValueError('invalid private RPC socket path')
    for ancestor in [parent,*parent.parents]:
        meta=ancestor.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0,os.geteuid()) or (meta.st_mode&0o022 and not meta.st_mode&stat.S_ISVTX):
            raise ValueError('unsafe writable ancestor of private RPC socket')
    meta=parent.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.geteuid() or meta.st_mode&0o077:
        raise ValueError('private RPC socket directory must be owner-only')


def credential(path):
    raw=private_bytes(path,4096)
    sockets=None
    if len(raw)==64:
        token=raw.decode('ascii')
    else:
        data=json.loads(raw)
        if not isinstance(data,dict) or set(data)!={'format','token','sockets'} or data['format']!='native-rpc-unix-v1':
            raise ValueError('invalid private RPC credential')
        token=data['token'];sockets=data['sockets']
        if not isinstance(sockets,dict) or not 1<=len(sockets)<=8:
            raise ValueError('invalid private RPC routes')
        for port,path in sockets.items():
            if not re.fullmatch(r'[1-9][0-9]{0,4}',port) or int(port)>65535 or not isinstance(path,str):
                raise ValueError('invalid private RPC route')
            private_parent(path)
    if not isinstance(token,str) or re.fullmatch('[0-9a-f]{64}',token) is None:
        raise ValueError('invalid raw RPC credential')
    return token,sockets


def check_socket(path):
    private_parent(path)
    meta=Path(path).lstat()
    if not stat.S_ISSOCK(meta.st_mode) or meta.st_uid!=os.geteuid() or meta.st_mode&0o077:
        raise ValueError('invalid private RPC socket')


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self,path,timeout):
        super().__init__('127.0.0.1',timeout=timeout);self.path=path
    def connect(self):
        check_socket(self.path)
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            self.sock.settimeout(self.timeout);self.sock.connect(self.path)
        except BaseException:
            self.sock.close();self.sock=None;raise


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*_):return None


class Operator:
    def __init__(self,url,key):
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!='http' or parsed.hostname!='127.0.0.1' or not parsed.port or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError('operator RPC requires a pinned loopback endpoint')
        token,sockets=credential(key)
        self.url=url;self.headers={'Content-Type':'application/json','X-Native-Operator':token};self.path=None
        if sockets is not None:
            if str(parsed.port) not in sockets:raise ValueError('private RPC route missing; TCP fallback forbidden')
            self.path=sockets[str(parsed.port)]
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def forward(self,raw,timeout=15):
        if self.path is not None:
            conn=UnixHTTP(self.path,timeout)
            try:
                conn.request('POST','/',raw,self.headers)
                response=conn.getresponse()
                if response.status!=200:raise ValueError('private RPC request denied')
                body=response.read(16*1024*1024+1)
            finally:conn.close()
        else:
            with self.opener.open(urllib.request.Request(self.url,raw,self.headers),timeout=timeout) as response:
                body=response.read(16*1024*1024+1)
        if len(body)>16*1024*1024:raise ValueError('RPC response exceeds gateway limit')
        return body
