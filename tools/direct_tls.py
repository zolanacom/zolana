"""Opt-in direct TLS tester ingress. No proxy, DNS lookup or trust-store change."""
import ipaddress
import re
import ssl
import urllib.parse

from wallet_release import decode, hex64, read, sha


def policy(path, expected, endpoint, port, cert, key):
    raw=read(path,8192,secret=True)
    if not hex64(expected) or sha(raw)!=expected:
        raise ValueError('reviewed direct TLS configuration digest differs')
    value=decode(raw)
    fields={'format','audience','bind_ip','port','certificate_sha256','key_sha256'}
    if (not isinstance(value,dict) or set(value)!=fields or value['format']!='zolana-direct-tls-v1' or
            value['audience']!=endpoint or type(port) is not int or type(value['port']) is not int or value['port']!=port or not 1<=port<=65535 or
            not isinstance(value['bind_ip'],str) or any(not hex64(value[k]) for k in ('certificate_sha256','key_sha256'))):
        raise ValueError('invalid direct TLS binding or audience')
    bind=ipaddress.IPv4Address(value['bind_ip'])
    if str(bind)!=value['bind_ip'] or bind.is_multicast or bind==ipaddress.IPv4Address('255.255.255.255'):
        raise ValueError('direct TLS requires an explicit unicast IPv4 bind or 0.0.0.0')
    url=urllib.parse.urlsplit(endpoint)
    host=url.hostname
    if (url.scheme!='https' or not host or url.username or url.password or url.path or url.query or url.fragment or
            (url.port if url.port is not None else 443)!=port or endpoint!='https://'+host+(':'+str(url.port) if url.port is not None else '')):
        raise ValueError('direct listener requires a canonical exact HTTPS audience')
    try:
        address=ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        if (len(host)>253 or any(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) is None for label in host.split('.')) or
                all(c in '0123456789.' for c in host)):
            raise ValueError('invalid direct TLS DNS audience')
        dns=True
    else:
        if str(address)!=host or address.is_unspecified or address.is_multicast or address==ipaddress.IPv4Address('255.255.255.255'):
            raise ValueError('invalid direct TLS IP audience')
        dns=False
    if cert is None or key is None or sha(read(cert,32768))!=value['certificate_sha256'] or sha(read(key,32768,secret=True))!=value['key_sha256']:
        raise ValueError('direct TLS certificate/key differ from review')
    return value,url.netloc,host,dns


def guarded(handler):
    class Direct(handler):
        def do_POST(self):
            # Fail before native admission/quota/RPC work. Duplicate framing or
            # routing headers are ambiguous even if the first value is correct.
            single=('Host','Content-Length','Content-Type','X-Testnet-Access')
            forbidden=('forwarded','x-forwarded-for','x-forwarded-host','x-forwarded-proto',
                       'x-real-ip','true-client-ip','cf-connecting-ip','proxy-authorization')
            if (self.headers.get_all('Host',[])!=[self.server.authority] or
                    self.headers.get('Origin') is not None or self.headers.get('Transfer-Encoding') is not None or
                    any(len(self.headers.get_all(name,[]))>1 for name in single) or
                    any(name.lower() in forbidden or name.lower().startswith('x-forwarded-') for name in self.headers)):
                self.close_connection = True  # Never parse a rejected body's bytes as another request.
                self.send_response(403)
                self.send_header('Content-Type','application/json')
                self.send_header('Cache-Control','no-store')
                self.send_header('X-Content-Type-Options','nosniff')
                data=b'{"error":"access_denied"}'
                self.send_header('Content-Length',str(len(data)))
                self.end_headers()
                try:self.wfile.write(data)
                except (BrokenPipeError,ConnectionResetError):pass
                return
            # Peer identity remains the actual TLS socket address. Never replace
            # it with a client-provided header, even on a loopback test bind.
            super().do_POST()
    return Direct


def listener(endpoint,port,handler,app,cert,key,config,expected):
    from service_tls import context,TLSServer
    value,authority,host,dns=policy(config,expected,endpoint,port,cert,key)
    ctx=context(cert,key)
    def sni(_connection,name,_context):
        if (dns and name!=host) or (not dns and name is not None):
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None
    ctx.set_servername_callback(sni)
    server=TLSServer((value['bind_ip'],port),guarded(handler),ctx)
    server.authority,server.app=authority,app
    return server
