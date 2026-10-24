"""Inert lease/expiry limits; no hosts, wallets or TLS bypass."""
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
import ssl
import threading
import time
import unittest
from unittest.mock import patch
import browser_gateway_transport as T

HEADERS={'Content-Type':'application/json','Accept-Encoding':'gzip'}
URL='https://fixture.invalid/'

class Response:
    def __init__(self, close=False):
        self.headers=Message();self.headers['Content-Length']='2'
        if close:self.headers['Connection']='close'
        self.status=200;self.length=2;self.will_close=close;self.closed=False
    def read(self,n):
        raw=b'{}'[:min(n,self.length)];self.length-=len(raw)
        if not self.length:self.closed=True
        return raw
    def isclosed(self):return self.closed
    def close(self):self.closed=True

class Connection:
    instances=[];force_close=False
    def __init__(self,*args,**kwargs):
        self.sock=self;self.attempts=0;self.closed=False;self.instances.append(self)
    def settimeout(self,value):self.timeout=value
    def request(self,*args,**kwargs):self.attempts+=1
    def getresponse(self):return Response(self.force_close)
    def close(self):self.closed=True;self.sock=None

class PoolTests(unittest.TestCase):
    def setUp(self):
        Connection.instances=[];Connection.force_close=False
        p=patch.object(T.http.client,'HTTPSConnection',Connection);p.start();self.addCleanup(p.stop)
        self.transport=T.UpstreamTransport([URL]);self.addCleanup(self.transport.close)
    def read(self):
        with self.transport.open(URL,b'{}',HEADERS) as r:self.assertEqual(r.read(10),b'{}')
    def test_two_leases_bound_concurrency_and_wait_timeout_never_sends(self):
        lock=threading.Lock();entered=threading.Event();release=threading.Event();count=0
        def hold():
            nonlocal count
            with self.transport.open(URL,b'{}',HEADERS) as r:
                self.assertEqual(r.read(10),b'{}')
                with lock:
                    count+=1
                    if count==2:entered.set()
                self.assertTrue(release.wait(2))
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending=[pool.submit(hold) for _ in range(2)]
            try:
                self.assertTrue(entered.wait(2))
                with self.assertRaisesRegex(ValueError,'capacity deadline'):
                    with self.transport.open(URL,b'{}',HEADERS,timeout=.02):pass
                self.assertEqual(len(Connection.instances),2)
                self.assertEqual(sum(c.attempts for c in Connection.instances),2)
            finally:release.set()
            for future in pending:future.result(timeout=2)
        self.read();self.assertEqual(len(Connection.instances),2)
    def test_idle_and_lifetime_checked_before_reuse(self):
        for field,age in (('last_used',4),('created',21)):
            with self.subTest(field=field):
                self.read();origin=next(iter(self.transport._origins));entry=self.transport._idle[origin][-1]
                previous=entry.connection;setattr(entry,field,time.monotonic()-age)
                self.read();self.assertTrue(previous.closed)
                self.assertIsNot(self.transport._idle[origin][-1].connection,previous)
    def test_retired_after_48_requests_or_advertised_close(self):
        for _ in range(48):self.read()
        self.assertEqual(len(Connection.instances),1);self.assertEqual(Connection.instances[0].attempts,48)
        self.assertTrue(Connection.instances[0].closed)
        self.read();self.assertEqual(len(Connection.instances),2)
        Connection.force_close=True;previous=Connection.instances[-1];self.read()
        self.assertTrue(previous.closed);self.read();self.assertEqual(len(Connection.instances),3)
    def test_application_failure_and_shutdown_retire_and_release(self):
        with self.assertRaisesRegex(ValueError,'fixture validation'):
            with self.transport.open(URL,b'{}',HEADERS) as r:
                self.assertEqual(r.read(10),b'{}');raise ValueError('fixture validation')
        self.assertTrue(Connection.instances[0].closed)
        self.read();self.assertEqual(len(Connection.instances),2)
        self.transport.close();self.assertTrue(Connection.instances[1].closed)
        with self.assertRaisesRegex(ValueError,'closed'):self.read()
    def test_unpinned_origins_http_and_disabled_certificate_checks_refused(self):
        for url in ('https://other.invalid/','https://fixture.invalid/?redirect=1','https://fixture.invalid/other','http://fixture.invalid/'):
            with self.subTest(url=url),self.assertRaises(ValueError):
                with self.transport.open(url,b'{}',HEADERS):pass
        self.assertEqual(Connection.instances,[])
        context=ssl.create_default_context();context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
        with self.assertRaises(ValueError):T.UpstreamTransport([URL],context=context)

if __name__=='__main__':unittest.main()
