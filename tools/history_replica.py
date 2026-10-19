#!/usr/bin/env python3
"""Bounded TLS replication of public ciphertext history; no wallet or raw RPC access."""
import argparse
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from history_retention import (atomic, capture, directory, manifest, parse_manifest,
                               read, sync_directory, usage, MAX_MANIFEST, MAX_SEGMENT,
                               MIN_FREE, STORE_BUDGET)
from service_tls import TLSServer, context

KEY_FORMAT = 'native-history-replica-key-v1'
SEGMENT = re.compile(r'segment-[0-9]{8}-[0-9a-f]{64}\.json')
DIGEST = re.compile(r'[0-9a-f]{64}')


def identity(path):
    value = json.loads(read(Path(path), 32768))
    result = {key: value[key] for key in ('network', 'genesis_hash')}
    from history_retention import block_hash
    if (not isinstance(result['network'], list) or len(result['network']) != 32
            or not all(type(n) is int and 0 <= n <= 255 for n in result['network'])
            or not block_hash(result['genesis_hash'])):
        raise ValueError('invalid pinned replica network')
    return result


def credential(path, network):
    value = json.loads(read(Path(path), 2048))
    if (not isinstance(value, dict) or set(value) != {'format', 'network', 'token'}
            or value['format'] != KEY_FORMAT or value['network'] != network
            or not isinstance(value['token'], str) or DIGEST.fullmatch(value['token']) is None):
        raise ValueError('invalid history-only replica credential')
    return value['token']


def initialize(root, network, credential_out):
    root = Path(root).absolute()
    if os.path.lexists(root) or os.path.lexists(credential_out):
        raise ValueError('replica initialization requires new paths; never reset an existing replica')
    directory(root.parent)
    directory(Path(credential_out).absolute().parent)
    root.mkdir(mode=0o700)
    directory(root)
    raw = json.dumps({'format': KEY_FORMAT, 'network': network, 'token': secrets.token_hex(32)}).encode()
    # The marker survives interrupted setup; never adopt/reinitialize a partial root.
    atomic(root / 'setup.started', b'native-history-replica-setup-v1')
    for path, data in [(root / 'network.json', json.dumps(network).encode()), (root / 'replica.key', raw),
                       (Path(credential_out), raw)]:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        sync_directory(path.parent)
    directory(root / 'committed', create=True); directory(root / 'incoming', create=True)
    atomic(root / 'setup.complete', b'native-history-replica-setup-v1')
    return {'initialized': True, 'contains_spending_or_rpc_keys': False}


def immutable(path, data):
    if os.path.lexists(path):
        if read(path, MAX_SEGMENT) != data:
            raise ValueError('immutable replica payload differs; preserve it')
        return
    temporary = path.parent / ('.upload-' + secrets.token_hex(12) + '.tmp')
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        os.link(temporary, path)
        sync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


class Receiver:
    def __init__(self, root):
        self.root = directory(root)
        if read(self.root / 'setup.complete', 64) != b'native-history-replica-setup-v1':
            raise ValueError('replica setup incomplete; preserve original root')
        self.network = identity(self.root / 'network.json')
        self.token = credential(self.root / 'replica.key', self.network)
        self.committed = directory(self.root / 'committed')
        self.incoming = directory(self.root / 'incoming')
        self.lock = threading.Lock()
        self.fd = os.open(self.root / '.receiver.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size:
                raise ValueError('invalid replica process lock')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd); raise

    def close(self):
        os.close(self.fd)

    def resources(self, extra=0):
        if shutil.disk_usage(self.root).free < MIN_FREE + MAX_SEGMENT + extra:
            raise ValueError('replica disk headroom exhausted')
        for path in [self.committed, self.incoming]:
            if usage(path) + extra > STORE_BUDGET:
                raise ValueError('replica storage capacity exhausted')

    def candidate(self, checkpoint):
        raw, files, tip = manifest(self.incoming, self.network)
        if hashlib.sha256(raw).hexdigest() != checkpoint:
            raise ValueError('replica candidate changed; retry the captured manifest')
        return raw, files, tip

    def prepare(self, raw):
        _, files, tip = parse_manifest(raw, self.network)
        self.resources(len(raw))
        current = []
        if (self.committed / 'manifest.json').exists():
            _, current, previous_tip = manifest(self.committed, self.network)
            if tip < previous_tip or files[:len(current)] != current:
                raise ValueError('replica rollback or immutable prefix change')
        # Reuse committed immutable payloads, not keys or arbitrary source files.
        for name, _ in current:
            if not os.path.lexists(self.incoming / name):
                read(self.committed / name, MAX_SEGMENT)
                os.link(self.committed / name, self.incoming / name)
        atomic(self.incoming / 'manifest.json', raw)
        return {'checkpoint': hashlib.sha256(raw).hexdigest(), 'committed_segments': len(current)}

    def upload(self, checkpoint, name, data):
        _, files, _ = self.candidate(checkpoint)
        allowed = dict(files)
        if name not in allowed or not 0 < len(data) <= MAX_SEGMENT:
            raise ValueError('payload outside captured manifest')
        if hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest() != allowed[name]['digest']:
            raise ValueError('replica payload checksum mismatch')
        self.resources(0 if os.path.lexists(self.incoming / name) else len(data))
        immutable(self.incoming / name, data)
        return {'stored': True}

    def commit(self, checkpoint):
        self.candidate(checkpoint); self.resources()
        result = capture(self.incoming, self.committed, self.network)
        if result['manifest_sha256'] != checkpoint:
            raise ValueError('replica commit changed candidate')
        # capture synced payloads and the directory before publishing the manifest.
        return dict(result, format='native-history-replica-receipt-v1', durable=True)

    def get(self, name):
        raw, files, _ = manifest(self.committed, self.network)
        if name == 'manifest.json': return raw
        if name not in dict(files): raise ValueError('not committed public history')
        data = read(self.committed / name, MAX_SEGMENT)
        descriptor = dict(files)[name]
        if hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest() != descriptor['digest']:
            raise ValueError('committed replica checksum mismatch')
        return data


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def log_message(self, *_): pass  # Never log credentials, payloads or client paths.

    def reply(self, code, data):
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data))); self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff'); self.end_headers()
        try: self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError): pass

    def handle_request(self):
        try:
            if (self.headers.get('Host') != self.server.authority or self.headers.get('Origin') is not None
                    or self.headers.get('Transfer-Encoding') is not None
                    or not hmac.compare_digest(self.headers.get('X-History-Replica', ''), self.server.app.token)):
                raise ValueError('denied')
            with self.server.app.lock:
                parts = self.path.split('/')
                if self.command == 'GET' and len(parts) == 3 and parts[:2] == ['', 'v1']:
                    if parts[2] != 'manifest.json' and SEGMENT.fullmatch(parts[2]) is None:
                        raise ValueError('denied')
                    return self.reply(200, self.server.app.get(parts[2]))
                maximum = MAX_MANIFEST if self.path == '/v1/prepare' else MAX_SEGMENT
                if self.command not in ['POST', 'PUT'] or self.headers.get('Content-Type') != 'application/json':
                    raise ValueError('denied')
                lengths = self.headers.get_all('Content-Length', [])
                if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= maximum:
                    raise ValueError('body bound')
                self.server.app.resources(int(lengths[0]))
                deadline = time.monotonic() + 15
                remaining = int(lengths[0]); chunks = []
                while remaining:
                    if time.monotonic() > deadline: raise ValueError('body deadline')
                    data = self.rfile.read(min(65536, remaining))
                    if not data: raise ValueError('short body')
                    chunks.append(data); remaining -= len(data)
                raw = b''.join(chunks)
                if self.command == 'POST' and self.path == '/v1/prepare':
                    result = self.server.app.prepare(raw)
                elif len(parts) == 4 and parts[:2] == ['', 'v1'] and DIGEST.fullmatch(parts[2]):
                    if self.command == 'POST' and parts[3] == 'commit' and raw == b'{}':
                        result = self.server.app.commit(parts[2])
                    elif self.command == 'PUT' and SEGMENT.fullmatch(parts[3]):
                        result = self.server.app.upload(parts[2], parts[3], raw)
                    else: raise ValueError('denied')
                else: raise ValueError('denied')
                return self.reply(200, json.dumps(result).encode())
        except (ValueError, OSError, KeyError, TypeError):
            self.reply(403, b'{"error":"replica_request_denied"}')

    do_GET = handle_request
    do_POST = handle_request
    do_PUT = handle_request


def server(root, port, cert, key):
    app = Receiver(root)
    try:
        result = TLSServer(('127.0.0.1', port), Handler, context(cert, key))
    except BaseException:
        app.close(); raise
    result.app = app; result.authority = '127.0.0.1:' + str(result.server_port)
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, request, response, code, message, headers):
        response.close()
        raise ValueError('replica redirects forbidden')
    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class Client:
    def __init__(self, url, network, credential_file, ca_file, ca_sha256=None, stop=None):
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or parsed.port is None or parsed.path
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise ValueError('replication requires a fixed HTTPS origin with explicit port')
        ca = read(Path(ca_file), 32768)
        if ca_sha256 is not None and hashlib.sha256(ca).hexdigest() != ca_sha256:
            raise ValueError('replica CA pin changed')
        ctx = ssl.create_default_context(cadata=ca.decode('ascii'))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=ctx))
        self.url = url; self.token = credential(credential_file, network)
        self.deadline = time.monotonic() + 45; self.stop = stop

    def request(self, method, name, data=None, maximum=MAX_MANIFEST):
        if (self.stop is not None and self.stop.is_set()) or time.monotonic() >= self.deadline:
            raise ValueError('replica transfer interrupted')
        request = urllib.request.Request(self.url + '/v1/' + name, data=data, method=method,
            headers={'X-History-Replica': self.token, 'Content-Type': 'application/json'})
        try:
            response = self.opener.open(request, timeout=3)
        except urllib.error.HTTPError as error:
            error.close()
            raise ValueError('replica request rejected (HTTP %s)' % error.code) from None
        with response:
            if response.status != 200 or response.headers.get('Transfer-Encoding') is not None:
                raise ValueError('unexpected replica response')
            length = response.headers.get('Content-Length', '')
            if not length.isdigit() or not 0 < int(length) <= maximum:
                raise ValueError('replica response exceeds bound')
            remaining = int(length); chunks = []
            while remaining:
                if (self.stop is not None and self.stop.is_set()) or time.monotonic() >= self.deadline:
                    raise ValueError('replica transfer interrupted')
                raw = response.read(min(65536, remaining))
                if not raw: raise ValueError('truncated replica response')
                remaining -= len(raw); chunks.append(raw)
        return b''.join(chunks)


def replicate(source, network, url, credential_file, ca_file, ca_sha256=None, stop=None):
    source = directory(source); raw, files, tip = manifest(source, network); usage(source)
    client = Client(url, network, credential_file, ca_file, ca_sha256, stop)
    prepared = json.loads(client.request('POST', 'prepare', raw, 4096))
    checkpoint = hashlib.sha256(raw).hexdigest()
    if (set(prepared) != {'checkpoint', 'committed_segments'} or prepared['checkpoint'] != checkpoint
            or type(prepared['committed_segments']) is not int or not 0 <= prepared['committed_segments'] <= len(files)):
        raise ValueError('invalid replica preparation receipt')
    sent = 0
    for name, descriptor in files[prepared['committed_segments']:]:
        data = read(source / name, MAX_SEGMENT)
        if hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest() != descriptor['digest']:
            raise ValueError('replica source checksum mismatch')
        if json.loads(client.request('PUT', checkpoint + '/' + name, data, 4096)) != {'stored': True}:
            raise ValueError('invalid replica upload receipt')
        sent += len(data)
    result = json.loads(client.request('POST', checkpoint + '/commit', b'{}', 4096))
    if (not isinstance(result, dict) or result.get('format') != 'native-history-replica-receipt-v1'
            or result.get('durable') is not True or result.get('manifest_sha256') != checkpoint
            or result.get('finalized_slot') != tip or result.get('segments') != len(files)):
        raise ValueError('unverified replica commit receipt')
    return dict(result, uploaded_bytes=sent)


def fetch(destination, network, url, credential_file, ca_file, ca_sha256=None):
    """Recover a captured committed prefix without touching validator RPC or keys."""
    destination = directory(destination, create=True)
    incoming = directory(destination.with_name(destination.name + '-download'), create=True)
    client = Client(url, network, credential_file, ca_file, ca_sha256)
    raw = client.request('GET', 'manifest.json')
    _, files, _ = parse_manifest(raw, network)
    # capture rejects rollback/prefix changes even if a source returns old history.
    for name, descriptor in files:
        if os.path.lexists(destination / name):
            data = read(destination / name, MAX_SEGMENT)
        else:
            data = client.request('GET', name, maximum=MAX_SEGMENT)
        if hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest() != descriptor['digest']:
            raise ValueError('replica download checksum mismatch')
        if usage(incoming) + len(data) > STORE_BUDGET:
            raise ValueError('replica download capacity exceeded')
        immutable(incoming / name, data)
    atomic(incoming / 'manifest.json', raw)
    return capture(incoming, destination, network)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    init = sub.add_parser('init'); init.add_argument('--root', type=Path, required=True)
    init.add_argument('--network', type=Path, required=True); init.add_argument('--credential-out', type=Path, required=True)
    serve = sub.add_parser('serve'); serve.add_argument('--root', type=Path, required=True)
    serve.add_argument('--port', type=int, required=True); serve.add_argument('--cert', type=Path, required=True)
    serve.add_argument('--key', type=Path, required=True); serve.add_argument('--duration', type=int, required=True)
    for name in ['push', 'fetch']:
        command = sub.add_parser(name); command.add_argument('--network', type=Path, required=True)
        command.add_argument('--source' if name == 'push' else '--destination', type=Path, required=True)
        command.add_argument('--url', required=True); command.add_argument('--credential-file', type=Path, required=True)
        command.add_argument('--ca-file', type=Path, required=True)
    args = parser.parse_args()
    if args.command == 'init': result = initialize(args.root, identity(args.network), args.credential_out)
    elif args.command == 'serve':
        if not 1 <= args.duration <= 600 or not 1 <= args.port <= 65535:
            raise ValueError('receiver needs a finite 1–600 second local test duration')
        listener = server(args.root, args.port, args.cert, args.key)
        stopping = threading.Event()
        def end(*_): stopping.set()
        signal.signal(signal.SIGALRM, end); signal.alarm(args.duration)
        signal.signal(signal.SIGTERM, end); signal.signal(signal.SIGINT, end)
        # Privilege-dropping launchers may inherit a blocked termination mask.
        # Install handlers before unblocking; never raise OSError subclasses
        # through socketserver's accept path, which can swallow them.
        if hasattr(signal, 'pthread_sigmask'):
            signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT, signal.SIGALRM})
        listener.timeout = .2
        print(json.dumps({'listening': listener.authority, 'tls': True}), flush=True)
        try:
            while not stopping.is_set(): listener.handle_request()
        finally:
            signal.alarm(0); listener.server_close(); listener.app.close()
        return
    else:
        options = dict(network=identity(args.network), url=args.url, credential_file=args.credential_file, ca_file=args.ca_file)
        result = replicate(args.source, **options) if args.command == 'push' else fetch(args.destination, **options)
    print(json.dumps(result))


if __name__ == '__main__': main()
