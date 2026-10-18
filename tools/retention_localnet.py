#!/usr/bin/env python3
"""Bounded real-validator acceptance for automatic history retention and mirrors."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import signal
import time

from archive_localnet import ArchiveExperiment
from fault_localnet import WALLET, atomic_json
from history_retention import Retention, manifest
from localnet import PROJECT, rpc, stop


class RetentionExperiment(ArchiveExperiment):
    def __init__(self, root):
        super().__init__(root)
        self.env['RAYON_NUM_THREADS'] = '2'

    worker = None
    exports = 0

    def event(self, kind, **fields):
        super().event(kind, **fields)
        if kind == 'device_local_ui_uses_snapshot_peer_history':
            self.worker.close()
            self.event('collector_stopped_before_copy_corruption_tests')

    def collector(self, url='http://127.0.0.1:18899'):
        return Retention(self.root, WALLET, url, lambda method, params: rpc(18899, method, params),
                         primary=self.root / 'retention-source', mirror=self.root / 'recovery-history', interval=5)

    def export(self):
        self.exports += 1
        if self.worker is None:
            self.worker = self.collector()
            self.worker.start()
        if self.exports == 2:
            self.interrupt_collector()
        target = rpc(18899, 'getSlot', [{'commitment': 'finalized'}])
        deadline = time.monotonic() + 120
        while True:
            with self.worker.lock: info = dict(self.worker.info)
            if not self.worker.healthy(): raise RuntimeError('automatic retention failed: ' + str(info))
            if info['phase'] == 'ready' and info['finalized_slot'] >= target: break
            if time.monotonic() >= deadline: raise RuntimeError('automatic collector did not advance')
            time.sleep(.2)
        _, files, tip = manifest(self.worker.mirror, self.worker.network)
        if tip < target or not files: raise RuntimeError('missing committed automatic mirror')
        self.event('automatic_history_mirrored', result=info)
        return info

    def interrupt_collector(self):
        self.worker.close()
        def committed(path):
            raw, files, _ = manifest(path, self.worker.network)
            return raw, {name: hashlib.sha256((path / name).read_bytes()).hexdigest() for name, _ in files}
        original = [committed(path) for path in [self.worker.primary, self.worker.mirror]]
        reached, release = threading.Event(), threading.Event()
        methods = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                length = int(self.headers.get('Content-Length', '0'))
                if self.path != '/' or not 1 <= length <= 32768:
                    self.send_error(400); return
                query = json.loads(self.rfile.read(length)); method = query.get('method')
                methods.append(method)
                if method not in {'getGenesisHash', 'getSlot', 'getBlocks', 'getBlock', 'getAccountInfo', 'getFirstAvailableBlock'}:
                    self.send_error(403); return
                value = rpc(18899, method, query.get('params', []))
                if method == 'getBlock': reached.set(); release.wait(15)
                data = json.dumps({'jsonrpc': '2.0', 'id': query['id'], 'result': value}).encode()
                self.send_response(200); self.send_header('Content-Length', str(len(data))); self.end_headers()
                try: self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        serving = threading.Thread(target=server.serve_forever, daemon=True); serving.start()
        killed = self.collector('http://127.0.0.1:%d' % server.server_port)
        errors = []
        def collect():
            try: killed.collect()
            except Exception as error: errors.append(type(error).__name__)
        running = threading.Thread(target=collect, daemon=True); running.start()
        try:
            if not reached.wait(30): raise RuntimeError('native collector did not reach real finalized block gate')
            with killed.lock: child = killed.child
            if child is None or child.poll() is not None: raise RuntimeError('not an owned live archive process')
            child.kill(); release.set(); running.join(20)
            if running.is_alive() or not errors or child.returncode != -9 or killed.healthy():
                raise RuntimeError('actual archive SIGKILL did not fail closed')
            for path, expected in zip([killed.primary, killed.mirror], original):
                if committed(path) != expected: raise RuntimeError('SIGKILL replaced committed recovery history')
            self.event('collector_sigkill_preserves_both_committed_prefixes', exit_code=child.returncode,
                       methods=sorted(set(methods)), phase=killed.info['phase'])
        finally:
            release.set(); killed.close(); running.join(15)
            server.shutdown(); server.server_close(); serving.join(5)
        self.worker = self.collector()
        self.worker.start()
        self.event('collector_restarts_without_resetting_history')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args(); root = args.root.resolve()
    if root.parent != PROJECT / '.data' or root.exists(): parser.error('use a new direct child of .data')
    if len(bytes(root / 'ledger-recovered-1/admin.rpc')) >= 104: parser.error('use a shorter root for the snapshot peer Unix socket')
    trial = RetentionExperiment(root)
    def timeout(*_): raise TimeoutError('ten-minute validator acceptance limit')
    signal.signal(signal.SIGALRM, timeout); signal.alarm(600)
    try:
        trial.run()
    except Exception as error:
        trial.result.update(status='failed', error=str(error)); raise
    finally:
        signal.alarm(0)
        errors = []
        try:
            if trial.worker is not None: trial.worker.close()
        except Exception as error: errors.append(type(error).__name__)
        for index in [1, 0]:
            if trial.children[index] is not None and trial.children[index].poll() is None:
                try: stop(root, index)
                except Exception as error: errors.append(type(error).__name__)
        if errors: trial.result.update(status='failed', cleanup_errors=errors)
        if root.exists(): atomic_json(root / 'archive-result.json', trial.result)
        if errors: raise RuntimeError('owned acceptance cleanup failed: ' + str(errors))
