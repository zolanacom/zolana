#!/usr/bin/env python3
"""Run the supply monitor against this repository's running disposable network.

The monitor watches both validators while the payment exercise deposits,
sends privately and withdraws, and must report green throughout. A loopback
relay then alters the validator's answers about the pool account and the
supply, and every alteration must turn the result red. Start a fresh network
with tools/localnet.py first; nothing here leaves loopback.
"""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import urllib.request

from localnet import PROJECT, lab, load, offset, port, rpc, wait_rpc
import supply_monitor as monitor

TOOL = Path(monitor.__file__)


def run_monitor(*args):
    result = subprocess.run([sys.executable, '-I', '-B', str(TOOL), *map(str, args)], capture_output=True, text=True, timeout=120)
    return result.returncode, result.stdout, result.stderr


class Relay(BaseHTTPRequestHandler):
    """Forwards reads to one validator and applies the current alteration."""

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        request = urllib.request.Request(self.server.upstream, body, {'Content-Type': 'application/json'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
            answer = json.load(response)
        calls = json.loads(body)
        plant = self.server.plant
        if plant:
            for call, item in zip(calls, answer) if isinstance(calls, list) else [(calls, answer)]:
                if call['method'] == plant[0] and (plant[0] != 'getAccountInfo' or call['params'][0] == monitor.POOL):
                    item['result']['value'] = plant[1](item['result']['value'])
        raw = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_):
        pass


def with_data(change):
    def plant(value):
        data = bytearray(base64.b64decode(value['data'][0]))
        change(value, data)
        return dict(value, data=[base64.b64encode(bytes(data)).decode(), 'base64'])
    return plant


def add_u64(data, position, delta):
    data[position:position + 8] = (int.from_bytes(data[position:position + 8], 'little') + delta).to_bytes(8, 'little')


def lower_together(value, data):
    add_u64(data, 48, -1)
    value['lamports'] -= 1


PLANTS = (
    ('one base unit missing from the pool account', 'getAccountInfo', lambda value: dict(value, lamports=value['lamports'] - 1), ['pool_backing']),
    ('backing overstated by one unit', 'getAccountInfo', with_data(lambda value, data: add_u64(data, 48, 1)), ['pool_backing', 'continuity']),
    ('rent floor understated by one unit', 'getAccountInfo', with_data(lambda value, data: add_u64(data, 40, -1)), ['pool_rent_floor', 'continuity']),
    ('backing and balance lowered together without a payment', 'getAccountInfo', with_data(lower_together), ['continuity']),
    ('note count rolled back by one payment', 'getAccountInfo', with_data(lambda value, data: add_u64(data, 56, -2)), ['continuity']),
    ('pool owned by the system program', 'getAccountInfo', lambda value: dict(value, owner='1' * 32), ['pool_account']),
    ('pool data truncated', 'getAccountInfo', with_data(lambda value, data: data.__delitem__(slice(-1, None))), ['pool_account']),
    ('pool account absent', 'getAccountInfo', lambda value: None, ['pool_account']),
    ('supply parts do not add up', 'getSupply', lambda value: dict(value, circulating=value['circulating'] + 1), ['supply_identity']),
    ('supply grown beyond any scheduled issuance', 'getSupply',
     lambda value: dict(value, total=value['total'] + 10**12, circulating=value['circulating'] + 10**12), ['supply_issuance']),
)


class Watch(threading.Thread):
    """Chained monitor runs against each validator until stopped."""

    def __init__(self, urls, genesis, work):
        super().__init__(daemon=True)
        self.urls, self.genesis, self.work = urls, genesis, work
        self.stopping = threading.Event()
        self.rows = []
        self.error = None

    def run(self):
        try:
            while not self.stopping.is_set():
                for index, url in enumerate(self.urls):
                    output = self.work / f'latest-{index}.json'
                    code, _, stderr = run_monitor('check', '--rpc', url, '--expect-genesis', self.genesis,
                                                  '--baseline', self.work / f'baseline-{index}.json', '--output', output)
                    value = json.loads(output.read_bytes())
                    pool, supply = value['pool'] or {}, value['supply'] or {}
                    self.rows.append({'validator': index, 'exit': code, 'status': value['status'], 'reason': value['reason'],
                                      'failed': value['failed'], 'slot': value['slot'], 'epoch': value['epoch'],
                                      'note_count': pool.get('note_count'), 'backing': pool.get('backing'),
                                      'surplus': pool.get('surplus'), 'total': supply.get('total'),
                                      'rewards_pending': supply.get('rewards_pending'), 'stderr': stderr.strip()})
                time.sleep(0.15)
        except Exception as error:  # surfaced by the caller
            self.error = error


def run(root, epochs=2):
    config = load(root)
    shift = offset(config)
    urls = [f'http://127.0.0.1:{port(index, shift)}' for index in (0, 1)]
    for index in (0, 1):
        wait_rpc(root, index, timeout=30)
    # The validator creates its system accounts in the first slots after
    # genesis, which adds to the supply once. Take the first baseline later.
    deadline = time.monotonic() + 120
    while min(rpc(port(index, shift), 'getSlot', [{'commitment': 'finalized'}]) for index in (0, 1)) < 16:
        if time.monotonic() > deadline:
            raise RuntimeError('the network has not finalized its first slots')
        time.sleep(1)
    work = root / 'supply-monitor'
    work.mkdir(mode=0o700)
    watch = Watch(urls, config['genesis_hash'], work)
    watch.start()
    time.sleep(3)
    lab(root, 'exercise')
    payment = json.loads((root / 'payment-result.json').read_text())
    # Keep watching until both validators have finalized the last payment and
    # the watch has also crossed the requested number of epoch boundaries.
    deadline = time.monotonic() + 600
    while True:
        rows = list(watch.rows)
        done = all(any(row['validator'] == index and row['slot'] is not None and row['slot'] > payment['slot'] for row in rows)
                   for index in (0, 1))
        first = [row['epoch'] for row in rows if row['epoch'] is not None][:1]
        if watch.error or (done and first and rows[-1]['epoch'] is not None and rows[-1]['epoch'] >= first[0] + epochs):
            break
        if time.monotonic() > deadline:
            raise RuntimeError('the watch did not reach the final payment and epoch in time')
        time.sleep(1)
    watch.stopping.set()
    watch.join(timeout=150)
    if watch.error:
        raise watch.error
    rows = watch.rows
    bad = [row for row in rows if row['exit'] != 0 or row['status'] != 'green']
    if bad:
        raise RuntimeError(f'monitor left green during valid payments: {bad[:3]}')
    states = {}
    for index in (0, 1):
        seen = []
        for row in rows:
            state = (row['note_count'], int(row['backing']))
            if row['validator'] == index and (not seen or seen[-1] != state):
                seen.append(state)
        states[index] = seen
        moves = [(after[0] - before[0], after[1] - before[1]) for before, after in zip(seen, seen[1:])]
        if (seen[0] != (0, 0) or any(notes <= 0 for notes, _ in moves) or not any(value > 0 for _, value in moves)
                or not any(value < 0 for _, value in moves) or not any(value == 0 for _, value in moves)):
            raise RuntimeError(f'validator {index}: the watch did not see a deposit, a private send and a withdrawal: {seen}')
        if any(row['surplus'] != '0' for row in rows if row['validator'] == index):
            raise RuntimeError('pool balance did not follow backing exactly')
    if states[0][-1] != states[1][-1]:
        raise RuntimeError('validators disagree about the final pool')
    result = {'status': 'running', 'genesis_hash': config['genesis_hash'], 'observations': len(rows),
              'green': len(rows), 'slots': [rows[0]['slot'], max(row['slot'] for row in rows)],
              'epochs': sorted({row['epoch'] for row in rows}),
              'observations_with_rewards_pending': sum(1 for row in rows if row['rewards_pending'] != '0'),
              'pool_states': {str(index): [list(state) for state in seen] for index, seen in states.items()},
              'supply_first_last': [rows[0]['total'], rows[-1]['total']], 'planted': [], 'signature': {}}

    relay = ThreadingHTTPServer(('127.0.0.1', 0), Relay)
    relay.upstream, relay.plant = urls[0], None
    relay.daemon_threads = True
    threading.Thread(target=relay.serve_forever, daemon=True).start()
    relayed = f'http://127.0.0.1:{relay.server_address[1]}'
    baseline = work / 'baseline-relay.json'
    accepted = (work / 'baseline-0.json').read_bytes()
    try:
        def relayed_check(name, *extra):
            baseline.write_bytes(accepted)
            output = work / f'{name}.json'
            code, _, _ = run_monitor('check', '--rpc', relayed, '--baseline', baseline, '--output', output, *extra)
            value = json.loads(output.read_bytes())
            return code, value

        code, value = relayed_check('relay-unaltered')
        if (code, value['status']) != (0, 'green'):
            raise RuntimeError(f'the unaltered relay is not green: {value}')
        for number, (name, method, plant, expected) in enumerate(PLANTS):
            relay.plant = (method, plant)
            code, value = relayed_check(f'planted-{number}')
            relay.plant = None
            if (code, value['status'], value['failed']) != (1, 'red', expected) or baseline.read_bytes() != accepted:
                raise RuntimeError(f'planted "{name}" was not reported as {expected}: exit {code}, {value["failed"]}')
            result['planted'].append({'plant': name, 'exit': code, 'status': value['status'], 'failed': value['failed']})
        code, value = relayed_check('relay-restored')
        if (code, value['status']) != (0, 'green'):
            raise RuntimeError('the relay did not return to green once the alteration was removed')

        # A disposable signing key, created here as an operator would supply one.
        key, public = work / 'disposable-signing.key', work / 'disposable-signing.pub'
        subprocess.run([monitor.OPENSSL, 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', str(key)],
                       check=True, capture_output=True, timeout=30)
        os.chmod(key, 0o600)
        subprocess.run([monitor.OPENSSL, 'pkey', '-in', str(key), '-pubout', '-out', str(public)], check=True, capture_output=True, timeout=30)
        pin = monitor.sha(monitor.public_der(public.read_bytes()))
        for name, plant, expected in (('signed-green', None, 0), ('signed-red', PLANTS[0][1:3], 1)):
            relay.plant = plant
            code, _ = relayed_check(name, '--signing-key', key)
            relay.plant = None
            verified, report, _ = run_monitor('verify', '--result', work / f'{name}.json', '--public-key', public, '--key-sha256', pin,
                                              '--expect-genesis', config['genesis_hash'], '--max-age', 600)
            if (code, verified) != (expected, expected):
                raise RuntimeError(f'{name}: check exit {code}, verify exit {verified}')
            result['signature'][name] = {'check_exit': code, 'verify_exit': verified, 'verify': json.loads(report)}
        edited = work / 'signed-edited.json'
        edited.write_bytes((work / 'signed-red.json').read_bytes().replace(b'"status": "red"', b'"status": "green"'))
        shutil.copyfile(work / 'signed-red.json.sig', work / 'signed-edited.json.sig')
        verified, _, _ = run_monitor('verify', '--result', edited, '--public-key', public, '--key-sha256', pin)
        if verified != monitor.EXIT_SIGNATURE:
            raise RuntimeError('an edited signed result was accepted')
        result['signature']['edited_result_verify_exit'] = verified
        key.unlink()
    finally:
        relay.shutdown()
        relay.server_close()
    result['status'] = 'passed'
    (work / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='a started network whose pool has no payments yet')
    parser.add_argument('--epochs', type=int, default=2, help='epoch boundaries the watch must cross')
    args = parser.parse_args()
    root = args.root.resolve()
    if not root.is_relative_to(PROJECT / '.data'):
        raise RuntimeError('local networks must stay inside this project\'s ignored .data directory')
    run(root, args.epochs)


if __name__ == '__main__':
    main()
