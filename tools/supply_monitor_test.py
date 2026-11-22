"""Supply monitor tests against a loopback stand-in for the validator's RPC.

The pool account bytes come from tools/fixtures/pool_backing_vectors_v1.json,
which protocol/payments/tests/pool_backing_vectors.rs writes with the real
encoder and pins. The supply and reward movements copy what a local
two-validator network reports: a fee burn in every slot, rewards computed at
an epoch boundary and credited one block later, and account contents that
can be one root newer than the slot a node reports. No network is contacted.
"""
import base64
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import explorer_model
import supply_monitor as monitor

VECTORS = json.loads((Path(__file__).parent / 'fixtures/pool_backing_vectors_v1.json').read_text())
OPENSSL = monitor.OPENSSL if os.access(monitor.OPENSSL, os.X_OK) else None


def step_data(sequence, step):
    data = bytearray(sequence['data_bytes'])
    for offset, part in step['segments']:
        data[offset:offset + len(part) // 2] = bytes.fromhex(part)
    return bytes(data)


def sequence_named(tag):
    return next(item for item in VECTORS['sequences'] if item['pool_format'] == tag)


class Fault(Exception):
    pass


class Chain:
    """The read methods the monitor uses, over state the test controls."""

    def __init__(self, sequence):
        self.sequence = sequence
        self.lock = threading.Lock()
        self.genesis = monitor.b58encode(hashlib.sha256(b'supply monitor test network').digest())
        self.slot = 1000
        self.span = 128
        self.total = 500_000_000_000_000_000
        self.idle = 125_000_000_000_000_000
        self.rate = 0.08
        self.burn = 10_000
        self.rewards = (0, 0, 0, 0, False)
        self.lag = 0
        self.history = {}
        self.rewards_account = True
        self.donated = 0
        self.batch = True
        self.skew = 0
        self.fault = None
        self.plant_pool = None
        self.plant_supply = None
        self.apply(sequence['steps'][0])

    def apply(self, step):
        """What finalization does: new account data, and the public value
        moves into or out of the pool account in the same transaction."""
        self.data = step_data(self.sequence, step)
        self.lamports = self.sequence['rent_floor'] + step['backing'] + self.donated

    def issue(self):
        return int(self.total * self.rate * self.span / monitor.SLOTS_PER_YEAR)

    def advance(self, slots=1):
        for _ in range(slots):
            self.slot += 1
            self.total -= self.burn
            first, blocks, computed, credited, active = self.rewards
            if self.slot % self.span == 0:
                # Every slot has a block here, so heights equal slots.
                self.rewards = (self.slot + 1, 1, self.issue(), 0, True)
            elif active:
                # The last unit is never paid out, as on the local network.
                self.rewards = (first, blocks, computed, computed - 1, False)
                self.total += computed - 1
            self.history[self.slot] = self.total

    def bank_slot(self):
        """The slot the node reports. With a lag its supply and epoch are that
        old while its accounts are served from the newer root."""
        return self.slot - self.lag

    def bank_total(self):
        return self.history[self.bank_slot()] if self.lag else self.total

    def epoch(self):
        return self.bank_slot() // self.span

    def at(self, value):
        return {'context': {'apiVersion': '3.0.14', 'slot': self.bank_slot()}, 'value': value}

    @staticmethod
    def account(lamports, owner, data):
        return {'data': [base64.b64encode(data).decode(), 'base64'], 'executable': False, 'lamports': lamports,
                'owner': owner, 'rentEpoch': monitor.U64, 'space': len(data)}

    def handle(self, method, params):
        if self.fault == method:
            raise Fault()
        if method == 'getAccountInfo':
            address, config = params
            assert config['encoding'] == 'base64'
            if address == monitor.POOL:
                value = self.account(self.lamports, monitor.PROGRAM, self.data)
                return self.at(self.plant_pool(value) if self.plant_pool else value)
            if address == monitor.EPOCH_REWARDS and self.rewards_account:
                first, blocks, computed, credited, active = self.rewards
                data = struct.pack('<QQ32s16sQQB', first, blocks, bytes(32), bytes(16), computed, credited, active)
                return self.at(self.account(1_454_640, 'Sysvar1111111111111111111111111111111111111', data))
            return self.at(None)
        if method == 'getSupply':
            if self.skew:
                self.skew -= 1
                self.advance()
            total = self.bank_total()
            value = {'total': total, 'circulating': total - self.idle, 'nonCirculating': self.idle, 'nonCirculatingAccounts': []}
            return self.at(self.plant_supply(value) if self.plant_supply else value)
        if method == 'getEpochInfo':
            slot = self.bank_slot()
            return {'absoluteSlot': slot, 'blockHeight': slot, 'epoch': self.epoch(),
                    'slotIndex': slot % self.span, 'slotsInEpoch': self.span, 'transactionCount': 7 * slot}
        if method == 'getInflationRate':
            return {'epoch': self.epoch(), 'foundation': 0.0, 'total': self.rate, 'validator': self.rate}
        if method == 'getGenesisHash':
            return self.genesis
        if method == 'getMinimumBalanceForRentExemption':
            return (VECTORS['rent_overhead_bytes'] + params[0]) * VECTORS['rent_per_byte']
        if method == 'getBlockTime':
            return 1_000_000 + params[0] // 2
        raise Fault()

    def answer(self, call):
        try:
            return {'jsonrpc': '2.0', 'id': call['id'], 'result': self.handle(call['method'], call.get('params', []))}
        except Fault:
            return {'jsonrpc': '2.0', 'id': call['id'], 'error': {'code': -32005, 'message': 'refused'}}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        chain = self.server.chain
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        with chain.lock:
            if not isinstance(body, list):
                answer = chain.answer(body)
            elif chain.batch:
                answer = [chain.answer(call) for call in body]
            else:
                answer = {'jsonrpc': '2.0', 'id': None, 'error': {'code': -32600, 'message': 'no batches'}}
        raw = json.dumps(answer).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_):
        pass


class Endpoint(unittest.TestCase):
    """A fresh chain and working directory per test, one server per class."""
    FORMAT = 'NPOOL003'

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server.daemon_threads = True
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f'http://127.0.0.1:{cls.server.server_address[1]}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.sequence = sequence_named(self.FORMAT)
        self.chain = self.server.chain = Chain(self.sequence)
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.work = Path(work.name)
        self.baseline = self.work / 'baseline.json'
        self.output = self.work / 'latest.json'

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = monitor.main([str(item) for item in argv])
        self.console = out.getvalue() + err.getvalue()
        return code

    def check(self, *extra, url=None, baseline=True):
        argv = ['check', '--rpc', url or self.url, '--output', self.output, *extra]
        if baseline:
            argv += ['--baseline', self.baseline]
        code = self.run_main(argv)
        if code == monitor.EXIT_USAGE or not self.output.exists():
            return code, None
        raw = self.output.read_bytes()
        value = monitor.validate(monitor.decode(raw))
        self.assertEqual(raw, monitor.encode(value))
        self.assertEqual(code, monitor.EXIT[value['status']])
        return code, value

    def green(self, *extra, **options):
        code, value = self.check(*extra, **options)
        self.assertEqual((code, value['status'], value['failed']), (0, 'green', []), value['checks'])
        return value

    def deposit(self):
        """A funded pool with an accepted baseline."""
        self.chain.apply(self.sequence['steps'][1])
        self.chain.advance(2)
        return self.green()

    def verdicts(self, value):
        return {item['id']: item['ok'] for item in value['checks']}


class Constants(unittest.TestCase):
    def test_addresses_are_the_ones_the_protocol_crate_derives(self):
        self.assertEqual(monitor.PROGRAM, VECTORS['program'])
        self.assertEqual(monitor.POOL, VECTORS['pool'])

    def test_public_key_text_agrees_with_the_explorer_model(self):
        for seed in range(40):
            raw = hashlib.sha256(bytes([seed])).digest() if seed else bytes(32)
            raw = bytes(seed % 4) + raw[seed % 4:]
            text = monitor.b58encode(raw)
            self.assertEqual(text, explorer_model.b58(raw))
            self.assertTrue(monitor.public_key(text) and explorer_model.public_key(text))
        for text in ('', '0' * 32, 'l' * 44, monitor.PROGRAM[:-1], monitor.PROGRAM + '1', 7, None):
            self.assertEqual(monitor.public_key(text), explorer_model.public_key(text), text)

    def test_header_decoding_matches_every_encoder_vector(self):
        self.assertEqual({item['pool_format'] for item in VECTORS['sequences']}, {'NPOOL003', 'NPOOL004'})
        for sequence in VECTORS['sequences']:
            self.assertEqual(sequence['data_bytes'], monitor.POOL_FORMATS[sequence['pool_format'].encode()])
            backing = 0
            for step in sequence['steps']:
                backing -= step['public_value_balance']
                with self.subTest(sequence['pool_format'], event=step['event'], backing=backing):
                    self.assertEqual(monitor.decode_pool(step_data(sequence, step)), {
                        'format': sequence['pool_format'], 'domain': VECTORS['network'], 'rent_floor': sequence['rent_floor'],
                        'backing': backing, 'note_count': step['note_count']})
                    self.assertEqual(step['backing'], backing)
            self.assertEqual([step['event'] for step in sequence['steps']],
                             ['genesis', 'deposit', 'deposit', 'send', 'withdrawal', 'withdrawal'])

    def test_header_decoding_refuses_what_the_validator_refuses(self):
        sequence = sequence_named('NPOOL003')
        good = step_data(sequence, sequence['steps'][1])
        monitor.decode_pool(good)

        def patched(offset, raw):
            return good[:offset] + raw + good[offset + len(raw):]

        for name, data in (
                ('truncated', good[:-1]), ('extended', good + b'\0'), ('empty', b''),
                ('retired format', patched(0, b'NPOOL002')), ('other format length', patched(0, b'NPOOL004')),
                ('no domain', patched(8, bytes(32))),
                ('backing above the signed range', patched(48, struct.pack('<Q', monitor.I64 + 1))),
                ('odd note count', patched(56, struct.pack('<Q', 3))),
                ('note count above the tree', patched(56, struct.pack('<Q', monitor.MAX_COMMITMENTS + 2)))):
            with self.subTest(name), self.assertRaises(ValueError):
                monitor.decode_pool(data)


class GreenPath(Endpoint):
    def test_stays_green_through_deposits_a_send_and_withdrawals(self):
        for tag in ('NPOOL003', 'NPOOL004'):
            with self.subTest(tag):
                self.FORMAT = tag
                self.setUp()
                self.chain.slot = self.chain.span * 9 - 7  # the walk crosses an epoch boundary
                seen = []
                previous = None
                for index, step in enumerate(self.sequence['steps']):
                    self.chain.apply(step)
                    self.chain.advance(3)
                    value = self.green()
                    pool = value['pool']
                    self.assertEqual((pool['format'], int(pool['backing']), pool['note_count'], pool['surplus']),
                                     (tag, step['backing'], step['note_count'], '0'))
                    self.assertEqual(int(pool['lamports']), self.sequence['rent_floor'] + step['backing'])
                    self.assertEqual(pool['data_sha256'], hashlib.sha256(step_data(self.sequence, step)).hexdigest())
                    self.assertEqual(value['slot'], self.chain.slot)
                    self.assertEqual(value['read_mode'], 'batch')
                    verdicts = self.verdicts(value)
                    self.assertEqual([verdicts[name] for name in ('pool_account', 'pool_backing', 'pool_rent_floor',
                                                                  'supply_identity', 'pool_within_supply')], [True] * 5)
                    self.assertIsNone(verdicts['supply_ceiling'])
                    if index:
                        self.assertEqual((verdicts['continuity'], verdicts['supply_issuance']), (True, True))
                        self.assertEqual(value['baseline']['sha256'], hashlib.sha256(previous).hexdigest())
                    else:
                        self.assertIsNone(value['baseline'])
                    previous = self.output.read_bytes()
                    self.assertEqual(self.baseline.read_bytes(), previous)
                    seen.append(value['epoch'])
                self.assertEqual(int(value['pool']['backing']), 0)
                self.assertEqual(sorted(set(seen)), [8, 9])
                # A quiet interval, and the same slot read twice, are green too.
                self.chain.advance(40)
                self.green()
                self.green()

    def test_a_donation_to_the_pool_is_a_reported_surplus_not_a_failure(self):
        self.deposit()
        self.chain.donated = 777
        self.chain.apply(self.sequence['steps'][1])
        self.chain.advance()
        value = self.green()
        self.assertEqual((value['pool']['surplus'], value['pool']['backing']), ('777', '1000'))
        # A later withdrawal leaves the donation where it is.
        self.chain.apply(self.sequence['steps'][4])
        self.chain.advance()
        self.assertEqual(self.green()['pool']['surplus'], '777')

    def test_a_declared_ceiling_is_checked_when_given(self):
        value = self.green('--supply-ceiling', self.chain.total)
        self.assertIs(self.verdicts(value)['supply_ceiling'], True)
        self.assertEqual(value['policy']['supply_ceiling'], str(self.chain.total))

    def test_rewards_are_allowed_exactly_as_the_chain_schedules_them(self):
        self.deposit()
        self.chain.advance(self.chain.span - self.chain.slot % self.chain.span)  # the boundary block itself
        boundary = self.green()
        pending = self.chain.issue()
        self.assertGreater(pending, 100_000)
        self.assertEqual((boundary['supply']['rewards_pending'], boundary['supply']['block_height']), (str(pending), self.chain.slot))
        self.chain.advance()  # the credit lands one block later
        credited = self.green()
        self.assertEqual(credited['supply']['rewards_pending'], '0')
        self.assertEqual(int(credited['supply']['total']) - int(boundary['supply']['total']), pending - 1 - self.chain.burn)
        # Nothing further may appear inside the epoch.
        self.chain.total += 1
        self.assertEqual(self.check()[1]['failed'], ['supply_issuance'])
        self.chain.total -= 1
        # Five boundaries between two runs are within the compounded bound...
        self.chain.advance(5 * self.chain.span)
        before = monitor.decode(self.baseline.read_bytes())
        allowed = monitor.issuance_allowance(
            monitor.baseline_summary(self.baseline.read_bytes(), before),
            {'validator_rate_ppb': 80_000_000, 'slots_in_epoch': self.chain.span}, self.chain.epoch(),
            {'slots_per_year': monitor.SLOTS_PER_YEAR, 'issuance_slack': '0'})
        growth = self.chain.total - int(before['supply']['total'])
        self.assertTrue(0 < growth <= allowed < growth + 6 * self.chain.burn * self.chain.span, (growth, allowed))
        # ...and one unit above the bound is not, unless the operator allows it.
        self.chain.total += allowed - growth + 1
        code, value = self.check()
        self.assertEqual((code, value['failed']), (1, ['supply_issuance']))
        self.green('--issuance-slack', 1)

    def test_account_contents_newer_than_the_reported_slot_raise_no_alarm(self):
        # Seen on the local network's second validator: at the boundary slot the
        # supply is still uncredited while the reward account already reads as
        # finished, and a payment shows in the pool before its slot is reported.
        steps = self.sequence['steps']
        for lag in (1, 3):
            with self.subTest(lag=lag):
                self.setUp()
                self.chain.slot = self.chain.span * 9 - 8
                self.chain.advance(lag)
                self.chain.lag = lag
                pending = []
                for tick in range(16 + lag):
                    if tick in (1, 5, 8, 9, 12):
                        self.chain.apply(steps[(1, 5, 8, 9, 12).index(tick) + 1])
                    self.chain.advance()
                    value = self.green()
                    self.assertEqual(value['slot'], self.chain.slot - lag)
                    self.assertEqual(value['supply']['total'], str(self.chain.history[value['slot']]))
                    pending.append(int(value['supply']['rewards_pending']))
                self.assertEqual(value['epoch'], 9)
                issued = [amount for amount in pending if amount]
                self.assertEqual((pending[0], len(set(issued)), pending[-1]), (0, 1, 0), pending)
                self.assertGreaterEqual(len(issued), 1)

    def test_without_reward_state_one_epoch_of_issuance_is_assumed_pending(self):
        self.chain.rewards_account = False
        value = self.green()
        self.assertEqual(int(value['supply']['rewards_pending']),
                         -(-self.chain.total * 80_000_000 * 128 // (10**9 * monitor.SLOTS_PER_YEAR)))

    def test_reads_that_straddle_a_slot_are_repeated_until_they_agree(self):
        self.chain.skew = 3
        start = self.chain.slot
        value = self.green()
        self.assertEqual((self.chain.skew, value['slot']), (0, start + 3))
        self.chain.skew = 10**6
        code, value = self.check('--attempts', 3)
        self.assertEqual((code, value['status'], value['reason'], value['pool']), (3, 'unknown', 'inconsistent_slots', None))
        self.assertEqual(self.chain.slot, start + 6)

    def test_an_endpoint_without_batches_is_read_one_call_at_a_time(self):
        self.chain.batch = False
        self.assertEqual(self.deposit()['read_mode'], 'sequential')
        self.chain.skew = 2
        self.assertEqual(self.green()['read_mode'], 'sequential')

    def test_the_command_line_entry_point_runs_standalone(self):
        result = subprocess.run([sys.executable, '-I', '-B', str(Path(monitor.__file__)), 'check', '--rpc', self.url],
                                capture_output=True, text=True, timeout=30, cwd=self.work)
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        self.assertEqual(monitor.validate(monitor.decode(result.stdout))['status'], 'green')


class RedPath(Endpoint):
    def planted(self):
        steps = self.sequence['steps']
        floor = self.sequence['rent_floor']

        def pool(change):
            def plant(value):
                value = dict(value)
                data = bytearray(base64.b64decode(value['data'][0]))
                value = change(value, data) or value
                if value.get('data') is not None and 'raw' not in value:
                    value['data'] = [base64.b64encode(bytes(data)).decode(), 'base64']
                value.pop('raw', None)
                return value
            return ('plant_pool', plant)

        def supply(change):
            def plant(value):
                value = dict(value)
                change(value)
                return value
            return ('plant_supply', plant)

        def field(offset, delta):
            def change(value, data):
                data[offset:offset + 8] = struct.pack('<Q', struct.unpack_from('<Q', data, offset)[0] + delta)
            return change

        def both(*changes):
            def change(value, data):
                for item in changes:
                    item(value, data)
            return change

        def lamports(delta):
            def change(value, data):
                value['lamports'] += delta
            return change

        def replaced(step, amount):
            def change(value, data):
                return dict(value, lamports=amount, raw=True,
                            data=[base64.b64encode(step_data(self.sequence, step)).decode(), 'base64'])
            return change

        return (
            ('one base unit missing from the pool account', pool(lamports(-1)), ['pool_backing']),
            ('backing overstated by one unit', pool(field(48, 1)), ['pool_backing', 'continuity']),
            ('backing overstated, with a note count that hides it from continuity',
             pool(replaced(steps[2], floor + steps[1]['backing'])), ['pool_backing']),
            ('rent floor understated to free reserved units', pool(field(40, -5_000)), ['pool_rent_floor', 'continuity']),
            ('backing and balance lowered together without a payment', pool(both(field(48, -100), lamports(-100))), ['continuity']),
            ('note tree rolled back to genesis', pool(replaced(steps[0], floor)), ['continuity']),
            ('another network domain', pool(lambda value, data: data.__setitem__(8, data[8] ^ 1)), ['continuity']),
            ('pool owned by another program', pool(lambda value, data: value.__setitem__('owner', '1' * 32)), ['pool_account']),
            ('pool marked executable', pool(lambda value, data: value.__setitem__('executable', True)), ['pool_account']),
            ('pool account absent', ('plant_pool', lambda value: None), ['pool_account']),
            ('pool data truncated', pool(lambda value, data: data.__delitem__(slice(-1, None))), ['pool_account']),
            ('pool data in a retired format', pool(lambda value, data: data.__setitem__(slice(0, 8), b'NPOOL002')), ['pool_account']),
            ('supply parts do not add up', supply(lambda value: value.__setitem__('circulating', value['circulating'] + 1)), ['supply_identity']),
            ('one unit created since the baseline', supply(lambda value: value.update(
                total=self.created, circulating=self.created - value['nonCirculating'])), ['supply_issuance']),
            ('pool holds more than exists', supply(lambda value: value.update(
                total=floor, circulating=floor, nonCirculating=0)), ['pool_within_supply']),
        )

    def test_every_planted_inconsistency_turns_the_result_red(self):
        for tag in ('NPOOL003', 'NPOOL004'):
            self.FORMAT = tag
            self.setUp()
            green = self.deposit()
            accepted = self.baseline.read_bytes()
            self.created = int(green['supply']['total']) + 1
            for name, (target, plant), expected in self.planted():
                with self.subTest(tag, plant=name):
                    setattr(self.chain, target, plant)
                    code, value = self.check()
                    self.assertEqual((code, value['status'], value['failed']), (1, 'red', expected), value['checks'])
                    self.assertEqual(self.baseline.read_bytes(), accepted, 'a red result must not become the baseline')
                    self.assertEqual(value['baseline']['sha256'], hashlib.sha256(accepted).hexdigest())
                    # Read without a baseline, the same account is judged on its own numbers.
                    alone = self.check(baseline=False)[1]
                    self.assertEqual(alone['failed'], [item for item in expected if item not in ('continuity', 'supply_issuance')])
                    setattr(self.chain, target, None)
                    self.green()
                    self.assertEqual(self.baseline.read_bytes(), self.output.read_bytes())
                    accepted = self.baseline.read_bytes()
                    self.created = int(monitor.decode(accepted)['supply']['total']) + 1

    def test_a_total_above_the_declared_ceiling_is_red(self):
        code, value = self.check('--supply-ceiling', self.chain.total - 1)
        self.assertEqual((code, value['failed']), (1, ['supply_ceiling']))
        self.assertFalse(self.baseline.exists())

    def test_a_rent_floor_below_the_rent_exempt_minimum_is_red_on_its_own(self):
        # A pool whose reserve was fixed too low at genesis: no baseline is needed to see it.
        self.chain.plant_pool = lambda value: dict(value, data=[base64.b64encode(
            self.chain.data[:40] + struct.pack('<Q', self.sequence['rent_floor'] - 1) + self.chain.data[48:]).decode(), 'base64'])
        code, value = self.check()
        self.assertEqual((code, value['failed'], value['pool']['surplus']), (1, ['pool_rent_floor'], '1'))

    def test_the_verdict_is_a_function_of_the_published_numbers(self):
        green = self.deposit()
        self.chain.plant_pool = lambda value: dict(value, lamports=value['lamports'] - 1)
        red = self.check()[1]
        for name, original, change in (
                ('red relabelled green', red, lambda value: value.update(status='green', failed=[])),
                ('green relabelled red', green, lambda value: value.update(status='red', failed=['pool_backing'])),
                ('failing check flipped', red, lambda value: value['checks'][1].update(ok=True)),
                ('balance repaired without the surplus', red, lambda value: value['pool'].update(lamports=green['pool']['lamports'])),
                ('balance and surplus repaired', red, lambda value: value['pool'].update(lamports=green['pool']['lamports'], surplus='0')),
                ('backing restated', green, lambda value: value['pool'].update(backing='999', surplus='1')),
                ('total restated', green, lambda value: value['supply'].update(total='1')),
                ('extra field', green, lambda value: value.update(note='added')),
                ('amount as a number', green, lambda value: value['supply'].update(total=int(value['supply']['total'])))):
            with self.subTest(name):
                value = json.loads(json.dumps(original))
                monitor.validate(value)
                change(value)
                with self.assertRaises(ValueError):
                    monitor.validate(value)


class NoObservation(Endpoint):
    def unknown(self, reason, *extra, **options):
        before = self.baseline.read_bytes() if self.baseline.exists() else None
        code, value = self.check(*extra, **options)
        self.assertEqual((code, value['status'], value['reason']), (3, 'unknown', reason), self.console)
        self.assertEqual((value['checks'], value['pool'], value['supply'], value['slot']), ([], None, None, None))
        self.assertEqual(self.baseline.read_bytes() if self.baseline.exists() else None, before)
        self.assertIn('no observation', self.console)

    def test_failures_to_observe_are_neither_green_nor_red(self):
        self.deposit()
        closed = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        port = closed.server_address[1]
        closed.server_close()
        self.unknown('rpc_unavailable', '--timeout', 2, url=f'http://127.0.0.1:{port}')
        self.unknown('wrong_network', '--expect-genesis', monitor.PROGRAM)
        for method, reason in (('getSupply', 'rpc_error'), ('getAccountInfo', 'rpc_error'), ('getGenesisHash', 'rpc_error')):
            self.chain.fault = method
            self.unknown(reason)
        self.chain.fault = 'getBlockTime'  # pruned block times are tolerated
        self.assertIsNone(self.green()['block_time'])
        self.chain.fault = None
        for name, plant in (('lamports as text', lambda value: dict(value, lamports=str(value['lamports']))),
                            ('negative lamports', lambda value: dict(value, lamports=-1)),
                            ('lamports above the unit range', lambda value: dict(value, lamports=monitor.U64 + 1)),
                            ('data in another encoding', lambda value: dict(value, data=[value['data'][0], 'base58'])),
                            ('data that is not base64', lambda value: dict(value, data=['!', 'base64'])),
                            ('owner that is not a key', lambda value: dict(value, owner='pool'))):
            with self.subTest(name):
                self.chain.plant_pool = plant
                self.unknown('malformed_response')
        self.chain.plant_pool = None
        self.chain.plant_supply = lambda value: dict(value, total=None)
        self.unknown('malformed_response')
        self.chain.plant_supply = None
        self.green()

    def test_an_endpoint_behind_or_beside_the_baseline_is_not_judged(self):
        self.deposit()
        self.chain.slot -= 5
        self.unknown('stale_endpoint')
        self.chain.slot += 5
        self.chain.genesis = monitor.PROGRAM
        self.unknown('wrong_network')

    def test_unusable_invocations_exit_two_and_write_nothing(self):
        self.deposit()
        accepted = self.baseline.read_bytes()
        self.output.unlink()
        cases = [
            ('plain http beyond loopback', ['check', '--rpc', 'http://rpc.example.org:8899', '--output', self.output]),
            ('credentials in the URL', ['check', '--rpc', 'https://user:secret@localhost/', '--output', self.output]),
            ('another scheme', ['check', '--rpc', 'file:///dev/null', '--output', self.output]),
            ('genesis that is not a hash', ['check', '--rpc', self.url, '--expect-genesis', 'genesis', '--output', self.output]),
            ('baseline at another commitment', ['check', '--rpc', self.url, '--commitment', 'confirmed',
                                                '--baseline', self.baseline, '--output', self.output]),
            ('signature without an output path', ['check', '--rpc', self.url, '--signing-key', self.work / 'absent.pem']),
            ('password without a key', ['check', '--rpc', self.url, '--password-file', self.work / 'absent', '--output', self.output]),
            ('absent signing key', ['check', '--rpc', self.url, '--signing-key', self.work / 'absent.pem', '--output', self.output]),
        ]
        for name, argv in cases:
            with self.subTest(name):
                self.assertEqual(self.run_main(argv), 2, self.console)
                self.assertFalse(self.output.exists())
        for name, raw in (('edited', accepted.replace(b'"backing": "1000"', b'"backing": "1001"')),
                          ('reformatted', json.dumps(json.loads(accepted)).encode()),
                          ('not a result', b'{}\n'), ('not JSON', b'baseline')):
            with self.subTest(baseline=name):
                self.baseline.write_bytes(raw)
                self.assertEqual(self.check()[0], 2)
                self.assertEqual(self.baseline.read_bytes(), raw)
        self.chain.plant_pool = lambda value: dict(value, lamports=value['lamports'] - 1)
        self.check(baseline=False)
        self.baseline.write_bytes(self.output.read_bytes())
        self.output.unlink()
        self.assertEqual(self.check()[0], 2, 'a red result is not a baseline')
        (self.work / 'latest.json.sig').write_bytes(b'stale')
        self.baseline.write_bytes(accepted)
        self.assertEqual(self.check()[0], 2, 'an unsigned result must not sit beside an old signature')
        self.assertFalse(self.output.exists())


@unittest.skipUnless(OPENSSL, 'the system OpenSSL is required for signature tests')
class Signature(Endpoint):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # A disposable key made by the test, as an operator would supply one.
        cls.keys = tempfile.TemporaryDirectory()
        root = Path(cls.keys.name)

        def openssl(*args):
            subprocess.run([OPENSSL, *map(str, args)], check=True, capture_output=True, timeout=30)

        for name, curve in (('operator', 'prime256v1'), ('other', 'prime256v1'), ('wrong-curve', 'secp384r1')):
            openssl('ecparam', '-name', curve, '-genkey', '-noout', '-out', root / f'{name}.pem')
            os.chmod(root / f'{name}.pem', 0o600)
            openssl('pkey', '-in', root / f'{name}.pem', '-pubout', '-out', root / f'{name}.pub')
        (root / 'password').write_text('disposable test password\n')
        (root / 'wrong-password').write_text('another password\n')
        for name in ('password', 'wrong-password'):
            os.chmod(root / name, 0o600)
        openssl('pkcs8', '-topk8', '-in', root / 'operator.pem', '-out', root / 'sealed.pem', '-passout', f"file:{root / 'password'}")
        os.chmod(root / 'sealed.pem', 0o600)
        cls.key, cls.public = root / 'operator.pem', root / 'operator.pub'
        cls.pin = hashlib.sha256(monitor.public_der(cls.public.read_bytes())).hexdigest()
        cls.root = root

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()
        super().tearDownClass()

    def signed(self, *extra, key=None):
        return self.check('--signing-key', key or self.key, *extra)

    def verify(self, *extra, public=None, pin=None, result=None):
        return self.run_main(['verify', '--result', result or self.output, '--public-key', public or self.public,
                              '--key-sha256', pin or self.pin, *extra])

    def test_a_signed_result_verifies_and_exposes_no_private_key(self):
        code, value = self.signed('--expect-genesis', self.chain.genesis)
        self.assertEqual((code, value['signer']), (0, {'algorithm': 'ecdsa-p256-sha256', 'key_sha256': self.pin}))
        self.assertTrue(json.loads(self.console)['signed'])
        signature = Path(str(self.output) + '.sig').read_bytes()
        private = self.key.read_bytes()
        body = b''.join(private.split(b'\n')[1:-2])
        self.assertGreater(len(body), 100)
        for name, published in (('result', self.output.read_bytes()), ('baseline', self.baseline.read_bytes()),
                                ('signature', signature), ('console', self.console.encode())):
            self.assertNotIn(b'PRIVATE', published, name)
            self.assertNotIn(body[:40], published, name)
        self.assertEqual(sorted(item.name for item in self.work.iterdir()), ['baseline.json', 'latest.json', 'latest.json.sig'])
        self.assertEqual(self.verify('--expect-genesis', self.chain.genesis, '--max-age', 600, '--min-slot', value['slot']), 0)
        report = json.loads(self.console)
        self.assertEqual((report['authentic'], report['status'], report['slot']), (True, 'green', value['slot']))
        self.assertEqual(report['result_sha256'], hashlib.sha256(self.output.read_bytes()).hexdigest())
        # The same check with nothing but the system tool: domain prefix, then the file.
        plain = subprocess.run([OPENSSL, 'dgst', '-sha256', '-verify', self.public, '-signature', str(self.output) + '.sig'],
                               input=monitor.DOMAIN + self.output.read_bytes(), capture_output=True, timeout=30)
        self.assertEqual(plain.returncode, 0)
        # The signed result is also the next run's baseline.
        self.chain.advance(4)
        self.assertEqual(self.signed()[1]['baseline']['sha256'], report['result_sha256'])

    def test_red_and_unknown_results_are_signed_and_keep_their_exit_codes(self):
        self.chain.plant_pool = lambda value: dict(value, lamports=value['lamports'] - 1)
        self.assertEqual(self.signed()[0], 1)
        self.assertEqual(self.verify(), 1)
        self.assertEqual(json.loads(self.console)['failed'], ['pool_backing'])
        self.chain.fault = 'getSupply'
        self.assertEqual(self.signed()[0], 3)
        self.assertEqual(self.verify(), 3)
        self.assertEqual(json.loads(self.console)['reason'], 'rpc_error')
        self.assertEqual(self.verify('--min-slot', 0), 4, 'an unknown result names no slot')

    def test_verification_refuses_anything_but_the_pinned_untouched_result(self):
        code, value = self.signed()
        self.assertEqual((code, self.verify()), (0, 0))
        raw = self.output.read_bytes()
        signature = Path(str(self.output) + '.sig').read_bytes()
        other_pin = hashlib.sha256(monitor.public_der((self.root / 'other.pub').read_bytes())).hexdigest()
        copy = self.work / 'copy.json'

        def published(body, detached=signature):
            copy.write_bytes(body)
            Path(str(copy) + '.sig').write_bytes(detached)
            return copy

        # Signed by another key while naming the operator's key as its signer.
        forged = monitor.encode(dict(value, observed_at=value['observed_at'] + 1))
        forgery = subprocess.run([OPENSSL, 'dgst', '-sha256', '-sign', self.root / 'other.pem'], input=monitor.DOMAIN + forged,
                                 capture_output=True, check=True, timeout=30).stdout
        self.assertEqual(monitor.validate(monitor.decode(forged))['signer']['key_sha256'], self.pin)
        refusals = (
            ('edited number', lambda: dict(result=published(raw.replace(b'"observed_at": ', b'"observed_at": 1')))),
            ('trailing byte', lambda: dict(result=published(raw + b'\n'))),
            ('signature bit', lambda: dict(result=published(raw, signature[:8] + bytes([signature[8] ^ 1]) + signature[9:]))),
            ('signature of another result', lambda: dict(result=published(forged))),
            ('empty signature', lambda: dict(result=published(raw, b'\0'))),
            ('pin of another key', lambda: dict(pin=other_pin)),
            ('another key under the right pin', lambda: dict(public=self.root / 'other.pub')),
            ('another key and its pin', lambda: dict(public=self.root / 'other.pub', pin=other_pin)),
            ('another key claiming the pinned identity', lambda: dict(result=published(forged, forgery), public=self.root / 'other.pub')),
            ('private key offered as public', lambda: dict(public=self.key)),
            ('pin that is not a digest', lambda: dict(pin='pin')),
        )
        for name, options in refusals:
            with self.subTest(name):
                self.assertEqual(self.verify(**options()), 4, self.console)
                self.assertNotIn('authentic', self.console)
        self.assertEqual(self.verify(result=published(raw)), 0, 'the untouched copy still verifies')
        self.assertEqual(self.verify(result=published(forged, forgery), public=self.root / 'other.pub', pin=other_pin), 4,
                         'a result must name the key that signed it')
        for name, extra in (('another network', ['--expect-genesis', monitor.PROGRAM]),
                            ('older slot', ['--min-slot', value['slot'] + 1])):
            with self.subTest(name):
                self.assertEqual(self.verify(*extra), 4)
        with patch.object(monitor.time, 'time', return_value=value['observed_at'] + 601):
            self.assertEqual(self.verify('--max-age', 600), 4)
            self.assertEqual(self.verify('--max-age', 601), 0)
        with patch.object(monitor.time, 'time', return_value=value['observed_at'] - 301):
            self.assertEqual(self.verify('--max-age', 600), 4, 'a result from the future is refused')
        # One result is one byte string: the operator's own signature over a
        # reformatted body is refused.
        loose = json.dumps(value).encode()
        resigned = subprocess.run([OPENSSL, 'dgst', '-sha256', '-sign', self.key], input=monitor.DOMAIN + loose,
                                  capture_output=True, check=True, timeout=30).stdout
        self.assertEqual(self.verify(result=published(loose, resigned)), 4)
        # A result signed by another key does not verify under the operator's pin,
        # and an unsigned result has no signature to check.
        self.signed(key=self.root / 'other.pem')
        self.assertEqual(self.verify(), 4)
        Path(str(self.output) + '.sig').unlink()
        self.green(baseline=False)
        self.assertEqual(self.verify(), 2)
        self.assertEqual(self.verify(result=published(self.output.read_bytes())), 4)

    def test_signing_key_files_must_be_private_p256_keys(self):
        loose = self.work / 'loose.pem'
        loose.write_bytes(self.key.read_bytes())
        for mode in (0o640, 0o604, 0o660):
            os.chmod(loose, mode)
            self.assertEqual(self.signed(key=loose)[0], 2)
        link = self.work / 'link.pem'
        link.symlink_to(self.key)
        self.assertEqual(self.signed(key=link)[0], 2)
        self.assertEqual(self.signed(key=self.work)[0], 2)
        self.assertEqual(self.signed(key=self.root / 'wrong-curve.pem')[0], 4)
        garbage = self.work / 'garbage.pem'
        garbage.write_bytes(b'not a key\n')
        os.chmod(garbage, 0o600)
        self.assertEqual(self.signed(key=garbage)[0], 4)
        self.assertEqual(self.signed(key=self.root / 'sealed.pem')[0], 4, 'a sealed key needs its password file')
        self.assertEqual(self.signed('--password-file', self.root / 'wrong-password', key=self.root / 'sealed.pem')[0], 4)
        self.assertFalse(self.output.exists() or self.baseline.exists() or Path(str(self.output) + '.sig').exists())
        self.assertNotIn('password', self.console.replace('--password-file', ''))
        code, value = self.signed('--password-file', self.root / 'password', key=self.root / 'sealed.pem')
        self.assertEqual((code, value['signer']['key_sha256'], self.verify()), (0, self.pin, 0))


if __name__ == '__main__':
    unittest.main()
