"""A second reading of docs/protocol-spec.md, checked against the protocol vectors.

Everything here is written from the specification and shares no code with the
Rust crates. It decodes payments, envelopes, checkpoint histories, pool
accounts and staging accounts, computes the digests and the derived addresses,
and replays the recorded sequences. Each result must equal what the vectors
record from the code.

Three things are taken from the vectors instead of computed: the tree hash,
signature verification and proof verification. The cases that depend on them
are named below.
"""
import hashlib
import json
from pathlib import Path
import unittest

VECTORS = Path(__file__).resolve().parent.parent / 'protocol/payments/tests/vectors'

# Section 2: the Pallas base field and curve.
P = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
MAX_COMMITMENTS = 2**32 - 2
LARGEST_AMOUNT = 2**63 - 1
EXPIRY_WINDOW = 1024
ANCHOR_WINDOW = 512
PROOF_BYTES = 7264
ACTION_BYTES = 884
TAG_EXTRA = {b'NPAY0001': 0, b'NPAY0002': 32, b'NPAY0003': 8}


class Refused(Exception):
    pass


def load(name):
    return json.loads((VECTORS / name).read_text())


def u(data):
    return int.from_bytes(data, 'little')


def i64(data):
    return int.from_bytes(data, 'little', signed=True)


def blake(personal, data):
    return hashlib.blake2b(data, digest_size=32, person=personal).digest()


def edited(base, edits):
    data = bytearray(base)
    for edit in edits:
        op = edit['op']
        if op == 'replace':
            new = bytes.fromhex(edit['hex'])
            data[edit['at']:edit['at'] + len(new)] = new
        elif op == 'remove':
            del data[edit['at']:edit['at'] + edit['length']]
        elif op == 'truncate':
            del data[edit['to']:]
        elif op == 'append':
            data += bytes.fromhex(edit['hex'])
        elif op == 'zero_extend':
            data += bytes(edit['to'] - len(data))
        else:
            raise AssertionError(op)
    return bytes(data)


def expanded(blob):
    data = bytes.fromhex(blob['prefix_hex'])
    data += bytes(blob['bytes'] - len(data))
    assert hashlib.blake2b(data, digest_size=32).hexdigest() == blob['blake2b_256']
    return data


def outcome(function, *arguments):
    try:
        function(*arguments)
    except Refused as refused:
        return str(refused)
    return 'ok'


def need(condition, error):
    if not condition:
        raise Refused(error)


def field(data):
    return u(data) < P


def point(data):
    """A valid point encoding; the identity is 32 zero bytes."""
    x = u(data) & ((1 << 255) - 1)
    if x >= P:
        return False
    return data == bytes(32) or pow((pow(x, 3, P) + 5) % P, (P - 1) // 2, P) == 1


# Section 5.2.
def decode_payment(network, data):
    extra = TAG_EXTRA.get(data[:8], 0)
    need(len(data) == 9222 + extra, 'InvalidLength')
    need(data[:8] in TAG_EXTRA, 'UnsupportedVersion')
    need(network != bytes(32) and data[8:40] == network, 'WrongNetwork')
    payment = {
        'tag': data[:8], 'extra': extra, 'expires_at': u(data[40:48]),
        'balance': i64(data[48:56]), 'sponsor': data[56:88], 'fee': None, 'recipient': None,
    }
    if extra == 8:
        payment['fee'] = u(data[88:96])
        need(0 < payment['fee'] <= LARGEST_AMOUNT and payment['balance'] == payment['fee'],
             'InvalidContext')
    need(payment['sponsor'] != bytes(32), 'InvalidContext')
    if extra == 32:
        payment['recipient'] = data[88:120]
        need(payment['recipient'] != bytes(32) and payment['balance'] > 0, 'InvalidContext')
    at = 88 + extra
    payment['anchor'] = data[at:at + 32]
    need(field(payment['anchor']), 'InvalidEncoding')
    need(data[at + 32] == 3 and data[at + 33] == 2, 'InvalidShape')
    at += 34
    payment['actions'] = []
    for _ in range(2):
        action = data[at:at + ACTION_BYTES]
        nullifier, rk, cmx, epk, cv = (action[n:n + 32] for n in (0, 32, 64, 96, 788))
        need(field(nullifier) and field(cmx), 'InvalidEncoding')
        need(point(rk) and rk != bytes(32), 'InvalidEncoding')
        need(point(epk) and epk != bytes(32), 'InvalidEncoding')
        need(point(cv), 'InvalidEncoding')
        payment['actions'].append({'offset': at, 'nullifier': nullifier, 'cmx': cmx, 'bytes': action})
        at += ACTION_BYTES
    need(u(data[at:at + 4]) == PROOF_BYTES, 'InvalidLength')
    payment['proof'] = data[at + 4:at + 4 + PROOF_BYTES]
    payment['binding'] = data[at + 4 + PROOF_BYTES:]
    return payment


# Section 6.
def authorization(data):
    extra = TAG_EXTRA[data[:8]]
    actions = [data[122 + extra + n * ACTION_BYTES:][:ACTION_BYTES] for n in range(2)]
    compact = blake(b'ZTxIdOrcActCHash', b''.join(a[0:32] + a[64:128] + a[128:180] for a in actions))
    memos = blake(b'ZTxIdOrcActMHash', b''.join(a[180:692] for a in actions))
    noncompact = blake(b'ZTxIdOrcActNHash',
                       b''.join(a[788:820] + a[32:64] + a[692:708] + a[708:788] for a in actions))
    anchor = 88 + extra
    commitment = blake(b'ZTxIdOrchardHash', compact + memos + noncompact
                       + data[anchor + 32:anchor + 33] + data[48:56] + data[anchor:anchor + 32])
    personal = {0: b'NativePayAuthV1!', 32: b'NativePayAuthV2!', 8: b'NativePayAuthV3!'}[extra]
    preimage = data[8:40] + (1).to_bytes(4, 'little') + commitment + data[40:88 + extra]
    return {'compact_digest': compact, 'memos_digest': memos, 'noncompact_digest': noncompact,
            'bundle_commitment': commitment, 'personalization': personal,
            'preimage_hex': preimage, 'digest': blake(personal, preimage)}


def payload_digest(data):
    return blake(b'NativeStageV1!!!', data)


# Section 7, checks 3 to 8: everything before the signatures.
def verify_before_signatures(payment, slot, anchors, spent, authorized):
    need(payment['expires_at'] >= slot, 'Expired')
    need(payment['expires_at'] - slot <= EXPIRY_WINDOW, 'InvalidContext')
    need(payment['balance'] == authorized, 'WrongValueBalance')
    need(payment['anchor'] in anchors, 'UnknownAnchor')
    nullifiers = [action['nullifier'] for action in payment['actions']]
    need(nullifiers[0] != nullifiers[1], 'DuplicateNullifier')
    need(not any(n in spent for n in nullifiers), 'SpentNullifier')


# Section 12.2.
def decode_envelope(network, slot, data):
    need(102 < len(data) <= 16384, 'InvalidLength')
    need(data[:8] == b'ZOLNPAY1' and u(data[8:10]) == 1, 'UnsupportedVersion')
    need(data[10:26] == b'ZolanaNativePay!', 'InvalidContext')
    need(network != bytes(32) and data[26:58] == network, 'WrongNetwork')
    length = u(data[98:102])
    need(0 < length <= 16282 and len(data) - 102 == length, 'InvalidLength')
    need(payload_digest(data[102:]) == data[66:98], 'DigestMismatch')
    payment = decode_payment(network, data[102:])
    need(payment['fee'] is not None, 'UnsupportedVersion')
    expires_at = u(data[58:66])
    need(payment['expires_at'] == expires_at, 'InvalidContext')
    need(expires_at >= slot, 'Expired')
    need(expires_at - slot <= EXPIRY_WINDOW, 'InvalidContext')


# Section 9.2.
class History:
    def __init__(self, network, entries=()):
        self.network, self.entries = network, list(entries)

    @staticmethod
    def entry_rule(empty_root, entry):
        _, count, root = entry
        need(count <= MAX_COMMITMENTS and count % 2 == 0 and root != bytes(32) and field(root)
             and (count == 0) == (root == empty_root), 'InvalidEncoding')

    @staticmethod
    def order_rule(previous, entry):
        need(entry[1] >= previous[1] and (entry[1] == previous[1]) == (entry[2] == previous[2]),
             'InvalidEncoding')

    @staticmethod
    def reuse_rule(entries, entry):
        need(not any(e[2] == entry[2] and e[1] != entry[1] for e in entries), 'InvalidEncoding')

    @classmethod
    def decode(cls, network, data, empty_root):
        need(60 <= len(data) <= 24636, 'InvalidLength')
        need(data[:8] == b'ZOLANCH1' and u(data[8:10]) == 1, 'UnsupportedVersion')
        need(data[10:26] == b'ZolanaSlotRoots1', 'InvalidContext')
        need(network != bytes(32) and data[26:58] == network, 'WrongNetwork')
        count = u(data[58:60])
        need(count <= 512 and len(data) - 60 == 48 * count, 'InvalidLength')
        history = cls(network)
        for index in range(count):
            raw = data[60 + 48 * index:][:48]
            entry = (u(raw[:8]), u(raw[8:16]), raw[16:])
            cls.entry_rule(empty_root, entry)
            if history.entries:
                need(entry[0] > history.entries[-1][0], 'InvalidEncoding')
                cls.order_rule(history.entries[-1], entry)
            cls.reuse_rule(history.entries, entry)
            history.entries.append(entry)
        if history.entries:
            need(history.entries[-1][0] - history.entries[0][0] < ANCHOR_WINDOW, 'InvalidEncoding')
        return history

    def encode(self):
        data = b'ZOLANCH1' + (1).to_bytes(2, 'little') + b'ZolanaSlotRoots1' + self.network
        data += len(self.entries).to_bytes(2, 'little')
        for slot, count, root in self.entries:
            data += slot.to_bytes(8, 'little') + count.to_bytes(8, 'little') + root
        return data

    def record(self, empty_root, slot, count, root):
        entry = (slot, count, root)
        self.entry_rule(empty_root, entry)
        if self.entries:
            need(slot >= self.entries[-1][0], 'InvalidContext')
            self.order_rule(self.entries[-1], entry)
        self.reuse_rule(self.entries, entry)
        self.entries = [e for e in self.entries if slot - e[0] < ANCHOR_WINDOW]
        if self.entries and self.entries[-1][0] == slot:
            self.entries[-1] = entry
        else:
            self.entries.append(entry)

    def roots_at(self, empty_root, slot):
        need(not self.entries or self.entries[-1][0] <= slot, 'InvalidContext')
        roots = {e[2] for e in self.entries if e[0] < slot and slot - e[0] < ANCHOR_WINDOW}
        if slot < ANCHOR_WINDOW:
            roots.add(empty_root)
        return roots


# Sections 8.3 and 8.4, without the rule that needs the tree hash.
def decode_pool(data, empty_root):
    if data[:8] == b'NPOOL004':
        need(len(data) == 25728, 'InvalidEncoding')
        frontier = 64
    else:
        need(len(data) == 3137 and data[:8] == b'NPOOL003', 'InvalidEncoding')
        frontier = 65
    pool = {'network': data[8:40], 'rent_floor': u(data[40:48]), 'backing': u(data[48:56]),
            'count': u(data[56:64])}
    need(pool['network'] != bytes(32) and pool['backing'] <= LARGEST_AMOUNT
         and pool['count'] <= MAX_COMMITMENTS and pool['count'] % 2 == 0, 'InvalidEncoding')
    if frontier == 65:
        need(1 <= data[64] <= 64, 'InvalidEncoding')
    for level in range(32):
        node = data[frontier + 32 * level:][:32]
        need(field(node) if pool['count'] >> level & 1 else node == bytes(32), 'InvalidEncoding')
    if frontier == 65:
        stored = [data[1089 + 32 * n:][:32] for n in range(64)]
        need(all(field(root) for root in stored[:data[64]])
             and all(root == bytes(32) for root in stored[data[64]:]), 'InvalidEncoding')
        pool['roots'] = stored[:data[64]]
        return pool
    length = u(data[1088:1092])
    need(length <= 24636, 'InvalidLength')
    need(not any(data[1092 + length:]), 'InvalidEncoding')
    pool['history'] = History.decode(pool['network'], data[1092:1092 + length], empty_root)
    if pool['history'].entries:
        need(pool['history'].entries[-1][1] <= pool['count'], 'InvalidEncoding')
    return pool


# Section 11.2.
class Buffer:
    def __init__(self, data):
        self.data = bytearray(data)

    @classmethod
    def initialize(cls, data, sponsor, length, digest, expiry):
        need(len(data) == 16480 and not any(data) and 1 <= length <= 16384, 'InvalidAccountData')
        header = (b'NBUF0001' + sponsor + length.to_bytes(4, 'little') + bytes(4) + digest
                  + expiry.to_bytes(8, 'little') + bytes(8))
        return cls(header + bytes(16384))

    @classmethod
    def decode(cls, data):
        need(len(data) == 16480 and data[:8] == b'NBUF0001' and data[88] in (0, 1, 3)
             and not any(data[89:96]), 'InvalidAccountData')
        length, received = u(data[40:44]), u(data[44:48])
        need(1 <= length <= 16384 and received <= length
             and (data[88] == 0 or received == length) and not any(data[96 + received:]),
             'InvalidAccountData')
        return cls(data)

    length = property(lambda self: u(self.data[40:44]))
    received = property(lambda self: u(self.data[44:48]))

    def write(self, offset, chunk):
        need(self.data[88] == 0 and offset == self.received and 1 <= len(chunk) <= 768
             and offset + len(chunk) <= self.length, 'InvalidInstructionData')
        self.data[96 + offset:96 + offset + len(chunk)] = chunk
        self.data[44:48] = (offset + len(chunk)).to_bytes(4, 'little')

    def seal(self):
        need(self.data[88] == 0 and self.received == self.length
             and payload_digest(bytes(self.data[96:96 + self.length])) == self.data[48:80],
             'InvalidAccountData')
        self.data[88] = 1

    def payload(self):
        need(self.data[88] == 1, 'InvalidAccountData')
        return bytes(self.data[96:96 + self.length])

    def consume(self):
        self.payload()
        self.data[88] = 3


# Section 10.1.
def on_curve(key):
    """Whether 32 bytes encode a point of the Ed25519 curve."""
    q = 2**255 - 19
    d = -121665 * pow(121666, -1, q) % q
    y = u(key) & ((1 << 255) - 1)
    if y >= q:
        return False
    x2 = (y * y - 1) * pow(d * y * y + 1, -1, q) % q
    if x2 == 0:
        return not key[31] >> 7
    return pow(x2, (q - 1) // 2, q) == 1


def derived_address(seeds, program):
    for bump in range(255, -1, -1):
        key = hashlib.sha256(b''.join(seeds) + bytes([bump]) + program + b'ProgramDerivedAddress').digest()
        if not on_curve(key):
            return key, bump
    raise AssertionError('no address')


def base58(data):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number, text = int.from_bytes(data, 'big'), ''
    while number:
        number, digit = divmod(number, 58)
        text = alphabet[digit] + text
    return '1' * (len(data) - len(data.lstrip(b'\0'))) + text


# Cases whose recorded refusal rests on the tree hash, which is not computed here.
TREE_HASH_CASES = {
    'legacy: occupied level holds another node',
    'legacy: occupied level zeroed',
    'legacy: present root changed',
    'slots: occupied level holds another node',
    'slots: last checkpoint of the present tree under another root',
}


class ProtocolVectors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payments = load('payments.json')
        cls.pool = load('pool.json')
        cls.network = bytes.fromhex(cls.payments['network'])
        cls.payloads = {p['name']: bytes.fromhex(p['payload_hex']) for p in cls.payments['payments']}
        cls.empty_root = bytes.fromhex(cls.pool['empty_roots_by_level'][32])

    def test_field_and_curve_constants(self):
        # Five is not a square, so no point has a zero x-coordinate.
        self.assertEqual(pow(5, (P - 1) // 2, P), P - 1)
        self.assertEqual(self.pool['empty_leaf'], (2).to_bytes(32, 'little').hex())
        self.assertEqual(self.pool['empty_roots_by_level'][0], self.pool['empty_leaf'])

    def test_payments_decode_to_the_recorded_fields(self):
        for record in self.payments['payments']:
            data = self.payloads[record['name']]
            self.assertEqual(len(data), record['payload_bytes'])
            self.assertEqual((VECTORS / 'payloads' / (record['name'] + '.hex')).read_text().strip(),
                             record['payload_hex'])
            payment, fields = decode_payment(self.network, data), record['fields']
            self.assertEqual(payment['tag'].decode(), record['tag'])
            self.assertEqual(payment['expires_at'], fields['expires_at'])
            self.assertEqual(payment['balance'], fields['public_value_balance'])
            self.assertEqual(payment['sponsor'].hex(), fields['sponsor'])
            self.assertEqual(payment['fee'], fields['shielded_fee'])
            self.assertEqual(payment['recipient'] and payment['recipient'].hex(),
                             fields['withdrawal_recipient'])
            self.assertEqual(payment['anchor'].hex(), fields['anchor'])
            self.assertEqual(88 + payment['extra'], fields['anchor_offset'])
            for action, expected in zip(payment['actions'], fields['actions']):
                self.assertEqual(action['offset'], expected['offset'])
                raw = action['bytes']
                self.assertEqual(
                    [raw[0:32].hex(), raw[32:64].hex(), raw[64:96].hex(), raw[96:128].hex(),
                     raw[788:820].hex(), raw[820:884].hex()],
                    [expected[k] for k in ('nullifier', 'rk', 'cmx', 'epk', 'cv_net',
                                           'spend_signature')])
            self.assertEqual(len(payment['proof']), fields['proof_bytes'])
            self.assertEqual(payment['binding'].hex(), fields['binding_signature'])
            self.assertEqual(payload_digest(data).hex(), record['payload_digest'])

    def test_authorization_digests(self):
        for record in self.payments['payments']:
            for key, value in authorization(self.payloads[record['name']]).items():
                expected = record['authorization'][key]
                self.assertEqual(value.decode() if key == 'personalization' else value.hex(),
                                 expected, (record['name'], key))

    def test_payment_decoder_cases(self):
        for case in self.payments['decode_cases']:
            data = edited(self.payloads[case['base']], case['edits'])
            self.assertEqual(outcome(decode_payment, self.network, data), case['result'], case['name'])
        other = bytes(32)
        self.assertEqual(outcome(decode_payment, other, self.payloads['send']), 'WrongNetwork')

    def test_verification_cases(self):
        for case in self.payments['verification_cases']:
            base = self.payloads[case['base']]
            data = edited(base, case['edits'])
            payment = decode_payment(self.network, data)
            result = outcome(
                verify_before_signatures, payment, case['current_slot'],
                {bytes.fromhex(r) for r in case['accepted_anchors']},
                {bytes.fromhex(n) for n in case['spent_nullifiers']},
                case['authorized_public_value_balance'])
            if result == 'ok':
                # The signatures cover the digest; the proof covers the actions.
                # A changed digest or signature fails first, then the binding
                # signature, then the proof.
                original = decode_payment(self.network, base)
                spend = lambda p: [a['bytes'][820:] for a in p['actions']]
                if (data[:8] != base[:8] or authorization(data)['digest'] != authorization(base)['digest']
                        or spend(payment) != spend(original)):
                    result = 'InvalidSpendAuthorization'
                elif payment['binding'] != original['binding']:
                    result = 'InvalidBindingSignature'
                elif payment['proof'] != original['proof']:
                    result = 'InvalidProof'
            self.assertEqual(result, case['result'], case['name'])
            if result == 'ok':
                self.assertEqual(case['effects'], {
                    'nullifiers': [a['nullifier'].hex() for a in payment['actions']],
                    'commitments': [a['cmx'].hex() for a in payment['actions']],
                    'public_value_balance': payment['balance']})

    def test_envelope(self):
        vectors = load('envelope.json')
        frame = vectors['frame']
        payload = self.payloads[frame['payment']]
        header = (b'ZOLNPAY1' + (1).to_bytes(2, 'little') + b'ZolanaNativePay!' + self.network
                  + frame['expires_at'].to_bytes(8, 'little') + payload_digest(payload)
                  + len(payload).to_bytes(4, 'little'))
        self.assertEqual(header.hex(), frame['header_hex'])
        whole = header + payload
        self.assertEqual(len(whole), frame['bytes'])
        self.assertEqual(hashlib.blake2b(whole, digest_size=32).hexdigest(), frame['blake2b_256'])
        for query in vectors['decode_by_slot']:
            self.assertEqual(outcome(decode_envelope, self.network, query['current_slot'], whole),
                             query['result'])
        later = bytearray(payload)
        later[40:48] = (frame['expires_at'] + 1).to_bytes(8, 'little')
        inner = {'send': self.payloads['send'], 'withdrawal': self.payloads['withdrawal'],
                 'fee-payment with expires_at one higher': bytes(later)}
        bases = {'frame': whole}
        for name, base in vectors['bases'].items():
            bases[name] = bytes.fromhex(base['header_hex']) + inner[base['payload']]
        for case in vectors['decode_cases']:
            data = edited(bases[case['base']], case['edits'])
            self.assertEqual(
                outcome(decode_envelope, self.network, vectors['decode_cases_at_slot'], data),
                case['result'], case['name'])

    def test_checkpoint_history(self):
        vectors = load('anchors.json')
        empty = bytes.fromhex(vectors['empty_tree_root'])
        self.assertEqual(empty, self.empty_root)
        history = History(self.network)
        self.assertEqual(history.encode().hex(), vectors['no_checkpoints_hex'])
        for step in vectors['records']:
            slot, count, root = step['record']
            self.assertEqual(outcome(history.record, empty, slot, count, bytes.fromhex(root)),
                             step['result'], step['note'])
            self.assertEqual([[s, c, r.hex()] for s, c, r in history.entries], step['entries_after'])
            self.assertEqual(history.encode().hex(), step['encoding_hex'])
        for query in vectors['queries']:
            history = History.decode(self.network, bytes.fromhex(query['encoding_hex']), empty)
            self.assertEqual([[s, c, r.hex()] for s, c, r in history.entries], query['entries'])
            for at in query['roots_at']:
                try:
                    roots = sorted(r.hex() for r in history.roots_at(empty, at['execution_slot']))
                    self.assertEqual(('ok', roots), (at['result'], at['roots']))
                except Refused as refused:
                    self.assertEqual((str(refused), None), (at['result'], at['roots']))
        full = History(self.network)
        for slot in range(ANCHOR_WINDOW + 1):
            full.record(empty, slot, 2 * (slot + 1), (slot + 1).to_bytes(32, 'little'))
        self.assertEqual(full.encode(), expanded(vectors['full_window']['encoding']))
        self.assertEqual(len(full.entries), vectors['full_window']['entries'])
        for case in vectors['decode_cases']:
            data = edited(bytes.fromhex(vectors['decode_bases'][case['base']]), case['edits'])
            self.assertEqual(outcome(History.decode, self.network, data, empty), case['result'],
                             case['name'])

    def test_pool_decoder_cases(self):
        bases = {name: expanded(blob) for name, blob in self.pool['decode_bases'].items()}
        for case in self.pool['decode_cases']:
            result = outcome(decode_pool, edited(bases[case['base']], case['edits']), self.empty_root)
            if case['name'] in TREE_HASH_CASES:
                self.assertEqual((result, case['result']), ('ok', 'InvalidEncoding'), case['name'])
            else:
                self.assertEqual(result, case['result'], case['name'])

    def test_pool_flows(self):
        for flow in self.pool['flows']:
            pool = decode_pool(expanded(flow['genesis']['account']), self.empty_root)
            self.assertEqual((pool['backing'], pool['count'], pool['rent_floor']),
                             (0, 0, flow['rent_floor']))
            spent = set()
            for step in flow['steps']:
                slot = step['slot']
                if 'accepted_roots' in step:
                    accepted = (pool['history'].roots_at(self.empty_root, slot)
                                if 'history' in pool else set(pool['roots']))
                    self.assertEqual(sorted(r.hex() for r in accepted), step['accepted_roots'])
                if step['event'] == 'payment':
                    payment = decode_payment(self.network, self.payloads[step['payment']])
                    self.assertEqual(
                        outcome(verify_before_signatures, payment, slot, accepted, spent,
                                payment['balance']), step['result'])
                if step.get('result') != 'ok':
                    continue
                after = decode_pool(expanded(step['state_after']['account']), self.empty_root)
                self.assertEqual(after['rent_floor'], pool['rent_floor'])
                self.assertEqual((after['backing'], after['count']),
                                 (step['state_after']['backing'], step['state_after']['note_count']))
                root = bytes.fromhex(step['state_after']['root'])
                if step['event'] == 'payment':
                    spent.update(a['nullifier'] for a in payment['actions'])
                    self.assertEqual(after['backing'], pool['backing'] - payment['balance'])
                    self.assertEqual(after['count'], pool['count'] + 2)
                    if 'history' in pool:
                        self.assertEqual(after['history'].entries, pool['history'].entries)
                    else:
                        self.assertEqual(after['roots'], (pool['roots'] + [root])[-64:])
                else:
                    self.assertEqual((after['backing'], after['count']), (pool['backing'], pool['count']))
                    pool['history'].record(self.empty_root, slot, pool['count'], root)
                    self.assertEqual(after['history'].entries, pool['history'].entries)
                pool = after

    def test_pool_transitions_and_rotation(self):
        for case in self.pool['transitions']:
            pool = decode_pool(expanded(case['state']), self.empty_root)
            balance = case['payment']['public_value_balance']

            def apply():
                need(pool['count'] <= MAX_COMMITMENTS - 2, 'CapacityExceeded')
                need(balance <= pool['backing'], 'InsufficientBacking')
                need(pool['backing'] - balance <= LARGEST_AMOUNT, 'CapacityExceeded')
                need(all(field(bytes.fromhex(c)) for c in case['payment']['commitments']),
                     'InvalidEncoding')
            self.assertEqual(outcome(apply), case['result'], case['name'])
            if case['result'] == 'ok':
                self.assertEqual((case['state_after']['backing'], case['state_after']['note_count']),
                                 (pool['backing'] - balance, pool['count'] + 2))
        rotation = self.pool['root_rotation']
        kept = rotation['state_after']['recent_roots']
        self.assertEqual((len(kept), kept[0]), (64, rotation['oldest_root_kept']))
        self.assertFalse(set(kept) & set(rotation['roots_dropped']))
        self.assertEqual(kept[-1], rotation['state_after']['root'])

    def test_staging_account(self):
        vectors = load('staging.json')
        for sample in vectors['payload_digests']:
            self.assertEqual(payload_digest(bytes.fromhex(sample['input_hex'])).hex(), sample['digest'])
        record = vectors['buffer']
        payload = self.payloads[record['payment']]
        self.assertEqual(payload_digest(payload).hex(), record['digest'])
        sponsor = bytes.fromhex(record['sponsor'])
        buffer = None
        for step in record['steps']:
            name = step['operation']
            if name == 'initialize':
                buffer = Buffer.initialize(bytes(16480), sponsor, record['length'],
                                           bytes.fromhex(record['digest']), record['expiry'])
                result = 'ok'
            elif name.startswith('write') and ' bytes at offset ' in name:
                size, offset = int(name.split()[1]), int(name.split()[-1])
                result = outcome(buffer.write, offset, payload[offset:offset + size])
            elif name.startswith('seal'):
                result = outcome(buffer.seal)
            elif name.startswith('consume'):
                result = outcome(buffer.consume)
            elif name.startswith('payload'):
                result = outcome(buffer.payload)
            else:
                offset, chunk = {
                    'write at offset 1': (1, b'\0'),
                    'write of no bytes': (0, b''),
                    'write of 769 bytes': (0, payload[:769]),
                    'write again at offset 0': (0, b'\0'),
                    'write past the stated length': (buffer.received, b'\0'),
                    'write after sealing': (buffer.received, b'\0'),
                }[name]
                result = outcome(buffer.write, offset, chunk)
            self.assertEqual(result, step['result'], name)
            self.assertEqual(bytes(buffer.data[:96]).hex(), step['header_hex'], name)
            self.assertEqual(buffer.received, step['payload_bytes_present'], name)
            self.assertEqual(hashlib.blake2b(buffer.data, digest_size=32).hexdigest(),
                             step['account_blake2b_256'], name)
            Buffer.decode(bytes(buffer.data))
        bases = {name: expanded(blob) for name, blob in vectors['stored_bases'].items()}
        for case in vectors['stored_cases']:
            self.assertEqual(outcome(Buffer.decode, edited(bases[case['base']], case['edits'])),
                             case['result'], case['name'])

    def test_derived_addresses(self):
        vectors = load('accounts.json')
        program = bytes.fromhex(vectors['program_id_hex'])
        self.assertEqual(base58(program), vectors['program_id'])
        self.assertEqual(base58(bytes(32)), vectors['system_program_id'])
        pool, bump = derived_address([vectors['pool_seed'].encode()], program)
        self.assertEqual((pool.hex(), bump, base58(pool)),
                         (vectors['pool']['address_hex'], vectors['pool']['bump'], vectors['pool']['address']))
        seen = []
        for marker in vectors['nullifier_markers']:
            nullifier = bytes.fromhex(marker['nullifier'])
            key, bump = derived_address([vectors['marker_seed'].encode(), pool, nullifier], program)
            account = marker['account']
            self.assertEqual((key.hex(), bump, base58(key)),
                             (account['address_hex'], account['bump'], account['address']))
            payment = decode_payment(self.network, self.payloads[marker['payment']])
            self.assertEqual(payment['actions'][marker['action']]['nullifier'], nullifier)
            seen.append(nullifier)
        self.assertEqual(len(set(seen)), 8)
        for role in ('sponsor', 'relay', 'recipient'):
            key = bytes.fromhex(vectors['scenario_keys'][role + '_hex'])
            self.assertEqual(base58(key), vectors['scenario_keys'][role])
            self.assertTrue(on_curve(key))


if __name__ == '__main__':
    unittest.main()
