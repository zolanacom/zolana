#!/usr/bin/env python3
"""Read-only three-validator audit of an owned Mac native-payment acceptance.

Uses only Python's standard library and read-only JSON RPC through operator-pinned
SSH (or three explicit loopback forwards). It never broadcasts, reads wallet keys,
rebuilds binaries, starts validators, or prints raw proofs/packets. RPC finality is
trusted validator evidence; this helper is not a light client or proof verifier.

Without --rpc, the SSH endpoint is operator configuration: ZOLANA_PILOT_SSH_TARGET
(user@host), ZOLANA_PILOT_SSH_IDENTITY (private key file) and
ZOLANA_PILOT_SSH_KNOWN_HOSTS (pinned host keys). Nothing is contacted by default.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request

PROJECT = Path(__file__).resolve().parents[1]
SSH_SETTINGS = ('ZOLANA_PILOT_SSH_TARGET', 'ZOLANA_PILOT_SSH_IDENTITY', 'ZOLANA_PILOT_SSH_KNOWN_HOSTS')


def pilot_ssh():
    """Operator-supplied pinned SSH endpoint; no host or key location is built in."""
    target, identity, known_hosts = (os.environ.get(name, '') for name in SSH_SETTINGS)
    if (target.count('@') != 1 or '' in target.split('@') or target.startswith('-')
            or any(character.isspace() for character in target)):
        raise ValueError('set ZOLANA_PILOT_SSH_TARGET to the operator user@host')
    for name, value in zip(SSH_SETTINGS[1:], (identity, known_hosts)):
        if not value or not Path(value).is_file():
            raise ValueError('set ' + name + ' to the existing operator file')
    return target, identity, known_hosts
PROGRAM = bytes([91, 34, 9, 203, 140, 74, 92, 11, 167, 20, 210, 73, 64, 155, 3, 220,
                 25, 87, 194, 52, 122, 28, 170, 241, 29, 131, 42, 88, 76, 107, 13, 190])
NETWORK = bytes([67]) * 32
PALLAS_BASE = int('40000000000000000000000000000000224698fc094cf91b992d30ed00000001', 16)
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
POOL_BYTES, MAX_FILE = 25_728, 8 * 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def b58(raw):
    number, out = int.from_bytes(raw, 'big'), ''
    while number:
        number, digit = divmod(number, 58)
        out = ALPHABET[digit] + out
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + out


def un58(value):
    number = 0
    for character in value:
        number = number * 58 + ALPHABET.index(character)
    raw = number.to_bytes((number.bit_length() + 7) // 8, 'big')
    return bytes(len(value) - len(value.lstrip('1'))) + raw


def on_ed25519_curve(raw):
    p = (1 << 255) - 19
    y = int.from_bytes(raw, 'little') & ((1 << 255) - 1)
    if y >= p:
        return False
    y2 = y * y % p
    d = -121665 * pow(121666, p - 2, p) % p
    denominator = (d * y2 + 1) % p
    if denominator == 0:
        return False
    x2 = (y2 - 1) * pow(denominator, p - 2, p) % p
    return pow(x2, (p - 1) // 2, p) in (0, 1)


def pda(seeds):
    require(all(len(seed) <= 32 for seed in seeds), 'invalid PDA seed length')
    for bump in range(255, -1, -1):
        raw = hashlib.sha256(b''.join(seeds) + bytes([bump]) + PROGRAM + b'ProgramDerivedAddress').digest()
        if not on_ed25519_curve(raw):
            return raw
    raise ValueError('PDA derivation failed')


POOL = pda([b'native-payment-pool-v1'])


def load(path, maximum=MAX_FILE):
    require(path.stat().st_size <= maximum, 'bounded evidence file exceeded')
    return json.loads(path.read_bytes())


def host_ready(path):
    require(path.stat().st_size <= 2 * 1024 * 1024, 'host evidence exceeded bound')
    raw = path.read_text()
    try:
        values = [json.loads(raw)]
    except json.JSONDecodeError:
        values = [json.loads(line) for line in raw.splitlines() if line.strip()]
    matches = [value['data'] for value in values if value.get('event') == 'external_mac_fixture_ready']
    host = matches[-1] if matches else values[-1]
    require(host['pool_format'] == 'NPOOL004' and bytes(host['network']['network']) == NETWORK,
            'explicit V4 network67 host evidence required')
    require(len(host['peers']) == 3 and len({p['identity'] for p in host['peers']}) == 3,
            'three distinct held validators required')
    for peer in host['peers']:
        address, port = peer['rpc'].rsplit(':', 1)
        require(address == '127.0.0.1' and 0 < int(port) <= 65535, 'host RPC must be loopback')
    return host


class Cursor:
    def __init__(self, raw):
        self.raw, self.offset = raw, 0

    def take(self, count):
        require(0 <= count <= len(self.raw) - self.offset, 'truncated transaction')
        value = self.raw[self.offset:self.offset + count]
        self.offset += count
        return value

    def short(self):
        start, value = self.offset, 0
        for index in range(3):
            byte = self.take(1)[0]
            value |= (byte & 127) << (7 * index)
            if byte < 128:
                require(value <= 65535, 'shortvec overflow')
                canonical, remaining = bytearray(), value
                while remaining >= 128:
                    canonical.append((remaining & 127) | 128)
                    remaining >>= 7
                canonical.append(remaining)
                require(bytes(canonical) == self.raw[start:self.offset], 'noncanonical shortvec')
                return value
        raise ValueError('shortvec overflow')


def transaction(raw):
    require(0 < len(raw) <= 16384, 'transaction byte bound')
    cursor = Cursor(raw)
    signatures = [b58(cursor.take(64)) for _ in range(cursor.short())]
    header = cursor.take(3)
    require(header[0] < 128, 'audit expects Legacy transaction')
    keys = [cursor.take(32) for _ in range(cursor.short())]
    cursor.take(32)
    instructions = []
    for _ in range(cursor.short()):
        program = cursor.take(1)[0]
        accounts = list(cursor.take(cursor.short()))
        data = cursor.take(cursor.short())
        require(program < len(keys) and all(a < len(keys) for a in accounts), 'invalid account index')
        instructions.append((keys[program], [keys[a] for a in accounts], data))
    require(cursor.offset == len(raw), 'trailing transaction bytes')
    return signatures, header, keys, instructions


def private_packet(raw, signature, sha, relay):
    require(len(raw) == 9676 and hashlib.sha256(raw).hexdigest() == sha, 'private packet size/hash mismatch')
    signatures, header, keys, instructions = transaction(raw)
    require(signatures == [signature] and header == bytes([1, 0, 3]) and len(keys) == 7,
            'native outer signature/header shape changed')
    require(keys[0] == un58(relay) and len(set(keys)) == 7 and len(instructions) == 2,
            'native account/relay shape changed')
    budget, payment = instructions
    require(b58(budget[0]) == 'ComputeBudget111111111111111111111111111111' and
            budget[1] == [] and budget[2] == bytes([2]) + struct.pack('<I', 1400000), 'native budget changed')
    require(payment[0] == PROGRAM and len(payment[1]) == 5 and payment[2][0] == 5,
            'native payment instruction changed')
    frame = payment[2][1:]
    require(frame[:8] == b'ZOLNPAY1' and frame[8:10] == b'\1\0' and
            frame[10:26] == b'ZolanaNativePay!' and frame[26:58] == NETWORK, 'native envelope domain changed')
    inner = frame[102:]
    require(len(inner) == 9230 and int.from_bytes(frame[98:102], 'little') == len(inner), 'inner proof payload length changed')
    require(hashlib.blake2b(inner, digest_size=32, person=b'NativeStageV1!!!').digest() == frame[66:98],
            'inner payment identity mismatch')
    require(inner[:8] == b'NPAY0003' and inner[8:40] == NETWORK and inner[40:48] == frame[58:66] and
            inner[56:88] == keys[0] and int.from_bytes(inner[48:56], 'little', signed=True) == 2 and
            int.from_bytes(inner[88:96], 'little') == 2 and inner[129] == 2, 'V3 signed context changed')
    nullifiers = [inner[130 + i * 884:162 + i * 884] for i in range(2)]
    markers = [pda([b'native-payment-spent-v1', POOL, nf]) for nf in nullifiers]
    require(payment[1] == [POOL, keys[0], bytes(32), *markers], 'proof-derived native account bindings changed')
    return {b58(address): b'NSPENT01' + nf for address, nf in zip(markers, nullifiers)}


def read_artifacts(directory, host):
    result = load(directory / 'result.json')
    require(result['status'] == 'passed' and result['network'] == host['network'], 'complete matching acceptance result required')
    require(result['private_balances'] == dict(alice=855, bob=68, charlie=67), 'acceptance final balances changed')
    normal = load(directory / 'normal-payments.json')
    require(len(normal) == 3, 'three normal payments required')
    packets = []
    for value in normal:
        prepared, receipt = value['prepared'], value['receipt']
        require(receipt['accepted'] and receipt['encrypted_checkpoints_durable'], 'normal payment not durably accepted')
        path = Path(prepared['raw_packet_file']).resolve(strict=True)
        require(path.is_relative_to(directory), 'packet artifact escaped owned acceptance directory')
        require(path.stat().st_size == 9676, 'packet artifact size changed')
        packets.append((receipt['signature'], receipt['packet_sha256'], path.read_bytes()))
        require(prepared['signature'] == receipt['signature'] and prepared['packet_sha256'] == receipt['packet_sha256'],
                'normal preparation and acceptance differ')
    events = result['events']
    for kind in ['actual_admitted_ack_lost_and_recovered', 'client_sigkill_original_packet_recovered']:
        matches = [event['receipt'] for event in events if event['kind'] == kind]
        require(len(matches) == 1 and matches[0]['accepted'] and matches[0]['encrypted_checkpoints_durable'],
                'unique successful recovery receipt required')
        receipt = matches[0]
        if kind == 'actual_admitted_ack_lost_and_recovered':
            intent = load(directory / 'ack-loss-original-intent.json', 64000)
            require(intent['signature'] == receipt['signature'] and intent['packet_sha256'] == receipt['packet_sha256'],
                    'ACK-loss recovery replaced original signed identity')
            raw = base64.b64decode(intent['packet'], validate=True)
        else:
            path = directory / 'wallets' / (receipt['signature'] + '.packet')
            require(path.stat().st_size == 9676, 'SIGKILL original packet size changed')
            raw = path.read_bytes()
        packets.append((receipt['signature'], receipt['packet_sha256'], raw))
    require(len({signature for signature, _, _ in packets}) == 5, 'five distinct private signatures required')
    expected = {}
    for signature, sha, raw in packets:
        markers = private_packet(raw, signature, sha, host['mac_relay'])
        require(not expected.keys() & markers.keys(), 'private payment reused a nullifier')
        expected.update(markers)
    deposit = []
    for path in sorted(directory.glob('client-*.stdout')):
        require(path.stat().st_size <= MAX_FILE, 'client evidence exceeds bound')
        for line in path.read_text().splitlines():
            value = json.loads(line).get('result', {})
            if value.get('balance') == 1000 and isinstance(value.get('receipt'), dict) and value['receipt'].get('staging_account'):
                deposit.append(value['receipt']['signature'])
    require(len(set(deposit)) == 1, 'unique original staged-deposit receipt required in client evidence')
    return packets, expected, deposit[0]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('RPC redirect refused')


class Rpc:
    def __init__(self, url):
        parsed = urllib.parse.urlsplit(url)
        require(parsed.scheme == 'http' and parsed.hostname == '127.0.0.1' and parsed.port and
                not parsed.username and not parsed.password and parsed.path in ('', '/') and
                not parsed.query and not parsed.fragment, 'explicit RPC must be loopback HTTP')
        self.url = url
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, method, params):
        require(method in {'getGenesisHash', 'getSignatureStatuses', 'getTransaction', 'getBlock',
                           'getAccountInfo', 'getProgramAccounts'}, 'non-read RPC refused')
        request = urllib.request.Request(self.url,
            json.dumps(dict(jsonrpc='2.0', id=1, method=method, params=params)).encode(),
            headers={'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=6) as response:
            raw = response.read(MAX_FILE + 1)
        require(len(raw) <= MAX_FILE, 'RPC response exceeds audit bound')
        value = json.loads(raw)
        require(value.get('id') == 1 and 'error' not in value and 'result' in value, 'read RPC failed: ' + method)
        return value['result']


def pool_state(raw, context):
    require(len(raw) == POOL_BYTES and raw[:8] == b'NPOOL004' and raw[8:40] == NETWORK, 'V4 pool layout/network mismatch')
    floor, backing, count = struct.unpack_from('<QQQ', raw, 40)
    require(backing == 990 and count == 12, 'pool backing/note count differs from all six accepted payments')
    for index in range(32):
        node = raw[64 + index * 32:96 + index * 32]
        require((int.from_bytes(node, 'little') < PALLAS_BASE) if count & (1 << index) else node == bytes(32),
                'noncanonical V4 frontier encoding')
    length = int.from_bytes(raw[1088:1092], 'little')
    require(60 <= length <= 24636 and raw[1092 + length:] == bytes(POOL_BYTES - 1092 - length), 'V4 history length/padding mismatch')
    history = raw[1092:1092 + length]
    require(history[:8] == b'ZOLANCH1' and history[8:10] == b'\1\0' and history[10:26] == b'ZolanaSlotRoots1' and
            history[26:58] == NETWORK, 'V4 history domain mismatch')
    entries = int.from_bytes(history[58:60], 'little')
    require(0 < entries <= 512 and len(history) == 60 + 48 * entries, 'V4 checkpoint count mismatch')
    checkpoints = []
    for offset in range(60, len(history), 48):
        slot, notes = struct.unpack_from('<QQ', history, offset)
        root = history[offset + 16:offset + 48]
        require(notes % 2 == 0 and notes <= count and root != bytes(32) and int.from_bytes(root, 'little') < PALLAS_BASE,
                'noncanonical V4 checkpoint entry')
        if checkpoints:
            old_slot, old_notes, old_root = checkpoints[-1]
            require(slot > old_slot and notes >= old_notes and ((notes == old_notes) == (root == old_root)),
                    'V4 checkpoint progress changed')
        checkpoints.append((slot, notes, root))
    require(checkpoints[-1][0] == context and checkpoints[-1][1] == count and
            checkpoints[-1][0] - checkpoints[0][0] < 512, 'pool checkpoint is not the finalized context')
    return dict(rent_floor=floor, backing=backing, note_count=count,
                root=checkpoints[-1][2].hex(), context_slot=context,
                frontier_sha256=hashlib.sha256(raw[64:1088]).hexdigest(),
                checkpoint_count=entries, pool_sha256=hashlib.sha256(raw).hexdigest())


def decode_account(account):
    require(account['owner'] == b58(PROGRAM) and not account['executable'] and account['data'][1] == 'base64',
            'native account owner/encoding changed')
    return base64.b64decode(account['data'][0], validate=True)


def audit_peer(url, host, packets, expected, deposit):
    rpc = Rpc(url)
    require(rpc.call('getGenesisHash', []) == host['network']['genesis_hash'], 'validator genesis differs')
    signatures = [packet[0] for packet in packets] + [deposit]
    statuses = rpc.call('getSignatureStatuses', [signatures, {'searchTransactionHistory': True}])['value']
    require(len(statuses) == 6, 'signature status omitted')
    slots, block_hashes, deposit_markers = {}, {}, None
    for index, (signature, status) in enumerate(zip(signatures, statuses)):
        require(status is not None and status['err'] is None and status['confirmationStatus'] == 'finalized',
                'payment is not successfully finalized on every peer')
        slot = status['slot']
        value = rpc.call('getTransaction', [signature, {'encoding': 'base64', 'commitment': 'finalized', 'maxSupportedTransactionVersion': 1}])
        require(value is not None and value['slot'] == slot and value['meta']['err'] is None, 'canonical transaction slot/success differs')
        raw = base64.b64decode(value['transaction'][0], validate=True)
        require(value['transaction'][1] == 'base64' and transaction(raw)[0][0] == signature, 'transaction signature/wire differs')
        if index < 5:
            require(raw == packets[index][2], 'canonical transaction replaced/truncated original proof packet')
        else:
            finals = [ix for ix in transaction(raw)[3] if ix[0] == PROGRAM and ix[2] == b'\3']
            require(len(finals) == 1 and len(finals[0][1]) == 6 and finals[0][1][0] == POOL,
                    'deposit receipt lacks canonical native staged finalization')
            deposit_markers = [b58(key) for key in finals[0][1][4:6]]
        if slot not in block_hashes:
            block = rpc.call('getBlock', [slot, {'encoding': 'base64', 'transactionDetails': 'full', 'rewards': False,
                                              'commitment': 'finalized', 'maxSupportedTransactionVersion': 1}])
            require(block is not None, 'finalized payment block unavailable')
            block_hashes[slot] = (block['blockhash'], block['previousBlockhash'], block['parentSlot'])
            encoded = [(base64.b64decode(item['transaction'][0], validate=True), item['meta']) for item in block['transactions']]
        else:
            block = rpc.call('getBlock', [slot, {'encoding': 'base64', 'transactionDetails': 'full', 'rewards': False,
                                              'commitment': 'finalized', 'maxSupportedTransactionVersion': 1}])
            encoded = [(base64.b64decode(item['transaction'][0], validate=True), item['meta']) for item in block['transactions']]
        require(sum(wire == raw and meta['err'] is None for wire, meta in encoded) == 1,
                'full original transaction missing/duplicated in finalized block')
        slots[signature] = slot
    require(len(set(deposit_markers)) == 2 and not set(deposit_markers) & expected.keys(), 'deposit nullifiers overlap private payments')
    markers_response = rpc.call('getProgramAccounts', [b58(PROGRAM), {'encoding': 'base64', 'commitment': 'finalized',
                                               'withContext': True, 'filters': [{'dataSize': 40}]}])
    require(len(markers_response['value']) == 12, 'exactly twelve permanent marker accounts required')
    markers = {}
    for item in markers_response['value']:
        address, account = item['pubkey'], item['account']
        raw = decode_account(account)
        require(len(raw) == 40 and raw[:8] == b'NSPENT01' and account['lamports'] == 1 and
                b58(pda([b'native-payment-spent-v1', POOL, raw[8:]])) == address, 'permanent nullifier account invalid')
        markers[address] = hashlib.sha256(raw).hexdigest()
        if address in expected:
            require(raw == expected[address], 'proof-derived marker data differs')
    require(set(markers) == expected.keys() | set(deposit_markers), 'marker addresses differ from canonical deposit/private transactions')
    for _ in range(8):
        response = rpc.call('getAccountInfo', [b58(POOL), {'encoding': 'base64', 'commitment': 'finalized'}])
        try:
            account = response['value']
            state = pool_state(decode_account(account), response['context']['slot'])
            require(account['lamports'] == state['rent_floor'] + 990, 'pool lamports/backing accounting differs')
            require(state['context_slot'] >= max(slots.values()), 'pool context precedes accepted payments')
            break
        except ValueError:
            time.sleep(.1)
    else:
        raise ValueError('no coherent finalized V4 pool/checkpoint account')
    return dict(slots=slots, blocks=block_hashes, pool=state, markers=markers, deposit_markers=deposit_markers)


@contextmanager
def forwarded(host, overrides):
    if overrides:
        require(len(overrides) == 3, 'exactly three explicit --rpc forwards required')
        yield overrides
        return
    target, identity, known_hosts = pilot_ssh()
    reservations = [socket.socket() for _ in range(3)]
    for reservation in reservations:
        reservation.bind(('127.0.0.1', 0))
    ports = [reservation.getsockname()[1] for reservation in reservations]
    for reservation in reservations:
        reservation.close()
    command = ['ssh', '-F', '/dev/null', '-i', identity, '-o', 'IdentitiesOnly=yes',
        '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + known_hosts,
        '-o', 'ConnectTimeout=15', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=10', '-N']
    for port, peer in zip(ports, host['peers']):
        command += ['-L', f'127.0.0.1:{port}:' + peer['rpc']]
    process = subprocess.Popen(command + [target], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 20
        while True:
            require(process.poll() is None, 'operator-pinned SSH forwarding exited')
            with socket.socket() as probe:
                if probe.connect_ex(('127.0.0.1', ports[0])) == 0:
                    break
            require(time.monotonic() < deadline, 'operator-pinned SSH readiness timed out')
            time.sleep(.05)
        yield ['http://127.0.0.1:' + str(port) for port in ports]
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-evidence', required=True, type=Path)
    parser.add_argument('--acceptance-directory', required=True, type=Path)
    parser.add_argument('--rpc', action='append', help='existing pinned loopback forward; repeat exactly three times')
    parser.add_argument('--output', type=Path, help='new owner-only sanitized audit report')
    args = parser.parse_args()
    os.umask(0o077)
    host = host_ready(args.host_evidence.resolve(strict=True))
    directory = args.acceptance_directory.resolve(strict=True)
    packets, expected, deposit = read_artifacts(directory, host)
    with forwarded(host, args.rpc) as urls:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(audit_peer, url, host, packets, expected, deposit) for url in urls]
            peers = [future.result(timeout=180) for future in futures]
    for peer in peers[1:]:
        require(peer['slots'] == peers[0]['slots'] and peer['blocks'] == peers[0]['blocks'] and
                peer['markers'] == peers[0]['markers'] and peer['deposit_markers'] == peers[0]['deposit_markers'],
                'validators disagree on finalized payment slots, blocks or permanent markers')
        require(all(peer['pool'][field] == peers[0]['pool'][field] for field in
                    ['rent_floor', 'backing', 'note_count', 'root', 'frontier_sha256']),
                'validators disagree on canonical pool effects')
    report = dict(status='passed', scope='Read-only trusted three-validator RPC audit; no light-client or independent proof/tree recomputation claim',
        genesis_hash=host['network']['genesis_hash'], network_byte=67, pool_format='NPOOL004',
        private_payments=[dict(signature=signature, slot=peers[0]['slots'][signature], packet_bytes=len(raw), packet_sha256=sha)
                          for signature, sha, raw in packets],
        staged_deposit_signature=deposit, deposit_slot=peers[0]['slots'][deposit],
        permanent_marker_count=12, marker_lamports_each=1, marker_set_sha256=hashlib.sha256(
            json.dumps(peers[0]['markers'], sort_keys=True).encode()).hexdigest(),
        peers=[dict(identity=identity['identity'], **peer['pool']) for identity, peer in zip(host['peers'], peers)])
    encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        with args.output.open('x') as output:
            output.write(encoded); output.flush(); os.fsync(output.fileno())
    print(encoded, end='')


if __name__ == '__main__':
    main()
