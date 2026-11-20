"""Stand-in for `native-wallet archive` in the first-sync mirror tests. Loopback only.

It has the real collector's command line, store layout and result line, and none of its
verification: no signature, proof, note tree, nullifier or pool is checked here. What it does
check is what the tests need a collector to notice: the node serves the expected network, the
retained store is intact and still ends on a block the node has, and every new block continues
the one before. Everything it retains is the public content the stand-in node served.

  first_sync_collector_stand_in.py archive --network FILE --rpc http://127.0.0.1:PORT --history DIRECTORY
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import urllib.parse

HEADER = {'transactionDetails': 'none', 'rewards': False, 'commitment': 'finalized'}
FULL = {'encoding': 'base64', 'transactionDetails': 'full', 'rewards': False, 'commitment': 'finalized',
        'maxSupportedTransactionVersion': 0}
SEGMENT_BLOCKS = 1024


def digest(data):
    return hashlib.blake2b(data, digest_size=32, person=b'NPayArchiveV1').hexdigest()


def write(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def main(argv):
    if len(argv) != 7 or argv[0] != 'archive' or argv[1::2] != ['--network', '--rpc', '--history']:
        raise SystemExit('archive --network FILE --rpc URL --history DIRECTORY')
    profile = json.loads(Path(argv[2]).read_bytes())
    network = {key: profile[key] for key in ('network', 'genesis_hash')}
    address = urllib.parse.urlsplit(argv[4])
    history = Path(argv[6])
    connection = http.client.HTTPConnection(address.hostname, address.port, timeout=20)

    def rpc(method, params):
        connection.request('POST', '/', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}),
                           {'Content-Type': 'application/json'})
        response = connection.getresponse()
        value = json.loads(response.read())
        if response.status != 200 or 'result' not in value:
            raise SystemExit('the node did not answer ' + method)
        return value['result']

    if rpc('getGenesisHash', []) != network['genesis_hash']:
        raise SystemExit('the node serves another network')
    # The retained store, read again in full before anything is added to it.
    descriptors, slot, blockhash, height = [], 0, network['genesis_hash'], 0
    manifest = history / 'manifest.json'
    if manifest.exists():
        value = json.loads(manifest.read_bytes())
        if value.get('format') != 'native-payment-history-v1' or value.get('network') != network:
            raise SystemExit('the retained store belongs to another network')
        descriptors = value['segments']
        for index, descriptor in enumerate(descriptors):
            data = (history / ('segment-%08d-%s.json' % (index, descriptor['digest']))).read_bytes()
            if digest(data) != descriptor['digest']:
                raise SystemExit('a retained segment differs from its checksum')
            for block in json.loads(data):
                if block['parent_slot'] != slot or block['previous_blockhash'] != blockhash or block['block_height'] != height + 1:
                    raise SystemExit('the retained store is not continuous')
                slot, blockhash, height = block['slot'], block['blockhash'], block['block_height']
        if slot and rpc('getBlock', [slot, HEADER])['blockhash'] != blockhash:
            raise SystemExit('the retained store ends on a block the node does not have')
    target = rpc('getSlot', [{'commitment': 'finalized'}])
    if target < slot:
        raise SystemExit('the node is behind the retained store')
    added = []
    for start in range(slot + 1, target + 1, 10000):
        for produced in rpc('getBlocks', [start, min(start + 9999, target), {'commitment': 'finalized'}]):
            block = rpc('getBlock', [produced, FULL])
            if block['parentSlot'] != slot or block['previousBlockhash'] != blockhash or block['blockHeight'] != height + 1:
                raise SystemExit('the node served a block that does not continue the one before')
            slot, blockhash, height = produced, block['blockhash'], block['blockHeight']
            added.append({'slot': slot, 'parent_slot': block['parentSlot'], 'blockhash': blockhash,
                          'previous_blockhash': block['previousBlockhash'], 'block_height': height,
                          'transactions': block['transactions']})
    if slot != target:
        raise SystemExit('the finalized slot has no block')
    for start in range(0, len(added), SEGMENT_BLOCKS):
        blocks = added[start:start + SEGMENT_BLOCKS]
        data = json.dumps(blocks, separators=(',', ':')).encode()
        descriptors.append({'first_slot': blocks[0]['slot'], 'last_slot': blocks[-1]['slot'], 'count': len(blocks),
                            'digest': digest(data)})
        write(history / ('segment-%08d-%s.json' % (len(descriptors) - 1, descriptors[-1]['digest'])), data)
    if added or not manifest.exists():
        # Segments first, the manifest last and in one step, as the real collector publishes.
        temporary = history / ('.manifest-%s.tmp' % os.urandom(8).hex())
        write(temporary, json.dumps({'format': 'native-payment-history-v1', 'network': network, 'segments': descriptors},
                                    separators=(',', ':')).encode())
        os.replace(temporary, manifest)
    # The real collector reports how many payments it verified; this one verifies none.
    print(json.dumps({'manifest_committed': True, 'finalized_slot': slot, 'new_blocks': len(added),
                      'payments_verified': 0}))


if __name__ == '__main__':
    main(sys.argv[1:])
