"""Lossless bounded retained-header transport; not canonical inclusion evidence.

The first parent/hash are explicit. Each record contains canonical unsigned
LEB128 slot and height deltas followed by the complete 32-byte block hash.
Height starts at zero; only the first height delta may be zero. Transactions
remain their original JSON values in an ordered sparse table.
"""
import base64
import binascii

from history_retention import block_hash, natural

FORMAT = 'zolana-retained-headers-v1'
MAX_HEADERS = 32768
U64_MAX = 2**64 - 1
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_HASH_DIGITS = {char: digit for digit, char in enumerate(ALPHABET)}
HEADER_KEYS = {'format', 'count', 'parent_slot', 'previous_blockhash', 'data_base64'}
BLOCK_KEYS = {'slot', 'parent_slot', 'blockhash', 'previous_blockhash',
              'block_height', 'transactions'}


def hash_bytes(text):
    if not isinstance(text, str) or not 32 <= len(text) <= 44:
        raise ValueError('invalid compact block hash')
    value = 0
    for char in text:
        digit = _HASH_DIGITS.get(char)
        if digit is None:
            raise ValueError('invalid compact block hash')
        value = value * 58 + digit
    if len(text) - len(text.lstrip('1')) + (value.bit_length() + 7) // 8 != 32:
        raise ValueError('invalid compact block hash')
    return value.to_bytes(32, 'big')


def hash_text(raw):
    if len(raw) != 32:
        raise ValueError('invalid compact hash length')
    zeros = len(raw) - len(raw.lstrip(b'\0'))
    value = int.from_bytes(raw, 'big')
    output = ''
    while value:
        value, digit = divmod(value, 58)
        output = ALPHABET[digit] + output
    return '1' * zeros + output


def varint(value):
    if not natural(value):
        raise ValueError('invalid compact unsigned integer')
    output = bytearray()
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return output


def read_varint(data, offset):
    start, value = offset, 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError('truncated compact integer')
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ValueError('compact integer overflow')
        value |= (byte & 127) << (7 * index)
        if byte < 128:
            if data[start:offset] != varint(value):
                raise ValueError('noncanonical compact integer')
            return value, offset
    raise ValueError('compact integer overflow')


def pack_blocks(blocks):
    if not isinstance(blocks, list) or len(blocks) > MAX_HEADERS:
        raise ValueError('invalid compact header count')
    if not blocks:
        return ({'format': FORMAT, 'count': 0, 'parent_slot': None,
                 'previous_blockhash': None, 'data_base64': ''}, [])
    first = blocks[0]
    if (not isinstance(first, dict) or set(first) != BLOCK_KEYS or
            not natural(first['parent_slot'])):
        raise ValueError('invalid compact header schema')
    previous_slot = first['parent_slot']
    previous_hash = first['previous_blockhash']
    hash_bytes(previous_hash)
    height, data, transactions = 0, bytearray(), []
    for index, block in enumerate(blocks):
        if (not isinstance(block, dict) or set(block) != BLOCK_KEYS or
                not natural(block['slot']) or block['slot'] <= previous_slot or
                block['parent_slot'] != previous_slot or type(block['parent_slot']) is not int or
                block['previous_blockhash'] != previous_hash or
                not natural(block['block_height']) or
                (block['block_height'] < height if index == 0 else block['block_height'] <= height) or
                not isinstance(block['transactions'], list)):
            raise ValueError('compact header continuity mismatch')
        data.extend(varint(block['slot'] - previous_slot))
        data.extend(varint(block['block_height'] - height))
        data.extend(hash_bytes(block['blockhash']))
        if block['transactions']:
            transactions.append([index, block['transactions']])
        previous_slot, previous_hash, height = block['slot'], block['blockhash'], block['block_height']
    return ({'format': FORMAT, 'count': len(blocks), 'parent_slot': first['parent_slot'],
             'previous_blockhash': first['previous_blockhash'],
             'data_base64': base64.b64encode(data).decode('ascii')}, transactions)


def unpack_blocks(headers, transactions):
    """Reference decoder used by cross-language fixtures and boundary tests."""
    if (not isinstance(headers, dict) or set(headers) != HEADER_KEYS or
            headers['format'] != FORMAT or type(headers['count']) is not int or
            not 0 <= headers['count'] <= MAX_HEADERS or
            not isinstance(headers['data_base64'], str) or
            not isinstance(transactions, list)):
        raise ValueError('invalid compact header schema')
    count, text = headers['count'], headers['data_base64']
    # Two at-most-ten-byte integers and one complete hash per header.
    if len(text) > ((count * 52 + 2) // 3) * 4:
        raise ValueError('compact header byte bound exceeded')
    try:
        data = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('invalid compact base64') from error
    if base64.b64encode(data).decode('ascii') != text:
        raise ValueError('noncanonical compact base64')
    if count == 0:
        if (data or transactions or headers['parent_slot'] is not None or
                headers['previous_blockhash'] is not None):
            raise ValueError('invalid empty compact page')
        return []
    if not natural(headers['parent_slot']):
        raise ValueError('invalid compact parent slot')
    hash_bytes(headers['previous_blockhash'])
    if len(transactions) > count:
        raise ValueError('compact transaction table exceeds header count')
    sparse, last_index = {}, -1
    for row in transactions:
        if (not isinstance(row, list) or len(row) != 2 or type(row[0]) is not int or
                not last_index < row[0] < count or
                not isinstance(row[1], list) or not row[1]):
            raise ValueError('invalid compact transaction table')
        last_index = row[0]
        sparse[row[0]] = row[1]
    slot, previous_hash, height, offset, blocks = headers['parent_slot'], headers['previous_blockhash'], 0, 0, []
    for index in range(count):
        slot_delta, offset = read_varint(data, offset)
        height_delta, offset = read_varint(data, offset)
        if (slot_delta == 0 or (index > 0 and height_delta == 0) or
                slot_delta > U64_MAX - slot or height_delta > U64_MAX - height):
            raise ValueError('compact header order or overflow')
        if offset + 32 > len(data):
            raise ValueError('truncated compact block hash')
        current_hash = hash_text(data[offset:offset+32])
        offset += 32
        blocks.append({'slot': slot + slot_delta, 'parent_slot': slot,
                       'blockhash': current_hash, 'previous_blockhash': previous_hash,
                       'block_height': height + height_delta,
                       'transactions': sparse.get(index, [])})
        slot, previous_hash, height = slot + slot_delta, current_hash, height + height_delta
    if offset != len(data):
        raise ValueError('trailing compact header bytes')
    return blocks
