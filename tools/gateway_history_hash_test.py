"""Cold segment hash acceptance and error parity with the frozen validator."""
import builtins
import json
from pathlib import Path
import random
import types
import unittest
from unittest.mock import patch

import gateway_history
from gateway_history_codec import hash_text
from history_retention_test import NETWORK, block


def old_valid_hash(value):
    # Frozen history_retention.block_hash, source f26a3b73...8268e441f2.
    if not isinstance(value, str) or not 32 <= len(value) <= 44:
        return False
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    number = 0
    for char in value:
        if char not in alphabet:
            return False
        number = number * 58 + alphabet.index(char)
    return len(value) - len(value.lstrip('1')) + (number.bit_length() + 7) // 8 == 32


def old_decoder(value):
    if not old_valid_hash(value):
        raise ValueError('invalid compact block hash')
    return bytes(32)  # The segment validator uses acceptance, not decoded bytes.


class ColdSegmentHashTests(unittest.TestCase):
    def validate(self, value, field, old=False):
        reader = gateway_history.History.__new__(gateway_history.History)
        reader.network = NETWORK
        row = dict(block(2), **{field: value})
        data = json.dumps([row], separators=(',', ':')).encode()
        descriptor = {'first_slot': 2, 'last_slot': 2, 'count': 1}
        try:
            if old:
                with patch('gateway_history_codec.hash_bytes', old_decoder):
                    result = reader._validate_segment(data, descriptor, 1)
            else:
                result = reader._validate_segment(data, descriptor, 1)
            return 'accepted', result
        except ValueError as error:
            return 'refused', type(error), str(error)

    def test_random_valid_hashes_and_all_leading_zero_boundaries_preserve_records(self):
        rng = random.Random(91032)
        values = [hash_text(rng.randbytes(32)) for _ in range(512)]
        values += [hash_text(bytes(n) + (b'\1' + bytes([255]) * (31-n) if n < 32 else b''))
                   for n in range(33)]
        for value in values:
            for field in ('blockhash', 'previous_blockhash'):
                actual = self.validate(value, field)
                self.assertEqual(actual[0], 'accepted')
                self.assertEqual(actual, self.validate(value, field, old=True))

    def test_malformed_types_lengths_alphabet_overflow_keep_original_continuity_error(self):
        values = [None, True, False, 0, 1.5, [], {}, '', '1'*31, '1'*33, '1'*44,
                  '1'*45, '2'*32, 'z'*44, '1'+'z'*43, '0'*32, 'O'*32,
                  'I'*32, 'l'*32, ' '*32, '\0'*32, '☃'*32, '1'*31+'\n']
        for value in values:
            for field in ('blockhash', 'previous_blockhash'):
                with self.subTest(value=value, field=field):
                    actual = self.validate(value, field)
                    self.assertEqual(actual, ('refused', ValueError, 'retained segment continuity mismatch'))
                    self.assertEqual(actual, self.validate(value, field, old=True))

    def test_randomized_boundary_strings_match_frozen_validator(self):
        rng = random.Random(91033)
        chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0OIl !☃\0\n'
        for _ in range(512):
            value = ''.join(rng.choice(chars) for _ in range(rng.randrange(28, 48)))
            for field in ('blockhash', 'previous_blockhash'):
                self.assertEqual(self.validate(value, field), self.validate(value, field, old=True))

    def test_detached_history_load_does_not_require_codec_until_validation(self):
        loading = [True]
        original = builtins.__import__

        def guarded(name, *args, **kwargs):
            if name == 'gateway_history_codec' and loading[0]:
                raise AssertionError('codec is not yet published by the sealed loader')
            return original(name, *args, **kwargs)

        module = types.ModuleType('detached_cold_history_test')
        module.__dict__['__builtins__'] = dict(vars(builtins), __import__=guarded)
        source = Path(gateway_history.__file__).read_bytes()
        exec(compile(source, gateway_history.__file__, 'exec'), module.__dict__)
        loading[0] = False
        reader = module.History.__new__(module.History)
        reader.network = NETWORK
        result = reader._validate_segment(json.dumps([block(1)]).encode(),
                                          {'first_slot': 1, 'last_slot': 1, 'count': 1}, 0)
        self.assertEqual(result[0], (1,))


if __name__ == '__main__':
    unittest.main()
