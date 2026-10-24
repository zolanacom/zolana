"""Differential acceptance and exact bytes against the frozen pre-change decoder."""
import random
import unittest

from gateway_history_codec import hash_bytes, hash_text


# Frozen from history_retention.block_hash and gateway_history_codec.hash_bytes
# before this change (codec source SHA256 2db5f29d087ac3fa68c0deca1298bdfb
# 13c5d6bc839163f1975a7ff5a6265572). Keep independent of the current validator.
_OLD_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def old_hash_bytes(text):
    if not isinstance(text, str) or not 32 <= len(text) <= 44:
        raise ValueError('invalid compact block hash')
    number = 0
    for char in text:
        if char not in _OLD_ALPHABET:
            raise ValueError('invalid compact block hash')
        number = number * 58 + _OLD_ALPHABET.index(char)
    if len(text) - len(text.lstrip('1')) + (number.bit_length() + 7) // 8 != 32:
        raise ValueError('invalid compact block hash')
    value = 0
    for char in text:
        value = value * 58 + _OLD_ALPHABET.index(char)
    return value.to_bytes(32, 'big')


def outcome(decoder, text):
    try:
        return ('bytes', decoder(text))
    except ValueError as error:
        return ('error', type(error), str(error))


class CompactHashDifferentialTests(unittest.TestCase):
    def test_random_valid_hashes_return_original_exact32bytes(self):
        rng = random.Random(231091)
        for _ in range(2048):
            raw = rng.randbytes(32)
            encoded = hash_text(raw)
            self.assertEqual(hash_bytes(encoded), raw)
            self.assertEqual(hash_bytes(encoded), old_hash_bytes(encoded))

    def test_all_leading_zero_boundaries_and_valid_extremes(self):
        for zeros in range(33):
            raw = bytes(zeros) + (b'\1' + bytes([255]) * (31 - zeros) if zeros < 32 else b'')
            encoded = hash_text(raw)
            self.assertEqual(hash_bytes(encoded), raw)
            self.assertEqual(outcome(hash_bytes, encoded), outcome(old_hash_bytes, encoded))
        for raw in (bytes(32), bytes([255]) * 32, b'\x80' + bytes(31), bytes(31) + b'\1'):
            self.assertEqual(hash_bytes(hash_text(raw)), raw)

    def test_invalid_types_lengths_alphabet_overflow_and_non32byte_values(self):
        malformed = [None, True, False, 0, 1, 1.5, b'1' * 32, bytearray(32), [], {},
                     '', '1' * 31, '1' * 33, '1' * 44, '1' * 45, '2' * 32,
                     'z' * 44, 'z' * 45, '1' + 'z' * 43,
                     '0' * 32, 'O' * 32, 'I' * 32, 'l' * 32, ' ' * 32,
                     '\0' * 32, '☃' * 32, '\n' + '1' * 31, '1' * 31 + '\t']
        for value in malformed:
            with self.subTest(value=repr(value)):
                self.assertEqual(outcome(hash_bytes, value), outcome(old_hash_bytes, value))
                self.assertEqual(outcome(hash_bytes, value), ('error', ValueError, 'invalid compact block hash'))

    def test_malformed_hashes_differential_randomized_boundaries(self):
        rng = random.Random(91231)
        chars = _OLD_ALPHABET + '0OIl !☃\0\n'
        for _ in range(2048):
            value = ''.join(rng.choice(chars) for _ in range(rng.randrange(28, 48)))
            self.assertEqual(outcome(hash_bytes, value), outcome(old_hash_bytes, value))


if __name__ == '__main__':
    unittest.main()
