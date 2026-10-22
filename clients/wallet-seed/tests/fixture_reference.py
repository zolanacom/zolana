"""Reproduce PUBLIC SYNTHETIC test vectors, never production keys or backups.

Optional audit helper; not a runtime/test-suite dependency. Uses Python's PBKDF2
and cryptography's OpenSSL-backed ChaCha primitives, independently of RustCrypto.
HChaCha is extracted from the block function by removing feed-forward, then
checked against draft-irtf-cfrg-xchacha-03 section 2.2.1 before fixture use:
https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#section-2.2.1
That document is an expired Internet-Draft, not an adopted IETF standard.
"""
import hashlib
import json
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def hchacha(key, nonce):
    initial = struct.unpack('<16I', b'expand 32-byte k' + key + nonce)
    block = Cipher(algorithms.ChaCha20(key, nonce), mode=None).encryptor().update(bytes(64))
    final = struct.unpack('<16I', block)
    return struct.pack('<8I', *((final[i] - initial[i]) & 0xffffffff for i in (0, 1, 2, 3, 12, 13, 14, 15)))


assert hchacha(bytes(range(32)), bytes.fromhex('000000090000004a0000000031415927')).hex() == (
    '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc')
salt, nonce = bytes(range(16, 32)), bytes(range(32, 56))
network = dict(network=[7] * 32, genesis_hash='1' * 32)
aad = json.dumps(['native-wallet-seed-v1', network, 600000, list(salt), list(nonce)], separators=(',', ':')).encode()
key = hashlib.pbkdf2_hmac('sha256', b'native codec fixture password', salt, 600000, 32)
ciphertext = ChaCha20Poly1305(hchacha(key, nonce[:16])).encrypt(bytes(4) + nonce[16:], bytes(range(32)), aad)
assert key.hex() == '38719be52e3a28e54fbde58c22b0c4d4ce0e9a476b8032cbb58149cf45a82679'
assert ciphertext.hex() == 'f5805ebd5b68ffb1488e0ff166d96214e7aa9922d115c5a2e055618909ef4e32be4d2078456e8e169ca57211f6696695'
print('Public synthetic seed codec reference vector passed; no user wallet input.')
