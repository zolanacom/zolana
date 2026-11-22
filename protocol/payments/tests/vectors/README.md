# Protocol test vectors

These files are written by `protocol/payments/tests/protocol_vectors.rs` from this crate's own encoders, decoders, verifier and state transition. That test regenerates every JSON file on each run and compares it with the copy here, so the files change only together with the code. [`docs/protocol-spec.md`](../../../../docs/protocol-spec.md) states the formats and rules the vectors exercise; its section 14 says how the files are produced and checked.

Every key in these files is public test material. The network domain `a0 a1 .. bf` is synthetic. Nothing here describes a running network.

| File | Contents |
| --- | --- |
| `payloads/*.hex` | Four payments with real proofs, one per line of hexadecimal: a deposit, a private send, a payment with a shielded fee and a withdrawal to a bound recipient. Each spends notes created by the ones before it. |
| `payments.json` | The four payments field by field, their authorization digests with every intermediate value, what the test wallets can decrypt, decoder cases and verification cases. |
| `envelope.json` | The frame around the fee payment, the slots in which it decodes, and decoder cases. |
| `staging.json` | Payload digests, a staging account through initialization, every write, sealing and consumption, and stored accounts the decoder accepts or refuses. |
| `anchors.json` | Slot checkpoint histories: records accepted and refused, the roots a slot may use, the largest history, and decoder cases. |
| `pool.json` | Empty-tree constants, tree hash samples, the four payments applied to an `NPOOL003` pool and to an `NPOOL004` pool slot by slot, root rotation, capacity limits, and decoder cases. |
| `accounts.json` | The program address, the pool address and the marker address of every nullifier in the four payments, with seeds and bump. |

`tools/protocol_vectors_test.py` reads the same files from the other side: it implements the decoders, digests and address derivation from the specification alone and requires its results to equal the ones recorded here.

## Conventions

- Byte strings are lowercase hexadecimal. Numbers are decimal integers of up to 64 bits, signed where the field is signed; a reader that keeps numbers as floating point loses digits above 2^53. Addresses that are named `address`, `program_id` or after a role are base58.
- A `result` is `ok` or the name of the error the code returns.
- An object with `bytes`, `prefix_hex` and `blake2b_256` stands for `bytes` bytes: the prefix followed by zero bytes. The digest is BLAKE2b with a 32-byte output, no key and no personalization, over the whole.
- A case with `base` and `edits` is the base encoding with the edits applied in order. `replace` overwrites bytes from offset `at`; `remove` deletes `length` bytes at `at`; `truncate` cuts to `to` bytes; `append` adds bytes; `zero_extend` adds zero bytes up to `to` bytes.
- Offsets count from zero.

## Regenerating

After an intended change of a format, a rule or an error, rewrite the JSON files and review the difference:

```sh
WRITE_PROTOCOL_VECTORS=1 sh tools/dev.sh test --offline --locked -p native-payments --test protocol_vectors
```

The four payments are read from `payloads/`, not rebuilt, on an ordinary run: the test requires the verifier to accept each of them. An ignored test rebuilds them from fixed keys and a fixed byte stream and compares the result with the files; with `PROTOCOL_VECTORS_PROVE=1` it rewrites them. A change of the payment encoding, of the authorization digest or of the proof system needs that step first:

```sh
PROTOCOL_VECTORS_PROVE=1 sh tools/dev.sh test --offline --locked -p native-payments --test protocol_vectors -- --ignored
```
