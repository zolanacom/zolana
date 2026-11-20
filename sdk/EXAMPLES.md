# SDK examples

Every example is offline: no RPC, no ledger, no funds. The keys are public
fixtures. Run them from the repository root after
`sh tools/dev.sh fetch --locked`.

The outputs below are what the commands printed on Apple Silicon macOS with
Rust 1.92.0. Proofs, ciphertexts and salts are randomized, so digests,
nullifiers, commitments and payment ids differ on every run; everything else is
fixed. Cargo's own build lines and the timings are left out.

The sources are in [`rust-examples/examples/`](rust-examples/examples), each
under 80 lines. Shared by the wallet examples:
[`rust-examples/src/lib.rs`](rust-examples/src/lib.rs) defines the fixture
network and `DemoWallet`, a 32-byte seed that implements `WalletKeys`.

| Example | Crates | Builds proofs |
| --- | --- | --- |
| [`wallet_address`](#wallet_address) | `native-wallet-seed`, `native-wallet-core` | No |
| [`verify_proof`](#verify_proof) | `native-payments`, the `payment-lab` fixture | Yes, two |
| [`wire_message`](#wire_message) | `native-payments`, `native-wallet-core` | Yes, one |
| [`private_payment`](#private_payment) | `native-payments`, `native-wallet-core` | Yes, two |
| [`nullifier_address`](#nullifier_address) | `native-payments` | No |
| [`pool_state`](#pool_state) | `native-payments` | No |

## wallet_address

Derives a wallet from a seed: writes the encrypted recovery file, reads it
back, derives the shielded receiving address and decodes it again.

```sh
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example wallet_address
```

```text
recovery file: format native-wallet-seed-v1, 1259 bytes
wrong password: password is incorrect or encrypted seed was modified
private address: npriv1gZWMfgeB9UAafpZyPa5Pf92AdWqYpJKVgDuHNf7Z7JGnpxQSqAYXtCgvrYcFkwfzSUDXFBDx5gtWuSQnRnGCDr6fVn3Ba7NwiuLA386Xd2dV
same text on another network: receiving address checksum or network mismatch
```

What it shows:

- A wallet is one 32-byte seed, and the seed is the Orchard spending key.
- The recovery file binds the seed to a network; so does the address. The size
  of the file varies by a few bytes between runs.
- The address is the same one the browser core derives for this seed. The test
  `demo_wallet_address_matches_the_browser_core_reference` pins that.

## verify_proof

Takes the repository's proof fixture (Alice deposits 100, then pays Bob 40 and
keeps 60), sends the payment through the staging format and verifies it. Then
it tries three things that must fail.

```sh
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example verify_proof
```

```text
payment: 9222 bytes, tag NPAY0001
staged in 13 chunks, digest 81ec9941bbcd8a50102b0c06afb67395e5c1dd50069181d23606a6b82da2664f
verified: signatures, binding signature and proof
  nullifier  49310197a2513aa8340f7871e07a2f1f15863f9ab4fd993a39ff946a89ca7f3d
  commitment 2b2e53047704ad5fafab6053b5b590d6a3bcdaf79a29291632217b4935f6b91d
  nullifier  fc049102740e899d54dc7cf73031d1ae95b88fc296365d0eee13cfade081b304
  commitment 48da17d9ec84c0e16ffc9ddbf9f6d508f1fe7d313a6f84c7868a285ecb087004
sent a second time: SpentNullifier
one flipped proof bit: InvalidProof
decoded for another network: WrongNetwork
```

What it shows:

- `wire::encode` and `wire::decode`, and `StagedPayload` for the chunked path.
- `PaymentVerifier::verify` needs a `ValidationView`: the current slot, the
  accepted anchors and the spent nullifiers. The verifier is only as
  trustworthy as that view.
- A verified payment yields two nullifiers and two commitments. Recording the
  nullifiers is what stops a second spend.

This is the same fixture as
`sh tools/dev.sh run --offline --locked -p payment-lab -- proof-smoke`.

## wire_message

Builds a deposit with `PaymentProver`, prints the header fields from their byte
offsets, and decodes the payment.

```sh
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example wire_message
```

```text
9222 bytes
tag           NPAY0001
network       0707070707070707070707070707070707070707070707070707070707070707
expiry slot   100
value balance -25
sponsor       5353535353535353535353535353535353535353535353535353535353535353
anchor        ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f
flags 3, actions 2
proof         7264 bytes
decoded and re-encoded to identical bytes
one byte short: InvalidLength
unknown tag: UnsupportedVersion
deposit in an inline envelope: UnsupportedVersion
```

What it shows:

- The layout of an `NPAY0001` payment: a 122-byte header, two 884-byte actions,
  the proof and a 64-byte binding signature. The other two variants insert a
  fee (`NPAY0003`) or a withdrawal recipient (`NPAY0002`) after the sponsor.
- The value balance is negative for a deposit, zero for a private send and
  positive when value leaves the pool.
- The anchor here is the root of the empty note tree.
- Decoding checks shape, not validity. It does not verify the proof.

## private_payment

Two wallets replay the same history. Alice receives a deposit of 100 and pays
Bob 40 with a shielded fee of 3. The program itself plays the chain.

```sh
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example private_payment
```

```text
after the deposit: alice 100, bob 0
payment: 9230 bytes, tag NPAY0003
envelope: 9332 bytes, payment id 809a468bab57a92b8082218a25ddb1607ca9efa3f412b29ac0749927ee7b3687
after the send: alice 57, bob 40
pool: 4 notes, backing 97
the same payment again: SpentNullifier
```

What it shows:

- `WalletState` is one wallet's view of the pool. `accept` verifies a payment
  and finds the notes this wallet can decrypt; `finish_slot` completes a slot so
  that its root can be used as an anchor.
- Alice's balance is 57: 100 less 40 less the fee of 3. The change came back to
  her as a new note. The pool's backing fell by the fee, which is public.
- A shielded-fee payment fits the single-transaction envelope; its id is the
  digest of the payment bytes.

What it leaves out: a real client must not feed payments to `accept` directly.
It takes them from finalized blocks, checks that the blocks are continuous, and
reconciles the result with the on-chain pool account (`Replay`,
`WalletState::reconcile`).

## nullifier_address

Prints the program id, the pool account and the account address of a nullifier.

```sh
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example nullifier_address
```

```text
program id        78kCqctsuUaj7kyV8xNVwXQrqovY3QtSytt4eCYApVUh
pool account      4mJMnxFhRVMQ3aNcyn2LgW8fztTjgckUvaaWrXggdAAL
nullifier         1111111111111111111111111111111111111111111111111111111111111111
nullifier account GuqZuJN89WRqYmKAiu35HeEoXbTzzpn6i4Xadwn8zVeN
```

Pass a nullifier as 64 hex digits to compute its account:

```sh
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example nullifier_address -- ea8b7872edce75282b236f96074726ff673cbb0891be44a759c13cdc73485209
```

```text
program id        78kCqctsuUaj7kyV8xNVwXQrqovY3QtSytt4eCYApVUh
pool account      4mJMnxFhRVMQ3aNcyn2LgW8fztTjgckUvaaWrXggdAAL
nullifier         ea8b7872edce75282b236f96074726ff673cbb0891be44a759c13cdc73485209
nullifier account HfdsUxcRWbfWm4LEmi96Rk7S5mX4URHmgK25yXyRyCKg
```

What it shows: both addresses are program-derived, so anyone can compute them.
A spent note has an account at its nullifier's address. These identifiers are
development values.

## pool_state

Encodes and decodes the pool account in both formats and asks which slots
accept a root.

```sh
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --example pool_state
```

```text
25728 bytes, tag NPOOL004
network        0707070707070707070707070707070707070707070707070707070707070707
rent floor     1000000
backing        0
notes          0
root           ae2935f1dfd8a24aed7c70df7de3a668eb7a49b1319880dde2bbd9031ae5d82f
  slot 0 holds 0 notes
  slot 7 holds 0 notes
root accepted at slot 7: true
root accepted at slot 8: true
root accepted at slot 518: true
root accepted at slot 519: false
3137 bytes, tag NPOOL003
legacy roots   1
truncated account: InvalidEncoding
```

What it shows:

- `PoolState::decode` reads both formats. `NPOOL004` keeps one root per
  completed slot; `NPOOL003` keeps the 64 most recent roots.
- A root recorded for slot 7 is accepted through slot 518 (age 511) and refused
  at slot 519 (age 512). A proof built against an old root stops being valid, so
  a wallet syncs before it proves.

## The tests

```sh
sh tools/dev.sh test --offline --locked -p zolana-sdk-examples
```

```text
running 5 tests
test account_addresses_are_the_published_development_values ... ok
test pool_state_sizes_tags_and_anchor_window ... ok
test demo_wallet_address_matches_the_browser_core_reference ... ok
test seed_backup_round_trips_and_refuses_other_passwords_and_networks ... ok
test deposit_has_the_documented_header_and_replays_into_a_balance ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

They pin the values printed above. The order of the lines can differ.

## The browser core in Node

After `sh sdk/build-browser-core.sh` (see the [README](README.md#the-browser-core-wasm)
for what that needs):

```sh
node sdk/js/vault-example.mjs
```

```text
core: {"circuit":"orchard_v2","fixture_only":true,"format":"zolana-browser-core-version-v1","multicore":false,"orchard":"0.16.0"}
private address: npriv1gZWMfgeB9UAafpZyPa5Pf92AdWqYpJKVgDuHNf7Z7JGoKDmfDaZTKHL8obU67MuPo7sjYETKNqBK22JD6Jwh8P4Fg3RyUjErY9Drnb3fNvzT
fee address:     CXCBNftdc3BH1EXFNEFgc3sxBjtBgT8RS1B9GdCnAJ7F
recovery file:   1264 bytes, native-wallet-seed-v1
restored the same wallet: true
access proof:    rpc for https://gateway.example valid 600 seconds
after lock():    zolana-wallet-error-v1:locked
wrong password:  zolana-wallet-error-v1:authentication
```

The wallet is created from a new random seed, so both addresses differ on every
run. `gateway.example` is a placeholder audience; no request is made.

## The JavaScript tests

```sh
node --test sdk/js/*.test.mjs
```

The summary at the end of its output:

```text
ℹ tests 10
ℹ suites 0
ℹ pass 10
ℹ fail 0
```

Eight tests cover the JSON-RPC client, most of them against a loopback server
that applies the invited gateway's request rules. Two compare the TypeScript
description of the browser core with the Rust source.
