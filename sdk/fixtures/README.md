# SDK fixtures

Real payments with real proofs, for the tests and the examples of the SDK. They
are made on a fixture network (the 32-byte domain `07…07` and the genesis hash
`111…1`) with public, disposable keys. They are not payments of any deployed
network and move nothing.

| File | What it holds |
| --- | --- |
| `deposit.hex` | An `NPAY0001` payment: 100 units enter the pool as a note for Alice |
| `shielded-send.hex` | An `NPAY0003` payment: Alice pays Bob 40 units and a shielded fee of 3 |
| `withdrawal.hex` | An `NPAY0002` payment: Alice withdraws 20 units to a public account |
| `pool-account.base64` | The data of the pool account (`NPOOL004`) after those three payments, one per slot |
| `expected.json` | What the Rust code reports for the files above: the inspector's JSON for each payment and for the send inside an inline envelope, the envelope header, the pool's fields and accepted roots, and the two addresses |
| `shielded-send.inspect.txt` | The text `inspect-payment` prints for the send |
| `refusals.json` | Changes to the fixtures and the error each must produce. Written by hand |

The payment files are hex, 32 bytes to a line. The three payments form one
history: the send spends the note the deposit created, and the withdrawal
spends the change of the send.

## Where they come from

An ignored test in
[`rust-examples/tests/inspect.rs`](../rust-examples/tests/inspect.rs) builds the
payments with `PaymentProver`, replays them into a `WalletState`, and writes
every file except `refusals.json`:

```sh
sh tools/dev.sh test --offline --locked -p zolana-sdk-examples --test inspect -- --ignored write_the_fixtures
```

Proofs, ciphertexts and signatures are randomized, so that command replaces
every payment, id, nullifier and commitment. To rewrite only `expected.json`
and the text report from the stored payments, after a change to what the
inspector reports:

```sh
sh tools/dev.sh test --offline --locked -p zolana-sdk-examples --test inspect -- --ignored refresh_the_derived_fixtures
```

After either command, run both test suites. The cookbook pages and
`sdk/EXAMPLES.md` quote values from these files and the JavaScript tests
compare them, so a replaced fixture shows up there as a failing test.

## What reads them

- `rust-examples/tests/inspect.rs` checks that the inspector still reports
  `expected.json` for the stored payments, and that every entry of
  `refusals.json` is refused by the Rust decoders with the error it names.
- `js/formats.test.mjs` holds the JavaScript readers to the same
  `expected.json` and the same `refusals.json`. Three entries are marked
  `javascript_accepts`: the Rust decoder refuses them and the JavaScript reader
  cannot, because the check needs curve arithmetic or the tree hash.
- `js/cookbook.test.mjs` compares the cookbook pages with these files and with
  what the examples print for them.
