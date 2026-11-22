# Verify a payment offline

`inspect-payment` decodes a payment and checks its spend authorization
signatures, its binding signature and its proof, with the same
`PaymentVerifier` a validator uses. It needs no RPC and no ledger.

```sh
sh tools/dev.sh run --offline --locked -p zolana-sdk-examples --bin inspect-payment -- sdk/fixtures/shielded-send.hex
```

The input is a payment or an inline envelope, as raw bytes, hex or base64: a
file, the argument itself, or `-` for standard input. `--json` prints one JSON
object instead, and `--network <64 hex digits>` refuses a payment made for any
other network. Every run first builds the verifying key; the whole command
took about two seconds on an Apple Silicon Mac.

<!-- file: sdk/fixtures/shielded-send.inspect.txt -->
```text
input                9230 bytes, tag NPAY0003
kind                 shielded-fee-payment
network              0707070707070707070707070707070707070707070707070707070707070707
payment id           2b8296f7d96e1f6077bdc31d4541859544c849af0bcd5261aedacd50225c8832
expiry slot          100
public value         3 units leave the pool to the sponsor as the fee
shielded fee         3
sponsor              6cGXszer5keoaWm8Co5G9f4KGBThuGz4NsKTqYij1emg
anchor               1fbe1c80664a1b478518e05c8029b49418782b2c39b077cf627d4af0b0b5b31d
action 0
  nullifier          6154b85afc11f06db91f2f7a1f9a860a0e7504217cb12dbd3422e16abb179604
  nullifier account  6NB5KEfy2yJmqRC7axs9zBHCFMbz73kKatsHiExsEkVp
  commitment         593c0de55f92909e654bfc77e9307b582c2ff968fd2760f0c1cb4149b0293b02
action 1
  nullifier          f017eb9715131a11a425e3a24d208b3ea7399541f71575ffe7a5303af95b6c27
  nullifier account  9eY7J7nSSJqqG2hGhZd3dJkRTwmD1dBZGYvakxCgFnAe
  commitment         5a4f325f4f2ea8d2f6b4f648215dabedc1d138a51a5fe71853eb27a2188ff82b
verified             the spend authorization signatures, the binding signature and the proof
not revealed         the shielded addresses, the value of each note and the memos
                     which actions spend or create a real note, and which are padding
not checked          that any chain accepts this anchor
                     that the nullifiers are unspent
                     the current slot: the verifier accepts this payment from slot 0 through slot 100
                     that the public accounts exist and can pay or be paid
                     that the payment was ever submitted or finalized
```

The exit status is 0 when the signatures and the proof are valid, 1 when the
bytes decode but do not verify, and 2 when they cannot be read or decoded.

## What "verified" means here

A validator verifies a payment against state it has authenticated: the current
slot, the roots it accepts as anchors, the nullifiers already spent, and the
public value the transaction is allowed to move. Offline there is no such
state, so the command takes all four from the payment itself:

<!-- snippet: sdk/rust-examples/src/inspect.rs -->
```rust
    let anchor = bundle.anchor().to_bytes();
    let (anchors, spent) = (BTreeSet::from([anchor]), BTreeSet::new());
    let view = ValidationView {
        current_slot: context.expires_at,
        accepted_anchors: &anchors,
        spent_nullifiers: &spent,
        authorized_public_value_balance: context.public_value_balance,
    };
    let verification = PaymentVerifier::with_shared_key(network, Arc::clone(key))?
        .verify(bundle, context, &view)
        .map(|_| ());
```

That is enough to show that the bytes are internally valid: the signatures
match the payment, and the proof holds for the anchor it names. It is not
enough to show that a chain would accept them. The report lists what was
not checked, and none of it can be checked from the bytes alone:

- whether the anchor is a root a chain accepts
  ([Watch the pool account](watch-the-pool-account.md) shows the roots a pool
  accepts);
- whether the nullifiers are unspent. Each `nullifier account` in the report
  is the address to look up with `getAccountInfo`: an existing account owned by
  the payment program means spent;
- whether the current slot is inside the window the report gives;
- whether the public accounts exist and can pay or be paid;
- whether the payment was ever submitted or finalized.

The same check is available as a library function, `inspect` in
[`sdk/rust-examples/src/inspect.rs`](../../sdk/rust-examples/src/inspect.rs).
