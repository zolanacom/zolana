# Decode a payment

A payment is a fixed layout of bytes: a tag, the network it is for, a few
public fields, two actions, a proof and a signature. `decodePayment` in
[`sdk/js/formats.mjs`](../../sdk/js/formats.mjs) reads the public part.

```sh
node sdk/js/examples/decode-payment.mjs
```

With no argument the example reads a fixture: Alice pays Bob 40 units with a
shielded fee of 3. Pass a file that holds a payment as hex to read your own.

<!-- snippet: sdk/js/examples/decode-payment.mjs -->
```js
const payment = decodePayment(hex);
console.log(`${payment.kind}: ${payment.bytes} bytes, tag ${payment.tag}`);
console.log(`network       ${payment.network}`);
console.log(`payment id    ${payment.paymentId}`);
console.log(`expiry slot   ${payment.expirySlot}`);
// Negative: value enters the pool. Zero: none moves. Positive: it leaves.
console.log(`public value  ${payment.publicValueBalance}`);
console.log(`shielded fee  ${payment.shieldedFee}`);
console.log(`sponsor       ${payment.sponsor}`);
console.log(`anchor        ${payment.anchor}`);
for (const action of payment.actions) {
  console.log(`nullifier     ${action.nullifier}`);
  console.log(`commitment    ${action.commitment}`);
}
```

<!-- output: node sdk/js/examples/decode-payment.mjs -->
```text
shielded-fee-payment: 9230 bytes, tag NPAY0003
network       0707070707070707070707070707070707070707070707070707070707070707
payment id    2b8296f7d96e1f6077bdc31d4541859544c849af0bcd5261aedacd50225c8832
expiry slot   100
public value  3
shielded fee  3
sponsor       6cGXszer5keoaWm8Co5G9f4KGBThuGz4NsKTqYij1emg
anchor        1fbe1c80664a1b478518e05c8029b49418782b2c39b077cf627d4af0b0b5b31d
nullifier     6154b85afc11f06db91f2f7a1f9a860a0e7504217cb12dbd3422e16abb179604
commitment    593c0de55f92909e654bfc77e9307b582c2ff968fd2760f0c1cb4149b0293b02
nullifier     f017eb9715131a11a425e3a24d208b3ea7399541f71575ffe7a5303af95b6c27
commitment    5a4f325f4f2ea8d2f6b4f648215dabedc1d138a51a5fe71853eb27a2188ff82b
for another network: WrongNetwork
```

What the fields mean:

- **kind** follows from the tag and the sign of the public value: `deposit`,
  `private-send`, `sponsor-withdrawal`, `recipient-withdrawal` or
  `shielded-fee-payment`.
- **public value** is negative when coins enter the pool, zero when none move
  and positive when they leave. Here it is the fee of 3, paid to the sponsor
  account. The 40 units and the recipient are not in the public fields.
- **payment id** is the BLAKE2b-256 digest of the bytes (`paymentId`). The
  relay returns it from `submitShieldedPayment`.
- **nullifier** and **commitment**: every action carries one of each, whether
  or not it spends or creates a real note. The bytes do not say which.

What decoding does not do: it does not verify the signatures or the proof, and
it does not check that the two 32-byte keys of an action are valid curve
points. A decoded payment says what the bytes claim. To check the claim, see
[Verify a payment offline](verify-a-payment-offline.md).

An inline envelope (`ZOLNPAY1`) around a payment is opened with
`decodeEnvelope`, which also checks that the payment is the one the envelope
names.
