# Check an address

A shielded address is text that starts with `npriv1`. It carries a version, a
tag that binds it to one network, the address bytes and a 4-byte checksum.
`checkAddress` in [`sdk/js/formats.mjs`](../../sdk/js/formats.mjs) checks all
of that before anything is paid.

```sh
node sdk/js/examples/check-address.mjs
```

With no argument the example checks a fixture address on the fixture network
of the SDK examples. Pass an address to check your own against that network.

<!-- snippet: sdk/js/examples/check-address.mjs -->
```js
function report(label, text, on) {
  try {
    checkAddress(text, on);
    console.log(`${label}: well formed, and for this network`);
  } catch (error) {
    if (!(error instanceof FormatError)) throw error;
    console.log(`${label}: refused (${error.message})`);
  }
}

report("the address", address, network);
// One wrong character breaks the checksum.
const swapped = address.at(-1) === "x" ? "y" : "x";
report("one character changed", address.slice(0, -1) + swapped, network);
// The same text is refused on a network with another domain.
report("on another network", address, { ...network, network: "08".repeat(32) });
```

<!-- output: node sdk/js/examples/check-address.mjs -->
```text
the address: well formed, and for this network
one character changed: refused (WrongNetwork: receiving address checksum or network mismatch)
on another network: refused (WrongNetwork: receiving address checksum or network mismatch)
```

A network is a 32-byte domain and a base58 genesis hash. A wallet has both in
its network identity, and `getGenesisHash` returns the second. Without the
second argument `checkAddress` checks the text alone and returns the network
tag it carries.

One thing is left to the Rust decoder: `checkAddress` does not check that the
43 address bytes are a valid shielded address. `decode_address` in
`native-wallet-core` does, and the wallets call it before they build a
payment.
