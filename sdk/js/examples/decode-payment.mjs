// Decode a payment and print what its bytes say.
//
//     node sdk/js/examples/decode-payment.mjs [file with the payment as hex]
//
// Offline. Without an argument it reads sdk/fixtures/shielded-send.hex: Alice
// pays Bob 40 units and a shielded fee of 3. Decoding is not verification; the
// inspect-payment command in sdk/rust-examples checks the signatures and the proof.
// @ts-check
import { readFileSync } from "node:fs";
import { decodePayment, FormatError } from "../formats.mjs";

const file = process.argv[2] ?? new URL("../../fixtures/shielded-send.hex", import.meta.url);
const hex = readFileSync(file, "utf8");

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

// The bytes name their network. Ask for another one and they are refused.
try {
  decodePayment(hex, { network: "09".repeat(32) });
} catch (error) {
  if (!(error instanceof FormatError)) throw error;
  console.log("for another network:", error.code);
}
