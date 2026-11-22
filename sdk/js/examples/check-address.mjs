// Check a shielded address before paying it.
//
//     node sdk/js/examples/check-address.mjs [address]
//
// Offline. Uses the fixture network of the SDK examples: the 32-byte domain
// 07…07 and the genesis hash 111…1. On a real network take the domain from the
// wallet's network identity and the genesis hash from getGenesisHash.
// @ts-check
import { readFileSync } from "node:fs";
import { checkAddress, FormatError } from "../formats.mjs";

const fixture = JSON.parse(readFileSync(new URL("../../fixtures/expected.json", import.meta.url), "utf8"));
const network = { network: fixture.network, genesisHash: fixture.genesis_hash };
const address = process.argv[2] ?? fixture.addresses.bob;

/** @param {string} label @param {string} text @param {{ network: string, genesisHash: string }} on */
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
