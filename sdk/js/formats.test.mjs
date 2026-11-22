// Runs with `node --test sdk/js/*.test.mjs`. Offline. The fixtures in sdk/fixtures are real
// payments made by sdk/rust-examples/tests/inspect.rs, with the values the Rust decoders and
// the Rust inspector report for them. These tests hold the JavaScript readers to those values.
import assert from "node:assert/strict";
import { createHash, getHashes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  acceptedRoots, addressNetworkTag, blake2b, checkAddress, decodeEnvelope, decodePayment, decodePoolAccount,
  ENVELOPE_HEADER_BYTES, FormatError, fromBase58, fromHex, paymentId, POOL_ADDRESS, POOL_BYTES, PROGRAM_ID, toBase58, toHex,
} from "./formats.mjs";

const fixture = name => readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8");
const expected = JSON.parse(fixture("expected.json"));
const payment = name => fromHex(fixture(`${name}.hex`));
const pool = () => new Uint8Array(Buffer.from(fixture("pool-account.base64"), "base64"));
const code = run => { try { run(); } catch (error) { assert.ok(error instanceof FormatError, String(error)); return error.code; } return "accepted"; };

// The Rust inspector's JSON, less what only Rust computes: the nullifier accounts and the verification.
const asReported = decoded => ({
  tag: decoded.tag, kind: decoded.kind, network: decoded.network, payment_id: decoded.paymentId,
  expiry_slot: String(decoded.expirySlot), public_value_balance: String(decoded.publicValueBalance),
  shielded_fee: decoded.shieldedFee === null ? null : String(decoded.shieldedFee),
  sponsor: decoded.sponsor, withdrawal_recipient: decoded.withdrawalRecipient, anchor: decoded.anchor,
  actions: decoded.actions.map(action => ({ nullifier: action.nullifier, commitment: action.commitment })),
});
const reported = report => ({
  ...Object.fromEntries(Object.keys(asReported(decodePayment(payment("deposit")))).map(key => [key, report[key]])),
  actions: report.actions.map(action => ({ nullifier: action.nullifier, commitment: action.commitment })),
});

test("BLAKE2b matches RFC 7693, Node's implementation and the Rust digests", () => {
  const abc = new TextEncoder().encode("abc");
  assert.equal(toHex(blake2b(abc)), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
  assert.equal(toHex(blake2b(abc, { length: 32 })), "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
  // Block boundaries: empty, one byte either side of one and two blocks, and a long input.
  assert.ok(getHashes().includes("blake2b512"));
  for (const length of [0, 1, 127, 128, 129, 255, 256, 257, 1000, 9230]) {
    const input = Uint8Array.from({ length }, (_, index) => (index * 31 + length) & 255);
    assert.equal(toHex(blake2b(input)), createHash("blake2b512").update(input).digest("hex"), `length ${length}`);
  }
  // The personalized form: the payment ids the Rust code computed for the fixtures.
  for (const name of Object.keys(expected.payments)) assert.equal(paymentId(payment(name)), expected.payments[name].payment_id, name);
  assert.equal(paymentId(fixture("deposit.hex")), expected.payments.deposit.payment_id, "hex input");
  assert.throws(() => blake2b(abc, { length: 65 }), RangeError);
  assert.throws(() => blake2b(abc, { personal: "short" }), RangeError);
  assert.throws(() => blake2b("abc"), TypeError);
});

test("the fixture payments decode to what the Rust inspector reports", () => {
  for (const [name, report] of Object.entries(expected.payments)) {
    const decoded = decodePayment(payment(name), { network: expected.network });
    assert.deepEqual(asReported(decoded), reported(report), name);
    assert.equal(decoded.bytes, report.bytes);
    assert.equal(report.verification, "ok");
    assert.deepEqual(decodePayment(fixture(`${name}.hex`)), decoded, "hex input");
  }
  const kinds = Object.fromEntries(Object.keys(expected.payments).map(name => [name, decodePayment(payment(name))]));
  assert.deepEqual([kinds.deposit.kind, kinds.deposit.publicValueBalance, kinds.deposit.shieldedFee], ["deposit", -100n, null]);
  assert.deepEqual([kinds["shielded-send"].kind, kinds["shielded-send"].publicValueBalance, kinds["shielded-send"].shieldedFee], ["shielded-fee-payment", 3n, 3n]);
  assert.deepEqual([kinds.withdrawal.kind, kinds.withdrawal.publicValueBalance], ["recipient-withdrawal", 20n]);
  assert.equal(kinds.withdrawal.withdrawalRecipient, toBase58(fromHex("58" + "66".repeat(31))));
  assert.equal(kinds.deposit.withdrawalRecipient, null);
  assert.equal(kinds.deposit.sponsor, toBase58(new Uint8Array(32).fill(0x53)));
  // The remaining two kinds differ from a deposit only in the sign of the value balance.
  // Their signatures no longer hold, which decoding does not look at.
  const zero = payment("deposit"), positive = payment("deposit");
  zero.fill(0, 48, 56);
  positive.set([25, 0, 0, 0, 0, 0, 0, 0], 48);
  assert.equal(decodePayment(zero).kind, "private-send");
  assert.deepEqual([decodePayment(positive).kind, decodePayment(positive).publicValueBalance], ["sponsor-withdrawal", 25n]);
  assert.equal(code(() => decodePayment(payment("deposit"), { network: "09".repeat(32) })), "WrongNetwork");
  assert.throws(() => decodePayment(12), TypeError);
  assert.throws(() => decodePayment("xyz"), TypeError);
});

test("the shared refusal list: the same changes are refused with the Rust decoder's error", () => {
  const cases = JSON.parse(fixture("refusals.json"));
  let unseen = 0;
  for (const item of cases) {
    const isPool = item.fixture === "pool-account";
    let bytes = isPool ? pool() : payment(item.fixture);
    for (const change of item.set ?? []) bytes.set(fromHex(change.hex), change.offset);
    bytes = bytes.subarray(0, bytes.length - (item.truncate ?? 0));
    const result = code(() => isPool ? decodePoolAccount(bytes) : decodePayment(bytes));
    // A few refusals need curve arithmetic or the tree hash. The list marks them.
    assert.equal(result, item.javascript_accepts ? "accepted" : item.error, item.why);
    unseen += item.javascript_accepts ? 1 : 0;
  }
  assert.equal(unseen, 3);
  assert.ok(cases.length >= 30);
});

test("field elements are refused exactly from the field order up", () => {
  const modulus = fromHex(expected.field_modulus).reverse(), largest = Uint8Array.from(modulus);
  largest[0] -= 1;
  for (const offset of [88, 122, 186]) {
    const bytes = payment("deposit");
    bytes.set(modulus, offset);
    assert.equal(code(() => decodePayment(bytes)), "InvalidEncoding");
    bytes.set(largest, offset);
    assert.equal(code(() => decodePayment(bytes)), "accepted");
  }
});

test("an inline envelope is opened, checked against its payment id and its expiry", () => {
  const inner = payment("shielded-send"), header = fromHex(expected.envelope.header);
  assert.equal(header.length, ENVELOPE_HEADER_BYTES);
  const frame = Uint8Array.from([...header, ...inner]);
  const opened = decodeEnvelope(frame, { network: expected.network, currentSlot: 2 });
  const report = expected.envelope.inspection;
  assert.deepEqual([opened.bytes, opened.payment.bytes, opened.paymentId], [report.bytes, report.payment_bytes, report.payment_id]);
  assert.deepEqual(asReported(opened.payment), reported(report));
  assert.deepEqual(opened.payment, decodePayment(inner));
  assert.equal(opened.expirySlot, 100n);
  // The program's expiry rule, applied only when a slot is given.
  assert.equal(code(() => decodeEnvelope(frame, { currentSlot: 100n })), "accepted");
  assert.equal(code(() => decodeEnvelope(frame, { currentSlot: 101 })), "Expired");
  assert.equal(code(() => decodeEnvelope(frame)), "accepted");
  const refusals = [
    [bytes => { bytes[bytes.length - 1] ^= 1; }, "DigestMismatch"],
    [bytes => { bytes[0] ^= 1; }, "UnsupportedVersion"],
    [bytes => { bytes[8] = 2; }, "UnsupportedVersion"],
    [bytes => { bytes[10] ^= 1; }, "InvalidContext"],
    [bytes => { bytes[26] ^= 1; }, "WrongNetwork"],
    [bytes => { bytes[58] ^= 1; }, "InvalidContext"], // the envelope's copy of the expiry
    [bytes => { bytes[98] ^= 1; }, "InvalidLength"],
  ];
  for (const [change, refusal] of refusals) {
    const changed = Uint8Array.from(frame);
    change(changed);
    assert.equal(code(() => decodeEnvelope(changed)), refusal);
  }
  assert.equal(code(() => decodeEnvelope(frame.subarray(0, ENVELOPE_HEADER_BYTES))), "InvalidLength");
  assert.equal(code(() => decodeEnvelope(frame, { network: "09".repeat(32) })), "WrongNetwork");
  // A deposit has no envelope, even behind a header that names it correctly.
  const deposit = payment("deposit"), other = Uint8Array.from([...header, ...deposit]);
  other.set(fromHex(paymentId(deposit)), 66);
  new DataView(other.buffer).setUint32(98, deposit.length, true);
  assert.equal(code(() => decodeEnvelope(other)), "UnsupportedVersion");
});

test("the pool account decodes to what PoolState reports, with the roots it accepts", () => {
  const decoded = decodePoolAccount(pool()), report = expected.pool;
  assert.equal(pool().length, POOL_BYTES.NPOOL004);
  assert.deepEqual(
    { tag: decoded.tag, bytes: pool().length, network: decoded.network, rent_floor: String(decoded.rentFloor), backing: String(decoded.backing), note_count: String(decoded.noteCount),
      slot_anchors: decoded.slotAnchors.map(entry => ({ slot: String(entry.slot), note_count: String(entry.noteCount), root: entry.root })) },
    Object.fromEntries(Object.entries(report).filter(([key]) => !["root", "accepted_roots"].includes(key))));
  // After the last completed slot the latest slot anchor is the pool's current root.
  assert.equal(decoded.slotAnchors.at(-1).root, report.root);
  assert.deepEqual([decoded.backing, decoded.noteCount], [77n, 6n]);
  for (const [slot, roots] of Object.entries(report.accepted_roots)) assert.deepEqual(acceptedRoots(decoded, Number(slot)), roots, `slot ${slot}`);
  assert.equal(code(() => acceptedRoots(decoded, 2)), "InvalidContext");
  assert.deepEqual(decodePoolAccount(toHex(pool())), decoded, "hex input");
  // The send fixture is anchored at the root of slot 1, which a pool at slot 2 accepts.
  assert.ok(acceptedRoots(decoded, 4).includes(expected.payments["shielded-send"].anchor));
});

test("a shielded address is checked for typing errors and for its network", () => {
  const network = { network: expected.network, genesisHash: expected.genesis_hash };
  for (const address of Object.values(expected.addresses)) {
    const checked = checkAddress(address, network);
    assert.deepEqual([checked.version, checked.networkTag, checked.rawAddress.length], [1, addressNetworkTag(network.network, network.genesisHash), 86]);
    assert.deepEqual(checkAddress(address), checked, "without a network only the text is checked");
    assert.equal(code(() => checkAddress(address, { ...network, network: "08".repeat(32) })), "WrongNetwork");
    assert.equal(code(() => checkAddress(address, { ...network, genesisHash: "2".repeat(32) })), "WrongNetwork");
    // A single changed character is caught, here at three positions.
    for (const position of [6, 40, address.length - 1]) {
      const other = address[position] === "z" ? "y" : "z";
      assert.notEqual(code(() => checkAddress(address.slice(0, position) + other + address.slice(position + 1), network)), "accepted");
    }
    assert.equal(code(() => checkAddress(address.slice(1), network)), "InvalidEncoding");
    assert.equal(code(() => checkAddress(address + "0", network)), "InvalidEncoding");
    assert.equal(code(() => checkAddress(address + "1".repeat(40), network)), "InvalidLength");
    assert.equal(code(() => checkAddress(address.slice(0, -2), network)), "WrongNetwork");
  }
  assert.notEqual(expected.addresses.alice, expected.addresses.bob);
  assert.throws(() => checkAddress(7), TypeError);
});

test("hex and base58 round-trip, and the account constants are the ones the Rust tests pin", () => {
  for (const bytes of [new Uint8Array(0), new Uint8Array(3), Uint8Array.from([0, 0, 1, 255]), new Uint8Array(32).fill(0x53)]) {
    assert.deepEqual(fromBase58(toBase58(bytes)), bytes);
    assert.deepEqual(fromHex(toHex(bytes)), bytes);
  }
  assert.equal(toBase58(new Uint8Array(32)), "1".repeat(32));
  assert.deepEqual(fromHex(" 0a\nFF "), Uint8Array.from([10, 255]));
  assert.throws(() => fromHex("abc"), TypeError);
  assert.throws(() => fromBase58("0OIl"), TypeError);
  const pinned = readFileSync(new URL("../rust-examples/tests/sdk.rs", import.meta.url), "utf8");
  for (const address of [PROGRAM_ID, POOL_ADDRESS]) {
    assert.ok(pinned.includes(`"${address}"`), address);
    assert.equal(fromBase58(address).length, 32);
  }
});
