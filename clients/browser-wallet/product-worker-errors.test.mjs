// Focused error-boundary tests. No WASM, wallets, credentials, RPC or IndexedDB.
import assert from "node:assert/strict";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource, sendWorkerMessage } from "./product-worker-harness.mjs";

class WalletStorageError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}
const responses = [];
const context = createWorkerContext({ TextEncoder, Uint8Array, WalletStorageError,
  self: { postMessage: value => responses.push(value) } });
const source = await loadWorkerSource();
vm.runInContext(`${source}\nglobalThis.errorBoundary = publicError;
globalThis.knownFailure = publicFailure; globalThis.completion = () => session.completion;`, context);
const normalize = value => JSON.parse(JSON.stringify(context.errorBoundary(value)));
const coreError = code => `zolana-wallet-error-v1:${code}`;
const authentication = normalize(coreError("authentication"));
assert.deepEqual(authentication, { code: "authentication", error: "Password could not open this wallet. Check it and try again." });
assert(!authentication.error.includes("incorrect")); // Cannot distinguish bad password from altered ciphertext.
assert.equal(normalize(coreError("network")).code, "network");
assert.equal(normalize(coreError("backup")).code, "backup");
assert.equal(normalize(coreError("history")).code, "sync");
assert.equal(normalize(coreError("sync_required")).code, "sync");
assert.equal(normalize(coreError("configuration")).code, "configuration");
assert.equal(normalize(coreError("review")).code, "review");
assert.equal(normalize(coreError("recovery")).code, "recovery");
assert.equal(normalize(coreError("locked")).code, "locked");
assert.equal(normalize(coreError("password")).code, "password");
assert.equal(normalize(context.knownFailure("connection", "Connection interrupted. Check this same wallet again.")).code, "connection");
assert.equal(normalize(new WalletStorageError("revision_conflict", "Another tab changed this wallet.")).code, "revision_conflict");
const sensitive = "PRIVATE-FIXTURE-DO-NOT-ECHO";
for (const value of [sensitive, new Error(sensitive), { message: sensitive },
  coreError(sensitive), new Error(coreError("authentication")), "wallet is locked",
  coreError(`authentication ${sensitive}`), "x".repeat(10000)]) {
  const result = normalize(value);
  assert.equal(result.code, "wallet_error"); assert(!JSON.stringify(result).includes(sensitive));
  assert(result.error.length <= 220);
}

// Exercise the actual worker catch/finally boundary with Rust-style thrown
// codes: password rejection still locks, clears password bytes and emits only
// the reviewed public message. This does not substitute for real crypto tests.
vm.runInContext(`globalThis.lockCount = 0;
session.release = () => { lockCount++; };
dispatch = async () => { throw "zolana-wallet-error-v1:authentication"; };`, context);
const password = new Uint8Array([11, 22, 33, 44]);
sendWorkerMessage(context, { id: "fixture-authentication", action: "unlock", password });
await context.completion();
assert.equal(context.lockCount, 1); assert(password.every(byte => byte === 0));
assert.deepEqual(JSON.parse(JSON.stringify(responses.pop())), { id: "fixture-authentication", ok: false, ...authentication });
vm.runInContext(`dispatch = async () => { throw "PRIVATE-FIXTURE-DO-NOT-ECHO"; };`, context);
const unknownPassword = new Uint8Array([11, 22, 33]);
sendWorkerMessage(context, { id: "fixture-unknown", action: "restore", password: unknownPassword });
await context.completion();
assert.equal(context.lockCount, 2); assert(unknownPassword.every(byte => byte === 0));
assert.equal(responses[0].code, "wallet_error"); assert(!JSON.stringify(responses).includes(sensitive));
console.log("PASS: versioned Rust error codes, unknown-text suppression, and worker fail-closed/password cleanup.");
