import { createWalletStore, openWalletStore, walletDatabaseName } from "./storage.js";

const output = document.querySelector("#output");
const databases = new Set();
const handles = new Set();
const reloadKey = "zolana-storage-fixture-reload-v1";
const packetA = "a".repeat(64), packetB = "b".repeat(64);
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const equal = (left, right) => left.length === right.length && left.every((value, index) => value === right[index]);
const encrypted = (value, length = 128) => new Uint8Array(length).fill(value);
const randomDigest = () => [...crypto.getRandomValues(new Uint8Array(32))].map(value => value.toString(16).padStart(2, "0")).join("");

function fixture() {
  const walletId = randomDigest(), networkId = randomDigest();
  return { dbName: walletDatabaseName(walletId, networkId), walletId, networkId,
    encryptedWallet: new TextEncoder().encode(JSON.stringify({
      format: "native-wallet-seed-v1", network: { network: Array(32).fill(9), genesis_hash: "1".repeat(32) },
      rounds: 600000, salt: Array(16).fill(1), nonce: Array(24).fill(2), ciphertext: Array(48).fill(3),
    })) };
}
async function created(configuration = fixture()) {
  databases.add(configuration.dbName);
  const handle = await createWalletStore(configuration); handles.add(handle);
  return { configuration, handle, instance: (await handle.snapshot()).instanceId };
}
async function reopened(configuration, instance) {
  const handle = await openWalletStore({ ...configuration, expectedInstanceId: instance }); handles.add(handle); return handle;
}
async function refuses(action, code) {
  let caught;
  try { await action(); } catch (error) { caught = error; }
  assert(caught && (!code || caught.code === code), `Expected ${code || "refusal"}; got ${caught?.code || "success"}`);
}
async function remove(name) {
  assert(databases.has(name), "Only databases allocated by this fixture may be deleted.");
  await new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = resolve; request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("Fixture cleanup blocked by an open test connection."));
  });
  databases.delete(name);
}
async function rawChange(name, change, abort = false) {
  assert(databases.has(name), "Only fixture databases may be changed directly.");
  const db = await new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1); request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
  });
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(["meta", "blobs"], "readwrite", { durability: "strict" });
      tx.oncomplete = () => resolve("committed"); tx.onabort = () => abort ? resolve("aborted") : reject(tx.error);
      const request = tx.objectStore("meta").get("state");
      request.onsuccess = () => { change(tx, request.result); if (abort) tx.abort(); };
    });
  } finally { db.close(); }
}
async function pendingFixture() {
  const value = await created();
  await value.handle.commitCheckpoint({ expectedRevision: 0, encryptedCheckpoint: encrypted(4) });
  await value.handle.reservePending({ expectedRevision: 1, packetId: packetA, encryptedPacket: encrypted(5) });
  return value;
}
const reconciliation = (configuration, decision = "accepted", packetId = packetA) => ({
  source: "canonical-finalized-history", networkId: configuration.networkId, packetId, decision,
});

export async function runStorageTests() {
  assert(sessionStorage.getItem(reloadKey) === null, "Recover the prepared reload fixture before running a new suite.");
  const results = [];
  const test = async (name, action) => {
    try { await action(); results.push({ name, passed: true }); }
    catch (error) { results.push({ name, passed: false, error: `${error.code || error.name}: ${error.message}` }); }
  };
  try {
    await test("native encrypted envelope bytes and returned copies survive close/reopen", async () => {
      const { configuration, handle, instance } = await created();
      const expected = configuration.encryptedWallet.slice(); configuration.encryptedWallet.fill(0);
      const saved = await handle.snapshot(); assert(equal(saved.encryptedWallet, expected), "Caller mutation entered the store.");
      saved.encryptedWallet.fill(0); handle.close();
      assert(equal((await (await reopened(configuration, instance)).snapshot()).encryptedWallet, expected), "Snapshot mutation entered the store.");
    });
    await test("creation never overwrites an existing wallet", async () => {
      const { configuration, handle } = await created();
      await refuses(() => createWalletStore(configuration), "already_exists"); assert((await handle.snapshot()).revision === 0, "Create changed revision.");
    });
    await test("identity, network, instance and alternate namespace fail closed", async () => {
      const { configuration, instance } = await created();
      await refuses(() => openWalletStore({ ...configuration, expectedInstanceId: crypto.randomUUID() }), "binding_mismatch");
      await refuses(() => openWalletStore({ ...configuration, walletId: randomDigest(), expectedInstanceId: instance }), "invalid_input");
      await refuses(() => createWalletStore({ ...configuration, dbName: configuration.dbName + "-other" }), "invalid_input");
    });
    await test("two connections race to reserve; exactly one pending packet commits", async () => {
      const { configuration, handle, instance } = await created();
      await handle.commitCheckpoint({ expectedRevision: 0, encryptedCheckpoint: encrypted(4) });
      const second = await reopened(configuration, instance);
      const result = await Promise.allSettled([
        handle.reservePending({ expectedRevision: 1, packetId: packetA, encryptedPacket: encrypted(5) }),
        second.reservePending({ expectedRevision: 1, packetId: packetB, encryptedPacket: encrypted(6) }),
      ]);
      assert(result.filter(value => value.status === "fulfilled").length === 1, "Conflicting sends both committed or neither committed.");
      assert(result.find(value => value.status === "rejected").reason.code === "revision_conflict", "Race failed for an unexpected reason.");
      const one = await handle.snapshot(), two = await second.snapshot();
      assert(one.revision === 2 && one.pending.packetId === two.pending.packetId, "Connections disagree on the original packet.");
    });
    await test("reservation requires the durable verified checkpoint", async () => {
      const { handle } = await created();
      await refuses(() => handle.reservePending({ expectedRevision: 0, packetId: packetA, encryptedPacket: encrypted(5) }), "checkpoint_required");
      assert((await handle.snapshot()).revision === 0, "Failed reservation changed revision.");
    });
    await test("pending survives reopening; timeout cannot replace it or its checkpoint", async () => {
      const { configuration, handle, instance } = await pendingFixture(); handle.close();
      const next = await reopened(configuration, instance);
      await refuses(() => next.reservePending({ expectedRevision: 2, packetId: packetB, encryptedPacket: encrypted(8) }), "pending_exists");
      await refuses(() => next.commitCheckpoint({ expectedRevision: 2, encryptedCheckpoint: encrypted(9) }), "pending_exists");
      await refuses(() => next.settlePending({ expectedRevision: 2, reconciliation: { ...reconciliation(configuration), decision: "timeout" }, encryptedCheckpoint: encrypted(9), encryptedReceipt: encrypted(10) }), "unreconciled");
      const saved = await next.snapshot(); assert(saved.revision === 2 && saved.pending.packetId === packetA && equal(saved.pending.encryptedPacket, encrypted(5)), "Original pending packet was changed.");
    });
    await test("wrong packet finality result leaves the original pending packet", async () => {
      const { configuration, handle } = await pendingFixture();
      await refuses(() => handle.settlePending({ expectedRevision: 2, reconciliation: reconciliation(configuration, "accepted", packetB), encryptedCheckpoint: encrypted(6), encryptedReceipt: encrypted(7) }), "pending_mismatch");
      assert((await handle.snapshot()).pending.packetId === packetA, "Mismatched finality removed original packet.");
    });
    await test("canonical reconciliation commits checkpoint/receipt and clears pending atomically", async () => {
      const { configuration, handle, instance } = await pendingFixture();
      await handle.settlePending({ expectedRevision: 2, reconciliation: reconciliation(configuration), encryptedCheckpoint: encrypted(6), encryptedReceipt: encrypted(7) }); handle.close();
      const next = await reopened(configuration, instance), saved = await next.snapshot();
      assert(saved.revision === 3 && saved.pending === null && saved.lastSettlement.packetId === packetA && equal(saved.encryptedCheckpoint, encrypted(6)) && equal(saved.lastSettlement.encryptedReceipt, encrypted(7)), "Final transaction was partial.");
      await refuses(() => next.reservePending({ expectedRevision: 3, packetId: packetA, encryptedPacket: encrypted(5) }), "already_settled");
    });
    await test("expired-and-canonically-absent is separate from transport timeout", async () => {
      const { configuration, handle } = await pendingFixture();
      await handle.settlePending({ expectedRevision: 2, reconciliation: reconciliation(configuration, "expired-absent"), encryptedCheckpoint: encrypted(6), encryptedReceipt: encrypted(7) });
      assert((await handle.snapshot()).lastSettlement.decision === "expired-absent", "Expiry decision was lost.");
    });
    await test("real IndexedDB transaction abort cannot publish partial settlement", async () => {
      const { configuration, handle, instance } = await pendingFixture();
      const aborted = await rawChange(configuration.dbName, (tx, state) => {
        tx.objectStore("blobs").delete("pending"); tx.objectStore("blobs").put(encrypted(99), "checkpoint");
        tx.objectStore("meta").put({ ...state, revision: 999, pendingId: null, pendingDigest: null }, "state");
      }, true);
      assert(aborted === "aborted", "Abort did not run."); handle.close();
      const saved = await (await reopened(configuration, instance)).snapshot();
      assert(saved.revision === 2 && saved.pending.packetId === packetA && equal(saved.encryptedCheckpoint, encrypted(4)), "Aborted writes became visible.");
    });
    await test("aborted adapter operation and stale revision preserve the old record", async () => {
      const { handle } = await created(); const controller = new AbortController(); controller.abort();
      await refuses(() => handle.commitCheckpoint({ expectedRevision: 0, encryptedCheckpoint: encrypted(4), signal: controller.signal }), "aborted");
      await handle.commitCheckpoint({ expectedRevision: 0, encryptedCheckpoint: encrypted(4) });
      await refuses(() => handle.commitCheckpoint({ expectedRevision: 0, encryptedCheckpoint: encrypted(8) }), "revision_conflict");
      assert(equal((await handle.snapshot()).encryptedCheckpoint, encrypted(4)), "Cancellation/stale write replaced checkpoint.");
    });
    await test("ciphertext corruption fails closed instead of resetting a wallet", async () => {
      const { configuration, handle, instance } = await created(); handle.close();
      const damaged = JSON.parse(new TextDecoder().decode(configuration.encryptedWallet)); damaged.ciphertext[0] ^= 1;
      await rawChange(configuration.dbName, tx => tx.objectStore("blobs").put(new TextEncoder().encode(JSON.stringify(damaged)), "wallet"));
      await refuses(() => reopened(configuration, instance), "corrupt");
      await refuses(() => createWalletStore(configuration), "already_exists");
    });
    await test("expected instance detects deletion; backup permits explicit fresh restoration", async () => {
      const { configuration, handle, instance } = await created(); handle.close(); await remove(configuration.dbName);
      await refuses(() => openWalletStore({ ...configuration, expectedInstanceId: instance }), "missing");
      const restored = await created(configuration);
      assert(restored.instance !== instance && equal((await restored.handle.snapshot()).encryptedWallet, configuration.encryptedWallet), "Explicit restoration did not retain encrypted native backup bytes.");
    });
    await test("plaintext input, oversized ciphertext and closed handles are refused", async () => {
      const configuration = fixture();
      await refuses(() => createWalletStore({ ...configuration, encryptedWallet: new TextEncoder().encode(JSON.stringify({ seed: "never store plaintext seed" })) }), "invalid_input");
      const { handle } = await created(configuration);
      await refuses(() => handle.reservePending({ expectedRevision: 0, packetId: packetA, encryptedPacket: new Uint8Array(32769) }), "invalid_input");
      handle.close(); await refuses(() => handle.snapshot(), "closed");
    });
  } finally {
    for (const handle of handles) handle.close(); handles.clear();
    for (const name of [...databases]) await remove(name);
  }
  const report = { format: "zolana-browser-storage-fixture-v1", passed: results.every(value => value.passed),
    testCount: results.length, results, cryptoVerified: false, chainFinalityVerified: false,
    existingWalletsTouched: false, fixtureDatabasesRemaining: databases.size };
  output.textContent = JSON.stringify(report, null, 2); window.storageTestResult = report;
  return report;
}

export async function prepareStorageReloadTest() {
  assert(sessionStorage.getItem(reloadKey) === null, "A prepared fixture already exists; recover it first.");
  const { configuration, handle, instance } = await pendingFixture(); handle.close(); handles.delete(handle);
  const record = { ...configuration, encryptedWallet: undefined, expectedInstanceId: instance };
  sessionStorage.setItem(reloadKey, JSON.stringify(record));
  output.textContent = "Synthetic pending packet committed. Reload this page, then check prepared reload recovery.";
  return { prepared: true, dbName: configuration.dbName, expectedRevision: 2, packetId: packetA };
}
export async function recoverStorageReloadTest() {
  const record = JSON.parse(sessionStorage.getItem(reloadKey) || "null"); assert(record, "No prepared reload fixture exists.");
  assert(record.dbName === walletDatabaseName(record.walletId, record.networkId), "Prepared fixture namespace differs.");
  databases.add(record.dbName);
  const handle = await openWalletStore(record);
  try {
    const saved = await handle.snapshot();
    assert(saved.revision === 2 && saved.pending.packetId === packetA && equal(saved.pending.encryptedPacket, encrypted(5)), "Reload lost the exact pending packet.");
    const report = { reloadRecovered: true, revision: saved.revision, packetId: saved.pending.packetId,
      cryptoVerified: false, chainFinalityVerified: false, existingWalletsTouched: false };
    output.textContent = JSON.stringify(report, null, 2); window.storageReloadResult = report;
    return report;
  } finally { handle.close(); await remove(record.dbName); sessionStorage.removeItem(reloadKey); }
}

window.runStorageTests = runStorageTests;
window.prepareStorageReloadTest = prepareStorageReloadTest;
window.recoverStorageReloadTest = recoverStorageReloadTest;
for (const [id, action] of [["run", runStorageTests], ["prepare", prepareStorageReloadTest], ["recover", recoverStorageReloadTest]]) {
  document.querySelector(`#${id}`).addEventListener("click", async () => {
    try { await action(); } catch (error) { output.textContent = `${error.code || error.name}: ${error.message}`; }
  });
}
