import { createWalletStore, openWalletStore, walletDatabaseName } from "./storage.js";

// PUBLIC DISPOSABLE FIXTURE ONLY. Never use this password for a real wallet.
const FIXTURE_PASSWORD = "public disposable browser vault password";
const WRONG_PASSWORD = "wrong public disposable fixture password";
// Public disposable native oracle, independently produced by the native wallet
// on Linux. These fixed addresses are never offered as payment destinations.
const NATIVE_ORACLE = Object.freeze({
  private_address: "npriv1gZWMfgeB9UAafpZyPa5Pf92AdWqYpJKVgDuHNf7Z7JGnpxQSqAYXtCgvrYcFkwfzSUDXFBDx5gtWuSQnRnGCDr6fVn3Ba7NwiuLA386Xd2dV",
  public_address: "DuHkP5SNhVMgQVyFy6BewwMX7XAna73sJrJKvBpZA7Xp",
  fee_address: "5ByNuvwqzEMuEgFGneSco289ta4RbfCmJNw5ZGLrNc1g",
});
const markerKey = "zolana-vault-reload-fixture-v1";
const output = document.querySelector("#output");
const fixtureDatabases = new Set();
let running = false, mainPasswordCopiesWiped = 0, mainPasswordWipeFailures = 0;
const assert = (condition, message) => { if (!condition) throw new Error(message); };
const equal = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
const sameIdentity = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const bytes = value => new TextEncoder().encode(value);
async function sha(value) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", value))].map(byte => byte.toString(16).padStart(2, "0")).join("");
}
function network() {
  return { network: [...crypto.getRandomValues(new Uint8Array(32))], genesis_hash: "1".repeat(32) };
}
async function refuses(action) {
  let rejected = false;
  try { await action(); } catch { rejected = true; }
  assert(rejected, "Invalid or locked operation unexpectedly succeeded.");
}

class VaultWorker {
  constructor() {
    this.worker = new Worker(new URL("./vault-worker.js", import.meta.url), { type: "module" });
    this.jobs = new Map(); this.closed = false;
    this.worker.onmessage = event => {
      const job = this.jobs.get(event.data?.id); if (!job) return;
      clearTimeout(job.timer); this.jobs.delete(event.data.id);
      if (event.data.ok) job.resolve(event.data.result); else job.reject(new Error(event.data.error || "Vault worker refused the operation."));
    };
    this.worker.onerror = () => this.close(new Error("Vault worker failed; no wallet state was replaced."));
  }
  call(action, parameters = {}) {
    if (this.closed) return Promise.reject(new Error("Vault worker is closed."));
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.close(new Error("Bounded vault fixture deadline exceeded.")), 60000);
      this.jobs.set(id, { resolve, reject, timer });
      try { this.worker.postMessage({ id, action, ...parameters }); }
      catch (error) { clearTimeout(timer); this.jobs.delete(id); reject(error); }
    });
  }
  async password(action, parameters = {}, text = FIXTURE_PASSWORD) {
    const password = bytes(text);
    try { return await this.call(action, { ...parameters, password }); }
    finally {
      password.fill(0); mainPasswordCopiesWiped++;
      if (!password.every(value => value === 0)) mainPasswordWipeFailures++;
    }
  }
  close(error = new Error("Vault fixture was closed.")) {
    if (this.closed) return; this.closed = true; this.worker.terminate();
    for (const job of this.jobs.values()) { clearTimeout(job.timer); job.reject(error); }
    this.jobs.clear();
  }
}

async function removeFixtureDatabase(name) {
  assert(fixtureDatabases.has(name), "Only allocated fixture databases may be deleted.");
  await new Promise((resolve, reject) => {
    const request = indexedDB.deleteDatabase(name);
    request.onsuccess = resolve; request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error("Another fixture connection blocks cleanup."));
  });
  fixtureDatabases.delete(name);
}
async function configurationFor(publicIdentity) {
  const networkId = await sha(bytes(JSON.stringify(["zolana-vault-fixture-network-v1", publicIdentity.network])));
  const walletId = await sha(bytes(JSON.stringify(["zolana-vault-fixture-wallet-v1", publicIdentity.network, publicIdentity.private_address])));
  return { walletId, networkId, dbName: walletDatabaseName(walletId, networkId) };
}
function show(report) {
  // Fixed public vectors are available to the root acceptance runner, while no
  // address or encrypted backup is displayed as a wallet to fund.
  const { referenceIdentity, ...visible } = report;
  output.textContent = JSON.stringify({ ...visible, publicReferenceAvailableForNativeComparison: !!referenceIdentity }, null, 2);
}
async function exclusive(action) {
  assert(!running, "Another vault acceptance operation is running."); running = true;
  try { return await action(); } finally { running = false; }
}

export async function runVaultTests() {
  return exclusive(async () => {
    assert(sessionStorage.getItem(markerKey) === null, "Recover the prepared reload fixture before a new suite.");
    const client = new VaultWorker(), results = [], started = performance.now();
    const synthetic = network(), networkJson = JSON.stringify(synthetic);
    let first, identity, backup, referenceIdentity, disposed, nativeOracleMatched = false;
    const test = async (name, action) => {
      const at = performance.now();
      try { await action(); results.push({ name, passed: true, elapsedMs: performance.now() - at }); }
      catch (error) { results.push({ name, passed: false, error: String(error.message || error).slice(0, 180) }); }
    };
    try {
      await test("opaque BrowserVault class loads in the scalar worker", async () => {
        assert((await client.call("ready")).opaqueVault === true, "Missing opaque BrowserVault ABI.");
      });
      await test("create generates an unlocked local vault without seed export", async () => {
        first = await client.password("create", { networkJson });
        assert(typeof first.handle === "string" && first.locked === false, "Create did not return an unlocked opaque handle.");
        identity = await client.call("identity", { handle: first.handle });
        assert(identity.format === "zolana-browser-vault-identity-v1" && identity.private_address.startsWith("npriv1") && sameIdentity(identity.network, synthetic), "Public identity format or synthetic network differs.");
      });
      await test("backup is the existing encrypted native format at 600000 rounds", async () => {
        backup = (await client.call("backup", { handle: first.handle })).encrypted;
        const envelope = JSON.parse(new TextDecoder().decode(backup));
        assert(envelope.format === "native-wallet-seed-v1" && envelope.rounds === 600000 && envelope.ciphertext.length === 48 && sameIdentity(envelope.network, synthetic), "Backup format/KDF differs.");
      });
      await test("lock revokes identity access but preserves encrypted backup bytes", async () => {
        assert((await client.call("lock", { handle: first.handle })).locked, "Lock did not revoke access.");
        await refuses(() => client.call("identity", { handle: first.handle }));
        assert(equal((await client.call("backup", { handle: first.handle })).encrypted, backup), "Lock changed encrypted backup.");
      });
      await test("unlock recovers the same identity", async () => {
        assert((await client.password("unlock", { handle: first.handle })).locked === false, "Unlock failed.");
        assert(sameIdentity(await client.call("identity", { handle: first.handle }), identity), "Unlock changed identity.");
      });
      await test("wrong password while unlocked fails closed and removes earlier access", async () => {
        await refuses(() => client.password("unlock", { handle: first.handle }, WRONG_PASSWORD));
        assert((await client.call("state", { handle: first.handle })).locked, "Failed unlock retained an earlier seed.");
        await refuses(() => client.call("identity", { handle: first.handle }));
        await client.password("unlock", { handle: first.handle });
      });
      await test("native encrypted backup restores exact identity and ciphertext", async () => {
        const restored = await client.password("restore", { networkJson, encrypted: backup });
        assert(sameIdentity(await client.call("identity", { handle: restored.handle }), identity), "Restore changed identity.");
        assert(equal((await client.call("backup", { handle: restored.handle })).encrypted, backup), "Restore re-encrypted or changed the original backup.");
        await client.call("free", { handle: restored.handle });
        await refuses(() => client.call("state", { handle: restored.handle }));
      });
      await test("wrong password/network/genesis cannot restore a vault", async () => {
        await refuses(() => client.password("restore", { networkJson, encrypted: backup }, WRONG_PASSWORD));
        const wrong = { ...synthetic, network: [...synthetic.network] }; wrong.network[0] ^= 1;
        await refuses(() => client.password("restore", { networkJson: JSON.stringify(wrong), encrypted: backup }));
        const wrongGenesis = { ...synthetic, genesis_hash: "1".repeat(31) + "2" };
        await refuses(() => client.password("restore", { networkJson: JSON.stringify(wrongGenesis), encrypted: backup }));
      });
      await test("modified ciphertext and downgraded KDF are rejected", async () => {
        const changed = JSON.parse(new TextDecoder().decode(backup)); changed.ciphertext[0] ^= 1;
        await refuses(() => client.password("restore", { networkJson, encrypted: bytes(JSON.stringify(changed)) }));
        const downgraded = JSON.parse(new TextDecoder().decode(backup)); downgraded.rounds = 1;
        await refuses(() => client.password("restore", { networkJson, encrypted: bytes(JSON.stringify(downgraded)) }));
      });
      await test("production creates use fresh salts and nonces", async () => {
        const other = await client.password("create", { networkJson });
        const second = (await client.call("backup", { handle: other.handle })).encrypted;
        const a = JSON.parse(new TextDecoder().decode(backup)), b = JSON.parse(new TextDecoder().decode(second));
        assert(!equal(a.salt, b.salt) && !equal(a.nonce, b.nonce), "Salt or nonce was reused.");
        await client.call("free", { handle: other.handle });
      });
      await test("actual Rust ABI rejects oversized/short malformed fixture inputs", async () => {
        assert((await client.call("bounds", { networkJson })).rustBoundsRejected === 5, "Rust bound checks incomplete.");
      });
      await test("real encrypted seed persists through IDB close/reopen and unlock", async () => {
        const configuration = await configurationFor(identity); fixtureDatabases.add(configuration.dbName);
        const store = await createWalletStore({ ...configuration, encryptedWallet: backup });
        const instance = (await store.snapshot()).instanceId; store.close();
        const reopened = await openWalletStore({ ...configuration, expectedInstanceId: instance });
        try {
          const saved = await reopened.snapshot();
          const restored = await client.password("restore", { networkJson, encrypted: saved.encryptedWallet });
          assert(sameIdentity(await client.call("identity", { handle: restored.handle }), identity), "IDB restoration changed identity.");
          await client.call("lock", { handle: restored.handle }); await client.password("unlock", { handle: restored.handle });
          assert(sameIdentity(await client.call("identity", { handle: restored.handle }), identity), "Reopened unlock changed identity.");
          await client.call("free", { handle: restored.handle });
        } finally { reopened.close(); await removeFixtureDatabase(configuration.dbName); }
      });
      await test("fixed Rust identity exactly matches the independent Linux native oracle", async () => {
        const accepted = await client.call("acceptance");
        assert(accepted.ok && accepted.fixtureOnly && accepted.rounds === 600000, "Rust acceptance failed.");
        referenceIdentity = accepted.referenceIdentity;
        assert(referenceIdentity?.format === "zolana-browser-vault-identity-v1" &&
          referenceIdentity.network?.network.length === 32 && referenceIdentity.network.network.every(value => value === 7) &&
          referenceIdentity.network.genesis_hash === "1".repeat(32), "Reference is not the fixed public fixture.");
        assert(Object.entries(NATIVE_ORACLE).every(([key, value]) => referenceIdentity[key] === value), "Browser identity differs from the independent Linux native wallet oracle.");
        nativeOracleMatched = true;
      });
      await test("free releases opaque handles and JS password copies were wiped", async () => {
        await client.call("free", { handle: first.handle });
        await refuses(() => client.call("identity", { handle: first.handle }));
        disposed = await client.call("dispose");
        assert(disposed.liveHandles === 0 && disposed.passwordCopiesWiped > 0 && disposed.passwordWipeFailures === 0 && mainPasswordWipeFailures === 0, "JS password-copy cleanup failed.");
      });
    } finally {
      try { if (!disposed) disposed = await client.call("dispose"); } catch { /* Worker failure is already a failed gate. */ }
      client.close();
      for (const name of [...fixtureDatabases]) await removeFixtureDatabase(name);
    }
    const report = { format: "zolana-browser-vault-js-acceptance-v1", passed: results.every(result => result.passed),
      testCount: results.length, results, elapsedMs: performance.now() - started,
      realLocalVaultCryptoExercised: !!(first && identity && backup), paymentTest: false, chainFinalityVerified: false,
      existingWalletsTouched: false, generatedAddressesDisplayed: false,
      mainPasswordCopiesWiped, mainPasswordWipeFailures, workerCleanup: disposed,
      referenceIdentity, nativeOracleMatched, nativeOracleComparisonRequired: !nativeOracleMatched };
    window.vaultTestResult = report; show(report); return report;
  });
}

export async function prepareVaultReloadTest() {
  return exclusive(async () => {
    assert(sessionStorage.getItem(markerKey) === null, "A prepared encrypted reload fixture already exists.");
    const client = new VaultWorker(); let store;
    try {
      const synthetic = network(), networkJson = JSON.stringify(synthetic);
      const created = await client.password("create", { networkJson });
      const identity = await client.call("identity", { handle: created.handle });
      const encryptedWallet = (await client.call("backup", { handle: created.handle })).encrypted;
      const configuration = await configurationFor(identity); fixtureDatabases.add(configuration.dbName);
      store = await createWalletStore({ ...configuration, encryptedWallet });
      const snapshot = await store.snapshot();
      const record = { format: markerKey, ...configuration, expectedInstanceId: snapshot.instanceId,
        network: synthetic, identityDigest: await sha(bytes(JSON.stringify(identity))),
        backupDigest: await sha(encryptedWallet) };
      sessionStorage.setItem(markerKey, JSON.stringify(record));
      await client.call("lock", { handle: created.handle }); await client.call("free", { handle: created.handle });
      const report = { prepared: true, realEncryptedNativeBackup: true, reloadRequired: true,
        sessionStorageContainsOnlyPublicMetadata: true, existingWalletsTouched: false };
      window.vaultReloadPrepared = report; show(report); return report;
    } finally { store?.close(); try { await client.call("dispose"); } catch { /* Preserve encrypted fixture on failure. */ } client.close(); }
  });
}

export async function recoverVaultReloadTest() {
  return exclusive(async () => {
    const record = JSON.parse(sessionStorage.getItem(markerKey) || "null");
    assert(record?.format === markerKey && record.dbName === walletDatabaseName(record.walletId, record.networkId), "No valid prepared encrypted reload fixture.");
    fixtureDatabases.add(record.dbName);
    const client = new VaultWorker(); let store, succeeded = false;
    try {
      store = await openWalletStore(record); const saved = await store.snapshot();
      assert(await sha(saved.encryptedWallet) === record.backupDigest, "Reload changed encrypted backup bytes.");
      const networkJson = JSON.stringify(record.network);
      await refuses(() => client.password("restore", { networkJson, encrypted: saved.encryptedWallet }, WRONG_PASSWORD));
      const restored = await client.password("restore", { networkJson, encrypted: saved.encryptedWallet });
      await client.call("lock", { handle: restored.handle });
      assert((await client.call("state", { handle: restored.handle })).locked, "Restored wallet did not lock.");
      await client.password("unlock", { handle: restored.handle });
      const identity = await client.call("identity", { handle: restored.handle });
      assert(await sha(bytes(JSON.stringify(identity))) === record.identityDigest, "Reload/unlock recovered another identity.");
      assert(equal((await client.call("backup", { handle: restored.handle })).encrypted, saved.encryptedWallet), "Reload re-encrypted the original backup.");
      await client.call("free", { handle: restored.handle });
      const cleaned = await client.call("dispose"); assert(cleaned.passwordWipeFailures === 0, "Worker password-copy cleanup failed.");
      const report = { format: "zolana-browser-vault-reload-v1", reloadRecovered: true,
        exactEncryptedBackupPreserved: true, samePublicIdentity: true, wrongPasswordRejected: true,
        lockedThenUnlocked: true, realLocalVaultCryptoExercised: true, paymentTest: false,
        chainFinalityVerified: false, existingWalletsTouched: false, generatedAddressesDisplayed: false };
      window.vaultReloadResult = report; show(report); succeeded = true; return report;
    } finally {
      store?.close(); try { await client.call("dispose"); } catch { /* No secrets are logged on failure. */ } client.close();
      if (succeeded) { await removeFixtureDatabase(record.dbName); sessionStorage.removeItem(markerKey); }
    }
  });
}

window.runVaultTests = runVaultTests;
window.prepareVaultReloadTest = prepareVaultReloadTest;
window.recoverVaultReloadTest = recoverVaultReloadTest;
for (const [id, action] of [["run", runVaultTests], ["prepare", prepareVaultReloadTest], ["recover", recoverVaultReloadTest]]) {
  document.querySelector(`#${id}`).addEventListener("click", async () => {
    try { await action(); } catch (error) { output.textContent = String(error.message || error).slice(0, 180); }
  });
}
