// Disposable acceptance worker only. No RPC, existing-wallet input or seed API.
// The wasm-bindgen BrowserVault owns the seed; messages carry opaque handles,
// public identity or encrypted backup bytes only.
let modulePromise;
const vaults = new Map();
let passwordCopiesWiped = 0, passwordWipeFailures = 0;

async function core() {
  if (!modulePromise) modulePromise = (async () => {
    const module = await import("/wasm/browser_core.js");
    await module.default();
    if (typeof module.BrowserVault?.create !== "function" || typeof module.BrowserVault?.restore !== "function") {
      throw new Error("Compiled artifact lacks the reviewed BrowserVault interface.");
    }
    return module;
  })();
  return modulePromise;
}
function boundedNetwork(value) {
  if (typeof value !== "string" || new TextEncoder().encode(value).length > 1024) throw new Error("Bounded synthetic network JSON required.");
  return value;
}
function encrypted(value) {
  if (!(value instanceof Uint8Array) || value.length > 4096) throw new Error("Bounded encrypted native backup required.");
  return value;
}
function withPassword(message, action) {
  const password = message.password;
  if (!(password instanceof Uint8Array) || password.length < 12 || password.length > 1024) throw new Error("Bounded password byte array required.");
  return action(password); // Outer message finally also covers module-load errors.
}
function vault(handle) {
  if (typeof handle !== "string" || !vaults.has(handle)) throw new Error("Unknown or released vault handle.");
  return vaults.get(handle);
}
function keep(value) {
  const handle = crypto.randomUUID(); vaults.set(handle, value);
  return { handle, locked: value.is_locked() };
}
function mustReject(action) {
  let result, accepted = false;
  try { result = action(); accepted = true; } catch { /* Expected rejection. */ }
  finally { if (result && typeof result.free === "function") result.free(); }
  if (accepted) throw new Error("Rust accepted an invalid bounded fixture input.");
}

async function dispatch(message) {
  if (!message || typeof message.id !== "string" || message.id.length > 64 ||
      !["ready", "create", "restore", "identity", "backup", "lock", "unlock", "state", "free", "bounds", "acceptance", "dispose"].includes(message.action)) {
    throw new Error("Unknown bounded vault test operation.");
  }
  const module = await core();
  switch (message.action) {
    case "ready": return { ready: true, mode: "scalar-worker", opaqueVault: true };
    case "create": return withPassword(message, password => keep(module.BrowserVault.create(boundedNetwork(message.networkJson), password)));
    case "restore": return withPassword(message, password => keep(module.BrowserVault.restore(boundedNetwork(message.networkJson), encrypted(message.encrypted), password)));
    case "identity": return JSON.parse(vault(message.handle).identity());
    case "backup": return { encrypted: vault(message.handle).encrypted_backup() };
    case "lock": { const value = vault(message.handle); value.lock(); return { locked: value.is_locked() }; }
    case "unlock": return withPassword(message, password => { const value = vault(message.handle); value.unlock(password); return { locked: value.is_locked() }; });
    case "state": return { locked: vault(message.handle).is_locked() };
    case "free": { const value = vault(message.handle); vaults.delete(message.handle); value.free(); return { released: true }; }
    case "bounds": {
      // Exercise the actual Rust ABI bounds, independently of the outer JS
      // message limits, using only small disposable buffers made here.
      const password = new TextEncoder().encode("public disposable vault boundary fixture");
      const tooLong = new Uint8Array(1025), tooShort = new Uint8Array(11);
      try {
        const networkJson = boundedNetwork(message.networkJson);
        mustReject(() => module.BrowserVault.create(networkJson, tooLong));
        mustReject(() => module.BrowserVault.create(networkJson, tooShort));
        mustReject(() => module.BrowserVault.create(" ".repeat(1025), password));
        mustReject(() => module.BrowserVault.restore(networkJson, new Uint8Array(4097), password));
        mustReject(() => module.BrowserVault.restore(networkJson, new Uint8Array(), password));
        return { rustBoundsRejected: 5 };
      } finally { password.fill(0); tooLong.fill(0); tooShort.fill(0); }
    }
    case "acceptance": {
      const result = JSON.parse(module.vault_acceptance());
      if (result.fixture_only !== true || result.ok !== true || result.reference?.fixture_only !== true) throw new Error("Rust fixture acceptance failed.");
      // No encrypted fixture or randomly generated identity enters the report.
      return { ok: true, fixtureOnly: true, rounds: result.rounds, checks: result.checks,
        referenceIdentity: result.reference.identity, elapsedMs: result.elapsed_ms };
    }
    case "dispose": {
      for (const value of vaults.values()) value.free(); vaults.clear();
      return { liveHandles: 0, passwordCopiesWiped, passwordWipeFailures };
    }
  }
}

let queue = Promise.resolve();
self.onmessage = event => {
  const message = event.data;
  queue = queue.then(async () => {
    let response;
    try { response = { id: message?.id, ok: true, result: await dispatch(message) }; }
    catch (error) {
      // Core errors contain no supplied seed/password/ciphertext; do not emit
      // stacks, input objects or diagnostic memory.
      response = { id: message?.id, ok: false,
        error: String(error?.message || error || "Vault fixture failed").slice(0, 180) };
    } finally {
      if (message?.password instanceof Uint8Array) {
        message.password.fill(0); passwordCopiesWiped++;
        if (!message.password.every(value => value === 0)) passwordWipeFailures++;
      }
    }
    self.postMessage(response);
  });
};
