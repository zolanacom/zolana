// Node-only test boundary. Never packaged into the browser wallet.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const storageImport = 'import { createWalletStore, openWalletStore, walletDatabaseName, WalletStorageError } from "./storage.js";';

export async function loadWorkerSource(location = new URL("./product-worker.js", import.meta.url)) {
  const source = await readFile(location, "utf8");
  const imports = source.match(/^import .* from .*;$/gm) || [];
  assert.deepEqual(imports, [storageImport], "Update the fixture's explicit storage boundary when production imports change.");
  return source.replace(storageImport + "\n", "");
}

export function createWorkerContext(globals = {}) {
  return vm.createContext({
    TextEncoder, TextDecoder, Uint8Array, AbortController, setTimeout, clearTimeout,
    fetch() { throw new Error("Unexpected network request in an offline worker fixture."); },
    ...globals,
  });
}

export function sendWorkerMessage(context, message) {
  return context.self.onmessage({ data: message });
}
