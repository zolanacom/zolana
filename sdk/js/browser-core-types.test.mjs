// Runs with `node --test sdk/js/*.test.mjs`. Compares the names exported to JavaScript by
// clients/browser-core (its #[wasm_bindgen] items) with zolana-browser-core.d.ts,
// so the hand-written types cannot silently fall behind the Rust source.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const read = path => readFileSync(new URL(path, import.meta.url), "utf8");
const sources = ["lib.rs", "vault.rs", "session.rs", "access.rs"].map(name => read(`../../clients/browser-core/src/${name}`));
const types = read("./zolana-browser-core.d.ts");

function exportedNames() {
  const methods = new Set(), functions = new Set();
  for (const source of sources) {
    const lines = source.split("\n");
    let inVaultImpl = false;
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index].trim();
      if (line === "impl BrowserVault {") inVaultImpl = lines[index - 1].trim() === "#[wasm_bindgen]";
      else if (/^(impl|mod|fn|pub fn|pub struct)\b/.test(lines[index])) inVaultImpl = false;
      if (!line.startsWith("#[wasm_bindgen")) continue;
      const next = lines[index + 1].trim();
      const named = line.match(/js_name\s*=\s*([a-z_]+)/);
      if (line.includes("js_namespace") || !next.startsWith("pub fn")) continue; // imports and impl blocks
      const name = named ? named[1] : next.match(/^pub fn ([a-z_]+)/)[1];
      (inVaultImpl ? methods : functions).add(name);
    }
  }
  return { methods: [...methods].sort(), functions: [...functions].sort() };
}

test("every exported name is declared, and nothing else is", () => {
  const { methods, functions } = exportedNames();
  assert.equal(methods.length, 23);
  assert.equal(functions.length, 6);
  const classBody = types.slice(types.indexOf("export class BrowserVault {"), types.indexOf("\n}\n", types.indexOf("export class BrowserVault {")));
  const declaredMethods = [...classBody.matchAll(/^  (?:static )?([a-z_]+)\(/gm)].map(match => match[1]).filter(name => name !== "free").sort();
  assert.deepEqual(declaredMethods, methods);
  const declaredFunctions = [...types.matchAll(/^export function ([a-z_]+)\(/gm)].map(match => match[1]).sort();
  assert.deepEqual(declaredFunctions, functions);
});

test("the error codes are the ones the core can emit", () => {
  const error = read("../../clients/browser-core/src/error.rs");
  const codes = [...error.matchAll(/ErrorCode::[A-Za-z]+ => "([a-z_]+)"/g)].map(match => match[1]).sort();
  const union = types.slice(types.indexOf("export type WalletErrorCode ="), types.indexOf(";", types.indexOf("export type WalletErrorCode =")));
  assert.deepEqual([...union.matchAll(/"([a-z_]+)"/g)].map(match => match[1]).sort(), codes);
  assert.equal(codes.length, 11);
});
