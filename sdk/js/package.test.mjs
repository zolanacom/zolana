// Runs with `node --test sdk/js/*.test.mjs`. Offline. Checks the package surface: the manifest,
// the single entry point, and that the declaration files name exactly what the modules export.
// The declarations are generated from the modules with TypeScript, which is not a dependency
// of this repository, so here they are compared by name, not regenerated.
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

const read = name => readFileSync(new URL(name, import.meta.url), "utf8");
const manifest = JSON.parse(read("./package.json"));

test("the manifest describes a private, dependency-free package whose files exist", () => {
  assert.equal(manifest.private, true, "the package must not be publishable");
  assert.equal(manifest.type, "module");
  assert.match(manifest.description, /not published to npm/);
  for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]) assert.equal(manifest[field], undefined, field);
  assert.deepEqual(Object.keys(manifest.exports), [".", "./rpc", "./formats", "./explorer"]);
  for (const entry of Object.values(manifest.exports)) for (const file of Object.values(entry)) assert.ok(existsSync(new URL(file, import.meta.url)), file);
  // The version is the workspace's.
  const workspace = readFileSync(new URL("../../Cargo.toml", import.meta.url), "utf8");
  assert.ok(workspace.includes(`version = "${manifest.version}"`));
});

test("the entry point exports every part, under the package's own name too", async () => {
  const parts = await Promise.all(["./rpc.mjs", "./formats.mjs", "./explorer.mjs"].map(name => import(name)));
  const names = parts.flatMap(part => Object.keys(part));
  assert.equal(new Set(names).size, names.length, "no two parts export the same name");
  const index = await import("./index.mjs");
  assert.deepEqual(Object.keys(index).sort(), [...names].sort());
  // Node resolves a package's own name from inside it, through the exports map.
  const byName = await import(manifest.name);
  assert.equal(byName.decodePayment, index.decodePayment);
  assert.equal((await import(`${manifest.name}/rpc`)).createRpcClient, index.createRpcClient);
  assert.equal((await import(`${manifest.name}/formats`)).paymentId, index.paymentId);
  assert.equal((await import(`${manifest.name}/explorer`)).findTransaction, index.findTransaction);
  await assert.rejects(() => import(`${manifest.name}/rpc.test.mjs`), { code: "ERR_PACKAGE_PATH_NOT_EXPORTED" });
  assert.equal(read("./index.d.mts").trim(), read("./index.mjs").split("\n").filter(line => line.startsWith("export ")).join("\n"));
});

test("the declaration files name exactly what formats.mjs and explorer.mjs export", async () => {
  for (const name of ["formats", "explorer"]) {
    const exported = Object.keys(await import(`./${name}.mjs`)).sort();
    const declared = [...read(`./${name}.d.mts`).matchAll(/^export (?:const|function|class) ([A-Za-z0-9_]+)/gm)].map(match => match[1]).sort();
    assert.deepEqual(declared, exported, name);
    // Every type the JSDoc of the module defines is declared as well.
    const types = [...read(`./${name}.mjs`).matchAll(/@typedef \{.*\} ([A-Za-z]+)/g)].map(match => match[1]);
    assert.ok(types.length >= 7, name);
    const declarations = read(`./${name}.d.mts`);
    for (const type of types) assert.match(declarations, new RegExp(`^export type ${type} = `, "m"), `${name}: ${type}`);
    // The first two lines say how the file was generated.
    assert.ok(declarations.startsWith(`// Generated from ${name}.mjs. Do not edit; regenerate with TypeScript 5.9:\n//   tsc `), name);
    assert.ok(declarations.split("\n")[1].endsWith(` ${name}.mjs`), name);
  }
});
