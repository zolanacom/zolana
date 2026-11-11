import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import vm from "node:vm";
import { createWorkerContext, loadWorkerSource } from "./product-worker-harness.mjs";

test("worker harness accepts a separate source path without loading real storage", async t => {
  const directory = await mkdtemp(join(tmpdir(), "zolana-worker-fixture-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const location = join(directory, "worker source.js");
  const original = await readFile(new URL("./product-worker.js", import.meta.url), "utf8");
  await writeFile(location, original);
  const source = await loadWorkerSource(location);
  assert(!source.includes('from "./storage.js"'));
  assert(source.includes("self.onmessage ="));
});

test("worker harness refuses a changed or additional static import", async t => {
  const directory = await mkdtemp(join(tmpdir(), "zolana-worker-import-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const location = join(directory, "worker.js");
  const original = await readFile(new URL("./product-worker.js", import.meta.url), "utf8");
  for (const source of [
    original.replace('from "./storage.js"', 'from "./changed-storage.js"'),
    original.replace(/^import .*;\n/m, ""),
    'import { unexpected } from "./other.js";\n' + original,
  ]) {
    await writeFile(location, source);
    await assert.rejects(loadWorkerSource(location), /explicit storage boundary/);
  }
});

test("worker contexts block network by default and permit explicit inert transports", () => {
  const context = createWorkerContext();
  assert.throws(() => vm.runInContext('fetch("https://fixture.invalid/")', context), /Unexpected network request/);
  const paths = [];
  const fixture = createWorkerContext({ fetch: path => { paths.push(path); return "fixture reply"; } });
  assert.equal(vm.runInContext('fetch("/fixture")', fixture), "fixture reply");
  assert.deepEqual(paths, ["/fixture"]);
});
