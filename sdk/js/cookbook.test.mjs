// Runs with `node --test sdk/js/*.test.mjs`. Offline. Keeps docs/cookbook and the examples in
// step: every code block on a cookbook page must be a passage of the file it names, and every
// output block must be what that file prints. Then runs the examples in the modes the pages
// describe, against loopback servers where a page talks about an endpoint.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { test } from "node:test";
import { POOL_ADDRESS, PROGRAM_ID } from "./formats.mjs";

const root = new URL("../../", import.meta.url);
const read = path => readFileSync(new URL(path, root), "utf8");
const run = promisify(execFile);
/** Runs `node <arguments>` from the repository root and returns what it printed. */
const node = async (...parts) => (await run(process.execPath, parts, { cwd: fileURLToPath(root) })).stdout;
const pages = readdirSync(new URL("docs/cookbook/", root)).filter(name => name.endsWith(".md")).sort();
const EXAMPLES = ["check-address", "decode-payment", "payment-landed", "watch-pool"];

/** The fenced blocks of a page: language, text, and the marker comment on the line before. */
function blocks(markdown) {
  const lines = markdown.split("\n"), found = [];
  for (let index = 0; index < lines.length; index++) {
    const open = lines[index].match(/^```([a-z]*)$/);
    if (!open) continue;
    const end = lines.indexOf("```", index + 1);
    assert.ok(end > index, "unterminated code block");
    const marker = lines[index - 1]?.match(/^<!-- (snippet|output|file): (.+) -->$/);
    found.push({ language: open[1], text: lines.slice(index + 1, end).join("\n"), marker: marker ? { kind: marker[1], target: marker[2] } : null });
    index = end;
  }
  return found;
}

/** Serves one answer per request on a loopback port for the duration of `use`. */
async function serving(answer, use) {
  const seen = [];
  const server = createServer((request, response) => {
    const chunks = [];
    request.on("data", chunk => chunks.push(chunk));
    request.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push(body);
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(answer(body));
    });
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  try { return await use(`http://127.0.0.1:${server.address().port}`, seen); }
  finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
}

test("the cookbook has the five pages its index lists, and their links resolve", () => {
  assert.deepEqual(pages, ["README.md", "check-an-address.md", "check-that-a-payment-landed.md", "decode-a-payment.md", "verify-a-payment-offline.md", "watch-the-pool-account.md"]);
  const index = read("docs/cookbook/README.md");
  for (const page of pages.slice(1)) assert.ok(index.includes(`](${page})`), page);
  for (const page of pages) {
    for (const [, target] of read(`docs/cookbook/${page}`).matchAll(/\]\(([^)#]+)(?:#[^)]*)?\)/g)) {
      if (/^https?:/.test(target)) continue;
      assert.ok(existsSync(new URL(target, new URL(`docs/cookbook/${page}`, root))), `${page}: ${target}`);
    }
  }
});

test("every code block is a passage of the file it names, and every output block is what that file prints", async () => {
  let snippets = 0, outputs = 0;
  for (const page of pages) {
    for (const block of blocks(read(`docs/cookbook/${page}`))) {
      const where = `${page}: ${block.text.split("\n")[0]}`;
      if (block.language === "sh") {
        // Commands: each names an example or a package target that exists.
        for (const line of block.text.split("\n")) {
          const example = line.match(/^node (sdk\/js\/examples\/[a-z-]+\.mjs)/), bin = line.match(/--bin ([a-z-]+)/);
          assert.ok(example || bin || line === "node --test sdk/js/*.test.mjs" || line === "sh tools/dev.sh test --offline --locked -p zolana-sdk-examples", where);
          if (example) assert.ok(existsSync(new URL(example[1], root)), where);
          if (bin) assert.ok(existsSync(new URL(`sdk/rust-examples/src/bin/${bin[1]}.rs`, root)) && line.startsWith("sh tools/dev.sh run --offline --locked -p zolana-sdk-examples "), where);
        }
        continue;
      }
      assert.ok(block.marker, `${where}: a ${block.language || "plain"} block needs a snippet, output or file marker`);
      const { kind, target } = block.marker;
      if (kind === "snippet") {
        assert.ok(["js", "rust"].includes(block.language) && block.text.trim().length > 40, where);
        assert.ok(read(target).includes(`\n${block.text}\n`), `${where}: not a passage of ${target}`);
        snippets++;
      } else if (kind === "output") {
        const command = target.match(/^node (sdk\/js\/examples\/[a-z-]+\.mjs)$/);
        assert.ok(command && block.language === "text", where);
        assert.equal(await node(command[1]), `${block.text}\n`, where);
        outputs++;
      } else {
        // The Rust tests compare this file with what the command prints.
        assert.equal(read(target), `${block.text}\n`, where);
        assert.ok(read("sdk/rust-examples/tests/inspect.rs").includes(`"${target.split("/").at(-1)}"`), where);
        outputs++;
      }
    }
  }
  assert.deepEqual([snippets, outputs], [6, 5]);
  // The SDK's own pages quote the same outputs. Their marked blocks are held to the same rule.
  let quoted = 0;
  for (const page of ["sdk/EXAMPLES.md", "sdk/js/README.md"]) {
    for (const block of blocks(read(page)).filter(block => block.marker)) {
      const { kind, target } = block.marker;
      if (kind === "file") assert.equal(read(target), `${block.text}\n`, page);
      else assert.equal(await node(target.replace(/^node /, "")), `${block.text}\n`, page);
      assert.ok(kind !== "snippet" && (kind === "file" || /^node sdk\/js\/examples\/[a-z-]+\.mjs$/.test(target)), page);
      quoted++;
    }
  }
  assert.equal(quoted, 3);
  // Each example is shown on a page with its output.
  const shown = pages.map(page => read(`docs/cookbook/${page}`)).join("\n");
  for (const name of EXAMPLES) assert.ok(shown.includes(`<!-- output: node sdk/js/examples/${name}.mjs -->`), name);
  assert.deepEqual(readdirSync(new URL("sdk/js/examples/", root)).sort(), EXAMPLES.map(name => `${name}.mjs`));
});

test("decode-payment and check-address take an argument", async () => {
  const deposit = await node("sdk/js/examples/decode-payment.mjs", "sdk/fixtures/deposit.hex");
  assert.match(deposit, /^deposit: 9222 bytes, tag NPAY0001\n/);
  assert.match(deposit, /\npublic value  -100\nshielded fee  null\n/);
  const expected = JSON.parse(read("sdk/fixtures/expected.json"));
  const alice = await node("sdk/js/examples/check-address.mjs", expected.addresses.alice);
  assert.match(alice, /^the address: well formed, and for this network\none character changed: refused /);
  const mistyped = await node("sdk/js/examples/check-address.mjs", expected.addresses.alice.replace("npriv1", "npriv2"));
  assert.match(mistyped, /^the address: refused \(InvalidEncoding: invalid receiving address prefix\)\n/);
  await assert.rejects(() => node("sdk/js/examples/decode-payment.mjs", "sdk/fixtures/pool-account.base64"));
});

test("watch-pool asks an endpoint for the pool account and prints it once while it is unchanged", async () => {
  const data = read("sdk/fixtures/pool-account.base64").trim();
  const account = owner => body => {
    const request = JSON.parse(body);
    return JSON.stringify({ jsonrpc: "2.0", id: request.id, result: { context: { slot: 3 }, value: { owner, lamports: 78, data: [data, "base64"] } } });
  };
  await serving(account(PROGRAM_ID), async (url, seen) => {
    const printed = await node("sdk/js/examples/watch-pool.mjs", "--url", url, "--interval", "20", "--polls", "3");
    assert.equal(printed, `slot 3: ${await node("sdk/js/examples/watch-pool.mjs")}`);
    assert.equal(seen.length, 3);
    for (const body of seen) assert.deepEqual([JSON.parse(body).method, JSON.parse(body).params], ["getAccountInfo", [POOL_ADDRESS, { commitment: "finalized", encoding: "base64" }]]);
  });
  // An account at the pool address that another program owns is refused.
  await serving(account("1".repeat(32)), async url => {
    await assert.rejects(() => node("sdk/js/examples/watch-pool.mjs", "--url", url, "--polls", "1"), /not owned by the payment program/);
  });
  await serving(body => JSON.stringify({ jsonrpc: "2.0", id: JSON.parse(body).id, result: { context: { slot: 3 }, value: null } }), async url => {
    await assert.rejects(() => node("sdk/js/examples/watch-pool.mjs", "--url", url, "--polls", "1"), /no pool account/);
  });
});

test("payment-landed reads a feed from a file or a URL and looks up the signatures it is given", async () => {
  const sample = read("clients/devnet-explorer/feed.sample.json"), feed = JSON.parse(sample);
  // The sample holds a transaction the node recorded an error for.
  const failed = feed.transactions.find(item => !item.ok), signature = failed.signature;
  const fromFile = await node("sdk/js/examples/payment-landed.mjs", signature, "--feed", "clients/devnet-explorer/feed.sample.json");
  assert.equal(fromFile.split("\n").length, 4);
  assert.ok(fromFile.endsWith(`${signature}\n  slot ${failed.slot}, failed, fee ${failed.fee}, at or below the feed's finalized slot\n`));
  await serving(() => sample, async (url, seen) => {
    const fromUrl = await node("sdk/js/examples/payment-landed.mjs", "--feed", `${url}/explorer/feed.json`, signature, "2".repeat(64));
    assert.equal(fromUrl, `${fromFile}${"2".repeat(64)}\n  not in the feed's window\n`);
    assert.equal(seen.length, 1);
  });
  // A document that is not a feed is refused before anything is looked up.
  await serving(() => JSON.stringify({ ...feed, format: "another" }), async url => {
    await assert.rejects(() => node("sdk/js/examples/payment-landed.mjs", "--feed", url), /format must be exactly zolana-explorer-feed-v0/);
  });
  // A feed that knows no finalized slot cannot place a transaction, and the example says so.
  await serving(() => JSON.stringify({ ...feed, network: { ...feed.network, finalized_slot: null } }), async url => {
    const printed = await node("sdk/js/examples/payment-landed.mjs", "--feed", url, signature);
    assert.match(printed, /finalized slot unknown, /);
    assert.ok(printed.endsWith(`fee ${failed.fee}, the feed reports no finalized slot\n`));
  });
  // The paused sample is a valid feed too.
  assert.match(await node("sdk/js/examples/payment-landed.mjs", "--feed", "clients/devnet-explorer/feed.paused.json"), /^feed zolana-explorer-feed-v0: status /);
});
