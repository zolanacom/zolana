// Read the pool account and print a line whenever it changes.
//
//     node sdk/js/examples/watch-pool.mjs
//     node sdk/js/examples/watch-pool.mjs --url http://127.0.0.1:18899 [--interval 2000] [--polls 10]
//
// Without --url it is offline: it decodes sdk/fixtures/pool-account.base64, the
// pool after a deposit of 100, a send with a fee of 3 and a withdrawal of 20.
// With --url it asks that endpoint for the account until interrupted. Use a
// local network; a devnet gateway answers cohort wallets only.
// @ts-check
import { readFileSync } from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { decodePoolAccount, POOL_ADDRESS, PROGRAM_ID } from "../formats.mjs";
import { createRpcClient } from "../rpc.mjs";

const option = (/** @type {string} */ name) => {
  const index = process.argv.indexOf(name);
  return index < 0 ? undefined : process.argv[index + 1];
};
const url = option("--url");
const interval = Number(option("--interval") ?? 2000);
const polls = Number(option("--polls") ?? Infinity);

/** @param {string} data The account data as base64. */
function describe(data) {
  const pool = decodePoolAccount(new Uint8Array(Buffer.from(data, "base64")));
  const latest = pool.slotAnchors.at(-1);
  return `${pool.tag}: ${pool.noteCount} notes, backing ${pool.backing}` +
    (latest ? `, latest root ${latest.root} at slot ${latest.slot}` : "");
}

if (url === undefined) {
  console.log(describe(readFileSync(new URL("../../fixtures/pool-account.base64", import.meta.url), "utf8")));
} else {
  const rpc = createRpcClient({ url });
  let previous;
  for (let poll = 0; poll < polls; poll++) {
    if (poll > 0) await sleep(interval);
    const account = await rpc.getAccountInfo(POOL_ADDRESS);
    if (account.value === null) throw new Error("this network has no pool account");
    // The pool is the account at this address that the payment program owns.
    if (account.value.owner !== PROGRAM_ID) throw new Error("the account is not owned by the payment program");
    const line = describe(account.value.data[0]);
    if (line !== previous) console.log(`slot ${account.context.slot}: ${line}`);
    previous = line;
  }
}
