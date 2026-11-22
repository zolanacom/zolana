// Look a transaction up in the devnet explorer feed.
//
//     node sdk/js/examples/payment-landed.mjs [signature ...] [--feed <file or URL>]
//
// Without --feed it is offline: it reads the sample feed in
// clients/devnet-explorer. Without a signature it looks up the newest and the
// oldest transaction of that feed and one signature the feed does not hold.
// @ts-check
import { readFileSync } from "node:fs";
import { findTransaction, validateExplorerFeed } from "../explorer.mjs";

const flag = process.argv.indexOf("--feed");
const source = flag < 0 ? undefined : process.argv[flag + 1];
const wanted = process.argv.slice(2).filter((_, index) => flag < 0 || (index + 2 !== flag && index + 2 !== flag + 1));

const text = source !== undefined && /^https?:/.test(source)
  ? await (await fetch(source, { cache: "no-store" })).text()
  : readFileSync(source ?? new URL("../../../clients/devnet-explorer/feed.sample.json", import.meta.url), "utf8");
// Refuses anything that does not follow the feed contract.
const feed = validateExplorerFeed(JSON.parse(text));
const finalized = feed.network.finalized_slot;
console.log(`feed ${feed.format}: status ${feed.network.status}, finalized slot ${finalized ?? "unknown"}, ${feed.transactions.length} transactions in the window`);

const signatures = wanted.length > 0 ? wanted
  : [feed.transactions[0].signature, feed.transactions.at(-1)?.signature ?? "", "1".repeat(64)];
for (const signature of signatures) {
  const found = findTransaction(feed, signature);
  if (found === null) {
    // Not in the window. This says nothing about whether it was ever executed.
    console.log(`${signature}\n  not in the feed's window`);
    continue;
  }
  const { transaction, atOrBelowFinalized } = found;
  const place = atOrBelowFinalized === null ? "the feed reports no finalized slot"
    : atOrBelowFinalized ? "at or below the feed's finalized slot" : "above the feed's finalized slot: look again later";
  console.log(`${signature}\n  slot ${transaction.slot}, ${transaction.ok ? "no error recorded" : "failed"}, fee ${transaction.fee}, ${place}`);
}
