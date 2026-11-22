// Runs with `node --test clients/devnet-explorer/*.test.mjs`. Offline, Node built-ins only.
// Reads index.html and explorer.js as text and checks that they still fit each other, and
// that the page words its figures for what they are. The script draws nothing unless every
// element it binds is on the page, so a page that falls behind the script fails here and
// not silently in a browser. Nothing is rendered: these are checks of the two texts.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const read = name => readFileSync(new URL(`./${name}`, import.meta.url), 'utf8');
const page = read('index.html');
const script = read('explorer.js');
const count = (text, part) => text.split(part).length - 1;

test('the page carries every element the script binds, once', () => {
  const bound = [...script.matchAll(/byId\('([a-z-]+)'\)/g)].map(match => match[1]);
  const lists = [...script.matchAll(/listView\('([a-z]+)',/g)].map(match => match[1]);
  assert.deepEqual(lists, ['blocks', 'transactions']);
  for (const prefix of lists) for (const part of ['body', 'wrap', 'empty', 'count', 'more']) bound.push(`${prefix}-${part}`);
  assert.equal(new Set(bound).size, 23);
  for (const id of new Set(bound)) assert.equal(count(page, ` id="${id}"`), 1, id);
  assert.equal(count(page, 'data-explorer-app'), 1);
  assert.equal(count(page, '<script defer src="/explorer.js"></script>'), 1);
});

test('every field on the page is one the script fills', () => {
  const known = new Set([...script.matchAll(/if \(name === '([a-z_]+)'\)/g)].map(match => match[1]));
  const fields = [...page.matchAll(/data-zolana-field="([^"]*)"/g)].map(match => match[1]);
  assert.deepEqual(fields, ['tip_slot', 'finalized_slot', 'block_height', 'validators_voting', 'updated',
    'window_summary', 'block_time', 'blocks_per_minute', 'window_transactions', 'window_non_vote', 'window_skipped']);
  for (const field of fields) assert.ok(known.has(field), field);
  // A field is filled only inside an element the script treats as a status root.
  assert.equal(count(page, 'data-zolana-status>'), 2);
});

test('figures are labelled for what they are', () => {
  // The block time is derived, not measured per block, and the page says how.
  assert.match(page, /<dt>Block time<\/dt><dd data-zolana-field="block_time">[^<]*<\/dd><dd class="basis">Average slot time × slots per block in this window<\/dd>/);
  assert.match(page, /<dt>Blocks per minute<\/dt><dd data-zolana-field="blocks_per_minute">[^<]*<\/dd><dd class="basis">At that block time<\/dd>/);
  assert.match(page, /it is not measured block by block\. The measured figures are shown only while the network is live\./);
  assert.match(page, /The feed does not mark which transactions are shielded payments\./);
  assert.match(page, /The explorer shows recent blocks only/);
  // Fees are test coins, on the page and in the detail panel the script builds.
  assert.match(page, /<th scope="col">Fee \(test coins\)<\/th>/);
  assert.match(page, /Coins are valueless test coins\./);
  assert.match(script, /' test coins \(' \+ formatInteger\(item\.fee\) \+ ' lamports\)'/);
  // No throughput or finality figure, and no claim about who can be identified, in the
  // explorer section or in anything the script writes. The page shell is not checked.
  const section = page.slice(page.indexOf('data-explorer-app'), page.indexOf('</section></main>'));
  assert.ok(section.length > 5000);
  for (const text of [section, script]) {
    assert.doesNotMatch(text, /\bTPS\b|per second|finality|anonym|\(ZOL\)|' ZOL/i);
  }
});

test('the page runs no inline script and no inline handler', () => {
  for (const tag of page.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
    assert.match(tag[1], /\bsrc="\/[a-z.-]+"/);
    assert.equal(tag[2], '');
  }
  assert.doesNotMatch(page, /\son[a-z]+\s*=/i);
  assert.doesNotMatch(page, /javascript:/i);
});
