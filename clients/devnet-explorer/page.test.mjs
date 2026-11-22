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
  assert.equal(new Set(bound).size, 25);
  for (const id of new Set(bound)) assert.equal(count(page, ` id="${id}"`), 1, id);
  assert.equal(count(page, 'data-explorer-app'), 1);
  assert.equal(count(page, '<script defer src="/explorer.js"></script>'), 1);
});

test('every field on the page is one the script fills', () => {
  const known = new Set([...script.matchAll(/if \(name === '([a-z_]+)'\)/g)].map(match => match[1]));
  const fields = [...page.matchAll(/data-zolana-field="([^"]*)"/g)].map(match => match[1]);
  assert.deepEqual(fields, ['tip_slot', 'finalized_slot', 'block_height', 'validators_voting', 'updated',
    'window_summary', 'block_time', 'blocks_per_minute', 'window_transactions', 'window_non_vote', 'window_skipped',
    'window_payments', 'window_payments_basis']);
  for (const field of fields) assert.ok(known.has(field), field);
  // A field is filled only inside an element the script treats as a status root.
  assert.equal(count(page, 'data-zolana-status>'), 2);
});

test('figures are labelled for what they are', () => {
  // The block time is derived, not measured per block, and the page says how.
  assert.match(page, /<dt>Block time<\/dt><dd data-zolana-field="block_time">[^<]*<\/dd><dd class="basis">Average slot time × slots per block in this window<\/dd>/);
  assert.match(page, /<dt>Blocks per minute<\/dt><dd data-zolana-field="blocks_per_minute">[^<]*<\/dd><dd class="basis">At that block time<\/dd>/);
  assert.match(page, /it is not measured block by block\. The measured figures are shown only while the network is live\./);
  // Shielded payments: the figure says what it counts, the footnote what the feed shows of a
  // payment, and the script keeps the sentence for a feed that does not mark payments.
  assert.match(page, /<div class="payment-figure"><dt>Shielded payments<\/dt><dd data-zolana-field="window_payments">[^<]*<\/dd><dd class="basis" data-zolana-field="window_payments_basis">Executed in this window’s blocks<\/dd><\/div>\s*<\/dl>/);
  assert.match(page, /A shielded payment is counted when a transaction that succeeded carries the payment program’s finalize or inline instruction, the two that execute a payment/);
  assert.match(page, /The feed names the instructions and nothing else about a payment: not whether it is a deposit, a private send or a withdrawal, and no amount\. <span id="payments-note"><\/span><\/p>/);
  assert.doesNotMatch(page, /The feed does not mark which transactions are shielded payments/);
  assert.match(script, /paymentsUnmarked: 'The feed does not mark which transactions are shielded payments\.'/);
  assert.match(script, /'Not marked in this feed'/);
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

test('the payment filter is on the page twice, hidden until the feed marks payments', () => {
  // One choice for the chart and the list: every button the script finds sets the same state.
  const groups = [...page.matchAll(/<div class="payment-filter" role="group" aria-label="[^"]+" data-payment-filters hidden>(.*?)<\/div>/g)];
  assert.equal(groups.length, 2);
  for (const group of groups) {
    const buttons = [...group[1].matchAll(/<button type="button" class="filter-button" data-payment-filter="([a-z]+)" aria-pressed="(true|false)">([^<]+)<\/button>/g)];
    assert.deepEqual(buttons.map(button => [button[1], button[2]]), [['all', 'true'], ['payments', 'false']]);
    assert.match(buttons[1][3], /^Payment program/);
  }
  assert.equal(count(page, 'data-payment-filter="'), 4);
  assert.match(script, /querySelectorAll\('\[data-payment-filters\]'\)/);
  assert.match(script, /querySelectorAll\('\[data-payment-filter\]'\)/);
  // The filter names only values the script knows.
  assert.match(script, /state\.paymentFilter = name === 'payments' && feedMarksPayments\(state\.feed\) \? 'payments' : 'all';/);
});

test('a validators list is filled only from attributes this script reads', () => {
  // The repository holds no page with a validators list; the script binds one by these names.
  for (const name of ['data-zolana-validators', 'data-validators-body', 'data-validators-wrap', 'data-validators-empty',
    'data-zolana-notice']) {
    assert.match(script, new RegExp(`\\[${name}\\]`), name);
    assert.equal(count(page, name), 0, name);
  }
  assert.match(script, /if \(name === 'validators_summary'\) return validatorsSummary\(feed, live\);/);
});

test('the page runs no inline script and no inline handler', () => {
  for (const tag of page.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
    assert.match(tag[1], /\bsrc="\/[a-z.-]+"/);
    assert.equal(tag[2], '');
  }
  assert.doesNotMatch(page, /\son[a-z]+\s*=/i);
  assert.doesNotMatch(page, /javascript:/i);
});
