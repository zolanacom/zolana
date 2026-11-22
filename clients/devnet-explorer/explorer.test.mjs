// Runs with `node --test clients/devnet-explorer/*.test.mjs`. Offline, Node built-ins only.
// Tests the validation, formatting, state, search, recent-window, payment-mark, validator
// and link functions of explorer.js against the sample feeds beside it, and a few rules
// about its source. feed.sample.json and feed.paused.json are feeds that do not mark
// payment-program transactions; feed.payments.json is the same window with the marks.
// explorer.js is a plain browser script that also exports these functions when a CommonJS
// module object is present, which is how it is loaded here: no document is needed.
import assert from 'node:assert';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(new URL('./explorer.js', import.meta.url));
const explorer = createRequire(import.meta.url)(scriptPath);
const source = fs.readFileSync(scriptPath, 'utf8');
const liveText = fs.readFileSync(new URL('./feed.sample.json', import.meta.url), 'utf8');
const pausedText = fs.readFileSync(new URL('./feed.paused.json', import.meta.url), 'utf8');
const markedText = fs.readFileSync(new URL('./feed.payments.json', import.meta.url), 'utf8');

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function load(text) {
  const result = explorer.parseFeedText(text);
  assert.strictEqual(result.ok, true, result.error);
  return result;
}

const live = load(liveText).feed;
const paused = load(pausedText).feed;
const rawLive = JSON.parse(liveText);
const rawMarked = JSON.parse(markedText);
const marked = load(markedText).feed;

/* What the page holds for a row of a feed that does not mark payments: the row itself,
   with "not known" in the place of each mark. */
function blockWithoutMarks(block) {
  return Object.assign({}, block, { payment_tx_count: null, executed_payment_count: null });
}
function transactionWithoutMarks(transaction) {
  return Object.assign({}, transaction, { payment_instructions: null });
}
function validatorWithoutRoot(validator) {
  return { identity: validator.identity, vote_account: validator.vote_account, last_vote: validator.last_vote,
    root_slot: null, active: validator.active };
}
const SCOPE = 'Only the recent window is searchable for now.';
const LINK_SCOPE = 'A link opens a block or transaction only while it is in the recent window.';

/* ---------- loading without a browser ---------- */

test('module exports the helpers and does not need a document', function () {
  assert.strictEqual(typeof document, 'undefined');
  ['validateFeed', 'parseFeedText', 'isLive', 'describeState', 'searchFeed', 'formatZol', 'formatAge',
    'formatUtc', 'shortHash', 'formatInteger', 'formatSlotTime', 'clockOffsetMs', 'nextLimit', 'countLabel']
    .forEach(function (name) { assert.strictEqual(typeof explorer[name], 'function', name); });
  assert.strictEqual(explorer.FEED_URL, '/explorer/feed.json');
  assert.strictEqual(explorer.FEED_FORMAT, 'zolana-explorer-feed-v0');
  assert.strictEqual(explorer.POLL_MS, 5000);
  assert.strictEqual(explorer.LIVE_WINDOW_SECONDS, 30);
  assert.strictEqual(explorer.PAGE_ROWS, 50);
});

/* ---------- validation ---------- */

test('both fixtures validate with nothing skipped', function () {
  assert.strictEqual(load(liveText).skipped, 0);
  assert.strictEqual(load(pausedText).skipped, 0);
  assert.strictEqual(live.blocks.length, 120);
  assert.strictEqual(live.transactions.length, 37);
  assert.strictEqual(paused.blocks.length, 120);
  assert.strictEqual(paused.transactions.length, 20);
});

test('validated fixtures keep every contract value', function () {
  assert.deepStrictEqual(live.blocks, rawLive.blocks.map(blockWithoutMarks));
  assert.deepStrictEqual(live.transactions, rawLive.transactions.map(transactionWithoutMarks));
  assert.deepStrictEqual(live.network, Object.assign({}, rawLive.network,
    { validators: rawLive.network.validators.map(validatorWithoutRoot) }));
  assert.deepStrictEqual(live.stats, Object.assign({}, rawLive.stats,
    { payments_since: null, payment_transactions_seen: null, executed_payments_seen: null }));
  assert.strictEqual(live.generated_at, rawLive.generated_at);
  assert.strictEqual(live.genesis_hash, rawLive.genesis_hash);
  const rawPaused = JSON.parse(pausedText);
  assert.deepStrictEqual(paused.network, Object.assign({}, rawPaused.network,
    { validators: rawPaused.network.validators.map(validatorWithoutRoot) }));
  /* A feed that marks payments is kept as it is: every mark is a contract value too. */
  assert.deepStrictEqual(marked.blocks, rawMarked.blocks);
  assert.deepStrictEqual(marked.transactions, rawMarked.transactions);
  assert.deepStrictEqual(marked.network, rawMarked.network);
  assert.deepStrictEqual(marked.stats, rawMarked.stats);
  assert.strictEqual(load(markedText).skipped, 0);
});

test('lists are newest first', function () {
  [live, paused].forEach(function (feed) {
    for (let i = 1; i < feed.blocks.length; i += 1) {
      assert.ok(feed.blocks[i - 1].slot > feed.blocks[i].slot);
    }
    for (let i = 1; i < feed.transactions.length; i += 1) {
      assert.ok(feed.transactions[i - 1].slot >= feed.transactions[i].slot);
    }
  });
});

test('paused fixture carries null network values and both transaction kinds', function () {
  assert.strictEqual(paused.network.status, 'unavailable');
  assert.strictEqual(paused.network.tip_slot, null);
  assert.strictEqual(paused.network.finalized_slot, null);
  assert.strictEqual(paused.network.block_height, null);
  assert.strictEqual(paused.network.slot_time_ms, null);
  assert.strictEqual(paused.network.validators[2].vote_account, null);
  assert.strictEqual(paused.network.validators[2].last_vote, null);
  const kinds = paused.transactions.map(function (row) { return row.kind; });
  assert.strictEqual(kinds.filter(function (kind) { return kind === 'vote'; }).length, 14);
  assert.strictEqual(kinds.filter(function (kind) { return kind === 'program'; }).length, 6);
});

test('rejects values that are not a feed', function () {
  [null, undefined, 7, 'feed', [], {}, { format: 'zolana-explorer-feed-v1' }].forEach(function (value) {
    const result = explorer.validateFeed(value);
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.feed, null);
    assert.strictEqual(typeof result.error, 'string');
  });
  const cases = [
    function (feed) { feed.generated_at = '1795100647'; },
    function (feed) { feed.generated_at = 1795100647.5; },
    function (feed) { feed.generated_at = -1; },
    function (feed) { delete feed.generated_at; },
    function (feed) { feed.network = null; },
    function (feed) { feed.network = []; },
    function (feed) { feed.blocks = {}; },
    function (feed) { delete feed.transactions; }
  ];
  cases.forEach(function (change, index) {
    const feed = clone(rawLive);
    change(feed);
    assert.strictEqual(explorer.validateFeed(feed).ok, false, 'case ' + index);
  });
});

test('parseFeedText tolerates error pages, bad JSON and oversized bodies', function () {
  ['', '<!doctype html><title>Page not found</title>', '{"format":', 'null', '[]', '"text"'].forEach(function (text) {
    const result = explorer.parseFeedText(text);
    assert.strictEqual(result.ok, false, text);
    assert.strictEqual(result.feed, null);
  });
  assert.strictEqual(explorer.parseFeedText(undefined).ok, false);
  const padded = liveText.slice(0, -1) + ',"pad":"' + 'x'.repeat(explorer.MAX_FEED_CHARS) + '"}';
  assert.strictEqual(JSON.parse(padded).format, explorer.FEED_FORMAT);
  assert.strictEqual(explorer.parseFeedText(padded).ok, false);
});

test('skips malformed rows and keeps the valid ones', function () {
  const feed = clone(rawLive);
  const good = feed.blocks.length;
  feed.blocks[0].blockhash = '<img src=x onerror=alert(1)>';
  feed.blocks[1].slot = -4;
  feed.blocks[2].slot = 254868.5;
  feed.blocks[3].tx_count = '4';
  feed.blocks[4].block_time = 'now';
  feed.blocks[5] = null;
  feed.blocks[6].blockhash = '';
  feed.blocks[7].blockhash = 'A'.repeat(129);
  feed.blocks[8].parent_slot = {};
  feed.blocks[9].blockhash = feed.blocks[9].blockhash.slice(0, 10) + '0' + feed.blocks[9].blockhash.slice(11);
  feed.transactions[0].signature = 'javascript:alert(1)';
  feed.transactions[1].ok = 'true';
  feed.transactions[2].fee = 5000.5;
  feed.transactions[3].kind = 'transfer';
  feed.transactions[4].fee = Number.MAX_SAFE_INTEGER + 2;
  feed.transactions[5] = ['row'];
  const result = explorer.validateFeed(feed);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.feed.blocks.length, good - 10);
  assert.strictEqual(result.feed.transactions.length, rawLive.transactions.length - 6);
  assert.strictEqual(result.skipped, 16);
  result.feed.blocks.forEach(function (block) { assert.ok(/^[1-9A-HJ-NP-Za-km-z]+$/.test(block.blockhash)); });
  result.feed.transactions.forEach(function (row) { assert.ok(/^[1-9A-HJ-NP-Za-km-z]+$/.test(row.signature)); });
});

test('normalises loose network values instead of trusting them', function () {
  const feed = clone(rawLive);
  feed.network.status = 'LIVE';
  feed.network.tip_slot = '254871';
  feed.network.slot_time_ms = -1;
  feed.network.last_block_at = 1e15;
  feed.network.validators = [{ identity: 'not base58 !', vote_account: null, last_vote: null, active: true },
    { identity: rawLive.network.validators[0].identity, vote_account: null, last_vote: null, active: 'yes' },
    rawLive.network.validators[1]];
  feed.genesis_hash = 42;
  feed.stats = { since: 'yesterday' };
  const result = explorer.validateFeed(feed);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.feed.network.status, 'unavailable');
  assert.strictEqual(result.feed.network.tip_slot, null);
  assert.strictEqual(result.feed.network.slot_time_ms, null);
  assert.strictEqual(result.feed.network.last_block_at, null);
  assert.strictEqual(result.feed.network.validators.length, 1);
  assert.strictEqual(result.feed.genesis_hash, null);
  assert.strictEqual(result.feed.stats, null);
  delete feed.network.validators;
  assert.deepStrictEqual(explorer.validateFeed(feed).feed.network.validators, []);
});

test('orders, de-duplicates and caps the lists', function () {
  const feed = clone(rawLive);
  feed.blocks.reverse();
  feed.blocks.push(clone(feed.blocks[0]));
  feed.transactions.reverse();
  feed.transactions.push(clone(feed.transactions[3]));
  let result = explorer.validateFeed(feed);
  assert.deepStrictEqual(result.feed.blocks, rawLive.blocks.map(blockWithoutMarks));
  assert.strictEqual(result.feed.transactions.length, rawLive.transactions.length);
  assert.strictEqual(result.feed.transactions[0].slot, rawLive.transactions[0].slot);
  assert.strictEqual(result.skipped, 2);

  const many = clone(rawLive);
  const blockTemplate = many.blocks[0];
  const transactionTemplate = many.transactions[0];
  many.blocks = [];
  many.transactions = [];
  for (let i = 0; i < 300; i += 1) {
    many.blocks.push(Object.assign({}, blockTemplate, { slot: 1000 + i }));
    many.transactions.push(Object.assign({}, transactionTemplate, {
      slot: 1000 + i,
      signature: transactionTemplate.signature.slice(0, 60) + String(1000 + i).replace(/0/g, 'z')
    }));
  }
  result = explorer.validateFeed(many);
  assert.strictEqual(result.feed.blocks.length, 120);
  assert.strictEqual(result.feed.transactions.length, 200);
  assert.strictEqual(result.feed.blocks[0].slot, 1299);
  assert.strictEqual(result.feed.transactions[0].slot, 1299);
});

test('a hostile key name does not leak into the validated feed', function () {
  const text = liveText.slice(0, -1) + ',"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}';
  const result = explorer.parseFeedText(text);
  assert.strictEqual(result.ok, true);
  assert.strictEqual({}.polluted, undefined);
  assert.strictEqual(result.feed.polluted, undefined);
  assert.deepStrictEqual(Object.keys(result.feed).sort(),
    ['blocks', 'format', 'generated_at', 'genesis_hash', 'network', 'stats', 'transactions']);
});

/* ---------- live and paused ---------- */

test('live rule: status is live and the feed is at most 30 seconds old', function () {
  const at = live.generated_at;
  assert.strictEqual(explorer.isLive(live, at), true);
  assert.strictEqual(explorer.isLive(live, at + 30), true);
  assert.strictEqual(explorer.isLive(live, at + 31), false);
  assert.strictEqual(explorer.isLive(live, at - 3), true);
  assert.strictEqual(explorer.isLive(paused, paused.generated_at), false);
  assert.strictEqual(explorer.isLive(null, at), false);
  const unavailable = clone(live);
  unavailable.network.status = 'unavailable';
  assert.strictEqual(explorer.isLive(unavailable, at), false);
});

test('describeState covers loading, no data, live and paused', function () {
  const pausedMessage = 'The network is paused. Showing the last recorded blocks.';
  const failedMessage = 'Explorer data could not be refreshed. Showing the last recorded blocks.';
  assert.deepStrictEqual(explorer.describeState(null, null, 0),
    { state: 'loading', label: 'Loading', message: '', updatedAt: null, notice: '' });
  assert.deepStrictEqual(explorer.describeState(null, false, 0), {
    state: 'nodata',
    label: 'No data',
    message: 'Explorer data is not available yet.',
    updatedAt: null,
    notice: 'Explorer data is not available yet.'
  });
  assert.deepStrictEqual(explorer.describeState(live, true, live.generated_at + 4),
    { state: 'live', label: 'Live', message: '', updatedAt: null, notice: '' });
  assert.deepStrictEqual(explorer.describeState(live, false, live.generated_at + 12),
    { state: 'live', label: 'Live', message: '', updatedAt: null, notice: '' });
  assert.deepStrictEqual(explorer.describeState(live, true, live.generated_at + 31), {
    state: 'paused',
    label: 'Paused',
    message: pausedMessage,
    updatedAt: 1795100647,
    notice: pausedMessage + ' Last updated 2026-11-19 15:04:07 UTC.'
  });
  assert.deepStrictEqual(explorer.describeState(paused, true, paused.generated_at + 2), {
    state: 'paused',
    label: 'Paused',
    message: pausedMessage,
    updatedAt: 1795109412,
    notice: pausedMessage + ' Last updated 2026-11-19 17:30:12 UTC.'
  });
  assert.deepStrictEqual(explorer.describeState(live, false, live.generated_at + 600), {
    state: 'paused',
    label: 'Paused',
    message: failedMessage,
    updatedAt: 1795100647,
    notice: failedMessage + ' Last updated 2026-11-19 15:04:07 UTC.'
  });
});

test('counts active validators', function () {
  assert.strictEqual(explorer.countActiveValidators(live), 3);
  assert.strictEqual(explorer.countActiveValidators(paused), 0);
  assert.strictEqual(explorer.countActiveValidators(null), 0);
});

test('clock offset follows the response Date header only for a clearly wrong clock', function () {
  const server = Date.parse('Thu, 19 Nov 2026 15:04:10 GMT');
  assert.strictEqual(explorer.clockOffsetMs('Thu, 19 Nov 2026 15:04:10 GMT', server + 900), 0);
  assert.strictEqual(explorer.clockOffsetMs('Thu, 19 Nov 2026 15:04:10 GMT', server - 5000), 0);
  assert.strictEqual(explorer.clockOffsetMs('Thu, 19 Nov 2026 15:04:10 GMT', server + 90000), -90000);
  assert.strictEqual(explorer.clockOffsetMs('Thu, 19 Nov 2026 15:04:10 GMT', server - 3600000), 3600000);
  assert.strictEqual(explorer.clockOffsetMs(null, server), 0);
  assert.strictEqual(explorer.clockOffsetMs('', server), 0);
  assert.strictEqual(explorer.clockOffsetMs('not a date', server), 0);
  assert.strictEqual(explorer.clockOffsetMs('Thu, 19 Nov 2026 15:04:10 GMT', NaN), 0);
});

/* ---------- formatting ---------- */

test('formatZol trims nine decimals', function () {
  assert.strictEqual(explorer.formatZol(0), '0');
  assert.strictEqual(explorer.formatZol(1), '0.000000001');
  assert.strictEqual(explorer.formatZol(5000), '0.000005');
  assert.strictEqual(explorer.formatZol(10000), '0.00001');
  assert.strictEqual(explorer.formatZol(999999999), '0.999999999');
  assert.strictEqual(explorer.formatZol(1000000000), '1');
  assert.strictEqual(explorer.formatZol(1500000000), '1.5');
  assert.strictEqual(explorer.formatZol(123456789012), '123.456789012');
  assert.strictEqual(explorer.formatZol(1234567000000000), '1,234,567');
  assert.strictEqual(explorer.formatZol(9007199254740991), '9,007,199.254740991');
  assert.strictEqual(explorer.formatZol(-1), '');
  assert.strictEqual(explorer.formatZol(1.5), '');
  assert.strictEqual(explorer.formatZol('5000'), '');
  live.transactions.forEach(function (row) {
    assert.ok(/^0\.0000(05|1)$/.test(explorer.formatZol(row.fee)), String(row.fee));
  });
});

test('formatAge', function () {
  assert.strictEqual(explorer.formatAge(0), '0 s');
  assert.strictEqual(explorer.formatAge(4), '4 s');
  assert.strictEqual(explorer.formatAge(59), '59 s');
  assert.strictEqual(explorer.formatAge(60), '1 min 0 s');
  assert.strictEqual(explorer.formatAge(125), '2 min 5 s');
  assert.strictEqual(explorer.formatAge(3599), '59 min 59 s');
  assert.strictEqual(explorer.formatAge(3600), '1 h 0 min');
  assert.strictEqual(explorer.formatAge(86399), '23 h 59 min');
  assert.strictEqual(explorer.formatAge(86400), '1 d 0 h');
  assert.strictEqual(explorer.formatAge(200000), '2 d 7 h');
  assert.strictEqual(explorer.formatAge(-12), '0 s');
  assert.strictEqual(explorer.formatAge(NaN), '0 s');
  assert.strictEqual(explorer.formatAge(4.9), '4 s');
});

test('formatUtc, isoUtc, formatInteger, formatSlotTime and shortHash', function () {
  assert.strictEqual(explorer.formatUtc(1795100647), '2026-11-19 15:04:07 UTC');
  assert.strictEqual(explorer.formatUtc(0), '1970-01-01 00:00:00 UTC');
  assert.strictEqual(explorer.formatUtc(null), 'Unknown time');
  assert.strictEqual(explorer.formatUtc(1e15), 'Unknown time');
  assert.strictEqual(explorer.isoUtc(1795100647), '2026-11-19T15:04:07Z');
  assert.strictEqual(explorer.isoUtc('x'), '');
  assert.strictEqual(explorer.formatInteger(0), '0');
  assert.strictEqual(explorer.formatInteger(999), '999');
  assert.strictEqual(explorer.formatInteger(1000), '1,000');
  assert.strictEqual(explorer.formatInteger(254871), '254,871');
  assert.strictEqual(explorer.formatInteger(1234567890), '1,234,567,890');
  assert.strictEqual(explorer.formatSlotTime(402.6), '403 ms');
  assert.strictEqual(explorer.formatSlotTime(999.4), '999 ms');
  assert.strictEqual(explorer.formatSlotTime(1250), '1.25 s');
  assert.strictEqual(explorer.formatSlotTime(0), '');
  assert.strictEqual(explorer.formatSlotTime(null), '');
  const hash = live.blocks[0].blockhash;
  assert.strictEqual(explorer.shortHash(hash), hash.slice(0, 8) + '…' + hash.slice(-6));
  assert.strictEqual(explorer.shortHash('abcdefghijklmno'), 'abcdefghijklmno');
  assert.strictEqual(explorer.shortHash('abcdefghijklmnop'), 'abcdefgh…klmnop');
  assert.strictEqual(explorer.shortHash('abcdefghijklmnop', 4, 4), 'abcd…mnop');
  assert.strictEqual(explorer.kindLabel('vote'), 'Vote');
  assert.strictEqual(explorer.kindLabel('program'), 'Program');
});

test('row limits and count labels', function () {
  assert.strictEqual(explorer.nextLimit(50, 120), 100);
  assert.strictEqual(explorer.nextLimit(100, 120), 120);
  assert.strictEqual(explorer.nextLimit(50, 37), 37);
  assert.strictEqual(explorer.nextLimit(150, 200), 200);
  assert.strictEqual(explorer.nextLimit(50, 0), 0);
  assert.strictEqual(explorer.countLabel(50, 120, 'block', 'blocks'), 'Showing 50 of 120 blocks in the recent window.');
  assert.strictEqual(explorer.countLabel(37, 37, 'transaction', 'transactions'),
    'Showing all 37 transactions in the recent window.');
  assert.strictEqual(explorer.countLabel(1, 1, 'block', 'blocks'), 'Showing all 1 block in the recent window.');
  assert.strictEqual(explorer.countLabel(0, 0, 'block', 'blocks'), '');
});

/* ---------- search ---------- */

function only(result, type) {
  assert.strictEqual(result.status, 'found', result.message);
  assert.strictEqual(result.matches.length, 1);
  assert.strictEqual(result.matches[0].type, type);
  return result.matches[0].item;
}

test('search finds a block by slot number', function () {
  const block = live.blocks[7];
  assert.strictEqual(only(explorer.searchFeed(live, String(block.slot)), 'block'), block);
  assert.strictEqual(only(explorer.searchFeed(live, '  ' + explorer.formatInteger(block.slot) + ' '), 'block'), block);
  assert.strictEqual(only(explorer.searchFeed(paused, String(paused.blocks[119].slot)), 'block'), paused.blocks[119]);
});

test('search by slot falls back to transactions when the block is outside the window', function () {
  const old = live.transactions[live.transactions.length - 1];
  assert.ok(old.slot < live.blocks[live.blocks.length - 1].slot);
  assert.strictEqual(only(explorer.searchFeed(live, String(old.slot)), 'transaction'), old);
});

test('search finds a block by blockhash prefix and by full blockhash', function () {
  [live, paused].forEach(function (feed) {
    const block = feed.blocks[33];
    assert.strictEqual(only(explorer.searchFeed(feed, block.blockhash), 'block'), block);
    assert.strictEqual(only(explorer.searchFeed(feed, block.blockhash.slice(0, 8)), 'block'), block);
  });
});

test('search finds a transaction by signature prefix and by full signature', function () {
  [live, paused].forEach(function (feed) {
    const row = feed.transactions[5];
    assert.strictEqual(only(explorer.searchFeed(feed, row.signature), 'transaction'), row);
    assert.strictEqual(only(explorer.searchFeed(feed, row.signature.slice(0, 9)), 'transaction'), row);
  });
});

test('every held block and transaction is found by its own identifier', function () {
  [live, paused].forEach(function (feed) {
    feed.blocks.forEach(function (block) {
      assert.strictEqual(explorer.searchFeed(feed, block.blockhash).matches[0].item, block);
      assert.strictEqual(explorer.searchFeed(feed, String(block.slot)).matches[0].item, block);
    });
    feed.transactions.forEach(function (row) {
      assert.strictEqual(explorer.searchFeed(feed, row.signature).matches[0].item, row);
    });
  });
});

test('search is case-sensitive', function () {
  const block = live.blocks.find(function (candidate) { return /[A-Za-z]/.test(candidate.blockhash.slice(0, 8)); });
  const prefix = block.blockhash.slice(0, 8);
  const flipped = prefix.split('').map(function (char) {
    const other = char === char.toLowerCase() ? char.toUpperCase() : char.toLowerCase();
    return /^[1-9A-HJ-NP-Za-km-z]$/.test(other) ? other : char;
  }).join('');
  assert.notStrictEqual(flipped, prefix);
  assert.strictEqual(explorer.searchFeed(live, prefix).status, 'found');
  assert.strictEqual(explorer.searchFeed(live, flipped).status, 'not_found');
});

test('search needs at least 4 base58 characters for a hash', function () {
  const hash = live.blocks.find(function (candidate) { return /[A-Za-z]/.test(candidate.blockhash.slice(0, 3)); }).blockhash;
  const short = explorer.searchFeed(live, hash.slice(0, 3));
  assert.strictEqual(short.status, 'invalid');
  assert.deepStrictEqual(short.matches, []);
  assert.ok(short.message.indexOf('at least 4 characters') !== -1);
  assert.ok(short.message.indexOf('Only the recent window is searchable for now.') !== -1);
  assert.strictEqual(explorer.searchFeed(live, hash.slice(0, 4)).status, 'found');
  ['abc0def', 'OOOO', 'IIII', 'llll', 'slot 12', '<script>', hash + '!', 'x'.repeat(129)].forEach(function (query) {
    assert.strictEqual(explorer.searchFeed(live, query).status, 'invalid', query);
  });
});

test('search says plainly when nothing in the recent window matches', function () {
  const expected = {
    '999999999': ['ahead', 'Slot 999,999,999 is ahead of the newest block in the recent window (slot 254,870). ' + SCOPE],
    '9007199254740991': ['ahead',
      'Slot 9,007,199,254,740,991 is ahead of the newest block in the recent window (slot 254,870). ' + SCOPE],
    '4': ['older', 'Slot 4 is older than the recent window, which starts at slot 254,748. ' + SCOPE],
    'zzzzzzzz': ['no_match',
      'No block or transaction in the recent window starts with \u201czzzzzzzz\u201d. It may be older than the window. ' + SCOPE]
  };
  Object.keys(expected).forEach(function (query) {
    const result = explorer.searchFeed(live, query);
    assert.strictEqual(result.status, 'not_found', query);
    assert.strictEqual(result.reason, expected[query][0], query);
    assert.strictEqual(result.message, expected[query][1]);
    assert.deepStrictEqual(result.matches, []);
  });
  const long = explorer.searchFeed(live, live.blocks[0].blockhash + 'z');
  assert.strictEqual(long.status, 'not_found');
  assert.strictEqual(long.message, 'No block or transaction in the recent window starts with \u201c' +
    live.blocks[0].blockhash.slice(0, 12) + '\u2026' + (live.blocks[0].blockhash + 'z').slice(-6) +
    '\u201d. It may be older than the window. ' + SCOPE);
  assert.strictEqual(explorer.searchFeed(live, paused.blocks[0].blockhash).status, 'not_found');
});

test('search handles an empty query, missing data and several matches', function () {
  assert.deepStrictEqual(explorer.searchFeed(live, '   '), { status: 'empty', matches: [], message: '' });
  assert.deepStrictEqual(explorer.searchFeed(live, undefined), { status: 'empty', matches: [], message: '' });
  assert.deepStrictEqual(explorer.searchFeed(null, '254870'),
    { status: 'nodata', matches: [], message: 'There is nothing to search until explorer data is available.' });

  const feed = clone(live);
  feed.blocks[10].blockhash = 'Zo1aNa' + feed.blocks[10].blockhash.slice(6);
  feed.blocks[40].blockhash = 'Zo1aNa' + feed.blocks[40].blockhash.slice(6);
  feed.transactions[2].signature = 'Zo1aNa' + feed.transactions[2].signature.slice(6);
  const result = explorer.searchFeed(feed, 'Zo1aNa');
  assert.strictEqual(result.status, 'found');
  assert.strictEqual(result.matches.length, 3);
  assert.strictEqual(result.message, 'Showing the newest of 3 matches. Enter more characters to narrow the search.');
  for (let i = 1; i < result.matches.length; i += 1) {
    assert.ok(result.matches[i - 1].item.slot >= result.matches[i].item.slot);
  }

  const sameSlot = live.transactions.filter(function (row) { return row.slot === live.transactions[0].slot; });
  assert.ok(sameSlot.length >= 2);
  const withoutBlock = clone(live);
  withoutBlock.blocks = withoutBlock.blocks.filter(function (block) { return block.slot !== sameSlot[0].slot; });
  assert.strictEqual(explorer.searchFeed(withoutBlock, String(sameSlot[0].slot)).matches.length, sameSlot.length);
});

test('a digit-only query that is not a held slot still matches a hash prefix', function () {
  const feed = clone(live);
  feed.blocks[20].blockhash = '7777' + feed.blocks[20].blockhash.slice(4);
  assert.strictEqual(only(explorer.searchFeed(feed, '7777'), 'block').slot, feed.blocks[20].slot);
});

/* ---------- recent window ---------- */

/* A feed with the given slots (newest first) where every block names the block before
   it in the list as its parent, unless `parents` says otherwise. */
function chain(slots, options) {
  const settings = options || {};
  const feed = clone(rawLive);
  feed.blocks = slots.map(function (slot, index) {
    const parent = settings.parents && settings.parents[slot] !== undefined ? settings.parents[slot] :
      (index + 1 < slots.length ? slots[index + 1] : slot - 1);
    const counts = settings.counts && settings.counts[slot] ? settings.counts[slot] : [0, 0];
    return { slot: slot, parent_slot: parent, blockhash: rawLive.blocks[index].blockhash, block_time: 1795000000 + index,
      block_height: 9000 - index, tx_count: counts[0], non_vote_tx_count: counts[1] };
  });
  feed.transactions = [];
  feed.network.slot_time_ms = settings.slotTime === undefined ? 200 : settings.slotTime;
  const result = explorer.validateFeed(feed);
  assert.strictEqual(result.ok, true, result.error);
  assert.strictEqual(result.skipped, 0);
  return result.feed;
}

/* A window as an idle network gives it: 120 blocks in consecutive slots, none holding a
   transaction, and one listed transaction older than every block held. Synthetic. */
function quietFeed() {
  const feed = clone(rawLive);
  const newest = 600119;
  feed.blocks = rawLive.blocks.map(function (block, index) {
    return { slot: newest - index, parent_slot: newest - index - 1, blockhash: block.blockhash,
      block_time: 1795000000 - index, block_height: 590119 - index, tx_count: 0, non_vote_tx_count: 0 };
  });
  feed.transactions = [Object.assign({}, rawLive.transactions[0], { slot: 590000, block_time: 1794990000 })];
  feed.network.slot_time_ms = 193.3;
  const result = explorer.validateFeed(feed);
  assert.strictEqual(result.ok, true, result.error);
  assert.strictEqual(result.skipped, 0);
  return result.feed;
}

test('new helpers are exported', function () {
  ['windowStats', 'slotStrip', 'stripSummary', 'describeSlotMiss', 'parseDeepLink', 'formatDeepLink',
    'resolveDeepLink', 'inWindow', 'tweenValue', 'validatorsVoting', 'paymentStep', 'isPaymentTransaction',
    'transactionLabel', 'describePayment', 'feedMarksPayments', 'filterTransactions', 'paymentsBasis', 'paymentsNote',
    'validatorRows', 'slotsBehind', 'votingLabel', 'validatorsSummary', 'validatorsNotice']
    .forEach(function (name) { assert.strictEqual(typeof explorer[name], 'function', name); });
  assert.strictEqual(explorer.STRIP_SLOTS, 120);
});

test('window statistics of the fixtures', function () {
  const stats = explorer.windowStats(live);
  assert.strictEqual(stats.blocks, 120);
  assert.strictEqual(stats.newest_slot, live.blocks[0].slot);
  assert.strictEqual(stats.oldest_slot, live.blocks[119].slot);
  assert.strictEqual(stats.transactions, live.blocks.reduce(function (sum, block) { return sum + block.tx_count; }, 0));
  assert.strictEqual(stats.non_vote_transactions,
    live.blocks.reduce(function (sum, block) { return sum + block.non_vote_tx_count; }, 0));
  assert.strictEqual(stats.transactions, 369);
  assert.strictEqual(stats.non_vote_transactions, 9);
  assert.strictEqual(stats.skipped_slots, 3);
  assert.strictEqual(stats.unlinked_blocks, 0);
  assert.strictEqual(stats.max_gap, 3);
  assert.strictEqual(stats.max_transactions, 5);
  assert.strictEqual(stats.slots_per_block, 123 / 120);
  assert.strictEqual(stats.block_time_ms, 412.7);
  assert.ok(Math.abs(stats.blocks_per_minute - 60000 / (402.6 * 1.025)) < 1e-9);
  assert.strictEqual(stats.series.length, 120);
  assert.strictEqual(stats.series[0].slot, stats.oldest_slot);
  assert.strictEqual(stats.series[119].slot, stats.newest_slot);
  assert.strictEqual(stats.series[119].block, live.blocks[0]);
  /* The window covers its slots exactly: blocks plus skipped slots. */
  assert.strictEqual(stats.newest_slot - stats.oldest_slot + 1, stats.blocks + stats.skipped_slots);
});

test('window statistics of a paused feed carry counts but no measured time', function () {
  const stats = explorer.windowStats(paused);
  assert.strictEqual(stats.blocks, 120);
  assert.strictEqual(stats.transactions, 363);
  assert.strictEqual(stats.skipped_slots, 1);
  assert.strictEqual(stats.block_time_ms, null);
  assert.strictEqual(stats.blocks_per_minute, null);
});

test('window statistics of a quiet window with one older transaction', function () {
  const quiet = quietFeed();
  const stats = explorer.windowStats(quiet);
  assert.strictEqual(stats.blocks, 120);
  assert.strictEqual(stats.skipped_slots, 0);
  assert.strictEqual(stats.unlinked_blocks, 0);
  assert.strictEqual(stats.slots_per_block, 1);
  assert.strictEqual(stats.transactions, 0);
  assert.strictEqual(stats.max_transactions, 0);
  assert.strictEqual(stats.block_time_ms, quiet.network.slot_time_ms);
  assert.strictEqual(explorer.formatSlotTime(stats.block_time_ms), '193 ms');
  assert.strictEqual(Math.round(stats.blocks_per_minute), 310);
  assert.strictEqual(explorer.validatorsVoting(quiet), '3 of 3');
  /* Its one listed transaction is older than the blocks that are held. */
  assert.strictEqual(quiet.transactions.length, 1);
  assert.ok(quiet.transactions[0].slot < stats.oldest_slot);
  assert.strictEqual(explorer.inWindow(quiet, { type: 'transaction', item: quiet.transactions[0] }), true);
  assert.strictEqual(explorer.describeSlotMiss(quiet, quiet.transactions[0].slot).reason, 'older');
});

test('window statistics of an empty, missing or malformed feed', function () {
  const empty = { blocks: 0, newest_slot: null, oldest_slot: null, transactions: 0, non_vote_transactions: 0,
    slots_per_block: null, skipped_slots: 0, unlinked_blocks: 0, max_gap: 0, max_transactions: 0,
    block_time_ms: null, blocks_per_minute: null, payment_transactions: 0, executed_payments: 0,
    marked_blocks: 0, max_payment_transactions: 0, series: [] };
  assert.deepStrictEqual(explorer.windowStats(null), empty);
  assert.deepStrictEqual(explorer.windowStats(undefined), empty);
  assert.deepStrictEqual(explorer.windowStats({}), empty);
  assert.deepStrictEqual(explorer.windowStats({ blocks: 'none' }), empty);
  assert.deepStrictEqual(explorer.windowStats(chain([])), empty);
  /* Rows the validator rejects never reach the statistics. */
  const broken = clone(rawLive);
  broken.blocks = [{ slot: 'x' }, null, 7, { slot: 5, blockhash: '0OIl', tx_count: 1, non_vote_tx_count: 0 }];
  const result = explorer.validateFeed(broken);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.skipped, 4);
  assert.deepStrictEqual(explorer.windowStats(result.feed), empty);
});

test('window statistics count skipped slots, unknown parents and blocks missing from the feed', function () {
  const steady = explorer.windowStats(chain([105, 104, 103, 102, 101]));
  assert.strictEqual(steady.slots_per_block, 1);
  assert.strictEqual(steady.skipped_slots, 0);
  assert.strictEqual(steady.block_time_ms, 200);
  assert.strictEqual(steady.blocks_per_minute, 300);
  assert.deepStrictEqual(steady.series.map(function (point) { return point.gap; }), [1, 1, 1, 1, 1]);

  const skipped = explorer.windowStats(chain([110, 107, 106, 103, 102], { counts: { 110: [4, 1], 106: [2, 2] } }));
  assert.strictEqual(skipped.skipped_slots, 4);
  assert.strictEqual(skipped.max_gap, 3);
  assert.strictEqual(skipped.slots_per_block, 9 / 5);
  assert.strictEqual(skipped.block_time_ms, 360);
  assert.strictEqual(skipped.transactions, 6);
  assert.strictEqual(skipped.non_vote_transactions, 3);
  assert.strictEqual(skipped.max_transactions, 4);
  assert.strictEqual(skipped.unlinked_blocks, 0);

  /* Block 107 names 106 as its parent, but the feed holds 105 next: one block is missing. */
  const missing = explorer.windowStats(chain([108, 107, 105, 104], { parents: { 107: 106 } }));
  assert.strictEqual(missing.unlinked_blocks, 1);
  assert.strictEqual(missing.skipped_slots, 0);

  const unknown = explorer.windowStats(chain([108, 107, 106], { parents: { 107: null, 106: null } }));
  assert.deepStrictEqual(unknown.series.map(function (point) { return point.gap; }), [null, null, 1]);
  assert.strictEqual(unknown.slots_per_block, 1);
  assert.strictEqual(unknown.unlinked_blocks, 0);

  const noParents = explorer.windowStats(chain([108], { parents: { 108: null } }));
  assert.strictEqual(noParents.slots_per_block, null);
  assert.strictEqual(noParents.block_time_ms, null);
  assert.strictEqual(noParents.blocks, 1);

  /* A parent that is not below its block is ignored instead of producing a negative gap. */
  const backwards = explorer.windowStats(chain([108, 107], { parents: { 108: 300 } }));
  assert.deepStrictEqual(backwards.series.map(function (point) { return point.gap; }), [1, null]);
  assert.strictEqual(backwards.skipped_slots, 0);

  assert.strictEqual(explorer.windowStats(chain([105, 104], { slotTime: null })).block_time_ms, null);
  /* A block cannot hold more non-vote transactions than transactions. */
  assert.strictEqual(explorer.windowStats(chain([105], { counts: { 105: [1, 9] } })).non_vote_transactions, 1);
});

test('slot strip marks blocks, skipped slots and slots the feed does not explain', function () {
  const strip = explorer.slotStrip(chain([110, 107, 106, 103, 102], { parents: { 106: 104 } }), 120);
  assert.deepStrictEqual(strip.ticks.map(function (tick) { return tick.slot; }), [102, 103, 104, 105, 106, 107, 108, 109, 110]);
  assert.deepStrictEqual(strip.ticks.map(function (tick) { return tick.state; }),
    ['block', 'block', 'unknown', 'skipped', 'block', 'block', 'skipped', 'skipped', 'block']);
  assert.deepStrictEqual([strip.first_slot, strip.last_slot, strip.blocks, strip.skipped, strip.unknown], [102, 110, 5, 3, 1]);
  assert.strictEqual(explorer.stripSummary(strip),
    '5 of the last 9 slots have a block; 3 were skipped; 1 is not in the explorer data. Slots 102 to 110.');

  const newest = explorer.slotStrip(chain([110, 107, 106, 103, 102]), 4);
  assert.deepStrictEqual(newest.ticks.map(function (tick) { return tick.slot + ':' + tick.state; }),
    ['107:block', '108:skipped', '109:skipped', '110:block']);

  const fixture = explorer.slotStrip(live, 120);
  assert.strictEqual(fixture.ticks.length, 120);
  assert.strictEqual(fixture.last_slot, live.blocks[0].slot);
  assert.strictEqual(fixture.blocks + fixture.skipped + fixture.unknown, 120);
  assert.strictEqual(fixture.unknown, 0);
  assert.strictEqual(explorer.stripSummary(fixture), '117 of the last 120 slots have a block; 3 were skipped. Slots 254,751 to 254,870.');
  assert.strictEqual(explorer.stripSummary(explorer.slotStrip(quietFeed(), 120)),
    '120 of the last 120 slots have a block. Slots 600,000 to 600,119.');
  assert.strictEqual(explorer.stripSummary(explorer.slotStrip(chain([7]), 120)), '1 of the last 1 slot has a block. Slots 7 to 7.');
});

test('slot strip of an empty feed, and of slots far apart, stays small', function () {
  const empty = { ticks: [], first_slot: null, last_slot: null, blocks: 0, skipped: 0, unknown: 0 };
  assert.deepStrictEqual(explorer.slotStrip(null, 120), empty);
  assert.deepStrictEqual(explorer.slotStrip(chain([]), 120), empty);
  assert.strictEqual(explorer.stripSummary(empty), null);
  assert.strictEqual(explorer.stripSummary(null), null);
  const far = explorer.slotStrip(chain([9007199254740000, 5], { parents: { 9007199254740000: 5, 5: 0 } }), 120);
  assert.strictEqual(far.ticks.length, 120);
  assert.strictEqual(far.blocks, 1);
  assert.strictEqual(far.skipped, 119);
  assert.strictEqual(explorer.slotStrip(live, 0).ticks.length, 120);
  assert.strictEqual(explorer.slotStrip(live, 'many').ticks.length, 120);
  assert.strictEqual(explorer.slotStrip(live, 5000000).ticks.length, live.blocks[0].slot - live.blocks[119].slot + 1);
});

test('a slot without a block is explained from the feed', function () {
  const feed = chain([110, 107, 106, 103, 102], { parents: { 106: 104 } });
  assert.deepStrictEqual(explorer.describeSlotMiss(feed, 111),
    { reason: 'ahead', message: 'Slot 111 is ahead of the newest block in the recent window (slot 110).' });
  assert.deepStrictEqual(explorer.describeSlotMiss(feed, 101),
    { reason: 'older', message: 'Slot 101 is older than the recent window, which starts at slot 102.' });
  assert.deepStrictEqual(explorer.describeSlotMiss(feed, 108),
    { reason: 'skipped', message: 'Slot 108 has no block: the slot was skipped.' });
  assert.strictEqual(explorer.describeSlotMiss(feed, 105).reason, 'skipped');
  assert.deepStrictEqual(explorer.describeSlotMiss(feed, 104),
    { reason: 'not_in_feed', message: 'Slot 104 is inside the recent window, but its block is not in the explorer data.' });
  assert.deepStrictEqual(explorer.describeSlotMiss(chain([]), 104),
    { reason: 'no_blocks', message: 'No blocks have been recorded yet.' });
  assert.strictEqual(explorer.describeSlotMiss(null, 104).reason, 'no_blocks');

  const skippedSlot = live.blocks.find(function (block) { return block.slot - block.parent_slot > 1; }).slot - 1;
  const result = explorer.searchFeed(live, String(skippedSlot));
  assert.strictEqual(result.status, 'not_found');
  assert.strictEqual(result.reason, 'skipped');
  assert.strictEqual(result.message, 'Slot ' + explorer.formatInteger(skippedSlot) + ' has no block: the slot was skipped. ' + SCOPE);
  assert.strictEqual(explorer.searchFeed(chain([]), '104').message, 'No blocks have been recorded yet. ' + SCOPE);
});

/* ---------- links to one block or transaction ---------- */

test('deep links are parsed strictly', function () {
  const signature = live.transactions[0].signature;
  assert.deepStrictEqual(explorer.parseDeepLink('#block=254870'), { type: 'block', slot: 254870 });
  assert.deepStrictEqual(explorer.parseDeepLink('block=0'), { type: 'block', slot: 0 });
  assert.deepStrictEqual(explorer.parseDeepLink('#tx=' + signature), { type: 'transaction', signature: signature });
  ['', '#', '#block', '#block=', '#block=12a', '#block=-1', '#block=1.5', '#block=1e3', '#block= 12', '#block=254,870',
    '#block=99999999999999999', '#block=9007199254740993', '#tx=', '#tx=0OIl', '#tx=abc def', '#tx=' + 'z'.repeat(129),
    '#slot=12', '#Block=12', '#tx=<script>', '#token', '#block=1&tx=' + signature, '#' + 'x'.repeat(4000),
    null, undefined, 12, {}].forEach(function (value) {
    assert.strictEqual(explorer.parseDeepLink(value), null, String(value).slice(0, 40));
  });
});

test('deep links are written and read back', function () {
  const block = { type: 'block', item: live.blocks[7] };
  const transaction = { type: 'transaction', item: live.transactions[3] };
  assert.strictEqual(explorer.formatDeepLink(block), '#block=' + live.blocks[7].slot);
  assert.strictEqual(explorer.formatDeepLink(transaction), '#tx=' + live.transactions[3].signature);
  assert.deepStrictEqual(explorer.parseDeepLink(explorer.formatDeepLink(block)), { type: 'block', slot: live.blocks[7].slot });
  assert.strictEqual(explorer.resolveDeepLink(live, explorer.parseDeepLink(explorer.formatDeepLink(block))).match.item, live.blocks[7]);
  assert.strictEqual(explorer.resolveDeepLink(live, explorer.parseDeepLink(explorer.formatDeepLink(transaction))).match.item,
    live.transactions[3]);
  [null, undefined, {}, { type: 'block' }, { type: 'block', item: { slot: -1 } }, { type: 'transaction', item: { signature: '0' } },
    { type: 'other', item: live.blocks[0] }].forEach(function (value) {
    assert.strictEqual(explorer.formatDeepLink(value), '');
  });
});

test('a deep link opens only an item that is still in the window', function () {
  assert.deepStrictEqual(explorer.resolveDeepLink(live, null), { status: 'none', match: null, message: '' });
  assert.deepStrictEqual(explorer.resolveDeepLink(null, { type: 'block', slot: 5 }), { status: 'nodata', match: null, message: '' });
  assert.deepStrictEqual(explorer.resolveDeepLink(live, { type: 'block', slot: 5 }), { status: 'outside', match: null,
    message: 'Slot 5 is older than the recent window, which starts at slot 254,748. ' + LINK_SCOPE });
  assert.deepStrictEqual(explorer.resolveDeepLink(live, { type: 'block', slot: 999999 }), { status: 'outside', match: null,
    message: 'Slot 999,999 is ahead of the newest block in the recent window (slot 254,870). ' + LINK_SCOPE });
  const other = paused.transactions[0].signature;
  assert.deepStrictEqual(explorer.resolveDeepLink(live, { type: 'transaction', signature: other }), { status: 'outside', match: null,
    message: 'Transaction ' + explorer.shortHash(other) + ' is not in the recent window. ' + LINK_SCOPE });
  /* A prefix is a search, not a link: a link names one whole signature. */
  assert.strictEqual(explorer.resolveDeepLink(live, { type: 'transaction', signature: live.transactions[0].signature.slice(0, 20) }).status,
    'outside');
  assert.strictEqual(explorer.inWindow(live, { type: 'block', item: live.blocks[119] }), true);
  assert.strictEqual(explorer.inWindow(live, { type: 'block', item: paused.blocks[0] }), false);
  assert.strictEqual(explorer.inWindow(paused, { type: 'transaction', item: live.transactions[0] }), false);
  assert.strictEqual(explorer.inWindow(null, { type: 'block', item: live.blocks[0] }), false);
  assert.strictEqual(explorer.inWindow(live, null), false);
});

/* ---------- counters and validators ---------- */

test('a counter moves from one feed value to the next and never passes it', function () {
  assert.strictEqual(explorer.tweenValue(100, 125, 0), 100);
  assert.strictEqual(explorer.tweenValue(100, 125, -3), 100);
  assert.strictEqual(explorer.tweenValue(100, 125, NaN), 100);
  assert.strictEqual(explorer.tweenValue(100, 125, 0.5), 112);
  assert.strictEqual(explorer.tweenValue(100, 125, 0.999), 124);
  assert.strictEqual(explorer.tweenValue(100, 125, 1), 125);
  assert.strictEqual(explorer.tweenValue(100, 125, 7), 125);
  assert.strictEqual(explorer.tweenValue(125, 100, 0.5), 100);
  let last = 100;
  for (let step = 0; step <= 100; step += 1) {
    const value = explorer.tweenValue(100, 125, step / 100);
    assert.ok(Number.isInteger(value) && value >= last && value <= 125);
    last = value;
  }
});

test('validators voting is the active share of the validators in the feed', function () {
  assert.strictEqual(explorer.validatorsVoting(live), '3 of 3');
  const feed = clone(live);
  feed.network.validators[1].active = false;
  assert.strictEqual(explorer.validatorsVoting(feed), '2 of 3');
  feed.network.validators = [];
  assert.strictEqual(explorer.validatorsVoting(feed), null);
  assert.strictEqual(explorer.validatorsVoting(null), null);
});

/* ---------- payment-program transactions ---------- */

test('a feed that does not mark payments is read as before, and the page can say so', function () {
  [live, paused].forEach(function (feed) {
    const stats = explorer.windowStats(feed);
    assert.strictEqual(explorer.feedMarksPayments(feed), false);
    assert.strictEqual(stats.marked_blocks, 0);
    assert.strictEqual(stats.payment_transactions, 0);
    assert.strictEqual(stats.executed_payments, 0);
    assert.strictEqual(explorer.paymentsBasis(stats), 'Not marked in this feed');
    assert.strictEqual(explorer.paymentsNote(stats), 'The feed does not mark which transactions are shielded payments.');
    assert.deepStrictEqual(explorer.filterTransactions(feed, 'payments'), []);
    assert.strictEqual(explorer.filterTransactions(feed, 'all'), feed.transactions);
    feed.transactions.forEach(function (transaction) {
      assert.strictEqual(explorer.paymentStep(transaction), 'not_marked');
      assert.strictEqual(explorer.isPaymentTransaction(transaction), false);
      assert.strictEqual(explorer.transactionLabel(transaction), explorer.kindLabel(transaction.kind));
      assert.strictEqual(explorer.describePayment(transaction), null);
    });
    stats.series.forEach(function (point) {
      assert.strictEqual(point.payment, null);
      assert.strictEqual(point.executed, null);
    });
  });
  assert.strictEqual(explorer.feedMarksPayments(null), false);
  assert.strictEqual(explorer.paymentsBasis(explorer.windowStats(null)), 'Not marked in this feed');
  assert.strictEqual(explorer.paymentsNote(explorer.windowStats(null)), '');
  assert.deepStrictEqual(explorer.filterTransactions(null, 'payments'), []);
});

test('a feed that marks payments is counted over the blocks of the window', function () {
  const stats = explorer.windowStats(marked);
  assert.strictEqual(explorer.feedMarksPayments(marked), true);
  assert.strictEqual(stats.marked_blocks, 120);
  assert.strictEqual(stats.payment_transactions, 8);
  assert.strictEqual(stats.executed_payments, 2);
  assert.strictEqual(stats.max_payment_transactions, 2);
  assert.strictEqual(stats.payment_transactions,
    marked.blocks.reduce(function (sum, block) { return sum + block.payment_tx_count; }, 0));
  assert.strictEqual(explorer.paymentsBasis(stats), 'Executed in this window\u2019s blocks, from 8 payment-program transactions');
  assert.strictEqual(explorer.paymentsNote(stats), '');
  /* The other figures of the window do not change with the marks. */
  const plain = explorer.windowStats(live);
  ['blocks', 'transactions', 'non_vote_transactions', 'skipped_slots', 'max_transactions', 'block_time_ms']
    .forEach(function (name) { assert.strictEqual(stats[name], plain[name], name); });
  const at = function (slot) { return stats.series.filter(function (point) { return point.slot === slot; })[0]; };
  assert.deepStrictEqual([at(254809).payment, at(254809).executed], [2, 1]);
  assert.deepStrictEqual([at(254867).payment, at(254867).executed], [1, 1]);
  assert.deepStrictEqual([at(254853).payment, at(254853).executed], [1, 0]);
  assert.deepStrictEqual([at(254870).payment, at(254870).executed], [0, 0]);
  /* One payment-program transaction is worded in the singular. */
  const one = clone(rawMarked);
  one.blocks.forEach(function (block) {
    block.payment_tx_count = block.slot === 254867 ? 1 : 0;
    block.executed_payment_count = 0;
  });
  assert.strictEqual(explorer.paymentsBasis(explorer.windowStats(explorer.validateFeed(one).feed)),
    'Executed in this window\u2019s blocks, from 1 payment-program transaction');
});

test('a window the feed marks only in part says how much of it is counted', function () {
  const feed = clone(rawMarked);
  feed.blocks.forEach(function (block, index) {
    if (index >= 40) {
      block.payment_tx_count = null;
      block.executed_payment_count = null;
    }
  });
  const result = explorer.validateFeed(feed);
  assert.strictEqual(result.skipped, 0);
  const stats = explorer.windowStats(result.feed);
  assert.strictEqual(stats.marked_blocks, 40);
  assert.strictEqual(stats.payment_transactions, 3);
  assert.strictEqual(stats.executed_payments, 1);
  assert.strictEqual(explorer.paymentsBasis(stats),
    'Executed in the 40 of 120 blocks this feed marks, from 3 payment-program transactions');
  assert.strictEqual(explorer.paymentsNote(stats),
    'The feed marks payment-program transactions in 40 of the 120 blocks in this window.');
  assert.strictEqual(explorer.feedMarksPayments(result.feed), true);
});

test('the mark of a transaction says what it did at the payment program', function () {
  const step = function (instructions, ok) {
    return explorer.paymentStep({ ok: ok !== false, kind: 'program', payment_instructions: instructions });
  };
  assert.strictEqual(step(['finalize']), 'executed');
  assert.strictEqual(step(['finalize', 'close']), 'executed');
  assert.strictEqual(step(['inline']), 'executed');
  assert.strictEqual(step(['finalize', 'close'], false), 'failed');
  assert.strictEqual(step(['inline'], false), 'failed');
  assert.strictEqual(step(['initialize', 'write']), 'staging');
  assert.strictEqual(step(['seal']), 'staging');
  assert.strictEqual(step(['close']), 'staging');
  assert.strictEqual(step(['write', 'unknown']), 'staging');
  assert.strictEqual(step(['unknown']), 'other');
  assert.strictEqual(step(['unknown'], false), 'other');
  assert.strictEqual(step([]), 'none');
  assert.strictEqual(step(null), 'not_marked');
  assert.strictEqual(step(undefined), 'not_marked');
  assert.strictEqual(explorer.paymentStep(null), 'not_marked');
  assert.deepStrictEqual(explorer.PAYMENT_INSTRUCTIONS, ['initialize', 'write', 'seal', 'finalize', 'close', 'inline', 'unknown']);

  const steps = marked.transactions.map(explorer.paymentStep);
  const count = function (name) { return steps.filter(function (value) { return value === name; }).length; };
  assert.deepStrictEqual([count('executed'), count('failed'), count('staging'), count('other'), count('none'), count('not_marked')],
    [4, 1, 8, 1, 23, 0]);
  assert.strictEqual(explorer.filterTransactions(marked, 'payments').length, 14);
  assert.strictEqual(explorer.filterTransactions(marked, 'all').length, 37);
  /* The filtered list keeps the order of the feed: newest first. */
  const filtered = explorer.filterTransactions(marked, 'payments');
  for (let i = 1; i < filtered.length; i += 1) assert.ok(filtered[i - 1].slot >= filtered[i].slot);

  const labels = {};
  marked.transactions.forEach(function (transaction) {
    labels[explorer.paymentStep(transaction)] = explorer.transactionLabel(transaction);
  });
  assert.deepStrictEqual(labels, { executed: 'Shielded payment', failed: 'Shielded payment', staging: 'Payment staging',
    other: 'Payment program', none: 'Program' });
  assert.strictEqual(explorer.transactionLabel({ ok: true, kind: 'vote', payment_instructions: [] }), 'Vote');

  const say = function (instructions, ok) {
    return explorer.describePayment({ ok: ok !== false, kind: 'program', payment_instructions: instructions });
  };
  assert.match(say(['finalize', 'close']), /^This transaction executed a shielded payment\. The feed does not say whether it was a deposit, a private send or a withdrawal, and it carries no amount\.$/);
  assert.match(say(['finalize'], false), /failed\. No payment was executed\.$/);
  assert.match(say(['initialize', 'write']), /^A staging step: .* It executed no payment\.$/);
  assert.match(say(['unknown']), /could not name\. It executed no payment\.$/);
  assert.strictEqual(say([]), null);
  assert.strictEqual(say(null), null);
});

test('malformed payment marks are skipped like any other malformed row', function () {
  const blockCases = [
    function (block) { block.payment_tx_count = '1'; },
    function (block) { block.payment_tx_count = -1; },
    function (block) { block.payment_tx_count = 1.5; },
    function (block) { block.payment_tx_count = true; },
    function (block) { block.payment_tx_count = null; },
    function (block) { block.executed_payment_count = null; },
    function (block) { delete block.executed_payment_count; },
    function (block) { block.executed_payment_count = block.payment_tx_count + 1; },
    function (block) { block.payment_tx_count = block.tx_count + 1; },
    function (block) { block.executed_payment_count = {}; }
  ];
  blockCases.forEach(function (change, index) {
    const feed = clone(rawMarked);
    change(feed.blocks[3]);                          /* slot 254867: 5 transactions, 1 payment, 1 executed */
    const result = explorer.validateFeed(feed);
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.skipped, 1, 'block case ' + index);
    assert.strictEqual(result.feed.blocks.length, 119);
  });
  const transactionCases = [
    'finalize', 3, true, {}, ['deposit'], ['Finalize'], [3], [null], [['finalize']], ['close', 'finalize'],
    ['write', 'write'], ['initialize', 'write', 'seal', 'finalize', 'close', 'inline', 'unknown', 'unknown']
  ];
  transactionCases.forEach(function (value, index) {
    const feed = clone(rawMarked);
    feed.transactions[0].payment_instructions = value;
    const result = explorer.validateFeed(feed);
    assert.strictEqual(result.skipped, 1, 'transaction case ' + index);
    assert.strictEqual(result.feed.transactions.length, 36);
  });
  /* Every name in the feed's order is the longest list there is. */
  const all = clone(rawMarked);
  all.transactions[0].payment_instructions = explorer.PAYMENT_INSTRUCTIONS.slice();
  assert.strictEqual(explorer.validateFeed(all).skipped, 0);
  /* A validator with an impossible root slot is skipped; stats with half the counters are dropped. */
  ['12', -1, 1.5, false].forEach(function (value) {
    const feed = clone(rawMarked);
    feed.network.validators[0].root_slot = value;
    const result = explorer.validateFeed(feed);
    assert.strictEqual(result.skipped, 1);
    assert.strictEqual(result.feed.network.validators.length, 2);
  });
  [function (stats) { delete stats.payments_since; }, function (stats) { stats.executed_payments_seen = 15; },
    function (stats) { stats.payment_transactions_seen = '14'; }].forEach(function (change) {
    const feed = clone(rawMarked);
    change(feed.stats);
    assert.strictEqual(explorer.validateFeed(feed).feed.stats, null);
  });
  /* The page's own copy of a mark is not the feed's array. */
  const feed = clone(rawMarked);
  const result = explorer.validateFeed(feed);
  feed.transactions[0].payment_instructions.push('unknown');
  assert.deepStrictEqual(result.feed.transactions[0].payment_instructions, ['finalize', 'close']);
});

/* ---------- validators ---------- */

test('validator rows carry what the feed reports and how far each vote is behind the tip', function () {
  assert.deepStrictEqual(explorer.validatorRows(null), []);
  const rows = explorer.validatorRows(live);
  assert.strictEqual(rows.length, 3);
  assert.deepStrictEqual(rows[0], { identity: rawLive.network.validators[0].identity,
    vote_account: rawLive.network.validators[0].vote_account, last_vote: 254870, behind: 1, root_slot: null,
    root_behind: null, active: true });
  assert.deepStrictEqual(rows.map(function (row) { return row.behind; }), [1, 1, 2]);
  /* With a feed that carries root slots the rows carry them as well. */
  const withRoots = explorer.validatorRows(marked);
  assert.deepStrictEqual(withRoots.map(function (row) { return [row.root_slot, row.root_behind]; }),
    [[254839, 32], [254838, 33], [254837, 34]]);
  /* A paused feed knows no tip: the last vote is shown, the distance is not. */
  const stopped = explorer.validatorRows(paused);
  assert.deepStrictEqual(stopped.map(function (row) { return [row.last_vote, row.behind, row.active]; }),
    [[276518, null, false], [276518, null, false], [null, null, false]]);
  assert.strictEqual(stopped[2].vote_account, null);
  /* A vote the node reports above the tip of the same feed is not a negative distance. */
  const ahead = clone(live);
  ahead.network.validators[0].last_vote = ahead.network.tip_slot + 3;
  assert.strictEqual(explorer.validatorRows(ahead)[0].behind, 0);
});

test('validator wording: distance, voting and the summary line', function () {
  assert.strictEqual(explorer.slotsBehind(0), 'At the tip');
  assert.strictEqual(explorer.slotsBehind(1), '1 slot behind');
  assert.strictEqual(explorer.slotsBehind(1500), '1,500 slots behind');
  assert.strictEqual(explorer.slotsBehind(null), null);
  assert.strictEqual(explorer.votingLabel(true, true), 'Voting');
  assert.strictEqual(explorer.votingLabel(false, true), 'Not voting');
  assert.strictEqual(explorer.votingLabel(true, false), 'Voting when last recorded');
  assert.strictEqual(explorer.votingLabel(false, false), 'Not voting when last recorded');
  assert.strictEqual(explorer.validatorsSummary(live, true), '3 of 3 validators in the feed are voting');
  assert.strictEqual(explorer.validatorsSummary(live, false), 'Last recorded: 3 of 3 validators in the feed were voting');
  assert.strictEqual(explorer.validatorsSummary(paused, false), 'Last recorded: 0 of 3 validators in the feed were voting');
  const one = clone(live);
  one.network.validators.length = 1;
  assert.strictEqual(explorer.validatorsSummary(one, true), '1 of 1 validator in the feed is voting');
  assert.strictEqual(explorer.validatorsSummary(one, false), 'Last recorded: 1 of 1 validator in the feed was voting');
  one.network.validators = [];
  assert.strictEqual(explorer.validatorsSummary(one, true), 'The feed lists no validators.');
  assert.strictEqual(explorer.validatorsSummary(null, false), 'The feed lists no validators.');
});

test('the notice of a validators list uses the same states as the explorer', function () {
  const notice = function (feed, fetched, now) { return explorer.validatorsNotice(explorer.describeState(feed, fetched, now)); };
  assert.strictEqual(notice(null, null, 0), '');
  assert.strictEqual(notice(null, false, 0), 'Validator data is not available yet.');
  assert.strictEqual(notice(live, true, live.generated_at + 5), '');
  assert.strictEqual(notice(live, true, live.generated_at + 31), 'The network is paused. Showing the validators as last recorded.');
  assert.strictEqual(notice(paused, true, paused.generated_at), 'The network is paused. Showing the validators as last recorded.');
  assert.strictEqual(notice(live, false, live.generated_at + 31),
    'Explorer data could not be refreshed. Showing the validators as last recorded.');
});

/* ---------- source rules ---------- */

test('explorer.js keeps to ES2019 syntax and DOM text nodes', function () {
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '');
  const banned = [
    [/\?\.(?!\d)/, 'optional chaining'],
    [/\?\?/, 'nullish coalescing'],
    [/\bBigInt\b|\b\d+n\b/, 'BigInt'],
    [/\bglobalThis\b/, 'globalThis'],
    [/\.replaceAll\(|\.at\(|\ballSettled\b|\bstructuredClone\b/, 'newer library calls'],
    [/\bimport\b|\bexport\b|\bawait\b/, 'module syntax'],
    [/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(|new Function/, 'markup or code from strings'],
    [/https?:\/\//, 'absolute URL'],
    [/localStorage|sessionStorage|document\.cookie/, 'browser storage']
  ];
  banned.forEach(function (rule) {
    assert.strictEqual(rule[0].test(code), false, rule[1]);
  });
  assert.ok(code.indexOf("cache: 'no-store'") !== -1);
  assert.ok(code.indexOf("'/explorer/feed.json'") !== -1);
  assert.strictEqual(new Function(source + '\nreturn typeof module;').call(undefined), 'undefined');
});

test('fixed wording of the feed states is present', function () {
  assert.strictEqual(explorer.TEXT.unavailable, 'Explorer data is not available yet.');
  assert.strictEqual(explorer.TEXT.paused,
    'The network is paused. Showing the last recorded blocks.');
  assert.strictEqual(explorer.TEXT.searchScope, 'Only the recent window is searchable for now.');
});
