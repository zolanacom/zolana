/* Tests for the pure helpers of site/explorer.js against both feed fixtures.
   Run with: node explorer_logic_test.js
   Uses only Node built-ins. Exits with a non-zero status when a test fails. */
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sitePath = path.join(__dirname, 'explorer.js');
const explorer = require(sitePath);
const source = fs.readFileSync(sitePath, 'utf8');
const liveText = fs.readFileSync(path.join(__dirname, 'feed.sample.json'), 'utf8');
const pausedText = fs.readFileSync(path.join(__dirname, 'feed.paused.json'), 'utf8');

const tests = [];
function test(name, body) {
  tests.push({ name: name, body: body });
}

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
  assert.deepStrictEqual(live.blocks, rawLive.blocks);
  assert.deepStrictEqual(live.transactions, rawLive.transactions);
  assert.deepStrictEqual(live.network, rawLive.network);
  assert.deepStrictEqual(live.stats, rawLive.stats);
  assert.strictEqual(live.generated_at, rawLive.generated_at);
  assert.strictEqual(live.genesis_hash, rawLive.genesis_hash);
  assert.deepStrictEqual(paused.network, JSON.parse(pausedText).network);
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
  assert.deepStrictEqual(result.feed.blocks, rawLive.blocks);
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
  const pausedMessage = 'The network is paused between windows. Showing the last recorded blocks.';
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
  ['999999999', '4', 'zzzzzzzz', live.blocks[0].blockhash + 'z', '9007199254740991'].forEach(function (query) {
    const result = explorer.searchFeed(live, query);
    assert.strictEqual(result.status, 'not_found', query);
    assert.strictEqual(result.message,
      'No matching block or transaction. Only the recent window is searchable for now.');
    assert.deepStrictEqual(result.matches, []);
  });
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

test('fixed wording required by the brief is present', function () {
  assert.strictEqual(explorer.TEXT.unavailable, 'Explorer data is not available yet.');
  assert.strictEqual(explorer.TEXT.paused,
    'The network is paused between windows. Showing the last recorded blocks.');
  assert.strictEqual(explorer.TEXT.searchScope, 'Only the recent window is searchable for now.');
});

/* ---------- runner ---------- */

let failed = 0;
tests.forEach(function (entry) {
  try {
    entry.body();
    console.log('ok   ' + entry.name);
  } catch (error) {
    failed += 1;
    console.log('FAIL ' + entry.name);
    console.log('     ' + String(error && error.stack ? error.stack : error).split('\n').join('\n     '));
  }
});
console.log('\n' + (tests.length - failed) + ' of ' + tests.length + ' tests passed (node ' + process.version + ')');
process.exit(failed === 0 ? 0 : 1);
