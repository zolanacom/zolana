/* Zolana explorer.
   Reads the public feed from the same origin, validates every field before use and
   renders with DOM text nodes only. The same file drives the status badge on other
   pages (any element with data-zolana-status). Formatting, validation and search
   helpers are exported for tests when a CommonJS module object is present. */
(function () {
  'use strict';

  const FEED_URL = '/explorer/feed.json';
  const FEED_FORMAT = 'zolana-explorer-feed-v0';
  const POLL_MS = 5000;
  const FETCH_TIMEOUT_MS = 4500;
  const LIVE_WINDOW_SECONDS = 30;
  const MAX_FEED_CHARS = 409600;
  const MAX_BLOCKS = 120;
  const MAX_TRANSACTIONS = 200;
  const MAX_VALIDATORS = 256;
  const MAX_ID_CHARS = 128;
  const MAX_UNIX_SECONDS = 99999999999;
  const MAX_SLOT_TIME_MS = 3600000;
  const PAGE_ROWS = 50;
  const MIN_HASH_QUERY = 4;
  const LAMPORTS_PER_ZOL = 1000000000;
  const CLOCK_SKEW_TOLERANCE_MS = 5000;
  const COPY_FEEDBACK_MS = 1600;
  const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
  const DIGITS = /^[0-9]+$/;
  const DASH = '\u2014';
  const INVALID = {};

  const TEXT = {
    unavailable: 'Explorer data is not available yet.',
    paused: 'The network is paused between windows. Showing the last recorded blocks.',
    refreshFailed: 'Explorer data could not be refreshed. Showing the last recorded blocks.',
    searchScope: 'Only the recent window is searchable for now.',
    searchEmpty: 'There is nothing to search until explorer data is available.',
    searchHint: 'Enter a slot number, or at least 4 characters from the start of a blockhash or signature. Blockhashes and signatures are case-sensitive.'
  };

  /* ---------- validation ---------- */

  function isObject(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
  }

  function isNatural(value) {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
  }

  function isTime(value) {
    return isNatural(value) && value <= MAX_UNIX_SECONDS;
  }

  function isId(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= MAX_ID_CHARS && BASE58.test(value);
  }

  function optional(value, check) {
    if (value === null || value === undefined) return null;
    return check(value) ? value : INVALID;
  }

  function readBlock(raw) {
    if (!isObject(raw)) return null;
    const parentSlot = optional(raw.parent_slot, isNatural);
    const blockTime = optional(raw.block_time, isTime);
    const blockHeight = optional(raw.block_height, isNatural);
    if (!isNatural(raw.slot) || !isId(raw.blockhash) || !isNatural(raw.tx_count) ||
        !isNatural(raw.non_vote_tx_count) || parentSlot === INVALID || blockTime === INVALID ||
        blockHeight === INVALID) {
      return null;
    }
    return {
      slot: raw.slot,
      parent_slot: parentSlot,
      blockhash: raw.blockhash,
      block_time: blockTime,
      block_height: blockHeight,
      tx_count: raw.tx_count,
      non_vote_tx_count: raw.non_vote_tx_count
    };
  }

  function readTransaction(raw) {
    if (!isObject(raw)) return null;
    const blockTime = optional(raw.block_time, isTime);
    if (!isId(raw.signature) || !isNatural(raw.slot) || blockTime === INVALID ||
        typeof raw.ok !== 'boolean' || !isNatural(raw.fee) ||
        (raw.kind !== 'vote' && raw.kind !== 'program')) {
      return null;
    }
    return {
      signature: raw.signature,
      slot: raw.slot,
      block_time: blockTime,
      ok: raw.ok,
      fee: raw.fee,
      kind: raw.kind
    };
  }

  function readValidator(raw) {
    if (!isObject(raw)) return null;
    const voteAccount = optional(raw.vote_account, isId);
    const lastVote = optional(raw.last_vote, isNatural);
    if (!isId(raw.identity) || typeof raw.active !== 'boolean' || voteAccount === INVALID ||
        lastVote === INVALID) {
      return null;
    }
    return { identity: raw.identity, vote_account: voteAccount, last_vote: lastVote, active: raw.active };
  }

  function readStats(raw) {
    if (!isObject(raw) || !isTime(raw.since) || !isNatural(raw.blocks_seen) ||
        !isNatural(raw.transactions_seen) || !isNatural(raw.non_vote_transactions_seen)) {
      return null;
    }
    return {
      since: raw.since,
      blocks_seen: raw.blocks_seen,
      transactions_seen: raw.transactions_seen,
      non_vote_transactions_seen: raw.non_vote_transactions_seen
    };
  }

  /* Reads a list, keeps the first entry for each key, orders it newest first and
     applies the contract limit. Returns the kept rows and how many were skipped. */
  function readList(rawList, readRow, keyOf, limit) {
    const rows = [];
    const seen = new Set();
    let skipped = 0;
    for (let i = 0; i < rawList.length; i += 1) {
      const row = readRow(rawList[i]);
      const key = row === null ? null : keyOf(row);
      if (row === null || seen.has(key)) {
        skipped += 1;
      } else {
        seen.add(key);
        rows.push(row);
      }
    }
    rows.sort(function (a, b) { return b.slot - a.slot; });
    return { rows: rows.slice(0, limit), skipped: skipped };
  }

  function rejectFeed(reason) {
    return { ok: false, feed: null, skipped: 0, error: reason };
  }

  function validateFeed(value) {
    if (!isObject(value)) return rejectFeed('The feed is not an object.');
    if (value.format !== FEED_FORMAT) return rejectFeed('The feed format is not supported.');
    if (!isTime(value.generated_at)) return rejectFeed('The feed has no valid generation time.');
    if (!isObject(value.network)) return rejectFeed('The feed has no network section.');
    if (!Array.isArray(value.blocks) || !Array.isArray(value.transactions)) {
      return rejectFeed('The feed has no block or transaction list.');
    }
    const network = value.network;
    const slotTime = network.slot_time_ms;
    const rawValidators = Array.isArray(network.validators) ? network.validators : [];
    const validators = [];
    let skipped = 0;
    for (let i = 0; i < rawValidators.length && validators.length < MAX_VALIDATORS; i += 1) {
      const validator = readValidator(rawValidators[i]);
      if (validator === null) skipped += 1; else validators.push(validator);
    }
    const blocks = readList(value.blocks, readBlock, function (block) { return block.slot; }, MAX_BLOCKS);
    const transactions = readList(value.transactions, readTransaction,
      function (transaction) { return transaction.signature; }, MAX_TRANSACTIONS);
    return {
      ok: true,
      error: null,
      skipped: skipped + blocks.skipped + transactions.skipped,
      feed: {
        format: FEED_FORMAT,
        generated_at: value.generated_at,
        genesis_hash: isId(value.genesis_hash) ? value.genesis_hash : null,
        network: {
          status: network.status === 'live' ? 'live' : 'unavailable',
          tip_slot: isNatural(network.tip_slot) ? network.tip_slot : null,
          finalized_slot: isNatural(network.finalized_slot) ? network.finalized_slot : null,
          block_height: isNatural(network.block_height) ? network.block_height : null,
          slot_time_ms: typeof slotTime === 'number' && isFinite(slotTime) && slotTime > 0 &&
            slotTime <= MAX_SLOT_TIME_MS ? slotTime : null,
          last_block_at: isTime(network.last_block_at) ? network.last_block_at : null,
          validators: validators
        },
        blocks: blocks.rows,
        transactions: transactions.rows,
        stats: readStats(value.stats)
      }
    };
  }

  /* Accepts the response body as text so that an error page or a truncated file is
     reported as unavailable data instead of raising. */
  function parseFeedText(text) {
    if (typeof text !== 'string' || text.length === 0) return rejectFeed('The feed is empty.');
    if (text.length > MAX_FEED_CHARS) return rejectFeed('The feed is larger than the contract allows.');
    let value;
    try {
      value = JSON.parse(text);
    } catch (error) {
      return rejectFeed('The feed is not valid JSON.');
    }
    return validateFeed(value);
  }

  /* ---------- state ---------- */

  function isLive(feed, nowSeconds) {
    return Boolean(feed) && feed.network.status === 'live' &&
      (nowSeconds - feed.generated_at) <= LIVE_WINDOW_SECONDS;
  }

  function countActiveValidators(feed) {
    let active = 0;
    if (feed) {
      feed.network.validators.forEach(function (validator) { if (validator.active) active += 1; });
    }
    return active;
  }

  function stateOf(state, label, message, updatedAt) {
    const updated = updatedAt === null ? '' : ' Last updated ' + formatUtc(updatedAt) + '.';
    return { state: state, label: label, message: message, updatedAt: updatedAt, notice: message + updated };
  }

  /* lastFetchOk is null before the first attempt has finished. The notice is the
     message followed, when a feed is held but not live, by its last update time. */
  function describeState(feed, lastFetchOk, nowSeconds) {
    if (!feed) {
      if (lastFetchOk === null) return stateOf('loading', 'Loading', '', null);
      return stateOf('nodata', 'No data', TEXT.unavailable, null);
    }
    if (isLive(feed, nowSeconds)) return stateOf('live', 'Live', '', null);
    return stateOf('paused', 'Paused', lastFetchOk === false ? TEXT.refreshFailed : TEXT.paused, feed.generated_at);
  }

  /* The feed time and the web server time both come from synchronised hosts. When the
     device clock clearly disagrees with the response Date header, the header wins so
     that a wrong device clock cannot turn a live feed into a paused one. */
  function clockOffsetMs(dateHeader, localMs) {
    if (typeof dateHeader !== 'string' || dateHeader === '') return 0;
    const serverMs = Date.parse(dateHeader);
    if (!isFinite(serverMs) || typeof localMs !== 'number' || !isFinite(localMs)) return 0;
    const offset = serverMs - localMs;
    return Math.abs(offset) > CLOCK_SKEW_TOLERANCE_MS ? offset : 0;
  }

  function nextLimit(limit, total) {
    return Math.min(Math.max(limit, 0) + PAGE_ROWS, Math.max(total, 0));
  }

  function countLabel(shown, total, singular, plural) {
    if (total === 0) return '';
    const noun = total === 1 ? singular : plural;
    if (shown >= total) return 'Showing all ' + formatInteger(total) + ' ' + noun + ' in the recent window.';
    return 'Showing ' + formatInteger(shown) + ' of ' + formatInteger(total) + ' ' + noun + ' in the recent window.';
  }

  /* ---------- formatting ---------- */

  function formatInteger(value) {
    return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  }

  /* Lamports to ZOL with up to nine decimals and no trailing zeros. */
  function formatZol(lamports) {
    if (!isNatural(lamports)) return '';
    const whole = Math.floor(lamports / LAMPORTS_PER_ZOL);
    const fraction = lamports % LAMPORTS_PER_ZOL;
    if (fraction === 0) return formatInteger(whole);
    const digits = ('000000000' + String(fraction)).slice(-9).replace(/0+$/, '');
    return formatInteger(whole) + '.' + digits;
  }

  function formatAge(seconds) {
    const total = Math.max(0, Math.floor(Number(seconds) || 0));
    if (total < 60) return total + ' s';
    if (total < 3600) return Math.floor(total / 60) + ' min ' + (total % 60) + ' s';
    if (total < 86400) return Math.floor(total / 3600) + ' h ' + Math.floor((total % 3600) / 60) + ' min';
    return Math.floor(total / 86400) + ' d ' + Math.floor((total % 86400) / 3600) + ' h';
  }

  function isoUtc(unixSeconds) {
    return isTime(unixSeconds) ? new Date(unixSeconds * 1000).toISOString().slice(0, 19) + 'Z' : '';
  }

  function formatUtc(unixSeconds) {
    const iso = isoUtc(unixSeconds);
    return iso === '' ? 'Unknown time' : iso.slice(0, 10) + ' ' + iso.slice(11, 19) + ' UTC';
  }

  function formatSlotTime(milliseconds) {
    if (typeof milliseconds !== 'number' || !isFinite(milliseconds) || milliseconds <= 0) return '';
    if (milliseconds < 1000) return Math.round(milliseconds) + ' ms';
    return (milliseconds / 1000).toFixed(2) + ' s';
  }

  function shortHash(value, head, tail) {
    const text = String(value);
    const lead = head === undefined ? 8 : head;
    const trail = tail === undefined ? 6 : tail;
    if (text.length <= lead + trail + 1) return text;
    return text.slice(0, lead) + '\u2026' + text.slice(text.length - trail);
  }

  function kindLabel(kind) {
    return kind === 'vote' ? 'Vote' : 'Program';
  }

  /* ---------- search ---------- */

  function searchResult(status, matches, message) {
    return { status: status, matches: matches, message: message };
  }

  /* Matches a slot number, or a case-sensitive base58 prefix of a blockhash or
     signature, within the feed that is currently held. Matches are newest first. */
  function searchFeed(feed, rawQuery) {
    const query = typeof rawQuery === 'string' ? rawQuery.trim() : '';
    if (query === '') return searchResult('empty', [], '');
    if (!feed) return searchResult('nodata', [], TEXT.searchEmpty);
    const asBlock = function (block) { return { type: 'block', item: block }; };
    const asTransaction = function (transaction) { return { type: 'transaction', item: transaction }; };
    const digits = query.replace(/[\s,_]/g, '');
    const isSlotQuery = DIGITS.test(digits) && Number.isSafeInteger(Number(digits));
    let matches = [];
    if (isSlotQuery) {
      const slot = Number(digits);
      matches = feed.blocks.filter(function (block) { return block.slot === slot; }).map(asBlock);
      if (matches.length === 0) {
        matches = feed.transactions.filter(function (transaction) { return transaction.slot === slot; })
          .map(asTransaction);
      }
    }
    const isHashQuery = query.length >= MIN_HASH_QUERY && query.length <= MAX_ID_CHARS && BASE58.test(query);
    if (matches.length === 0 && isHashQuery) {
      matches = feed.blocks.filter(function (block) { return block.blockhash.lastIndexOf(query, 0) === 0; })
        .map(asBlock)
        .concat(feed.transactions
          .filter(function (transaction) { return transaction.signature.lastIndexOf(query, 0) === 0; })
          .map(asTransaction));
      matches.sort(function (a, b) { return b.item.slot - a.item.slot; });
    }
    if (matches.length === 1) return searchResult('found', matches, '');
    if (matches.length > 1) {
      return searchResult('found', matches, 'Showing the newest of ' + matches.length +
        ' matches. Enter more characters to narrow the search.');
    }
    if (isSlotQuery || isHashQuery) {
      return searchResult('not_found', [], 'No matching block or transaction. ' + TEXT.searchScope);
    }
    return searchResult('invalid', [], TEXT.searchHint + ' ' + TEXT.searchScope);
  }

  const api = {
    FEED_URL: FEED_URL,
    FEED_FORMAT: FEED_FORMAT,
    POLL_MS: POLL_MS,
    LIVE_WINDOW_SECONDS: LIVE_WINDOW_SECONDS,
    MAX_FEED_CHARS: MAX_FEED_CHARS,
    MAX_BLOCKS: MAX_BLOCKS,
    MAX_TRANSACTIONS: MAX_TRANSACTIONS,
    PAGE_ROWS: PAGE_ROWS,
    TEXT: TEXT,
    validateFeed: validateFeed,
    parseFeedText: parseFeedText,
    isLive: isLive,
    countActiveValidators: countActiveValidators,
    describeState: describeState,
    clockOffsetMs: clockOffsetMs,
    nextLimit: nextLimit,
    countLabel: countLabel,
    formatInteger: formatInteger,
    formatZol: formatZol,
    formatAge: formatAge,
    formatUtc: formatUtc,
    isoUtc: isoUtc,
    formatSlotTime: formatSlotTime,
    shortHash: shortHash,
    kindLabel: kindLabel,
    searchFeed: searchFeed
  };

  if (typeof module === 'object' && module !== null && typeof module.exports === 'object') {
    module.exports = api;
  }

  /* ---------- page ---------- */

  function start(doc, win) {
    const app = doc.querySelector('[data-explorer-app]');
    const statusRoots = Array.prototype.slice.call(doc.querySelectorAll('[data-zolana-status]'));
    if (!app && statusRoots.length === 0) return;

    const state = {
      feed: null,
      lastFetchOk: null,
      clockOffsetMs: 0,
      blockLimit: PAGE_ROWS,
      transactionLimit: PAGE_ROWS,
      detailOpener: null
    };
    let inFlight = false;
    let awaitingResume = false;
    let lastPollStarted = -Infinity;

    function monotonicMs() {
      return win.performance && typeof win.performance.now === 'function' ? win.performance.now() : Date.now();
    }

    function nowSeconds() {
      return Math.floor((Date.now() + state.clockOffsetMs) / 1000);
    }

    function el(tag, className, text) {
      const node = doc.createElement(tag);
      if (className) node.className = className;
      if (text !== undefined && text !== null) node.textContent = String(text);
      return node;
    }

    function setText(node, text) {
      if (node.textContent !== text) node.textContent = text;
    }

    function setMissing(node, description) {
      if (node.getAttribute('data-missing') === '1') return;
      node.textContent = '';
      const dash = el('span', '', DASH);
      dash.setAttribute('aria-hidden', 'true');
      node.appendChild(dash);
      node.appendChild(el('span', 'sr-only', description));
      node.setAttribute('data-missing', '1');
    }

    function setValue(node, text) {
      if (text === null) {
        setMissing(node, 'Not reported');
        return;
      }
      node.removeAttribute('data-missing');
      setText(node, text);
    }

    /* ----- status badge and fields, on every page that carries them ----- */

    function withFallback(nodes) {
      return Array.prototype.map.call(nodes, function (node) {
        return { node: node, fallback: node.textContent };
      });
    }

    const statusViews = statusRoots.map(function (root) {
      return {
        root: root,
        inApp: Boolean(app) && app.contains(root),
        dots: Array.prototype.slice.call(root.querySelectorAll('[data-zolana-status-dot]')),
        labels: withFallback(root.querySelectorAll('[data-zolana-status-text]')),
        fields: withFallback(root.querySelectorAll('[data-zolana-field]'))
      };
    });

    function fieldText(name, feed, seconds) {
      const network = feed.network;
      if (name === 'tip_slot') return network.tip_slot === null ? null : formatInteger(network.tip_slot);
      if (name === 'finalized_slot') return network.finalized_slot === null ? null : formatInteger(network.finalized_slot);
      if (name === 'block_height') return network.block_height === null ? null : formatInteger(network.block_height);
      if (name === 'slot_time') return network.slot_time_ms === null ? null : formatSlotTime(network.slot_time_ms);
      if (name === 'validators') return formatInteger(countActiveValidators(feed));
      if (name === 'updated') return 'Updated ' + formatAge(seconds - feed.generated_at) + ' ago';
      if (name === 'updated_utc') return formatUtc(feed.generated_at);
      return null;
    }

    function renderStatus(view, description, seconds) {
      const feed = state.feed;
      const live = description.state === 'live';
      view.root.setAttribute('data-state', description.state);
      view.dots.forEach(function (dot) {
        dot.classList.toggle('running', live);
        dot.classList.toggle('unknown', !live);
      });
      view.labels.forEach(function (entry) {
        setText(entry.node, feed || view.inApp ? description.label : entry.fallback);
        if (entry.node.classList.contains('badge')) entry.node.classList.toggle('verified', live);
      });
      view.fields.forEach(function (entry) {
        if (!feed) {
          entry.node.removeAttribute('data-missing');
          setText(entry.node, entry.fallback);
        } else {
          setValue(entry.node, fieldText(entry.node.getAttribute('data-zolana-field'), feed, seconds));
        }
      });
    }

    /* ----- explorer page ----- */

    function byId(id) {
      return doc.getElementById(id);
    }

    function listView(prefix, singular, plural) {
      const view = {
        body: byId(prefix + '-body'),
        wrap: byId(prefix + '-wrap'),
        empty: byId(prefix + '-empty'),
        count: byId(prefix + '-count'),
        more: byId(prefix + '-more'),
        singular: singular,
        plural: plural,
        rows: new Map()
      };
      return view.body && view.wrap && view.empty && view.count && view.more ? view : null;
    }

    const page = app ? {
      notice: byId('explorer-notice'),
      data: byId('explorer-data'),
      form: byId('explorer-search'),
      input: byId('explorer-query'),
      searchNote: byId('explorer-search-note'),
      detail: byId('explorer-detail'),
      announcer: byId('explorer-announcer'),
      blocks: listView('blocks', 'block', 'blocks'),
      transactions: listView('transactions', 'transaction', 'transactions')
    } : null;
    const pageReady = Boolean(page) && Object.keys(page).every(function (key) { return Boolean(page[key]); });

    function announce(message) {
      page.announcer.textContent = '';
      win.setTimeout(function () { page.announcer.textContent = message; }, 30);
    }

    function legacyCopy(text) {
      const area = el('textarea', 'sr-only');
      area.value = text;
      area.setAttribute('readonly', '');
      area.setAttribute('aria-hidden', 'true');
      doc.body.appendChild(area);
      area.select();
      let copied = false;
      try {
        copied = doc.execCommand('copy');
      } catch (error) {
        copied = false;
      }
      doc.body.removeChild(area);
      return copied;
    }

    function copyText(text) {
      const clipboard = win.navigator && win.navigator.clipboard;
      if (clipboard && typeof clipboard.writeText === 'function') {
        return clipboard.writeText(text).then(function () { return true; }, function () { return legacyCopy(text); });
      }
      return Promise.resolve(legacyCopy(text));
    }

    function copyButton(value, name) {
      const button = el('button', 'copy-button', 'Copy');
      let timer = 0;
      button.type = 'button';
      button.setAttribute('aria-label', 'Copy ' + name);
      button.addEventListener('click', function () {
        copyText(value).then(function (copied) {
          button.textContent = copied ? 'Copied' : 'Copy failed';
          button.focus();
          announce(copied ? 'Copied ' + name + '.' : 'Could not copy ' + name + '. Select the text to copy it.');
          win.clearTimeout(timer);
          timer = win.setTimeout(function () { button.textContent = 'Copy'; }, COPY_FEEDBACK_MS);
        });
      });
      return button;
    }

    function linkButton(text, className, label, onOpen) {
      const button = el('button', className, text);
      button.type = 'button';
      if (label) button.setAttribute('aria-label', label);
      button.addEventListener('click', function () { onOpen(button); });
      return button;
    }

    function resultBadge(ok) {
      return el('span', ok ? 'badge verified' : 'badge failed', ok ? 'Success' : 'Failed');
    }

    function findBlock(slot) {
      const blocks = state.feed ? state.feed.blocks : [];
      for (let i = 0; i < blocks.length; i += 1) {
        if (blocks[i].slot === slot) return blocks[i];
      }
      return null;
    }

    function detailRow(list, term, value, copyValue, copyName) {
      const description = el('dd');
      description.appendChild(value);
      if (copyValue !== undefined) description.appendChild(copyButton(copyValue, copyName));
      list.appendChild(el('dt', '', term));
      list.appendChild(description);
    }

    function textValue(text, className) {
      return el('span', className || '', text);
    }

    function optionalValue(value, format) {
      const node = el('span');
      if (value === null) setMissing(node, 'Not recorded'); else node.textContent = format(value);
      return node;
    }

    function slotValue(slot, opener) {
      const block = slot === null ? null : findBlock(slot);
      if (!block) return optionalValue(slot, String);
      const holder = el('span');
      holder.appendChild(linkButton(String(slot), 'data-link', 'Block ' + String(slot) + ', show details',
        function () { openDetail({ type: 'block', item: block }, opener); }));
      return holder;
    }

    function closeDetail() {
      const opener = state.detailOpener;
      page.detail.hidden = true;
      page.detail.textContent = '';
      state.detailOpener = null;
      if (opener && doc.contains(opener)) opener.focus(); else page.input.focus();
    }

    function openDetail(match, opener) {
      const panel = page.detail;
      const item = match.item;
      const isBlock = match.type === 'block';
      const heading = el('div', 'detail-heading');
      const title = el('h2', 'subheading', isBlock ? 'Block ' + formatInteger(item.slot) : 'Transaction');
      const close = linkButton('Close', 'back-button', 'Close details', closeDetail);
      const list = el('dl', 'detail-grid');
      state.detailOpener = opener || state.detailOpener;
      title.id = 'explorer-detail-title';
      title.tabIndex = -1;
      heading.appendChild(title);
      heading.appendChild(close);
      if (isBlock) {
        detailRow(list, 'Slot', textValue(String(item.slot)), String(item.slot), 'slot');
        detailRow(list, 'Blockhash', textValue(item.blockhash, 'identifier'), item.blockhash, 'blockhash');
        detailRow(list, 'Parent slot', slotValue(item.parent_slot, state.detailOpener));
        detailRow(list, 'Block time', optionalValue(item.block_time, formatUtc));
        detailRow(list, 'Block height', optionalValue(item.block_height, formatInteger));
        detailRow(list, 'Transactions', textValue(formatInteger(item.tx_count)));
        detailRow(list, 'Non-vote transactions', textValue(formatInteger(item.non_vote_tx_count)));
        const held = state.feed ? state.feed.transactions.filter(function (transaction) {
          return transaction.slot === item.slot;
        }) : [];
        if (held.length > 0) {
          const links = el('span', 'explorer-links');
          held.forEach(function (transaction) {
            links.appendChild(linkButton(shortHash(transaction.signature), 'data-link identifier',
              'Transaction ' + shortHash(transaction.signature) + ', show details',
              function () { openDetail({ type: 'transaction', item: transaction }, state.detailOpener); }));
          });
          detailRow(list, 'Transactions in the recent window', links);
        }
      } else {
        detailRow(list, 'Signature', textValue(item.signature, 'identifier'), item.signature, 'signature');
        detailRow(list, 'Slot', slotValue(item.slot, state.detailOpener), String(item.slot), 'slot');
        detailRow(list, 'Block time', optionalValue(item.block_time, formatUtc));
        detailRow(list, 'Result', resultBadge(item.ok));
        detailRow(list, 'Fee', textValue(formatZol(item.fee) + ' ZOL (' + formatInteger(item.fee) + ' lamports)'));
        detailRow(list, 'Kind', textValue(kindLabel(item.kind)));
      }
      panel.textContent = '';
      panel.appendChild(heading);
      panel.appendChild(list);
      panel.hidden = false;
      panel.scrollIntoView({ block: 'nearest' });
      title.focus({ preventScroll: true });
    }

    function ageCell(time) {
      const cell = el('td');
      if (time === null) {
        setMissing(cell, 'Not recorded');
        return { cell: cell, node: null };
      }
      const node = el('time');
      node.setAttribute('datetime', isoUtc(time));
      node.title = formatUtc(time);
      cell.appendChild(node);
      return { cell: cell, node: node };
    }

    function wrapCell(node) {
      const cell = el('td');
      cell.appendChild(node);
      return cell;
    }

    /* The first cell names the row for assistive technology. */
    function rowHeader(node) {
      const cell = el('th');
      cell.setAttribute('scope', 'row');
      cell.appendChild(node);
      return cell;
    }

    function buildBlockRow(block) {
      const row = el('tr');
      const age = ageCell(block.block_time);
      const slot = formatInteger(block.slot);
      const hash = el('span', 'identifier', shortHash(block.blockhash));
      hash.title = block.blockhash;
      row.appendChild(rowHeader(linkButton(slot, 'data-link', 'Block ' + slot + ', show details',
        function (button) { openDetail({ type: 'block', item: block }, button); })));
      row.appendChild(wrapCell(hash));
      row.appendChild(age.cell);
      row.appendChild(el('td', '', formatInteger(block.tx_count)));
      row.appendChild(el('td', '', formatInteger(block.non_vote_tx_count)));
      return { row: row, age: age.node, time: block.block_time };
    }

    function buildTransactionRow(transaction) {
      const row = el('tr');
      const age = ageCell(transaction.block_time);
      const short = shortHash(transaction.signature);
      row.appendChild(rowHeader(linkButton(short, 'data-link identifier', 'Transaction ' + short + ', show details',
        function (button) { openDetail({ type: 'transaction', item: transaction }, button); })));
      row.appendChild(el('td', '', formatInteger(transaction.slot)));
      row.appendChild(age.cell);
      row.appendChild(wrapCell(resultBadge(transaction.ok)));
      row.appendChild(el('td', '', formatZol(transaction.fee)));
      row.appendChild(el('td', '', kindLabel(transaction.kind)));
      return { row: row, age: age.node, time: transaction.block_time };
    }

    function blockKey(block) {
      return [block.slot, block.blockhash, block.parent_slot, block.block_time, block.block_height,
        block.tx_count, block.non_vote_tx_count].join('|');
    }

    function transactionKey(transaction) {
      return [transaction.signature, transaction.slot, transaction.block_time, transaction.ok,
        transaction.fee, transaction.kind].join('|');
    }

    /* Keeps existing rows in place so that keyboard focus and text selection survive
       a refresh; only new rows are created and only departed rows are removed. */
    function renderList(view, items, limit, keyOf, build) {
      const body = view.body;
      const shown = Math.min(limit, items.length);
      const wanted = new Set();
      for (let i = 0; i < shown; i += 1) {
        const key = keyOf(items[i]);
        let entry = view.rows.get(key);
        if (!entry) {
          entry = build(items[i]);
          view.rows.set(key, entry);
        }
        wanted.add(key);
        if (body.children[i] !== entry.row) body.insertBefore(entry.row, body.children[i] || null);
      }
      view.rows.forEach(function (entry, key) {
        if (!wanted.has(key)) {
          if (entry.row.parentNode === body) body.removeChild(entry.row);
          view.rows.delete(key);
        }
      });
      view.wrap.hidden = items.length === 0;
      view.empty.hidden = items.length !== 0;
      view.more.hidden = shown >= items.length;
      setText(view.count, countLabel(shown, items.length, view.singular, view.plural));
    }

    function renderData() {
      const feed = state.feed;
      page.data.hidden = !feed;
      if (!feed) return;
      renderList(page.blocks, feed.blocks, state.blockLimit, blockKey, buildBlockRow);
      renderList(page.transactions, feed.transactions, state.transactionLimit, transactionKey, buildTransactionRow);
    }

    /* Block times come from the chain's own clock, which stands still while the
       network is paused. Ages are shown relative to when the feed saw its newest block. */
    function chainClockLag() {
      const feed = state.feed;
      if (!feed || !feed.blocks.length) return 0;
      let newest = null;
      feed.blocks.forEach(function (block) {
        if (block.block_time !== null && (newest === null || block.block_time > newest)) newest = block.block_time;
      });
      if (newest === null) return 0;
      const lag = feed.generated_at - newest;
      return lag > 120 ? lag : 0;
    }

    function renderAges(seconds) {
      const lag = chainClockLag();
      [page.blocks, page.transactions].forEach(function (view) {
        view.rows.forEach(function (entry) {
          if (entry.age) setText(entry.age, formatAge(Math.max(0, seconds - entry.time - lag)) + ' ago');
        });
      });
    }

    /* Rewritten only when the wording changes, so it is announced once. */
    function renderNotice(description) {
      const notice = page.notice;
      if (notice.getAttribute('data-tone') !== description.state) notice.setAttribute('data-tone', description.state);
      if (notice.textContent === description.notice) return;
      notice.textContent = '';
      if (description.updatedAt === null) {
        notice.textContent = description.notice;
        return;
      }
      const time = el('time', '', formatUtc(description.updatedAt));
      time.setAttribute('datetime', isoUtc(description.updatedAt));
      notice.appendChild(doc.createTextNode(description.message + ' Last updated '));
      notice.appendChild(time);
      notice.appendChild(doc.createTextNode('.'));
    }

    function runSearch() {
      const result = searchFeed(state.feed, page.input.value);
      if (result.status === 'invalid') page.input.setAttribute('aria-invalid', 'true');
      else page.input.removeAttribute('aria-invalid');
      page.searchNote.textContent = result.message;
      if (result.status === 'found') {
        openDetail(result.matches[0], page.input);
      } else if (!page.detail.hidden) {
        state.detailOpener = null;
        page.detail.hidden = true;
        page.detail.textContent = '';
      }
    }

    function showMore(view, limitName, items) {
      state[limitName] = nextLimit(state[limitName], items.length);
      renderData();
      renderAges(nowSeconds());
      if (view.more.hidden) view.wrap.focus();
    }

    if (pageReady) {
      page.form.addEventListener('submit', function (event) {
        event.preventDefault();
        runSearch();
      });
      page.input.addEventListener('input', function () {
        page.input.removeAttribute('aria-invalid');
      });
      page.detail.addEventListener('keydown', function (event) {
        if (event.key === 'Escape' && !page.detail.hidden) {
          event.stopPropagation();
          closeDetail();
        }
      });
      page.blocks.more.addEventListener('click', function () {
        if (state.feed) showMore(page.blocks, 'blockLimit', state.feed.blocks);
      });
      page.transactions.more.addEventListener('click', function () {
        if (state.feed) showMore(page.transactions, 'transactionLimit', state.feed.transactions);
      });
    }

    /* ----- refresh loop ----- */

    function render() {
      const seconds = nowSeconds();
      const description = describeState(state.feed, state.lastFetchOk, seconds);
      statusViews.forEach(function (view) { renderStatus(view, description, seconds); });
      if (pageReady) {
        app.setAttribute('data-state', description.state);
        renderNotice(description);
        renderAges(seconds);
      }
    }

    function poll() {
      if (inFlight) return;
      inFlight = true;
      lastPollStarted = monotonicMs();
      const controller = typeof win.AbortController === 'function' ? new win.AbortController() : null;
      const options = { cache: 'no-store', headers: { Accept: 'application/json' } };
      const timeout = win.setTimeout(function () { if (controller) controller.abort(); }, FETCH_TIMEOUT_MS);
      let dateHeader = null;
      let receivedAt = 0;
      if (controller) options.signal = controller.signal;
      Promise.resolve().then(function () {
        return win.fetch(FEED_URL, options);
      }).then(function (response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        dateHeader = response.headers.get('Date');
        receivedAt = Date.now();
        return response.text();
      }).then(function (text) {
        const result = parseFeedText(text);
        if (!result.ok) throw new Error(result.error);
        state.feed = result.feed;
        state.lastFetchOk = true;
        state.clockOffsetMs = clockOffsetMs(dateHeader, receivedAt);
        if (pageReady) renderData();
      }).catch(function () {
        state.lastFetchOk = false;
      }).then(function () {
        win.clearTimeout(timeout);
        inFlight = false;
        awaitingResume = false;
        render();
      });
    }

    /* Polling stops while the tab is hidden. On return the page refreshes first, so a
       tab that was hidden for a while does not flash a paused notice. */
    function tick() {
      if (doc.hidden) return;
      if (monotonicMs() - lastPollStarted >= POLL_MS - 50) poll();
      if (!awaitingResume) render();
    }

    doc.addEventListener('visibilitychange', function () {
      if (doc.hidden) return;
      awaitingResume = true;
      tick();
      if (!inFlight) {
        awaitingResume = false;
        render();
      }
    });
    win.setInterval(tick, 1000);
    tick();
  }

  if (typeof document !== 'undefined' && typeof window !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', function () { start(document, window); });
    } else {
      start(document, window);
    }
  }
}());
