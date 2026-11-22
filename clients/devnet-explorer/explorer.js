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
  const STRIP_SLOTS = 120;
  const CHART_COLUMNS = 120;
  const TWEEN_MS = 1200;
  const TICKER_MS = 4600;
  const MAX_TWEEN_SPAN = 20000;
  const ROW_STAGGER_MS = 14;
  const MAX_ROW_DELAY_MS = 420;
  const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
  const DIGITS = /^[0-9]+$/;
  const DASH = '\u2014';
  const INVALID = {};

  const TEXT = {
    unavailable: 'Explorer data is not available yet.',
    paused: 'The network is paused. Showing the last recorded blocks.',
    refreshFailed: 'Explorer data could not be refreshed. Showing the last recorded blocks.',
    searchScope: 'Only the recent window is searchable for now.',
    linkScope: 'A link opens a block or transaction only while it is in the recent window.',
    leftWindow: 'This item has left the recent window. Its details stay here until you close them; its link no longer opens it.',
    chartHint: 'Oldest block on the left, newest on the right. Select a column to read one block.',
    chartEmpty: 'No blocks to draw yet.',
    searchEmpty: 'There is nothing to search until explorer data is available.',
    searchHint: 'Enter a slot number, or at least 4 characters from the start of a blockhash or signature. Blockhashes and signatures are case-sensitive.',
    paymentsUnmarked: 'The feed does not mark which transactions are shielded payments.',
    paymentExecuted: 'This transaction executed a shielded payment. The feed does not say whether it was a deposit, a private send or a withdrawal, and it carries no amount.',
    paymentFailed: 'This transaction carried the instruction that executes a shielded payment and failed. No payment was executed.',
    paymentStaging: 'A staging step: this transaction initialized, wrote, sealed or closed an account that holds the bytes of a payment before it is executed. It executed no payment.',
    paymentOther: 'This transaction carried an instruction of the payment program that the feed could not name. It executed no payment.',
    paymentNone: 'No instruction of the payment program',
    paymentNotMarked: 'Not marked for this transaction',
    validatorsPaused: 'The network is paused. Showing the validators as last recorded.',
    validatorsRefreshFailed: 'Explorer data could not be refreshed. Showing the validators as last recorded.',
    validatorsWaiting: 'Validator data is not available yet.',
    validatorsNone: 'The feed lists no validators.'
  };

  /* A feed may mark the transactions that invoke the payment program: it names the
     instructions each one carries, in this order, and counts them per block. A feed
     without those fields is read as before, and the page says that it does not mark
     them. The same file also fills a list of validators on a page that carries one
     (data-zolana-validators). */
  const PAYMENT_INSTRUCTIONS = ['initialize', 'write', 'seal', 'finalize', 'close', 'inline', 'unknown'];

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

  /* The mark of a transaction: the names of the payment-program instructions it carries,
     each once, in the feed's order. null when the feed does not say. */
  function readInstructions(raw) {
    if (raw === null || raw === undefined) return null;
    if (!Array.isArray(raw) || raw.length > PAYMENT_INSTRUCTIONS.length) return INVALID;
    let position = -1;
    for (let i = 0; i < raw.length; i += 1) {
      const found = typeof raw[i] === 'string' ? PAYMENT_INSTRUCTIONS.indexOf(raw[i]) : -1;
      if (found <= position) return INVALID;
      position = found;
    }
    return raw.slice();
  }

  /* The two payment counts of a block are null together when the feed does not mark the
     block. A row whose counts cannot be true (one without the other, or more than the
     block holds) is skipped like any other malformed row. */
  function readBlock(raw) {
    if (!isObject(raw)) return null;
    const parentSlot = optional(raw.parent_slot, isNatural);
    const blockTime = optional(raw.block_time, isTime);
    const blockHeight = optional(raw.block_height, isNatural);
    const paymentCount = optional(raw.payment_tx_count, isNatural);
    const executedCount = optional(raw.executed_payment_count, isNatural);
    if (!isNatural(raw.slot) || !isId(raw.blockhash) || !isNatural(raw.tx_count) ||
        !isNatural(raw.non_vote_tx_count) || parentSlot === INVALID || blockTime === INVALID ||
        blockHeight === INVALID || paymentCount === INVALID || executedCount === INVALID ||
        (paymentCount === null) !== (executedCount === null) ||
        (paymentCount !== null && (executedCount > paymentCount || paymentCount > raw.tx_count))) {
      return null;
    }
    return {
      slot: raw.slot,
      parent_slot: parentSlot,
      blockhash: raw.blockhash,
      block_time: blockTime,
      block_height: blockHeight,
      tx_count: raw.tx_count,
      non_vote_tx_count: raw.non_vote_tx_count,
      payment_tx_count: paymentCount,
      executed_payment_count: executedCount
    };
  }

  function readTransaction(raw) {
    if (!isObject(raw)) return null;
    const blockTime = optional(raw.block_time, isTime);
    const instructions = readInstructions(raw.payment_instructions);
    if (!isId(raw.signature) || !isNatural(raw.slot) || blockTime === INVALID ||
        typeof raw.ok !== 'boolean' || !isNatural(raw.fee) ||
        (raw.kind !== 'vote' && raw.kind !== 'program') || instructions === INVALID) {
      return null;
    }
    return {
      signature: raw.signature,
      slot: raw.slot,
      block_time: blockTime,
      ok: raw.ok,
      fee: raw.fee,
      kind: raw.kind,
      payment_instructions: instructions
    };
  }

  function readValidator(raw) {
    if (!isObject(raw)) return null;
    const voteAccount = optional(raw.vote_account, isId);
    const lastVote = optional(raw.last_vote, isNatural);
    const rootSlot = optional(raw.root_slot, isNatural);
    if (!isId(raw.identity) || typeof raw.active !== 'boolean' || voteAccount === INVALID ||
        lastVote === INVALID || rootSlot === INVALID) {
      return null;
    }
    return { identity: raw.identity, vote_account: voteAccount, last_vote: lastVote, root_slot: rootSlot,
      active: raw.active };
  }

  /* The payment counters are all present or all absent; they count from payments_since. */
  function readStats(raw) {
    if (!isObject(raw) || !isTime(raw.since) || !isNatural(raw.blocks_seen) ||
        !isNatural(raw.transactions_seen) || !isNatural(raw.non_vote_transactions_seen)) {
      return null;
    }
    const marked = [raw.payments_since, raw.payment_transactions_seen, raw.executed_payments_seen]
      .some(function (value) { return value !== undefined && value !== null; });
    if (marked && (!isTime(raw.payments_since) || !isNatural(raw.payment_transactions_seen) ||
        !isNatural(raw.executed_payments_seen) || raw.executed_payments_seen > raw.payment_transactions_seen)) {
      return null;
    }
    return {
      since: raw.since,
      blocks_seen: raw.blocks_seen,
      transactions_seen: raw.transactions_seen,
      non_vote_transactions_seen: raw.non_vote_transactions_seen,
      payments_since: marked ? raw.payments_since : null,
      payment_transactions_seen: marked ? raw.payment_transactions_seen : null,
      executed_payments_seen: marked ? raw.executed_payments_seen : null
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

  /* ---------- payment-program transactions ---------- */

  /* What the mark of a transaction says:
     'not_marked'  the feed does not say;
     'none'        no instruction of the payment program;
     'executed'    it succeeded and carries finalize or inline, the two that execute a payment;
     'failed'      it carries one of those two and failed, so no payment was executed;
     'staging'     it only initialized, wrote, sealed or closed a staging account;
     'other'       it carries only an instruction the feed could not name. */
  function paymentStep(transaction) {
    const names = transaction ? transaction.payment_instructions : null;
    if (!Array.isArray(names)) return 'not_marked';
    if (names.length === 0) return 'none';
    if (names.indexOf('finalize') !== -1 || names.indexOf('inline') !== -1) return transaction.ok ? 'executed' : 'failed';
    return names.length === 1 && names[0] === 'unknown' ? 'other' : 'staging';
  }

  function isPaymentTransaction(transaction) {
    const step = paymentStep(transaction);
    return step !== 'not_marked' && step !== 'none';
  }

  /* The kind shown for a transaction. A failed payment keeps the name: the result column
     says that it failed. */
  function transactionLabel(transaction) {
    const step = paymentStep(transaction);
    if (step === 'executed' || step === 'failed') return 'Shielded payment';
    if (step === 'staging') return 'Payment staging';
    if (step === 'other') return 'Payment program';
    return kindLabel(transaction.kind);
  }

  /* One sentence for the detail panel, or null when there is nothing to say. */
  function describePayment(transaction) {
    const step = paymentStep(transaction);
    if (step === 'executed') return TEXT.paymentExecuted;
    if (step === 'failed') return TEXT.paymentFailed;
    if (step === 'staging') return TEXT.paymentStaging;
    if (step === 'other') return TEXT.paymentOther;
    return null;
  }

  function feedMarksPayments(feed) {
    if (!feed) return false;
    return feed.blocks.some(function (block) { return typeof block.payment_tx_count === 'number'; }) ||
      feed.transactions.some(function (transaction) { return Array.isArray(transaction.payment_instructions); });
  }

  function filterTransactions(feed, filter) {
    const transactions = feed ? feed.transactions : [];
    return filter === 'payments' ? transactions.filter(isPaymentTransaction) : transactions;
  }

  /* What the "Shielded payments" figure of the recent window counts. */
  function paymentsBasis(stats) {
    if (!stats || stats.blocks === 0 || stats.marked_blocks === 0) return 'Not marked in this feed';
    const from = ', from ' + formatInteger(stats.payment_transactions) +
      (stats.payment_transactions === 1 ? ' payment-program transaction' : ' payment-program transactions');
    if (stats.marked_blocks === stats.blocks) return 'Executed in this window\u2019s blocks' + from;
    return 'Executed in the ' + formatInteger(stats.marked_blocks) + ' of ' + formatInteger(stats.blocks) +
      ' blocks this feed marks' + from;
  }

  /* Says when the feed marks no block of the window, or only some. Empty otherwise. */
  function paymentsNote(stats) {
    if (!stats || stats.blocks === 0 || stats.marked_blocks === stats.blocks) return '';
    if (stats.marked_blocks === 0) return TEXT.paymentsUnmarked;
    return 'The feed marks payment-program transactions in ' + formatInteger(stats.marked_blocks) + ' of the ' +
      formatInteger(stats.blocks) + ' blocks in this window.';
  }

  /* ---------- validators ---------- */

  /* One row per validator the feed lists, in the feed's order. `behind` is how many slots
     the validator's last vote is behind the tip slot of the same feed, never below zero;
     null when either is not reported. `root_behind` is the same for its root slot. */
  function validatorRows(feed) {
    if (!feed) return [];
    const tip = feed.network.tip_slot;
    const behind = function (slot) {
      return tip === null || slot === null || slot === undefined ? null : Math.max(0, tip - slot);
    };
    return feed.network.validators.map(function (validator) {
      const root = validator.root_slot === undefined ? null : validator.root_slot;
      return { identity: validator.identity, vote_account: validator.vote_account, last_vote: validator.last_vote,
        behind: behind(validator.last_vote), root_slot: root, root_behind: behind(root), active: validator.active };
    });
  }

  function slotsBehind(behind) {
    if (behind === null) return null;
    if (behind === 0) return 'At the tip';
    return formatInteger(behind) + (behind === 1 ? ' slot behind' : ' slots behind');
  }

  /* While the feed is live the list says who is voting; otherwise only what was recorded. */
  function votingLabel(active, live) {
    if (live) return active ? 'Voting' : 'Not voting';
    return active ? 'Voting when last recorded' : 'Not voting when last recorded';
  }

  function validatorsSummary(feed, live) {
    const total = feed ? feed.network.validators.length : 0;
    if (total === 0) return TEXT.validatorsNone;
    const count = formatInteger(countActiveValidators(feed)) + ' of ' + formatInteger(total);
    const noun = total === 1 ? ' validator in the feed' : ' validators in the feed';
    return live ? count + noun + (total === 1 ? ' is voting' : ' are voting') :
      'Last recorded: ' + count + noun + (total === 1 ? ' was voting' : ' were voting');
  }

  /* The notice of a page that lists validators: the same states, worded for that list. */
  function validatorsNotice(description) {
    if (description.message === TEXT.paused) return TEXT.validatorsPaused;
    if (description.message === TEXT.refreshFailed) return TEXT.validatorsRefreshFailed;
    if (description.message === TEXT.unavailable) return TEXT.validatorsWaiting;
    return description.message;
  }

  /* ---------- recent window ---------- */

  /* Figures for the blocks held in the feed, oldest first in `series`. A block's gap is
     the number of slots since its parent; a gap above 1 means skipped slots. The block
     time is the feed's average slot time multiplied by the mean gap: block times are not
     measured per block, and the chain's own clock has a resolution of one second. */
  function windowStats(feed) {
    const stats = {
      blocks: 0, newest_slot: null, oldest_slot: null, transactions: 0, non_vote_transactions: 0,
      slots_per_block: null, skipped_slots: 0, unlinked_blocks: 0, max_gap: 0, max_transactions: 0,
      block_time_ms: null, blocks_per_minute: null, payment_transactions: 0, executed_payments: 0,
      marked_blocks: 0, max_payment_transactions: 0, series: []
    };
    const blocks = feed && Array.isArray(feed.blocks) ? feed.blocks : [];
    if (blocks.length === 0) return stats;
    let gapSum = 0;
    let gapCount = 0;
    for (let i = blocks.length - 1; i >= 0; i -= 1) {
      const block = blocks[i];
      const older = i + 1 < blocks.length ? blocks[i + 1] : null;
      const gap = block.parent_slot !== null && block.parent_slot < block.slot ? block.slot - block.parent_slot : null;
      const nonVote = Math.min(block.non_vote_tx_count, block.tx_count);
      /* Payment counts are sums over the blocks the feed marks; an unmarked block adds nothing. */
      const marked = typeof block.payment_tx_count === 'number' && typeof block.executed_payment_count === 'number';
      const payment = marked ? Math.min(block.payment_tx_count, block.tx_count) : null;
      const executed = marked ? Math.min(block.executed_payment_count, payment) : null;
      if (marked) {
        stats.marked_blocks += 1;
        stats.payment_transactions += payment;
        stats.executed_payments += executed;
        if (payment > stats.max_payment_transactions) stats.max_payment_transactions = payment;
      }
      if (gap !== null) {
        gapSum += gap;
        gapCount += 1;
        if (gap > stats.max_gap) stats.max_gap = gap;
      }
      if (older && block.parent_slot !== null) {
        if (block.parent_slot !== older.slot) stats.unlinked_blocks += 1;
        if (gap !== null && block.parent_slot >= older.slot) stats.skipped_slots += gap - 1;
      }
      stats.transactions += block.tx_count;
      stats.non_vote_transactions += nonVote;
      if (block.tx_count > stats.max_transactions) stats.max_transactions = block.tx_count;
      stats.series.push({ slot: block.slot, gap: gap, transactions: block.tx_count, non_vote: nonVote,
        payment: payment, executed: executed, block: block });
    }
    stats.blocks = blocks.length;
    stats.newest_slot = blocks[0].slot;
    stats.oldest_slot = blocks[blocks.length - 1].slot;
    if (gapCount > 0) stats.slots_per_block = gapSum / gapCount;
    const slotTime = feed.network ? feed.network.slot_time_ms : null;
    if (stats.slots_per_block !== null && typeof slotTime === 'number' && isFinite(slotTime) && slotTime > 0) {
      stats.block_time_ms = Math.round(slotTime * stats.slots_per_block * 10) / 10;
      stats.blocks_per_minute = 60000 / (slotTime * stats.slots_per_block);
    }
    return stats;
  }

  /* One entry per slot for the newest `count` slots of the window, oldest first:
     'block' when the feed holds a block for the slot, 'skipped' when a later block names
     an earlier slot as its parent, and 'unknown' when the feed does not say. */
  function slotStrip(feed, count) {
    const size = isNatural(count) && count > 0 ? Math.min(count, 1000) : STRIP_SLOTS;
    const strip = { ticks: [], first_slot: null, last_slot: null, blocks: 0, skipped: 0, unknown: 0 };
    const blocks = feed && Array.isArray(feed.blocks) ? feed.blocks : [];
    if (blocks.length === 0) return strip;
    const last = blocks[0].slot;
    const first = Math.max(blocks[blocks.length - 1].slot, last - size + 1);
    const states = [];
    for (let slot = first; slot <= last; slot += 1) states.push('unknown');
    blocks.forEach(function (block) {
      if (block.slot >= first && block.slot <= last) states[block.slot - first] = 'block';
    });
    blocks.forEach(function (block) {
      if (block.slot < first || block.slot > last || block.parent_slot === null) return;
      for (let slot = Math.max(block.parent_slot + 1, first); slot < block.slot; slot += 1) {
        if (states[slot - first] === 'unknown') states[slot - first] = 'skipped';
      }
    });
    states.forEach(function (state, index) {
      strip.ticks.push({ slot: first + index, state: state });
      if (state === 'block') strip.blocks += 1;
      else if (state === 'skipped') strip.skipped += 1;
      else strip.unknown += 1;
    });
    strip.first_slot = first;
    strip.last_slot = last;
    return strip;
  }

  function stripSummary(strip) {
    if (!strip || strip.ticks.length === 0) return null;
    const total = strip.ticks.length;
    let text = formatInteger(strip.blocks) + ' of the last ' + formatInteger(total) + (total === 1 ? ' slot has' : ' slots have') + ' a block';
    if (strip.skipped > 0) text += '; ' + formatInteger(strip.skipped) + (strip.skipped === 1 ? ' was' : ' were') + ' skipped';
    if (strip.unknown > 0) text += '; ' + formatInteger(strip.unknown) + (strip.unknown === 1 ? ' is' : ' are') + ' not in the explorer data';
    return text + '. Slots ' + formatInteger(strip.first_slot) + ' to ' + formatInteger(strip.last_slot) + '.';
  }

  /* Says why a slot number has no block in the feed that is held. */
  function describeSlotMiss(feed, slot) {
    const blocks = feed && Array.isArray(feed.blocks) ? feed.blocks : [];
    const name = 'Slot ' + formatInteger(slot);
    if (blocks.length === 0) return { reason: 'no_blocks', message: 'No blocks have been recorded yet.' };
    const newest = blocks[0].slot;
    const oldest = blocks[blocks.length - 1].slot;
    if (slot > newest) {
      return { reason: 'ahead', message: name + ' is ahead of the newest block in the recent window (slot ' +
        formatInteger(newest) + ').' };
    }
    if (slot < oldest) {
      return { reason: 'older', message: name + ' is older than the recent window, which starts at slot ' +
        formatInteger(oldest) + '.' };
    }
    let next = null;
    for (let i = 0; i < blocks.length; i += 1) {
      if (blocks[i].slot > slot) next = blocks[i]; else break;
    }
    if (next && next.parent_slot !== null && next.parent_slot < slot) {
      return { reason: 'skipped', message: name + ' has no block: the slot was skipped.' };
    }
    return { reason: 'not_in_feed', message: name + ' is inside the recent window, but its block is not in the explorer data.' };
  }

  /* ---------- links to one block or transaction ---------- */

  /* '#block=<slot>' or '#tx=<signature>'. Anything else is not a link to an item. */
  function parseDeepLink(hash) {
    if (typeof hash !== 'string' || hash.length > MAX_ID_CHARS + 8) return null;
    const text = hash.charAt(0) === '#' ? hash.slice(1) : hash;
    const split = text.indexOf('=');
    if (split === -1) return null;
    const name = text.slice(0, split);
    const value = text.slice(split + 1);
    if (name === 'block' && value.length <= 16 && DIGITS.test(value) && Number.isSafeInteger(Number(value))) {
      return { type: 'block', slot: Number(value) };
    }
    if (name === 'tx' && isId(value)) return { type: 'transaction', signature: value };
    return null;
  }

  function formatDeepLink(match) {
    if (!match || !match.item) return '';
    if (match.type === 'block' && isNatural(match.item.slot)) return '#block=' + String(match.item.slot);
    if (match.type === 'transaction' && isId(match.item.signature)) return '#tx=' + match.item.signature;
    return '';
  }

  function resolveDeepLink(feed, link) {
    if (!link) return { status: 'none', match: null, message: '' };
    if (!feed) return { status: 'nodata', match: null, message: '' };
    if (link.type === 'block') {
      for (let i = 0; i < feed.blocks.length; i += 1) {
        if (feed.blocks[i].slot === link.slot) {
          return { status: 'found', match: { type: 'block', item: feed.blocks[i] }, message: '' };
        }
      }
      return { status: 'outside', match: null, message: describeSlotMiss(feed, link.slot).message + ' ' + TEXT.linkScope };
    }
    for (let i = 0; i < feed.transactions.length; i += 1) {
      if (feed.transactions[i].signature === link.signature) {
        return { status: 'found', match: { type: 'transaction', item: feed.transactions[i] }, message: '' };
      }
    }
    return { status: 'outside', match: null, message: 'Transaction ' + shortHash(link.signature) +
      ' is not in the recent window. ' + TEXT.linkScope };
  }

  function inWindow(feed, match) {
    return resolveDeepLink(feed, parseDeepLink(formatDeepLink(match))).status === 'found';
  }

  /* The whole number shown while a counter moves from one feed value to the next. It
     never passes the newer value. */
  function tweenValue(from, to, progress) {
    if (!(progress > 0)) return from;
    if (progress >= 1 || to <= from) return to;
    return from + Math.floor((to - from) * progress);
  }

  function validatorsVoting(feed) {
    const total = feed ? feed.network.validators.length : 0;
    return total === 0 ? null : formatInteger(countActiveValidators(feed)) + ' of ' + formatInteger(total);
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
    if (isSlotQuery) {
      const miss = describeSlotMiss(feed, Number(digits));
      const missed = searchResult('not_found', [], miss.message + ' ' + TEXT.searchScope);
      missed.reason = miss.reason;
      return missed;
    }
    if (isHashQuery) {
      const unmatched = searchResult('not_found', [], 'No block or transaction in the recent window starts with \u201c' +
        shortHash(query, 12, 6) + '\u201d. It may be older than the window. ' + TEXT.searchScope);
      unmatched.reason = 'no_match';
      return unmatched;
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
    STRIP_SLOTS: STRIP_SLOTS,
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
    PAYMENT_INSTRUCTIONS: PAYMENT_INSTRUCTIONS,
    paymentStep: paymentStep,
    isPaymentTransaction: isPaymentTransaction,
    transactionLabel: transactionLabel,
    describePayment: describePayment,
    feedMarksPayments: feedMarksPayments,
    filterTransactions: filterTransactions,
    paymentsBasis: paymentsBasis,
    paymentsNote: paymentsNote,
    validatorRows: validatorRows,
    slotsBehind: slotsBehind,
    votingLabel: votingLabel,
    validatorsSummary: validatorsSummary,
    validatorsNotice: validatorsNotice,
    searchFeed: searchFeed,
    windowStats: windowStats,
    slotStrip: slotStrip,
    stripSummary: stripSummary,
    describeSlotMiss: describeSlotMiss,
    parseDeepLink: parseDeepLink,
    formatDeepLink: formatDeepLink,
    resolveDeepLink: resolveDeepLink,
    inWindow: inWindow,
    tweenValue: tweenValue,
    validatorsVoting: validatorsVoting
  };

  if (typeof module === 'object' && module !== null && typeof module.exports === 'object') {
    module.exports = api;
  }

  /* ---------- page ---------- */

  function start(doc, win) {
    const app = doc.querySelector('[data-explorer-app]');
    const statusRoots = Array.prototype.slice.call(doc.querySelectorAll('[data-zolana-status]'));
    const validatorRoots = Array.prototype.slice.call(doc.querySelectorAll('[data-zolana-validators]'));
    const noticeNodes = Array.prototype.slice.call(doc.querySelectorAll('[data-zolana-notice]'));
    if (!app && statusRoots.length === 0 && validatorRoots.length === 0 && noticeNodes.length === 0) return;

    const state = {
      feed: null,
      lastFetchOk: null,
      clockOffsetMs: 0,
      blockLimit: PAGE_ROWS,
      transactionLimit: PAGE_ROWS,
      detailOpener: null,
      detail: null,
      stats: windowStats(null),
      strip: slotStrip(null, STRIP_SLOTS),
      link: parseDeepLink(win.location.hash),
      chartIndex: -1,
      paymentFilter: 'all'
    };
    const reducedMotion = typeof win.matchMedia === 'function' ? win.matchMedia('(prefers-reduced-motion: reduce)') : null;
    const tweens = [];
    let tweenFrame = 0;
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

    /* Motion is skipped when the device asks for less of it, or when the home page's own
       "Reduce motion" control is on. */
    function motionAllowed() {
      return !(reducedMotion && reducedMotion.matches) && !(doc.body && doc.body.classList.contains('motion-reduced')) &&
        typeof win.requestAnimationFrame === 'function';
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
        return { node: node, fallback: node.textContent, name: node.getAttribute('data-zolana-field'), from: null, to: null,
          shown: null, started: 0, duration: TWEEN_MS };
      });
    }

    const statusViews = statusRoots.map(function (root) {
      return {
        root: root,
        inApp: Boolean(app) && app.contains(root),
        liveLine: root.hasAttribute('data-zolana-live-line'),
        dots: Array.prototype.slice.call(root.querySelectorAll('[data-zolana-status-dot]')),
        labels: withFallback(root.querySelectorAll('[data-zolana-status-text]')),
        fields: withFallback(root.querySelectorAll('[data-zolana-field]'))
      };
    });

    const COUNTERS = { tip_slot: true, finalized_slot: true, block_height: true };

    /* Measured values are shown only while the network is live. Counts taken from the
       recorded window stay on the page while it is paused. */
    function fieldText(name, feed, seconds, live) {
      const network = feed.network;
      const stats = state.stats;
      if (name === 'validators_voting') return live ? validatorsVoting(feed) : null;
      if (name === 'block_time') return live && stats.block_time_ms !== null ? formatSlotTime(stats.block_time_ms) : null;
      if (name === 'blocks_per_minute') {
        return live && stats.blocks_per_minute !== null ? formatInteger(Math.round(stats.blocks_per_minute)) : null;
      }
      if (name === 'window_transactions') return stats.blocks === 0 ? null : formatInteger(stats.transactions);
      if (name === 'window_non_vote') return stats.blocks === 0 ? null : formatInteger(stats.non_vote_transactions);
      if (name === 'window_skipped') return stats.blocks === 0 ? null : formatInteger(stats.skipped_slots);
      if (name === 'window_payments') return stats.marked_blocks === 0 ? null : formatInteger(stats.executed_payments);
      if (name === 'window_payments_basis') return paymentsBasis(stats);
      if (name === 'validators_summary') return validatorsSummary(feed, live);
      if (name === 'window_summary') {
        if (stats.blocks === 0) return 'No blocks recorded';
        return formatInteger(stats.blocks) + (stats.blocks === 1 ? ' block, slot ' + formatInteger(stats.newest_slot) :
          ' blocks, slots ' + formatInteger(stats.oldest_slot) + ' to ' + formatInteger(stats.newest_slot));
      }
      if (name === 'pulse_summary') {
        const summary = stripSummary(state.strip);
        if (summary === null) return 'No blocks recorded';
        return live ? summary : 'Last recorded: ' + summary.charAt(0).toLowerCase() + summary.slice(1);
      }
      if (name === 'last_block_age') {
        return network.last_block_at === null ? null : formatAge(Math.max(0, seconds - network.last_block_at));
      }
      if (name === 'tip_slot') return network.tip_slot === null ? null : formatInteger(network.tip_slot);
      if (name === 'finalized_slot') return network.finalized_slot === null ? null : formatInteger(network.finalized_slot);
      if (name === 'block_height') return network.block_height === null ? null : formatInteger(network.block_height);
      if (name === 'slot_time') return network.slot_time_ms === null ? null : formatSlotTime(network.slot_time_ms);
      if (name === 'validators') return formatInteger(countActiveValidators(feed));
      if (name === 'updated') return 'Updated ' + formatAge(seconds - feed.generated_at) + ' ago';
      if (name === 'updated_utc') return formatUtc(feed.generated_at);
      return null;
    }

    function settle(entry, value) {
      entry.from = entry.to = entry.shown = value;
    }

    function stepTweens() {
      const now = monotonicMs();
      let running = false;
      tweenFrame = 0;
      tweens.forEach(function (entry) {
        if (entry.shown === null || entry.shown === entry.to) return;
        const value = motionAllowed() ? tweenValue(entry.from, entry.to, (now - entry.started) / entry.duration) : entry.to;
        if (value !== entry.shown) {
          entry.shown = value;
          setText(entry.node, formatInteger(value));
        }
        if (value !== entry.to) running = true;
      });
      if (running) tweenFrame = win.requestAnimationFrame(stepTweens);
    }

    /* A slot or height counts up from the value of the previous feed to the value of the
       newest one, so the figure on the page is always one the feed has reported or passed.
       Beside the tables it catches up quickly; the single line on the home page takes
       the time between two feeds. */
    function showCounter(entry, value, live) {
      entry.node.setAttribute('data-value', formatInteger(value));
      if (tweens.indexOf(entry) === -1) tweens.push(entry);
      if (!live || !motionAllowed() || entry.shown === null || value < entry.to || value - entry.shown > MAX_TWEEN_SPAN) {
        settle(entry, value);
        entry.node.removeAttribute('data-missing');
        setText(entry.node, formatInteger(value));
        return;
      }
      if (value === entry.to) return;
      entry.from = entry.shown;
      entry.to = value;
      entry.started = monotonicMs();
      if (!tweenFrame) tweenFrame = win.requestAnimationFrame(stepTweens);
    }

    function renderStatus(view, description, seconds) {
      const feed = state.feed;
      const live = description.state === 'live';
      const hidden = view.liveLine && (!feed || feed.network.block_height === null);
      const duration = view.liveLine ? TICKER_MS : TWEEN_MS;
      view.root.setAttribute('data-state', hidden ? 'nodata' : description.state);
      view.dots.forEach(function (dot) {
        dot.classList.toggle('running', live);
        dot.classList.toggle('unknown', !live);
      });
      view.labels.forEach(function (entry) {
        setText(entry.node, feed || view.inApp ? description.label : entry.fallback);
        if (entry.node.classList.contains('badge')) entry.node.classList.toggle('verified', live);
      });
      view.fields.forEach(function (entry) {
        const counter = feed && COUNTERS[entry.name] === true ? feed.network[entry.name] : null;
        if (!feed) {
          entry.shown = null;
          entry.node.removeAttribute('data-missing');
          entry.node.removeAttribute('data-value');
          setText(entry.node, entry.fallback);
        } else if (counter !== null) {
          entry.duration = duration;
          showCounter(entry, counter, live);
        } else {
          entry.shown = null;
          setValue(entry.node, fieldText(entry.name, feed, seconds, live));
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
      if (view.empty) view.emptyText = view.empty.textContent;
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
      charts: byId('window-charts'),
      intervalChart: byId('chart-interval'),
      intervalNote: byId('chart-interval-note'),
      transactionChart: byId('chart-transactions'),
      transactionTitle: byId('chart-transactions-title'),
      transactionNote: byId('chart-transactions-note'),
      readout: byId('window-readout'),
      paymentsNote: byId('payments-note'),
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

    /* `value` is the text to copy, or a function that returns it when the button is used. */
    function copyButton(value, name, label) {
      const idle = label || 'Copy';
      const button = el('button', 'copy-button', idle);
      let timer = 0;
      button.type = 'button';
      button.setAttribute('aria-label', 'Copy ' + name);
      button.addEventListener('click', function () {
        copyText(typeof value === 'function' ? value() : value).then(function (copied) {
          button.textContent = copied ? 'Copied' : 'Copy failed';
          button.focus();
          announce(copied ? 'Copied ' + name + '.' : 'Could not copy ' + name + '. Select the text to copy it.');
          win.clearTimeout(timer);
          timer = win.setTimeout(function () { button.textContent = idle; }, COPY_FEEDBACK_MS);
        });
      });
      return button;
    }

    /* Drawn elements take their namespace from a drawing that is already on the page. */
    const drawingSpace = pageReady ? page.intervalChart.namespaceURI : null;

    function shape(name, attributes) {
      const node = doc.createElementNS(drawingSpace, name);
      Object.keys(attributes).forEach(function (key) { node.setAttribute(key, String(attributes[key])); });
      return node;
    }

    /* A small copy control beside a shortened hash in a table row. It is left out of the
       tab order: the same value has a labelled Copy button in the detail panel. */
    function rowCopy(value, name) {
      const button = el('button', 'copy-icon');
      const icon = shape('svg', { viewBox: '0 0 16 16', 'aria-hidden': 'true', focusable: 'false' });
      let timer = 0;
      icon.appendChild(shape('rect', { class: 'icon-copy', x: 5.5, y: 5.5, width: 8, height: 8, rx: 1 }));
      icon.appendChild(shape('path', { class: 'icon-copy', d: 'M10.5 3.5V3a.5.5 0 0 0-.5-.5H3a.5.5 0 0 0-.5.5v7a.5.5 0 0 0 .5.5h.5' }));
      icon.appendChild(shape('path', { class: 'icon-done', d: 'M3 8.5l3.2 3.2L13 4.8' }));
      button.type = 'button';
      button.tabIndex = -1;
      button.title = 'Copy ' + name;
      button.setAttribute('aria-label', 'Copy ' + name);
      button.appendChild(icon);
      button.addEventListener('click', function () {
        copyText(value).then(function (copied) {
          button.classList.toggle('copied', copied);
          announce(copied ? 'Copied ' + name + '.' : 'Could not copy ' + name + '. Open the details to select it.');
          win.clearTimeout(timer);
          timer = win.setTimeout(function () { button.classList.remove('copied'); }, COPY_FEEDBACK_MS);
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

    /* The address of the page names the open item, so a reload or a shared link opens it
       again for as long as it is in the recent window. */
    function setLink(hash) {
      try {
        if (win.location.hash === hash) return;
        win.history.replaceState(null, '', hash === '' ? win.location.pathname + win.location.search : hash);
      } catch (error) {
        /* The address stays as it was; the panel still works. */
      }
    }

    function hideDetail() {
      page.detail.hidden = true;
      page.detail.textContent = '';
      state.detail = null;
      state.link = null;
      setLink('');
    }

    function closeDetail() {
      const opener = state.detailOpener;
      hideDetail();
      state.detailOpener = null;
      if (opener && doc.contains(opener)) opener.focus(); else page.input.focus();
    }

    function neighbour(block, step) {
      const blocks = state.feed ? state.feed.blocks : [];
      for (let i = 0; i < blocks.length; i += 1) {
        if (blocks[i].slot === block.slot) return blocks[i - step] || null;
      }
      return null;
    }

    function finalizedText(block) {
      const finalized = state.feed ? state.feed.network.finalized_slot : null;
      if (finalized === null) return null;
      return block.slot <= finalized ? 'Yes' : 'Not yet';
    }

    /* Runs after every feed: the open panel keeps its values, and only what the newer
       feed changes is updated. */
    function refreshDetail() {
      const detail = state.detail;
      if (!detail) return;
      const held = inWindow(state.feed, detail.match);
      detail.note.hidden = held;
      if (detail.match.type !== 'block') return;
      if (held) {
        const text = finalizedText(detail.match.item);
        if (text === null) setMissing(detail.finalized, 'Not reported'); else setValue(detail.finalized, text);
      }
      detail.older.disabled = !neighbour(detail.match.item, -1);
      detail.newer.disabled = !neighbour(detail.match.item, 1);
    }

    function stepButton(text, label, block, step) {
      return linkButton(text, 'back-button step-button', label, function () {
        const target = neighbour(block, step);
        if (target) openDetail({ type: 'block', item: target }, state.detailOpener, step === 1 ? 'newer' : 'older');
      });
    }

    /* `keep` names the step button that was used, so that stepping through blocks from
       the keyboard does not lose its place. */
    function openDetail(match, opener, keep) {
      const panel = page.detail;
      const item = match.item;
      const isBlock = match.type === 'block';
      const heading = el('div', 'detail-heading');
      const title = el('h2', 'subheading', isBlock ? 'Block ' + formatInteger(item.slot) : 'Transaction');
      const actions = el('div', 'detail-actions');
      const close = linkButton('Close', 'back-button', 'Close details', closeDetail);
      const note = el('p', 'detail-note', TEXT.leftWindow);
      const list = el('dl', 'detail-grid');
      const detail = { match: match, note: note, finalized: null, older: null, newer: null };
      state.detailOpener = opener || state.detailOpener;
      title.id = 'explorer-detail-title';
      title.tabIndex = -1;
      note.hidden = true;
      heading.appendChild(title);
      if (isBlock) {
        detail.older = stepButton('Older', 'Open the block before this one', item, -1);
        detail.newer = stepButton('Newer', 'Open the block after this one', item, 1);
        actions.appendChild(detail.older);
        actions.appendChild(detail.newer);
      }
      actions.appendChild(copyButton(function () { return win.location.href; }, 'link to this ' + (isBlock ? 'block' : 'transaction'), 'Copy link'));
      actions.appendChild(close);
      heading.appendChild(actions);
      if (isBlock) {
        const skipped = item.parent_slot !== null && item.parent_slot < item.slot ? item.slot - item.parent_slot - 1 : null;
        detail.finalized = el('span');
        detailRow(list, 'Slot', textValue(String(item.slot)), String(item.slot), 'slot');
        detailRow(list, 'Blockhash', textValue(item.blockhash, 'identifier'), item.blockhash, 'blockhash');
        detailRow(list, 'Parent slot', slotValue(item.parent_slot, state.detailOpener));
        detailRow(list, 'Block time', optionalValue(item.block_time, formatUtc));
        detailRow(list, 'Block height', optionalValue(item.block_height, formatInteger));
        detailRow(list, 'Transactions', textValue(formatInteger(item.tx_count)));
        detailRow(list, 'Non-vote transactions', textValue(formatInteger(item.non_vote_tx_count)));
        if (item.payment_tx_count !== null) {
          detailRow(list, 'Payment-program transactions', textValue(formatInteger(item.payment_tx_count)));
          detailRow(list, 'Shielded payments executed', textValue(formatInteger(item.executed_payment_count)));
        }
        detailRow(list, 'Skipped slots before this block', optionalValue(skipped, formatInteger));
        detailRow(list, 'Finalized', detail.finalized);
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
        detailRow(list, 'Fee', textValue(formatZol(item.fee) + ' test coins (' + formatInteger(item.fee) + ' lamports)'));
        detailRow(list, 'Kind', textValue(transactionLabel(item)));
        if (feedMarksPayments(state.feed) || Array.isArray(item.payment_instructions)) {
          const step = paymentStep(item);
          const sentence = describePayment(item);
          detailRow(list, 'Payment program', textValue(step === 'not_marked' ? TEXT.paymentNotMarked :
            step === 'none' ? TEXT.paymentNone : 'Instructions: ' + item.payment_instructions.join(', ')));
          if (sentence !== null) detailRow(list, 'What the feed shows', textValue(sentence));
        }
        if (!findBlock(item.slot)) detailRow(list, 'Block', textValue('Not among the blocks in the recent window'));
      }
      panel.textContent = '';
      panel.appendChild(heading);
      panel.appendChild(note);
      panel.appendChild(list);
      panel.hidden = false;
      state.detail = detail;
      state.link = null;
      setLink(formatDeepLink(match));
      refreshDetail();
      panel.scrollIntoView({ block: 'nearest' });
      if (keep && detail[keep] && !detail[keep].disabled) detail[keep].focus({ preventScroll: true });
      else title.focus({ preventScroll: true });
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
      const hashCell = wrapCell(hash);
      hashCell.className = 'with-copy';
      hashCell.appendChild(rowCopy(block.blockhash, 'blockhash of block ' + slot));
      row.appendChild(hashCell);
      row.appendChild(age.cell);
      row.appendChild(el('td', '', formatInteger(block.tx_count)));
      row.appendChild(el('td', '', formatInteger(block.non_vote_tx_count)));
      return { row: row, age: age.node, time: block.block_time };
    }

    function buildTransactionRow(transaction) {
      const row = el('tr');
      const age = ageCell(transaction.block_time);
      const short = shortHash(transaction.signature);
      const name = rowHeader(linkButton(short, 'data-link identifier', 'Transaction ' + short + ', show details',
        function (button) { openDetail({ type: 'transaction', item: transaction }, button); }));
      name.className = 'with-copy';
      name.appendChild(rowCopy(transaction.signature, 'signature ' + short));
      row.appendChild(name);
      row.appendChild(el('td', '', formatInteger(transaction.slot)));
      row.appendChild(age.cell);
      row.appendChild(wrapCell(resultBadge(transaction.ok)));
      row.appendChild(el('td', '', formatZol(transaction.fee)));
      /* A transaction of the payment program carries a mark before its kind. */
      const step = paymentStep(transaction);
      const kind = el('td', '', transactionLabel(transaction));
      if (isPaymentTransaction(transaction)) {
        kind.className = 'kind-payment';
        row.setAttribute('data-payment', step);
      }
      row.appendChild(kind);
      return { row: row, age: age.node, time: transaction.block_time };
    }

    function blockKey(block) {
      return [block.slot, block.blockhash, block.parent_slot, block.block_time, block.block_height,
        block.tx_count, block.non_vote_tx_count].join('|');
    }

    function transactionKey(transaction) {
      return [transaction.signature, transaction.slot, transaction.block_time, transaction.ok,
        transaction.fee, transaction.kind, paymentStep(transaction),
        (transaction.payment_instructions || []).join('+')].join('|');
    }

    /* Keeps existing rows in place so that keyboard focus and text selection survive
       a refresh; only new rows are created and only departed rows are removed. Rows that
       arrive with a newer feed fade in, newest first; the first fill and "Show more" do not. */
    function renderList(view, items, limit, keyOf, build, arriving) {
      const body = view.body;
      const shown = Math.min(limit, items.length);
      const wanted = new Set();
      const animate = arriving && view.rows.size > 0 && motionAllowed();
      let fresh = 0;
      for (let i = 0; i < shown; i += 1) {
        const key = keyOf(items[i]);
        let entry = view.rows.get(key);
        if (!entry) {
          entry = build(items[i]);
          view.rows.set(key, entry);
          if (animate) {
            entry.row.classList.add('row-new');
            entry.row.style.animationDelay = Math.min(fresh * ROW_STAGGER_MS, MAX_ROW_DELAY_MS) + 'ms';
            fresh += 1;
          }
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

    /* ----- charts of the recent window ----- */

    function clearNode(node) {
      while (node.firstChild) node.removeChild(node.firstChild);
    }

    function slotCount(gap) {
      return formatInteger(gap) + (gap === 1 ? ' slot' : ' slots');
    }

    function intervalText(gap) {
      const slotTime = state.feed ? state.feed.network.slot_time_ms : null;
      return slotTime === null ? slotCount(gap) : formatSlotTime(gap * slotTime);
    }

    /* Both charts have one column per block and share the same columns, so a block sits
       at the same place in each. The newest block is in the last column. */
    function renderCharts() {
      const stats = state.stats;
      const series = stats.series;
      const offset = CHART_COLUMNS - series.length;
      const top = Math.max(2, stats.max_gap);
      /* With the payment filter on, the columns count payment-program transactions and the
         bright part the payments executed; otherwise all transactions and the non-vote part. */
      const filtered = state.paymentFilter === 'payments';
      const most = filtered ? stats.max_payment_transactions : stats.max_transactions;
      const line = [];
      const kept = state.chartIndex;
      clearNode(page.intervalChart);
      clearNode(page.transactionChart);
      page.transactionChart.appendChild(shape('rect', { class: 'chart-cursor', x: 0, y: 0, width: 1, height: 40 }));
      page.intervalChart.appendChild(shape('rect', { class: 'chart-cursor', x: 0, y: 0, width: 1, height: 40 }));
      page.intervalChart.appendChild(shape('line', { class: 'chart-rule', x1: 0, y1: 38.5, x2: CHART_COLUMNS, y2: 38.5 }));
      function flush() {
        if (line.length === 0) return;
        const first = line[0].split(',')[0];
        const last = line[line.length - 1].split(',')[0];
        page.intervalChart.appendChild(shape('polygon', { class: 'chart-area', points: first + ',38.5 ' + line.join(' ') + ' ' + last + ',38.5' }));
        page.intervalChart.appendChild(shape('polyline', { class: 'chart-line', points: line.join(' ') }));
        line.length = 0;
      }
      series.forEach(function (point, index) {
        const x = offset + index;
        if (point.gap === null) {
          flush();
        } else {
          const y = (38.5 - Math.min(point.gap / top, 1) * 30).toFixed(2);
          line.push(x + ',' + y);
          line.push((x + 1) + ',' + y);
        }
        const total = filtered ? (point.payment === null ? 0 : point.payment) : point.transactions;
        const bright = filtered ? (point.executed === null ? 0 : point.executed) : point.non_vote;
        page.transactionChart.appendChild(shape('rect', { class: 'bar-base', x: x + 0.15, y: 37, width: 0.7, height: 3 }));
        if (total > 0) {
          const height = Math.max(3, total / most * 31);
          page.transactionChart.appendChild(shape('rect', { class: 'bar-total', x: x + 0.15, y: 36 - height, width: 0.7, height: height }));
        }
        if (bright > 0) {
          const part = Math.max(3, bright / most * 31);
          page.transactionChart.appendChild(shape('rect', { class: 'bar-part', x: x + 0.15, y: 36 - part, width: 0.7, height: part }));
        }
        /* A mark above the column of a block that holds payment-program transactions:
           filled when one of them executed a payment, hollow otherwise. */
        if (!filtered && point.payment !== null && point.payment > 0) {
          page.transactionChart.appendChild(shape('rect', { class: point.executed > 0 ? 'bar-mark executed' : 'bar-mark',
            x: x + 0.15, y: 0.5, width: 0.7, height: 2.5 }));
        }
      });
      flush();
      if (series.length === 0 || stats.max_gap === 0) {
        setText(page.intervalNote, '');
      } else if (stats.skipped_slots === 0 && stats.max_gap === 1) {
        setText(page.intervalNote, 'Every block one slot after its parent, ' + intervalText(1));
      } else {
        setText(page.intervalNote, intervalText(1) + ' to ' + intervalText(stats.max_gap));
      }
      setText(page.transactionTitle, filtered ? 'Payment-program transactions per block' : 'Transactions per block');
      if (series.length === 0) setText(page.transactionNote, '');
      else if (most === 0) setText(page.transactionNote, 'None in these blocks');
      else setText(page.transactionNote, 'Most in one block: ' + formatInteger(most));
      showColumn(kept === -1 ? -1 : Math.min(kept, series.length - 1));
    }

    function showColumn(index) {
      const series = state.stats.series;
      const point = index >= 0 && index < series.length ? series[index] : null;
      const x = CHART_COLUMNS - series.length + index;
      state.chartIndex = point ? index : -1;
      [page.intervalChart, page.transactionChart].forEach(function (chart) {
        const cursor = chart.querySelector('.chart-cursor');
        if (!cursor) return;
        cursor.setAttribute('x', String(point ? x : 0));
        cursor.classList.toggle('shown', Boolean(point));
      });
      if (!point) {
        setText(page.readout, series.length === 0 ? TEXT.chartEmpty : TEXT.chartHint);
        return;
      }
      let text = 'Slot ' + formatInteger(point.slot);
      if (point.gap !== null) {
        text += ' \u00b7 ' + slotCount(point.gap) + ' after its parent';
        if (state.feed && state.feed.network.slot_time_ms !== null) text += ', ' + intervalText(point.gap) + ' at the average slot time';
      }
      text += ' \u00b7 ' + formatInteger(point.transactions) + (point.transactions === 1 ? ' transaction' : ' transactions');
      if (point.transactions > 0) text += ', ' + formatInteger(point.non_vote) + ' non-vote';
      if (point.payment !== null) {
        text += ' \u00b7 ' + formatInteger(point.payment) + ' payment-program';
        if (point.payment > 0) {
          text += ', ' + formatInteger(point.executed) + (point.executed === 1 ? ' shielded payment' : ' shielded payments') + ' executed';
        }
      }
      setText(page.readout, text);
    }

    function columnAt(event) {
      const box = page.transactionChart.getBoundingClientRect();
      if (!(box.width > 0)) return -1;
      const column = Math.floor((event.clientX - box.left) / box.width * CHART_COLUMNS);
      const index = column - (CHART_COLUMNS - state.stats.series.length);
      return index >= 0 && index < state.stats.series.length ? index : -1;
    }

    function openColumn(index) {
      const point = state.stats.series[index];
      if (point) openDetail({ type: 'block', item: point.block }, page.charts);
    }

    /* Opens the item named in the address once a feed is held. */
    function followLink() {
      const result = resolveDeepLink(state.feed, state.link);
      if (result.status === 'found') {
        page.searchNote.textContent = '';
        openDetail(result.match, null);
      } else if (result.status === 'outside') {
        state.link = null;
        if (!page.detail.hidden) {
          page.detail.hidden = true;
          page.detail.textContent = '';
          state.detail = null;
        }
        page.searchNote.textContent = result.message;
      }
    }

    function renderData(arriving) {
      const feed = state.feed;
      page.data.hidden = !feed;
      if (!feed) return;
      const filtered = state.paymentFilter === 'payments';
      page.transactions.singular = filtered ? 'payment-program transaction' : 'transaction';
      page.transactions.plural = filtered ? 'payment-program transactions' : 'transactions';
      setText(page.transactions.empty, filtered ? 'No payment-program transactions in the recent window.' :
        page.transactions.emptyText);
      renderList(page.blocks, feed.blocks, state.blockLimit, blockKey, buildBlockRow, arriving);
      renderList(page.transactions, filterTransactions(feed, state.paymentFilter), state.transactionLimit,
        transactionKey, buildTransactionRow, arriving);
    }

    /* ----- payment marks: the figure's footnote and the filter ----- */

    const filterGroups = app ? Array.prototype.slice.call(app.querySelectorAll('[data-payment-filters]')) : [];
    const filterButtons = app ? Array.prototype.slice.call(app.querySelectorAll('[data-payment-filter]')) : [];

    /* The filter is offered only while the feed marks payment-program transactions. */
    function renderPaymentMarks() {
      const stats = state.stats;
      const marked = feedMarksPayments(state.feed);
      if (!marked) state.paymentFilter = 'all';
      app.setAttribute('data-payments', stats.blocks === 0 ? 'unknown' : stats.marked_blocks === 0 ? 'unmarked' : 'marked');
      setText(page.paymentsNote, paymentsNote(stats));
      filterGroups.forEach(function (group) { group.hidden = !marked; });
      filterButtons.forEach(function (button) {
        const pressed = button.getAttribute('data-payment-filter') === state.paymentFilter;
        button.setAttribute('aria-pressed', pressed ? 'true' : 'false');
      });
    }

    function setPaymentFilter(name) {
      state.paymentFilter = name === 'payments' && feedMarksPayments(state.feed) ? 'payments' : 'all';
      state.transactionLimit = PAGE_ROWS;
      renderPaymentMarks();
      renderData(false);
      renderAges(nowSeconds());
      renderCharts();
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

    /* Rewritten only when the wording changes, so it is announced once. `message` is the
       sentence for this notice; the time of the last update follows it when there is one. */
    function renderNotice(notice, description, message) {
      const text = description.updatedAt === null ? message : message + ' Last updated ' + formatUtc(description.updatedAt) + '.';
      if (notice.getAttribute('data-tone') !== description.state) notice.setAttribute('data-tone', description.state);
      if (notice.textContent === text) return;
      notice.textContent = '';
      if (description.updatedAt === null) {
        notice.textContent = text;
        return;
      }
      const time = el('time', '', formatUtc(description.updatedAt));
      time.setAttribute('datetime', isoUtc(description.updatedAt));
      notice.appendChild(doc.createTextNode(message + ' Last updated '));
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
        hideDetail();
      }
    }

    function showMore(view, limitName, items) {
      state[limitName] = nextLimit(state[limitName], items.length);
      renderData(false);
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
        if (state.feed) showMore(page.transactions, 'transactionLimit', filterTransactions(state.feed, state.paymentFilter));
      });
      filterButtons.forEach(function (button) {
        button.addEventListener('click', function () { setPaymentFilter(button.getAttribute('data-payment-filter')); });
      });
      [page.blocks, page.transactions].forEach(function (view) {
        view.body.addEventListener('animationend', function (event) {
          if (event.target.classList) event.target.classList.remove('row-new');
        });
      });
      page.charts.addEventListener('pointermove', function (event) { showColumn(columnAt(event)); });
      page.charts.addEventListener('pointerleave', function () {
        if (doc.activeElement !== page.charts) showColumn(-1);
      });
      page.charts.addEventListener('blur', function () { showColumn(-1); });
      page.charts.addEventListener('click', function (event) {
        const index = columnAt(event);
        if (index !== -1) openColumn(index);
      });
      page.charts.addEventListener('keydown', function (event) {
        const count = state.stats.series.length;
        if (count === 0) return;
        const current = state.chartIndex === -1 ? count : state.chartIndex;
        if (event.key === 'ArrowLeft') showColumn(Math.max(0, current - 1));
        else if (event.key === 'ArrowRight') showColumn(Math.min(count - 1, current + 1));
        else if (event.key === 'Home') showColumn(0);
        else if (event.key === 'End') showColumn(count - 1);
        else if (event.key === 'Enter' && state.chartIndex !== -1) openColumn(state.chartIndex);
        else return;
        event.preventDefault();
      });
      win.addEventListener('hashchange', function () {
        const link = parseDeepLink(win.location.hash);
        if (!link) return;
        state.link = link;
        followLink();
      });
      renderCharts();
    }

    /* ----- validators the feed lists, on any page that carries the list ----- */

    const validatorViews = validatorRoots.map(function (root) {
      const view = { root: root, body: root.querySelector('[data-validators-body]'),
        wrap: root.querySelector('[data-validators-wrap]'), empty: root.querySelector('[data-validators-empty]'),
        rows: new Map() };
      return view.body && view.wrap && view.empty ? view : null;
    }).filter(Boolean);

    /* Each cell carries its column name, which a narrow layout shows beside the value. */
    function labelledCell(tag, label, className) {
      const cell = el(tag, className || '');
      cell.setAttribute('data-label', label);
      return cell;
    }

    function buildValidatorRow(validator) {
      const entry = { row: el('tr'), name: labelledCell('th', 'Identity'), vote: labelledCell('td', 'Vote account'),
        lastVote: labelledCell('td', 'Last vote'), behind: labelledCell('td', 'Behind the tip'),
        root: labelledCell('td', 'Root slot', 'validator-root'), voting: labelledCell('td', 'Voting'),
        badge: el('span', 'badge'), account: el('span', 'identifier') };
      entry.name.setAttribute('scope', 'row');
      entry.name.appendChild(el('span', 'identifier', validator.identity));
      entry.vote.appendChild(entry.account);
      entry.voting.appendChild(entry.badge);
      [entry.name, entry.vote, entry.lastVote, entry.behind, entry.root, entry.voting].forEach(function (cell) {
        entry.row.appendChild(cell);
      });
      return entry;
    }

    /* Rows stay in place from one feed to the next; only their values change. The root
       slot column is shown when the feed carries a root slot for at least one validator. */
    function renderValidators(live) {
      if (validatorViews.length === 0) return;
      const rows = validatorRows(state.feed);
      const withRoot = rows.some(function (row) { return row.root_slot !== null; });
      validatorViews.forEach(function (view) {
        const wanted = new Set();
        rows.forEach(function (row, index) {
          const key = row.identity + '|' + (row.vote_account === null ? '' : row.vote_account);
          let entry = view.rows.get(key);
          if (!entry) {
            entry = buildValidatorRow(row);
            view.rows.set(key, entry);
          }
          wanted.add(key);
          setValue(entry.account, row.vote_account);
          setValue(entry.lastVote, row.last_vote === null ? null : formatInteger(row.last_vote));
          setValue(entry.behind, slotsBehind(row.behind));
          setValue(entry.root, row.root_slot === null ? null : formatInteger(row.root_slot));
          setText(entry.badge, votingLabel(row.active, live));
          const tone = !live ? 'badge' : row.active ? 'badge verified' : 'badge failed';
          if (entry.badge.className !== tone) entry.badge.className = tone;
          if (view.body.children[index] !== entry.row) view.body.insertBefore(entry.row, view.body.children[index] || null);
        });
        view.rows.forEach(function (entry, key) {
          if (!wanted.has(key)) {
            if (entry.row.parentNode === view.body) view.body.removeChild(entry.row);
            view.rows.delete(key);
          }
        });
        view.root.setAttribute('data-root', withRoot ? 'shown' : 'absent');
        view.wrap.hidden = rows.length === 0;
        view.empty.hidden = rows.length !== 0;
        setText(view.empty, state.feed ? TEXT.validatorsNone : TEXT.validatorsWaiting);
      });
    }

    /* ----- strip of recent slots, on any page that carries one ----- */

    const pulses = Array.prototype.map.call(doc.querySelectorAll('[data-zolana-pulse]'), function (root) {
      const ticks = [];
      clearNode(root);
      for (let i = 0; i < STRIP_SLOTS; i += 1) {
        const tick = el('span', 'tick');
        root.appendChild(tick);
        ticks.push(tick);
      }
      return { root: root, ticks: ticks, newest: null };
    });

    const TICK_TITLES = { block: 'block recorded', skipped: 'skipped, no block', unknown: 'not in the explorer data' };

    function renderPulses() {
      const entries = state.strip.ticks;
      const offset = STRIP_SLOTS - entries.length;
      pulses.forEach(function (pulse) {
        const animate = pulse.newest !== null && motionAllowed();
        pulse.ticks.forEach(function (tick, index) {
          const entry = index >= offset ? entries[index - offset] : null;
          const name = entry ? 'tick ' + entry.state + (animate && entry.slot > pulse.newest ? ' tick-new' : '') : 'tick';
          if (tick.className !== name) tick.className = name;
          if (entry) tick.title = 'Slot ' + formatInteger(entry.slot) + ': ' + TICK_TITLES[entry.state];
          else tick.removeAttribute('title');
        });
        pulse.newest = state.strip.last_slot;
      });
    }

    /* ----- refresh loop ----- */

    function render() {
      const seconds = nowSeconds();
      const description = describeState(state.feed, state.lastFetchOk, seconds);
      statusViews.forEach(function (view) { renderStatus(view, description, seconds); });
      renderValidators(description.state === 'live');
      noticeNodes.forEach(function (node) {
        renderNotice(node, description, node.getAttribute('data-zolana-notice') === 'validators' ?
          validatorsNotice(description) : description.message);
      });
      if (pageReady) {
        app.setAttribute('data-state', description.state);
        renderNotice(page.notice, description, description.message);
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
        state.stats = windowStats(result.feed);
        state.strip = slotStrip(result.feed, STRIP_SLOTS);
        renderPulses();
        if (pageReady) {
          renderPaymentMarks();
          renderData(true);
          renderCharts();
          refreshDetail();
          if (state.link) followLink();
        }
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
