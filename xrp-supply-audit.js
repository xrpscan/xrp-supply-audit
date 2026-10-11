#!/usr/bin/env node
/**
 * XRP Supply Audit
 *
 * Reconciles the total XRP supply recorded in a ledger header (`total_coins`)
 * against the XRP actually held in that ledger's state tree. Written in
 * response to the "Payment Engine XRP Overflow" disclosure:
 * https://xrpl.org/blog/2026/vulnerabilitydisclosurereport-bug-20261009#payment-engine-xrp-overflow
 *
 * That bug could mint XRP without the "no XRP created" invariant noticing,
 * because the invariant used the same wrapping arithmetic. Such XRP would sit
 * in ordinary AccountRoot balances while `total_coins` stayed unchanged, so an
 * independent sum of every XRP-holding ledger object exposes it.
 *
 * XRP in the ledger state lives in exactly these places:
 *   - AccountRoot.Balance (includes AMM, Vault and other pseudo-accounts)
 *   - Escrow.Amount, when the amount is XRP (a string of drops)
 *   - PayChannel.Amount - PayChannel.Balance (the unclaimed remainder)
 * Burned transaction fees are already deducted from `total_coins`, so for a
 * healthy ledger:
 *
 *   total_coins == sum(AccountRoot) + sum(XRP Escrow) + sum(PayChannel unclaimed)
 *
 * All arithmetic uses BigInt, so the audit itself cannot overflow.
 *
 * Zero dependencies: uses the global WebSocket client built into Node.js >= 22.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';

const DEFAULT_WS = 'wss://s1.ripple.com';
const PAGE_LIMIT = 2048;
const PROGRESS_EVERY = 100_000; // objects scanned between verbose progress lines
const REQUEST_TIMEOUT_MS = 60_000;
const MAX_RETRIES = 8;
const DROPS_PER_XRP = 1_000_000n;
const MAX_XRP_DROPS = 100_000_000_000n * DROPS_PER_XRP;
const REPLAY_CONCURRENCY = 4;
const DEFAULT_CACHE = 'xrp-supply-audit-cache.json';

const USAGE = `Usage: node xrp-supply-audit.js [options]

Reconcile total XRP supply (ledger total_coins) against the sum of all
XRP-holding ledger objects.

Options:
  --ws <url>          WebSocket server to query (default: ${DEFAULT_WS})
  -l, --ledger <idx>  Ledger index to audit, or "validated" (default: validated)
  -v, --verbose       Print progress and details (to stderr with --json)
      --json          Print the final report as JSON on stdout
  -h, --help          Show this help

Bisect mode (needs a full-history server):
      --bisect        Find the first ledger where the supply difference
                      changes, between --from (good) and --ledger (bad)
      --from <idx>    Known-good ledger (default: earliest ledger the
                      server has)
      --replay-threshold <n>
                      Once the range is this many ledgers or fewer, check
                      each ledger's transaction metadata (1 request per
                      ledger) instead of walking state. Default: the number
                      of pages in one state walk. 0 = bisect all the way.
      --cache <file>  File that stores walk results so an interrupted
                      bisect can resume (default: ${DEFAULT_CACHE})

Exit codes: 0 = reconciled (bisect: no change in range),
            1 = discrepancy found (bisect: ledger found), 2 = error`;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

let args;
try {
  ({ values: args } = parseArgs({
    options: {
      ws: { type: 'string', default: DEFAULT_WS },
      ledger: { type: 'string', short: 'l', default: 'validated' },
      verbose: { type: 'boolean', short: 'v', default: false },
      json: { type: 'boolean', default: false },
      bisect: { type: 'boolean', default: false },
      from: { type: 'string' },
      'replay-threshold': { type: 'string' },
      cache: { type: 'string', default: DEFAULT_CACHE },
      help: { type: 'boolean', short: 'h', default: false },
    },
  }));
} catch (err) {
  console.error(`${err.message}\n\n${USAGE}`);
  process.exit(2);
}

if (args.help) {
  console.log(USAGE);
  process.exit(0);
}

if (!/^wss?:\/\//i.test(args.ws)) {
  console.error(`Invalid --ws value "${args.ws}": must start with ws:// or wss://`);
  process.exit(2);
}

if (args.ledger !== 'validated' && !/^\d+$/.test(args.ledger)) {
  console.error(`Invalid --ledger value "${args.ledger}": must be a ledger index or "validated"`);
  process.exit(2);
}

if (args.from !== undefined && !/^\d+$/.test(args.from)) {
  console.error(`Invalid --from value "${args.from}": must be a ledger index`);
  process.exit(2);
}

if (args['replay-threshold'] !== undefined && !/^\d+$/.test(args['replay-threshold'])) {
  console.error(`Invalid --replay-threshold value "${args['replay-threshold']}": must be a whole number`);
  process.exit(2);
}

if (!args.bisect && (args.from !== undefined || args['replay-threshold'] !== undefined)) {
  console.error('--from and --replay-threshold only apply with --bisect');
  process.exit(2);
}

if (typeof WebSocket === 'undefined') {
  console.error('This script needs a global WebSocket (Node.js >= 22).');
  process.exit(2);
}

const ts = () => new Date().toISOString().slice(11, 19);
// Progress goes to stdout, except with --json, where stdout must hold only the report.
const log = (...m) => { if (args.verbose) (args.json ? console.error : console.log)(`[${ts()}]`, ...m); };
const warn = (...m) => console.error(`[${ts()}] WARN`, ...m);

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/** Format a BigInt number of drops as an XRP string with 6 decimals. */
function fmtXrp(drops) {
  const neg = drops < 0n;
  const abs = neg ? -drops : drops;
  const whole = (abs / DROPS_PER_XRP).toLocaleString('en-US');
  const frac = (abs % DROPS_PER_XRP).toString().padStart(6, '0');
  return `${neg ? '-' : ''}${whole}.${frac} XRP`;
}

const fmtInt = (n) => Number(n).toLocaleString('en-US');

/** Parse a drops string strictly; anything else is an anomaly. */
function parseDrops(value) {
  if (typeof value !== 'string' || !/^-?\d+$/.test(value)) return null;
  return BigInt(value);
}

// ---------------------------------------------------------------------------
// Minimal resilient WebSocket JSON-RPC client
// ---------------------------------------------------------------------------

class XrplClient {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  connect() {
    return new Promise((resolve, reject) => {
      log(`Connecting to ${this.url} ...`);
      const ws = new WebSocket(this.url);
      let opened = false;

      ws.addEventListener('open', () => {
        opened = true;
        this.ws = ws;
        log(`Connected to ${this.url}`);
        resolve();
      });

      ws.addEventListener('message', (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        const p = this.pending.get(msg.id);
        if (!p) return;
        this.pending.delete(msg.id);
        clearTimeout(p.timer);
        p.resolve(msg);
      });

      ws.addEventListener('error', () => {
        if (!opened) reject(new Error(`Unable to connect to ${this.url}`));
      });

      ws.addEventListener('close', (ev) => {
        if (this.ws === ws) this.ws = null;
        if (opened) log(`Connection closed (code ${ev.code})`);
        for (const [id, p] of this.pending) {
          clearTimeout(p.timer);
          p.reject(new Error(`Connection closed (code ${ev.code})`));
          this.pending.delete(id);
        }
      });
    });
  }

  send(command) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        reject(new Error('Not connected'));
        return;
      }
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      this.ws.send(JSON.stringify({ ...command, id }));
    });
  }

  /**
   * Send a command, reconnecting and retrying with exponential backoff on
   * transport errors and transient server errors (slowDown, tooBusy, ...).
   */
  async request(command) {
    for (let attempt = 1; ; attempt++) {
      try {
        if (!this.ws) await this.connect();
        const res = await this.send(command);
        if (res.status === 'success') return res.result;

        const code = res.error ?? res.result?.error ?? 'unknown';
        const transient = ['slowDown', 'tooBusy', 'noNetwork', 'noCurrent', 'noClosed'];
        const err = new Error(`${command.command} failed: ${code}${res.error_message ? ` (${res.error_message})` : ''}`);
        err.fatal = !transient.includes(code);
        throw err;
      } catch (err) {
        if (err.fatal || attempt >= MAX_RETRIES) throw err;
        const delay = Math.min(30_000, 500 * 2 ** attempt);
        warn(`${err.message}; retry ${attempt}/${MAX_RETRIES - 1} in ${delay / 1000}s`);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
  }

  close() {
    if (this.ws) this.ws.close();
  }
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

/**
 * Walk every ledger object in a fixed ledger in a single pass, invoking the
 * handler registered for its LedgerEntryType. A single unfiltered pass is used
 * because ledger_data's `type` filter still walks the entire state tree on the
 * server, so filtered passes per type would each cost a full walk.
 */
async function walkLedgerState(client, ledgerHash, handlers) {
  let marker;
  let pages = 0;
  let scanned = 0;
  let nextProgress = PROGRESS_EVERY;
  const counts = Object.fromEntries(Object.keys(handlers).map((t) => [t, 0]));
  const started = Date.now();

  log('Scanning ledger state ...');
  do {
    const result = await client.request({
      command: 'ledger_data',
      ledger_hash: ledgerHash,
      limit: PAGE_LIMIT,
      binary: false,
      ...(marker !== undefined && { marker }),
    });

    if (result.ledger_hash && result.ledger_hash !== ledgerHash) {
      throw new Error(`Server returned data for ledger ${result.ledger_hash}, expected ${ledgerHash}`);
    }

    for (const obj of result.state) {
      scanned++;
      const handler = handlers[obj.LedgerEntryType];
      if (!handler) continue;
      handler(obj);
      counts[obj.LedgerEntryType]++;
    }
    pages++;
    marker = result.marker;

    if (args.verbose && (scanned >= nextProgress || marker === undefined)) {
      nextProgress = (Math.floor(scanned / PROGRESS_EVERY) + 1) * PROGRESS_EVERY;
      const secs = (Date.now() - started) / 1000;
      const rate = fmtInt(Math.round(scanned / Math.max(secs, 0.001)));
      const breakdown = Object.entries(counts).map(([t, n]) => `${t} ${fmtInt(n)}`).join(', ');
      log(`  ${fmtInt(scanned)} objects scanned, ${fmtInt(pages)} pages, ${rate} obj/s | ${breakdown}`);
    }
  } while (marker !== undefined);

  log(`Finished scan: ${fmtInt(scanned)} objects in ${((Date.now() - started) / 1000).toFixed(1)}s`);
  return { counts, pages };
}

async function audit(client, ledgerIndex) {
  // 1. Pin the audit to one exact ledger so every page sees the same state.
  log(`Fetching ledger header for ${ledgerIndex} ...`);
  const { ledger, validated } = await client.request({ command: 'ledger', ledger_index: ledgerIndex });

  if (!validated) throw new Error(`Ledger ${ledger.ledger_index} is not validated on this server`);
  const totalCoins = parseDrops(ledger.total_coins);
  if (totalCoins === null) throw new Error(`Unexpected total_coins value: ${ledger.total_coins}`);

  const ledgerHash = ledger.ledger_hash;
  const closeTime = ledger.close_time_iso ?? ledger.close_time_human;
  log(`Auditing ledger ${ledger.ledger_index} (${ledgerHash}), closed ${closeTime}`);
  log(`Ledger header total_coins: ${fmtXrp(totalCoins)}`);

  const anomalies = [];
  const flag = (kind, obj, detail) => {
    anomalies.push({ kind, index: obj.index, account: obj.Account, detail });
    warn(`Anomaly [${kind}] ${obj.LedgerEntryType} ${obj.index}${obj.Account ? ` (${obj.Account})` : ''}: ${detail}`);
  };

  let accountSum = 0n;
  let escrowSum = 0n;
  let tokenEscrows = 0;
  let paychanSum = 0n;
  const top = []; // largest balances, for context in the report

  const { counts, pages } = await walkLedgerState(client, ledgerHash, {
    // 2. AccountRoot balances (includes AMM / Vault pseudo-accounts).
    AccountRoot: (obj) => {
      const bal = parseDrops(obj.Balance);
      if (bal === null) return flag('malformed-balance', obj, `Balance=${JSON.stringify(obj.Balance)}`);
      if (bal < 0n) flag('negative-balance', obj, fmtXrp(bal));
      if (bal > totalCoins) flag('balance-exceeds-supply', obj, fmtXrp(bal));
      accountSum += bal;

      if (top.length < 10 || bal > top[top.length - 1].balance) {
        top.push({ account: obj.Account, balance: bal });
        top.sort((a, b) => (b.balance > a.balance ? 1 : b.balance < a.balance ? -1 : 0));
        if (top.length > 10) top.pop();
      }
    },

    // 3. Escrows. Only XRP escrows (Amount as a drops string) hold XRP;
    //    token escrows carry an object Amount and are skipped.
    Escrow: (obj) => {
      if (typeof obj.Amount === 'object') { tokenEscrows++; return; }
      const amt = parseDrops(obj.Amount);
      if (amt === null) return flag('malformed-amount', obj, `Amount=${JSON.stringify(obj.Amount)}`);
      if (amt < 0n) flag('negative-escrow', obj, fmtXrp(amt));
      escrowSum += amt;
    },

    // 4. Payment channels hold Amount minus what has already been claimed.
    PayChannel: (obj) => {
      const amt = parseDrops(obj.Amount);
      const claimed = obj.Balance === undefined ? 0n : parseDrops(obj.Balance);
      if (amt === null || claimed === null) {
        return flag('malformed-amount', obj, `Amount=${JSON.stringify(obj.Amount)} Balance=${JSON.stringify(obj.Balance)}`);
      }
      if (claimed > amt) flag('overclaimed-channel', obj, `Balance ${fmtXrp(claimed)} > Amount ${fmtXrp(amt)}`);
      paychanSum += amt - claimed;
    },
  });
  const accounts = counts.AccountRoot;
  const escrows = counts.Escrow;
  const paychans = counts.PayChannel;

  // 5. Reconcile.
  const stateSum = accountSum + escrowSum + paychanSum;
  const difference = stateSum - totalCoins;
  if (totalCoins > MAX_XRP_DROPS) {
    anomalies.push({ kind: 'total-coins-exceeds-genesis', detail: fmtXrp(totalCoins) });
  }

  return {
    ledger: {
      index: Number(ledger.ledger_index),
      hash: ledgerHash,
      closeTime,
    },
    server: args.ws,
    pages,
    totalCoins,
    accounts: { count: accounts, drops: accountSum },
    escrows: { count: escrows, xrpCount: escrows - tokenEscrows, drops: escrowSum },
    paychans: { count: paychans, drops: paychanSum },
    stateSum,
    difference,
    anomalies,
    top,
    reconciled: difference === 0n && anomalies.length === 0,
  };
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

function printReport(r) {
  if (args.json) {
    const replacer = (_k, v) => (typeof v === 'bigint' ? v.toString() : v);
    console.log(JSON.stringify(r, replacer, 2));
    return;
  }

  const row = (label, drops, extra = '') => console.log(`  ${label.padEnd(28)} ${fmtXrp(drops).padStart(34)}${extra}`);

  console.log('');
  console.log('XRP Supply Reconciliation');
  console.log('='.repeat(72));
  console.log(`  Server        ${r.server}`);
  console.log(`  Ledger        ${r.ledger.index}`);
  console.log(`  Hash          ${r.ledger.hash}`);
  console.log(`  Close time    ${r.ledger.closeTime}`);
  console.log('-'.repeat(72));
  row('AccountRoot balances', r.accounts.drops, `  (${fmtInt(r.accounts.count)} accounts)`);
  row('XRP Escrows', r.escrows.drops, `  (${fmtInt(r.escrows.xrpCount)} of ${fmtInt(r.escrows.count)} escrows)`);
  row('PayChannel unclaimed', r.paychans.drops, `  (${fmtInt(r.paychans.count)} channels)`);
  console.log('-'.repeat(72));
  row('Sum of ledger state', r.stateSum);
  row('Ledger header total_coins', r.totalCoins);
  row('Difference (state - header)', r.difference);
  console.log('='.repeat(72));

  if (args.verbose) {
    console.log('  Largest balances:');
    for (const t of r.top) console.log(`    ${t.account.padEnd(36)} ${fmtXrp(t.balance).padStart(32)}`);
    console.log('='.repeat(72));
  }

  if (r.anomalies.length) {
    console.log(`  ${r.anomalies.length} anomal${r.anomalies.length === 1 ? 'y' : 'ies'} found:`);
    for (const a of r.anomalies.slice(0, 50)) {
      console.log(`    [${a.kind}] ${a.index ?? ''} ${a.account ?? ''} ${a.detail}`);
    }
    if (r.anomalies.length > 50) console.log(`    ... and ${r.anomalies.length - 50} more (use --json for all)`);
  }

  if (r.reconciled) {
    console.log('  RESULT: RECONCILED - ledger state matches total_coins exactly.');
  } else if (r.difference > 0n) {
    console.log(`  RESULT: DISCREPANCY - ledger state holds ${fmtXrp(r.difference)} MORE than total_coins.`);
    console.log('          This is the signature of XRP created outside total_coins accounting.');
  } else if (r.difference < 0n) {
    console.log(`  RESULT: DISCREPANCY - ledger state holds ${fmtXrp(-r.difference)} LESS than total_coins.`);
  } else {
    console.log('  RESULT: TOTALS MATCH, BUT ANOMALIES WERE FOUND - review the list above.');
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// Bisect
// ---------------------------------------------------------------------------
//
// The supply difference D(L) = (XRP held in state) - total_coins only changes
// when a ledger creates or destroys XRP outside total_coins accounting. A full
// state walk measures D at one ledger, so binary search finds the ledger where
// D first changes in about log2(range) walks.
//
// Each ledger's transaction metadata also records the exact before/after value
// of every balance it touched, so the change in D across a single ledger can
// be measured with one request. Once the range is no bigger than the number of
// pages in a walk, checking each ledger is cheaper than another walk.

/** XRP held by a ledger object, given its fields, for each XRP-holding type. */
const HELD_XRP = {
  AccountRoot: (f) => parseDrops(f.Balance) ?? 0n,
  Escrow: (f) => (typeof f.Amount === 'string' ? parseDrops(f.Amount) ?? 0n : 0n),
  PayChannel: (f) => (parseDrops(f.Amount) ?? 0n) - (f.Balance === undefined ? 0n : parseDrops(f.Balance) ?? 0n),
};

/** Change in XRP held in ledger state caused by one transaction, from its metadata. */
function stateDeltaFromMeta(meta) {
  let delta = 0n;
  for (const wrapper of meta.AffectedNodes ?? []) {
    const [kind, node] = Object.entries(wrapper)[0];
    const held = HELD_XRP[node.LedgerEntryType];
    if (!held) continue;
    if (kind === 'CreatedNode') {
      delta += held(node.NewFields ?? {});
    } else {
      const before = held({ ...node.FinalFields, ...node.PreviousFields });
      const after = kind === 'DeletedNode' ? 0n : held(node.FinalFields ?? {});
      delta += after - before;
    }
  }
  return delta;
}

/** Fetch a ledger header plus every transaction's fee and state delta. */
async function fetchLedgerTxs(client, index) {
  const { ledger, validated } = await client.request({
    command: 'ledger', ledger_index: index, transactions: true, expand: true,
  });
  if (!validated) throw new Error(`Ledger ${index} is not validated on this server`);

  const txs = (ledger.transactions ?? []).map((t) => {
    const tx = t.tx_json ?? t; // API v2 nests the transaction in tx_json
    const meta = t.meta ?? t.metaData;
    if (typeof meta !== 'object') throw new Error(`Ledger ${index}: transaction metadata missing`);
    return {
      hash: t.hash ?? tx.hash,
      type: tx.TransactionType,
      account: tx.Account,
      fee: parseDrops(tx.Fee) ?? 0n,
      stateDelta: stateDeltaFromMeta(meta),
    };
  });

  return {
    index: Number(ledger.ledger_index),
    hash: ledger.ledger_hash,
    closeTime: ledger.close_time_iso ?? ledger.close_time_human,
    totalCoins: parseDrops(ledger.total_coins),
    txs,
  };
}

/**
 * Check ledgers good+1 .. bad one at a time via metadata and return the first
 * one whose transactions change the supply difference, or null.
 */
async function replayRange(client, goodIndex, badIndex) {
  const count = badIndex - goodIndex;
  log(`Replaying transaction metadata for ${fmtInt(count)} ledgers (${goodIndex + 1}..${badIndex}) ...`);
  const { ledger: base } = await client.request({ command: 'ledger', ledger_index: goodIndex });
  let prevTotal = parseDrops(base.total_coins);
  const started = Date.now();

  for (let start = goodIndex + 1; start <= badIndex; start += REPLAY_CONCURRENCY) {
    const batch = [];
    for (let i = start; i < start + REPLAY_CONCURRENCY && i <= badIndex; i++) batch.push(fetchLedgerTxs(client, i));

    for (const l of await Promise.all(batch)) {
      const stateDelta = l.txs.reduce((sum, t) => sum + t.stateDelta, 0n);
      const drift = stateDelta - (l.totalCoins - prevTotal);
      if (drift !== 0n) {
        // A healthy transaction removes exactly its fee from state.
        const culprits = l.txs
          .filter((t) => t.stateDelta + t.fee !== 0n)
          .map((t) => ({ hash: t.hash, type: t.type, account: t.account, created: t.stateDelta + t.fee }));
        const feesBurned = l.txs.reduce((sum, t) => sum + t.fee, 0n);
        return {
          index: l.index, hash: l.hash, closeTime: l.closeTime, drift, culprits,
          totalCoinsChange: l.totalCoins - prevTotal, feesBurned,
        };
      }
      prevTotal = l.totalCoins;
    }

    const done = Math.min(start + REPLAY_CONCURRENCY - 1, badIndex) - goodIndex;
    if (args.verbose && (done % 200 < REPLAY_CONCURRENCY || done === count)) {
      const secs = (Date.now() - started) / 1000;
      log(`  replayed ${fmtInt(done)} / ${fmtInt(count)} ledgers, ${(done / Math.max(secs, 0.001)).toFixed(1)} ledgers/s`);
    }
  }
  return null;
}

function loadCache(file) {
  try {
    const text = readFileSync(file, 'utf8');
    return text.trim() ? JSON.parse(text) : {};
  } catch (err) {
    if (err.code === 'ENOENT') return {};
    throw new Error(`Cannot read cache file ${file}: ${err.message}`);
  }
}

/** Parse complete_ledgers ("32570-1000,1005-2000") into [start, end] pairs. */
function parseCompleteLedgers(text) {
  return String(text ?? '').split(',')
    .map((r) => r.trim().match(/^(\d+)(?:-(\d+))?$/))
    .filter(Boolean)
    .map((m) => [Number(m[1]), Number(m[2] ?? m[1])]);
}

async function bisect(client) {
  const started = Date.now();
  const cache = loadCache(args.cache);
  let walks = 0;

  // Measure the supply difference at one ledger, reusing a cached walk when
  // the cached ledger hash matches what this server has.
  const probe = async (index) => {
    const { ledger } = await client.request({ command: 'ledger', ledger_index: index });
    const hit = cache[index];
    if (hit && hit.hash === ledger.ledger_hash) {
      log(`Ledger ${index}: difference ${fmtXrp(BigInt(hit.difference))} (from cache)`);
      return { index, difference: BigInt(hit.difference), pages: hit.pages };
    }
    const walkStarted = Date.now();
    const r = await audit(client, index);
    walks++;
    cache[index] = { hash: r.ledger.hash, difference: r.difference.toString(), pages: r.pages };
    writeFileSync(args.cache, JSON.stringify(cache, null, 2));
    log(`Ledger ${index}: difference ${fmtXrp(r.difference)} (walk ${walks}, ${((Date.now() - walkStarted) / 60000).toFixed(1)} min)`);
    return { index, difference: r.difference, pages: r.pages };
  };

  // 1. Resolve the range.
  const { info } = await client.request({ command: 'server_info' });
  const ranges = parseCompleteLedgers(info.complete_ledgers);
  if (ranges.length === 0) throw new Error(`Server reports no complete ledgers (${info.complete_ledgers})`);
  if (ranges.length > 1) warn(`Server history has gaps (${info.complete_ledgers}); probes inside a gap will fail`);
  const inHistory = (i) => ranges.some(([a, b]) => i >= a && i <= b);
  for (const i of [args.from, args.ledger].filter((v) => v !== undefined && v !== 'validated').map(Number)) {
    if (!inHistory(i)) throw new Error(`Ledger ${i} is not in this server's history (complete_ledgers: ${info.complete_ledgers})`);
  }

  const { ledger: toLedger } = await client.request({
    command: 'ledger', ledger_index: args.ledger === 'validated' ? 'validated' : Number(args.ledger),
  });
  const to = Number(toLedger.ledger_index);
  const from = args.from !== undefined ? Number(args.from) : ranges[0][0];
  if (from >= to) throw new Error(`--from (${from}) must be lower than the bad ledger (${to})`);
  log(`Bisecting ledgers ${from} (good) .. ${to} (bad): ${fmtInt(to - from)} ledgers`);

  // 2. Measure both ends.
  let bad = await probe(to);
  let good = await probe(from);
  const result = {
    mode: 'bisect',
    server: args.ws,
    from,
    to,
    differenceAtFrom: good.difference,
    differenceAtTo: bad.difference,
    found: false,
  };

  if (good.difference === bad.difference) {
    result.walks = walks;
    return result;
  }

  // 3. Binary search with state walks until replaying metadata is cheaper.
  const threshold = Math.max(1, args['replay-threshold'] !== undefined ? Number(args['replay-threshold']) : bad.pages);
  const remaining = Math.max(0, Math.ceil(Math.log2((to - from) / threshold)));
  log(`Replay threshold ${fmtInt(threshold)} ledgers: about ${remaining} more state walk(s), then up to ${fmtInt(threshold)} ledger replays`);

  while (bad.index - good.index > threshold) {
    const mid = good.index + Math.floor((bad.index - good.index) / 2);
    const p = await probe(mid);
    if (p.difference === good.difference) good = p; else bad = p;
    log(`Range narrowed to ${good.index}..${bad.index} (${fmtInt(bad.index - good.index)} ledgers)`);
  }

  // 4. Pinpoint the ledger and transaction(s) from metadata.
  const hit = await replayRange(client, good.index, bad.index);
  if (!hit) {
    throw new Error(
      `State walks show the difference changing between ledgers ${good.index} and ${bad.index}, `
      + 'but no transaction metadata in that range accounts for it.',
    );
  }

  log(`Bisect completed in ${((Date.now() - started) / 60000).toFixed(1)} min`);
  return { ...result, walks, found: true, ledger: hit };
}

function printBisectReport(r) {
  if (args.json) {
    const replacer = (_k, v) => (typeof v === 'bigint' ? v.toString() : v);
    console.log(JSON.stringify(r, replacer, 2));
    return;
  }

  console.log('');
  console.log('XRP Supply Bisect');
  console.log('='.repeat(72));
  console.log(`  Server              ${r.server}`);
  console.log(`  Range               ${r.from} .. ${r.to}`);
  console.log(`  Difference at ${String(r.from).padEnd(6)}${fmtXrp(r.differenceAtFrom).padStart(32)}`);
  console.log(`  Difference at ${String(r.to).padEnd(6)}${fmtXrp(r.differenceAtTo).padStart(32)}`);
  console.log(`  State walks run     ${r.walks}`);
  console.log('-'.repeat(72));

  if (!r.found) {
    console.log('  RESULT: The supply difference does not change in this range.');
    if (r.differenceAtFrom !== 0n) {
      console.log(`          It is already ${fmtXrp(r.differenceAtFrom)} at ledger ${r.from}; try an earlier --from.`);
    }
    console.log('');
    return;
  }

  const l = r.ledger;
  console.log(`  RESULT: The difference first changes in ledger ${l.index}`);
  console.log(`  Hash                ${l.hash}`);
  console.log(`  Close time          ${l.closeTime}`);
  console.log(`  Change in ledger    ${fmtXrp(l.drift)}`);
  if (l.totalCoinsChange + l.feesBurned !== 0n) {
    console.log(`  total_coins moved ${fmtXrp(l.totalCoinsChange)} but fees burned were ${fmtXrp(l.feesBurned)}`);
  }
  if (l.culprits.length) {
    console.log('  Transactions that changed XRP held by more than their fee:');
    for (const t of l.culprits) {
      console.log(`    ${t.hash} ${t.type} ${t.account}`);
      console.log(`      created ${fmtXrp(t.created)}`);
    }
  }
  console.log('');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const client = new XrplClient(args.ws);
let exitCode = 2;

process.on('SIGINT', () => {
  console.error('\nInterrupted.');
  client.close();
  process.exit(130);
});

try {
  if (args.bisect) {
    const result = await bisect(client);
    printBisectReport(result);
    exitCode = result.found ? 1 : 0;
  } else {
    const started = Date.now();
    const report = await audit(client, args.ledger === 'validated' ? 'validated' : Number(args.ledger));
    log(`Audit completed in ${((Date.now() - started) / 1000).toFixed(1)}s`);
    printReport(report);
    exitCode = report.reconciled ? 0 : 1;
  }
} catch (err) {
  console.error(`Error: ${err.message}`);
} finally {
  client.close();
}
process.exit(exitCode);
