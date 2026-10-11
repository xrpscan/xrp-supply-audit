# XRP Supply Audit

Checks the total XRP supply recorded in an XRP Ledger header (`total_coins`) against the XRP actually held in that ledger.

Written in response to the [Payment Engine XRP Overflow](https://xrpl.org/blog/2026/vulnerabilitydisclosurereport-bug-20261009#payment-engine-xrp-overflow) disclosure. That bug, fixed in xrpld 3.4.1, could create XRP without the "no XRP created" invariant noticing, because the invariant used the same overflowing arithmetic. XRP created this way would sit in ordinary account balances while `total_coins` stayed the same. Adding up every XRP balance independently exposes it.

## Requirements

- Node.js 22 or later (uses the built-in `WebSocket` client)
- No npm dependencies

## Usage

```sh
node xrp-supply-audit.js [options]
```

| Option | Description | Default |
| --- | --- | --- |
| `--ws <url>` | WebSocket server to query (`ws://` or `wss://`) | `wss://s1.ripple.com` |
| `-l, --ledger <idx>` | Ledger index to audit, or `validated` | `validated` |
| `-v, --verbose` | Print progress and details (to stderr when `--json` is set) | off |
| `--json` | Print the final report as JSON on stdout | off |
| `-h, --help` | Show help | |
| `--bisect` | Find the ledger where the difference first changes (see [Bisect mode](#bisect-mode)) | off |
| `--from <idx>` | Bisect: known-good ledger | earliest ledger on the server |
| `--replay-threshold <n>` | Bisect: range size at which to switch from state walks to per-ledger metadata checks | pages in one state walk |
| `--cache <file>` | Bisect: file that stores walk results so a run can resume | `xrp-supply-audit-cache.json` |

### Examples

Audit the latest validated ledger on mainnet, with progress output:

```sh
node xrp-supply-audit.js --ws wss://s1.ripple.com -v
```

Audit a specific ledger on your own node and save the report as JSON:

```sh
node xrp-supply-audit.js --ws ws://localhost:6006 --ledger 98765432 --json > report.json
```

Warnings and errors go to stderr. Verbose progress goes to stdout, except with `--json`, where it moves to stderr so the JSON on stdout stays clean for piping.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Reconciled: the ledger state matches `total_coins` exactly and nothing was flagged. Bisect: the difference doesn't change in the range |
| `1` | A discrepancy or a flagged object was found. Bisect: the ledger was found |
| `2` | Error (bad arguments, connection failure, ledger not found, etc.) |

## How the reconciliation works

The script checks that the XRP the ledger says exists matches the XRP actually held in it.

**1. The claimed total.** Each ledger header has a field, `total_coins`, that records how much XRP exists. It started at 100 billion and goes down each time transaction fees are burned. The script fixes one validated ledger and reads this number.

**2. The XRP actually held.** The script reads every object in that ledger once, and adds up all the XRP it finds. Every request is pinned to the same ledger hash, so the state can't change partway through a long run. XRP can only be held in three places:

- **Account balances** (`AccountRoot.Balance`), which includes AMM, Vault and other pseudo-accounts.
- **Escrows** (`Escrow.Amount`), counted only when the amount is XRP. Token escrows are skipped.
- **Payment channels**: `Amount - Balance`, which is the part not yet paid out.

**3. Compare.** In a healthy ledger, the two match exactly, to the drop:

```
total_coins == AccountRoot balances
             + XRP held in Escrow
             + unclaimed XRP in PayChannels (Amount - Balance)
```

Fees don't throw it off, because a burned fee leaves an account balance and comes off `total_coins` together.

### Why this catches the overflow bug

The bug paid out XRP that was never deducted from anyone, so it ended up in ordinary account balances while `total_coins` stayed the same. The ledger's built-in "no XRP created" check missed it because it used the same overflowing arithmetic. The script adds everything up independently with BigInt, which can't overflow, so any created XRP shows up as the sum being **larger** than `total_coins`.

### Checks on individual objects

It also flags:

- a negative balance or escrow amount
- an account balance larger than the total supply
- a malformed amount
- a payment channel that has paid out more than it holds
- `total_coins` above the original 100 billion XRP

The bug report notes that created XRP could be spread across many accounts so that no single account exceeds the total supply. None of these checks may fire in that case, which is why the totals check is the one that matters.

### Finding where it started

The difference (XRP held minus `total_coins`) only changes in a ledger that creates XRP. [Bisect mode](#bisect-mode) uses this to find the exact ledger and transaction where a difference first appears.

## Bisect mode

If an audit finds a discrepancy, `--bisect` finds the ledger where it first appeared and the transaction(s) responsible. It needs a **full-history** server, because it reads old ledgers.

```sh
node xrp-supply-audit.js --ws wss://your-full-history-node --bisect -v
```

`--ledger` is the bad end of the range (default: latest validated) and `--from` is the good end (default: the earliest ledger the server has).

How it works:

1. **Walk both ends.** If the difference is the same at both, nothing changed in the range and it stops.
2. **Binary search with state walks.** Each step walks the middle ledger and keeps the half where the difference changes.
3. **Check single ledgers from metadata.** Each ledger's transaction metadata records the exact before and after value of every balance it touched. So one request per ledger is enough to see whether that ledger changed the difference. Once the range is no bigger than the number of pages in one walk, checking each ledger costs less than another walk.
4. **Report.** It prints the first ledger that changes the difference and every transaction in it whose XRP movement doesn't match its fee, with the amount created.

### How many state walks

Plain bisection takes `⌈log₂(range)⌉` walks, plus 2 for the endpoints. Mainnet full history (ledger 32,570 to about 107.6 million) is about 107.6 million ledgers, so that's **29 walks**.

With the metadata step, the walk count drops to about `⌈log₂(range ÷ pages per walk)⌉ + 2`. The page count is measured on the first walk. If mainnet's state is around 15,000 pages, that is about **15 walks**, followed by up to 15,000 single-ledger checks (about one walk's worth of requests). In testing against a public server, single-ledger checks ran at about 3 ledgers/s. Walks of older ledgers are faster, because the state was smaller then.

Use `--replay-threshold 0` to bisect with walks all the way down to a single ledger.

### Resuming

Each finished walk is saved to the cache file (`--cache`), keyed by ledger index and checked against the ledger hash. If a bisect is interrupted, run the same command again and finished walks are reused. Delete the file to start fresh.

### Limitations

Bisection assumes the difference changes once in the range. If XRP was created and then destroyed again by the same kind of bug, the difference could return to its earlier value and bisection might miss it.

## Running time

Mainnet has tens of millions of ledger objects, and the script reads all of them. Expect a run of several hours against a public server, which limits request rates. Your own node with no request limits will be much faster.

If the connection drops or the server reports it is busy (`slowDown`, `tooBusy`), the script waits, reconnects and resumes from where it stopped. It gives up after repeated failures.
