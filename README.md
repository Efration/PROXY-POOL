# Public proxy pool

This is a **single public GitHub repository**. The worker, the subscription
list, the GitHub Actions workflow, and the published proxy list all live here.
There is no second repository.

On a schedule the workflow downloads every URL in `subscriptions.txt`,
normalizes the bodies, extracts proxy configurations, tags each name with
`<provider>`, deduplicates by **host/IP + port**, runs a real protocol-level
connectivity test with [sing-box](https://github.com/SagerNet/sing-box), and
commits the survivors to `proxies.txt` when the file actually changed.

There is **no speed test, no ranking, and no country detection**. The file is
a pool of *usable* configs. Ranking is left to your client.

---

## Subscription URL

After you upload this project to GitHub, clients can use the raw list:

```text
https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/proxies.txt
```

Replace `YOUR_USER` and `YOUR_REPO` with the owner and name of **this**
repository.

---

## Config names (`<provider>`)

Every configuration name starts with a tag taken from the subscription URL
it was extracted from:

```text
<provider>original name
```

Examples:

```text
<youfoundamin>🇩🇪 Germany 01
<iampedi5>🇩🇪 Germany 🚀 Premium
<xrayvip>US-01
```

- The text inside `<...>` is the provider (GitHub owner, or the meaningful
  part of the domain).
- The rest of the name is the original remark (flags, emojis, spaces, Unicode).
- The tag only names the **source subscription**. It is not a rank or a
  country check.

---

## Purpose

- Collect free/public subscription links listed in `subscriptions.txt`
- Decode Base64 lists and convert sing-box JSON to share-link URIs
- Keep one config per `host:port`
- Prove each line with a real tunnel test (not ping)
- Publish the healthy set as `proxies.txt` on the same public repo

Because the repository is public, **source, config, and subscription URLs
are visible**. Do not put private tokens or paid-subscription links in
`subscriptions.txt`.

## Features

- **One repo** — Actions fetch, test, and commit `proxies.txt` here
- **72-hour interval** — `config.json` → `update_interval_hours: 72` (every
  three days). The workflow still ticks hourly; the Python gate skips early
  hours. **Run workflow** always runs immediately
- **Fault isolation** — one dead subscription URL never aborts the run
- **Formats** — plain URI lists, Base64 URI lists, sing-box JSON (including
  Base64-wrapped JSON)
- **Protocols tested** — Shadowsocks, VMess, VLESS, Trojan, TUIC, Hysteria,
  Hysteria2, SOCKS5, HTTP
- **OLD vs NEW** — endpoints already in `proxies.txt` get retries; new
  endpoints get one attempt
- **Python 3.10+ standard library only** — nothing to `pip install`. The
  workflow downloads sing-box itself

---

## How it works

```
subscriptions.txt
        ↓
Fetch ALL subscription URLs
        ↓
Normalize (Base64 / sing-box JSON / plain URIs)
        ↓
Extract ALL proxy configurations
        ↓
Prefix each remark with <provider>
        ↓
FINISH extraction  (no tests yet)
        ↓
Deduplicate by host/IP + port
        ↓
Load existing proxies.txt  →  OLD vs NEW
        ↓
GitHub Actions: 6 test shards × 16 in-process workers
        ↓
Healthy lines  →  proxies.txt  (committed only if changed)
```

GitHub Actions jobs:

1. **Prepare candidates** — interval gate, fetch, extract, upload
   `candidates.json`
2. **Test shard 0…5** — six parallel jobs; each tests one slice
3. **Merge & commit** — write `proxies.txt` and push to **this** repo

---

## Repository structure

```
.
├── .github/workflows/update.yml   # hourly tick + manual dispatch
├── HOW_TO_RUN.md                  # create the public repo on github.com
├── README.md                      # this file
├── config.json                    # interval, workers, timeouts
├── subscriptions.txt              # one subscription URL per line
├── proxies.txt                    # published pool (one URI per line)
├── requirements.txt               # no third-party packages
├── worker/                        # Python implementation
│   ├── main.py
│   ├── check_interval.py
│   ├── fetcher.py
│   ├── decoder.py
│   ├── subscription.py
│   ├── parser.py
│   ├── provider.py
│   ├── dedupe.py
│   ├── singbox.py
│   ├── tester.py
│   ├── merge_results.py
│   └── config.py
└── tests/test_worker.py
```

---

## Configuration (`config.json`)

| Key | Value in this repo | Meaning |
|---|---|---|
| `update_interval_hours` | `72` | Refresh every three days |
| `test_workers` | `16` | Parallel tests **inside each** shard job |
| `old_config_retries` | `3` | Extra attempts for endpoints already in `proxies.txt` |
| `connectivity_timeout_seconds` | `10` | HTTP timeout through each proxy |
| `test_url` | `https://www.gstatic.com/generate_204` | Endpoint fetched through the proxy |
| `sing_box_version` | `1.10.7` | Core downloaded by the workflow |
| `subscriptions_file` / `proxies_file` | `subscriptions.txt` / `proxies.txt` | Input / output |

`test_workers` does **not** create extra GitHub runners. `TOTAL_SHARDS: 6` in
the workflow is the number of parallel test jobs.

Change the interval by editing `update_interval_hours` in `config.json` on
GitHub (pencil → commit). You do not need to edit the workflow cron.

---

## Connectivity test

ICMP or a raw TCP connect is not enough. Each config is turned into a
sing-box outbound, a local core is started, and `curl` fetches `test_url`
through that tunnel. HTTP 2xx/3xx within the timeout → keep; otherwise fail.

---

## Deduplication and retries

Duplicate key: **`host/IP + port` only**. Protocol, UUID, and SNI do not
matter.

- **OLD** — endpoint already in `proxies.txt` → 1 test + up to
  `old_config_retries` retries. The original line is kept if it passes.
- **NEW** — all other endpoints → exactly one test. Fail → drop.

---

## Using the list

Point a client at the raw `proxies.txt` URL above. One healthy URI per line.
The file is overwritten on each successful update. Skip a line that fails in
your client; the next run may drop it.

---

## What this repository does not do

- It does not split the worker and the list across two GitHub repositories
- It does not hide `subscriptions.txt` or `config.json`
- It does not rank proxies by speed or country
- It does not require a personal access token for publishing (Actions commits
  with `GITHUB_TOKEN` to this same repo)
