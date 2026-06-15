---
name: hot-intel
description: >
  Use when the user asks to fetch, refresh, inspect, or troubleshoot hot
  web-intel signals in core.db, including fetch_hot runs, targeted vuln_id
  evaluation, and hot evidence inspection.
---

# Skill: hot-intel

## Always read first

`docs/FEEDS.md`, `sync/fetch_hot.py`, `sync/hot_intel.py`, `app/skills.py`,
and `sync/feed_quality.py`.
Run `db/migrate.py` before any DB read.

For command examples and output interpretation, see
[references/hot.md](references/hot.md).

## When to use

- Refresh `hot` from live sources.
- Investigate why a CVE did or did not become hot.
- Inspect the latest hot watchlist or a single `vuln_id`.
- Explain `hot` evidence payloads and source mix.

## Required workflow

1. Run `db/migrate.py`.
2. If refreshing, run `python3 -m sync.fetch_hot` after `core.db` has been
   refreshed.
3. If targeting specific CVEs, use `python3 -m sync.fetch_hot --vuln-id ...`
   with optional `--profile`, `--query-term`, or `--simple`.
4. For review, use `python3 -m app.skills hot --limit 20 --details` or direct
   SQL on `signals` where `signal_type='hot'`.
5. Treat `hot` as early-attention, reference-only signal. Do not rank it above
   KEV, exploit, EPSS, or CVSS unless the user explicitly asks.

## Operational rules

- `hot` is append-only history. Exact duplicate signals are skipped; `observed_at`
  is not part of the identity.
- Prefer the latest `hot` row per `vuln_id` when summarizing current state.
- Use the JSON payload for `headline`, `search_hits`, `evidence_details`,
  `search_budget`, `evidence_types`, and `source_types`.
- Hatena is best-effort; absence of Hatena evidence is not a failure.
- Expect outbound HTTP/DNS. In restricted environments, request approval before
  running the fetcher.
- When the user asks for "recent" hot coverage, use a practical window of about
  4 days from `first_seen_at`.

## Output expectations

- When listing hot items, include `vuln_id`, title, `observed_at`, `hot_score`,
  `evidence_types`, and source count.
- When explaining one CVE, show the evidence URLs and why each hit was
  classified.
