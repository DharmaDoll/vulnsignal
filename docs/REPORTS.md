# Reports

This document defines the report types, their purpose, dependencies, side
effects, and storage locations.

The short version:

- Use `scripts/run_daily_review.py --daily` when you want to refresh data and
  produce the daily operator report.
- Use `scripts/report_recent_attention.py` when data is already current and you
  only want a reproducible, date-columned attention report.
- Treat `data/reports/triage/llm_reviews/` as audit logs for Codex context
  review decisions, not as the primary operator report.

## Dependency Model

```text
external feeds / git mirrors / db/exploit.db
  -> scripts/refresh_all_sources.sh
  -> scripts/ingest_recent_core_db.sh
  -> db/core.db
  -> sync.fetch_hot
  -> scripts/run_daily_review.py
       -> data/reports/triage/*.json
       -> data/reports/triage/llm_reviews/*.json

db/core.db
  -> scripts/report_recent_attention.py
       -> data/reports/attention/*.json
```

`run_daily_review.py --daily` is allowed to mutate local data because it is the
daily operation wrapper. `report_recent_attention.py` is read-only with respect
to vulnerability data; it only runs migrations and writes its own report file.

## Report Types

| Report | Command | Saves to | Updates feeds or DB? | Purpose |
|---|---|---|---|---|
| Daily review | `uv run python scripts/run_daily_review.py --daily --limit 40` | `data/reports/triage/*.json` | Yes | End-to-end daily operator run: refresh sources, ingest recent data, refresh hot, triage new CVEs, optionally review and deep-dive. |
| Daily review, report-only | `uv run python scripts/run_daily_review.py --limit 40` | `data/reports/triage/*.json` | No feed refresh; runs migrations | Re-run the daily review view from the existing `core.db` without mirror refresh, ingest, or hot refresh. |
| Recent attention | `uv run python scripts/report_recent_attention.py --days 7 --as-of <ISO8601>` | `data/reports/attention/*.json` | No feed refresh; runs migrations | Reproducible recent watchlist with date columns for operator-facing review. |
| Codex triage review log | Produced by `--codex-review` | `data/reports/triage/llm_reviews/*.json` | No direct feed updates | Audit trail for context review decisions, including suppress reasons. |
| Manual triage JSON | `uv run python scripts/triage_new_cves.py --since <ISO8601> --json` | stdout only | No, except migration | Low-level deterministic triage output. Use when debugging candidate selection. |
| Deep dive JSON | `uv run python scripts/deep_dive.py CVE-... --json` | stdout only | No, except optional targeted hot refresh when requested by that tool | Single-CVE investigation. When daily review deep-dives watch items, the result is embedded in the daily JSON. |
| Hot CLI view | `uv run python -m app.skills hot --limit 20 --details` | stdout only | No, unless `--vuln-id` triggers targeted refresh | Inspect current hot evidence from `core.db`. |

## Daily Review

Default command:

```bash
uv run python scripts/run_daily_review.py --daily --limit 40
```

Default save directory:

```text
data/reports/triage/
```

Main dependencies:

- `db/migrate.py`
- `scripts/refresh_all_sources.sh`
- `scripts/ingest_recent_core_db.sh`
- `sync.fetch_hot`
- `sync.feed_quality`
- `scripts/triage_new_cves.py`
- `scripts/codex_triage_review.py` when Codex review is enabled
- `scripts/deep_dive.py` when watch-now deep dives are enabled
- `app/scoring.py` for the current hot watchlist

Important behavior:

- `--daily` enables source refresh, recent ingest, hot refresh, Codex review,
  and watch-now deep dives.
- If `refresh_all_sources.sh` runs first, the wrapper passes
  `SKIP_MIRROR_REFRESH=1` into `ingest_recent_core_db.sh` so mirrors are not
  refreshed twice.
- The cutoff defaults to the previous successful `cve_program` fetch. That makes
  the review focus on what changed since the prior successful ingest.
- The saved JSON includes command tails, step status, feed quality, triage,
  `watch_list`, `hot_watchlist`, optional `deep_dives`, and context review
  metrics.

Use this when:

- It is the first daily operation run.
- You want current data, not only a report from already-current data.
- You need the audit trail for source refresh, ingest, and hot refresh.

Do not use this when:

- The feeds have already been refreshed and ingested, and you only want another
  operator view. Use `report_recent_attention.py` or `run_daily_review.py`
  without `--daily`.

## Recent Attention

Default command:

```bash
uv run python scripts/report_recent_attention.py --days 7 --as-of 2026-07-17T00:00:00+00:00
```

Default save directory:

```text
data/reports/attention/
```

Main dependencies:

- `db/migrate.py`
- `db/core.db`
- `scripts/triage_new_cves.py`
- `app/scoring.py`
- `epss_current`
- `signals`
- `fetch_log` for feed watermarks

Important behavior:

- It does not refresh mirrors.
- It does not ingest feeds.
- It does not refresh hot evidence.
- It prints a Markdown table to the CLI and saves a JSON artifact unless
  `--no-save` is passed.
- It includes date columns:
  - `watch_now`: `published`, `first_seen`
  - `hot`: `observed`, `published`, `first_seen`
- Pin `--as-of` to reproduce the same relative window against the same local DB
  state.
- For full reproducibility after the DB changes, use the saved JSON artifact as
  the source of truth.

Use this when:

- Daily data refresh already happened.
- You want a concise, date-columned list of notable vulnerabilities.
- You want a report that can be re-rendered from a pinned `--as-of` and saved
  JSON.

## Codex Review Logs

Save directory:

```text
data/reports/triage/llm_reviews/
```

These are not primary operator reports. They exist to explain and audit context
review decisions such as suppressing a CVSS-only candidate.

Each log can include:

- command
- prompt
- response
- stdout / stderr
- return code
- request summary
- timing

Use these when:

- A candidate was suppressed and the reason needs review.
- You need to verify that Codex did not suppress KEV or exploit-backed items.
- You need root-cause context for noisy watchlist decisions.

## Reproducibility Rules

1. Pin the time window when the report needs to be reproducible:

   ```bash
   uv run python scripts/report_recent_attention.py \
     --days 7 \
     --as-of 2026-07-17T07:00:31+00:00
   ```

2. Preserve the saved JSON. If `core.db` changes later, the saved JSON is the
   exact artifact that was shown to the operator.

3. For reports generated after feed refresh, keep the daily review JSON because
   it records step status and command tails.

4. Use `--no-save` only for temporary CLI inspection.

5. Avoid using free-form assistant summaries as the system of record. The
   reproducible record is the JSON artifact plus the command arguments.

## Choosing a Report

| Need | Use |
|---|---|
| Run the full daily operation from external sources to operator output | `run_daily_review.py --daily` |
| Re-run a daily-style view from the existing DB | `run_daily_review.py --limit 40` |
| Show the last 7 days of notable vulnerabilities with date columns | `report_recent_attention.py --days 7 --as-of <time>` |
| Explain why a candidate was suppressed | `data/reports/triage/llm_reviews/*.json` |
| Debug raw deterministic triage candidate selection | `triage_new_cves.py --since <time> --json` |
| Investigate one CVE deeply | `deep_dive.py CVE-... --json` |
| Inspect current hot evidence only | `python -m app.skills hot --details` |
