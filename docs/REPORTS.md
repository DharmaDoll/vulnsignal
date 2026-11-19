# Reports

This document defines the report types, their purpose, dependencies, side
effects, and storage locations.

The short version:

- Use `scripts/refresh_intelligence.py --refresh --save` when you want to refresh data and
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
  -> scripts/refresh_intelligence.py
       -> data/reports/triage/*.json
       -> data/reports/triage/llm_reviews/*.json

db/core.db
  -> scripts/report_recent_attention.py
       -> data/reports/attention/*.json
```

`refresh_intelligence.py --refresh --save` is allowed to mutate local data because it is the
intelligence update entry point. `report_recent_attention.py` is read-only with respect
to vulnerability data; it only runs migrations and writes its own report file.

## Report Types

| Report | Command | Saves to | Updates feeds or DB? | Purpose |
|---|---|---|---|---|
| Daily review | `uv run python scripts/refresh_intelligence.py --refresh --save --limit 40` | `data/reports/triage/*.json` | Yes | End-to-end daily operator run: refresh sources, ingest recent data, refresh hot, triage new CVEs, optionally review and deep-dive. |
| Daily review, report-only | `uv run python scripts/refresh_intelligence.py --limit 40` | `data/reports/triage/*.json` | No feed refresh; runs migrations | Re-run the daily review view from the existing `core.db` without mirror refresh, ingest, or hot refresh. |
| Recent attention | `uv run python scripts/report_recent_attention.py --days 7 --as-of <ISO8601>` | `data/reports/attention/*.json` | No feed refresh; runs migrations | Reproducible recent watchlist with date columns for operator-facing review. |
| Codex triage review log | Produced by `--codex-review` | `data/reports/triage/llm_reviews/*.json` | No direct feed updates | Audit trail for context review decisions, including suppress reasons. |
| Manual triage JSON | `uv run python scripts/triage_new_cves.py --since <ISO8601> --json` | stdout only | No, except migration | Low-level deterministic triage output. Use when debugging candidate selection. |
| Deep dive JSON | `uv run python scripts/deep_dive.py CVE-... --json` | stdout only | No, except optional targeted hot refresh when requested by that tool | Single-CVE investigation. When daily review deep-dives watch items, the result is embedded in the daily JSON. |
| Hot CLI view | `uv run python -m app.skills hot --limit 20 --details` | stdout only | No, unless `--vuln-id` triggers targeted refresh | Inspect current hot evidence from `core.db`. |

## Intelligence Refresh and Daily Review

Default command:

```bash
uv run python scripts/refresh_intelligence.py --refresh --save --limit 40
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

- `--refresh --save` enables source refresh, recent ingest, hot refresh, Codex review,
  and watch-now deep dives.
- Source refresh and other long-running commands stream their live output to the
  terminal while still saving stdout/stderr tails into the report JSON.
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
  operator view. Use `report_recent_attention.py` or `refresh_intelligence.py`
  without `--refresh --save`.

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
| Run the full daily operation from external sources to operator output | `refresh_intelligence.py --refresh --save` |
| Re-run a daily-style view from the existing DB | `refresh_intelligence.py --limit 40` |
| Show the last 7 days of notable vulnerabilities with date columns | `report_recent_attention.py --days 7 --as-of <time>` |
| Explain why a candidate was suppressed | `data/reports/triage/llm_reviews/*.json` |
| Debug raw deterministic triage candidate selection | `triage_new_cves.py --since <time> --json` |
| Investigate one CVE deeply | `deep_dive.py CVE-... --json` |
| Inspect current hot evidence only | `python -m app.skills hot --details` |

## 期間別推薦の並行評価

日次の明示エクスポート（--refresh --save）は同じ実行の従来トリアージ結果と新方式の入力を圧縮JSONに保存する。単独集計は `python -m scripts.period_recommendations` を使う。`--period day|week|month|quarter`、`--date YYYY-MM-DD`、`--timezone`、オフセット付き `--as-of` を指定できる。各期間は開始を含み、終了・締切を含まない。`--json` は推薦根拠と観測欠損区間の詳細を出力する。月報・四半期報には前期の代表案件、テーマ別件数、比較可否を含む。

`--replay FILE` はDBやネットワークを使わず保存内容を再計算する。同じ入力で `--themes FILE` または `--exclude-feed FEED` を指定すると、登録テーマや採用ソースを変えた結果を別のファイルに保存する。資料の観測時刻は取り込み時刻であり、初回公表の証拠には公表日・KEV追加日など出典側の日付を使う。

比較評価では `python -m scripts.evaluate_recommendations prompt SNAPSHOT` が固定プロンプトと対象期間・判断締切を出力する。簡易プロンプトの上位IDをJSON配列に保存し、`prepare SNAPSHOT --simple-result IDS.json --output-dir REVIEW_DIR` で方式名を伏せた評価票を生成する。単独集計には同じ締切の従来方式のID配列を `--baseline` で渡す。読者が評価票の worth_reading、出典整合性 source_supported と独立に選んだ重要案件一覧 independent_watchlist を記入し、`score REVIEW_DIR/ballot.json REVIEW_DIR/methods.json` で的中率・掲載件数・見逃しを集計する。判定に使う事実は当日の締切までに公表されたものに限る。
