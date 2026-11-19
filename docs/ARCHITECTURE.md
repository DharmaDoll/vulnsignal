# ARCHITECTURE.md

## Project philosophy

Lean AI-native vulnerability intelligence platform. SQLite-first. Python ingestion jobs. Minimal dependencies.

VulnSignal recommends which vulnerabilities merit attention over a day, week, month or quarter. The global ranking uses observed changes in source evidence. Registered technology themes match stored evidence after ingestion. Internal asset matching and patch queues are frozen. The recommendation rollout and acceptance criteria are in [the recommendation plan](RECOMMENDATION_PLAN.md).

-----

## System overview

通常更新は `scripts/refresh_intelligence.py --refresh` が担当する。Agent は更新済みのローカル DB を対話の都度検索し、回答の根拠を元の観測までたどれる。

```text
Git mirrors (CVE Program / GHSA / Vulnrichment) ----+
HTTP feeds  (CISA KEV / FIRST EPSS / hot web intel) +--> sync/ fetch + normalize
go-exploitdb --> db/exploit.db --> exploit_adapter -+             |
                                                                 v
db/core.db
  |
  +-- Source data
  |     vulnerabilities    vulnerability IDs and metadata
  |     signals            append-only observations, each with a signal ID
  |     epss_current       latest EPSS probability, percentile and date
  |     fetch_log          feed run status and freshness
  |
  +-- Intelligence mart (scripts.intel refresh reads signals incrementally)
        intel_evidence     provider and title linked to the original signal
        intel_terms        FTS5 index of product names and textual mentions
        intel_event        events such as KEV listing or a PoC reference
        intel_cvss         score history by provider, advisory and CVSS version
        intel*_state       refresh checkpoints
              |
              v
       scripts.intel search <--- period, theme (React / Java / PostgreSQL), event type, CVE
              |              +-- current EPSS and feed freshness at query time
              v
       Agent answer ---------> scripts.intel evidence <signal_id>
                                       |
                                       v
                               original observation in signals
```

- **期間とテーマ**　日・週・月・四半期の問いは検索期間に展開する。公開元の日付とローカルでの観測時刻を選べるため、「今週公表された情報」と「今週新たに把握した情報」を区別できる。登録テーマは取得後に検索索引と照合する。
- **スコアの読み方**　同じ脆弱性・提供元・アドバイザリ・CVSS バージョンの評価を比較し、上昇・下降を `intel_event` に記録する。EPSS は最新スナップショットを検索時に参照するため、任意の過去日の確率を再現できるとは限らない。
- **任意の出力**　期間別レポートや再現用アーカイブが必要な場合は `scripts/period_recommendations.py` を利用できる。通常の日次更新はデータマートの更新で完了する。Trivy の取り込みと内部資産との照合は日次経路から外している。

運用コマンドの役割と実行タイミングは [COMMANDS.md](COMMANDS.md)、検索例は [README](../README.md)、マートのテーブル定義は [SCHEMA.md](SCHEMA.md#searchable-intelligence-mart-migration-010) を参照。

-----

## Database strategy

### core.db (primary)

All normalized data lives here. Tables: `vulnerabilities`, `assets`, `asset_observations`, `findings`, `decisions`, `signals`, `epss_current`, `report_history`, `fetch_log`.

`report_history` is used to dedupe alert delivery runs. The core report/ranking
outputs remain complete; only notification channels like Slack should consult
the history table to skip previously sent vulnerabilities.

### External DBs (read-only, separate files)

- `db/exploit.db` — go-exploitdb (accessed only via `sync/exploit_adapter.py`)
- `db/trivy_cache.db` — Trivy DB cache for optional backfill (accessed only via `sync/trivy_adapter.py`)

Use `ATTACH DATABASE` for cross-DB queries only when necessary. ETL summaries into `core.db` are preferred.

-----

## Key design decisions

**Signals are append-only.** Never update or delete signal records once emitted. High-volume current-state feeds such as EPSS use dedicated current tables and only append material changes to `signals`.

**Adapters isolate external schema churn.** Both Trivy DB and go-exploitdb have broken their schemas across versions. All external DB access goes through adapter modules with schema version pinning.

**Trust hierarchy over last-write-wins.** Multiple feeds may report conflicting severity data. The recommendation engine considers evidence from approved providers and records their provenance. The CVE Program is the canonical CVE identifier/reference backbone; NVD is optional enrichment in the current phase. See `FEEDS.md`.

**Coarse asset observations are useful.** Keep weaker observations like `Ubuntu 22` or `Nuxt.js` as append-only evidence when exact versions are unknown.

**VEX is a hard suppression.** A vendor `not_affected` assertion overrides CVSS/KEV signals and excludes the item from ranking. Not a soft weight — a business decision.

**Scoring is versioned.** Formula changes increment `scoring_version`. Historical decisions remain interpretable.

-----

## Non-goals (current phase)

- Full vulnerability scanner
- Full CMDB / asset discovery
- Auto-patching
- Slack/Teams automation (separate repo if needed)
- Executive dashboards (separate repo if needed)
- Multi-tenant mode
- HTTP API surface in the current phase

A Long-Term Expansion module is only in scope if it **produces a signal that improves risk scoring**.
