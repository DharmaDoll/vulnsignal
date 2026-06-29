# ARCHITECTURE.md

## Project philosophy

Lean AI-native vulnerability intelligence platform. SQLite-first. Python ingestion jobs. Minimal dependencies.

**Not a scanner. Not a CMDB.** A data aggregation + risk decision engine that answers:

1. What is exploitable right now?
1. What affects our important assets?
1. What should we patch this week?
1. What can be safely deprioritized?

Optimize for 80/20 outcomes. Speed and clarity over completeness.

-----

## System overview

```
External Feeds
 ├ CVE Program  — canonical CVE reference
 ├ KEV          — known exploited vulnerabilities
 ├ EPSS         — exploit probability scores
 ├ GHSA         — OSS package advisories and GHSA-only IDs
 ├ Trivy JSON / vuln-list — package advisories and scanner-aligned metadata
 ├ Trivy DB     — optional vulnerability metadata backfill
 ├ go-exploitdb — PoC/exploit presence and maturity
 ├ Hot web intel — current attention / exploitation signal
 ├ VEX/CSAF     — vendor not-affected assertions
 └ Vulnrichment — supplemental enrichment
        ↓
Fetch / Normalize Layer  (sync/)
        ↓
SQLite core.db           (db/)
        ↓
Decision Engine          (app/scoring.py)
        ↓
Skills CLI / workers     (app/skills.py)
```

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

**Trust hierarchy over last-write-wins.** Multiple feeds may report conflicting severity data. Resolution is deterministic and starts with GHSA, Vulnrichment, and Trivy JSON/vuln-list. The CVE Program is the canonical CVE identifier/reference backbone; NVD is optional enrichment in the current phase. See `FEEDS.md`.

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
