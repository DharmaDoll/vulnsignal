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
 ├ Trivy DB     — vulnerability metadata enrichment
 ├ go-exploitdb — PoC/exploit presence and maturity
 ├ VEX/CSAF     — vendor not-affected assertions
 └ Vulnrichment — supplemental enrichment
        ↓
Fetch / Normalize Layer  (sync/)
        ↓
SQLite core.db           (db/)
        ↓
Decision Engine          (app/scoring.py)
        ↓
Skills API               (app/api.py)
```

-----

## Database strategy

### core.db (primary)

All normalized data lives here. Tables: `vulnerabilities`, `assets`, `findings`, `decisions`, `signals`, `fetch_log`.

### External DBs (read-only, separate files)

- `db/exploit.db` — go-exploitdb (accessed only via `sync/exploit_adapter.py`)
- `db/trivy_cache.db` — Trivy DB cache (accessed only via `sync/trivy_adapter.py`)

Use `ATTACH DATABASE` for cross-DB queries only when necessary. ETL summaries into `core.db` are preferred.

-----

## Key design decisions

**Signals are append-only for emitted events.** Never update or delete signal records once emitted. High-volume current-state feeds such as EPSS use dedicated current tables and only append risk-relevant events or material changes to `signals`.

**Adapters isolate external schema churn.** Both Trivy DB and go-exploitdb have broken their schemas across versions. All external DB access goes through adapter modules with schema version pinning.

**Trust hierarchy over last-write-wins.** Multiple feeds may report conflicting severity data. Resolution is deterministic and starts with GHSA, Vulnrichment, and Trivy JSON. The CVE Program is the canonical CVE identifier/reference backbone; NVD is optional enrichment in the current phase. See `FEEDS.md`.

**Coarse asset observations are useful.** Exact package versions are ideal, but the platform should still retain weaker observations like `Ubuntu 22` or `Nuxt.js` as append-only evidence. They are not CMDB truth, but they are strong enough to improve prioritization when version-level inventory is incomplete.

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

A Long-Term Expansion module is only in scope if it **produces a signal that improves risk scoring**. Workflow and reporting concerns belong elsewhere.
