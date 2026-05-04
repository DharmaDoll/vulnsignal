## What this project is

Lean vulnerability intelligence platform. Ingests external feeds (NVD, KEV, EPSS, Trivy DB, go-exploitdb, VEX, Vulnrichment), normalizes them into signals, and produces risk-scored remediation priorities.

**Not a scanner. Not a CMDB. A signal aggregation + decision engine.**

Full architecture: `docs/ARCHITECTURE.md`

---

## Absolute rules

- **Never query external DBs directly.** All access to Trivy DB and go-exploitdb must go through their adapter modules (`sync/trivy_adapter.py`, `sync/exploit_adapter.py`).
- **Never delete signal history.** Signals table is append-only. Use `observed_at` for ordering.
- **Never overwrite higher-trust data with lower-trust data.** See trust hierarchy in `docs/FEEDS.md`.
- **Always run `db/migrate.py` before any DB operation in tests or scripts.**
- **Never let raw external DB column names leak outside adapter files.**
- **On fetch failure, fall back to cached data. Never leave DB empty.**

---

## Repository layout

```
project/
├── AGENTS.md                  ← you are here
├── docs/
│   ├── ARCHITECTURE.md        ← design decisions, philosophy
│   ├── SCHEMA.md              ← full table definitions
│   ├── SCORING.md             ← risk score formula v1
│   └── FEEDS.md               ← per-feed specs, trust hierarchy, adapter contracts
├── app/
│   ├── api.py                 ← FastAPI Skills API
│   ├── skills.py              ← skill implementations
│   ├── scoring.py             ← scoring engine
│   └── scheduler.py           ← cron/job runner
├── sync/
│   ├── fetch_nvd.py
│   ├── fetch_kev.py
│   ├── fetch_epss.py
│   ├── fetch_trivy.py
│   ├── fetch_vex.py
│   ├── fetch_vulnrichment.py
│   ├── trivy_adapter.py       ← Trivy DB isolation layer
│   └── exploit_adapter.py     ← go-exploitdb isolation layer
├── db/
│   ├── migrate.py             ← migration runner (run first)
│   └── core.db                ← main database
├── sql/
│   ├── schema.sql
│   ├── indexes.sql
│   └── migrations/            ← NNN_description.sql
└── config/
    └── settings.yaml
```

---

## Build order for new implementations

1. `sql/migrations/001_initial_schema.sql` + `db/migrate.py`
2. `sync/exploit_adapter.py` and `sync/trivy_adapter.py`
3. Fetch jobs — each with retry/backoff + `fetch_log` writes
4. `app/scoring.py` — implement v1 formula from `docs/SCORING.md`
5. `app/skills.py` + `app/api.py` — FastAPI Skills API
6. Tests
7. `data_freshness()` endpoint

---

## Skills API surface (target)

```python
find_vuln(vuln_id)
top_risks(limit)
has_exploit(vuln_id)
affected_assets(vuln_id)
recommend_patch_queue()
explain_asset_risk(hostname)
data_freshness()
```

---

## When to read docs/

| You are working on... | Read |
|---|---|
| Scoring logic / weights | `docs/SCORING.md` |
| Any fetch job or adapter | `docs/FEEDS.md` |
| Schema / migrations | `docs/SCHEMA.md` |
| Architecture decisions | `docs/ARCHITECTURE.md` |
