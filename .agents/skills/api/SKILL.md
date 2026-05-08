---
name: api
description: >
  Use when implementing or modifying the FastAPI Skills API (app/api.py,
  app/skills.py).
  Triggers on: “implement API”, “add endpoint”, “Skills API”, “find_vuln”,
  “top_risks”, “has_exploit”, “affected_assets”, “recommend_patch_queue”,
  “explain_asset_risk”, “data_freshness”, “FastAPI”, “skills.py”.
---

# Skill: api

## Target Skills API surface

Implement all endpoints as FastAPI routes. Each maps to a function in `app/skills.py`.

```python
GET /vuln/{vuln_id}              → find_vuln(vuln_id)
GET /risks?limit=N               → top_risks(limit)
GET /vuln/{vuln_id}/has_exploit  → has_exploit(vuln_id)
GET /vuln/{vuln_id}/assets       → affected_assets(vuln_id)
GET /patch-queue                 → recommend_patch_queue()
GET /assets/{hostname}/risk      → explain_asset_risk(hostname)
GET /freshness                   → data_freshness()
```

## Invariants for each skill

**top_risks()**

- Exclude findings with VEX `not_affected` suppression
- Order by `risk_score DESC`
- Default limit: 20

**recommend_patch_queue()**

- Order: `risk_score DESC`, then `kev_present DESC`
- Only include findings with `status = 'open'`
- Include `rationale` field explaining score components

**data_freshness()**

- Read from `fetch_log` table — never estimate from system clock
- Return latest `attempted_at` and `status` per feed
- Flag feeds exceeding staleness threshold (see `docs/FEEDS.md`)

**explain_asset_risk()**

- Include per-finding score breakdown (which components contributed)
- Include `scoring_version` in response

## Response contract

All responses must include:

```json
{
  "data": ...,
  "meta": {
    "scoring_version": "v1",
    "generated_at": "<ISO8601>"
  }
}
```

## Rules

- `app/` must never import from `sync/trivy_adapter.py` or `sync/exploit_adapter.py`
- Read signals from `db/core.db` only — never re-fetch from external sources
- All DB access via parameterized queries — no string interpolation in SQL
