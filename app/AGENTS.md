# AGENTS.md — app/

You are working inside the decision and API layer.

## Responsibilities of this directory

- Implement risk scoring (`scoring.py`)
- Expose Skills API via FastAPI (`api.py`, `skills.py`)
- Run scheduled jobs (`scheduler.py`)

## Rules specific to this layer

- `app/` must never import from `sync/trivy_adapter.py` or `sync/exploit_adapter.py` directly
- Read signals from `db/core.db` — do not re-fetch from external sources
- All scoring must use the v1 formula defined in `docs/SCORING.md` — no ad-hoc weights
- Store `scoring_version = "v1"` on every decision record written
- Skills API responses must include `data_freshness` metadata so callers can detect stale data

## Scoring implementation reference

See `docs/SCORING.md` for the full formula, component table, and VEX suppression logic.

## Key invariants

- `top_risks()` must exclude VEX `not_affected` suppressions from results
- `recommend_patch_queue()` must order by `risk_score DESC`, then `kev_present DESC`
- `data_freshness()` must read from `fetch_log` table, not from system clock estimates
