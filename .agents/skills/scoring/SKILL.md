-----

## name: scoring
description: Use when implementing or modifying the risk scoring engine in app/scoring.py. Triggers on tasks like “implement scoring”, “fix score calculation”, “add scoring component”, or any work touching risk_score or scoring_version.

Always read `docs/SCORING.md` before writing any scoring code.

Key constraints:

- Use formula v1 exactly as specified — no improvised weights
- All signal lookups: latest per (vuln_id, signal_type) ordered by observed_at DESC
- VEX not_affected is a hard suppression, not a multiplier
- Store scoring_version = “v1” on every findings and decisions row
- Return score as integer 0–100
