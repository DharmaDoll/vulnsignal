-----

## name: scoring
description: >
Use when implementing or modifying the risk scoring engine (app/scoring.py),
changing score weights or components, adding new signal types to scoring logic,
or debugging why a CVE’s score looks wrong.
Triggers on: “implement scoring”, “fix score”, “add scoring component”,
“why is this score X”, “scoring formula”, “risk_score”, “scoring_version”.

# Skill: scoring

## Always read first

`docs/SCORING.md` — contains the canonical v1 formula and all component weights.
Do not implement scoring logic from memory. Read the doc, then code.

## Formula summary (do not use as source of truth — read SCORING.md)

```
risk_score = min(100, round(
    cvss_component      # cvss_score * 4.0,  max 40
  + epss_component      # epss_score * 20.0, max 20
  + kev_bonus           # 15 if KEV, else 0
  + exploit_bonus       # 10 if exploit signal exists, else 0
  + exposure_bonus      # 10 if asset exposed=1, else 0
  + criticality_bonus   # critical=10, high=7, medium=3, low=0
  - vex_suppression     # 40 if VEX not_affected, else 0
))
```

## Critical implementation rules

- Signal lookups: always take the **latest** per `(vuln_id, signal_type)` ordered by `observed_at DESC`
- VEX `not_affected` is a **hard suppression** — not a multiplier, not optional
- NULL cvss_score → use 0, do not skip scoring
- NULL epss_score → use 0, do not skip scoring
- Always write `scoring_version = "v1"` on every `findings` and `decisions` row
- Never invent weights — if the formula needs updating, bump the version in SCORING.md first

## Common mistakes to avoid

- Do NOT query raw signals table without the `ORDER BY observed_at DESC LIMIT 1` guard
- Do NOT apply VEX suppression as a multiplier — it is a flat subtraction of 40
- Do NOT recalculate historical decisions when formula changes — old rows keep their version tag
