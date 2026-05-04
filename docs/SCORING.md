# SCORING.md

## Formula v1

```python
risk_score = min(100, round(
    cvss_component
  + epss_component
  + kev_bonus
  + exploit_bonus
  + exposure_bonus
  + criticality_bonus
  - vex_suppression
))
```

|Component          |Calculation                             |Max|
|-------------------|----------------------------------------|---|
|`cvss_component`   |`cvss_score * 4.0`                      |40 |
|`epss_component`   |`epss_score * 20.0`                     |20 |
|`kev_bonus`        |`15` if KEV signal present, else `0`    |15 |
|`exploit_bonus`    |`10` if exploit signal present, else `0`|10 |
|`exposure_bonus`   |`10` if asset `exposed = 1`, else `0`   |10 |
|`criticality_bonus`|critical=10, high=7, medium=3, low=0    |10 |
|`vex_suppression`  |`40` if VEX `not_affected`, else `0`    |—  |

## Implementation notes

- All signal lookups must use the **latest** signal per `(vuln_id, signal_type)` ordered by `observed_at DESC`
- VEX suppression is a hard override — a `not_affected` VEX brings any score ≤ 60 to near-zero effectively
- If `cvss_score` is NULL (NVD not yet enriched), use `0` — do not block scoring
- If `epss_score` is NULL (not yet fetched), use `0`
- Store `scoring_version = "v1"` on every `findings` and `decisions` row written

## Versioning policy

When the formula changes:

1. Increment version string (e.g. `"v2"`)
1. Create a new migration that adds any required columns
1. Do NOT retroactively recalculate old decisions — they stay as `v1`
1. New findings use the new version going forward
