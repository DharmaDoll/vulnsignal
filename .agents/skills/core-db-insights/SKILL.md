---
name: core-db-insights
description: >
  Use when the user wants an insight-oriented report from db/core.db that goes
  beyond counts: concentration, coverage gaps, signal quality, source overlap,
  and actionable vulnerability intelligence patterns over a bounded time window.
---

# Skill: core-db-insights

## Always read first

`docs/FEEDS.md`, `sync/feed_quality.py`, `docs/SCORING.md`, and
`app/scoring.py`. Run `db/migrate.py` before reading the database.

## Goal

Produce a report that answers:

- Where is the risk concentrated?
- Which sources are carrying the analysis?
- Which records are richly supported versus weakly supported?
- Which signal combinations are strongest?
- What gaps limit confidence?
- What should be prioritized first if assets exist?

## Required workflow

1. Run `db/migrate.py`.
2. Determine an explicit cutoff for the requested window.
3. Read `db/core.db` only.
4. Compute both counts and derived insights.
5. Separate distinct `vuln_id` counts from raw signal counts.
6. If `assets` and `findings` exist, include scoring-oriented observations; otherwise say they are absent.

## Report filter policy

- For report output, exclude boundary/network appliance vulnerabilities by
  default unless the user explicitly asks to include them.
- Treat vendors such as `Cisco`, `Palo Alto`, `Fortinet`, `Juniper`, `F5`,
  and similar perimeter appliance families as out of scope for the default
  report view.
- Keep the underlying records and scores intact; this is a presentation filter,
  not a data deletion or scoring change.
- If the user asks for boundary-device analysis explicitly, include them in a
  separate, clearly labeled section.

## Mandatory insight sections

Include these sections in the report:

1. Scope and cutoff
2. Dataset composition
3. Concentration and skew
4. Signal strength matrix
5. Coverage and completeness
6. Notable outliers
7. Operational implications
8. Caveats

## Insight rules

- Treat `enrichment + epss` as baseline context, `package_advisory` as remediation context, and `exploit` / `kev` as escalation signals.
- Highlight when one source dominates the corpus.
- Highlight when many records lack `severity` or `cvss_score`.
- Highlight when `package_advisory` is present without `enrichment`, or vice versa.
- Highlight when `exploit` or `kev` is rare but concentrated on a small set of vuln_ids.
- If `findings` exists, mention how many findings would be suppressible by VEX `not_affected`.
- Apply the report filter policy above before presenting default results.

## Derived metrics to compute

- source share of recent `vulnerabilities`
- year-over-year trend within the window
- severity distribution, including missing / unknown
- CVSS coverage by source
- distinct vuln_ids with each signal type
- signal combination matrix for recent vuln_ids
- recent rows with `exploit` or `kev`
- recent rows with `package_advisory` and no `cvss_score`
- if `findings` exists: top findings by `risk_score`, count of `open` findings, and count of suppressed findings

## Output style

Write a concise report with short bullets and concrete numbers. Prefer:

- counts
- percentages
- ratios
- a few representative vuln_ids
- one-line interpretation after each metric block
- include both `published_at` and `first_seen_at` for representative and ranked vulnerability examples

Do not write generic prose without supporting numbers.

## Reference queries

Use `references/insight-queries.md` as the canonical SQL pack for the above.
