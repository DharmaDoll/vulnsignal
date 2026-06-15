---
name: core-db-analysis
description: >
  Use when generating a reproducible analysis report from db/core.db, especially
  for recent vulnerability trends, feed quality, signal overlap, severity mix,
  and operational summaries over a bounded time window such as the last 3 years.
---

# Skill: core-db-analysis

## Always read first

`docs/FEEDS.md` and `sync/feed_quality.py` for feed semantics, signal names, and
quality metrics. `db/migrate.py` must run before any DB read if the database may
be stale or newly created.

## Scope

Use this skill when the user wants a repeatable report from `db/core.db`, not a
free-form one-off summary.

## Required workflow

1. Run `db/migrate.py`.
2. Open `db/core.db` with read-only SQL.
3. Use a bounded window for "recent" analysis. Prefer `first_seen_at >= date('now', '-3 years')` or the equivalent explicit ISO cutoff.
4. Summarize the same core views every time:
   - total vulnerable records in scope
   - year-by-year trend
   - source mix
   - severity mix
   - signal mix by `signal_type`
   - overlap between `enrichment`, `package_advisory`, `exploit`, `kev`, and `epss`
   - EPSS coverage and representative EPSS values for notable vulnerabilities
   - CVSS coverage by source
   - notable high-risk examples
   - caveats and gaps
5. Keep conclusions tied to the query results. Do not infer asset impact unless
   `assets` and `findings` exist in the DB.

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

## Output shape

Use this structure:

1. Scope and cutoff
2. Dataset size
3. Trend summary
4. Source mix
5. Severity mix
6. Signal overlap
7. Coverage and gaps
8. Representative examples
9. Short conclusion

## Recent asset-hit risks

Use this recipe when the user asks for vulnerabilities "that hit assets",
"asset impact order", or similar phrasing.

1. Run the standard recent-window analysis first.
2. If `findings` has rows, rank by `risk_score` and report the matching assets.
3. If `findings` is empty, use `assets` plus `asset_observations` to infer coarse matches:
   - prefer exact product, framework, middleware, software, or runtime name matches
   - treat specific OS matches as weaker signals
   - add `exposed = 1` and higher `criticality` as tie-breakers
4. Always show:
   - `published_at`
   - `EPSS`
   - the matched asset or `asset hit: none`
   - the match reason when inferred from observations
5. Keep the ranking explicit as a heuristic when `findings` is absent.

## Recent exploit risks

Use this recipe when the user asks for "notable exploits", "exploit-priority
vulnerabilities", or similar phrasing without asking about a specific asset.

1. Use a half-year cutoff unless the user specifies a different window.
2. Restrict to vulnerabilities with an `exploit` signal.
3. Rank by general impact, not asset impact:
   - `cvss_score * 4.0`
   - `epss_score * 20.0`
   - `+15` for `kev`
   - `+10` for `exploit`
4. Always show:
   - `published_at`
   - `EPSS`
   - `signals` (`kev`, `exploit`)
   - the computed score
5. Do not include asset terms unless the user explicitly asks for asset impact.

## Hot signal handling

- Treat `hot` as an early-attention signal, not as the main risk score.
- Use a practical detection target of about 4 days from `first_seen_at`.
- When a report includes `hot`, present it as a separate watchlist or reference-only block unless the user explicitly asks to rank by hot attention.

EPSS requirement:

- Every report must include EPSS values for notable vulnerabilities.
- If a vulnerability has an `epss_current` row, show the numeric EPSS value.
- If a vulnerability has no EPSS row, state `EPSS: missing` explicitly.
- Every ranked vulnerability list and representative example must include `published_at` and `first_seen_at`.
- Use an explicit date/time format when showing `published_at` and `first_seen_at`; do not omit them.

## Guardrails

- Do not query external feeds.
- Do not invent values when `assets` or `findings` are absent.
- Do not mix raw feed counts with distinct vuln_id counts without labeling the difference.
- If the user asks for "last 3 years", use an explicit ISO cutoff derived from the current date.
- Include EPSS in ranked vulnerability lists and representative examples.
- Apply the report filter policy above before presenting default results.

## Reference queries

See `references/report-queries.md` for the canonical SQL pack and report checklist.
