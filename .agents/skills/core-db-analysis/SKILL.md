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
3. Use a bounded window for "recent" analysis. Prefer `published_at >= date('now', '-3 years')` or the equivalent explicit ISO cutoff.
4. Summarize the same core views every time:
   - total vulnerable records in scope
   - year-by-year trend
   - source mix
   - severity mix
   - signal mix by `signal_type`
   - overlap between `enrichment`, `package_advisory`, `exploit`, `kev`, and `epss`
   - CVSS coverage by source
   - notable high-risk examples
   - caveats and gaps
5. Keep conclusions tied to the query results. Do not infer asset impact unless
   `assets` and `findings` exist in the DB.

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

## Guardrails

- Do not query external feeds.
- Do not invent values when `assets` or `findings` are absent.
- Do not mix raw feed counts with distinct vuln_id counts without labeling the difference.
- If the user asks for "last 3 years", use an explicit ISO cutoff derived from the current date.

## Reference queries

See `references/report-queries.md` for the canonical SQL pack and report checklist.
