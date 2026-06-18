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
free-form one-off summary. If the intent is ambiguous, prefer the shortest
actionable vulnerability list over a dashboard-style report.

## Fast list mode

If the user asks for a quick or simple vulnerability list, or says things like
"必要な脆弱性一覧だけ", skip the full analytical sections and return only the
minimum rows needed to act.

In fast list mode:

1. Use the same bounded cutoff, but only compute the rows needed for the list.
2. Return at most 10-20 vulnerabilities.
3. Keep columns to:
   - `vuln_id`
   - `title`
   - `source`
   - `published_at`
   - `first_seen_at`
   - `CVSS`
   - `EPSS`
   - `signals`
   - one short reason
4. Prefer `exploit`, `kev`, `hot`, or high-EPSS rows when the user wants
   "important" items.
5. Do not include year-by-year trend, source mix, severity mix, or overlap
   unless the user explicitly asks for them.

## Daily latest-30 mode

Use this when the user says things like "today 時点", "今日時点", "最新順", or
"注目すべきものを30件". This is the canonical short report.

1. Compute an explicit cutoff at the start of the current day in the local
   report timezone.
2. Exclude boundary/network appliance vendors by default.
3. Return exactly the newest 30 vuln_ids by `first_seen_at DESC` unless the user
   asks for a different ranking.
4. Keep the output compact:
   - `vuln_id`
   - `title`
   - `source`
   - `published_at`
   - `first_seen_at`
   - `CVSS`
   - `EPSS`
   - `signals`
   - one short reason
5. Prefer rows with `kev`, `exploit`, `hot`, or high EPSS when multiple items
   share the same recency.
6. Do not expand into trend/source/severity sections unless explicitly asked.

## Pinpoint watchlist mode

Use this when the user asks for "注目の脆弱性", "more pinpoint", "important
vulnerabilities", or similar wording and wants fewer false positives than a
plain latest list.

1. Use a 7-day cutoff by default unless the user specifies a different window.
2. Keep only vulnerabilities that meet at least one of:
   - `kev`
   - `exploit`
   - `hot`
   - `cvss_score >= 9.0`
   - `epss >= 0.05`
3. Prefer 10-30 rows, sorted by the same general-impact score used elsewhere.
4. If the result set becomes too small, expand only by relaxing EPSS slightly,
   not by reintroducing pure recent rows first.
5. Keep the output compact and actionable. If a row has no strong signal, do not
   include it in this mode.

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
3. Needed vulnerabilities only
4. Coverage and gaps
5. Short conclusion

For the daily latest-30 mode, collapse this to:

1. Scope and cutoff
2. Latest 30 vulnerabilities
3. Short conclusion

For pinpoint watchlists, use:

1. Scope and cutoff
2. Pinpoint watchlist
3. Short conclusion

For full analysis requests, expand back to the detailed sections in the
reference queries.

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

For a quick exploit list, return only the ranked table and skip the broader
dataset summary.

## Hot signal handling

- Treat `hot` as an early-attention signal, not as the main risk score.
- Use a practical detection target of about 4 days from `first_seen_at`.
- When a report includes `hot`, present it as a separate watchlist or reference-only block unless the user explicitly asks to rank by hot attention.
- In fast list mode, include `hot` only if it is directly relevant to the user's ask.

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
