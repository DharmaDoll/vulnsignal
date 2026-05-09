# ROADMAP.md

## Current Direction

The current phase is feed feasibility and local data quality. The goal is to prove that each source can provide useful, normalized vulnerability signals before building a heavier API or scoring layer.

Key decisions:

- NVD is optional enrichment, not a blocker for MVP ingestion.
- GHSA is a core feed.
- Trivy supports advisory JSON and direct DB ingestion.
- VEX `not_affected` excludes items from rankings.
- Assets are expected to start as CSV import, with the exact format still open.
- Feed quality should be judged with simple per-feed metrics and a combined operational assessment.

## Task Plan

|Status|Task|Exit criteria|
|---|---|---|
|Done|Initial schema and migration runner|`db/migrate.py` creates `core.db` with core tables and indexes|
|Done|Core fetch foundation|Common fetch/cache/log/signal helpers exist and write `fetch_log`|
|Done|KEV sample ingestion|Small KEV fetch writes `kev` signals|
|Done|EPSS bulk CSV ingestion|EPSS fetcher reads FIRST bulk CSV and upserts `epss_current`|
|Done|GHSA sample ingestion|Small GHSA fetch writes `enrichment` and `package_advisory` signals|
|Done|Trivy JSON importer|Sample advisory JSON produces `package_advisory` signals through `sync/trivy_adapter.py`|
|Done|Trivy DB importer|Compiled Trivy DB produces `enrichment` signals through `sync/trivy_adapter.py`|
|Done|Feed quality summary|A local command reports simple feed metrics from `core.db`|
|Done|go-exploitdb adapter|All go-exploitdb access goes through `sync/exploit_adapter.py` with schema validation|
|Done|go-exploitdb sample ingestion|Sample import writes `exploit` signals and records source URL/type when available|
|Done|go-exploitdb refresh wrapper|Local command wraps `go-exploitdb fetch` and validates resulting SQLite schema|
|Done|Trivy vuln-list fetcher|Fetch selected JSON trees from `aquasecurity/vuln-list` and pass them through `sync/trivy_adapter.py`|
|Done|GHSA pagination fix|Remove the sample-style row cap and fetch GHSA through full pagination or incremental updates|
|Done|Vulnrichment ingestion|Sample import writes severity/CVSS/summary enrichment without overwriting higher-trust data|
|Planned|Asset CSV importer|CSV import creates or updates `assets` with conservative defaults|
|Done|Minimal scoring/ranking|v1 scoring works from latest signals and ranking excludes VEX `not_affected`|
|Planned|Minimal Skills API|`find_vuln`, `top_risks`, `has_exploit`, and `data_freshness` work from local DB|

## Simple Feed Quality Metrics

Each feed should report:

- `rows_fetched`
- `signals_written`
- `vuln_id_coverage`
- `required_field_coverage`
- `duplicate_rate`
- `last_success_at`
- `staleness_status`

These metrics are intentionally simple. The final data quality judgment should combine them with manual inspection of representative samples.

Note: `rows_fetched` is currently returned by fetch commands but is not persisted in `fetch_log` yet.

High-volume current-state feeds should not append every row to `signals`. EPSS uses `epss_current`; `signals` should only receive material EPSS events later.

## Trivy Data Acquisition Plan

Trivy source data is available through two paths:

1. Raw advisory JSON from `aquasecurity/vuln-list`.
2. Compiled Trivy DB cache for direct vendor-normalized lookup.

Current implementation:

- reads from a local checkout or unpacked archive of `aquasecurity/vuln-list`
- reads from a local Trivy DB cache directory containing `trivy.db` and `metadata.json`
- starts with selected JSON targets only: `alpine`, `debian`, `ubuntu`, `ghsa`, `glad`, `go`, and `osv`
- sends all Trivy-shaped data through `sync/trivy_adapter.py`
- writes package advisory signals from Trivy JSON/vuln-list and vulnerability enrichment from Trivy DB to `core.db`
- reports field coverage for `ecosystem`, `package_name`, `affected_versions`, and `fixed_version`
- the local DB acquisition steps are documented in `docs/FEEDS.md`

Day 1 interpretation:

- `vuln-list` is optional unless package-range fidelity becomes the bottleneck.
- If the main job is to match against existing assets, Trivy JSON and other scanner-aligned feeds can be enough to start.
- Keep `vuln-list` as a quality-improvement path rather than a blocker for the first usable asset-to-vulnerability workflow.

All direct DB access stays inside `sync/trivy_adapter.py` and the dedicated Trivy DB dump helper under `cmd/trivydbdump/`.

## Open Questions

- Exact asset CSV columns and required fields.
- Whether GHSA `unreviewed` advisories should be included after reviewed advisories are stable.
- Whether GHSA should be fetched as full pagination or updated incrementally by `updated_at`.
- Whether to run all go-exploitdb sources by default or keep a smaller source set for routine refresh.
- Whether internal override should eventually become the highest-trust severity source.

## go-exploitdb Verification Notes

On 2026-05-06, `go-exploitdb fetch exploitdb` was verified with the v0.7.0 command installed under `/tmp`.

Observed results:

- `exploitdb` source fetched 60,578 Offensive Security records.
- 30,862 records had CVE IDs and were importable as `exploit` signals.
- SQLite tables included `exploits`, `fetch_meta`, `documents`, `offensive_securities`, `shell_codes`, `papers`, and `ghdbs`.
- `fetch_meta.schema_version` was `3`.

Routine refresh still needs a decision on whether to fetch only `exploitdb` or also `awesomepoc`, `githubrepos`, `inthewild`, and `nuclei`.

## go-exploitdb Insights

The current go-exploitdb behavior suggests the following:

- The database is not a single-purpose CVE table; it stores multiple source families, so adapter boundaries need to remain narrow.
- The CVE-linked subset is materially smaller than the raw Offensive Security feed, which matters for refresh cost and downstream signal density.
- `fetch_meta` is the stable place to read schema version from current builds.
- The project should treat `exploitdb` as the default operational source and add the auxiliary sources only when a use case justifies the extra volume.
