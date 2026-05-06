# ROADMAP.md

## Current Direction

The current phase is feed feasibility and local data quality. The goal is to prove that each source can provide useful, normalized vulnerability signals before building a heavier API or scoring layer.

Key decisions:

- NVD is optional enrichment, not a blocker for MVP ingestion.
- GHSA is a core feed.
- Trivy starts from advisory JSON. Direct DB ingestion is a later option.
- VEX `not_affected` excludes items from rankings.
- Assets are expected to start as CSV import, with the exact format still open.
- Feed quality should be judged with simple per-feed metrics and a combined operational assessment.

## Task Plan

|Status|Task|Exit criteria|
|---|---|---|
|Done|Initial schema and migration runner|`db/migrate.py` creates `core.db` with core tables and indexes|
|Done|Core fetch foundation|Common fetch/cache/log/signal helpers exist and write `fetch_log`|
|Done|KEV sample ingestion|Small KEV fetch writes `kev` signals|
|Done|EPSS sample ingestion|Small EPSS fetch writes `epss` signals|
|Done|GHSA sample ingestion|Small GHSA fetch writes `enrichment` and `package_advisory` signals|
|Done|Trivy JSON importer|Sample advisory JSON produces `package_advisory` signals through `sync/trivy_adapter.py`|
|Done|Feed quality summary|A local command reports simple feed metrics from `core.db`|
|Next|Trivy vuln-list fetcher|Fetch selected JSON trees from `aquasecurity/vuln-list` and pass them through `sync/trivy_adapter.py`|
|Planned|go-exploitdb adapter|All go-exploitdb access goes through `sync/exploit_adapter.py` with schema validation|
|Planned|go-exploitdb sample ingestion|Sample import writes `exploit` signals and records source URL/type when available|
|Planned|Vulnrichment ingestion|Sample import writes severity/CVSS/summary enrichment without overwriting higher-trust data|
|Planned|Asset CSV importer|CSV import creates or updates `assets` with conservative defaults|
|Planned|Minimal scoring/ranking|v1 scoring works from latest signals and ranking excludes VEX `not_affected`|
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

## Trivy Data Acquisition Plan

Use Trivy source data in two phases:

1. Fetch raw advisory JSON from `aquasecurity/vuln-list`.
2. Consider compiled Trivy DB v2 ingestion only if raw JSON is insufficient.

The next implementation should add a `vuln-list` fetcher that:

- reads from a local checkout or downloaded archive of `aquasecurity/vuln-list`
- starts with selected targets only: `alpine`, `debian`, `ubuntu`, `ghsa`, `glad`, `go`, and `osv`
- sends all Trivy-shaped data through `sync/trivy_adapter.py`
- writes only normalized `package_advisory` signals to `core.db`
- reports field coverage for `ecosystem`, `package_name`, `affected_versions`, and `fixed_version`

Compiled DB ingestion is intentionally later because it requires schema inspection and validation. If added, all direct DB access must stay inside `sync/trivy_adapter.py`.

## Open Questions

- Exact asset CSV columns and required fields.
- Whether GHSA `unreviewed` advisories should be included after reviewed advisories are stable.
- Whether Trivy `vuln-list` should be fetched by git clone, GitHub archive download, or a pinned local path.
- go-exploitdb schema version detection method.
- Whether internal override should eventually become the highest-trust severity source.
