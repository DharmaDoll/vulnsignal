# FEEDS.md

## Feed schedule and staleness policy

|Feed        |Frequency|Max staleness|On exceeded      |
|------------|---------|-------------|-----------------|
|KEV         |hourly   |3h           |Alert + use cache|
|EPSS        |daily    |48h          |Warn + use cache |
|GHSA        |every 6h |24h          |Warn + use cache |
|Trivy DB    |every 6h |24h          |Warn + use cache |
|go-exploitdb|every 6h |48h          |Warn + use cache |
|VEX/CSAF    |every 12h|48h          |Warn + use cache |
|Vulnrichment|every 12h|48h          |Warn + use cache |
|NVD         |optional |24h          |Warn + use cache |

## Fetch failure policy

- Retry: exponential backoff, base 5s, cap 300s, 3 attempts minimum
- On all retries exhausted: write `fetch_log` row with `status='error'`, exit cleanly
- **Never delete existing data on failure** — always fall back to last known good state
- `data_freshness()` API endpoint must read `fetch_log` to surface staleness per feed

## Trust hierarchy (conflict resolution)

### CVSS / severity

Initial priority (highest wins): GHSA → Vulnrichment → Trivy JSON → feed-provided severity.

NVD is optional enrichment in the current phase. If enabled later, use it as a canonical CVE reference without blocking ingestion from the core feeds.

Never overwrite a higher-trust value. Store all values as signals; `vulnerabilities.cvss_score` reflects highest-trust available.

### Exploit presence

OR logic: if **any** feed reports an exploit, `has_exploit = true`. Record provider in signal.

### VEX not-affected

A vendor’s `not_affected` assertion overrides all CVE-level signals regardless of CVSS or KEV status.
In ranking APIs, `not_affected` records are excluded rather than merely downweighted.

-----

## go-exploitdb adapter contract

File: `sync/exploit_adapter.py`

```python
@dataclass
class ExploitRecord:
    vuln_id: str
    source: str           # "go-exploitdb"
    exploit_type: str     # "poc" | "weaponized"
    url: str | None
    observed_at: str      # ISO8601

def get_exploits(vuln_id: str) -> list[ExploitRecord]: ...
```

Rules:

- All access to `db/exploit.db` must go through this adapter
- Current implementation supports the go-exploitdb `exploits` table shape from v0.7.0 and the older local sample `cve_exploits` shape
- Validate schema on cold start: check expected tables/columns exist
- If schema mismatch: raise `ExploitDBSchemaError`, skip sync
- Pin version in `config/settings.yaml` under `exploit_db.expected_schema_version` (currently `3`)
- Signal type written to core.db: `exploit`
- Local DB refresh command: `python3 -m sync.update_exploitdb`

## go-exploitdb execution notes

Observed workflow for the real database:

1. Install a matching binary, for example `go install github.com/vulsio/go-exploitdb@v0.7.0`.
2. Fetch the desired source into SQLite, for example `go-exploitdb fetch exploitdb --dbtype sqlite3 --dbpath db/exploit.db`.
3. Validate the generated DB through `sync/exploit_adapter.py` before writing any signals.
4. Import CVE-linked rows with `python3 -m sync.fetch_exploitdb --db db/exploit.db`.

Observed facts from the current verification run:

- `exploitdb` fetched 60,578 Offensive Security records.
- 30,862 of those rows had CVE IDs and were importable as `exploit` signals.
- The SQLite database exposed `exploits`, `fetch_meta`, `documents`, `ghdbs`, `git_hub_repositories`, `in_the_wilds`, `offensive_securities`, `papers`, and `shell_codes`.
- `fetch_meta.schema_version` was `3`.

Operational implications:

- The adapter must treat `fetch_meta` as the schema/version anchor for current go-exploitdb builds.
- Only CVE-linked rows are usable for this project's `vuln_id` model.
- Routine refreshes should keep the source set small until there is a clear reason to ingest all auxiliary sources.

-----

## Trivy DB adapter contract

File: `sync/trivy_adapter.py`

```python
@dataclass
class AdvisoryRecord:
    vuln_id: str
    source: str               # "trivy-db"
    ecosystem: str            # "pypi" | "npm" | "go" | "debian" | ...
    package_name: str
    affected_versions: list[str]
    fixed_version: str | None
    severity: str | None
    observed_at: str          # ISO8601

def get_advisories(vuln_id: str) -> list[AdvisoryRecord]: ...
def get_advisories_by_package(ecosystem: str, package: str, version: str) -> list[AdvisoryRecord]: ...
```

Rules:

- Current phase: ingest Trivy advisory JSON first to validate field coverage and fixed-version quality.
- Later phase: use `trivy db download` for direct DB-backed ingestion only after the JSON path has proven insufficient.
- Never parse Trivy scan output JSON as the source of advisory truth.
- Validate Trivy DB schema version on cold start
- If schema mismatch: raise `TrivyDBSchemaError`, skip sync
- Pin version in `config/settings.yaml` under `trivy_db.expected_schema_version`
- Signal type written to core.db: `package_advisory` (distinct from `exploit`)

-----

## KEV

- Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Full list on each fetch — diff against existing signals to detect new additions
- Signal type: `kev`

## EPSS

- Source: FIRST.org EPSS API
- Use the daily bulk gzip CSV (`https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz`) instead of paginated API queries
- Default ingestion reads all CSV rows and upserts `epss_current`; use `--limit` only for local sampling
- `--date YYYY-MM-DD` selects the score date; default is yesterday
- Signal type: `epss` is reserved for material EPSS events, not daily full snapshots

## GHSA

- Source: GitHub Global Security Advisories API or `github/advisory-database`
- Current phase: ingest reviewed advisories first
- Signal types:
  - `package_advisory` for ecosystem, package, affected range, fixed version
  - `enrichment` for severity, CVSS, CWE, summary
- GHSA-only advisories are valid `vuln_id` values when no CVE exists.

## NVD

- Optional enrichment feed in the current phase
- Use REST API v2.0 with incremental updates (`lastModStartDate` / `lastModEndDate`) if enabled
- Requires API key (`config/settings.yaml` → `nvd.api_key`) for reliable throughput
- Signal type: `enrichment`

## VEX / CSAF / OpenVEX

- Per-vendor CSAF feeds or OpenVEX documents
- Signal type: `vex`
- value_json must include: `{"status": "...", "justification": "..."}`

## Vulnrichment

- Source: CISA Vulnrichment GitHub repository
- Signal type: `enrichment`

## Local feed quality

- Command: `python3 -m sync.feed_quality`
- Reads only `core.db`
- Reports simple per-feed metrics for early data-quality assessment
