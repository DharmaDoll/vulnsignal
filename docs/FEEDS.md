# FEEDS.md

## Feed schedule and staleness policy

|Feed        |Frequency|Max staleness|On exceeded      |
|------------|---------|-------------|-----------------|
|KEV         |hourly   |3h           |Alert + use cache|
|NVD         |every 6h |24h          |Alert + use cache|
|EPSS        |daily    |48h          |Warn + use cache |
|Trivy DB    |every 6h |24h          |Warn + use cache |
|go-exploitdb|every 6h |48h          |Warn + use cache |
|VEX/CSAF    |every 12h|48h          |Warn + use cache |
|Vulnrichment|every 12h|48h          |Warn + use cache |

## Fetch failure policy

- Retry: exponential backoff, base 5s, cap 300s, 3 attempts minimum
- On all retries exhausted: write `fetch_log` row with `status='error'`, exit cleanly
- **Never delete existing data on failure** — always fall back to last known good state
- `data_freshness()` API endpoint must read `fetch_log` to surface staleness per feed

## Trust hierarchy (conflict resolution)

### CVSS / severity

Priority (highest wins): NVD → Vulnrichment → Trivy DB → internal override (future)

Never overwrite a higher-trust value. Store all values as signals; `vulnerabilities.cvss_score` reflects highest-trust available.

### Exploit presence

OR logic: if **any** feed reports an exploit, `has_exploit = true`. Record provider in signal.

### VEX not-affected

A vendor’s `not_affected` assertion overrides all CVE-level signals regardless of CVSS or KEV status.

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
- Validate schema on cold start: check expected tables/columns exist
- If schema mismatch: raise `ExploitDBSchemaError`, skip sync
- Pin version in `config/settings.yaml` under `exploit_db.expected_schema_version`
- Signal type written to core.db: `exploit`

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

- Use `trivy db download` to fetch DB — never parse scan output JSON
- Validate Trivy DB schema version on cold start
- If schema mismatch: raise `TrivyDBSchemaError`, skip sync
- Pin version in `config/settings.yaml` under `trivy_db.expected_schema_version`
- Signal type written to core.db: `package_advisory` (distinct from `exploit`)

-----

## NVD

- Use REST API v2.0 with incremental updates (`lastModStartDate` / `lastModEndDate`)
- Requires API key (`config/settings.yaml` → `nvd.api_key`)
- Rate limit: 5 req/30s without key, 50 req/30s with key — respect headers
- Signal type: `enrichment`

## KEV

- Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Full list on each fetch — diff against existing signals to detect new additions
- Signal type: `kev`

## EPSS

- Source: FIRST.org EPSS API
- Daily bulk CSV preferred over per-CVE queries
- Signal type: `epss`

## VEX / CSAF / OpenVEX

- Per-vendor CSAF feeds or OpenVEX documents
- Signal type: `vex`
- value_json must include: `{"status": "...", "justification": "..."}`

## Vulnrichment

- Source: CISA Vulnrichment GitHub repository
- Signal type: `enrichment`
