# FEEDS.md

## Feed schedule and staleness policy

|Feed        |Frequency|Max staleness|On exceeded      |
|------------|---------|-------------|-----------------|
|CVE Program  |every 6h |24h          |Warn + use cache |
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

The CVE Program is the canonical CVE identifier and metadata backbone. Use it to fill missing identifiers, dates, titles, and references, but do not let it override higher-trust severity or CVSS when those are already present.

NVD is optional enrichment in the current phase. If enabled later, use it as a canonical CVE reference without blocking ingestion from the core feeds.

Never overwrite a higher-trust value. Store all values as signals; `vulnerabilities.cvss_score` reflects highest-trust available.

### Exploit presence

OR logic: if **any** feed reports an exploit, `has_exploit = true`. Record provider in signal.

### VEX not-affected

A vendor’s `not_affected` assertion overrides all CVE-level signals regardless of CVSS or KEV status.
In ranking APIs, `not_affected` records are excluded rather than merely downweighted.

-----

## CVE Program

- Source: `CVEProject/cvelistV5`
- Signal type: `enrichment`
- The CVE Program tree is the canonical CVE metadata backbone for this project.
- When writing to `core.db`, keep only records published in 2015 or later.

### Production operation

Mirror the repository locally and ingest the local JSON tree.

```bash
git clone https://github.com/CVEProject/cvelistV5 data/cvelistv5-mirror
git -C data/cvelistv5-mirror pull --ff-only
python3 -m sync.fetch_cve_program --source-dir data/cvelistv5-mirror
```

For bounded validation:

```bash
python3 -m sync.fetch_cve_program --source-dir data/cvelistv5-mirror --min-year 2024
```

Notes:

- The fetcher reads local JSON only; it does not talk to cve.org directly.
- Keep the mirror on disk and update it by git pull or archive replacement.

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

For a bounded validation ingest, add `--min-year 2024` to the import command.

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
class VulnerabilityRecord:
    vuln_id: str
    source: str               # "trivy-db"
    title: str | None
    summary: str | None
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    vendor_severity: dict[str, Any] | None
    references: list[str]
    observed_at: str          # ISO8601

def get_vulnerabilities(vuln_id: str) -> list[VulnerabilityRecord]: ...
def get_vulnerabilities_from_db(db_dir: Path) -> list[VulnerabilityRecord]: ...
```

Rules:

- Current phase: support both Trivy advisory JSON and direct Trivy DB ingestion.
- JSON remains useful for field-coverage checks and fixture-based validation.
- Direct Trivy DB ingestion currently yields vulnerability metadata enrichment, not package ranges.
- Never parse Trivy scan output JSON as the source of advisory truth.
- Validate Trivy DB schema version on cold start
- If schema mismatch: raise `TrivyDBSchemaError`, skip sync
- Pin version in `config/settings.yaml` under `trivy_db.expected_schema_version`
- Signal type written to core.db: `enrichment` (distinct from `exploit`)

## Trivy DB execution notes

Use the compiled Trivy DB cache when you want vulnerability metadata directly from Trivy's DB.

Current command:

```bash
python3 -m sync.fetch_trivy_db --db-dir db/trivy_cache.db
```

Operational notes:

- `--db-dir` must point to a local directory that contains `trivy.db` and `metadata.json`.
- The repository does not store the Trivy DB itself; the command reads a local cache or an extracted download.
- `metadata.json.Version` is the schema/version gate.
- The adapter extracts vulnerability metadata from `vulnerability` and writes `enrichment` signals.
- The output signal type remains `enrichment`.

For a bounded validation ingest, add `--min-year 2024` to the command above.

### How to obtain the DB

Two supported ways to get a usable cache directory:

1. Trivy managed download:

```bash
TRIVY_TEMP_DIR=$(mktemp -d)
trivy --cache-dir "$TRIVY_TEMP_DIR" image --download-db-only
mkdir -p db/trivy_cache.db
cp "$TRIVY_TEMP_DIR/db/trivy.db" db/trivy_cache.db/
cp "$TRIVY_TEMP_DIR/db/metadata.json" db/trivy_cache.db/
rm -rf "$TRIVY_TEMP_DIR"
```

2. ORAS pull from GHCR:

```bash
oras pull ghcr.io/aquasecurity/trivy-db:2
```

After pulling with ORAS, copy or extract the resulting `trivy.db` and `metadata.json` into the cache directory you pass to `--db-dir`.

## Trivy vuln-list execution notes

Use the raw advisory tree from `aquasecurity/vuln-list` as the first ingestion step.
When writing to `core.db`, keep only records published in 2015 or later.

Current command:

```bash
python3 -m sync.fetch_trivy_vuln_list --source-dir data/aquasecurity-vuln-list-mirror
```

Recommended mirror setup:

```bash
git clone https://github.com/aquasecurity/vuln-list data/aquasecurity-vuln-list-mirror
git -C data/aquasecurity-vuln-list-mirror pull --ff-only
```

Default targets:

- `alpine`
- `debian`
- `ubuntu`
- `ghsa`
- `glad`
- `go`
- `osv`

Operational notes:

- The fetcher reads local checkout or unpacked archive content only.
- All Trivy-shaped normalization stays in `sync/trivy_adapter.py`.
- The output signal type remains `package_advisory`.
- The Trivy DB path stays reserved for vulnerability metadata enrichment and scanner-aligned CVSS/severity context.

For a bounded validation ingest, add `--min-year 2024`.

Day 1 note:

- `vuln-list` is useful when we want to improve package-range quality and test coverage, but it is not required to start asset matching.
- If the immediate goal is to join against existing asset inventories, the current Trivy JSON path and scanner-aligned sources are usually enough.
- A `vuln-list` sync can be added later if package coverage or fixed-version fidelity becomes the limiting factor.

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

- Source: `github/advisory-database`
- Current phase: ingest reviewed advisories first
- Signal types:
  - `package_advisory` for ecosystem, package, affected range, fixed version
  - `enrichment` for severity, CVSS, CWE, summary
- GHSA-only advisories are valid `vuln_id` values when no CVE exists.
- When writing to `core.db`, keep only records published in 2015 or later.

### Production operation

Mirror the advisory database locally and ingest the reviewed tree.

```bash
git clone https://github.com/github/advisory-database data/github-advisory-database-mirror
git -C data/github-advisory-database-mirror pull --ff-only
python3 -m sync.fetch_ghsa --source-dir data/github-advisory-database-mirror
```

The default fetcher path reads `advisories/github-reviewed` under that mirror. Pass `--include-unreviewed` only if you intentionally want the extra advisories.
For a bounded validation ingest, add `--min-year 2024`.

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
- When writing to `core.db`, keep only records published in 2015 or later.

### Production operation

Keep a local mirror of the upstream repository or an unpacked archive, then point the fetcher at that local tree.

Recommended layout:

```text
data/vulnrichment/
  2024/0xxx/CVE-2024-0043.json
  2024/1xxx/...
  2025/...
```

Initial mirror setup:

```bash
git clone https://github.com/cisagov/vulnrichment data/vulnrichment-mirror
```

Or update all mirrors at once:

```bash
./scripts/update_data_mirrors.sh
```

Routine update:

```bash
git -C data/vulnrichment-mirror pull --ff-only
```

Local ingestion:

```bash
python3 -m sync.fetch_vulnrichment --source-dir data/vulnrichment-mirror
```

Recommended operational sequence:

1. Refresh the local mirror.
2. Run a dry run if you want to check file coverage first: `python3 -m sync.fetch_vulnrichment --source-dir data/vulnrichment-mirror --dry-run`
3. Run the real ingest command.
4. Review `fetch_log` and feed-quality output after the run.

Notes:

- The fetcher reads local JSON only; it does not talk to GitHub directly.
- `--source-dir` may also point at an unpacked archive export if you do not want a git checkout.
- Keep the local mirror on disk and update it by git pull or archive replacement, not by per-file manual downloads.

For a bounded validation ingest, add `--min-year 2024`.

## Local feed quality

- Command: `python3 -m sync.feed_quality`
- Reads only `core.db`
- Reports simple per-feed metrics for early data-quality assessment

## Core DB validation

Use this when you want a reproducible local ingest window that is small enough to inspect manually.

```bash
./scripts/ingest_recent_core_db.sh
```

The script:

- runs `db/migrate.py` first
- refreshes the local git mirrors
- ingests GHSA, Trivy vuln-list, and Vulnrichment with a rolling `MIN_YEAR` cutoff
- optionally ingests `db/trivy_cache.db` and `db/exploit.db` when those local sources exist
- finishes with `python3 -m sync.feed_quality`

Override the year window if needed:

```bash
MIN_YEAR=2024 ./scripts/ingest_recent_core_db.sh
```

The default window is the latest three calendar years, computed from the current year.
