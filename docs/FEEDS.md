# FEEDS.md

## Feed schedule and staleness policy

|Feed        |Frequency|Max staleness|On exceeded      |
|------------|---------|-------------|-----------------|
|CVE Program  |every 6h |24h          |Warn + use cache |
|KEV         |hourly   |3h           |Alert + use cache|
|Hot web intel|hourly   |6h           |Warn + use cache |
|EPSS        |daily    |48h          |Warn + use cache |
|GHSA        |every 6h |24h          |Warn + use cache |
|go-exploitdb|every 6h |48h          |Warn + use cache |
|VEX/CSAF    |every 12h|48h          |Warn + use cache |
|Vulnrichment|every 12h|48h          |Warn + use cache |
|NVD         |optional |24h          |Warn + use cache |

## Fetch failure policy

- Retry: exponential backoff, base 5s, cap 300s, 3 attempts minimum
- On all retries exhausted: write `fetch_log` row with `status='error'`, exit cleanly

Command examples below use `python3` for portability. If you are using `uv`, prefer `uv run python -m ...` for the same repo commands.
- **Never delete existing data on failure** — try DNS-over-HTTPS for name resolution first, then fall back to the last known good cache state
- `data_freshness()` API endpoint must read `fetch_log` to surface staleness per feed; `fetch_log.cache_used` records whether the latest successful run used a cache fallback

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
git clone --depth 1 https://github.com/CVEProject/cvelistV5 data/cvelistv5-mirror
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
- Use a shallow clone unless you explicitly need full history.

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

1. Install a matching binary, for example `go install github.com/vulsio/go-exploitdb@latest`.
2. Fetch the database through the repo wrapper, which defaults to all source families, for example `python3 -m sync.update_exploitdb --binary ~/go/bin/go-exploitdb`.
3. Validate the generated DB through `sync/exploit_adapter.py` before writing any signals.
4. Import CVE-linked rows with `python3 -m sync.fetch_exploitdb --db db/exploit.db`.

For a bounded validation ingest, add `--min-year 2024` to the import command.

If you want one top-level command that refreshes both the git mirrors and `db/exploit.db`, run `./scripts/refresh_all_sources.sh` first and then run `./scripts/ingest_recent_core_db.sh`.

Observed facts from the current verification run:

- `exploitdb` fetched 60,578 Offensive Security records.
- 30,862 of those rows had CVE IDs and were importable as `exploit` signals.
- The SQLite database exposed `exploits`, `fetch_meta`, `documents`, `ghdbs`, `git_hub_repositories`, `in_the_wilds`, `offensive_securities`, `papers`, and `shell_codes`.
- `fetch_meta.schema_version` was `3`.

Operational implications:

- The adapter must treat `fetch_meta` as the schema/version anchor for current go-exploitdb builds.
- Only CVE-linked rows are usable for this project's `vuln_id` model.
- Routine refreshes should keep the source set small until there is a clear reason to ingest all auxiliary sources.
- `signals` ingestion is idempotent for exact duplicates; `observed_at` stays as a history field, not part of the duplicate key.

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
- Direct Trivy DB ingestion currently yields vulnerability metadata enrichment, not package ranges, and is treated as an optional backfill path rather than a default refresh input.
- Never parse Trivy scan output JSON as the source of advisory truth.
- Validate Trivy DB schema version on cold start
- If schema mismatch: raise `TrivyDBSchemaError`, skip sync
- Pin version in `config/settings.yaml` under `trivy_db.expected_schema_version`
- Signal type written to core.db: `enrichment` (distinct from `exploit`)

## Trivy DB execution notes

Use the compiled Trivy DB cache only when you explicitly want scanner-aligned vulnerability metadata enrichment from Trivy's DB.

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
- This path is not part of the default refresh script.

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

If `db/core.db` is locked by another ingest run and you want to validate Trivy DB in isolation, set `VULNSIGNAL_DB_PATH` to point at a separate SQLite file before running `db/migrate.py` and `python3 -m sync.fetch_trivy_db`.

## Trivy vuln-list execution notes

Use the raw advisory tree from `aquasecurity/vuln-list` as the first ingestion step.
This is the default Trivy advisory path. If you need package ranges, fixed-version fidelity,
or target-specific advisory coverage, start here before considering any other fallback.
When writing to `core.db`, keep only records published in 2015 or later.

Current command:

```bash
python3 -m sync.fetch_trivy_vuln_list --source-dir data/aquasecurity-vuln-list-mirror
```

Recommended mirror setup:

```bash
git clone --depth 1 https://github.com/aquasecurity/vuln-list data/aquasecurity-vuln-list-mirror
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
- The fetcher updates `vulnerabilities` and the local cache, but it no longer appends `package_advisory` rows to `core.db`.
- If package-level context is needed later, resolve it on demand from the local vuln-list mirror instead of persisting the full history. This is the intended path, not a workaround.
- Do not remove or ignore the local mirror if package-range fidelity matters; the mirror is the authoritative source for on-demand lookups.
- The Trivy DB path stays reserved for vulnerability metadata enrichment and scanner-aligned CVSS/severity context.

For a bounded validation ingest, add `--min-year 2024`.

Day 1 note:

- `vuln-list` is still useful for package-range quality and test coverage, but the full package history does not need to live in `core.db`.
- If the immediate goal is to join against existing asset inventories, the current Trivy JSON path and scanner-aligned sources are usually enough.
- A `vuln-list` lookup can be done later, on demand, when package coverage or fixed-version fidelity becomes the limiting factor. Treat that lookup as the normal escalation path for Trivy package detail, not as an optional extra.
- For now, the `osv` target inside `aquasecurity/vuln-list` is considered sufficient; we do not need a separate `OSV.dev` ingest until coverage or freshness gaps show up in analysis.

On-demand lookup recipe:

1. Identify the `vuln_id` or package name you want to inspect.
2. Confirm the local mirror has a hit:

```bash
rg -n --glob '*.json' 'CVE-2026-31431' data/aquasecurity-vuln-list-mirror/{alpine,debian,ubuntu,ghsa,glad,go,osv,seal}
```

3. Load the normalized advisory records through the adapter helper, not by parsing raw tree shape yourself:

```bash
python3 - <<'PY'
from pathlib import Path
from sync.trivy_adapter import load_advisories_for_vuln_id_from_directory

source_dir = Path("data/aquasecurity-vuln-list-mirror")
for advisory in load_advisories_for_vuln_id_from_directory(
    source_dir,
    "CVE-2026-31431",
    "2026-06-18T00:00:00Z",
    targets=["alpine", "debian", "ubuntu", "ghsa", "glad", "go", "osv", "seal"],
):
    print(advisory)
PY
```

4. If the lookup is only for review, stop there. If you need to persist the advisory context, rerun `python3 -m sync.fetch_trivy_vuln_list --source-dir data/aquasecurity-vuln-list-mirror`.
5. If the CVE looks noisy but important, check the other local sources in this order:

   - `db/core.db` `signals` for `kev`, `exploit`, and `hot`
   - `db/exploit.db` through `sync.exploit_adapter` for raw exploit/proof-of-concept context
   - `hot` evidence via `python3 -m sync.fetch_hot --vuln-id <CVE-ID> --simple` when you want the attention signal refreshed for one ID

6. Write down the exact `vuln_id`, `package_name`, `fixed_version`, and `signal_type` you used so the lookup can be repeated later without guesswork.

Recommended deep-dive order for a single CVE:

1. `core.db` entry exists?
2. `signals` show `kev`, `exploit`, or `hot`?
3. `aquasecurity/vuln-list` mirror has package or OSV context?
4. `db/exploit.db` adds PoC / weaponized detail?
5. `hot` adds current attention context?
6. If needed, rerun the bounded ingest to persist the result.

Copy-paste template:

```bash
VULN_ID='CVE-2026-31431'
MIRROR_DIR='data/aquasecurity-vuln-list-mirror'

rg -n --glob '*.json' "$VULN_ID" "$MIRROR_DIR"/{alpine,debian,ubuntu,ghsa,glad,go,osv,seal}

python3 - <<'PY'
from pathlib import Path
from datetime import datetime, timezone
from sync.trivy_adapter import load_advisories_for_vuln_id_from_directory

vuln_id = 'CVE-2026-31431'
source_dir = Path('data/aquasecurity-vuln-list-mirror')
observed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
targets = ['alpine', 'debian', 'ubuntu', 'ghsa', 'glad', 'go', 'osv', 'seal']

for advisory in load_advisories_for_vuln_id_from_directory(source_dir, vuln_id, observed_at, targets=targets):
    print(advisory.vuln_id, advisory.source, advisory.ecosystem, advisory.package_name, advisory.fixed_version)
PY

sqlite3 -header -column db/core.db "
SELECT signal_type, provider, score, observed_at
FROM signals
WHERE vuln_id = '$VULN_ID'
ORDER BY observed_at DESC, id DESC;
"

python3 -m sync.fetch_hot --vuln-id "$VULN_ID" --simple
```

-----

## KEV

- Source: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- Full list on each fetch — diff against existing signals to detect new additions
- If the live fetch fails, the importer falls back to the local cached JSON snapshot.
- Signal type: `kev`

## EPSS

- Source: FIRST.org EPSS API
- Use the daily bulk gzip CSV (`https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz`) instead of paginated API queries
- Default ingestion reads all CSV rows and upserts `epss_current`; use `--limit` only for local sampling
- `--date YYYY-MM-DD` selects the score date; default is yesterday
- If the requested live CSV is unavailable, the importer falls back to the newest cached EPSS snapshot on disk and uses that snapshot's date in `epss_current`.
- Signal type: `epss` is reserved for material EPSS events, not daily full snapshots

### Production operation

Run the daily snapshot importer directly:

```bash
python3 -m sync.fetch_epss
```

To pin a specific date:

```bash
python3 -m sync.fetch_epss --date 2026-05-12
```

For bounded sampling only:

```bash
python3 -m sync.fetch_epss --limit 1000
```

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
git clone --depth 1 https://github.com/github/advisory-database data/github-advisory-database-mirror
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

## Assets

- Source: local CSV export from inventory / discovery tooling
- Current phase: import coarse asset records plus append-only technology observations
- Primary command: `python3 -m sync.import_assets_csv --csv data/assets.csv`

Supported CSV columns:

- Required: `asset_id`, `hostname`
- Asset fields: `os`, `os_version`, `version`, `owner`, `exposed`, `criticality`
- Observation fields: `kind`, `name`, `version`, `confidence`, `source`, `observed_at`, `details_json`
- Convenience observation fields: `software`, `software_version`, `product`, `product_version`, `middleware`, `middleware_version`, `framework`, `framework_version`, `runtime`, `runtime_version`, `language`, `language_version`

Behavior:

- `assets` is updated conservatively so existing non-empty values are preserved.
- `asset_observations` is append-only and skips exact duplicates.
- If both the generic observation fields and convenience fields are present, the importer records each observation separately.
- A row without `asset_id` or `hostname` is skipped.

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
git clone --depth 1 https://github.com/cisagov/vulnrichment data/vulnrichment-mirror
```

Or update all mirrors at once:

```bash
./scripts/update_data_mirrors.sh
```

The update script uses shallow clones and recreates broken mirrors automatically.

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

## Hot web intel

- Source: RSS / article-feed discovery over current vulnerability reporting, then resolution against `core.db`
- Signal type: `hot`
- Purpose: detect current external attention, active exploitation, or public exploitability that is not yet fully captured by KEV / exploit / vendor feeds
- Execution environment: run this from a machine with working outbound HTTP/DNS. In this project, `hot` is a local-run feature; Codex Cloud or other restricted-network environments may not be able to resolve or fetch the RSS sources reliably.
- Positioning: reference-only signal in the main risk view; hot-oriented views may use it as a first-class ranking input ahead of raw CVSS-only records
- Refresh target: every 6 hours in local operations, with a bounded search cap
- Operational detection target: surface notable records within about 4 days of `first_seen_at`
- Storage model: append-only history in `signals`
- Primary consumers: the `hot` CLI view and any review workflow that wants current attention separate from core risk ranking
- Execution order: run `hot` only after `core.db` has been refreshed; otherwise candidate resolution will miss newly ingested CVEs

### Operating model

- Start from broad RSS / article-feed discovery over current exploitation and advisory reporting.
- Use the number of discovered vulnerabilities as the default search budget.
- Keep the search budget bounded by a configurable cap so a large corpus does not fan out into an unbounded crawl.
- Current default discovery depth is 20 items per RSS feed per run.
- Optional extra discovery terms can be supplied on the CLI to widen the web search beyond the built-in baseline.
- Extract CVE IDs from feed items and resolve them against `core.db` before writing signals.
- Treat the feed item title, summary, and source domain as the evidence payload for classification.
- Prefer high-signal sources:
  - official vendor advisories and security blogs
  - CISA / government advisories
  - reputable security news outlets
  - researcher blogs and write-ups
  - X posts only when they contain a direct CVE reference, PoC, exploit, or clear corroboration
- Do not treat a single social post as strong evidence on its own.
- Use the discovery result count and evidence count as first-class signal fields.

### Built-in baseline and optional manual terms

The fetcher starts with a small built-in baseline of high-signal discovery terms:

- `active exploitation`
- `in the wild`
- `PoC`
- `zero-day`

If the baseline is too thin, the fetcher broadens with additional low-priority discovery terms:

- `CVE-2026`
- `CVE-2025`
- `exploit`
- `weaponized`
- `vulnerability`

The CLI `--query-term` arguments are additive. Use them only when you want to widen coverage further beyond both the built-in baseline and the broadening set.

### Recommended `value_json`

```json
{
  "window_cutoff": "2026-05-25T00:00:00+00:00",
  "search_budget": 20,
  "query_budget": 3,
  "discovery_queries": ["https://feeds.feedburner.com/TheHackersNews", "https://securityonline.info/feed/"],
  "discovery_query_count": 3,
  "discovery_result_count": 8,
  "search_queries": ["\"Example vuln title\"", "\"Example vuln summary\" exploit OR PoC OR \"active exploitation\""],
  "result_count": 8,
  "evidence_count": 3,
  "independent_sources": 2,
  "evidence_types": ["kev", "active_exploitation", "public_poc"],
  "source_types": ["vendor", "cisa", "news"],
  "urls": ["https://...", "https://..."],
  "discovery_hits": [{"query": "...", "title": "...", "summary": "...", "url": "...", "domain": "...", "published_at": "...", "cve_ids": ["CVE-2026-42945"]}],
  "discovered_vuln_ids": ["CVE-2026-42945"],
  "search_hits": [{"query": "...", "title": "...", "url": "...", "domain": "..."}],
  "evidence_details": [{"evidence_type": "...", "source_type": "...", "weight": 0.95, "url": "...", "title": "...", "domain": "...", "query": "...", "matched_terms": ["..."]}],
  "headline": "short human-readable summary"
}
```

### Interpretation rules

- `evidence_count` and `independent_sources` matter more than raw mention volume.
- `KEV` or vendor-confirmed active exploitation should produce a strong `hot` signal.
- Public PoC / exploit reporting should produce a medium-strength `hot` signal.
- Broad chatter without direct evidence should stay weak or be dropped.
- Append one `hot` signal per vulnerability per run. Treat each run as a new observation in history.
- `hot_score` is a confidence / attention score, not the main risk score.
- The score is intentionally compressed so a small number of outliers do not all collapse to 1.0.
- Main ranking still prefers `KEV > exploit > EPSS > CVSS > published_at`.
- Operational threshold:
  - `hot_score >= 0.85` = strong hot
  - `0.70 <= hot_score < 0.85` = moderate hot
  - `hot_score < 0.70` = weak hot / reference-only
- SLA note:
  - 4 days is the practical target for early detection
  - 3 days is often too strict and will miss legitimate late-arriving hot coverage

### Production operation

The fetcher should:

1. Run broad RSS / article-feed discovery for current exploitation / advisory coverage.
2. Extract CVE IDs from the feed items and resolve them against `core.db`.
3. Convert the resulting feed items into a single append-only `hot` signal row per vulnerability.
4. Write `fetch_log` with the normal success / error contract.

Local command:

```bash
uv run python -m sync.fetch_hot --search-cap 20
```

Profile shortcuts:

```bash
uv run python -m sync.fetch_hot --profile strict
uv run python -m sync.fetch_hot --profile balanced
uv run python -m sync.fetch_hot --profile broad
```

To evaluate one or more CVEs directly without running discovery, repeat `--vuln-id`:

```bash
uv run python -m sync.fetch_hot --vuln-id CVE-2026-42945
uv run python -m sync.fetch_hot --vuln-id CVE-2026-42945 --vuln-id CVE-2026-3300
```

This path skips RSS / DuckDuckGo discovery and only gathers evidence for the
specified vuln_ids already present in `core.db`.

To widen discovery with manual terms, repeat `--query-term`:

```bash
uv run python -m sync.fetch_hot --search-cap 20 --query-term "Palo Alto" --query-term "active exploitation"
```

For frequent production runs, schedule the job every 6 hours. Keep the `--search-cap` bounded to avoid heavy search fan-out.

### Model case: one practical schedule

This is an example operational pattern, not a required configuration.

- Daily:
  - `db/migrate.py`
  - `./scripts/refresh_all_sources.sh`
  - `./scripts/ingest_recent_core_db.sh`
  - `uv run python -m sync.feed_quality`
  - short vuln list
- Every 6 hours:
  - `uv run python -m sync.fetch_hot`
- Every hour, if you want a faster KEV watch:
  - `uv run python -m sync.fetch_kev`

The intent is:

- keep `core.db` fresh once per day
- refresh `hot` often enough to catch current attention
- track KEV more aggressively if you need faster escalation visibility

Do not treat this as a hard requirement. It is a model case for local operations.
If your execution environment has restricted outbound networking, run the `hot` step from a local shell with working DNS and HTTP access.

### Operational notes

- The current implementation uses RSS/article feeds instead of a search engine because search pages were unreliable in this environment.
- `hot` is expected to be run from a local environment with outbound network access; if that is not available, the feed may log zero discoveries even when the code is healthy.
- Current feed sources are intentionally small and high-signal.
- Duplicate observations are expected and are preserved in `signals` for history.
- The `hot` CLI shows `hot_score` plus the reference-only evidence payload separately.
- In local operations, run `hot` after the main `core.db` refresh step, not before it.
- When running `hot` from Codex or any restricted environment, use an approval/escalated run because the job needs outbound HTTP/DNS.
- If `--query-term` is omitted, the fetcher still uses the built-in baseline queries above in addition to RSS/article-feed discovery. The manual CLI terms are an expansion layer on top of that baseline.

## Local feed quality

- Command: `uv run python -m sync.feed_quality`
- Reads only `core.db`
- Reports simple per-feed metrics for early data-quality assessment

## Core DB validation

Use this when you want a reproducible local ingest window that is small enough to inspect manually.

```bash
./scripts/ingest_recent_core_db.sh
```

The script:

- runs `db/migrate.py` first
- refreshes the local git mirrors unless `SKIP_MIRROR_REFRESH=1`
- assumes `./scripts/update_data_mirrors.sh` has already been run if you want the latest mirror commits before a diff-based ingest
- fetches KEV and EPSS from the live feeds, falling back to the local cache when needed
- ingests CVE Program, GHSA, Trivy vuln-list, and Vulnrichment with a rolling `MIN_YEAR` cutoff
- optionally ingests `db/exploit.db` when that local source exists
- finishes with `uv run python -m sync.feed_quality`
- takes a lock so only one refresh run touches `core.db` at a time
- stores the last successful mirror refs in `db/refresh_recent_core_db.refs` and reuses them on the next run

Override the year window if needed:

```bash
MIN_YEAR=2024 ./scripts/ingest_recent_core_db.sh
```

The default window is the latest three calendar years, computed from the current year.

Current end-to-end flow for a reproducible local corpus:

1. Run `db/migrate.py`.
2. Refresh the source inputs with `./scripts/refresh_all_sources.sh`. If you are offline and intentionally reusing the current mirrors, set `SKIP_MIRROR_REFRESH=1`. If you want to skip the go-exploitdb refresh for a local-only run, set `SKIP_EXPLOITDB_UPDATE=1`.
3. Run `./scripts/ingest_recent_core_db.sh` to fetch KEV and EPSS, ingest `cvelistV5`, GHSA, Trivy vuln-list, and Vulnrichment with `--min-year`, and finish with `uv run python -m sync.feed_quality`.
4. Optionally ingest `db/exploit.db` when that local source is present.

Manual review order after the ingest pass:

1. Run `uv run python -m sync.fetch_hot` only after `core.db` has been refreshed.
2. Inspect `uv run python -m sync.feed_quality` output for freshness and coverage.
3. Use `uv run python -m app.skills hot --limit 10 --details` or SQL queries for a short hot watchlist.
4. Use the Skills CLI or direct SQL for a short vuln list when you do not need a full report.

If you only need the newest operational KEV set, run `uv run python -m sync.fetch_kev` directly. For the bounded 3-year validation corpus, prefer the wrapper script so the mirror refresh and quality check happen in the same pass. The mirror refresh step matters for the advisory feeds because `ingest_recent_core_db.sh` diffs against the last ingested mirror refs.
