# SCHEMA.md

## Migration rules

- Schema version tracked via `PRAGMA user_version`
- Migration files: `sql/migrations/NNN_description.sql`
- All migrations are idempotent SQL
- Never modify already-applied migration files
- `db/migrate.py` must be run before any DB operation (tests, scripts, API start)

```sql
-- Template for each migration file
PRAGMA user_version = N;
-- your DDL here
```

-----

## Tables

### vulnerabilities

Canonical vulnerability records. One row per vuln_id.

```sql
CREATE TABLE vulnerabilities (
  vuln_id      TEXT PRIMARY KEY,   -- CVE-YYYY-NNNNN / GHSA-xxx / vendor ID
  source       TEXT NOT NULL,      -- ingest source label such as 'cve_program' | 'ghsa' | 'trivy' | 'kev'
  title        TEXT,
  summary      TEXT,
  severity     TEXT,               -- source-preserved severity; mixed case values may appear
  cvss_score   REAL,
  cvss_source  TEXT,               -- which feed provided this score
  published_at TEXT,
  first_seen_at TEXT,              -- first announcement/publication date seen in core.db
  updated_at   TEXT
);
```

### assets

Known systems and workloads. Current phase uses CSV import.

```sql
CREATE TABLE assets (
  asset_id     TEXT PRIMARY KEY,
  hostname     TEXT NOT NULL,
  os           TEXT,
  version      TEXT,
  owner        TEXT,
  exposed      INTEGER DEFAULT 0,  -- 1 = internet-exposed
  criticality  TEXT DEFAULT 'low'  -- 'critical' | 'high' | 'medium' | 'low'
);
```

### asset_observations

Append-only coarse technology observations for an asset.

```sql
CREATE TABLE asset_observations (
  id           INTEGER PRIMARY KEY,
  asset_id     TEXT NOT NULL REFERENCES assets(asset_id),
  kind         TEXT NOT NULL,      -- 'os' | 'framework' | 'runtime' | 'middleware' | 'product' | 'language'
  name         TEXT NOT NULL,      -- normalized label such as 'Ubuntu' or 'Nuxt.js'
  version      TEXT,               -- coarse version like '22' or '3.x'
  confidence   REAL NOT NULL DEFAULT 0.5,
  source       TEXT NOT NULL,
  details_json TEXT,
  observed_at  TEXT NOT NULL
);
```

Use it to rank risk from partial observations like `Ubuntu 22` or `Nuxt.js` when exact versions are unavailable.

### findings

Join of asset × vulnerability. Represents a known-affected combination.

```sql
CREATE TABLE findings (
  id           INTEGER PRIMARY KEY,
  asset_id     TEXT NOT NULL REFERENCES assets(asset_id),
  vuln_id      TEXT NOT NULL REFERENCES vulnerabilities(vuln_id),
  risk_score   REAL,
  scoring_version TEXT DEFAULT 'v1',
  status       TEXT DEFAULT 'open', -- 'open' | 'in_progress' | 'patched' | 'suppressed'
  updated_at   TEXT
);
```

### decisions

Operational remediation tasks derived from findings.

```sql
CREATE TABLE decisions (
  id              INTEGER PRIMARY KEY,
  vuln_id         TEXT NOT NULL,
  priority        INTEGER,
  rationale       TEXT,
  due_date        TEXT,
  state           TEXT DEFAULT 'open', -- 'open' | 'in_progress' | 'resolved'
  scoring_version TEXT DEFAULT 'v1',
  created_at      TEXT,
  updated_at      TEXT
);
```

### signals

Append-only intelligence event feed for risk-relevant observations.

```sql
CREATE TABLE signals (
  id           INTEGER PRIMARY KEY,
  vuln_id      TEXT NOT NULL,
  signal_type  TEXT NOT NULL,  -- see signal taxonomy below
  provider     TEXT NOT NULL,
  score        REAL,
  value_json   TEXT,           -- JSON blob for structured data
  observed_at  TEXT NOT NULL
);
```

### epss_current

Current EPSS values. Daily full snapshots are upserted here instead of appended wholesale to `signals`.

```sql
CREATE TABLE epss_current (
  vuln_id     TEXT PRIMARY KEY,
  epss        REAL NOT NULL,
  percentile  REAL,
  score_date  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
```

Signal type taxonomy:

- `epss` — EPSS probability score
- `kev` — CISA KEV listing
- `exploit` — PoC/exploit presence (from go-exploitdb)
- `package_advisory` — package-level affected range (from Trivy JSON; vuln-list context is resolved on demand)
- `vex` — vendor not-affected / affected assertion
- `enrichment` — supplemental metadata (CVE Program, GHSA, Vulnrichment, Trivy DB vulnerability metadata)
- `hot` — current external attention / exploitation signal derived from web discovery and follow-up research over vulnerability titles and summaries
- `ssvc_factor` — future SSVC inputs

Initial feed quality metrics should stay simple:

- `rows_fetched`
- `signals_written`
- `vuln_id_coverage`
- `required_field_coverage`
- `duplicate_rate`
- `last_success_at`
- `staleness_status`

### fetch_log

Operational log for every sync attempt.

```sql
CREATE TABLE fetch_log (
  id            INTEGER PRIMARY KEY,
  feed          TEXT NOT NULL,
  attempted_at  TEXT NOT NULL,
  status        TEXT NOT NULL,  -- 'ok' | 'error' | 'skipped'
  error_msg     TEXT,
  rows_affected INTEGER,
  cache_used    INTEGER NOT NULL DEFAULT 0
);
```

### report_history

Append-only log of emitted notifications for deduping alert delivery; it does not filter the underlying report output.

```sql
CREATE TABLE report_history (
  id            INTEGER PRIMARY KEY,
  report_key    TEXT NOT NULL,
  vuln_id       TEXT NOT NULL REFERENCES vulnerabilities(vuln_id),
  report_run_id TEXT,
  payload_json  TEXT,
  reported_at   TEXT NOT NULL
);
```

-----

## Key indexes (sql/indexes.sql)

```sql
CREATE INDEX idx_signals_vuln_id      ON signals(vuln_id);
CREATE INDEX idx_signals_type         ON signals(signal_type);
CREATE INDEX idx_signals_observed_at  ON signals(observed_at);
CREATE INDEX idx_findings_vuln_id     ON findings(vuln_id);
CREATE INDEX idx_findings_asset_id    ON findings(asset_id);
CREATE INDEX idx_findings_risk_score  ON findings(risk_score DESC);
CREATE INDEX idx_asset_observations_asset_kind ON asset_observations(asset_id, kind, observed_at DESC);
CREATE INDEX idx_asset_observations_observed_at ON asset_observations(observed_at);
CREATE INDEX idx_fetch_log_feed       ON fetch_log(feed, attempted_at DESC, id DESC);
CREATE INDEX idx_report_history_key_vuln ON report_history(report_key, vuln_id);
CREATE INDEX idx_report_history_reported_at ON report_history(reported_at DESC);
```

### epss_batch

Migration 008 records the date, SHA-256 digest and row count of the last fully applied daily EPSS file in the same transaction as its scores. Partial imports invalidate the checkpoint when they change scores. An expression index on signal observation time supports calendar-period lookups.

### feed_metrics

Migration 009 links elapsed seconds, rows read and downloaded HTTP response-body bytes to the CLI run’s fetch_log ID. Git transport, subprocess traffic, headers and failed transfers are outside the HTTP byte counter. Historical rows without measurements remain unknown.

### Searchable intelligence mart (migration 010)

`intel_evidence` links eligible source observations to normalized vulnerability IDs and attributed titles. SQLite FTS5 indexes product/package terms separately from textual mentions in `intel_terms`. `intel_event` groups repeat observations by vulnerability, event type and identity and references a supporting signal. `intel_state` tracks the last processed signal ID. Index rows and the cursor commit in the same transaction. The original signals provide the durable evidence trail. Search queries expose source dates, observation times and online ingestion freshness.

### CVSS observations (migration 011)

`intel_cvss` stores the base score for each eligible source signal, keyed by signal ID. The series index groups vulnerability, provider, advisory and CVSS version in observation order. `intel_cvss_state` checkpoints its historical backfill independently of the text index. Derived `cvss_increase` and `cvss_decrease` events point to the changed observation. An out-of-order insertion also updates the affected successor's derived event. Raw evidence remains append-only. EPSS is joined from `epss_current` by vulnerability ID at query time.

### Hot evidence projection (migration 012)

`intel_state.hot_rule_version` records the article matching rules applied by the mart. The first `scripts.intel refresh` after migration replays indexed Web Hot Intel observations in signal ID order. It replaces their derived attention events and search terms and checkpoints the version in one transaction. A subsequent refresh resumes incremental indexing.
