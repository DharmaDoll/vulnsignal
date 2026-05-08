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
  source       TEXT NOT NULL,      -- 'nvd' | 'ghsa' | 'vendor'
  title        TEXT,
  summary      TEXT,
  severity     TEXT,               -- 'critical' | 'high' | 'medium' | 'low' | 'none'
  cvss_score   REAL,
  cvss_source  TEXT,               -- which feed provided this score
  published_at TEXT,
  updated_at   TEXT
);
```

### assets

Known systems and workloads. Current phase expects CSV import; future ingestion can replace or supplement it.

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

Append-only intelligence event feed. Core risk-relevant observations live here, but high-volume current-state feeds can use dedicated tables and only emit material changes as signals.

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

Current EPSS values. EPSS is high-volume, so daily full snapshots are upserted here instead of appended wholesale to `signals`.

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
- `package_advisory` — package-level affected range (from Trivy JSON/vuln-list)
- `vex` — vendor not-affected / affected assertion
- `enrichment` — supplemental metadata (Vulnrichment, Trivy DB vulnerability metadata)
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
  rows_affected INTEGER
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
CREATE INDEX idx_fetch_log_feed       ON fetch_log(feed, attempted_at DESC);
```
