CREATE TABLE IF NOT EXISTS vulnerabilities (
  vuln_id      TEXT PRIMARY KEY,
  source       TEXT NOT NULL,
  title        TEXT,
  summary      TEXT,
  severity     TEXT,
  cvss_score   REAL,
  cvss_source  TEXT,
  published_at TEXT,
  updated_at   TEXT
);

CREATE TABLE IF NOT EXISTS assets (
  asset_id     TEXT PRIMARY KEY,
  hostname     TEXT NOT NULL,
  os           TEXT,
  version      TEXT,
  owner        TEXT,
  exposed      INTEGER DEFAULT 0,
  criticality  TEXT DEFAULT 'low'
);

CREATE TABLE IF NOT EXISTS findings (
  id              INTEGER PRIMARY KEY,
  asset_id        TEXT NOT NULL REFERENCES assets(asset_id),
  vuln_id         TEXT NOT NULL REFERENCES vulnerabilities(vuln_id),
  risk_score      REAL,
  scoring_version TEXT DEFAULT 'v1',
  status          TEXT DEFAULT 'open',
  updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS decisions (
  id              INTEGER PRIMARY KEY,
  vuln_id         TEXT NOT NULL,
  priority        INTEGER,
  rationale       TEXT,
  due_date        TEXT,
  state           TEXT DEFAULT 'open',
  scoring_version TEXT DEFAULT 'v1',
  created_at      TEXT,
  updated_at      TEXT
);

CREATE TABLE IF NOT EXISTS signals (
  id           INTEGER PRIMARY KEY,
  vuln_id      TEXT NOT NULL,
  signal_type  TEXT NOT NULL,
  provider     TEXT NOT NULL,
  score        REAL,
  value_json   TEXT,
  observed_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS fetch_log (
  id            INTEGER PRIMARY KEY,
  feed          TEXT NOT NULL,
  attempted_at  TEXT NOT NULL,
  status        TEXT NOT NULL,
  error_msg     TEXT,
  rows_affected INTEGER
);

PRAGMA user_version = 1;
