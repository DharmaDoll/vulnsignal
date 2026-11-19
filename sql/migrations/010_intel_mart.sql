PRAGMA user_version = 10;

CREATE TABLE IF NOT EXISTS intel_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  last_signal_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS intel_evidence (
  signal_id INTEGER PRIMARY KEY REFERENCES signals(id),
  vuln_id TEXT NOT NULL,
  provider TEXT NOT NULL,
  title TEXT,
  observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_intel_evidence_id ON intel_evidence(vuln_id, observed_at DESC);
CREATE VIRTUAL TABLE IF NOT EXISTS intel_terms USING fts5(product, mention, content='');
CREATE TABLE IF NOT EXISTS intel_event (
  vuln_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  identity TEXT NOT NULL,
  signal_id INTEGER NOT NULL REFERENCES intel_evidence(signal_id),
  source_date TEXT,
  effective_at TEXT NOT NULL,
  PRIMARY KEY(vuln_id,kind,identity)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_intel_event_time ON intel_event(effective_at DESC);
