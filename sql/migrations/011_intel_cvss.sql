PRAGMA user_version = 11;

CREATE TABLE IF NOT EXISTS intel_cvss (
    signal_id INTEGER PRIMARY KEY REFERENCES intel_evidence(signal_id),
    vuln_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    advisory TEXT NOT NULL,
    version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    score REAL NOT NULL CHECK(score BETWEEN 0 AND 10)
);
CREATE INDEX IF NOT EXISTS idx_intel_cvss_series
    ON intel_cvss(vuln_id,provider,advisory,version,observed_at,signal_id);
CREATE TABLE IF NOT EXISTS intel_cvss_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    last_signal_id INTEGER NOT NULL
);
