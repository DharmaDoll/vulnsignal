PRAGMA user_version = 5;

CREATE TABLE IF NOT EXISTS report_history (
  id            INTEGER PRIMARY KEY,
  report_key    TEXT NOT NULL,
  vuln_id       TEXT NOT NULL REFERENCES vulnerabilities(vuln_id),
  report_run_id TEXT,
  payload_json  TEXT,
  reported_at   TEXT NOT NULL
);

