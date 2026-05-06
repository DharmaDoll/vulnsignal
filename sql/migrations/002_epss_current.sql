CREATE TABLE IF NOT EXISTS epss_current (
  vuln_id     TEXT PRIMARY KEY,
  epss        REAL NOT NULL,
  percentile  REAL,
  score_date  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_epss_current_epss ON epss_current(epss DESC);
CREATE INDEX IF NOT EXISTS idx_epss_current_percentile ON epss_current(percentile DESC);

PRAGMA user_version = 2;
