PRAGMA user_version = 8;

CREATE TABLE IF NOT EXISTS epss_batch (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    score_date TEXT NOT NULL,
    digest TEXT NOT NULL,
    row_count INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_signal_observation_time ON signals(julianday(observed_at));
