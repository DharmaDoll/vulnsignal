PRAGMA user_version = 9;

CREATE TABLE IF NOT EXISTS feed_metrics (
    fetch_id INTEGER PRIMARY KEY REFERENCES fetch_log(id),
    elapsed_seconds REAL NOT NULL,
    rows_read INTEGER,
    http_body_bytes INTEGER NOT NULL
);
