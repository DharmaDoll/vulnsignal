ALTER TABLE fetch_log ADD COLUMN cache_used INTEGER NOT NULL DEFAULT 0;

PRAGMA user_version = 4;
