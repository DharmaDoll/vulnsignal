PRAGMA user_version = 3;

CREATE TABLE IF NOT EXISTS asset_observations (
  id           INTEGER PRIMARY KEY,
  asset_id     TEXT NOT NULL REFERENCES assets(asset_id),
  kind         TEXT NOT NULL,      -- 'os' | 'framework' | 'runtime' | 'middleware' | 'product' | 'language'
  name         TEXT NOT NULL,      -- normalized label such as 'Ubuntu' or 'Nuxt.js'
  version      TEXT,               -- coarse version like '22' or '3.x'
  confidence   REAL NOT NULL DEFAULT 0.5,
  source       TEXT NOT NULL,      -- discovery source / method
  details_json TEXT,
  observed_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_asset_observations_asset_kind
  ON asset_observations(asset_id, kind, observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_asset_observations_observed_at
  ON asset_observations(observed_at);
