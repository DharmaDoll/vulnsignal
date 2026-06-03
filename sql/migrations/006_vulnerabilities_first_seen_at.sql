PRAGMA user_version = 6;

ALTER TABLE vulnerabilities ADD COLUMN first_seen_at TEXT;

UPDATE vulnerabilities
SET first_seen_at = COALESCE(
  first_seen_at,
  (SELECT MIN(observed_at) FROM signals WHERE signals.vuln_id = vulnerabilities.vuln_id),
  published_at,
  updated_at
)
WHERE first_seen_at IS NULL;
