PRAGMA user_version = 7;

UPDATE vulnerabilities
SET first_seen_at = published_at
WHERE published_at IS NOT NULL
  AND trim(published_at) != '';

UPDATE vulnerabilities
SET first_seen_at = COALESCE(
  first_seen_at,
  (
    SELECT json_extract(signals.value_json, '$.date_added')
    FROM signals
    WHERE signals.vuln_id = vulnerabilities.vuln_id
      AND signals.signal_type = 'kev'
    ORDER BY observed_at ASC, id ASC
    LIMIT 1
  )
)
WHERE source = 'kev'
  AND first_seen_at IS NULL;
