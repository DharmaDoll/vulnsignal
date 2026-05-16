# Core DB analysis report queries

Use these against `db/core.db` after running `db/migrate.py`.

## 1. Scope

```sql
SELECT count(*) AS total
FROM vulnerabilities
WHERE published_at >= :cutoff;
```

## 2. Trend by year

```sql
SELECT substr(published_at, 1, 4) AS year, count(*) AS n
FROM vulnerabilities
WHERE published_at >= :cutoff
GROUP BY year
ORDER BY year;
```

## 3. Source mix

```sql
SELECT source, count(*) AS n
FROM vulnerabilities
WHERE published_at >= :cutoff
GROUP BY source
ORDER BY n DESC, source;
```

## 4. Severity mix

```sql
SELECT CASE
  WHEN severity IS NULL OR trim(severity) = '' THEN 'MISSING'
  ELSE upper(severity)
END AS severity,
count(*) AS n
FROM vulnerabilities
WHERE published_at >= :cutoff
GROUP BY severity
ORDER BY n DESC, severity;
```

## 5. Signal mix

```sql
SELECT signal_type, count(*) AS n
FROM signals
GROUP BY signal_type
ORDER BY n DESC, signal_type;
```

## 6. Recent signal overlap

```sql
WITH recent AS (
  SELECT DISTINCT vuln_id
  FROM vulnerabilities
  WHERE published_at >= :cutoff
),
flags AS (
  SELECT r.vuln_id,
         max(CASE WHEN s.signal_type = 'enrichment' THEN 1 ELSE 0 END) AS enrichment,
         max(CASE WHEN s.signal_type = 'package_advisory' THEN 1 ELSE 0 END) AS package_advisory,
         max(CASE WHEN s.signal_type = 'exploit' THEN 1 ELSE 0 END) AS exploit,
         max(CASE WHEN s.signal_type = 'kev' THEN 1 ELSE 0 END) AS kev,
         max(CASE WHEN s.signal_type = 'epss' THEN 1 ELSE 0 END) AS epss
  FROM recent r
  LEFT JOIN signals s ON s.vuln_id = r.vuln_id
  GROUP BY r.vuln_id
)
SELECT enrichment, package_advisory, exploit, kev, epss, count(*) AS n
FROM flags
GROUP BY enrichment, package_advisory, exploit, kev, epss
ORDER BY n DESC;
```

## 7. CVSS coverage by source

```sql
SELECT source,
       count(*) AS total,
       sum(CASE WHEN cvss_score IS NOT NULL THEN 1 ELSE 0 END) AS with_cvss
FROM vulnerabilities
WHERE published_at >= :cutoff
GROUP BY source
ORDER BY total DESC, source;
```

## 8. EPSS coverage and values

```sql
SELECT
  count(*) AS total_recent,
  sum(CASE WHEN e.vuln_id IS NOT NULL THEN 1 ELSE 0 END) AS with_epss
FROM vulnerabilities v
LEFT JOIN epss_current e ON e.vuln_id = v.vuln_id
WHERE v.published_at >= :cutoff;
```

```sql
SELECT v.vuln_id, v.source, v.title, e.epss, e.percentile, e.score_date
FROM vulnerabilities v
LEFT JOIN epss_current e ON e.vuln_id = v.vuln_id
WHERE v.published_at >= :cutoff
ORDER BY COALESCE(e.epss, -1) DESC, v.published_at DESC
LIMIT 10;
```

## 9. Representative examples

```sql
SELECT v.vuln_id, v.source, v.title, v.severity, v.cvss_score, e.epss, v.published_at
FROM vulnerabilities
LEFT JOIN epss_current e ON e.vuln_id = v.vuln_id
WHERE v.published_at >= :cutoff
  AND v.cvss_score IS NOT NULL
ORDER BY v.cvss_score DESC, COALESCE(e.epss, -1) DESC, v.published_at DESC
LIMIT 10;
```

```sql
SELECT DISTINCT v.vuln_id, v.source, v.title, v.severity, e.epss, v.published_at
FROM vulnerabilities v
JOIN signals s ON s.vuln_id = v.vuln_id
LEFT JOIN epss_current e ON e.vuln_id = v.vuln_id
WHERE v.published_at >= :cutoff
  AND s.signal_type IN ('exploit', 'kev')
ORDER BY v.published_at DESC, v.vuln_id
LIMIT 10;
```

## Checklist

- Convert the user request into an explicit cutoff date.
- Run the same query set every time.
- Report counts as distinct vuln_ids unless explicitly saying "signals".
- Mention when `assets` and `findings` are absent.
- Always include EPSS in representative examples and ranked vulnerability lists.
