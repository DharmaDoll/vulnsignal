# Core DB analysis report queries

Use these against `db/core.db` after running `db/migrate.py`.

## 1. Scope

```sql
SELECT count(*) AS total
FROM vulnerabilities
WHERE first_seen_at >= :cutoff;
```

## 2. Trend by year

```sql
SELECT substr(first_seen_at, 1, 4) AS year, count(*) AS n
FROM vulnerabilities
WHERE first_seen_at >= :cutoff
GROUP BY year
ORDER BY year;
```

## 3. Source mix

```sql
SELECT source, count(*) AS n
FROM vulnerabilities
WHERE first_seen_at >= :cutoff
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
WHERE first_seen_at >= :cutoff
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
  WHERE first_seen_at >= :cutoff
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
WHERE first_seen_at >= :cutoff
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
WHERE v.first_seen_at >= :cutoff;
```

```sql
SELECT v.vuln_id, v.source, v.title, e.epss, e.percentile, e.score_date
FROM vulnerabilities v
LEFT JOIN epss_current e ON e.vuln_id = v.vuln_id
WHERE v.first_seen_at >= :cutoff
ORDER BY COALESCE(e.epss, -1) DESC, v.first_seen_at DESC
LIMIT 10;
```

## 9. Representative examples

```sql
SELECT v.vuln_id, v.source, v.title, v.severity, v.cvss_score, e.epss, v.published_at, v.first_seen_at
FROM vulnerabilities
LEFT JOIN epss_current e ON e.vuln_id = v.vuln_id
WHERE v.first_seen_at >= :cutoff
  AND v.cvss_score IS NOT NULL
ORDER BY v.cvss_score DESC, COALESCE(e.epss, -1) DESC, v.first_seen_at DESC
LIMIT 10;
```

```sql
SELECT DISTINCT v.vuln_id, v.source, v.title, v.severity, e.epss, v.published_at, v.first_seen_at
FROM vulnerabilities v
JOIN signals s ON s.vuln_id = v.vuln_id
LEFT JOIN epss_current e ON e.vuln_id = v.vuln_id
WHERE v.first_seen_at >= :cutoff
  AND s.signal_type IN ('exploit', 'kev')
ORDER BY v.first_seen_at DESC, v.vuln_id
LIMIT 10;
```

## 10. Recent exploit risks

```sql
WITH recent AS (
  SELECT vuln_id, source, title, severity, cvss_score, published_at, first_seen_at
  FROM vulnerabilities
  WHERE first_seen_at >= :cutoff
),
latest AS (
  SELECT vuln_id, signal_type, observed_at, id,
         row_number() OVER (PARTITION BY vuln_id, signal_type ORDER BY observed_at DESC, id DESC) AS rn
  FROM signals
),
flags AS (
  SELECT r.vuln_id, r.source, r.title, r.severity, COALESCE(r.cvss_score, 0) AS cvss_score, r.published_at, r.first_seen_at,
         max(CASE WHEN l.signal_type = 'kev' THEN 1 ELSE 0 END) AS kev_present,
         max(CASE WHEN l.signal_type = 'exploit' THEN 1 ELSE 0 END) AS exploit_present
  FROM recent r
  LEFT JOIN latest l ON l.vuln_id = r.vuln_id AND l.rn = 1
  GROUP BY r.vuln_id
)
SELECT f.vuln_id,
       f.published_at,
       f.first_seen_at,
       f.source,
       f.severity,
       f.cvss_score,
       COALESCE(e.epss, 0) AS epss,
       ROUND(f.cvss_score * 4.0 + COALESCE(e.epss, 0) * 20.0 + CASE WHEN f.kev_present = 1 THEN 15 ELSE 0 END + CASE WHEN f.exploit_present = 1 THEN 10 ELSE 0 END, 2) AS score,
       CASE WHEN f.kev_present = 1 THEN 'kev ' ELSE '' END || CASE WHEN f.exploit_present = 1 THEN 'exploit' ELSE '' END AS signals,
       f.title
FROM flags f
LEFT JOIN epss_current e ON e.vuln_id = f.vuln_id
WHERE f.exploit_present = 1
ORDER BY score DESC, f.kev_present DESC, f.cvss_score DESC, COALESCE(e.epss, 0) DESC, f.first_seen_at DESC
LIMIT 20;
```

## Checklist

- Convert the user request into an explicit cutoff date.
- Run the same query set every time.
- Report counts as distinct vuln_ids unless explicitly saying "signals".
- Mention when `assets` and `findings` are absent.
- Always include EPSS in representative examples and ranked vulnerability lists.
- Always include `published_at` in representative examples and ranked vulnerability lists.
- For recency-based report windows, use `first_seen_at` as the scope boundary.
