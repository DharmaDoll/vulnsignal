# Core DB insight queries

Run `db/migrate.py` first. Bind `:cutoff` to an explicit ISO date.

## 1. Dataset composition

```sql
SELECT
  count(*) AS total,
  count(DISTINCT source) AS source_count,
  count(DISTINCT substr(published_at, 1, 4)) AS year_count
FROM vulnerabilities
WHERE published_at >= :cutoff;
```

## 2. Source share

```sql
SELECT source, count(*) AS n,
       round(100.0 * count(*) / sum(count(*)) OVER (), 2) AS pct
FROM vulnerabilities
WHERE published_at >= :cutoff
GROUP BY source
ORDER BY n DESC, source;
```

## 3. Severity distribution with missingness

```sql
SELECT
  CASE
    WHEN severity IS NULL OR trim(severity) = '' THEN 'MISSING'
    ELSE upper(severity)
  END AS severity,
  count(*) AS n
FROM vulnerabilities
WHERE published_at >= :cutoff
GROUP BY severity
ORDER BY n DESC, severity;
```

## 4. CVSS coverage by source

```sql
SELECT source,
       count(*) AS total,
       sum(CASE WHEN cvss_score IS NOT NULL THEN 1 ELSE 0 END) AS with_cvss,
       round(100.0 * sum(CASE WHEN cvss_score IS NOT NULL THEN 1 ELSE 0 END) / count(*), 2) AS pct
FROM vulnerabilities
WHERE published_at >= :cutoff
GROUP BY source
ORDER BY total DESC, source;
```

## 5. Signal combination matrix

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
ORDER BY n DESC, enrichment DESC, package_advisory DESC, exploit DESC, kev DESC, epss DESC;
```

## 6. Strong signal clusters

```sql
SELECT v.vuln_id,
       v.source,
       v.title,
       v.severity,
       v.cvss_score,
       max(CASE WHEN s.signal_type = 'epss' THEN 1 ELSE 0 END) AS has_epss,
       max(CASE WHEN s.signal_type = 'exploit' THEN 1 ELSE 0 END) AS has_exploit,
       max(CASE WHEN s.signal_type = 'kev' THEN 1 ELSE 0 END) AS has_kev,
       max(CASE WHEN s.signal_type = 'package_advisory' THEN 1 ELSE 0 END) AS has_package
FROM vulnerabilities v
LEFT JOIN signals s ON s.vuln_id = v.vuln_id
WHERE v.published_at >= :cutoff
GROUP BY v.vuln_id
ORDER BY has_kev DESC, has_exploit DESC, has_package DESC, has_epss DESC, v.cvss_score DESC
LIMIT 20;
```

## 7. Weakly supported records

```sql
SELECT v.vuln_id, v.source, v.title, v.severity, v.cvss_score
FROM vulnerabilities v
LEFT JOIN signals s ON s.vuln_id = v.vuln_id
WHERE v.published_at >= :cutoff
GROUP BY v.vuln_id
HAVING sum(CASE WHEN s.signal_type IN ('enrichment', 'package_advisory', 'exploit', 'kev', 'epss') THEN 1 ELSE 0 END) <= 1
ORDER BY v.published_at DESC
LIMIT 20;
```

## 8. Finding-oriented summary if assets exist

```sql
SELECT status, count(*) AS n
FROM findings
GROUP BY status
ORDER BY n DESC, status;
```

```sql
SELECT count(*) AS top_risk_count
FROM findings
WHERE risk_score >= 80 AND COALESCE(status, 'open') = 'open';
```

## Checklist

- Always use explicit numbers and one interpretation sentence per section.
- Mention whether the corpus is dominated by a single source.
- Mention whether the corpus is mostly enriched context or has strong escalation signals.
- Mention absent `assets` / `findings` as a limitation if needed.
