# Hot Intel Reference

## Common commands

Refresh hot signals:

```bash
python3 -m sync.fetch_hot
```

Profile shortcuts:

```bash
python3 -m sync.fetch_hot --profile strict
python3 -m sync.fetch_hot --profile balanced
python3 -m sync.fetch_hot --profile broad
```

Target one or more CVEs directly:

```bash
python3 -m sync.fetch_hot --vuln-id CVE-2026-42945
python3 -m sync.fetch_hot --vuln-id CVE-2026-42945 --vuln-id CVE-2026-3300
```

Widen discovery with manual terms:

```bash
python3 -m sync.fetch_hot --search-cap 20 --query-term "Palo Alto" --query-term "active exploitation"
```

Inspect current hot rows:

```bash
python3 -m app.skills hot --limit 20 --details
```

## Reading the output

- `hot_score` is the main ranking value in `app.skills hot`.
- `evidence_types` tells you whether the row was driven by `public_poc`,
  `active_exploitation`, `news_mention`, or `kev`.
- `source_types` summarizes whether the evidence came from search, news, social,
  vendor, or CISA.
- `search_hits` are reference-only matches. They are not all stored as signals.
- `evidence_details` are the classified hits that actually contributed to the
  score.

## Practical checks

- If `hot` is empty, verify `core.db` was refreshed first and that outbound HTTP
  works.
- If Hatena does not appear, that is acceptable; it is a best-effort source.
- If a CVE is already present in `signals`, a repeat fetch may still add newer
  evidence with a different `observed_at`.
