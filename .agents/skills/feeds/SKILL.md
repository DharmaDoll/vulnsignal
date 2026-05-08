---
name: feeds
description: >
  Use when implementing or modifying any fetch job (fetch_nvd.py,
  fetch_kev.py, fetch_epss.py, fetch_trivy.py, fetch_vex.py,
  fetch_vulnrichment.py) or adapter module (trivy_adapter.py,
  exploit_adapter.py).
  Triggers on: “implement fetcher”, “add feed”, “fix adapter”,
  “write sync job”, “fetch_nvd”, “fetch_kev”, “trivy_adapter”,
  “exploit_adapter”, “retry logic”, “fetch_log”, “staleness”,
  “data freshness”.
---

# Skill: feeds

## Always read first

`docs/FEEDS.md` — contains adapter contracts, signal type taxonomy,
staleness thresholds, and per-feed specs.
Do not implement fetch logic from memory. Read the doc, then code.

## Non-negotiable rules for every fetch job

```python
# Every fetch job MUST follow this structure:
def run_sync():
    try:
        rows = fetch_with_retry()
        write_signals(rows)
        write_fetch_log(feed="nvd", status="ok", rows_affected=len(rows))
    except Exception as e:
        write_fetch_log(feed="nvd", status="error", error_msg=str(e))
        # exit cleanly — do NOT re-raise
```

- **Always write to `fetch_log`** — both on success and failure
- **Never raise uncaught exceptions** to the scheduler — log and exit cleanly
- **Never delete existing data** on failure — fall back to last known good state

## Retry pattern (mandatory)

```python
import time

def fetch_with_retry(fn, base=5, cap=300, attempts=3):
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            if i == attempts - 1:
                raise
            time.sleep(min(base * (2 ** i), cap))
```

## Adapter rules

- All access to `db/exploit.db` → only through `exploit_adapter.py`
- All access to Trivy DB → only through `trivy_adapter.py`
- On cold start, validate schema version — raise named error and abort if mismatch:
  - `ExploitDBSchemaError` for go-exploitdb
  - `TrivyDBSchemaError` for Trivy DB
- Never let raw external column names appear outside adapter files

## Signal type taxonomy (must use exactly)

|signal_type       |Source               |
|------------------|---------------------|
|`epss`            |EPSS / FIRST.org     |
|`kev`             |CISA KEV             |
|`exploit`         |go-exploitdb         |
|`package_advisory`|Trivy DB             |
|`vex`             |VEX/CSAF vendor feeds|
|`enrichment`      |NVD, Vulnrichment    |

Using wrong signal_type breaks scoring lookups — check taxonomy before writing signals.

## Staleness thresholds (for data_freshness() implementation)

|Feed        |Max staleness|
|------------|-------------|
|KEV         |3h           |
|NVD         |24h          |
|EPSS        |48h          |
|Trivy DB    |24h          |
|go-exploitdb|48h          |
|VEX/CSAF    |48h          |
|Vulnrichment|48h          |
