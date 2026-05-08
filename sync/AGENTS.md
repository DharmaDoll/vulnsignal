# AGENTS.md — sync/

You are working inside the feed ingestion layer.

## Responsibilities of this directory

- Fetch raw data from external sources
- Normalize via adapter contracts (see `docs/FEEDS.md`)
- Write signals and vulnerabilities to `db/core.db`
- Log every run to `fetch_log` table

## Rules specific to this layer

- Every fetch function must catch exceptions and write a `fetch_log` row with `status='error'`
- Retry with exponential backoff: base 5s, max 300s, 3 attempts minimum
- After max retries, log and exit cleanly — do NOT raise uncaught exceptions to the scheduler
- `trivy_adapter.py` and `exploit_adapter.py` are isolation boundaries — never import from them in `app/`
- Validate adapter schema version on every cold start; abort sync if version mismatch

## Adapter contracts

See `docs/FEEDS.md` for:

- `ExploitRecord` dataclass definition
- `AdvisoryRecord` dataclass definition for Trivy JSON / vuln-list
- `VulnerabilityRecord` dataclass definition for Trivy DB enrichment
- Expected schema version config keys
- Signal type taxonomy (`exploit`, `package_advisory`, `enrichment`)
