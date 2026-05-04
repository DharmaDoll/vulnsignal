-----

## name: feeds
description: Use when implementing fetch jobs (fetch_nvd.py, fetch_kev.py, etc.) or adapter modules (trivy_adapter.py, exploit_adapter.py). Triggers on tasks like “implement fetcher”, “add feed”, “fix adapter”, “write sync job”.

Always read `docs/FEEDS.md` before writing any fetch or adapter code.

Key constraints:

- Every fetch job must write to fetch_log table on both success and failure
- Retry: exponential backoff base 5s, cap 300s, 3 attempts
- Adapters must validate schema version on cold start — raise named error and abort on mismatch
- Never let raw external column names escape the adapter file
- Signal types: use `exploit` for go-exploitdb, `package_advisory` for Trivy DB — never mix them
