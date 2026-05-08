---
name: schema
description: >
  Use when creating or modifying database schema, writing migration files,
  working with db/migrate.py, adding tables or columns, adding indexes,
  or debugging schema-related errors.
  Triggers on: “add table”, “create migration”, “modify schema”, “add column”,
  “add index”, “PRAGMA user_version”, “migrate.py”, “schema.sql”,
  “migrations/”.
---

# Skill: schema

## Always read first

`docs/SCHEMA.md` — contains all table definitions, index definitions,
migration naming rules, and the signals append-only invariant.
Do not write schema from memory. Read the doc, then code.

## Migration rules (non-negotiable)

- Every migration file: `sql/migrations/NNN_description.sql` (e.g. `003_add_signals_index.sql`)
- First line of every migration: `PRAGMA user_version = N;`
- All migrations must be **idempotent** — safe to run twice
- **Never modify an already-applied migration file** — always create a new one
- `db/migrate.py` must be invoked before any DB operation (tests, scripts, API start)

```sql
-- Template: sql/migrations/002_example.sql
PRAGMA user_version = 2;

CREATE TABLE IF NOT EXISTS new_table (
  id INTEGER PRIMARY KEY,
  ...
);
```

## Signals table invariant

```sql
-- NEVER write these against the signals table:
UPDATE signals ...;
DELETE FROM signals ...;

-- ALWAYS append:
INSERT INTO signals (vuln_id, signal_type, provider, score, value_json, observed_at)
VALUES (?, ?, ?, ?, ?, ?);
```

The signals table is append-only. Ordering by `observed_at DESC` gives the latest value.
Violating this breaks EPSS drift tracking, VEX reversal history, and audit trails.

## Key table relationships

```
vulnerabilities (vuln_id PK)
       │
       ├── signals (vuln_id FK) — append-only intelligence
       │
findings (asset_id FK, vuln_id FK)
       │
decisions (vuln_id FK)

assets (asset_id PK)
       │
findings (asset_id FK)

fetch_log — operational log, independent
```

## Required indexes (already in sql/indexes.sql — do not duplicate)

- `signals(vuln_id)`
- `signals(signal_type)`
- `signals(observed_at)`
- `findings(vuln_id)`
- `findings(asset_id)`
- `findings(risk_score DESC)`
- `fetch_log(feed, attempted_at DESC)`
