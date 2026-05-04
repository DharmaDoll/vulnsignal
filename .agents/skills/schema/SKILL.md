-----

## name: schema
description: Use when creating or modifying database schema, writing migrations, or working with db/migrate.py. Triggers on tasks like “add table”, “create migration”, “modify schema”, “add column”, “add index”.

Always read `docs/SCHEMA.md` before writing any schema or migration code.

Key constraints:

- Migration files must be idempotent SQL named NNN_description.sql
- Increment PRAGMA user_version in every migration file
- Never modify already-applied migration files — create a new one
- db/migrate.py must be invoked before any DB operation
- signals table is append-only — never add UPDATE or DELETE for signal rows
