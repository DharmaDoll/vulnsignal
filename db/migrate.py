#!/usr/bin/env python3
from __future__ import annotations

import os
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.environ.get("VULNSIGNAL_DB_PATH", str(ROOT / "db" / "core.db")))
MIGRATIONS_DIR = ROOT / "sql" / "migrations"
INDEXES_PATH = ROOT / "sql" / "indexes.sql"


def migration_number(path: Path) -> int:
    prefix = path.name.split("_", 1)[0]
    return int(prefix)


def current_version(conn: sqlite3.Connection) -> int:
    row = conn.execute("PRAGMA user_version").fetchone()
    return int(row[0])


def apply_sql_file(conn: sqlite3.Connection, path: Path) -> None:
    sql = path.read_text(encoding="utf-8")
    for statement in sql.split(";"):
        stmt = statement.strip()
        if not stmt:
            continue
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError as exc:
            if "duplicate column name: first_seen_at" in str(exc) and "ADD COLUMN first_seen_at" in stmt:
                continue
            raise


def migrate(db_path: Path = DB_PATH) -> int:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        version = current_version(conn)
        migrations = sorted(MIGRATIONS_DIR.glob("*.sql"), key=migration_number)
        for migration in migrations:
            number = migration_number(migration)
            if number > version:
                apply_sql_file(conn, migration)
                version = current_version(conn)

        if INDEXES_PATH.exists():
            apply_sql_file(conn, INDEXES_PATH)

        conn.commit()
        return current_version(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    version = migrate()
    print(f"migrated {DB_PATH} to schema version {version}")
