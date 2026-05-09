from __future__ import annotations

from pathlib import Path
from typing import Any

from sync.common import DB_PATH, connect

from app import scoring


def _connection(db_path: Path | None = None):
    return connect(db_path or DB_PATH)


def find_vuln(vuln_id: str, db_path: Path | None = None) -> dict[str, Any] | None:
    conn = _connection(db_path)
    try:
        return scoring.find_vuln(conn, vuln_id)
    finally:
        conn.close()


def top_risks(limit: int = 10, db_path: Path | None = None) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.top_risks(conn, limit=limit)
    finally:
        conn.close()


def recommend_patch_queue(limit: int = 20, db_path: Path | None = None) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.recommend_patch_queue(conn, limit=limit)
    finally:
        conn.close()


def has_exploit(vuln_id: str, db_path: Path | None = None) -> bool:
    conn = _connection(db_path)
    try:
        return scoring.has_exploit(conn, vuln_id)
    finally:
        conn.close()


def data_freshness(db_path: Path | None = None) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.data_freshness(conn)
    finally:
        conn.close()
