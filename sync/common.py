from __future__ import annotations

import json
import os
import sqlite3
import tempfile
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.environ.get("VULNSIGNAL_DB_PATH", str(ROOT / "db" / "core.db")))
CACHE_DIR = ROOT / "db" / "cache"


class FetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class FetchResult:
    rows_fetched: int
    rows_written: int
    cache_used: bool = False


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_bytes(url: str, headers: dict[str, str] | None = None, attempts: int = 3) -> bytes:
    request = Request(url, headers=headers or {})
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            with urlopen(request, timeout=60) as response:
                return response.read()
        except (URLError, TimeoutError) as exc:
            last_error = exc
            if attempt < attempts - 1:
                time.sleep(min(300, 5 * (2**attempt)))
    raise FetchError(str(last_error))


def fetch_text(url: str, headers: dict[str, str] | None = None, attempts: int = 3) -> str:
    try:
        return fetch_bytes(url, headers=headers, attempts=attempts).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FetchError(str(exc)) from exc


def fetch_json(url: str, headers: dict[str, str] | None = None, attempts: int = 3) -> Any:
    try:
        return json.loads(fetch_text(url, headers=headers, attempts=attempts))
    except json.JSONDecodeError as exc:
        raise FetchError(str(exc)) from exc


def cache_path(feed: str, suffix: str = "json") -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{feed}.{suffix}"


def read_cache(feed: str) -> Any:
    path = cache_path(feed)
    if not path.exists():
        raise FetchError(f"cache missing for {feed}: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def write_cache(feed: str, payload: Any) -> None:
    cache_path(feed).write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


class JsonArrayCacheWriter(AbstractContextManager["JsonArrayCacheWriter"]):
    def __init__(self, feed: str):
        self._feed = feed
        self._path = cache_path(feed)
        self._tmp: Any = None
        self._started = False
        self._closed = False

    def __enter__(self) -> "JsonArrayCacheWriter":
        self._tmp = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=str(self._path.parent),
            prefix=f"{self._path.name}.tmp.",
        )
        self._tmp.write("[")
        return self

    def write(self, payload: Any) -> None:
        if self._closed or self._tmp is None:
            raise RuntimeError("cache writer is not open")
        if self._started:
            self._tmp.write(",")
        self._tmp.write(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        self._started = True

    def commit(self) -> None:
        if self._closed or self._tmp is None:
            return
        self._tmp.write("]")
        self._tmp.flush()
        os.fsync(self._tmp.fileno())
        self._tmp.close()
        os.replace(self._tmp.name, self._path)
        self._closed = True

    def abort(self) -> None:
        if self._closed or self._tmp is None:
            return
        try:
            self._tmp.close()
        finally:
            try:
                os.unlink(self._tmp.name)
            except FileNotFoundError:
                pass
        self._closed = True

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is None:
            if self._tmp is not None and not self._closed:
                if not self._started:
                    self._tmp.write("]")
                    self._tmp.flush()
                    os.fsync(self._tmp.fileno())
                    self._tmp.close()
                    os.replace(self._tmp.name, self._path)
                else:
                    self.commit()
            return False
        self.abort()
        return False


def read_text_cache(feed: str, suffix: str = "txt") -> str:
    path = cache_path(feed, suffix)
    if not path.exists():
        raise FetchError(f"cache missing for {feed}: {path}")
    return path.read_text(encoding="utf-8")


def write_text_cache(feed: str, payload: str, suffix: str = "txt") -> None:
    cache_path(feed, suffix).write_text(payload, encoding="utf-8")


def read_bytes_cache(feed: str, suffix: str = "bin") -> bytes:
    path = cache_path(feed, suffix)
    if not path.exists():
        raise FetchError(f"cache missing for {feed}: {path}")
    return path.read_bytes()


def write_bytes_cache(feed: str, payload: bytes, suffix: str = "bin") -> None:
    cache_path(feed, suffix).write_bytes(payload)


def log_fetch(
    conn: sqlite3.Connection,
    feed: str,
    status: str,
    rows_affected: int = 0,
    error_msg: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO fetch_log (feed, attempted_at, status, error_msg, rows_affected)
        VALUES (?, ?, ?, ?, ?)
        """,
        (feed, utc_now(), status, error_msg, rows_affected),
    )


def append_signal(
    conn: sqlite3.Connection,
    vuln_id: str,
    signal_type: str,
    provider: str,
    score: float | None,
    value: dict[str, Any],
    observed_at: str | None = None,
) -> bool:
    value_json = json.dumps(value, sort_keys=True, ensure_ascii=False)
    before = conn.total_changes
    # observed_at is a history field; exact signal identity ignores it so reruns stay idempotent.
    conn.execute(
        """
        INSERT INTO signals (vuln_id, signal_type, provider, score, value_json, observed_at)
        SELECT ?, ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
          SELECT 1
          FROM signals
          WHERE vuln_id = ?
            AND signal_type = ?
            AND provider = ?
            AND score IS ?
            AND value_json = ?
        )
        """,
        (
            vuln_id,
            signal_type,
            provider,
            score,
            value_json,
            observed_at or utc_now(),
            vuln_id,
            signal_type,
            provider,
            score,
            value_json,
        ),
    )
    return conn.total_changes > before


def upsert_vulnerability(
    conn: sqlite3.Connection,
    vuln_id: str,
    source: str,
    title: str | None = None,
    summary: str | None = None,
    severity: str | None = None,
    cvss_score: float | None = None,
    cvss_source: str | None = None,
    published_at: str | None = None,
    updated_at: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO vulnerabilities (
          vuln_id, source, title, summary, severity, cvss_score, cvss_source, published_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(vuln_id) DO UPDATE SET
          title = COALESCE(excluded.title, vulnerabilities.title),
          summary = COALESCE(excluded.summary, vulnerabilities.summary),
          severity = COALESCE(excluded.severity, vulnerabilities.severity),
          cvss_score = COALESCE(excluded.cvss_score, vulnerabilities.cvss_score),
          cvss_source = COALESCE(excluded.cvss_source, vulnerabilities.cvss_source),
          published_at = COALESCE(excluded.published_at, vulnerabilities.published_at),
          updated_at = COALESCE(excluded.updated_at, vulnerabilities.updated_at)
        """,
        (
            vuln_id,
            source,
            title,
            summary,
            severity,
            cvss_score,
            cvss_source,
            published_at,
            updated_at,
        ),
    )
