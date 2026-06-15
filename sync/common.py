from __future__ import annotations

import json
import os
import shlex
import socket
import sqlite3
import subprocess
import tempfile
import time
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from urllib.error import URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(os.environ.get("VULNSIGNAL_DB_PATH", str(ROOT / "db" / "core.db")))
CACHE_DIR = ROOT / "db" / "cache"
DOH_ENDPOINTS = (
    "https://1.1.1.1/dns-query",
    "https://8.8.8.8/resolve",
)


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
        except (URLError, TimeoutError, socket.gaierror) as exc:
            last_error = exc
            resolved_ip = _resolve_request_host_via_doh(request)
            if resolved_ip:
                try:
                    with _urlopen_with_resolved_host(request, resolved_ip):
                        with urlopen(request, timeout=60) as response:
                            return response.read()
                except (URLError, TimeoutError, socket.gaierror) as retry_exc:
                    last_error = retry_exc
            try:
                return _fetch_bytes_via_curl(url, headers=headers, timeout=60)
            except FetchError as curl_exc:
                last_error = curl_exc
            if attempt < attempts - 1:
                time.sleep(min(300, 5 * (2**attempt)))
    raise FetchError(str(last_error))


def _fetch_bytes_via_curl(url: str, headers: dict[str, str] | None = None, timeout: int = 60) -> bytes:
    cmd_parts = [
        "curl",
        "-4",
        "-L",
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        str(timeout),
    ]
    for key, value in (headers or {}).items():
        cmd_parts.extend(["-H", f"{key}: {value}"])
    cmd_parts.append(url)
    shell_cmd = " ".join(shlex.quote(part) for part in cmd_parts)
    result = subprocess.run(["bash", "-lc", shell_cmd], check=False, capture_output=True)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise FetchError(stderr or f"curl exited with status {result.returncode}")
    return result.stdout


def _resolve_via_doh(host: str) -> str | None:
    query_headers = {"Accept": "application/dns-json", "User-Agent": "vulnsignal/0.1"}
    for endpoint in DOH_ENDPOINTS:
        try:
            cmd = [
                "curl",
                "-4",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                "15",
                "-H",
                f"Accept: {query_headers['Accept']}",
                "-H",
                f"User-Agent: {query_headers['User-Agent']}",
                f"{endpoint}?name={host}&type=A",
            ]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            if result.returncode != 0:
                continue
            payload = json.loads(result.stdout)
            if payload.get("Status") != 0:
                continue
            answers = payload.get("Answer") or []
            for answer in answers:
                if isinstance(answer, dict) and answer.get("type") == 1 and answer.get("data"):
                    return str(answer["data"])
        except Exception:
            continue
    return None


def _resolve_request_host_via_doh(request: Request) -> str | None:
    parts = urlsplit(request.full_url)
    host = parts.hostname
    if not host:
        return None
    try:
        socket.inet_aton(host)
        return None
    except OSError:
        pass

    return _resolve_via_doh(host)


@contextmanager
def _urlopen_with_resolved_host(request: Request, resolved_ip: str):
    parts = urlsplit(request.full_url)
    host = parts.hostname
    if not host:
        yield
        return

    original_getaddrinfo = socket.getaddrinfo

    def patched_getaddrinfo(node: str, port: int | str | None, family=0, type=0, proto=0, flags=0):
        if node == host:
            return original_getaddrinfo(resolved_ip, port, family, type, proto, flags)
        return original_getaddrinfo(node, port, family, type, proto, flags)

    socket.getaddrinfo = patched_getaddrinfo  # type: ignore[assignment]
    try:
        yield
    finally:
        socket.getaddrinfo = original_getaddrinfo  # type: ignore[assignment]


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


def git_changed_files(source_dir: Path, since_ref: str) -> list[Path]:
    repo_dir = source_dir if source_dir.is_dir() else source_dir.parent
    try:
        subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "--verify", since_ref],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise FetchError(f"invalid git ref {since_ref!r} in {repo_dir}") from exc

    try:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "diff", "--name-only", "--diff-filter=AM", f"{since_ref}..HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise FetchError(f"unable to compute git diff for {repo_dir}") from exc

    return [Path(line) for line in result.stdout.splitlines() if line.endswith(".json")]


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
    cache_used: bool = False,
) -> None:
    conn.execute(
        """
        INSERT INTO fetch_log (feed, attempted_at, status, error_msg, rows_affected, cache_used)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (feed, utc_now(), status, error_msg, rows_affected, int(cache_used)),
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
    first_seen_at: str | None = None,
    updated_at: str | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO vulnerabilities (
          vuln_id, source, title, summary, severity, cvss_score, cvss_source, published_at, first_seen_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(vuln_id) DO UPDATE SET
          title = COALESCE(excluded.title, vulnerabilities.title),
          summary = COALESCE(excluded.summary, vulnerabilities.summary),
          severity = COALESCE(excluded.severity, vulnerabilities.severity),
          cvss_score = COALESCE(excluded.cvss_score, vulnerabilities.cvss_score),
          cvss_source = COALESCE(excluded.cvss_source, vulnerabilities.cvss_source),
          published_at = COALESCE(excluded.published_at, vulnerabilities.published_at),
          first_seen_at = CASE
            WHEN vulnerabilities.first_seen_at IS NULL THEN excluded.first_seen_at
            WHEN excluded.first_seen_at IS NULL THEN vulnerabilities.first_seen_at
            WHEN excluded.first_seen_at < vulnerabilities.first_seen_at THEN excluded.first_seen_at
            ELSE vulnerabilities.first_seen_at
          END,
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
            first_seen_at,
            updated_at,
        ),
    )


def upsert_asset(
    conn: sqlite3.Connection,
    asset_id: str,
    hostname: str,
    os: str | None = None,
    version: str | None = None,
    owner: str | None = None,
    exposed: int | None = None,
    criticality: str | None = None,
) -> None:
    before = conn.total_changes
    conn.execute(
        """
        INSERT INTO assets (
          asset_id, hostname, os, version, owner, exposed, criticality
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id) DO UPDATE SET
          hostname = CASE
            WHEN assets.hostname IS NULL OR trim(assets.hostname) = '' THEN excluded.hostname
            ELSE assets.hostname
          END,
          os = COALESCE(assets.os, excluded.os),
          version = COALESCE(assets.version, excluded.version),
          owner = COALESCE(assets.owner, excluded.owner),
          exposed = COALESCE(assets.exposed, excluded.exposed),
          criticality = COALESCE(assets.criticality, excluded.criticality)
        WHERE
          (assets.hostname IS NULL OR trim(assets.hostname) = '')
          OR (assets.os IS NULL AND excluded.os IS NOT NULL)
          OR (assets.version IS NULL AND excluded.version IS NOT NULL)
          OR (assets.owner IS NULL AND excluded.owner IS NOT NULL)
          OR (assets.exposed IS NULL AND excluded.exposed IS NOT NULL)
          OR (assets.criticality IS NULL AND excluded.criticality IS NOT NULL)
        """,
        (asset_id, hostname, os, version, owner, exposed, criticality),
    )
    return conn.total_changes > before


def append_asset_observation(
    conn: sqlite3.Connection,
    asset_id: str,
    kind: str,
    name: str,
    version: str | None = None,
    confidence: float = 0.5,
    source: str = "csv",
    details: dict[str, Any] | None = None,
    observed_at: str | None = None,
) -> bool:
    details_json = json.dumps(details or {}, sort_keys=True, ensure_ascii=False) if details is not None else None
    before = conn.total_changes
    conn.execute(
        """
        INSERT INTO asset_observations (
          asset_id, kind, name, version, confidence, source, details_json, observed_at
        )
        SELECT ?, ?, ?, ?, ?, ?, ?, ?
        WHERE NOT EXISTS (
          SELECT 1
          FROM asset_observations
          WHERE asset_id = ?
            AND kind = ?
            AND name = ?
            AND COALESCE(version, '') = COALESCE(?, '')
            AND COALESCE(confidence, -1) = COALESCE(?, -1)
            AND source = ?
            AND COALESCE(details_json, '') = COALESCE(?, '')
        )
        """,
        (
            asset_id,
            kind,
            name,
            version,
            confidence,
            source,
            details_json,
            observed_at or utc_now(),
            asset_id,
            kind,
            name,
            version,
            confidence,
            source,
            details_json,
        ),
    )
    return conn.total_changes > before
