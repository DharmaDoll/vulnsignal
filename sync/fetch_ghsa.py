#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sync.common import (
    ROOT,
    FetchResult,
    append_signal,
    connect,
    log_fetch,
    read_cache,
    upsert_vulnerability,
    utc_now,
    write_cache,
)


FEED = "ghsa"
PROVIDER = "GitHub Advisory Database"
DEFAULT_SOURCE_DIR = ROOT / "data" / "github-advisory-database-mirror"
MIN_YEAR = 2015


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", []):
            return value
    return None


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def _year_from_iso(value: str | None) -> int | None:
    if not value or len(value) < 4:
        return None
    try:
        return int(value[:4])
    except ValueError:
        return None


def _alias_year(alias: str) -> int | None:
    if not alias.startswith("CVE-"):
        return None
    parts = alias.split("-")
    if len(parts) < 3:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _keep_for_core_db(item: dict[str, Any], min_year: int) -> bool:
    year = _year_from_iso(item.get("published_at"))
    if year is not None:
        return year >= min_year
    for alias in item.get("aliases") or []:
        if isinstance(alias, str):
            alias_year = _alias_year(alias)
            if alias_year is not None:
                return alias_year >= min_year
    return True


def _candidate_roots(source_dir: Path, include_unreviewed: bool) -> list[Path]:
    if source_dir.is_file():
        return [source_dir.parent]
    advisory_root = source_dir / "advisories"
    if advisory_root.is_dir():
        roots = [advisory_root / "github-reviewed"]
        if include_unreviewed:
            roots.append(advisory_root / "unreviewed")
        return [root for root in roots if root.exists()]
    return [source_dir]


def _iter_json_files(source_dir: Path, include_unreviewed: bool) -> list[Path]:
    paths: list[Path] = []
    for root in _candidate_roots(source_dir, include_unreviewed):
        if root.is_file() and root.suffix == ".json":
            paths.append(root)
        elif root.is_dir():
            paths.extend(sorted(path for path in root.rglob("*.json") if path.is_file()))
    return paths


def _normalize_severity(value: Any) -> str | None:
    if isinstance(value, str):
        severity = value.strip()
        return severity.upper() if severity else None
    if isinstance(value, dict):
        return _normalize_severity(_first_non_empty(value.get("severity"), value.get("score"), value.get("level")))
    if isinstance(value, list):
        for item in value:
            severity = _normalize_severity(item)
            if severity:
                return severity
    return None


def _extract_cvss_vector(value: Any) -> str | None:
    if isinstance(value, dict):
        vector = value.get("score") or value.get("vector")
        return vector if isinstance(vector, str) else None
    if isinstance(value, list):
        for item in value:
            vector = _extract_cvss_vector(item)
            if vector:
                return vector
    if isinstance(value, str) and value.startswith("CVSS:"):
        return value
    return None


def _extract_aliases(item: dict[str, Any]) -> list[str]:
    aliases = item.get("aliases")
    if not isinstance(aliases, list):
        return []
    return _unique([alias for alias in aliases if isinstance(alias, str) and alias])


def _extract_vuln_ids(item: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    ghsa_id = _first_non_empty(item.get("ghsa_id"), item.get("id"))
    if isinstance(ghsa_id, str) and ghsa_id:
        ids.append(ghsa_id)
    ids.extend(_extract_aliases(item))
    return _unique(ids)


def _extract_references(item: dict[str, Any]) -> list[str]:
    references: list[str] = []
    raw_references = item.get("references")
    if isinstance(raw_references, list):
        for entry in raw_references:
            if isinstance(entry, str) and entry:
                references.append(entry)
            elif isinstance(entry, dict):
                url = _first_non_empty(entry.get("url"), entry.get("href"))
                if isinstance(url, str) and url:
                    references.append(url)
    return _unique(references)


def _extract_affected(item: dict[str, Any]) -> list[dict[str, Any]]:
    affected: list[dict[str, Any]] = []
    raw_affected = item.get("affected")
    if not isinstance(raw_affected, list):
        return affected

    for entry in raw_affected:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        if not isinstance(package, dict):
            package = {}
        package_name = _first_non_empty(package.get("name"), package.get("package_name"))
        ecosystem = _first_non_empty(package.get("ecosystem"), package.get("Ecosystem"))
        affected_versions: list[str] = []
        fixed_version: str | None = None
        ranges = entry.get("ranges")
        if isinstance(ranges, list):
            for range_item in ranges:
                if not isinstance(range_item, dict):
                    continue
                range_type = range_item.get("type")
                events = range_item.get("events") or []
                if not isinstance(events, list):
                    events = [events]
                for event in events:
                    if not isinstance(event, dict):
                        continue
                    for key in ("introduced", "fixed", "last_affected", "limit"):
                        value = event.get(key)
                        if value not in (None, "", []):
                            prefix = f"{range_type}:" if range_type else ""
                            affected_versions.append(f"{prefix}{key}:{value}")
                            if key == "fixed" and fixed_version is None:
                                fixed_version = str(value)
        affected.append(
            {
                "ecosystem": ecosystem if isinstance(ecosystem, str) else None,
                "package_name": package_name if isinstance(package_name, str) else None,
                "affected_versions": affected_versions,
                "fixed_version": fixed_version,
            }
        )
    return affected


def _advisory_from_payload(payload: dict[str, Any], source_path: Path) -> dict[str, Any] | None:
    vuln_ids = _extract_vuln_ids(payload)
    if not vuln_ids:
        stem = source_path.stem
        if stem.startswith("GHSA-"):
            vuln_ids = [stem]
    if not vuln_ids:
        return None

    title = _first_non_empty(payload.get("summary"), payload.get("title"))
    summary = _first_non_empty(payload.get("details"), payload.get("description"))
    severity = _normalize_severity(
        _first_non_empty(
            (payload.get("database_specific") or {}).get("severity") if isinstance(payload.get("database_specific"), dict) else None,
            payload.get("severity"),
        )
    )
    cvss_vector = _extract_cvss_vector(payload.get("severity"))
    published_at = _first_non_empty(payload.get("published"), payload.get("published_at"))
    updated_at = _first_non_empty(payload.get("modified"), payload.get("updated_at"))

    return {
        "vuln_ids": vuln_ids,
        "ghsa_id": vuln_ids[0] if vuln_ids[0].startswith("GHSA-") else None,
        "aliases": [vuln_id for vuln_id in vuln_ids[1:] if vuln_id.startswith("CVE-")],
        "title": title if isinstance(title, str) else None,
        "summary": summary if isinstance(summary, str) else None,
        "severity": severity,
        "cvss_score": None,
        "cvss_vector": cvss_vector,
        "references": _extract_references(payload),
        "affected": _extract_affected(payload),
        "published_at": published_at if isinstance(published_at, str) else None,
        "updated_at": updated_at if isinstance(updated_at, str) else None,
        "source_path": str(source_path),
    }


def load_payload(
    source_dir: Path,
    cache_only: bool,
    include_unreviewed: bool = False,
) -> tuple[list[dict[str, Any]], bool]:
    if cache_only:
        return read_cache(FEED), True

    rows: list[dict[str, Any]] = []
    try:
        for path in _iter_json_files(source_dir, include_unreviewed):
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                continue
            advisory = _advisory_from_payload(payload, path)
            if advisory is not None:
                rows.append(advisory)
        write_cache(FEED, rows)
        return rows, False
    except Exception:
        return read_cache(FEED), True


def sync(
    source_dir: Path = DEFAULT_SOURCE_DIR,
    limit: int | None = None,
    dry_run: bool = False,
    cache_only: bool = False,
    include_unreviewed: bool = False,
    min_year: int = MIN_YEAR,
) -> FetchResult:
    conn = None
    written = 0
    fetched = 0
    cache_used = False
    try:
        rows, cache_used = load_payload(source_dir, cache_only, include_unreviewed=include_unreviewed)
        fetched = len(rows)
        if limit is not None:
            rows = rows[:limit]

        if dry_run:
            return FetchResult(rows_fetched=len(rows), rows_written=0, cache_used=cache_used)

        conn = connect()
        for item in rows:
            if not _keep_for_core_db(item, min_year):
                continue
            cvss_score = item.get("cvss_score")
            cvss_vector = item.get("cvss_vector")
            vuln_ids = item.get("vuln_ids") or []
            if not isinstance(vuln_ids, list):
                vuln_ids = []
            for vuln_id in vuln_ids:
                upsert_vulnerability(
                    conn,
                    vuln_id=vuln_id,
                    source="ghsa",
                    title=item.get("title"),
                    summary=item.get("summary"),
                    severity=item.get("severity"),
                    cvss_score=float(cvss_score) if cvss_score is not None else None,
                    cvss_source=PROVIDER if cvss_score is not None else None,
                    published_at=item.get("published_at"),
                    updated_at=item.get("updated_at"),
                )
                append_signal(
                    conn,
                    vuln_id=vuln_id,
                    signal_type="enrichment",
                    provider=PROVIDER,
                    score=float(cvss_score) if cvss_score is not None else None,
                    value={
                        "ghsa_id": item.get("ghsa_id"),
                        "aliases": item.get("aliases"),
                        "severity": item.get("severity"),
                        "cvss_score": cvss_score,
                        "cvss_vector": cvss_vector,
                        "references": item.get("references"),
                        "source_path": item.get("source_path"),
                    },
                    observed_at=utc_now(),
                )
                written += 1

            for affected in item.get("affected") or []:
                if not isinstance(affected, dict):
                    continue
                for vuln_id in vuln_ids:
                    append_signal(
                        conn,
                        vuln_id=vuln_id,
                        signal_type="package_advisory",
                        provider=PROVIDER,
                        score=None,
                        value={
                            "ghsa_id": item.get("ghsa_id"),
                            "aliases": item.get("aliases"),
                            "ecosystem": affected.get("ecosystem"),
                            "package_name": affected.get("package_name"),
                            "affected_versions": affected.get("affected_versions"),
                            "fixed_version": affected.get("fixed_version"),
                            "source_path": item.get("source_path"),
                        },
                        observed_at=utc_now(),
                    )
                    written += 1

        log_fetch(conn, FEED, "ok", written)
        conn.commit()
        return FetchResult(rows_fetched=fetched, rows_written=written, cache_used=cache_used)
    except Exception as exc:
        if conn is None:
            conn = connect()
        else:
            conn.rollback()
        log_fetch(conn, FEED, "error", written, str(exc))
        conn.commit()
        return FetchResult(rows_fetched=fetched, rows_written=written, cache_used=cache_used)
    finally:
        if conn is not None:
            conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=DEFAULT_SOURCE_DIR,
        help="Path to a local github/advisory-database checkout or unpacked archive.",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    parser.add_argument("--include-unreviewed", action="store_true")
    parser.add_argument(
        "--min-year",
        type=int,
        default=MIN_YEAR,
        help="Only write advisories published in this year or later to core.db.",
    )
    args = parser.parse_args()
    result = sync(
        source_dir=args.source_dir,
        limit=args.limit,
        dry_run=args.dry_run,
        cache_only=args.cache_only,
        include_unreviewed=args.include_unreviewed,
        min_year=args.min_year,
    )
    print(result)


if __name__ == "__main__":
    main()
