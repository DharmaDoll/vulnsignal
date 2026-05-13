#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

from sync.common import (
    ROOT,
    FetchResult,
    JsonArrayCacheWriter,
    append_signal,
    connect,
    log_fetch,
    read_cache,
    upsert_vulnerability,
    utc_now,
    write_cache,
)


FEED = "vulnrichment"
PROVIDER = "CISA Vulnrichment"
DEFAULT_SOURCE_DIR = ROOT / "data" / "vulnrichment-mirror"
MIN_YEAR = 2015
TRUST_PRIORITY = {
    "ghsa": 2,
    "vulnrichment": 1,
    "trivy": 0,
    "vendor": 0,
}


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", []):
            return value
    return None


def _year_from_iso(value: str | None) -> int | None:
    if not value or len(value) < 4:
        return None
    try:
        return int(value[:4])
    except ValueError:
        return None


def _keep_for_core_db_min_year(item: dict[str, Any], min_year: int) -> bool:
    year = _year_from_iso(item.get("published_at"))
    if year is not None:
        return year >= min_year
    vuln_id = item.get("vuln_id")
    if isinstance(vuln_id, str) and vuln_id.startswith("CVE-"):
        parts = vuln_id.split("-")
        if len(parts) >= 3:
            try:
                return int(parts[1]) >= min_year
            except ValueError:
                return True
    return True


def _iter_source_files(source_dir: Path) -> list[Path]:
    if source_dir.is_file():
        return [source_dir]
    return sorted(path for path in source_dir.rglob("*.json") if path.is_file())


def _parse_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_severity(value: Any) -> str | None:
    if isinstance(value, str):
        severity = value.strip()
        return severity.upper() if severity else None
    if isinstance(value, dict):
        return _normalize_severity(
            _first_non_empty(value.get("baseSeverity"), value.get("severity"), value.get("level"), value.get("score"))
        )
    if isinstance(value, list):
        for item in value:
            severity = _normalize_severity(item)
            if severity:
                return severity
    return None


def _extract_vuln_id(item: dict[str, Any], source_path: Path) -> str | None:
    vuln_id = _first_non_empty(
        item.get("vuln_id"),
        item.get("cve_id"),
        item.get("cveId"),
        item.get("id"),
        ((item.get("cveMetadata") or {}).get("cveId") if isinstance(item.get("cveMetadata"), dict) else None),
    )
    if isinstance(vuln_id, str) and vuln_id:
        return vuln_id
    stem = source_path.stem
    return stem if stem.startswith("CVE-") else None


def _extract_title(item: dict[str, Any]) -> str | None:
    containers = item.get("containers")
    if isinstance(containers, dict):
        cna = containers.get("cna")
        if isinstance(cna, dict):
            title = cna.get("title")
            if isinstance(title, str) and title:
                return title

    title = _first_non_empty(item.get("title"), item.get("name"))
    return title if isinstance(title, str) and title else None


def _extract_summary(item: dict[str, Any]) -> str | None:
    direct_description = _first_non_empty(item.get("summary"), item.get("description"))
    if isinstance(direct_description, str) and direct_description:
        return direct_description

    containers = item.get("containers")
    if isinstance(containers, dict):
        cna = containers.get("cna")
        if isinstance(cna, dict):
            raw_descriptions = cna.get("descriptions")
            if isinstance(raw_descriptions, list):
                for entry in raw_descriptions:
                    if not isinstance(entry, dict):
                        continue
                    text = _first_non_empty(entry.get("value"), entry.get("description"))
                    if isinstance(text, str) and text:
                        lang = entry.get("lang")
                        if lang in (None, "en"):
                            return text

    return None


def _extract_references(item: dict[str, Any]) -> list[str]:
    references: list[str] = []
    containers = item.get("containers")
    if isinstance(containers, dict):
        cna = containers.get("cna")
        if isinstance(cna, dict):
            raw_references = cna.get("references")
            if isinstance(raw_references, list):
                for entry in raw_references:
                    if isinstance(entry, str) and entry:
                        references.append(entry)
                    elif isinstance(entry, dict):
                        url = _first_non_empty(entry.get("url"), entry.get("href"))
                        if isinstance(url, str) and url:
                            references.append(url)
    raw_references = item.get("references")
    if isinstance(raw_references, list):
        for entry in raw_references:
            if isinstance(entry, str) and entry:
                references.append(entry)
            elif isinstance(entry, dict):
                url = _first_non_empty(entry.get("url"), entry.get("href"))
                if isinstance(url, str) and url:
                    references.append(url)
    return references


def _extract_cvss(item: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    candidates: list[Any] = [item]
    for key in ("cvss", "metrics"):
        value = item.get(key)
        if value is not None:
            candidates.append(value)

    containers = item.get("containers")
    if isinstance(containers, dict):
        cna = containers.get("cna")
        if isinstance(cna, dict):
            metrics = cna.get("metrics")
            if metrics is not None:
                candidates.append(metrics)

    for candidate in candidates:
        if isinstance(candidate, list):
            for entry in candidate:
                score, vector, severity = _extract_cvss(entry)
                if score is not None or vector is not None or severity is not None:
                    return score, vector, severity
            continue
        if not isinstance(candidate, dict):
            continue
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvss"):
            metric = candidate.get(key)
            if isinstance(metric, dict):
                score = metric.get("baseScore") or metric.get("score")
                vector = metric.get("vectorString") or metric.get("vector")
                severity = metric.get("baseSeverity") or metric.get("severity")
                return (
                    float(score) if score is not None else None,
                    vector if isinstance(vector, str) else None,
                    _normalize_severity(severity),
                )
        score = candidate.get("baseScore") or candidate.get("score")
        vector = candidate.get("vectorString") or candidate.get("vector")
        severity = candidate.get("baseSeverity") or candidate.get("severity")
        if score is not None or vector is not None or severity is not None:
            return (
                float(score) if score is not None else None,
                vector if isinstance(vector, str) else None,
                _normalize_severity(severity),
            )

    return None, None, None


def _record_from_item(item: dict[str, Any], source_path: Path) -> dict[str, Any] | None:
    vuln_id = _extract_vuln_id(item, source_path)
    if not vuln_id:
        return None

    title = _extract_title(item)
    summary = _extract_summary(item)
    if title is None and summary is not None:
        title = summary

    severity = _normalize_severity(_first_non_empty(item.get("severity"), item.get("Severity")))
    if severity is None:
        _, _, severity = _extract_cvss(item)

    cvss_score, cvss_vector, cvss_severity = _extract_cvss(item)
    if severity is None:
        severity = cvss_severity

    published_at = _first_non_empty(
        item.get("published_at"),
        item.get("datePublished"),
        ((item.get("cveMetadata") or {}).get("datePublished") if isinstance(item.get("cveMetadata"), dict) else None),
    )
    updated_at = _first_non_empty(
        item.get("updated_at"),
        item.get("dateUpdated"),
        ((item.get("cveMetadata") or {}).get("dateUpdated") if isinstance(item.get("cveMetadata"), dict) else None),
    )

    return {
        "vuln_id": vuln_id,
        "source": FEED,
        "title": title,
        "summary": summary,
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_source": PROVIDER if cvss_score is not None else None,
        "cvss_vector": cvss_vector,
        "references": _extract_references(item),
        "published_at": published_at,
        "updated_at": updated_at,
        "source_path": str(source_path),
    }


def _load_rows_from_source_dir(source_dir: Path):
    for path in _iter_source_files(source_dir):
        payload = _parse_json(path)
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict):
                continue
            row = _record_from_item(item, path)
            if row is not None:
                yield row


def load_payload(source_dir: Path, cache_only: bool = False) -> tuple[list[dict[str, Any]], bool]:
    if cache_only:
        return read_cache(FEED), True

    try:
        rows = list(_load_rows_from_source_dir(source_dir))
        write_cache(FEED, rows)
        return rows, False
    except Exception:
        return read_cache(FEED), True


def _trust_rank(source: str | None) -> int:
    return TRUST_PRIORITY.get(source or "", -1)


def _merge_vulnerability(
    existing: sqlite3.Row | None,
    item: dict[str, Any],
) -> dict[str, Any]:
    if existing is None:
        return item

    existing_rank = _trust_rank(existing["source"])
    new_rank = _trust_rank(item["source"])
    merged = dict(item)
    for field in ("title", "summary", "severity", "cvss_score", "cvss_source", "published_at", "updated_at"):
        existing_value = existing[field]
        new_value = item[field]
        if existing_rank > new_rank and existing_value not in (None, "", []):
            merged[field] = existing_value
        elif new_value in (None, "", []):
            merged[field] = existing_value
    return merged


def sync(
    source_dir: Path,
    limit: int | None = None,
    dry_run: bool = False,
    cache_only: bool = False,
    min_year: int = MIN_YEAR,
) -> FetchResult:
    conn = None
    written = 0
    fetched = 0
    cache_used = False
    try:
        if cache_only:
            rows, cache_used = read_cache(FEED), True
            fetched = len(rows)
            if limit is not None:
                rows = rows[:limit]
            if dry_run:
                return FetchResult(rows_fetched=len(rows), rows_written=0, cache_used=cache_used)
            item_iter = iter(rows)
            cache_writer = None
        else:
            item_iter = _load_rows_from_source_dir(source_dir)
            if limit is not None:
                from itertools import islice

                item_iter = islice(item_iter, limit)
            if dry_run:
                rows = list(item_iter)
                fetched = len(rows)
                return FetchResult(rows_fetched=fetched, rows_written=0, cache_used=cache_used)
            cache_writer = JsonArrayCacheWriter(FEED)

        conn = connect()
        if cache_writer is not None:
            with cache_writer as cache:
                for item in item_iter:
                    fetched += 1
                    if not _keep_for_core_db_min_year(item, min_year):
                        continue
                    existing = conn.execute(
                        """
                        SELECT source, title, summary, severity, cvss_score, cvss_source, published_at, updated_at
                        FROM vulnerabilities
                        WHERE vuln_id = ?
                        """,
                        (item["vuln_id"],),
                    ).fetchone()
                    merged = _merge_vulnerability(existing, item)
                    upsert_vulnerability(
                        conn,
                        vuln_id=merged["vuln_id"],
                        source=merged["source"],
                        title=merged["title"],
                        summary=merged["summary"],
                        severity=merged["severity"],
                        cvss_score=merged["cvss_score"],
                        cvss_source=merged["cvss_source"],
                        published_at=merged["published_at"],
                        updated_at=merged["updated_at"],
                    )
                    if append_signal(
                        conn,
                        vuln_id=merged["vuln_id"],
                        signal_type="enrichment",
                        provider=PROVIDER,
                        score=merged["cvss_score"],
                        value={
                            "summary": merged["summary"],
                            "severity": merged["severity"],
                            "cvss_score": merged["cvss_score"],
                            "cvss_vector": merged.get("cvss_vector"),
                            "references": merged.get("references"),
                            "source_path": merged.get("source_path"),
                        },
                        observed_at=utc_now(),
                    ):
                        written += 1
                    cache.write(item)
                cache.commit()
        else:
            for item in item_iter:
                fetched += 1
                if not _keep_for_core_db_min_year(item, min_year):
                    continue
                existing = conn.execute(
                    """
                    SELECT source, title, summary, severity, cvss_score, cvss_source, published_at, updated_at
                    FROM vulnerabilities
                    WHERE vuln_id = ?
                    """,
                    (item["vuln_id"],),
                ).fetchone()
                merged = _merge_vulnerability(existing, item)
                upsert_vulnerability(
                    conn,
                    vuln_id=merged["vuln_id"],
                    source=merged["source"],
                    title=merged["title"],
                    summary=merged["summary"],
                    severity=merged["severity"],
                    cvss_score=merged["cvss_score"],
                    cvss_source=merged["cvss_source"],
                    published_at=merged["published_at"],
                    updated_at=merged["updated_at"],
                )
                if append_signal(
                    conn,
                    vuln_id=merged["vuln_id"],
                    signal_type="enrichment",
                    provider=PROVIDER,
                    score=merged["cvss_score"],
                    value={
                        "summary": merged["summary"],
                        "severity": merged["severity"],
                        "cvss_score": merged["cvss_score"],
                        "cvss_vector": merged.get("cvss_vector"),
                        "references": merged.get("references"),
                        "source_path": merged.get("source_path"),
                    },
                    observed_at=utc_now(),
                ):
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
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR, help="Path to a local Vulnrichment checkout or unpacked archive.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    parser.add_argument(
        "--min-year",
        type=int,
        default=MIN_YEAR,
        help="Only write records published in this year or later to core.db.",
    )
    args = parser.parse_args()
    result = sync(
        source_dir=args.source_dir,
        limit=args.limit,
        dry_run=args.dry_run,
        cache_only=args.cache_only,
        min_year=args.min_year,
    )
    print(result)


if __name__ == "__main__":
    main()
