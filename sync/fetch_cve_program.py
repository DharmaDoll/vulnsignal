#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sync.common import (
    ROOT,
    FetchResult,
    JsonArrayCacheWriter,
    append_signal,
    connect,
    git_changed_files,
    log_fetch,
    read_cache,
    upsert_vulnerability,
    utc_now,
    write_cache,
)


FEED = "cve_program"
PROVIDER = "CVE Program"
DEFAULT_SOURCE_DIR = ROOT / "data" / "cvelistv5-mirror"
MIN_YEAR = 2015


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


def _keep_for_core_db(item: dict[str, Any], min_year: int) -> bool:
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


def _iter_source_files(source_dir: Path, source_files: list[Path] | None = None) -> list[Path]:
    if source_files is not None:
        return [path for path in source_files if path.is_file()]
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
        return _normalize_severity(_first_non_empty(value.get("baseSeverity"), value.get("severity"), value.get("level"), value.get("score")))
    if isinstance(value, list):
        for item in value:
            severity = _normalize_severity(item)
            if severity:
                return severity
    return None


def _normalize_float(value: Any) -> float | None:
    if value in (None, "", []):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _extract_vuln_id(item: dict[str, Any], source_path: Path) -> str | None:
    vuln_id = _first_non_empty(
        item.get("vuln_id"),
        item.get("cve_id"),
        item.get("cveId"),
        ((item.get("cveMetadata") or {}).get("cveId") if isinstance(item.get("cveMetadata"), dict) else None),
    )
    if isinstance(vuln_id, str) and vuln_id:
        return vuln_id
    stem = source_path.stem
    return stem if stem.startswith("CVE-") else None


def _container_values(containers: Any) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    if isinstance(containers, dict):
        cna = containers.get("cna")
        if isinstance(cna, dict):
            values.append(cna)
        adp = containers.get("adp")
        if isinstance(adp, list):
            values.extend([item for item in adp if isinstance(item, dict)])
        elif isinstance(adp, dict):
            values.append(adp)
    return values


def _extract_title(item: dict[str, Any]) -> str | None:
    containers = item.get("containers")
    for container in _container_values(containers):
        title = container.get("title")
        if isinstance(title, str) and title:
            return title
    title = _first_non_empty(item.get("title"), item.get("name"))
    return title if isinstance(title, str) and title else None


def _extract_summary(item: dict[str, Any]) -> str | None:
    direct = _first_non_empty(item.get("summary"), item.get("description"))
    if isinstance(direct, str) and direct:
        return direct

    containers = item.get("containers")
    for container in _container_values(containers):
        descriptions = container.get("descriptions")
        if isinstance(descriptions, list):
            for entry in descriptions:
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
    for container in _container_values(item.get("containers")):
        raw_references = container.get("references")
        if not isinstance(raw_references, list):
            continue
        for entry in raw_references:
            if isinstance(entry, str) and entry:
                references.append(entry)
            elif isinstance(entry, dict):
                url = _first_non_empty(entry.get("url"), entry.get("href"))
                if isinstance(url, str) and url:
                    references.append(url)
    return list(dict.fromkeys(references))


def _extract_cvss(item: dict[str, Any]) -> tuple[float | None, str | None, str | None]:
    containers = item.get("containers")
    for container in _container_values(containers):
        metrics = container.get("metrics")
        if isinstance(metrics, list):
            for entry in metrics:
                score, vector, severity = _extract_cvss_from_metric(entry)
                if score is not None or vector is not None or severity is not None:
                    return score, vector, severity
        elif isinstance(metrics, dict):
            score, vector, severity = _extract_cvss_from_metric(metrics)
            if score is not None or vector is not None or severity is not None:
                return score, vector, severity
    return None, None, None


def _extract_cvss_from_metric(metric: Any) -> tuple[float | None, str | None, str | None]:
    if not isinstance(metric, dict):
        return None, None, None
    for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvss"):
        value = metric.get(key)
        if isinstance(value, dict):
            score = value.get("baseScore")
            if score is None:
                score = value.get("score")
            vector = value.get("vectorString")
            if vector is None:
                vector = value.get("vector")
            severity = value.get("baseSeverity")
            if severity is None:
                severity = value.get("severity")
            return (
                _normalize_float(score),
                vector if isinstance(vector, str) else None,
                _normalize_severity(severity),
            )
    score = metric.get("baseScore")
    if score is None:
        score = metric.get("score")
    vector = metric.get("vectorString")
    if vector is None:
        vector = metric.get("vector")
    severity = metric.get("baseSeverity")
    if severity is None:
        severity = metric.get("severity")
    if score is not None or vector is not None or severity is not None:
        return (
            _normalize_float(score),
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
    severity = _normalize_severity(_first_non_empty(item.get("severity"), item.get("Severity")))
    cvss_score, cvss_vector, cvss_severity = _extract_cvss(item)
    if severity is None:
        severity = cvss_severity

    cve_metadata = item.get("cveMetadata")
    published_at = _first_non_empty(
        item.get("published_at"),
        ((cve_metadata or {}).get("datePublished") if isinstance(cve_metadata, dict) else None),
    )
    updated_at = _first_non_empty(
        item.get("updated_at"),
        ((cve_metadata or {}).get("dateUpdated") if isinstance(cve_metadata, dict) else None),
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
        "published_at": published_at if isinstance(published_at, str) else None,
        "updated_at": updated_at if isinstance(updated_at, str) else None,
        "source_path": str(source_path),
    }


def _load_rows_from_source_dir(source_dir: Path, source_files: list[Path] | None = None) -> list[dict[str, Any]]:
    for path in _iter_source_files(source_dir, source_files):
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


def sync(
    source_dir: Path,
    limit: int | None = None,
    dry_run: bool = False,
    cache_only: bool = False,
    min_year: int = MIN_YEAR,
    changed_since_ref: str | None = None,
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
            row_iter = iter(rows)
            cache_writer = None
        else:
            source_files = None
            if changed_since_ref is not None:
                source_files = [source_dir / rel for rel in git_changed_files(source_dir, changed_since_ref)]
            row_iter = _load_rows_from_source_dir(source_dir, source_files=source_files)
            if limit is not None:
                from itertools import islice

                row_iter = islice(row_iter, limit)
            if dry_run:
                rows = list(row_iter)
                fetched = len(rows)
                return FetchResult(rows_fetched=fetched, rows_written=0, cache_used=cache_used)
            cache_writer = None if changed_since_ref is not None else JsonArrayCacheWriter(FEED)

        conn = connect()
        if cache_writer is not None:
            with cache_writer as cache:
                for item in row_iter:
                    fetched += 1
                    if not _keep_for_core_db(item, min_year):
                        continue
                    upsert_vulnerability(
                        conn,
                        vuln_id=item["vuln_id"],
                        source=item["source"],
                        title=item.get("title"),
                        summary=item.get("summary"),
                        severity=item.get("severity"),
                        cvss_score=item.get("cvss_score"),
                        cvss_source=item.get("cvss_source"),
                        published_at=item.get("published_at"),
                        updated_at=item.get("updated_at"),
                    )
                    cache.write(item)
                    if append_signal(
                        conn,
                        vuln_id=item["vuln_id"],
                        signal_type="enrichment",
                        provider=PROVIDER,
                        score=item.get("cvss_score"),
                        value={
                            "title": item.get("title"),
                            "summary": item.get("summary"),
                            "severity": item.get("severity"),
                            "cvss_score": item.get("cvss_score"),
                            "cvss_vector": item.get("cvss_vector"),
                            "references": item.get("references"),
                            "source_path": item.get("source_path"),
                        },
                        observed_at=utc_now(),
                        ):
                            written += 1
                cache.commit()
        else:
            for item in row_iter:
                fetched += 1
                if not _keep_for_core_db(item, min_year):
                    continue
                upsert_vulnerability(
                    conn,
                    vuln_id=item["vuln_id"],
                    source=item["source"],
                    title=item.get("title"),
                    summary=item.get("summary"),
                    severity=item.get("severity"),
                    cvss_score=item.get("cvss_score"),
                    cvss_source=item.get("cvss_source"),
                    published_at=item.get("published_at"),
                    updated_at=item.get("updated_at"),
                )
                if append_signal(
                    conn,
                    vuln_id=item["vuln_id"],
                    signal_type="enrichment",
                    provider=PROVIDER,
                    score=item.get("cvss_score"),
                    value={
                        "title": item.get("title"),
                        "summary": item.get("summary"),
                        "severity": item.get("severity"),
                        "cvss_score": item.get("cvss_score"),
                        "cvss_vector": item.get("cvss_vector"),
                        "references": item.get("references"),
                        "source_path": item.get("source_path"),
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
    parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE_DIR, help="Path to a local CVE Program checkout or unpacked archive.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    parser.add_argument("--changed-since-ref", help="Only ingest files changed since the given git ref, e.g. HEAD@{1}.")
    parser.add_argument("--min-year", type=int, default=MIN_YEAR, help="Only write records published in this year or later to core.db.")
    args = parser.parse_args()
    result = sync(
        source_dir=args.source_dir,
        limit=args.limit,
        dry_run=args.dry_run,
        cache_only=args.cache_only,
        min_year=args.min_year,
        changed_since_ref=args.changed_since_ref,
    )
    print(result)


if __name__ == "__main__":
    main()
