#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sync.common import ROOT, FetchResult, append_signal, connect, log_fetch, upsert_vulnerability, utc_now
from sync.trivy_adapter import (
    TRIVY_DB_SCHEMA_VERSION,
    iter_trivy_db_dump_rows,
    load_vulnerabilities_from_db_cache_only,
    load_trivy_vulnerability_fingerprints_from_cache,
    vulnerability_from_payload,
)


FEED = "trivy_db"
PROVIDER = "Trivy DB"
DEFAULT_DB_DIR = ROOT / "db" / "trivy_cache.db"


def _vuln_year(vuln_id: str | None) -> int | None:
    if not vuln_id or not vuln_id.startswith("CVE-"):
        return None
    parts = vuln_id.split("-")
    if len(parts) < 3:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _keep_for_core_db(vulnerability, min_year: int) -> bool:
    return (_vuln_year(vulnerability.vuln_id) or min_year) >= min_year


def sync(
    db_dir: Path,
    limit: int | None = None,
    dry_run: bool = False,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
    min_year: int = 2015,
) -> FetchResult:
    conn = None
    written = 0
    fetched = 0
    cache_used = False
    try:
        observed_at = utc_now()
        previous_fingerprints = load_trivy_vulnerability_fingerprints_from_cache(expected_schema_version)
        if dry_run:
            for row in iter_trivy_db_dump_rows(db_dir, expected_schema_version):
                if row.get("row_type") != "vulnerability":
                    continue
                if limit is not None and fetched >= limit:
                    break
                fetched += 1
            return FetchResult(rows_fetched=fetched, rows_written=0, cache_used=False)

        conn = connect()
        try:
            for row in iter_trivy_db_dump_rows(db_dir, expected_schema_version):
                if row.get("row_type") != "vulnerability":
                    continue
                vuln_id = row.get("vuln_id")
                payload = row.get("payload")
                payload_hash = row.get("payload_hash")
                if not isinstance(vuln_id, str) or not isinstance(payload, dict):
                    continue
                if limit is not None and fetched >= limit:
                    break
                fetched += 1
                if previous_fingerprints.get(vuln_id) == payload_hash:
                    continue
                vulnerability = vulnerability_from_payload(vuln_id, payload, observed_at, source_hint="trivy-db")
                if not _keep_for_core_db(vulnerability, min_year):
                    continue
                upsert_vulnerability(
                    conn,
                    vuln_id=vulnerability.vuln_id,
                    source="trivy-db",
                    title=vulnerability.title,
                    summary=vulnerability.summary,
                    severity=vulnerability.severity,
                    cvss_score=vulnerability.cvss_score,
                    cvss_source="Trivy DB",
                )
                if append_signal(
                    conn,
                    vuln_id=vulnerability.vuln_id,
                    signal_type="enrichment",
                    provider=PROVIDER,
                    score=vulnerability.cvss_score,
                    value={
                        "title": vulnerability.title,
                        "summary": vulnerability.summary,
                        "severity": vulnerability.severity,
                        "cvss_score": vulnerability.cvss_score,
                        "cvss_vector": vulnerability.cvss_vector,
                        "vendor_severity": vulnerability.vendor_severity,
                        "references": vulnerability.references,
                        "source_path": str(db_dir),
                    },
                    observed_at=vulnerability.observed_at,
                ):
                    written += 1
            log_fetch(conn, FEED, "ok", written)
            conn.commit()
            return FetchResult(rows_fetched=fetched, rows_written=written, cache_used=False)
        except Exception:
            conn.rollback()
            vulnerabilities = load_vulnerabilities_from_db_cache_only(db_dir, observed_at, expected_schema_version)
            cache_used = True
            if limit is not None:
                vulnerabilities = vulnerabilities[:limit]
            for vulnerability in vulnerabilities:
                fetched += 1
                if not _keep_for_core_db(vulnerability, min_year):
                    continue
                upsert_vulnerability(
                    conn,
                    vuln_id=vulnerability.vuln_id,
                    source="trivy-db",
                    title=vulnerability.title,
                    summary=vulnerability.summary,
                    severity=vulnerability.severity,
                    cvss_score=vulnerability.cvss_score,
                    cvss_source="Trivy DB",
                )
                if append_signal(
                    conn,
                    vuln_id=vulnerability.vuln_id,
                    signal_type="enrichment",
                    provider=PROVIDER,
                    score=vulnerability.cvss_score,
                    value={
                        "title": vulnerability.title,
                        "summary": vulnerability.summary,
                        "severity": vulnerability.severity,
                        "cvss_score": vulnerability.cvss_score,
                        "cvss_vector": vulnerability.cvss_vector,
                        "vendor_severity": vulnerability.vendor_severity,
                        "references": vulnerability.references,
                        "source_path": str(db_dir),
                    },
                    observed_at=vulnerability.observed_at,
                ):
                    written += 1
            log_fetch(conn, FEED, "ok", written)
            conn.commit()
            return FetchResult(rows_fetched=fetched, rows_written=written, cache_used=cache_used)
    except Exception as exc:
        if not dry_run:
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
    parser.add_argument("--db-dir", type=Path, default=DEFAULT_DB_DIR, help="Path to a Trivy DB cache directory.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--min-year", type=int, default=2015, help="Only write vulnerabilities from this year or later to core.db.")
    parser.add_argument(
        "--expected-schema-version",
        type=int,
        default=TRIVY_DB_SCHEMA_VERSION,
        help="Expected Trivy DB schema version from metadata.json.",
    )
    args = parser.parse_args()
    result = sync(
        db_dir=args.db_dir,
        limit=args.limit,
        dry_run=args.dry_run,
        expected_schema_version=args.expected_schema_version,
        min_year=args.min_year,
    )
    print(result)


if __name__ == "__main__":
    main()
