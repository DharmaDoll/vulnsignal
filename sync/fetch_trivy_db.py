#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sync.common import ROOT, FetchResult, append_signal, connect, log_fetch, upsert_vulnerability, utc_now
from sync.trivy_adapter import TRIVY_DB_SCHEMA_VERSION, load_vulnerabilities_from_db_with_cache


FEED = "trivy_db"
PROVIDER = "Trivy DB"
DEFAULT_DB_DIR = ROOT / "db" / "trivy_cache.db"


def sync(
    db_dir: Path,
    limit: int | None = None,
    dry_run: bool = False,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> FetchResult:
    conn = None
    written = 0
    fetched = 0
    cache_used = False
    try:
        observed_at = utc_now()
        vulnerabilities, cache_used = load_vulnerabilities_from_db_with_cache(db_dir, observed_at, expected_schema_version)
        fetched = len(vulnerabilities)
        if limit is not None:
            vulnerabilities = vulnerabilities[:limit]

        if dry_run:
            return FetchResult(rows_fetched=len(vulnerabilities), rows_written=0, cache_used=cache_used)

        conn = connect()
        for vulnerability in vulnerabilities:
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
            append_signal(
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
            )
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
    )
    print(result)


if __name__ == "__main__":
    main()
