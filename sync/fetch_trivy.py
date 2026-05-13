#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sync.common import FetchResult, append_signal, connect, log_fetch, upsert_vulnerability, utc_now
from sync.trivy_adapter import load_advisories_from_json


FEED = "trivy"
PROVIDER = "Trivy JSON"


def _year_from_iso(value: str | None) -> int | None:
    if not value or len(value) < 4:
        return None
    try:
        return int(value[:4])
    except ValueError:
        return None


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


def _keep_for_core_db(advisory, min_year: int) -> bool:
    year = _year_from_iso(advisory.published_at)
    if year is not None:
        return year >= min_year
    return (_vuln_year(advisory.vuln_id) or min_year) >= min_year


def sync(path: Path, limit: int | None = None, dry_run: bool = False, min_year: int = 2015) -> FetchResult:
    conn = None
    written = 0
    try:
        observed_at = utc_now()
        advisories = load_advisories_from_json(path, observed_at)
        if limit is not None:
            advisories = advisories[:limit]

        if dry_run:
            return FetchResult(rows_fetched=len(advisories), rows_written=0, cache_used=False)

        conn = connect()
        for advisory in advisories:
            if not _keep_for_core_db(advisory, min_year):
                continue
            upsert_vulnerability(
                conn,
                vuln_id=advisory.vuln_id,
                source="trivy",
                title=advisory.title,
                summary=advisory.summary,
                severity=advisory.severity,
            )
            if append_signal(
                conn,
                vuln_id=advisory.vuln_id,
                signal_type="package_advisory",
                provider=PROVIDER,
                score=None,
                value={
                    "ecosystem": advisory.ecosystem,
                    "package_name": advisory.package_name,
                    "affected_versions": advisory.affected_versions,
                    "fixed_version": advisory.fixed_version,
                    "severity": advisory.severity,
                    "source_path": str(path),
                },
                observed_at=advisory.observed_at,
            ):
                written += 1
        log_fetch(conn, FEED, "ok", written)
        conn.commit()
        return FetchResult(rows_fetched=len(advisories), rows_written=written, cache_used=False)
    except Exception as exc:
        if not dry_run:
            if conn is None:
                conn = connect()
            else:
                conn.rollback()
            log_fetch(conn, FEED, "error", written, str(exc))
            conn.commit()
        raise
    finally:
        if conn is not None:
            conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", required=True, type=Path, help="Path to Trivy advisory JSON.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--min-year", type=int, default=2015, help="Only write advisories from this year or later to core.db.")
    args = parser.parse_args()
    result = sync(path=args.json, limit=args.limit, dry_run=args.dry_run, min_year=args.min_year)
    print(result)


if __name__ == "__main__":
    main()
