#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sync.common import ROOT, FetchResult, append_signal, connect, log_fetch, upsert_vulnerability, utc_now
from sync.trivy_adapter import load_advisories_from_directory


FEED = "trivy_vuln_list"
PROVIDER = "Trivy vuln-list"
DEFAULT_TARGETS = ("alpine", "debian", "ubuntu", "ghsa", "glad", "go", "osv")
DEFAULT_SOURCE_DIR = ROOT / "data" / "aquasecurity-vuln-list-mirror"
MIN_YEAR = 2015


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


def _keep_for_core_db_min_year(advisory, min_year: int) -> bool:
    year = _year_from_iso(advisory.published_at)
    if year is not None:
        return year >= min_year
    return (_vuln_year(advisory.vuln_id) or min_year) >= min_year


def sync(
    source_dir: Path,
    targets: list[str] | None = None,
    limit: int | None = None,
    dry_run: bool = False,
    min_year: int = MIN_YEAR,
) -> FetchResult:
    conn = None
    written = 0
    fetched = 0
    try:
        targets = targets or list(DEFAULT_TARGETS)
        observed_at = utc_now()
        advisories = load_advisories_from_directory(source_dir, observed_at, targets=targets)
        fetched = len(advisories)
        if limit is not None:
            advisories = advisories[:limit]

        if dry_run:
            return FetchResult(rows_fetched=len(advisories), rows_written=0, cache_used=False)

        conn = connect()
        for advisory in advisories:
            if not _keep_for_core_db_min_year(advisory, min_year):
                continue
            upsert_vulnerability(
                conn,
                vuln_id=advisory.vuln_id,
                source="trivy",
                title=advisory.title,
                summary=advisory.summary,
                severity=advisory.severity,
            )
            append_signal(
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
                    "source_path": str(source_dir),
                },
                observed_at=advisory.observed_at,
            )
            written += 1
        log_fetch(conn, FEED, "ok", written)
        conn.commit()
        return FetchResult(rows_fetched=fetched, rows_written=written, cache_used=False)
    except Exception as exc:
        if conn is None:
            conn = connect()
        else:
            conn.rollback()
        log_fetch(conn, FEED, "error", written, str(exc))
        conn.commit()
        return FetchResult(rows_fetched=fetched, rows_written=written, cache_used=False)
    finally:
        if conn is not None:
            conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-dir",
        type=Path,
        default=DEFAULT_SOURCE_DIR,
        help="Path to a local trivy/vuln-list checkout or unpacked archive.",
    )
    parser.add_argument("--target", action="append", choices=DEFAULT_TARGETS, help="Limit to one target directory. Can be repeated.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--min-year",
        type=int,
        default=MIN_YEAR,
        help="Only write advisories published in this year or later to core.db.",
    )
    args = parser.parse_args()
    result = sync(
        source_dir=args.source_dir,
        targets=args.target,
        limit=args.limit,
        dry_run=args.dry_run,
        min_year=args.min_year,
    )
    print(result)


if __name__ == "__main__":
    main()
