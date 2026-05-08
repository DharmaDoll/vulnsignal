#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sync.common import FetchResult, append_signal, connect, log_fetch, upsert_vulnerability, utc_now
from sync.trivy_adapter import load_advisories_from_directory


FEED = "trivy_vuln_list"
PROVIDER = "Trivy vuln-list"
DEFAULT_TARGETS = ("alpine", "debian", "ubuntu", "ghsa", "glad", "go", "osv")


def sync(
    source_dir: Path,
    targets: list[str] | None = None,
    limit: int | None = None,
    dry_run: bool = False,
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
    parser.add_argument("--source-dir", required=True, type=Path, help="Path to a local trivy/vuln-list checkout or unpacked archive.")
    parser.add_argument("--target", action="append", choices=DEFAULT_TARGETS, help="Limit to one target directory. Can be repeated.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = sync(source_dir=args.source_dir, targets=args.target, limit=args.limit, dry_run=args.dry_run)
    print(result)


if __name__ == "__main__":
    main()
