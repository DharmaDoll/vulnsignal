#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from sync.common import FetchResult, append_signal, connect, log_fetch, upsert_vulnerability, utc_now
from sync.trivy_adapter import load_advisories_from_json


FEED = "trivy"
PROVIDER = "Trivy JSON"


def sync(path: Path, limit: int | None = None, dry_run: bool = False) -> FetchResult:
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
                    "source_path": str(path),
                },
                observed_at=advisory.observed_at,
            )
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
    args = parser.parse_args()
    result = sync(path=args.json, limit=args.limit, dry_run=args.dry_run)
    print(result)


if __name__ == "__main__":
    main()
