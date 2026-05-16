#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import gzip
import io
from datetime import date, timedelta

from sync.common import (
    FetchResult,
    connect,
    fetch_bytes,
    log_fetch,
    read_bytes_cache,
    utc_now,
    write_bytes_cache,
)


FEED = "epss"
URL_TEMPLATE = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"


def default_date() -> str:
    return (date.today() - timedelta(days=1)).isoformat()


def load_payload(score_date: str, cache_only: bool) -> tuple[str, bool]:
    cache_name = f"{FEED}-{score_date}"
    if cache_only:
        return gzip.decompress(read_bytes_cache(cache_name, "csv.gz")).decode("utf-8"), True
    try:
        payload = fetch_bytes(URL_TEMPLATE.format(date=score_date), headers={"User-Agent": "vulnsignal/0.1"})
        write_bytes_cache(cache_name, payload, "csv.gz")
        return gzip.decompress(payload).decode("utf-8"), False
    except Exception:
        return gzip.decompress(read_bytes_cache(cache_name, "csv.gz")).decode("utf-8"), True


def parse_rows(payload: str) -> list[dict[str, str]]:
    lines = [line for line in payload.splitlines() if line and not line.startswith("#")]
    return list(csv.DictReader(io.StringIO("\n".join(lines))))


def upsert_epss_current(conn, vuln_id: str, epss: float, percentile: float | None, score_date: str) -> None:
    conn.execute(
        """
        INSERT INTO epss_current (vuln_id, epss, percentile, score_date, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(vuln_id) DO UPDATE SET
          epss = excluded.epss,
          percentile = excluded.percentile,
          score_date = excluded.score_date,
          updated_at = excluded.updated_at
        """,
        (vuln_id, epss, percentile, score_date, utc_now()),
    )


def load_current_epss(conn) -> dict[str, tuple[float, float | None]]:
    rows = conn.execute("SELECT vuln_id, epss, percentile FROM epss_current").fetchall()
    current: dict[str, tuple[float, float | None]] = {}
    for row in rows:
        current[str(row["vuln_id"])] = (float(row["epss"]), float(row["percentile"]) if row["percentile"] is not None else None)
    return current


def sync(
    limit: int | None = None,
    dry_run: bool = False,
    cache_only: bool = False,
    score_date: str | None = None,
) -> FetchResult:
    score_date = score_date or default_date()
    payload, cache_used = load_payload(score_date, cache_only)
    rows = parse_rows(payload)
    if limit is not None:
        rows = rows[:limit]

    if dry_run:
        return FetchResult(rows_fetched=len(rows), rows_written=0, cache_used=cache_used)

    conn = connect()
    written = 0
    try:
        current = load_current_epss(conn)
        for item in rows:
            vuln_id = item.get("cve")
            if not vuln_id:
                continue
            epss = float(item.get("epss") or 0)
            percentile = float(item["percentile"]) if item.get("percentile") else None
            previous = current.get(vuln_id)
            if previous is not None and previous == (epss, percentile):
                continue
            upsert_epss_current(conn, vuln_id, epss, percentile, score_date)
            current[vuln_id] = (epss, percentile)
            written += 1
        log_fetch(conn, FEED, "ok", written)
        conn.commit()
        return FetchResult(rows_fetched=len(rows), rows_written=written, cache_used=cache_used)
    except Exception as exc:
        conn.rollback()
        log_fetch(conn, FEED, "error", written, str(exc))
        conn.commit()
        raise
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, help="Limit rows for local sampling. Defaults to all CSV rows.")
    parser.add_argument("--date", dest="score_date", help="EPSS score date in YYYY-MM-DD. Defaults to yesterday.")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    args = parser.parse_args()
    result = sync(limit=args.limit, dry_run=args.dry_run, cache_only=args.cache_only, score_date=args.score_date)
    print(result)


if __name__ == "__main__":
    main()
