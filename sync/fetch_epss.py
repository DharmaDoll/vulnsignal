#!/usr/bin/env python3
from __future__ import annotations

import argparse
from urllib.parse import urlencode

from sync.common import FetchResult, append_signal, connect, fetch_json, log_fetch, read_cache, utc_now, write_cache


FEED = "epss"
URL = "https://api.first.org/data/v1/epss"


def load_payload(limit: int | None, cache_only: bool) -> tuple[dict, bool]:
    if cache_only:
        return read_cache(FEED), True
    params = {"limit": str(limit or 100)}
    try:
        payload = fetch_json(f"{URL}?{urlencode(params)}", headers={"User-Agent": "vulnsignal/0.1"})
        write_cache(FEED, payload)
        return payload, False
    except Exception:
        return read_cache(FEED), True


def sync(limit: int | None = 100, dry_run: bool = False, cache_only: bool = False) -> FetchResult:
    payload, cache_used = load_payload(limit, cache_only)
    rows = payload.get("data", [])
    if limit is not None:
        rows = rows[:limit]

    if dry_run:
        return FetchResult(rows_fetched=len(rows), rows_written=0, cache_used=cache_used)

    conn = connect()
    written = 0
    try:
        for item in rows:
            vuln_id = item.get("cve")
            if not vuln_id:
                continue
            epss = float(item.get("epss") or 0)
            append_signal(
                conn,
                vuln_id=vuln_id,
                signal_type="epss",
                provider="FIRST EPSS",
                score=epss,
                value={"epss": epss, "percentile": item.get("percentile"), "date": item.get("date")},
                observed_at=item.get("date") or utc_now(),
            )
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
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    args = parser.parse_args()
    result = sync(limit=args.limit, dry_run=args.dry_run, cache_only=args.cache_only)
    print(result)


if __name__ == "__main__":
    main()
