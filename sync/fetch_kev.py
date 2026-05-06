#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any

from sync.common import (
    FetchResult,
    append_signal,
    connect,
    fetch_json,
    log_fetch,
    read_cache,
    upsert_vulnerability,
    utc_now,
    write_cache,
)


FEED = "kev"
URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load_payload(cache_only: bool) -> tuple[dict[str, Any], bool]:
    if cache_only:
        return read_cache(FEED), True
    try:
        payload = fetch_json(URL, headers={"User-Agent": "vulnsignal/0.1"})
        write_cache(FEED, payload)
        return payload, False
    except Exception:
        return read_cache(FEED), True


def sync(limit: int | None = None, dry_run: bool = False, cache_only: bool = False) -> FetchResult:
    payload, cache_used = load_payload(cache_only)
    rows = payload.get("vulnerabilities", [])
    if limit is not None:
        rows = rows[:limit]

    if dry_run:
        return FetchResult(rows_fetched=len(rows), rows_written=0, cache_used=cache_used)

    conn = connect()
    written = 0
    try:
        for item in rows:
            vuln_id = item.get("cveID")
            if not vuln_id:
                continue
            upsert_vulnerability(
                conn,
                vuln_id=vuln_id,
                source="kev",
                title=item.get("vulnerabilityName"),
                summary=item.get("shortDescription"),
            )
            append_signal(
                conn,
                vuln_id=vuln_id,
                signal_type="kev",
                provider="CISA KEV",
                score=1.0,
                value={
                    "date_added": item.get("dateAdded"),
                    "due_date": item.get("dueDate"),
                    "vendor_project": item.get("vendorProject"),
                    "product": item.get("product"),
                    "known_ransomware_campaign_use": item.get("knownRansomwareCampaignUse"),
                    "required_action": item.get("requiredAction"),
                },
                observed_at=utc_now(),
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
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    args = parser.parse_args()
    result = sync(limit=args.limit, dry_run=args.dry_run, cache_only=args.cache_only)
    print(result)


if __name__ == "__main__":
    main()
