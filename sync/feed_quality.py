#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from sync.common import connect


FEED_PROVIDERS = {
    "kev": ("CISA KEV",),
    "epss": ("FIRST EPSS",),
    "ghsa": ("GitHub Advisory Database",),
    "trivy": ("Trivy JSON", "trivy-db"),
    "go-exploitdb": ("go-exploitdb",),
    "vulnrichment": ("Vulnrichment",),
    "vex": ("VEX", "CSAF", "OpenVEX"),
    "nvd": ("NVD",),
}

REQUIRED_FIELDS = {
    "kev": ("date_added",),
    "epss": ("epss", "percentile"),
    "ghsa": ("severity",),
    "trivy": ("ecosystem", "package_name", "fixed_version"),
    "go-exploitdb": ("exploit_type", "url"),
    "vulnrichment": ("severity",),
    "vex": ("status", "justification"),
    "nvd": ("severity", "cvss"),
}

MAX_STALENESS_HOURS = {
    "kev": 3,
    "epss": 48,
    "ghsa": 24,
    "trivy": 24,
    "go-exploitdb": 48,
    "vulnrichment": 48,
    "vex": 48,
    "nvd": 24,
}


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def rows(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return list(conn.execute(sql, params).fetchall())


def last_fetch(conn: sqlite3.Connection, feed: str) -> sqlite3.Row | None:
    row = conn.execute(
        """
        SELECT feed, attempted_at, status, rows_affected
        FROM fetch_log
        WHERE feed = ?
        ORDER BY attempted_at DESC, id DESC
        LIMIT 1
        """,
        (feed,),
    ).fetchone()
    return row


def last_success(conn: sqlite3.Connection, feed: str) -> sqlite3.Row | None:
    row = conn.execute(
        """
        SELECT feed, attempted_at, status, rows_affected
        FROM fetch_log
        WHERE feed = ? AND status = 'ok'
        ORDER BY attempted_at DESC, id DESC
        LIMIT 1
        """,
        (feed,),
    ).fetchone()
    return row


def providers_for(feed: str) -> tuple[str, ...]:
    return FEED_PROVIDERS.get(feed, (feed,))


def signal_rows(conn: sqlite3.Connection, feed: str) -> list[sqlite3.Row]:
    providers = providers_for(feed)
    placeholders = ",".join("?" for _ in providers)
    return rows(
        conn,
        f"""
        SELECT vuln_id, signal_type, provider, value_json
        FROM signals
        WHERE provider IN ({placeholders})
        """,
        tuple(providers),
    )


def required_field_coverage(feed: str, signal_items: list[sqlite3.Row]) -> float | None:
    required = REQUIRED_FIELDS.get(feed)
    if not required or not signal_items:
        return None

    total = 0
    present = 0
    for signal in signal_items:
        try:
            value = json.loads(signal["value_json"] or "{}")
        except json.JSONDecodeError:
            value = {}
        for field in required:
            total += 1
            if value.get(field) not in (None, "", []):
                present += 1
    return round(present / total, 4) if total else None


def duplicate_rate(signal_items: list[sqlite3.Row]) -> float:
    if not signal_items:
        return 0.0
    keys = [
        (
            signal["vuln_id"],
            signal["signal_type"],
            signal["provider"],
            signal["value_json"],
        )
        for signal in signal_items
    ]
    unique_count = len(set(keys))
    return round((len(keys) - unique_count) / len(keys), 4)


def staleness_status(feed: str, attempted_at: str | None) -> str:
    last = parse_time(attempted_at)
    if not last:
        return "missing"
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    age_hours = (datetime.now(timezone.utc) - last.astimezone(timezone.utc)).total_seconds() / 3600
    max_hours = MAX_STALENESS_HOURS.get(feed)
    if max_hours is None:
        return "unknown"
    return "fresh" if age_hours <= max_hours else "stale"


def summarize_feed(conn: sqlite3.Connection, feed: str) -> dict[str, Any]:
    fetch = last_fetch(conn, feed)
    success = last_success(conn, feed)
    signals = signal_rows(conn, feed)
    vuln_ids = [signal["vuln_id"] for signal in signals if signal["vuln_id"]]

    return {
        "feed": feed,
        "rows_fetched": None,
        "signals_written": len(signals),
        "vuln_id_coverage": 1.0 if signals and len(vuln_ids) == len(signals) else 0.0,
        "required_field_coverage": required_field_coverage(feed, signals),
        "duplicate_rate": duplicate_rate(signals),
        "last_success_at": success["attempted_at"] if success else None,
        "staleness_status": staleness_status(feed, success["attempted_at"] if success else None),
        "last_fetch_status": fetch["status"] if fetch else "missing",
        "last_rows_affected": fetch["rows_affected"] if fetch else None,
    }


def summarize(feeds: list[str] | None = None) -> list[dict[str, Any]]:
    conn = connect()
    try:
        selected = feeds or list(FEED_PROVIDERS)
        return [summarize_feed(conn, feed) for feed in selected]
    finally:
        conn.close()


def print_table(items: list[dict[str, Any]]) -> None:
    columns = (
        "feed",
        "signals_written",
        "vuln_id_coverage",
        "required_field_coverage",
        "duplicate_rate",
        "staleness_status",
        "last_fetch_status",
    )
    print("\t".join(columns))
    for item in items:
        print("\t".join("" if item[column] is None else str(item[column]) for column in columns))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--feed", action="append", help="Limit summary to one feed. Can be repeated.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of tabular output.")
    args = parser.parse_args()
    items = summarize(args.feed)
    if args.json:
        print(json.dumps(items, indent=2, sort_keys=True))
    else:
        print_table(items)


if __name__ == "__main__":
    main()
