#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import scoring
from db.migrate import migrate
from sync.common import DB_PATH, connect, utc_now


REPORT_SCHEMA_VERSION = 1
DEFAULT_DAYS = 7
DEFAULT_LIMIT = 30
DEFAULT_HOT_LIMIT = 20
DEFAULT_REPORT_DIR = ROOT / "data" / "reports" / "attention"
FEED_WATERMARKS = (
    "cve_program",
    "kev",
    "epss",
    "hot",
    "ghsa",
    "trivy_vuln_list",
    "go-exploitdb",
    "vulnrichment",
)


def _load_script_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


triage_new_cves = _load_script_module("triage_new_cves_attention", ROOT / "scripts" / "triage_new_cves.py")


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_as_of(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    parsed = parse_time(value)
    if parsed is None:
        raise ValueError(f"invalid --as-of: {value}")
    return parsed


def date_only(value: Any) -> str:
    parsed = parse_time(str(value)) if value else None
    if parsed is not None:
        return parsed.date().isoformat()
    return str(value or "")


def format_number(value: Any, digits: int = 5) -> str:
    if value is None:
        return "missing"
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def compact(value: Any, limit: int = 96) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def feed_watermarks(db_path: Path) -> dict[str, Any]:
    conn = connect(db_path)
    try:
        watermarks: dict[str, Any] = {}
        for feed in FEED_WATERMARKS:
            row = conn.execute(
                """
                SELECT attempted_at, rows_affected, cache_used
                FROM fetch_log
                WHERE feed = ? AND status = 'ok'
                ORDER BY attempted_at DESC, id DESC
                LIMIT 1
                """,
                (feed,),
            ).fetchone()
            watermarks[feed] = dict(row) if row else None
        return watermarks
    finally:
        conn.close()


def epss_lookup(db_path: Path, vuln_ids: list[str]) -> dict[str, float | None]:
    if not vuln_ids:
        return {}
    placeholders = ",".join("?" for _ in vuln_ids)
    conn = connect(db_path)
    try:
        rows = conn.execute(
            f"""
            SELECT vuln_id, epss
            FROM epss_current
            WHERE vuln_id IN ({placeholders})
            """,
            tuple(vuln_ids),
        ).fetchall()
    finally:
        conn.close()
    values = {vuln_id: None for vuln_id in vuln_ids}
    values.update({row["vuln_id"]: float(row["epss"]) for row in rows})
    return values


def normalize_watch_items(items: list[dict[str, Any]], epss_by_id: dict[str, float | None]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in items:
        vuln_id = item["vuln_id"]
        normalized.append(
            {
                "vuln_id": vuln_id,
                "title": item.get("title"),
                "source": item.get("source"),
                "published_at": item.get("published_at"),
                "published_date": date_only(item.get("published_at")),
                "first_seen_at": item.get("first_seen_at"),
                "first_seen_date": date_only(item.get("first_seen_at")),
                "cvss": item.get("cvss"),
                "epss": epss_by_id.get(vuln_id),
                "signals": item.get("signals") or [],
                "tier": item.get("tier"),
                "reason": item.get("reason"),
                "confidence": item.get("confidence"),
                "score": item.get("score"),
            }
        )
    return normalized


def normalize_hot_items(items: list[dict[str, Any]], epss_by_id: dict[str, float | None]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in items:
        vuln_id = item["vuln_id"]
        normalized.append(
            {
                "vuln_id": vuln_id,
                "title": item.get("title"),
                "source": item.get("source"),
                "observed_at": item.get("observed_at"),
                "observed_date": date_only(item.get("observed_at")),
                "published_at": item.get("published_at"),
                "published_date": date_only(item.get("published_at")),
                "first_seen_at": item.get("first_seen_at"),
                "first_seen_date": date_only(item.get("first_seen_at")),
                "hot_score": item.get("hot_score"),
                "cvss": item.get("cvss_score"),
                "epss": epss_by_id.get(vuln_id),
                "kev": bool(item.get("kev_present")),
                "exploit": bool(item.get("exploit_present")),
                "evidence_types": item.get("evidence_types") or [],
                "source_count": item.get("independent_sources"),
                "headline": item.get("headline"),
                "urls": item.get("urls") or [],
            }
        )
    return normalized


def build_report(
    db_path: Path = DB_PATH,
    days: int = DEFAULT_DAYS,
    as_of: str | None = None,
    cutoff: str | None = None,
    limit: int = DEFAULT_LIMIT,
    hot_limit: int = DEFAULT_HOT_LIMIT,
) -> dict[str, Any]:
    if days <= 0:
        raise ValueError("days must be positive")
    if limit <= 0:
        raise ValueError("limit must be positive")
    if hot_limit < 0:
        raise ValueError("hot-limit must be >= 0")

    migrate(db_path)
    as_of_dt = parse_as_of(as_of)
    selected_cutoff = cutoff or (as_of_dt - timedelta(days=days)).isoformat(timespec="seconds")
    cutoff_dt = parse_time(selected_cutoff)
    if cutoff_dt is None:
        raise ValueError(f"invalid cutoff: {selected_cutoff}")

    triage_report = triage_new_cves.build_report(cutoff=selected_cutoff, limit=limit, db_path=db_path)
    watch_candidates = triage_report.get("watch_now", [])
    watch_ids = [item["vuln_id"] for item in watch_candidates]
    watch_items = normalize_watch_items(watch_candidates, epss_lookup(db_path, watch_ids))

    conn = connect(db_path)
    try:
        hot_rows = scoring.top_hot(conn, limit=None)
    finally:
        conn.close()
    recent_hot = [
        item
        for item in hot_rows
        if (parse_time(item.get("observed_at")) and parse_time(item.get("observed_at")) >= cutoff_dt)
    ]
    if hot_limit:
        recent_hot = recent_hot[:hot_limit]
    hot_ids = [item["vuln_id"] for item in recent_hot]
    hot_items = normalize_hot_items(recent_hot, epss_lookup(db_path, hot_ids))

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "kind": "recent_attention_report",
        "generated_at": utc_now(),
        "as_of": as_of_dt.isoformat(timespec="seconds"),
        "cutoff": cutoff_dt.isoformat(timespec="seconds"),
        "days": days,
        "db_path": str(db_path),
        "options": {
            "limit": limit,
            "hot_limit": hot_limit,
        },
        "feed_watermarks": feed_watermarks(db_path),
        "triage_summary": triage_report.get("summary", {}),
        "watch_now": watch_items,
        "hot": hot_items,
    }


def save_report(report: dict[str, Any], report_dir: Path = DEFAULT_REPORT_DIR) -> Path:
    report_dir.mkdir(parents=True, exist_ok=True)
    generated_at = (
        str(report["generated_at"])
        .replace("+00:00", "Z")
        .replace(":", "")
        .replace("/", "-")
    )
    path = report_dir / f"{generated_at}.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    return path


def markdown_table(columns: list[str], rows: list[list[str]]) -> None:
    print("| " + " | ".join(columns) + " |")
    print("|" + "|".join("---" for _ in columns) + "|")
    for row in rows:
        print("| " + " | ".join(cell.replace("|", "\\|") for cell in row) + " |")


def print_report(report: dict[str, Any]) -> None:
    print(f"scope: {report['cutoff']} .. {report['as_of']} UTC")
    summary = report.get("triage_summary") or {}
    print(
        "counts: "
        f"recent={summary.get('recent_count', 0)} "
        f"watch_now={len(report.get('watch_now', []))} "
        f"hot={len(report.get('hot', []))}"
    )
    print()
    print("watch_now:")
    if report.get("watch_now"):
        markdown_table(
            ["published", "first_seen", "vuln_id", "reason", "CVSS", "EPSS", "signals", "title"],
            [
                [
                    item["published_date"],
                    item["first_seen_date"],
                    item["vuln_id"],
                    str(item.get("reason") or ""),
                    format_number(item.get("cvss"), digits=1),
                    format_number(item.get("epss"), digits=5),
                    ",".join(item.get("signals") or []) or "-",
                    compact(item.get("title")),
                ]
                for item in report.get("watch_now", [])
            ],
        )
    else:
        print("- none")
    print()
    print("hot:")
    if report.get("hot"):
        markdown_table(
            ["observed", "published", "first_seen", "vuln_id", "hot", "CVSS", "EPSS", "KEV", "exploit", "evidence", "title"],
            [
                [
                    item["observed_date"],
                    item["published_date"],
                    item["first_seen_date"],
                    item["vuln_id"],
                    format_number(item.get("hot_score"), digits=2),
                    format_number(item.get("cvss"), digits=1),
                    format_number(item.get("epss"), digits=5),
                    "yes" if item.get("kev") else "no",
                    "yes" if item.get("exploit") else "no",
                    ",".join(item.get("evidence_types") or []) or "-",
                    compact(item.get("title")),
                ]
                for item in report.get("hot", [])
            ],
        )
    else:
        print("- none")
    if report.get("report_path"):
        print()
        print(f"report_path: {report['report_path']}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Report notable vulnerabilities over a reproducible recent window.")
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--as-of", help="Pinned report end time. Use this to reproduce the same relative window.")
    parser.add_argument("--cutoff", help="Explicit inclusive window start. Overrides --days for the start time.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Maximum deterministic triage candidates to evaluate.")
    parser.add_argument("--hot-limit", type=int, default=DEFAULT_HOT_LIMIT, help="Maximum recent hot rows to print. Use 0 for all.")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = build_report(
        db_path=args.db_path,
        days=args.days,
        as_of=args.as_of,
        cutoff=args.cutoff,
        limit=args.limit,
        hot_limit=args.hot_limit,
    )
    if not args.no_save:
        report["report_path"] = str(save_report(report, report_dir=args.report_dir))
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print_report(report)


if __name__ == "__main__":
    main()
