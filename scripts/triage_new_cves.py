#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from db.migrate import migrate
from sync.common import DB_PATH, connect, utc_now


TRIAGE_SCHEMA_VERSION = 1
CONTEXT_REVIEW_SCHEMA_VERSION = 1
DEFAULT_LIMIT = 40
DEFAULT_WINDOW_HOURS = 24
BOUNDARY_FILTERS = (
    "cisco",
    "palo alto",
    "fortinet",
    "juniper",
    "f5",
)


def default_cutoff(now: datetime | None = None, hours: int = DEFAULT_WINDOW_HOURS) -> str:
    base = now or datetime.now(timezone.utc)
    return (base - timedelta(hours=hours)).isoformat(timespec="seconds")


def _signals(row: dict[str, Any]) -> list[str]:
    names = []
    if row["kev_present"]:
        names.append("kev")
    if row["exploit_present"]:
        names.append("exploit")
    if row["hot_present"]:
        names.append("hot")
    if row["package_present"]:
        names.append("package_advisory")
    return names


def _tier(row: dict[str, Any]) -> str:
    epss = float(row["epss"] or 0.0)
    if (row["kev_present"] and row["exploit_present"]) or (row["hot_present"] and row["exploit_present"]) or epss >= 0.5:
        return "P0"
    if row["kev_present"] or row["exploit_present"] or row["hot_present"] or epss >= 0.05:
        return "P1"
    return "P2"


def _reason(row: dict[str, Any]) -> str:
    epss = float(row["epss"] or 0.0)
    cvss = float(row["cvss_score"] or 0.0)
    if row["kev_present"] and row["exploit_present"]:
        return "KEV + exploit"
    if row["hot_present"] and row["exploit_present"]:
        return "hot + exploit"
    if row["kev_present"]:
        return "KEV"
    if row["exploit_present"]:
        return "exploit"
    if row["hot_present"]:
        return "hot"
    if epss >= 0.05:
        return "high EPSS"
    if cvss >= 9.8:
        return "critical CVSS"
    return "high CVSS"


def _confidence(row: dict[str, Any]) -> str:
    if row["kev_present"] or row["exploit_present"]:
        return "high"
    if row["hot_present"] or float(row["epss"] or 0.0) >= 0.05:
        return "medium"
    return "low"


def _candidate(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "vuln_id": row["vuln_id"],
        "title": row["title"],
        "source": row["source"],
        "published_at": row["published_at"],
        "first_seen_at": row["first_seen_at"],
        "cvss": row["cvss_score"],
        "epss": row["epss"],
        "signals": _signals(row),
        "tier": _tier(row),
        "reason": _reason(row),
        "confidence": _confidence(row),
        "score": row["score"],
    }


def _parse_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _latest_signal_context(conn, vuln_ids: list[str]) -> dict[str, dict[str, Any]]:
    if not vuln_ids:
        return {}
    placeholders = ",".join("?" for _ in vuln_ids)
    rows = conn.execute(
        f"""
        SELECT vuln_id, signal_type, provider, score, value_json, observed_at
        FROM (
          SELECT vuln_id, signal_type, provider, score, value_json, observed_at, id,
                 row_number() OVER (
                   PARTITION BY vuln_id, signal_type
                   ORDER BY observed_at DESC, id DESC
                 ) AS rn
          FROM signals
          WHERE vuln_id IN ({placeholders})
        )
        WHERE rn = 1
        ORDER BY vuln_id, signal_type
        """,
        tuple(vuln_ids),
    ).fetchall()
    context: dict[str, dict[str, Any]] = {vuln_id: {} for vuln_id in vuln_ids}
    for row in rows:
        value = _parse_json(row["value_json"])
        evidence = {
            "provider": row["provider"],
            "score": row["score"],
            "observed_at": row["observed_at"],
        }
        if row["signal_type"] == "hot":
            evidence["summary"] = {
                "attention_score": value.get("attention_score") or value.get("score"),
                "domains": value.get("domains") or value.get("top_domains") or [],
                "urls": value.get("urls") or [],
                "fetch_errors": value.get("fetch_errors") or [],
            }
        elif row["signal_type"] == "exploit":
            evidence["summary"] = {
                "source": value.get("source"),
                "exploit_type": value.get("exploit_type"),
                "url": value.get("url"),
            }
        elif row["signal_type"] == "kev":
            evidence["summary"] = {
                "vendor_project": value.get("vendorProject"),
                "product": value.get("product"),
                "known_ransomware": value.get("knownRansomwareCampaignUse"),
                "due_date": value.get("dueDate"),
            }
        context.setdefault(row["vuln_id"], {})[row["signal_type"]] = evidence
    return context


def _review_payload(report: dict[str, Any], signal_context: dict[str, dict[str, Any]]) -> dict[str, Any]:
    candidates = [*report["watch_now"], *report["monitor_only"]]
    return {
        "schema_version": CONTEXT_REVIEW_SCHEMA_VERSION,
        "kind": "new_cve_context_review_request",
        "instructions": [
            "Review whether each candidate deserves human attention now.",
            "Use only the supplied local DB context.",
            "Do not browse the web.",
            "Return JSON with reviews[].",
            "Allowed decision values: watch_now, monitor_only, suppress.",
            "Do not suppress KEV or exploit-backed candidates; explain them instead.",
            "Downgrade weak hot-only or CVSS-only candidates when the context is not actionable.",
        ],
        "cutoff": report["cutoff"],
        "candidates": [
            {
                **candidate,
                "signal_context": signal_context.get(candidate["vuln_id"], {}),
            }
            for candidate in candidates
        ],
        "response_schema": {
            "schema_version": CONTEXT_REVIEW_SCHEMA_VERSION,
            "kind": "new_cve_context_review_response",
            "reviews": [
                {
                    "vuln_id": "CVE-YYYY-NNNN",
                    "decision": "watch_now|monitor_only|suppress",
                    "confidence": "high|medium|low",
                    "reason": "short operational reason",
                }
            ],
        },
    }


def _run_context_review(command: str, payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    completed = subprocess.run(
        shlex.split(command),
        input=json.dumps(payload, ensure_ascii=False),
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or f"context review command failed: {completed.returncode}")
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("context review command did not return JSON") from exc
    if not isinstance(response, dict):
        raise RuntimeError("context review command returned non-object JSON")
    return response


def _review_by_id(response: dict[str, Any]) -> dict[str, dict[str, Any]]:
    reviews = response.get("reviews")
    if not isinstance(reviews, list):
        return {}
    by_id: dict[str, dict[str, Any]] = {}
    for review in reviews:
        if not isinstance(review, dict):
            continue
        vuln_id = str(review.get("vuln_id") or "")
        decision = str(review.get("decision") or "")
        if not vuln_id or decision not in {"watch_now", "monitor_only", "suppress"}:
            continue
        by_id[vuln_id] = review
    return by_id


def _protected_from_suppression(item: dict[str, Any]) -> bool:
    signals = set(item.get("signals") or [])
    return bool(signals & {"kev", "exploit"})


def _apply_context_reviews(report: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    by_id = _review_by_id(response)
    original_items = [*report["watch_now"], *report["monitor_only"]]
    watch_now: list[dict[str, Any]] = []
    monitor_only: list[dict[str, Any]] = []
    suppressed_by_review = 0

    for item in original_items:
        review = by_id.get(item["vuln_id"])
        if review:
            decision = str(review["decision"])
            if decision == "suppress" and _protected_from_suppression(item):
                decision = "watch_now"
            reviewed = {
                **item,
                "context_review": {
                    "decision": decision,
                    "confidence": review.get("confidence") or item.get("confidence"),
                    "reason": review.get("reason") or item.get("reason"),
                },
                "reason": review.get("reason") or item.get("reason"),
                "confidence": review.get("confidence") or item.get("confidence"),
            }
        else:
            decision = "watch_now" if item["tier"] in {"P0", "P1"} else "monitor_only"
            reviewed = item

        if decision == "watch_now":
            watch_now.append(reviewed)
        elif decision == "monitor_only":
            monitor_only.append(reviewed)
        else:
            suppressed_by_review += 1

    updated = {
        **report,
        "watch_now": watch_now,
        "monitor_only": monitor_only,
        "context_review": {
            "enabled": True,
            "schema_version": CONTEXT_REVIEW_SCHEMA_VERSION,
            "reviewed_count": len(by_id),
            "suppressed_count": suppressed_by_review,
        },
    }
    updated["summary"] = {
        **report["summary"],
        "watch_now_count": len(watch_now),
        "monitor_only_count": len(monitor_only),
        "candidate_count": len(watch_now) + len(monitor_only),
        "suppressed_count": report["summary"]["suppressed_count"] + suppressed_by_review,
    }
    updated["caveats"] = [
        *report["caveats"],
        "Context review can downgrade weak hot-only or CVSS-only candidates, but cannot suppress KEV or exploit-backed candidates.",
    ]
    return updated


def build_report(
    cutoff: str,
    limit: int = DEFAULT_LIMIT,
    db_path: Path = DB_PATH,
    include_hot: bool = True,
    context_review_cmd: str | None = None,
    context_review_timeout: int = 120,
) -> dict[str, Any]:
    migrate(db_path)
    conn = connect(db_path)
    try:
        filters = " AND ".join(
            [
                "lower(coalesce(v.title, '') || ' ' || coalesce(v.summary, '')) NOT LIKE ?"
                for _ in BOUNDARY_FILTERS
            ]
        )
        params: list[Any] = [cutoff, *(f"%{item}%" for item in BOUNDARY_FILTERS)]
        hot_present = "max(CASE WHEN l.signal_type = 'hot' THEN 1 ELSE 0 END)" if include_hot else "0"
        rows = conn.execute(
            f"""
            WITH latest AS (
              SELECT vuln_id, signal_type, score, observed_at, id,
                     row_number() OVER (
                       PARTITION BY vuln_id, signal_type
                       ORDER BY observed_at DESC, id DESC
                     ) AS rn
              FROM signals
            ),
            flags AS (
              SELECT
                v.vuln_id,
                v.source,
                v.title,
                v.published_at,
                v.first_seen_at,
                COALESCE(v.cvss_score, 0) AS cvss_score,
                COALESCE(e.epss, 0) AS epss,
                max(CASE WHEN l.signal_type = 'kev' THEN 1 ELSE 0 END) AS kev_present,
                max(CASE WHEN l.signal_type = 'exploit' THEN 1 ELSE 0 END) AS exploit_present,
                {hot_present} AS hot_present,
                max(CASE WHEN l.signal_type = 'package_advisory' THEN 1 ELSE 0 END) AS package_present
              FROM vulnerabilities v
              LEFT JOIN latest l ON l.vuln_id = v.vuln_id AND l.rn = 1
              LEFT JOIN epss_current e ON e.vuln_id = v.vuln_id
              WHERE v.first_seen_at >= ?
                AND {filters}
              GROUP BY v.vuln_id
            )
            SELECT *,
                   ROUND(
                     cvss_score * 4.0
                     + epss * 20.0
                     + CASE WHEN kev_present = 1 THEN 15 ELSE 0 END
                     + CASE WHEN exploit_present = 1 THEN 10 ELSE 0 END
                     + CASE WHEN hot_present = 1 THEN 5 ELSE 0 END,
                     2
                   ) AS score
            FROM flags
            WHERE kev_present = 1
               OR exploit_present = 1
               OR hot_present = 1
               OR epss >= 0.05
               OR cvss_score >= 9.0
            ORDER BY score DESC, kev_present DESC, exploit_present DESC, hot_present DESC,
                     cvss_score DESC, epss DESC, first_seen_at DESC, vuln_id
            LIMIT ?
            """,
            (*params, limit),
        ).fetchall()

        total_recent = conn.execute(
            f"""
            SELECT count(*) AS n
            FROM vulnerabilities v
            WHERE v.first_seen_at >= ?
              AND {filters}
            """,
            params,
        ).fetchone()["n"]
        signal_context = _latest_signal_context(conn, [row["vuln_id"] for row in rows])
    finally:
        conn.close()

    candidates = [_candidate(dict(row)) for row in rows]
    watch_now = [item for item in candidates if item["tier"] in {"P0", "P1"}]
    monitor_only = [item for item in candidates if item["tier"] == "P2"]

    report = {
        "schema_version": TRIAGE_SCHEMA_VERSION,
        "kind": "new_cve_triage",
        "generated_at": utc_now(),
        "cutoff": cutoff,
        "limit": limit,
        "include_hot": include_hot,
        "summary": {
            "recent_count": total_recent,
            "candidate_count": len(candidates),
            "watch_now_count": len(watch_now),
            "monitor_only_count": len(monitor_only),
            "suppressed_count": max(0, total_recent - len(candidates)),
        },
        "watch_now": watch_now,
        "monitor_only": monitor_only,
        "caveats": [
            "Ranking is signal-based; asset impact is not inferred unless findings/assets exist.",
            "Hot is treated as early attention and should be checked when it is the only strong signal.",
        ],
    }
    if not context_review_cmd:
        return report

    payload = _review_payload(report, signal_context)
    try:
        response = _run_context_review(context_review_cmd, payload, context_review_timeout)
    except Exception as exc:
        return {
            **report,
            "context_review": {
                "enabled": True,
                "status": "error",
                "error": str(exc),
            },
            "caveats": [
                *report["caveats"],
                "Context review failed; report fell back to deterministic triage only.",
            ],
        }
    return _apply_context_reviews(report, response)


def _print_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"cutoff: {report['cutoff']}")
    print(
        "counts: "
        f"recent={summary['recent_count']} "
        f"watch_now={summary['watch_now_count']} "
        f"monitor_only={summary['monitor_only_count']} "
        f"suppressed={summary['suppressed_count']}"
    )
    print("tier\tvuln_id\tcvss\tepss\tsignals\treason\ttitle")
    for item in [*report["watch_now"], *report["monitor_only"]]:
        print(
            "\t".join(
                [
                    item["tier"],
                    item["vuln_id"],
                    "" if item["cvss"] is None else str(item["cvss"]),
                    "" if item["epss"] is None else str(round(float(item["epss"]), 5)),
                    ",".join(item["signals"]) or "-",
                    item["reason"],
                    item["title"] or "",
                ]
            )
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Filter newly ingested CVEs into a short triage list.")
    parser.add_argument("--since", help="Explicit first_seen_at cutoff. Defaults to the last 24h in UTC.")
    parser.add_argument("--hours", type=int, default=DEFAULT_WINDOW_HOURS, help="Window used when --since is omitted.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-hot", action="store_true", help="Ignore hot as a triage signal.")
    parser.add_argument(
        "--llm-review-cmd",
        help="Optional command that receives review JSON on stdin and returns review JSON on stdout.",
    )
    parser.add_argument("--llm-review-timeout", type=int, default=120)
    args = parser.parse_args()

    cutoff = args.since or default_cutoff(hours=args.hours)
    report = build_report(
        cutoff=cutoff,
        limit=args.limit,
        db_path=args.db_path,
        include_hot=not args.no_hot,
        context_review_cmd=args.llm_review_cmd,
        context_review_timeout=args.llm_review_timeout,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        _print_summary(report)


if __name__ == "__main__":
    main()
