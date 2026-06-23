from __future__ import annotations

from pathlib import Path
from typing import Any

from app.routing import plan_request
from sync.common import DB_PATH, connect

from app import scoring


def _connection(db_path: Path | None = None):
    return connect(db_path or DB_PATH)


def find_vuln(vuln_id: str, db_path: Path | None = None) -> dict[str, Any] | None:
    conn = _connection(db_path)
    try:
        return scoring.find_vuln(conn, vuln_id)
    finally:
        conn.close()


def top_risks(limit: int = 20, db_path: Path | None = None) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.top_risks(conn, limit=limit)
    finally:
        conn.close()


def top_unreported_risks(
    limit: int = 100,
    report_key: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.top_unreported_risks(conn, limit=limit, report_key=report_key)
    finally:
        conn.close()


def top_new_alerts(
    limit: int = 100,
    alert_key: str | None = None,
    db_path: Path | None = None,
) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.top_new_alerts(conn, limit=limit, alert_key=alert_key)
    finally:
        conn.close()


def recommend_patch_queue(limit: int = 20, db_path: Path | None = None) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.recommend_patch_queue(conn, limit=limit)
    finally:
        conn.close()


def top_hot(
    limit: int = 20,
    db_path: Path | None = None,
    vuln_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.top_hot(conn, limit=limit, vuln_ids=vuln_ids)
    finally:
        conn.close()


def refresh_hot_for_vuln_ids(
    vuln_ids: list[str],
    db_path: Path | None = None,
    profile: str | None = None,
    query_terms: list[str] | None = None,
    simple: bool = False,
) -> Any:
    from sync import fetch_hot

    return fetch_hot.sync(
        vuln_ids=vuln_ids,
        db_path=db_path,
        profile=profile,
        query_terms=query_terms,
        simple=simple,
    )


def has_exploit(vuln_id: str, db_path: Path | None = None) -> bool:
    conn = _connection(db_path)
    try:
        return scoring.has_exploit(conn, vuln_id)
    finally:
        conn.close()


def affected_assets(vuln_id: str, db_path: Path | None = None) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.affected_assets(conn, vuln_id)
    finally:
        conn.close()


def explain_asset_risk(hostname: str, db_path: Path | None = None) -> dict[str, Any] | None:
    conn = _connection(db_path)
    try:
        return scoring.explain_asset_risk(conn, hostname)
    finally:
        conn.close()


def data_freshness(db_path: Path | None = None) -> list[dict[str, Any]]:
    conn = _connection(db_path)
    try:
        return scoring.data_freshness(conn)
    finally:
        conn.close()


def route_request(request: str) -> dict[str, Any]:
    return plan_request(request).to_dict()


def record_report_history(
    vuln_ids: list[str],
    report_key: str | None = None,
    report_run_id: str | None = None,
    payloads_by_vuln_id: dict[str, Any] | None = None,
    db_path: Path | None = None,
) -> int:
    conn = _connection(db_path)
    try:
        rows_written = scoring.record_report_history(
            conn,
            vuln_ids=vuln_ids,
            report_key=report_key,
            report_run_id=report_run_id,
            payloads_by_vuln_id=payloads_by_vuln_id,
        )
        conn.commit()
        return rows_written
    finally:
        conn.close()


def record_notification_history(
    vuln_ids: list[str],
    alert_key: str | None = None,
    notification_run_id: str | None = None,
    payloads_by_vuln_id: dict[str, Any] | None = None,
    db_path: Path | None = None,
) -> int:
    conn = _connection(db_path)
    try:
        rows_written = scoring.record_notification_history(
            conn,
            vuln_ids=vuln_ids,
            alert_key=alert_key,
            notification_run_id=notification_run_id,
            payloads_by_vuln_id=payloads_by_vuln_id,
        )
        conn.commit()
        return rows_written
    finally:
        conn.close()


def _print_table(rows: list[dict[str, Any]], columns: tuple[str, ...]) -> None:
    print("\t".join(columns))
    for row in rows:
        print("\t".join("" if row.get(column) is None else str(row.get(column)) for column in columns))


def _print_hot_rows(rows: list[dict[str, Any]], details: bool = False) -> None:
    priority_columns = (
        "hot_score",
        "kev_present",
        "exploit_present",
        "epss_score",
        "cvss_score",
        "published_at",
        "first_seen_at",
        "vuln_id",
    )
    reference_columns = (
        "vuln_id",
        "signal_score",
        "observed_at",
        "source",
        "severity",
        "title",
        "source_label",
        "query_count",
        "search_queries",
        "search_budget",
        "result_count",
        "evidence_count",
        "independent_sources",
        "evidence_types",
        "source_types",
        "urls",
        "headline",
        "discovery_query_count",
        "discovery_queries",
        "discovery_result_count",
        "discovery_hits",
        "discovered_vuln_ids",
    )
    print("priority [hot / KEV / exploit / EPSS / CVSS / published_at]")
    _print_table(rows, priority_columns)
    if details:
        print()
        print("hot_reference [reference-only]")
        _print_table(rows, reference_columns)


def main() -> None:
    import argparse
    import json

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    hot_parser = subparsers.add_parser("hot", help="Show current hot vulnerabilities.")
    hot_parser.add_argument("--limit", type=int, default=20)
    hot_parser.add_argument("--details", action="store_true", help="Show reference-only hot evidence columns.")
    hot_parser.add_argument("--json", action="store_true")
    hot_parser.add_argument("--vuln-id", action="append", default=[], help="Directly evaluate one or more vuln_ids for hot evidence. Can be repeated.")
    hot_parser.add_argument("--profile", choices=("strict", "balanced", "broad"), help="Shortcut for hot search settings when evaluating vuln_ids.")
    hot_parser.add_argument("--query-term", action="append", default=[], help="Optional extra discovery term to widen hot coverage when evaluating vuln_ids.")
    hot_parser.add_argument("--simple", action="store_true", help="Evaluate vuln_ids with RSS-only discovery mode.")

    route_parser = subparsers.add_parser("route", help="Plan main/sub-agent routing for a request.")
    route_parser.add_argument("request", help="Free-form request to route.")
    route_parser.add_argument("--json", action="store_true")

    vuln_parser = subparsers.add_parser("vuln", help="Show one vulnerability from core.db.")
    vuln_parser.add_argument("vuln_id")
    vuln_parser.add_argument("--json", action="store_true")

    risks_parser = subparsers.add_parser("risks", help="Show the top risk-ranked findings.")
    risks_parser.add_argument("--limit", type=int, default=20)
    risks_parser.add_argument("--json", action="store_true")

    patch_parser = subparsers.add_parser("patch-queue", help="Show the patch queue.")
    patch_parser.add_argument("--limit", type=int, default=20)
    patch_parser.add_argument("--json", action="store_true")

    has_exploit_parser = subparsers.add_parser("has-exploit", help="Check whether a vuln has exploit evidence.")
    has_exploit_parser.add_argument("vuln_id")
    has_exploit_parser.add_argument("--json", action="store_true")

    assets_parser = subparsers.add_parser("assets", help="Show affected assets for one vulnerability.")
    assets_parser.add_argument("vuln_id")
    assets_parser.add_argument("--json", action="store_true")

    asset_risk_parser = subparsers.add_parser("asset-risk", help="Explain risk for one asset hostname.")
    asset_risk_parser.add_argument("hostname")
    asset_risk_parser.add_argument("--json", action="store_true")

    freshness_parser = subparsers.add_parser("freshness", help="Show feed freshness from fetch_log.")
    freshness_parser.add_argument("--json", action="store_true")

    args = parser.parse_args()

    if args.command == "hot":
        if args.vuln_id:
            refresh_hot_for_vuln_ids(
                vuln_ids=args.vuln_id,
                profile=args.profile,
                query_terms=args.query_term,
                simple=args.simple,
            )
        rows = top_hot(limit=args.limit, vuln_ids=args.vuln_id or None)
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True))
        else:
            _print_hot_rows(rows, details=args.details)
    elif args.command == "route":
        plan = plan_request(args.request)
        if args.json:
            print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
        else:
            print(f"mode: {plan.mode}")
            print(f"primary_agent: {plan.primary_agent}")
            print(f"confidence: {plan.confidence}")
            print(f"summary: {plan.summary}")
            if plan.sub_agents:
                print("sub_agents:")
                for step in plan.sub_agents:
                    print(f"  - role: {step.role}")
                    print(f"    task: {step.task}")
                    print(f"    reason: {step.reason}")
                    if step.inputs:
                        print(f"    inputs: {', '.join(step.inputs)}")
                    if step.commands:
                        print("    commands:")
                        for command in step.commands:
                            print(f"      - {command}")
    elif args.command == "vuln":
        row = find_vuln(args.vuln_id)
        if args.json:
            print(json.dumps(row, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(json.dumps(row, indent=2, sort_keys=True, ensure_ascii=False))
    elif args.command == "risks":
        rows = top_risks(limit=args.limit)
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False))
    elif args.command == "patch-queue":
        rows = recommend_patch_queue(limit=args.limit)
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False))
    elif args.command == "has-exploit":
        result = {"vuln_id": args.vuln_id, "has_exploit": has_exploit(args.vuln_id)}
        if args.json:
            print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    elif args.command == "assets":
        rows = affected_assets(args.vuln_id)
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False))
    elif args.command == "asset-risk":
        row = explain_asset_risk(args.hostname)
        if args.json:
            print(json.dumps(row, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(json.dumps(row, indent=2, sort_keys=True, ensure_ascii=False))
    elif args.command == "freshness":
        rows = data_freshness()
        if args.json:
            print(json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False))
        else:
            print(json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=False))


if __name__ == "__main__":
    main()
