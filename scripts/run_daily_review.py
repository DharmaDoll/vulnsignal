#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from db.migrate import migrate
from sync.common import DB_PATH, connect, utc_now
from sync.feed_quality import summarize as summarize_feed_quality
from app import scoring


DAILY_REVIEW_SCHEMA_VERSION = 1
DEFAULT_REPORT_DIR = ROOT / "data" / "reports" / "triage"
DEFAULT_CODEX_REVIEW_CMD = "python3 scripts/codex_triage_review.py --timeout 300"
DEFAULT_HOT_LIMIT: int | None = None


def _load_script_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


triage_new_cves = _load_script_module("triage_new_cves_daily", ROOT / "scripts" / "triage_new_cves.py")
deep_dive = _load_script_module("deep_dive_daily", ROOT / "scripts" / "deep_dive.py")


def timed_step(name: str, fn: Callable[[], Any]) -> tuple[Any, dict[str, Any]]:
    start = time.perf_counter()
    try:
        result = fn()
    except Exception as exc:
        elapsed = time.perf_counter() - start
        return None, {
            "name": name,
            "status": "error",
            "elapsed_seconds": round(elapsed, 3),
            "error": str(exc),
        }
    elapsed = time.perf_counter() - start
    return result, {
        "name": name,
        "status": "ok",
        "elapsed_seconds": round(elapsed, 3),
    }


def run_command(command: list[str], env: dict[str, str] | None = None) -> dict[str, Any]:
    process_env = os.environ.copy()
    if env:
        process_env.update(env)
    completed = subprocess.run(command, text=True, capture_output=True, check=False, cwd=ROOT, env=process_env)
    return {
        "command": command,
        "env": env or {},
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def context_review_metrics(triage_report: dict[str, Any]) -> dict[str, Any]:
    review = triage_report.get("context_review") or {}
    reviewed_items = [
        item
        for section in ("watch_now", "monitor_only")
        for item in triage_report.get(section, [])
        if item.get("context_review")
    ]
    decisions: dict[str, int] = {}
    for item in reviewed_items:
        decision = str((item.get("context_review") or {}).get("decision") or "unknown")
        decisions[decision] = decisions.get(decision, 0) + 1

    return {
        "enabled": bool(review.get("enabled")),
        "status": review.get("status", "ok") if review else "not_run",
        "reviewed_count": int(review.get("reviewed_count") or 0),
        "suppressed_count": int(review.get("suppressed_count") or 0),
        "decisions": decisions,
        "kept_after_review_count": len(reviewed_items),
    }


def determine_cutoff(
    db_path: Path = DB_PATH,
    feed: str = "cve_program",
    fallback_hours: int = 24,
) -> dict[str, Any]:
    conn = connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT attempted_at, rows_affected, cache_used
            FROM fetch_log
            WHERE feed = ? AND status = 'ok'
            ORDER BY attempted_at DESC, id DESC
            LIMIT 2
            """,
            (feed,),
        ).fetchall()
    finally:
        conn.close()

    if len(rows) >= 2:
        return {
            "cutoff": rows[1]["attempted_at"],
            "strategy": "previous_success",
            "feed": feed,
            "latest_success_at": rows[0]["attempted_at"],
            "previous_success_at": rows[1]["attempted_at"],
        }

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=fallback_hours)).isoformat(timespec="seconds")
    return {
        "cutoff": cutoff,
        "strategy": "fallback_hours",
        "feed": feed,
        "fallback_hours": fallback_hours,
        "latest_success_at": rows[0]["attempted_at"] if rows else None,
        "previous_success_at": None,
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


def build_watch_list(triage_report: dict[str, Any]) -> list[dict[str, Any]]:
    watch_now = sorted(
        triage_report.get("watch_now", []),
        key=lambda item: (not bool(item.get("watch_now_locked")),),
    )
    return [
        {**item, "category": "watch_now"}
        for item in watch_now
    ] + [
        {**item, "category": "monitor_only"}
        for item in triage_report.get("monitor_only", [])
    ]


def build_hot_watchlist(db_path: Path = DB_PATH, limit: int | None = DEFAULT_HOT_LIMIT) -> list[dict[str, Any]]:
    if limit is not None and limit < 0:
        raise ValueError("hot limit must be >= 0")
    conn = connect(db_path)
    try:
        return scoring.top_hot(conn, limit=None if limit == 0 else limit)
    finally:
        conn.close()


def build_daily_review(
    db_path: Path = DB_PATH,
    limit: int = 40,
    cutoff: str | None = None,
    cutoff_feed: str = "cve_program",
    fallback_hours: int = 24,
    codex_review: bool = False,
    codex_review_cmd: str = DEFAULT_CODEX_REVIEW_CMD,
    codex_review_timeout: int = 360,
    deep_dive_watch_now: bool = False,
    refresh_sources: bool = False,
    ingest_recent: bool = False,
    refresh_hot: bool = False,
    hot_limit: int | None = DEFAULT_HOT_LIMIT,
    save: bool = True,
    report_dir: Path = DEFAULT_REPORT_DIR,
) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    commands: dict[str, Any] = {}

    _, step = timed_step("migrate", lambda: migrate(db_path))
    steps.append(step)
    if step["status"] != "ok":
        raise RuntimeError(step["error"])

    if refresh_sources:
        result, step = timed_step("refresh_sources", lambda: run_command([str(ROOT / "scripts" / "refresh_all_sources.sh")]))
        steps.append(step)
        commands["refresh_sources"] = result
        if not result or result["returncode"] != 0:
            raise RuntimeError("refresh_sources failed")

    if ingest_recent:
        env = {"SKIP_MIRROR_REFRESH": "1"} if refresh_sources else None
        result, step = timed_step(
            "ingest_recent",
            lambda: run_command([str(ROOT / "scripts" / "ingest_recent_core_db.sh")], env=env),
        )
        steps.append(step)
        commands["ingest_recent"] = result
        if not result or result["returncode"] != 0:
            raise RuntimeError("ingest_recent failed")

    if refresh_hot:
        result, step = timed_step("refresh_hot", lambda: run_command([sys.executable, "-m", "sync.fetch_hot"]))
        steps.append(step)
        commands["refresh_hot"] = result
        if not result or result["returncode"] != 0:
            raise RuntimeError("refresh_hot failed")

    feed_quality, step = timed_step("feed_quality", lambda: summarize_feed_quality(db_path=db_path))
    steps.append(step)

    cutoff_info = {"cutoff": cutoff, "strategy": "explicit"} if cutoff else determine_cutoff(
        db_path=db_path,
        feed=cutoff_feed,
        fallback_hours=fallback_hours,
    )
    selected_cutoff = str(cutoff_info["cutoff"])

    triage_report, step = timed_step(
        "triage",
        lambda: triage_new_cves.build_report(
            cutoff=selected_cutoff,
            limit=limit,
            db_path=db_path,
            context_review_cmd=codex_review_cmd if codex_review else None,
            context_review_timeout=codex_review_timeout,
        ),
    )
    steps.append(step)
    if triage_report is None:
        raise RuntimeError(step.get("error") or "triage failed")

    deep_dives: dict[str, Any] = {}
    if deep_dive_watch_now:
        for item in sorted(
            triage_report.get("watch_now", []),
            key=lambda item: (not bool(item.get("watch_now_locked")),),
        ):
            vuln_id = item["vuln_id"]
            deep_report, step = timed_step(
                f"deep_dive:{vuln_id}",
                lambda vuln_id=vuln_id: deep_dive.build_report(vuln_id=vuln_id, db_path=db_path),
            )
            steps.append(step)
            if deep_report is not None:
                deep_dives[vuln_id] = deep_report

    watch_list = build_watch_list(triage_report)
    hot_watchlist, step = timed_step("hot_watchlist", lambda: build_hot_watchlist(db_path=db_path, limit=hot_limit))
    steps.append(step)
    if hot_watchlist is None:
        hot_watchlist = []

    report = {
        "schema_version": DAILY_REVIEW_SCHEMA_VERSION,
        "kind": "daily_review",
        "generated_at": utc_now(),
        "db_path": str(db_path),
        "cutoff": cutoff_info,
        "limit": limit,
        "options": {
            "codex_review": codex_review,
            "deep_dive_watch_now": deep_dive_watch_now,
            "refresh_sources": refresh_sources,
            "ingest_recent": ingest_recent,
            "refresh_hot": refresh_hot,
            "hot_limit": hot_limit,
        },
        "feed_quality": feed_quality,
        "triage": triage_report,
        "watch_list": watch_list,
        "context_review_metrics": context_review_metrics(triage_report),
        "hot_watchlist": hot_watchlist,
        "deep_dives": deep_dives,
        "commands": commands,
        "steps": steps,
        "elapsed_seconds": round(sum(float(step["elapsed_seconds"]) for step in steps), 3),
    }
    report["screen_lines"] = _render_summary_lines(report)

    if save:
        path, step = timed_step("save_report", lambda: save_report(report, report_dir=report_dir))
        steps.append(step)
        if path is not None:
            report["report_path"] = str(path)
            report["screen_lines"] = _render_summary_lines(report)
        report["elapsed_seconds"] = round(sum(float(item["elapsed_seconds"]) for item in steps), 3)
    return report


def _compact(value: Any, limit: int = 160) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _fmt_number(value: Any, digits: int = 4) -> str:
    if value is None or value == "":
        return ""
    try:
        return f"{float(value):.{digits}f}"
    except (TypeError, ValueError):
        return str(value)


def _fmt_bool(value: Any) -> str:
    return "yes" if bool(value) else "no"


def _print_str_list(label: str, values: list[Any], indent: str = "  ") -> None:
    if not values:
        return
    print(f"{indent}{label}:")
    for value in values:
        print(f"{indent}- {value}")


def _render_watch_list_lines(rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"watch_list: count={len(rows)}"]
    if not rows:
        lines.append("- none")
        return lines
    for item in rows:
        signals = ",".join(item.get("signals") or []) or "-"
        lines.append(
            f"- {item['vuln_id']} "
            f"category={item.get('category', '')} "
            f"tier={item.get('tier', '')} "
            f"confidence={item.get('confidence', '')} "
            f"locked={_fmt_bool(item.get('watch_now_locked'))} "
            f"score={_fmt_number(item.get('score'), 2)} "
            f"cvss={_fmt_number(item.get('cvss'), 1)} "
            f"epss={_fmt_number(item.get('epss'), 5)} "
            f"signals={signals} "
            f"source={item.get('source') or ''} "
            f"published={item.get('published_at') or ''} "
            f"first_seen={item.get('first_seen_at') or ''}"
        )
        if item.get("title"):
            lines.append(f"  title: {_compact(item.get('title'))}")
        lines.append(f"  reason: {_compact(item.get('reason'), 220)}")
        review = item.get("context_review") or {}
        if review:
            lines.append(
                "  context_review: "
                f"decision={review.get('decision') or ''} "
                f"confidence={review.get('confidence') or ''} "
                f"reason={_compact(review.get('reason'), 220)}"
            )
    return lines


def _render_hot_section_lines(rows: list[dict[str, Any]]) -> list[str]:
    lines = [f"hot_list: count={len(rows)}"]
    if not rows:
        lines.append("- none")
        return lines
    for item in rows:
        evidence_types = ",".join(item.get("evidence_types") or []) or "-"
        source_types = ",".join(item.get("source_types") or []) or "-"
        urls = [str(url) for url in (item.get("urls") or []) if url]
        lines.append(
            f"- {item['vuln_id']} "
            f"hot={_fmt_number(item.get('hot_score'), 2)} "
            f"signal={_fmt_number(item.get('signal_score'), 2)} "
            f"cvss={_fmt_number(item.get('cvss_score'), 1)} "
            f"epss={_fmt_number(item.get('epss_score'), 5)} "
            f"kev={_fmt_bool(item.get('kev_present'))} "
            f"exploit={_fmt_bool(item.get('exploit_present'))} "
            f"severity={item.get('severity') or ''} "
            f"observed={item.get('observed_at') or ''} "
            f"published={item.get('published_at') or ''} "
            f"first_seen={item.get('first_seen_at') or ''} "
            f"evidence={evidence_types} "
            f"source_types={source_types} "
            f"evidence_count={item.get('evidence_count') or 0} "
            f"sources={item.get('independent_sources') or 0} "
            f"results={item.get('result_count') or 0}"
        )
        if item.get("title"):
            lines.append(f"  title: {_compact(item.get('title'))}")
        if item.get("headline"):
            lines.append(f"  headline: {_compact(item.get('headline'))}")
        if urls:
            lines.append("  urls:")
            for url in urls:
                lines.append(f"  - {url}")
        evidence_details = [value for value in (item.get("evidence_details") or []) if isinstance(value, dict)]
        if evidence_details:
            lines.append("  evidence_details:")
            for evidence in evidence_details:
                lines.append(
                    "  - "
                    f"type={evidence.get('evidence_type') or ''} "
                    f"source={evidence.get('source_type') or ''} "
                    f"weight={_fmt_number(evidence.get('weight'), 2)} "
                    f"domain={evidence.get('domain') or ''} "
                    f"title={_compact(evidence.get('title'), 120)}"
                )
                if evidence.get("url"):
                    lines.append(f"    url: {evidence.get('url')}")
    return lines


def _render_summary_lines(report: dict[str, Any]) -> list[str]:
    lines = []
    summary = report["triage"]["summary"]
    lines.append(f"cutoff: {report['cutoff']['cutoff']} ({report['cutoff']['strategy']})")
    lines.append(f"elapsed_seconds: {report['elapsed_seconds']}")
    lines.append(
        "triage: "
        f"recent={summary['recent_count']} "
        f"watch_now={summary['watch_now_count']} "
        f"monitor_only={summary['monitor_only_count']} "
        f"suppressed={summary['suppressed_count']}"
    )
    if "context_review" in report["triage"]:
        review = report["context_review_metrics"]
        lines.append(
            "context_review: "
            f"reviewed={review.get('reviewed_count', 0)} "
            f"suppressed={review.get('suppressed_count', 0)} "
            f"status={review.get('status', 'ok')}"
        )
    lines.extend(_render_watch_list_lines(report.get("watch_list") or build_watch_list(report["triage"])))
    lines.extend(_render_hot_section_lines(report.get("hot_watchlist", [])))
    if report.get("report_path"):
        lines.append(f"report_path: {report['report_path']}")
    return lines


def _print_summary(report: dict[str, Any]) -> None:
    for line in report.get("screen_lines") or _render_summary_lines(report):
        print(line)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the normal local vulnerability review workflow.")
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    parser.add_argument("--limit", type=int, default=40)
    parser.add_argument("--cutoff")
    parser.add_argument("--cutoff-feed", default="cve_program")
    parser.add_argument("--fallback-hours", type=int, default=24)
    parser.add_argument("--codex-review", action="store_true")
    parser.add_argument("--codex-review-cmd", default=DEFAULT_CODEX_REVIEW_CMD)
    parser.add_argument("--codex-review-timeout", type=int, default=360)
    parser.add_argument("--deep-dive-watch-now", action="store_true")
    parser.add_argument("--refresh-sources", action="store_true")
    parser.add_argument("--ingest-recent", action="store_true")
    parser.add_argument("--refresh-hot", action="store_true")
    parser.add_argument(
        "--daily",
        action="store_true",
        help="Run the full daily ops flow: refresh sources, ingest recent feeds, refresh hot, review, and deep-dive watch_now.",
    )
    parser.add_argument("--no-codex-review", action="store_true", help="Disable Codex context review when using --daily.")
    parser.add_argument("--no-deep-dive-watch-now", action="store_true", help="Disable watch_now deep dives when using --daily.")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument(
        "--hot-limit",
        type=int,
        default=DEFAULT_HOT_LIMIT,
        help="Limit hot rows in the saved report and summary. Default is all current hot rows; 0 also means all.",
    )
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    refresh_sources = args.refresh_sources or args.daily
    ingest_recent = args.ingest_recent or args.daily
    refresh_hot = args.refresh_hot or args.daily
    codex_review = (args.codex_review or args.daily) and not args.no_codex_review
    deep_dive_watch_now = (args.deep_dive_watch_now or args.daily) and not args.no_deep_dive_watch_now

    report = build_daily_review(
        db_path=args.db_path,
        limit=args.limit,
        cutoff=args.cutoff,
        cutoff_feed=args.cutoff_feed,
        fallback_hours=args.fallback_hours,
        codex_review=codex_review,
        codex_review_cmd=args.codex_review_cmd,
        codex_review_timeout=args.codex_review_timeout,
        deep_dive_watch_now=deep_dive_watch_now,
        refresh_sources=refresh_sources,
        ingest_recent=ingest_recent,
        refresh_hot=refresh_hot,
        hot_limit=args.hot_limit,
        save=not args.no_save,
        report_dir=args.report_dir,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        _print_summary(report)


if __name__ == "__main__":
    main()
