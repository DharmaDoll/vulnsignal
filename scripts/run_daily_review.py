#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
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


DAILY_REVIEW_SCHEMA_VERSION = 1
DEFAULT_REPORT_DIR = ROOT / "data" / "reports" / "triage"
DEFAULT_CODEX_REVIEW_CMD = "python3 scripts/codex_triage_review.py --timeout 300"


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


def run_command(command: list[str]) -> dict[str, Any]:
    completed = subprocess.run(command, text=True, capture_output=True, check=False, cwd=ROOT)
    return {
        "command": command,
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
    refresh_hot: bool = False,
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
        for item in triage_report.get("watch_now", []):
            vuln_id = item["vuln_id"]
            deep_report, step = timed_step(
                f"deep_dive:{vuln_id}",
                lambda vuln_id=vuln_id: deep_dive.build_report(vuln_id=vuln_id, db_path=db_path),
            )
            steps.append(step)
            if deep_report is not None:
                deep_dives[vuln_id] = deep_report

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
            "refresh_hot": refresh_hot,
        },
        "feed_quality": feed_quality,
        "triage": triage_report,
        "context_review_metrics": context_review_metrics(triage_report),
        "deep_dives": deep_dives,
        "commands": commands,
        "steps": steps,
        "elapsed_seconds": round(sum(float(step["elapsed_seconds"]) for step in steps), 3),
    }

    if save:
        path, step = timed_step("save_report", lambda: save_report(report, report_dir=report_dir))
        steps.append(step)
        if path is not None:
            report["report_path"] = str(path)
        report["elapsed_seconds"] = round(sum(float(item["elapsed_seconds"]) for item in steps), 3)
    return report


def _print_summary(report: dict[str, Any]) -> None:
    summary = report["triage"]["summary"]
    print(f"cutoff: {report['cutoff']['cutoff']} ({report['cutoff']['strategy']})")
    print(f"elapsed_seconds: {report['elapsed_seconds']}")
    print(
        "triage: "
        f"recent={summary['recent_count']} "
        f"watch_now={summary['watch_now_count']} "
        f"monitor_only={summary['monitor_only_count']} "
        f"suppressed={summary['suppressed_count']}"
    )
    if "context_review" in report["triage"]:
        review = report["context_review_metrics"]
        print(
            "context_review: "
            f"reviewed={review.get('reviewed_count', 0)} "
            f"suppressed={review.get('suppressed_count', 0)} "
            f"status={review.get('status', 'ok')}"
        )
    print("watch_now:")
    for item in report["triage"].get("watch_now", []):
        print(f"- {item['vuln_id']} cvss={item.get('cvss')} epss={item.get('epss')} reason={item.get('reason')}")
    print("monitor_only:")
    for item in report["triage"].get("monitor_only", [])[:10]:
        print(f"- {item['vuln_id']} cvss={item.get('cvss')} epss={item.get('epss')} reason={item.get('reason')}")
    if report.get("report_path"):
        print(f"report_path: {report['report_path']}")


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
    parser.add_argument("--refresh-hot", action="store_true")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = build_daily_review(
        db_path=args.db_path,
        limit=args.limit,
        cutoff=args.cutoff,
        cutoff_feed=args.cutoff_feed,
        fallback_hours=args.fallback_hours,
        codex_review=args.codex_review,
        codex_review_cmd=args.codex_review_cmd,
        codex_review_timeout=args.codex_review_timeout,
        deep_dive_watch_now=args.deep_dive_watch_now,
        refresh_sources=args.refresh_sources,
        refresh_hot=args.refresh_hot,
        save=not args.no_save,
        report_dir=args.report_dir,
    )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        _print_summary(report)


if __name__ == "__main__":
    main()
