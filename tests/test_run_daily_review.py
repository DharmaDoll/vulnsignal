from __future__ import annotations

import importlib.util
import json
import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


def _load_daily_review_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "run_daily_review.py"
    spec = importlib.util.spec_from_file_location("run_daily_review_script", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load scripts/run_daily_review.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _init_fetch_log(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE fetch_log (
              id INTEGER PRIMARY KEY,
              feed TEXT NOT NULL,
              attempted_at TEXT NOT NULL,
              status TEXT NOT NULL,
              error_msg TEXT,
              rows_affected INTEGER,
              cache_used INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        conn.executemany(
            """
            INSERT INTO fetch_log (feed, attempted_at, status, rows_affected, cache_used)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("cve_program", "2026-06-29T00:00:00+00:00", "ok", 10, 0),
                ("cve_program", "2026-06-30T00:00:00+00:00", "ok", 20, 0),
                ("cve_program", "2026-06-30T01:00:00+00:00", "error", 0, 1),
            ],
        )
        conn.commit()
    finally:
        conn.close()


class DailyReviewWorkflowTests(TestCase):
    def test_determine_cutoff_uses_previous_successful_fetch(self) -> None:
        module = _load_daily_review_module()
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            _init_fetch_log(db_path)

            cutoff = module.determine_cutoff(db_path=db_path)

        self.assertEqual("previous_success", cutoff["strategy"])
        self.assertEqual("2026-06-29T00:00:00+00:00", cutoff["cutoff"])
        self.assertEqual("2026-06-30T00:00:00+00:00", cutoff["latest_success_at"])

    def test_save_report_writes_versioned_json(self) -> None:
        module = _load_daily_review_module()
        report = {
            "schema_version": 1,
            "kind": "daily_review",
            "generated_at": "2026-06-30T12:34:56+00:00",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = module.save_report(report, report_dir=Path(tmp))
            saved = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual("2026-06-30T123456Z.json", path.name)
        self.assertEqual(report, saved)

    def test_build_daily_review_runs_triage_and_deep_dive_for_watch_now(self) -> None:
        module = _load_daily_review_module()
        triage_report = {
            "summary": {
                "recent_count": 2,
                "candidate_count": 2,
                "watch_now_count": 1,
                "monitor_only_count": 1,
                "suppressed_count": 0,
            },
            "watch_now": [{"vuln_id": "CVE-2026-0001", "reason": "exploit"}],
            "monitor_only": [{"vuln_id": "CVE-2026-0002", "reason": "critical CVSS"}],
            "context_review": {
                "enabled": True,
                "reviewed_count": 1,
                "suppressed_count": 0,
            },
        }
        deep_report = {"kind": "deep_dive", "vuln_id": "CVE-2026-0001"}

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            with (
                patch.object(module, "migrate", return_value=None) as migrate_mock,
                patch.object(module, "summarize_feed_quality", return_value=[{"feed": "cve_program"}]),
                patch.object(module, "utc_now", return_value="2026-06-30T12:00:00+00:00"),
                patch.object(module.triage_new_cves, "build_report", return_value=triage_report) as triage_mock,
                patch.object(module.deep_dive, "build_report", return_value=deep_report) as deep_mock,
            ):
                report = module.build_daily_review(
                    db_path=db_path,
                    cutoff="2026-06-29T00:00:00+00:00",
                    deep_dive_watch_now=True,
                    save=False,
                )

        migrate_mock.assert_called_once_with(db_path)
        triage_mock.assert_called_once()
        deep_mock.assert_called_once_with(vuln_id="CVE-2026-0001", db_path=db_path)
        self.assertEqual("daily_review", report["kind"])
        self.assertEqual("explicit", report["cutoff"]["strategy"])
        self.assertEqual(triage_report, report["triage"])
        self.assertEqual(
            {
                "enabled": True,
                "status": "ok",
                "reviewed_count": 1,
                "suppressed_count": 0,
                "decisions": {},
                "kept_after_review_count": 0,
            },
            report["context_review_metrics"],
        )
        self.assertEqual(deep_report, report["deep_dives"]["CVE-2026-0001"])
        self.assertEqual(
            ["migrate", "feed_quality", "triage", "deep_dive:CVE-2026-0001"],
            [step["name"] for step in report["steps"]],
        )
