from __future__ import annotations

import importlib.util
import io
import json
import sqlite3
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import call, patch


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
                patch.object(module, "build_hot_watchlist", return_value=[{"vuln_id": "CVE-2026-0003"}]),
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
            [
                {"category": "watch_now", "vuln_id": "CVE-2026-0001", "reason": "exploit"},
                {"category": "monitor_only", "vuln_id": "CVE-2026-0002", "reason": "critical CVSS"},
            ],
            report["watch_list"],
        )
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
            [step["name"] for step in report["steps"][:-1]],
        )
        self.assertEqual("hot_watchlist", report["steps"][-1]["name"])
        self.assertEqual([{"vuln_id": "CVE-2026-0003"}], report["hot_watchlist"])

    def test_build_daily_review_prioritizes_locked_watch_now_first(self) -> None:
        module = _load_daily_review_module()
        triage_report = {
            "summary": {
                "recent_count": 2,
                "candidate_count": 2,
                "watch_now_count": 2,
                "monitor_only_count": 0,
                "suppressed_count": 0,
            },
            "watch_now": [
                {
                    "vuln_id": "CVE-2026-1002",
                    "reason": "high EPSS",
                    "watch_now_locked": False,
                },
                {
                    "vuln_id": "CVE-2026-1001",
                    "reason": "broad internet-facing auth/API issue",
                    "watch_now_locked": True,
                },
            ],
            "monitor_only": [],
        }
        deep_report = {"kind": "deep_dive", "vuln_id": "CVE-2026-1001"}

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            with (
                patch.object(module, "migrate", return_value=None),
                patch.object(module, "summarize_feed_quality", return_value=[{"feed": "cve_program"}]),
                patch.object(module, "utc_now", return_value="2026-06-30T12:00:00+00:00"),
                patch.object(module.triage_new_cves, "build_report", return_value=triage_report),
                patch.object(module.deep_dive, "build_report", return_value=deep_report) as deep_mock,
                patch.object(module, "build_hot_watchlist", return_value=[]),
            ):
                report = module.build_daily_review(
                    db_path=db_path,
                    cutoff="2026-06-29T00:00:00+00:00",
                    deep_dive_watch_now=True,
                    save=False,
                )

        self.assertEqual("CVE-2026-1001", report["watch_list"][0]["vuln_id"])
        self.assertEqual("CVE-2026-1002", report["watch_list"][1]["vuln_id"])
        self.assertEqual(
            ["CVE-2026-1001", "CVE-2026-1002"],
            [call.kwargs["vuln_id"] for call in deep_mock.call_args_list],
        )

    def test_build_daily_review_can_run_full_daily_source_steps(self) -> None:
        module = _load_daily_review_module()
        triage_report = {
            "summary": {
                "recent_count": 0,
                "candidate_count": 0,
                "watch_now_count": 0,
                "monitor_only_count": 0,
                "suppressed_count": 0,
            },
            "watch_now": [],
            "monitor_only": [],
        }

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            with (
                patch.object(module, "migrate", return_value=None),
                patch.object(module, "summarize_feed_quality", return_value=[{"feed": "cve_program"}]),
                patch.object(module, "utc_now", return_value="2026-06-30T12:00:00+00:00"),
                patch.object(module.triage_new_cves, "build_report", return_value=triage_report),
                patch.object(module, "run_command", return_value={"returncode": 0}) as run_command_mock,
                patch.object(module, "build_hot_watchlist", return_value=[]),
            ):
                report = module.build_daily_review(
                    db_path=db_path,
                    cutoff="2026-06-29T00:00:00+00:00",
                    refresh_sources=True,
                    ingest_recent=True,
                    refresh_hot=True,
                    save=False,
                )

        run_command_mock.assert_has_calls(
            [
                call([str(module.ROOT / "scripts" / "refresh_all_sources.sh")]),
                call([str(module.ROOT / "scripts" / "ingest_recent_core_db.sh")], env={"SKIP_MIRROR_REFRESH": "1"}),
                call([module.sys.executable, "-m", "sync.fetch_hot"]),
            ]
        )
        self.assertEqual(
            ["migrate", "refresh_sources", "ingest_recent", "refresh_hot", "feed_quality", "triage", "hot_watchlist"],
            [step["name"] for step in report["steps"]],
        )
        self.assertTrue(report["options"]["refresh_sources"])
        self.assertTrue(report["options"]["ingest_recent"])
        self.assertTrue(report["options"]["refresh_hot"])

    def test_build_daily_review_emits_screen_lines_in_report(self) -> None:
        module = _load_daily_review_module()
        triage_report = {
            "summary": {
                "recent_count": 1,
                "candidate_count": 1,
                "watch_now_count": 1,
                "monitor_only_count": 0,
                "suppressed_count": 0,
            },
            "watch_now": [
                {
                    "vuln_id": "CVE-2026-0001",
                    "tier": "P1",
                    "confidence": "medium",
                    "watch_now_locked": True,
                    "score": 37.2,
                    "cvss": 9.3,
                    "epss": 0.0,
                    "signals": [],
                    "source": "cve_program",
                    "published_at": "2026-07-20T19:18:09.685Z",
                    "first_seen_at": "2026-07-20T19:18:09.685Z",
                    "title": "Example",
                    "reason": "broad internet-facing auth/API issue",
                }
            ],
            "monitor_only": [],
        }
        hot_rows = [
            {
                "vuln_id": "CVE-2026-0002",
                "hot_score": 0.88,
                "signal_score": 0.86,
                "cvss_score": 9.8,
                "epss_score": 0.2,
                "kev_present": False,
                "exploit_present": True,
                "severity": "CRITICAL",
                "observed_at": "2026-07-20T00:00:00+00:00",
                "published_at": "2026-07-19T00:00:00+00:00",
                "first_seen_at": "2026-07-19T00:00:00+00:00",
                "evidence_types": ["public_poc"],
                "source_types": ["search"],
                "evidence_count": 1,
                "independent_sources": 2,
                "result_count": 3,
                "title": "Hot Example",
                "headline": "PoC released",
                "urls": ["https://example.test/poc"],
                "evidence_details": [],
            }
        ]

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            with (
                patch.object(module, "migrate", return_value=None),
                patch.object(module, "summarize_feed_quality", return_value=[{"feed": "cve_program"}]),
                patch.object(module, "utc_now", return_value="2026-07-20T12:00:00+00:00"),
                patch.object(module.triage_new_cves, "build_report", return_value=triage_report),
                patch.object(module, "build_hot_watchlist", return_value=hot_rows),
            ):
                report = module.build_daily_review(
                    db_path=db_path,
                    cutoff="2026-07-19T00:00:00+00:00",
                    save=False,
                )

        self.assertEqual(report["screen_lines"], module._render_summary_lines(report))
        self.assertIn("locked=yes", "\n".join(report["screen_lines"]))
        self.assertIn("hot_list: count=1", report["screen_lines"])

    def test_print_summary_includes_watchlists_and_hot(self) -> None:
        module = _load_daily_review_module()
        report = {
            "cutoff": {"cutoff": "2026-06-29T00:00:00+00:00", "strategy": "previous_success"},
            "elapsed_seconds": 1.23,
            "triage": {
                "summary": {
                    "recent_count": 14,
                    "watch_now_count": 1,
                    "monitor_only_count": 1,
                    "suppressed_count": 1,
                },
                "context_review": {"enabled": True},
                "watch_now": [
                    {
                        "vuln_id": "CVE-2026-0001",
                        "tier": "P1",
                        "cvss": 9.8,
                        "epss": 0.12,
                        "signals": ["exploit"],
                        "published_at": "2026-06-29T00:00:00+00:00",
                        "first_seen_at": "2026-06-29T00:00:00+00:00",
                        "title": "Example RCE",
                        "reason": "exploit",
                    }
                ],
                "monitor_only": [
                    {
                        "vuln_id": "CVE-2026-0002",
                        "tier": "P2",
                        "confidence": "low",
                        "score": 36.0,
                        "cvss": 9.0,
                        "epss": 0.001,
                        "signals": [],
                        "source": "cve_program",
                        "published_at": "2026-06-29T00:00:00+00:00",
                        "first_seen_at": "2026-06-29T00:00:00+00:00",
                        "title": "Monitor Example",
                        "reason": "high CVSS",
                    }
                ],
            },
            "context_review_metrics": {"reviewed_count": 1, "suppressed_count": 1, "status": "ok"},
            "hot_watchlist": [
                {
                    "vuln_id": "CVE-2026-0004",
                    "hot_score": 0.88,
                    "signal_score": 0.86,
                    "cvss_score": 9.8,
                    "epss_score": 0.2,
                    "kev_present": False,
                    "exploit_present": True,
                    "severity": "CRITICAL",
                    "observed_at": "2026-06-30T00:00:00+00:00",
                    "published_at": "2026-06-29T00:00:00+00:00",
                    "first_seen_at": "2026-06-29T00:00:00+00:00",
                    "evidence_types": ["public_poc"],
                    "source_types": ["search"],
                    "evidence_count": 1,
                    "independent_sources": 2,
                    "result_count": 3,
                    "title": "Hot Example",
                    "headline": "PoC released",
                    "urls": ["https://example.test/poc"],
                    "evidence_details": [
                        {
                            "evidence_type": "public_poc",
                            "source_type": "search",
                            "weight": 0.75,
                            "domain": "example.test",
                            "title": "PoC released",
                            "url": "https://example.test/poc",
                        }
                    ],
                }
            ]
            + [
                {
                    "vuln_id": f"CVE-2026-{index:04d}",
                    "hot_score": 0.5,
                    "observed_at": "2026-06-30T00:00:00+00:00",
                }
                for index in range(5, 17)
            ],
        }
        output = io.StringIO()
        with redirect_stdout(output):
            module._print_summary(report)

        self.assertEqual(module._render_summary_lines(report), output.getvalue().splitlines())
