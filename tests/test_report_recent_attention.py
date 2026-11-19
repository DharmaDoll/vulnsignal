from __future__ import annotations

import importlib.util
import io
import json
import sqlite3
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


def _load_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "report_recent_attention.py"
    spec = importlib.util.spec_from_file_location("report_recent_attention_script", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load scripts/report_recent_attention.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _init_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE vulnerabilities (
              vuln_id TEXT PRIMARY KEY,
              source TEXT,
              title TEXT,
              summary TEXT,
              severity TEXT,
              cvss_score REAL,
              published_at TEXT,
              first_seen_at TEXT,
              updated_at TEXT
            );
            CREATE TABLE epss_current (
              vuln_id TEXT PRIMARY KEY,
              epss REAL NOT NULL,
              percentile REAL,
              score_date TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE signals (
              id INTEGER PRIMARY KEY,
              vuln_id TEXT NOT NULL,
              signal_type TEXT NOT NULL,
              provider TEXT NOT NULL,
              score REAL,
              value_json TEXT,
              observed_at TEXT NOT NULL
            );
            CREATE TABLE fetch_log (
              id INTEGER PRIMARY KEY,
              feed TEXT NOT NULL,
              attempted_at TEXT NOT NULL,
              status TEXT NOT NULL,
              error_msg TEXT,
              rows_affected INTEGER,
              cache_used INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        conn.executemany(
            """
            INSERT INTO vulnerabilities (
              vuln_id, source, title, summary, severity, cvss_score,
              published_at, first_seen_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "CVE-2026-0001",
                    "cve_program",
                    "Important RCE",
                    "",
                    "CRITICAL",
                    9.8,
                    "2026-07-15T00:00:00+00:00",
                    "2026-07-15T01:00:00+00:00",
                    "2026-07-15T01:00:00+00:00",
                ),
                (
                    "CVE-2026-0002",
                    "cve_program",
                    "Hot Example",
                    "",
                    "HIGH",
                    8.8,
                    "2026-07-14T00:00:00+00:00",
                    "2026-07-14T01:00:00+00:00",
                    "2026-07-14T01:00:00+00:00",
                ),
                (
                    "CVE-2026-0003",
                    "cve_program",
                    "Old Hot Example",
                    "",
                    "HIGH",
                    8.8,
                    "2026-06-01T00:00:00+00:00",
                    "2026-06-01T01:00:00+00:00",
                    "2026-06-01T01:00:00+00:00",
                ),
            ],
        )
        conn.executemany(
            """
            INSERT INTO epss_current (vuln_id, epss, percentile, score_date, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("CVE-2026-0001", 0.12, 0.9, "2026-07-16", "2026-07-16T00:00:00+00:00"),
                ("CVE-2026-0002", 0.34, 0.95, "2026-07-16", "2026-07-16T00:00:00+00:00"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO signals (vuln_id, signal_type, provider, score, value_json, observed_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    "CVE-2026-0002",
                    "hot",
                    "Web Hot Intel",
                    0.8,
                    json.dumps(
                        {
                            "evidence_types": ["public_poc"],
                            "source_types": ["search"],
                            "independent_sources": 2,
                            "urls": ["https://example.test/poc"],
                            "evidence_details": [
                                {
                                    "evidence_type": "public_poc",
                                    "source_type": "search",
                                    "weight": 0.75,
                                    "domain": "example.test",
                                    "url": "https://example.test/poc",
                                    "title": "Public PoC for CVE-2026-0002",
                                }
                            ],
                        }
                    ),
                    "2026-07-16T02:00:00+00:00",
                ),
                (
                    "CVE-2026-0003",
                    "hot",
                    "Web Hot Intel",
                    0.9,
                    json.dumps({"evidence_types": ["active_exploitation"], "evidence_details": []}),
                    "2026-07-01T02:00:00+00:00",
                ),
            ],
        )
        conn.execute(
            """
            INSERT INTO fetch_log (feed, attempted_at, status, rows_affected, cache_used)
            VALUES ('cve_program', '2026-07-16T03:00:00+00:00', 'ok', 10, 0)
            """
        )
        conn.commit()
    finally:
        conn.close()


class RecentAttentionReportTests(TestCase):
    def test_build_report_uses_pinned_window_and_date_columns(self) -> None:
        module = _load_module()
        triage_report = {
            "summary": {
                "recent_count": 3,
                "candidate_count": 1,
                "watch_now_count": 1,
                "monitor_only_count": 0,
                "suppressed_count": 2,
            },
            "watch_now": [
                {
                    "vuln_id": "CVE-2026-0001",
                    "title": "Important RCE",
                    "source": "cve_program",
                    "published_at": "2026-07-15T00:00:00+00:00",
                    "first_seen_at": "2026-07-15T01:00:00+00:00",
                    "cvss": 9.8,
                    "epss": 0.12,
                    "signals": ["exploit"],
                    "tier": "P1",
                    "reason": "exploit",
                    "confidence": "high",
                    "score": 49.6,
                }
            ],
            "monitor_only": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            _init_db(db_path)
            with (
                patch.object(module, "migrate", return_value=None),
                patch.object(module.triage_new_cves, "build_report", return_value=triage_report) as triage_mock,
                patch.object(module, "utc_now", return_value="2026-07-17T00:00:00+00:00"),
            ):
                report = module.build_report(
                    db_path=db_path,
                    as_of="2026-07-17T00:00:00+00:00",
                    days=7,
                    limit=30,
                    hot_limit=20,
                )

        triage_mock.assert_called_once()
        self.assertEqual("2026-07-10T00:00:00+00:00", report["cutoff"])
        self.assertEqual("2026-07-17T00:00:00+00:00", report["as_of"])
        self.assertEqual("2026-07-15", report["watch_now"][0]["published_date"])
        self.assertEqual("2026-07-15", report["watch_now"][0]["first_seen_date"])
        self.assertEqual(0.12, report["watch_now"][0]["epss"])
        self.assertEqual(["CVE-2026-0002"], [item["vuln_id"] for item in report["hot"]])
        self.assertEqual("2026-07-16", report["hot"][0]["observed_date"])
        self.assertEqual(0.34, report["hot"][0]["epss"])
        self.assertEqual("2026-07-16T03:00:00+00:00", report["feed_watermarks"]["cve_program"]["attempted_at"])

    def test_print_report_includes_date_headers(self) -> None:
        module = _load_module()
        report = {
            "cutoff": "2026-07-10T00:00:00+00:00",
            "as_of": "2026-07-17T00:00:00+00:00",
            "triage_summary": {"recent_count": 1},
            "watch_now": [
                {
                    "published_date": "2026-07-15",
                    "first_seen_date": "2026-07-15",
                    "vuln_id": "CVE-2026-0001",
                    "reason": "exploit",
                    "cvss": 9.8,
                    "epss": 0.12,
                    "signals": ["exploit"],
                    "title": "Important RCE",
                }
            ],
            "hot": [
                {
                    "observed_date": "2026-07-16",
                    "published_date": "2026-07-14",
                    "first_seen_date": "2026-07-14",
                    "vuln_id": "CVE-2026-0002",
                    "hot_score": 0.8,
                    "cvss": 8.8,
                    "epss": 0.34,
                    "kev": False,
                    "exploit": True,
                    "evidence_types": ["public_poc"],
                    "title": "Hot Example",
                }
            ],
        }
        output = io.StringIO()
        with redirect_stdout(output):
            module.print_report(report)

        text = output.getvalue()
        self.assertIn("| published | first_seen | vuln_id |", text)
        self.assertIn("| observed | published | first_seen | vuln_id |", text)
        self.assertIn("2026-07-15", text)
        self.assertIn("2026-07-16", text)
