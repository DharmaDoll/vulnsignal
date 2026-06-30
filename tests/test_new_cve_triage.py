from __future__ import annotations

import importlib.util
import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


def _load_triage_module():
    module_path = Path(__file__).resolve().parents[1] / "scripts" / "triage_new_cves.py"
    spec = importlib.util.spec_from_file_location("triage_new_cves_script", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load scripts/triage_new_cves.py")
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
              source TEXT NOT NULL,
              title TEXT,
              summary TEXT,
              severity TEXT,
              cvss_score REAL,
              cvss_source TEXT,
              published_at TEXT,
              first_seen_at TEXT,
              updated_at TEXT
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
            CREATE TABLE epss_current (
              vuln_id TEXT PRIMARY KEY,
              epss REAL,
              percentile REAL,
              score_date TEXT
            );
            """
        )
        rows = [
            ("CVE-2026-0001", "cve_program", "Critical exploited app", "", "CRITICAL", 9.8, "2026-06-28T00:00:00Z", "2026-06-28T00:00:00Z"),
            ("CVE-2026-0002", "cve_program", "Hot only library", "", "HIGH", 7.5, "2026-06-28T01:00:00Z", "2026-06-28T01:00:00Z"),
            ("CVE-2026-0003", "cve_program", "Plain recent low", "", "LOW", 4.3, "2026-06-28T02:00:00Z", "2026-06-28T02:00:00Z"),
            ("CVE-2026-0004", "cve_program", "High EPSS service", "", "HIGH", 8.0, "2026-06-28T03:00:00Z", "2026-06-28T03:00:00Z"),
        ]
        conn.executemany(
            """
            INSERT INTO vulnerabilities (
              vuln_id, source, title, summary, severity, cvss_score, published_at, first_seen_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        conn.executemany(
            """
            INSERT INTO signals (vuln_id, signal_type, provider, score, value_json, observed_at)
            VALUES (?, ?, ?, ?, '{}', ?)
            """,
            [
                ("CVE-2026-0001", "exploit", "go-exploitdb", 1.0, "2026-06-28T00:10:00Z"),
                ("CVE-2026-0001", "kev", "cisa", 1.0, "2026-06-28T00:11:00Z"),
                ("CVE-2026-0002", "hot", "hot-intel", 0.72, "2026-06-28T01:10:00Z"),
            ],
        )
        conn.executemany(
            "INSERT INTO epss_current (vuln_id, epss, percentile, score_date) VALUES (?, ?, ?, ?)",
            [
                ("CVE-2026-0001", 0.8, 0.99, "2026-06-28"),
                ("CVE-2026-0002", 0.01, 0.2, "2026-06-28"),
                ("CVE-2026-0004", 0.2, 0.8, "2026-06-28"),
            ],
        )
        conn.commit()
    finally:
        conn.close()


class NewCveTriageContractTests(TestCase):
    def test_build_report_filters_plain_recent_and_emits_contract(self) -> None:
        module = _load_triage_module()
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            _init_db(db_path)
            with (
                patch.object(module, "migrate", return_value=None),
                patch.object(module, "utc_now", return_value="2026-06-28T04:00:00Z"),
            ):
                report = module.build_report("2026-06-28T00:00:00Z", limit=10, db_path=db_path)

        self.assertEqual(1, report["schema_version"])
        self.assertEqual("new_cve_triage", report["kind"])
        self.assertEqual("2026-06-28T00:00:00Z", report["cutoff"])
        self.assertEqual(4, report["summary"]["recent_count"])
        self.assertEqual(3, report["summary"]["candidate_count"])
        self.assertEqual(3, report["summary"]["watch_now_count"])
        self.assertEqual(0, report["summary"]["monitor_only_count"])
        self.assertEqual(1, report["summary"]["suppressed_count"])

        watch_ids = [item["vuln_id"] for item in report["watch_now"]]
        monitor_ids = [item["vuln_id"] for item in report["monitor_only"]]
        self.assertEqual(["CVE-2026-0001", "CVE-2026-0004", "CVE-2026-0002"], watch_ids)
        self.assertEqual([], monitor_ids)
        self.assertEqual(["kev", "exploit"], report["watch_now"][0]["signals"])
        self.assertEqual("P0", report["watch_now"][0]["tier"])
        self.assertEqual("P1", report["watch_now"][1]["tier"])

    def test_cvss_only_candidate_is_monitor_only(self) -> None:
        module = _load_triage_module()
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "core.db"
            _init_db(db_path)
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                      vuln_id, source, title, summary, severity, cvss_score, published_at, first_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "CVE-2026-0005",
                        "cve_program",
                        "Critical CVSS only",
                        "",
                        "CRITICAL",
                        10.0,
                        "2026-06-28T04:00:00Z",
                        "2026-06-28T04:00:00Z",
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            with (
                patch.object(module, "migrate", return_value=None),
                patch.object(module, "utc_now", return_value="2026-06-28T04:00:00Z"),
            ):
                report = module.build_report("2026-06-28T00:00:00Z", limit=10, db_path=db_path)

        monitor_by_id = {item["vuln_id"]: item for item in report["monitor_only"]}
        self.assertIn("CVE-2026-0005", monitor_by_id)
        self.assertEqual("P2", monitor_by_id["CVE-2026-0005"]["tier"])
        self.assertEqual("critical CVSS", monitor_by_id["CVE-2026-0005"]["reason"])

    def test_context_review_can_suppress_cvss_only_candidate(self) -> None:
        module = _load_triage_module()
        report = {
            "summary": {
                "recent_count": 2,
                "candidate_count": 2,
                "watch_now_count": 1,
                "monitor_only_count": 1,
                "suppressed_count": 0,
            },
            "watch_now": [
                {
                    "vuln_id": "CVE-2026-0001",
                    "signals": ["exploit"],
                    "tier": "P1",
                    "reason": "exploit",
                    "confidence": "high",
                }
            ],
            "monitor_only": [
                {
                    "vuln_id": "CVE-2026-0005",
                    "signals": [],
                    "tier": "P2",
                    "reason": "critical CVSS",
                    "confidence": "low",
                }
            ],
            "caveats": [],
        }
        response = {
            "reviews": [
                {
                    "vuln_id": "CVE-2026-0005",
                    "decision": "suppress",
                    "confidence": "low",
                    "reason": "CVSS-only plugin issue without exploit, KEV, hot, or EPSS signal",
                }
            ]
        }

        updated = module._apply_context_reviews(report, response)

        self.assertEqual(1, updated["summary"]["watch_now_count"])
        self.assertEqual(0, updated["summary"]["monitor_only_count"])
        self.assertEqual(1, updated["summary"]["suppressed_count"])
        self.assertEqual([], updated["monitor_only"])

    def test_context_review_cannot_suppress_exploit_candidate(self) -> None:
        module = _load_triage_module()
        report = {
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
                    "signals": ["exploit"],
                    "tier": "P1",
                    "reason": "exploit",
                    "confidence": "high",
                }
            ],
            "monitor_only": [],
            "caveats": [],
        }
        response = {
            "reviews": [
                {
                    "vuln_id": "CVE-2026-0001",
                    "decision": "suppress",
                    "confidence": "low",
                    "reason": "looks noisy",
                }
            ]
        }

        updated = module._apply_context_reviews(report, response)

        self.assertEqual(1, updated["summary"]["watch_now_count"])
        self.assertEqual(0, updated["summary"]["suppressed_count"])
        self.assertEqual("watch_now", updated["watch_now"][0]["context_review"]["decision"])
