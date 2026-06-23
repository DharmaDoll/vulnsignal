from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase

from app import scoring
from app import skills
from db.migrate import migrate
from sync.common import append_signal, utc_now


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


class ScoringTests(TestCase):
    def test_top_risks_uses_latest_signals_and_skips_not_affected_vex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = _connect(core_db)
            try:
                conn.execute(
                    """
                    INSERT INTO assets (asset_id, hostname, os, version, owner, exposed, criticality)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("asset-1", "host-1", "linux", "1", "team-a", 1, "high"),
                )
                conn.execute(
                    """
                    INSERT INTO assets (asset_id, hostname, os, version, owner, exposed, criticality)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("asset-2", "host-2", "linux", "1", "team-b", 0, "low"),
                )
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (vuln_id, source, title, summary, severity, cvss_score, cvss_source, published_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("CVE-2024-0001", "ghsa", "v1", "summary", "HIGH", 8.0, "GHSA", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
                )
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (vuln_id, source, title, summary, severity, cvss_score, cvss_source, published_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("CVE-2024-0002", "ghsa", "v2", "summary", "HIGH", 9.0, "GHSA", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
                )
                conn.execute(
                    """
                    INSERT INTO findings (asset_id, vuln_id, risk_score, scoring_version, status, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    ("asset-1", "CVE-2024-0001", None, "v1", "open", "2026-05-09T00:00:00+00:00"),
                )
                conn.execute(
                    """
                    INSERT INTO findings (asset_id, vuln_id, risk_score, scoring_version, status, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    ("asset-2", "CVE-2024-0002", None, "v1", "open", "2026-05-09T00:00:00+00:00"),
                )
                conn.execute(
                    """
                    INSERT INTO epss_current (vuln_id, epss, percentile, score_date, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("CVE-2024-0001", 0.8, 0.9, "2026-05-08", "2026-05-08T00:00:00+00:00"),
                )
                conn.execute(
                    """
                    INSERT INTO epss_current (vuln_id, epss, percentile, score_date, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("CVE-2024-0002", 0.1, 0.2, "2026-05-08", "2026-05-08T00:00:00+00:00"),
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2024-0001",
                    signal_type="kev",
                    provider="CISA KEV",
                    score=None,
                    value={"date_added": "2024-01-01"},
                    observed_at="2026-05-08T00:00:00+00:00",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2024-0001",
                    signal_type="exploit",
                    provider="go-exploitdb",
                    score=None,
                    value={"exploit_type": "poc", "url": "https://example.invalid/exploit"},
                    observed_at="2026-05-08T00:00:00+00:00",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2024-0001",
                    signal_type="vex",
                    provider="VEX",
                    score=None,
                    value={"status": "not_affected", "justification": "older assertion"},
                    observed_at="2026-05-08T00:00:00+00:00",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2024-0001",
                    signal_type="vex",
                    provider="VEX",
                    score=None,
                    value={"status": "affected", "justification": "newer assertion"},
                    observed_at="2026-05-09T00:00:00+00:00",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2024-0002",
                    signal_type="vex",
                    provider="VEX",
                    score=None,
                    value={"status": "not_affected", "justification": "suppressed"},
                    observed_at="2026-05-09T00:00:00+00:00",
                )
                conn.commit()

                ranked = scoring.top_risks(conn, limit=10)
                patch_queue = scoring.recommend_patch_queue(conn, limit=10)
                finding = scoring.score_vulnerability(conn, conn.execute(
                    "SELECT * FROM vulnerabilities WHERE vuln_id = ?",
                    ("CVE-2024-0001",),
                ).fetchone(), conn.execute("SELECT * FROM assets WHERE asset_id = ?", ("asset-1",)).fetchone())
            finally:
                conn.close()

            self.assertEqual(1, len(ranked))
            self.assertEqual("CVE-2024-0001", ranked[0]["vuln_id"])
            self.assertEqual("asset-1", ranked[0]["asset_id"])
            self.assertTrue(ranked[0]["kev_present"])
            self.assertTrue(ranked[0]["exploit_present"])
            self.assertFalse(ranked[0]["vex_suppressed"])
            self.assertGreaterEqual(ranked[0]["risk_score"], 80)
            self.assertEqual(1, len(patch_queue))
            self.assertEqual("CVE-2024-0001", patch_queue[0]["vuln_id"])
            self.assertTrue(finding.kev_present)
            self.assertFalse(finding.vex_suppressed)

    def test_find_vuln_has_exploit_and_data_freshness(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = _connect(core_db)
            try:
                fresh_at = utc_now()
                conn.execute(
                    """
                    INSERT INTO assets (asset_id, hostname, os, version, owner, exposed, criticality)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("asset-9", "host-9", "linux", "1", "team-z", 1, "high"),
                )
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (vuln_id, source, title, summary, severity, cvss_score, cvss_source, published_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("CVE-2024-9999", "ghsa", "sample", "summary", "MEDIUM", 5.0, "GHSA", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
                )
                conn.execute(
                    """
                    INSERT INTO findings (asset_id, vuln_id, risk_score, scoring_version, status, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    ("asset-9", "CVE-2024-9999", None, "v1", "open", "2026-05-09T00:00:00+00:00"),
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2024-9999",
                    signal_type="exploit",
                    provider="go-exploitdb",
                    score=None,
                    value={"exploit_type": "weaponized", "url": "https://example.invalid/exploit"},
                    observed_at="2026-05-09T00:00:00+00:00",
                )
                conn.execute(
                    """
                    INSERT INTO fetch_log (feed, attempted_at, status, error_msg, rows_affected)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("ghsa", fresh_at, "ok", None, 1),
                )
                conn.execute(
                    """
                    INSERT INTO fetch_log (feed, attempted_at, status, error_msg, rows_affected)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("hot", fresh_at, "ok", None, 1),
                )
                conn.execute(
                    """
                    INSERT INTO fetch_log (feed, attempted_at, status, error_msg, rows_affected)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    ("kev", fresh_at, "error", "boom", 0),
                )
                conn.commit()

                found = skills.find_vuln("CVE-2024-9999", db_path=core_db)
                affected_assets = skills.affected_assets("CVE-2024-9999", db_path=core_db)
                asset_risk = skills.explain_asset_risk("host-9", db_path=core_db)
                freshness = {row["feed"]: row for row in skills.data_freshness(db_path=core_db)}
            finally:
                conn.close()

            self.assertIsNotNone(found)
            self.assertTrue(found["has_exploit"])
            self.assertIn("exploit", found["signals"])
            self.assertEqual("go-exploitdb", found["signals"]["exploit"]["provider"])
            self.assertEqual(1, len(affected_assets))
            self.assertIn("finding", affected_assets[0])
            self.assertIn("score_breakdown", affected_assets[0]["finding"])
            self.assertIsNotNone(asset_risk)
            self.assertEqual("host-9", asset_risk["asset"]["hostname"])
            self.assertGreaterEqual(len(asset_risk["findings"]), 1)
            self.assertIn("score_breakdown", asset_risk["findings"][0]["finding"])
            self.assertEqual("fresh", freshness["ghsa"]["staleness_status"])
            self.assertEqual("fresh", freshness["hot"]["staleness_status"])
            self.assertEqual("error", freshness["kev"]["last_fetch_status"])
