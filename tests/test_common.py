from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from db.migrate import migrate
from sync.common import upsert_vulnerability


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


class UpsertVulnerabilityTests(TestCase):
    def test_first_seen_at_tracks_earliest_announcement_date(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = _connect(core_db)
            try:
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-0001",
                    source="ghsa",
                    title="Initial title",
                    summary="Initial summary",
                    severity="LOW",
                    cvss_score=4.2,
                    cvss_source="GHSA",
                    published_at="2026-05-11T00:00:00Z",
                    first_seen_at="2026-05-11T00:00:00Z",
                    updated_at="2026-05-10T00:00:00Z",
                )
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-0001",
                    source="cve_program",
                    title="Updated title",
                    summary="Updated summary",
                    severity="HIGH",
                    cvss_score=9.8,
                    cvss_source="CVE Program",
                    published_at="2026-05-09T00:00:00Z",
                    first_seen_at="2026-05-09T00:00:00Z",
                    updated_at="2026-05-11T00:00:00Z",
                )
                row = conn.execute(
                    """
                    SELECT source, title, summary, severity, cvss_score, cvss_source, published_at, first_seen_at, updated_at
                    FROM vulnerabilities
                    WHERE vuln_id = ?
                    """,
                    ("CVE-2026-0001",),
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(row)
            self.assertEqual("ghsa", row["source"])
            self.assertEqual("Updated title", row["title"])
            self.assertEqual("Updated summary", row["summary"])
            self.assertEqual("HIGH", row["severity"])
            self.assertEqual(9.8, row["cvss_score"])
            self.assertEqual("CVE Program", row["cvss_source"])
            self.assertEqual("2026-05-09T00:00:00Z", row["published_at"])
            self.assertEqual("2026-05-09T00:00:00Z", row["first_seen_at"])
            self.assertEqual("2026-05-11T00:00:00Z", row["updated_at"])
