from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from db.migrate import migrate
from sync import fetch_trivy_vuln_list


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class FetchTrivyVulnListTests(TestCase):
    def test_sync_skips_advisories_before_2015(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "vuln-list"
            advisory_dir = source_dir / "ghsa" / "maven" / "sample" / "pkg"
            advisory_dir.mkdir(parents=True)
            _write_json(
                advisory_dir / "GHSA-old.json",
                {
                    "ghsa_id": "GHSA-old",
                    "cve_id": "CVE-2014-1234",
                    "PublishedAt": "2014-12-31T00:00:00Z",
                    "summary": "Old Trivy vuln-list advisory",
                    "description": "Should be skipped by the 2015 cutoff.",
                    "severity": "high",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "maven", "name": "sample"},
                            "vulnerable_version_range": "< 1.0.0",
                            "first_patched_version": {"identifier": "1.0.0"},
                        }
                    ],
                },
            )
            migrate(core_db)

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_trivy_vuln_list.connect", side_effect=connect_to_core_db):
                result = fetch_trivy_vuln_list.sync(source_dir=source_dir, dry_run=False)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)
            self.assertFalse(result.cache_used)

            conn = connect_to_core_db()
            conn.row_factory = sqlite3.Row
            try:
                vuln_count = conn.execute("SELECT count(*) FROM vulnerabilities").fetchone()[0]
                signal_count = conn.execute("SELECT count(*) FROM signals").fetchone()[0]
            finally:
                conn.close()

            self.assertEqual(0, vuln_count)
            self.assertEqual(0, signal_count)

    def test_sync_skips_advisories_before_custom_min_year(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "vuln-list"
            advisory_dir = source_dir / "ghsa" / "maven" / "sample" / "pkg"
            advisory_dir.mkdir(parents=True)
            _write_json(
                advisory_dir / "GHSA-old.json",
                {
                    "ghsa_id": "GHSA-old",
                    "cve_id": "CVE-2023-1234",
                    "PublishedAt": "2023-12-31T00:00:00Z",
                    "summary": "Old Trivy vuln-list advisory",
                    "description": "Should be skipped by the 2024 cutoff.",
                    "severity": "high",
                    "vulnerabilities": [
                        {
                            "package": {"ecosystem": "maven", "name": "sample"},
                            "vulnerable_version_range": "< 1.0.0",
                            "first_patched_version": {"identifier": "1.0.0"},
                        }
                    ],
                },
            )
            migrate(core_db)

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_trivy_vuln_list.connect", side_effect=connect_to_core_db):
                result = fetch_trivy_vuln_list.sync(source_dir=source_dir, dry_run=False, min_year=2024)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)
            self.assertFalse(result.cache_used)
