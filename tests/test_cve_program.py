from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from db.migrate import migrate
from sync import fetch_cve_program


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class CveProgramLoadTests(TestCase):
    def test_load_payload_reads_local_json_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp)
            _write_json(
                source_dir / "CVE-2024-0001.json",
                {
                    "cveMetadata": {
                        "cveId": "CVE-2024-0001",
                        "datePublished": "2024-01-01T00:00:00Z",
                        "dateUpdated": "2024-01-02T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "title": "Sample CVE Program advisory",
                            "descriptions": [{"lang": "en", "value": "Synthetic summary."}],
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": 9.1,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ],
                            "references": [{"url": "https://example.invalid/cve-program"}],
                        }
                    },
                },
            )

            rows, cache_used = fetch_cve_program.load_payload(source_dir, cache_only=False)

        self.assertFalse(cache_used)
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual("CVE-2024-0001", row["vuln_id"])
        self.assertEqual("Sample CVE Program advisory", row["title"])
        self.assertEqual("Synthetic summary.", row["summary"])
        self.assertEqual("CRITICAL", row["severity"])
        self.assertEqual(9.1, row["cvss_score"])
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", row["cvss_vector"])

    def test_load_payload_preserves_zero_cvss_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp)
            _write_json(
                source_dir / "CVE-2026-41517.json",
                {
                    "cveMetadata": {
                        "cveId": "CVE-2026-41517",
                        "datePublished": "2026-05-01T00:00:00Z",
                        "dateUpdated": "2026-05-02T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "title": "Zero-score advisory",
                            "descriptions": [{"lang": "en", "value": "Synthetic zero score."}],
                            "metrics": [
                                {
                                    "cvssV4_0": {
                                        "baseScore": 0,
                                        "baseSeverity": "NONE",
                                        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
                                    }
                                }
                            ],
                        }
                    },
                },
            )

            rows, cache_used = fetch_cve_program.load_payload(source_dir, cache_only=False)

        self.assertFalse(cache_used)
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual("CVE-2026-41517", row["vuln_id"])
        self.assertEqual(0.0, row["cvss_score"])
        self.assertEqual("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", row["cvss_vector"])
        self.assertEqual("NONE", row["severity"])


class CveProgramSyncTests(TestCase):
    def test_sync_skips_records_before_custom_min_year(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "cvelist"
            source_dir.mkdir()
            migrate(core_db)

            _write_json(
                source_dir / "CVE-2023-0001.json",
                {
                    "cveMetadata": {
                        "cveId": "CVE-2023-0001",
                        "datePublished": "2023-01-01T00:00:00Z",
                        "dateUpdated": "2023-01-02T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "title": "Old CVE Program advisory",
                            "descriptions": [{"lang": "en", "value": "Should be skipped."}],
                        }
                    },
                },
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_cve_program.connect", side_effect=connect_to_core_db):
                result = fetch_cve_program.sync(source_dir=source_dir, dry_run=False, min_year=2024)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)
            self.assertFalse(result.cache_used)

    def test_sync_writes_signals_from_local_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "cvelist"
            source_dir.mkdir()
            migrate(core_db)

            _write_json(
                source_dir / "CVE-2024-0002.json",
                {
                    "cveMetadata": {
                        "cveId": "CVE-2024-0002",
                        "datePublished": "2024-02-01T00:00:00Z",
                        "dateUpdated": "2024-02-02T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "title": "CVE Program sync sample",
                            "descriptions": [{"lang": "en", "value": "Synthetic CVE Program sample."}],
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": 7.2,
                                        "baseSeverity": "HIGH",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                                    }
                                }
                            ],
                            "references": [{"url": "https://example.invalid/cve-program-sync"}],
                        }
                    },
                },
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_cve_program.connect", side_effect=connect_to_core_db):
                result = fetch_cve_program.sync(source_dir=source_dir, dry_run=False)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(1, result.rows_written)
            self.assertFalse(result.cache_used)

            conn = connect_to_core_db()
            conn.row_factory = sqlite3.Row
            try:
                vuln_row = conn.execute(
                    "SELECT source, title, summary, severity, cvss_score, cvss_source FROM vulnerabilities WHERE vuln_id = ?",
                    ("CVE-2024-0002",),
                ).fetchone()
                signal_row = conn.execute(
                    "SELECT signal_type, provider, value_json FROM signals WHERE vuln_id = ? ORDER BY id DESC LIMIT 1",
                    ("CVE-2024-0002",),
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(vuln_row)
            self.assertEqual("cve_program", vuln_row["source"])
            self.assertEqual("CVE Program sync sample", vuln_row["title"])
            self.assertEqual("Synthetic CVE Program sample.", vuln_row["summary"])
            self.assertEqual("HIGH", vuln_row["severity"])
            self.assertEqual(7.2, vuln_row["cvss_score"])
            self.assertEqual("CVE Program", vuln_row["cvss_source"])
            self.assertIsNotNone(signal_row)
            self.assertEqual("enrichment", signal_row["signal_type"])
            self.assertEqual("CVE Program", signal_row["provider"])
