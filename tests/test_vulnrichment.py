from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from db.migrate import migrate
from sync import fetch_vulnrichment


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class VulnrichmentLoadTests(TestCase):
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
                            "title": "Sample Vulnrichment advisory",
                            "descriptions": [{"lang": "en", "value": "Synthetic summary."}],
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": 8.1,
                                        "baseSeverity": "HIGH",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                }
                            ],
                            "references": [{"url": "https://example.invalid/vulnrichment"}],
                        }
                    },
                },
            )

            rows, cache_used = fetch_vulnrichment.load_payload(source_dir, cache_only=False)

        self.assertFalse(cache_used)
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual("CVE-2024-0001", row["vuln_id"])
        self.assertEqual("Sample Vulnrichment advisory", row["title"])
        self.assertEqual("Synthetic summary.", row["summary"])
        self.assertEqual("HIGH", row["severity"])
        self.assertEqual(8.1, row["cvss_score"])
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", row["cvss_vector"])


class VulnrichmentSyncTests(TestCase):
    def test_sync_preserves_higher_trust_ghsa_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "vulnrichment"
            source_dir.mkdir()
            migrate(core_db)

            _write_json(
                source_dir / "CVE-2024-0001.json",
                {
                    "cveMetadata": {"cveId": "CVE-2024-0001"},
                    "containers": {
                        "cna": {
                            "title": "Vulnrichment title",
                            "descriptions": [{"lang": "en", "value": "Vulnrichment summary."}],
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                        "vectorString": "CVSS:3.1/AV:N",
                                    }
                                }
                            ],
                        }
                    },
                },
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            conn = connect_to_core_db()
            try:
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                      vuln_id, source, title, summary, severity, cvss_score, cvss_source, published_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "CVE-2024-0001",
                        "ghsa",
                        "GHSA title",
                        "GHSA summary",
                        "CRITICAL",
                        9.8,
                        "GHSA",
                        "2024-01-01T00:00:00Z",
                        "2024-01-02T00:00:00Z",
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            with patch("sync.fetch_vulnrichment.connect", side_effect=connect_to_core_db):
                result = fetch_vulnrichment.sync(source_dir=source_dir, dry_run=False)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(1, result.rows_written)
            self.assertFalse(result.cache_used)

            conn = connect_to_core_db()
            try:
                vuln_row = conn.execute(
                    """
                    SELECT source, title, summary, severity, cvss_score, cvss_source
                    FROM vulnerabilities
                    WHERE vuln_id = ?
                    """,
                    ("CVE-2024-0001",),
                ).fetchone()
                signal_row = conn.execute(
                    """
                    SELECT signal_type, provider, value_json
                    FROM signals
                    WHERE vuln_id = ?
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    ("CVE-2024-0001",),
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(vuln_row)
            self.assertEqual("ghsa", vuln_row["source"])
            self.assertEqual("GHSA title", vuln_row["title"])
            self.assertEqual("GHSA summary", vuln_row["summary"])
            self.assertEqual("CRITICAL", vuln_row["severity"])
            self.assertEqual(9.8, vuln_row["cvss_score"])
            self.assertEqual("GHSA", vuln_row["cvss_source"])
            self.assertIsNotNone(signal_row)
            self.assertEqual("enrichment", signal_row["signal_type"])
            self.assertEqual("CISA Vulnrichment", signal_row["provider"])

    def test_sync_fills_missing_trivy_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "vulnrichment"
            source_dir.mkdir()
            migrate(core_db)

            _write_json(
                source_dir / "CVE-2024-0002.json",
                {
                    "cveMetadata": {"cveId": "CVE-2024-0002"},
                    "containers": {
                        "cna": {
                            "title": "Vulnrichment fills blanks",
                            "descriptions": [{"lang": "en", "value": "Filled by Vulnrichment."}],
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": 6.5,
                                        "baseSeverity": "MEDIUM",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
                                    }
                                }
                            ],
                        }
                    },
                },
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            conn = connect_to_core_db()
            try:
                conn.execute(
                    """
                    INSERT INTO vulnerabilities (
                      vuln_id, source, title, summary, severity, cvss_score, cvss_source, published_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "CVE-2024-0002",
                        "trivy",
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            with patch("sync.fetch_vulnrichment.connect", side_effect=connect_to_core_db):
                result = fetch_vulnrichment.sync(source_dir=source_dir, dry_run=False)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(1, result.rows_written)

            conn = connect_to_core_db()
            try:
                vuln_row = conn.execute(
                    """
                    SELECT source, title, summary, severity, cvss_score, cvss_source
                    FROM vulnerabilities
                    WHERE vuln_id = ?
                    """,
                    ("CVE-2024-0002",),
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(vuln_row)
            self.assertEqual("trivy", vuln_row["source"])
            self.assertEqual("Vulnrichment fills blanks", vuln_row["title"])
            self.assertEqual("Filled by Vulnrichment.", vuln_row["summary"])
            self.assertEqual("MEDIUM", vuln_row["severity"])
            self.assertEqual(6.5, vuln_row["cvss_score"])
            self.assertEqual("CISA Vulnrichment", vuln_row["cvss_source"])

    def test_sync_skips_records_before_2015(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "vulnrichment"
            source_dir.mkdir()
            migrate(core_db)

            _write_json(
                source_dir / "CVE-2014-0001.json",
                {
                    "cveMetadata": {"cveId": "CVE-2014-0001", "datePublished": "2014-01-01T00:00:00Z"},
                    "containers": {
                        "cna": {
                            "title": "Old Vulnrichment advisory",
                            "descriptions": [{"lang": "en", "value": "Should be skipped."}],
                            "metrics": [
                                {
                                    "cvssV3_1": {
                                        "baseScore": 9.1,
                                        "baseSeverity": "CRITICAL",
                                        "vectorString": "CVSS:3.1/AV:N",
                                    }
                                }
                            ],
                        }
                    },
                },
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_vulnrichment.connect", side_effect=connect_to_core_db):
                result = fetch_vulnrichment.sync(source_dir=source_dir, dry_run=False)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)

            conn = connect_to_core_db()
            try:
                vuln_count = conn.execute("SELECT count(*) FROM vulnerabilities").fetchone()[0]
                signal_count = conn.execute("SELECT count(*) FROM signals").fetchone()[0]
            finally:
                conn.close()

            self.assertEqual(0, vuln_count)
            self.assertEqual(0, signal_count)

    def test_sync_skips_records_before_custom_min_year(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "vulnrichment"
            source_dir.mkdir()
            migrate(core_db)

            _write_json(
                source_dir / "CVE-2023-0001.json",
                {
                    "cveMetadata": {"cveId": "CVE-2023-0001", "datePublished": "2023-01-01T00:00:00Z"},
                    "containers": {
                        "cna": {
                            "title": "Old Vulnrichment sample",
                            "descriptions": [{"lang": "en", "value": "Should be skipped by the 2024 cutoff."}],
                        }
                    },
                },
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_vulnrichment.connect", side_effect=connect_to_core_db):
                result = fetch_vulnrichment.sync(source_dir=source_dir, dry_run=False, min_year=2024)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)
