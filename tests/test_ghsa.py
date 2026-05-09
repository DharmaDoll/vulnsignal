from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from db.migrate import migrate
from sync import fetch_ghsa


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class GhsaFetchTests(TestCase):
    def test_load_payload_reads_local_mirror_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source_dir = Path(tmp)
            advisory_dir = source_dir / "advisories" / "github-reviewed" / "2024" / "05" / "GHSA-test-1111"
            advisory_dir.mkdir(parents=True)
            _write_json(
                advisory_dir / "GHSA-test-1111.json",
                {
                    "schema_version": "1.4.0",
                    "id": "GHSA-test-1111",
                    "published": "2024-05-01T00:00:00Z",
                    "modified": "2024-05-02T00:00:00Z",
                    "aliases": ["CVE-2024-1111"],
                    "summary": "Local GHSA sample",
                    "details": "Synthetic GHSA advisory for local mirror verification.",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "sample-package"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "1.2.3"}],
                                }
                            ],
                        }
                    ],
                    "references": [{"url": "https://example.invalid/ghsa"}],
                    "database_specific": {"severity": "MODERATE"},
                },
            )

            rows, cache_used = fetch_ghsa.load_payload(source_dir, cache_only=False)

        self.assertFalse(cache_used)
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual("GHSA-test-1111", row["ghsa_id"])
        self.assertEqual(["CVE-2024-1111"], row["aliases"])
        self.assertEqual("Local GHSA sample", row["title"])
        self.assertEqual("Synthetic GHSA advisory for local mirror verification.", row["summary"])
        self.assertEqual("MODERATE", row["severity"])
        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", row["cvss_vector"])
        self.assertEqual("2024-05-01T00:00:00Z", row["published_at"])
        self.assertEqual("2024-05-02T00:00:00Z", row["updated_at"])
        self.assertEqual(1, len(row["affected"]))
        self.assertEqual("sample-package", row["affected"][0]["package_name"])
        self.assertEqual("PyPI", row["affected"][0]["ecosystem"])

    def test_sync_skips_advisories_before_2015(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "advisories"
            advisory_dir = source_dir / "github-reviewed" / "2014" / "12" / "GHSA-old"
            advisory_dir.mkdir(parents=True)
            _write_json(
                advisory_dir / "GHSA-old.json",
                {
                    "schema_version": "1.4.0",
                    "id": "GHSA-old",
                    "published": "2014-12-01T00:00:00Z",
                    "modified": "2014-12-02T00:00:00Z",
                    "aliases": ["CVE-2014-1111"],
                    "summary": "Old GHSA advisory",
                    "details": "Should be skipped by the 2015 cutoff.",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "old-package"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
                        }
                    ],
                },
            )
            migrate(core_db)

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_ghsa.connect", side_effect=connect_to_core_db):
                result = fetch_ghsa.sync(source_dir=source_dir, dry_run=False)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)
            self.assertFalse(result.cache_used)

            conn = sqlite3.connect(core_db)
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
            source_dir = tmp_path / "advisories"
            advisory_dir = source_dir / "github-reviewed" / "2023" / "12" / "GHSA-old"
            advisory_dir.mkdir(parents=True)
            _write_json(
                advisory_dir / "GHSA-old.json",
                {
                    "schema_version": "1.4.0",
                    "id": "GHSA-old",
                    "published": "2023-12-01T00:00:00Z",
                    "modified": "2023-12-02T00:00:00Z",
                    "aliases": ["CVE-2023-1111"],
                    "summary": "Old GHSA advisory",
                    "details": "Should be skipped by the 2024 cutoff.",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
                    "affected": [
                        {
                            "package": {"ecosystem": "PyPI", "name": "old-package"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
                        }
                    ],
                },
            )
            migrate(core_db)

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_ghsa.connect", side_effect=connect_to_core_db):
                result = fetch_ghsa.sync(source_dir=source_dir, dry_run=False, min_year=2024)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)
            self.assertFalse(result.cache_used)

    def test_sync_writes_signals_from_local_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "advisories"
            advisory_dir = source_dir / "github-reviewed" / "2024" / "05" / "GHSA-test-2222"
            advisory_dir.mkdir(parents=True)
            _write_json(
                advisory_dir / "GHSA-test-2222.json",
                {
                    "schema_version": "1.4.0",
                    "id": "GHSA-test-2222",
                    "published": "2024-05-03T00:00:00Z",
                    "modified": "2024-05-04T00:00:00Z",
                    "aliases": ["CVE-2024-2222"],
                    "summary": "Local GHSA sync sample",
                    "details": "Synthetic GHSA advisory for sync verification.",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "sample-package"},
                            "ranges": [
                                {
                                    "type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                                }
                            ],
                        }
                    ],
                    "references": [{"url": "https://example.invalid/ghsa-sync"}],
                    "database_specific": {"severity": "HIGH"},
                },
            )
            migrate(core_db)

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_ghsa.connect", side_effect=connect_to_core_db):
                result = fetch_ghsa.sync(source_dir=source_dir, dry_run=False)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(4, result.rows_written)
            self.assertFalse(result.cache_used)

            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                vuln_row = conn.execute(
                    """
                    SELECT source, title, summary, severity, published_at, updated_at
                    FROM vulnerabilities
                    WHERE vuln_id = ?
                    """,
                    ("GHSA-test-2222",),
                ).fetchone()
                cve_row = conn.execute(
                    """
                    SELECT source, title, summary, severity
                    FROM vulnerabilities
                    WHERE vuln_id = ?
                    """,
                    ("CVE-2024-2222",),
                ).fetchone()
                signals = conn.execute(
                    """
                    SELECT signal_type, provider, value_json
                    FROM signals
                    WHERE vuln_id = ?
                    ORDER BY id
                    """,
                    ("GHSA-test-2222",),
                ).fetchall()
            finally:
                conn.close()

            self.assertIsNotNone(vuln_row)
            self.assertEqual("ghsa", vuln_row["source"])
            self.assertEqual("Local GHSA sync sample", vuln_row["title"])
            self.assertEqual("Synthetic GHSA advisory for sync verification.", vuln_row["summary"])
            self.assertEqual("HIGH", vuln_row["severity"])
            self.assertEqual("2024-05-03T00:00:00Z", vuln_row["published_at"])
            self.assertEqual("2024-05-04T00:00:00Z", vuln_row["updated_at"])
            self.assertIsNotNone(cve_row)
            self.assertEqual("ghsa", cve_row["source"])
            self.assertEqual(2, len(signals))
            self.assertEqual("enrichment", signals[0]["signal_type"])
            self.assertEqual("package_advisory", signals[1]["signal_type"])
