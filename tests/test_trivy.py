from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from db.migrate import migrate
from sync import fetch_trivy
from sync import fetch_trivy_db
from sync.trivy_adapter import AdvisoryRecord, TrivyDBSchemaError, VulnerabilityRecord, load_vulnerabilities_from_db_with_cache


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class TrivyAdapterTests(TestCase):
    def test_schema_version_mismatch_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = Path(tmp)
            _write_json(db_dir / "metadata.json", {"Version": 999})

            with self.assertRaises(TrivyDBSchemaError):
                load_vulnerabilities_from_db_with_cache(
                    db_dir,
                    "2026-05-08T00:00:00+00:00",
                    expected_schema_version=2,
                )

    def test_load_vulnerabilities_from_db_with_cache_enriches_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_dir = Path(tmp)
            _write_json(db_dir / "metadata.json", {"Version": 2})

            rows = (
                {
                    "row_type": "vulnerability",
                    "vuln_id": "CVE-2024-0001",
                    "payload": {
                        "Title": "Sample OpenSSL vulnerability",
                        "Description": "Synthetic sample for importer verification.",
                        "Severity": "HIGH",
                        "CVSS": {"aqua": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N"}},
                        "VendorSeverity": {"aqua": 4},
                        "References": ["https://example.invalid/advisory"],
                    },
                },
            )

            with patch("sync.trivy_adapter._load_trivy_db_dump_from_helper", return_value=(rows, True)):
                vulnerabilities, cache_used = load_vulnerabilities_from_db_with_cache(
                    db_dir,
                    "2026-05-08T00:00:00+00:00",
                    expected_schema_version=2,
                )

            self.assertTrue(cache_used)
            self.assertEqual(1, len(vulnerabilities))
            vulnerability = vulnerabilities[0]
            self.assertEqual("CVE-2024-0001", vulnerability.vuln_id)
            self.assertEqual("Sample OpenSSL vulnerability", vulnerability.title)
            self.assertEqual("Synthetic sample for importer verification.", vulnerability.summary)
            self.assertEqual("HIGH", vulnerability.severity)
            self.assertEqual(7.5, vulnerability.cvss_score)
            self.assertEqual("CVSS:3.1/AV:N", vulnerability.cvss_vector)
            self.assertEqual({"aqua": 4}, vulnerability.vendor_severity)
            self.assertEqual(["https://example.invalid/advisory"], vulnerability.references)


class FetchTrivyDbTests(TestCase):
    def test_sync_skips_trivy_json_before_custom_min_year(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            advisory_path = tmp_path / "advisory.json"
            migrate(core_db)

            advisory = AdvisoryRecord(
                vuln_id="CVE-2023-0001",
                source="trivy",
                ecosystem="maven",
                package_name="sample",
                affected_versions=["< 1.0.0"],
                fixed_version="1.0.0",
                severity="HIGH",
                observed_at="2026-05-08T00:00:00+00:00",
                published_at="2023-01-01T00:00:00Z",
                source_path=str(advisory_path),
                title="Old Trivy advisory",
                summary="Should be skipped by the 2024 cutoff.",
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_trivy.connect", side_effect=connect_to_core_db), patch(
                "sync.fetch_trivy.load_advisories_from_json",
                return_value=[advisory],
            ):
                result = fetch_trivy.sync(advisory_path, dry_run=False, min_year=2024)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)

    def test_sync_writes_signals_and_fetch_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            trivy_db_dir = tmp_path / "trivy_cache.db"
            trivy_db_dir.mkdir()
            _write_json(trivy_db_dir / "metadata.json", {"Version": 2})
            migrate(core_db)

            vulnerability = VulnerabilityRecord(
                vuln_id="CVE-2024-0001",
                source="trivy-db",
                title="Sample OpenSSL vulnerability",
                summary="Synthetic sample for importer verification.",
                severity="HIGH",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N",
                vendor_severity={"aqua": 4},
                references=["https://example.invalid/advisory"],
                observed_at="2026-05-08T00:00:00+00:00",
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_trivy_db.connect", side_effect=connect_to_core_db), patch(
                "sync.fetch_trivy_db.load_vulnerabilities_from_db_with_cache",
                return_value=([vulnerability], False),
            ):
                result = fetch_trivy_db.sync(trivy_db_dir, dry_run=False)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(1, result.rows_written)
            self.assertFalse(result.cache_used)

            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                signal_count = conn.execute("SELECT count(*) FROM signals").fetchone()[0]
                fetch_count = conn.execute("SELECT count(*) FROM fetch_log").fetchone()[0]
                log_row = conn.execute(
                    "SELECT feed, status, rows_affected, error_msg FROM fetch_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
                vuln_row = conn.execute(
                    "SELECT source, title, summary, severity FROM vulnerabilities WHERE vuln_id = ?",
                    ("CVE-2024-0001",),
                ).fetchone()
            finally:
                conn.close()

            self.assertEqual(1, signal_count)
            self.assertEqual(1, fetch_count)
            self.assertIsNotNone(log_row)
            self.assertEqual("trivy_db", log_row["feed"])
            self.assertEqual("ok", log_row["status"])
            self.assertEqual(1, log_row["rows_affected"])
            self.assertIsNone(log_row["error_msg"])
            self.assertIsNotNone(vuln_row)
            self.assertEqual("trivy-db", vuln_row["source"])
            self.assertEqual("Sample OpenSSL vulnerability", vuln_row["title"])
            self.assertEqual("Synthetic sample for importer verification.", vuln_row["summary"])
            self.assertEqual("HIGH", vuln_row["severity"])

    def test_sync_skips_trivy_db_before_custom_min_year(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            trivy_db_dir = tmp_path / "trivy_cache.db"
            trivy_db_dir.mkdir()
            _write_json(trivy_db_dir / "metadata.json", {"Version": 2})
            migrate(core_db)

            vulnerability = VulnerabilityRecord(
                vuln_id="CVE-2023-0001",
                source="trivy-db",
                title="Old OpenSSL vulnerability",
                summary="Should be skipped by the 2024 cutoff.",
                severity="HIGH",
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N",
                vendor_severity={"aqua": 4},
                references=["https://example.invalid/advisory"],
                observed_at="2026-05-08T00:00:00+00:00",
            )

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_trivy_db.connect", side_effect=connect_to_core_db), patch(
                "sync.fetch_trivy_db.load_vulnerabilities_from_db_with_cache",
                return_value=([vulnerability], False),
            ):
                result = fetch_trivy_db.sync(trivy_db_dir, dry_run=False, min_year=2024)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(0, result.rows_written)

    def test_sync_logs_error_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            trivy_db_dir = tmp_path / "trivy_cache.db"
            trivy_db_dir.mkdir()
            _write_json(trivy_db_dir / "metadata.json", {"Version": 2})
            migrate(core_db)

            def connect_to_core_db() -> sqlite3.Connection:
                conn = sqlite3.connect(core_db)
                conn.row_factory = sqlite3.Row
                return conn

            with patch("sync.fetch_trivy_db.connect", side_effect=connect_to_core_db), patch(
                "sync.fetch_trivy_db.load_vulnerabilities_from_db_with_cache",
                side_effect=RuntimeError("boom"),
            ):
                result = fetch_trivy_db.sync(trivy_db_dir, dry_run=False)

            self.assertEqual(0, result.rows_fetched)
            self.assertEqual(0, result.rows_written)

            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                log_row = conn.execute(
                    "SELECT feed, status, rows_affected, error_msg FROM fetch_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(log_row)
            self.assertEqual("trivy_db", log_row["feed"])
            self.assertEqual("error", log_row["status"])
            self.assertEqual(0, log_row["rows_affected"])
            self.assertIn("boom", log_row["error_msg"])
