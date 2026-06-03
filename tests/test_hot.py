from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from io import StringIO
from unittest import TestCase
from unittest.mock import patch
from contextlib import redirect_stdout

from db.migrate import migrate
from sync import fetch_hot
from sync.hot_intel import SearchHit, classify_hit
from sync.common import connect
from sync.common import append_signal, upsert_vulnerability
from app import skills


class HotIntelTests(TestCase):
    def test_classify_hit_recognizes_active_exploitation_and_x_mentions(self) -> None:
        active = classify_hit(
            SearchHit(
                query='"CVE-2026-0257"',
                title="Palo Alto PAN-OS flaw actively exploited in the wild",
                url="https://thehackernews.com/2026/05/pan-os-flaw-actively-exploited.html",
                domain="thehackernews.com",
            )
        )
        social = classify_hit(
            SearchHit(
                query='"CVE-2026-0257"',
                title="CVE-2026-0257 is being discussed on X",
                url="https://x.com/example/status/123",
                domain="x.com",
            )
        )

        self.assertIsNotNone(active)
        self.assertEqual("active_exploitation", active.evidence_type)
        self.assertIsNotNone(social)
        self.assertEqual("x_mention", social.evidence_type)


class FetchHotTests(TestCase):
    def test_sync_writes_hot_signal_for_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-45185",
                    source="cve_program",
                    title="Sample Application Remote Code Execution Vulnerability",
                    severity="HIGH",
                    cvss_score=7.8,
                    published_at="2026-05-29",
                    first_seen_at="2026-05-13T18:15:10.172Z",
                )
                conn.commit()
            finally:
                conn.close()

            def fake_collect(vuln_id: str, title: str | None = None, queries_per_vuln: int = 3, results_per_query: int = 5):
                if vuln_id == "CVE-2026-45185":
                    return {
                        "score": 0.95,
                        "query_count": 3,
                        "result_count": 7,
                        "evidence_count": 3,
                        "independent_sources": 2,
                        "evidence_types": ["active_exploitation", "vendor_advisory"],
                        "source_types": ["news", "vendor"],
                        "urls": ["https://example.invalid/a", "https://example.invalid/b"],
                        "headline": "Palo Alto advisory and coverage mention active exploitation",
                    }
                return None

            with patch("sync.fetch_hot.collect_hot_evidence_for_vuln", side_effect=fake_collect):
                result = fetch_hot.sync(cutoff="2026-05-01T00:00:00+00:00", search_cap=5, db_path=core_db)

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(1, result.rows_written)

            conn = connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                signal_row = conn.execute(
                    "SELECT signal_type, provider, score, value_json FROM signals WHERE vuln_id = ?",
                    ("CVE-2026-45185",),
                ).fetchone()
                log_row = conn.execute(
                    "SELECT feed, status, rows_affected FROM fetch_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(signal_row)
            self.assertEqual("hot", signal_row["signal_type"])
            self.assertEqual("Web Hot Intel", signal_row["provider"])
            self.assertGreater(signal_row["score"], 0.9)
            self.assertIsNotNone(log_row)
            self.assertEqual("hot", log_row["feed"])
            self.assertEqual("ok", log_row["status"])
            self.assertEqual(1, log_row["rows_affected"])


class HotListTests(TestCase):
    def test_top_hot_returns_latest_hot_per_vuln(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-9999",
                    source="ghsa",
                    title="Example Hot Vulnerability",
                    severity="HIGH",
                    cvss_score=8.1,
                    published_at="2026-05-20T00:00:00Z",
                    first_seen_at="2026-05-20T00:00:00Z",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2026-9999",
                    signal_type="hot",
                    provider="Web Hot Intel",
                    score=0.3,
                    value={
                        "search_budget": 5,
                        "result_count": 2,
                        "evidence_count": 1,
                        "independent_sources": 1,
                        "evidence_types": ["news_mention"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/old"],
                        "headline": "older observation",
                    },
                    observed_at="2026-05-29T00:00:00+00:00",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2026-9999",
                    signal_type="hot",
                    provider="Web Hot Intel",
                    score=0.9,
                    value={
                        "search_budget": 5,
                        "result_count": 6,
                        "evidence_count": 3,
                        "independent_sources": 2,
                        "evidence_types": ["active_exploitation", "vendor_advisory"],
                        "source_types": ["vendor", "news"],
                        "urls": ["https://example.invalid/new"],
                        "headline": "newer observation",
                    },
                    observed_at="2026-05-30T00:00:00+00:00",
                )
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-9998",
                    source="ghsa",
                    title="Another Hot Vulnerability",
                    severity="CRITICAL",
                    cvss_score=9.9,
                    published_at="2026-05-20T00:00:00Z",
                    first_seen_at="2026-05-20T00:00:00Z",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2026-9998",
                    signal_type="hot",
                    provider="Web Hot Intel",
                    score=0.2,
                    value={
                        "search_budget": 5,
                        "result_count": 2,
                        "evidence_count": 1,
                        "independent_sources": 1,
                        "evidence_types": ["news_mention"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/other"],
                        "headline": "lower hot score but higher CVSS",
                    },
                    observed_at="2026-05-30T00:00:00+00:00",
                )
                conn.commit()
            finally:
                conn.close()

            rows = skills.top_hot(limit=10, db_path=core_db)

            self.assertEqual(2, len(rows))
            self.assertEqual("CVE-2026-9998", rows[0]["vuln_id"])
            self.assertEqual("lower hot score but higher CVSS", rows[0]["headline"])
            self.assertEqual("CVE-2026-9999", rows[1]["vuln_id"])
            self.assertEqual("newer observation", rows[1]["headline"])
            self.assertIn("kev_present", rows[0])
            self.assertIn("exploit_present", rows[0])
            self.assertIn("epss_score", rows[0])
            self.assertIn("cvss_score", rows[0])
            self.assertIn("published_at", rows[0])

    def test_hot_cli_labels_reference_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-9997",
                    source="ghsa",
                    title="CLI Label Sample",
                    severity="HIGH",
                    cvss_score=7.5,
                    published_at="2026-05-20T00:00:00Z",
                    first_seen_at="2026-05-20T00:00:00Z",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2026-9997",
                    signal_type="hot",
                    provider="Web Hot Intel",
                    score=0.7,
                    value={
                        "search_budget": 3,
                        "result_count": 1,
                        "evidence_count": 1,
                        "independent_sources": 1,
                        "evidence_types": ["news_mention"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/cli"],
                        "headline": "cli label sample",
                    },
                    observed_at="2026-06-01T00:00:00+00:00",
                )
                conn.commit()
            finally:
                conn.close()

            buf = StringIO()
            with redirect_stdout(buf):
                skills._print_hot_rows(skills.top_hot(limit=5, db_path=core_db), details=False)

            output = buf.getvalue()
            self.assertIn("priority [KEV / exploit / EPSS / CVSS / published_at]", output)
            self.assertIn("kev_present\texploit_present\tepss_score\tcvss_score\tpublished_at\tfirst_seen_at\tvuln_id", output)
            self.assertNotIn("hot_reference [reference-only]", output)

            buf = StringIO()
            with redirect_stdout(buf):
                skills._print_hot_rows(skills.top_hot(limit=5, db_path=core_db), details=True)

            output = buf.getvalue()
            self.assertIn("hot_reference [reference-only]", output)
