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
from sync.hot_intel import SearchHit, classify_hit, discover_hot_candidates, fetch_rss_feed_items, hot_queries, search_hatena
from sync.common import FetchError, connect
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

    def test_classify_hit_ignores_negated_in_the_wild_phrases(self) -> None:
        hit = classify_hit(
            SearchHit(
                query='"CVE-2026-2473" exploit OR PoC OR "active exploitation"',
                title="Google Vertex AI SDK flaw saw no exploitation in the wild",
                url="https://thehackernews.com/2026/06/google-vertex-ai-sdk-flaw-let-attackers.html",
                domain="thehackernews.com",
            )
        )

        self.assertIsNotNone(hit)
        self.assertNotEqual("active_exploitation", hit.evidence_type)

    def test_classify_hit_uses_query_context_for_generic_blog_results(self) -> None:
        hit = classify_hit(
            SearchHit(
                query='"HTTP/2 Bomb" exploit OR PoC OR "active exploitation"',
                title="Codex Discovered a Hidden HTTP/2 Bomb",
                url="https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb",
                domain="blog.calif.io",
            )
        )

        self.assertIsNotNone(hit)
        self.assertEqual("active_exploitation", hit.evidence_type)
        self.assertEqual("search", hit.source_type)

    def test_hot_queries_are_title_based(self) -> None:
        queries = hot_queries(
            title="NGINX ngx_http_rewrite_module vulnerability",
            summary="NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module.",
        )

        self.assertGreaterEqual(len(queries), 3)
        self.assertNotIn("CVE-2026-42945", " ".join(queries))
        self.assertIn("NGINX ngx_http_rewrite_module", queries[0])
        self.assertIn("exploit OR PoC OR \"active exploitation\"", queries[1])

    def test_hot_queries_broaden_denial_of_service_titles(self) -> None:
        queries = hot_queries(
            title="HTTP/2 Bomb denial of service issue",
            summary="HTTP/2 Bomb denial of service issue",
        )

        self.assertGreaterEqual(len(queries), 3)
        self.assertEqual('"HTTP/2 Bomb"', queries[0])
        self.assertIn('"HTTP/2 Bomb" exploit OR PoC OR "active exploitation"', queries[1])
        self.assertTrue(any("悪用 OR 公開PoC OR 実証コード OR ゼロデイ" in query for query in queries))

    def test_search_hatena_parses_popular_results(self) -> None:
        html = """
        <html>
          <body>
            <div class="search-container">
              <ul class="entrysearch-articles">
                <li class="bookmark-item js-user-bookmark-item js-keyboard-selectable-item">
                  <div class="centerarticle-entry">
                    <h3 class="centerarticle-entry-title">
                      <a href="https://qiita.com/long-910/items/76779fc1d8602dab73b3">HTTP/2 Bomb をわかりやすく解説——AIが人間より先に気づいた脆弱性 - Qiita</a>
                    </h3>
                    <div class="entry-summary">Apache で CVE-2026-49975 が話題。本文に CVE を含む。</div>
                  </div>
                  <span class="bookmark-count">
                    <a href="/entry/s/qiita.com/long-910/items/76779fc1d8602dab73b3" data-gtm-click-label="entry-search-result-item-users">27 users</a>
                  </span>
                </li>
              </ul>
            </div>
          </body>
        </html>
        """

        with patch("sync.hot_intel.fetch_text", return_value=html):
            hits = search_hatena("HTTP/2 Bomb")

        self.assertEqual(1, len(hits))
        self.assertEqual("https://b.hatena.ne.jp/entry/s/qiita.com/long-910/items/76779fc1d8602dab73b3", hits[0].url)
        self.assertEqual(27, hits[0].metadata["hatena_users"])
        self.assertIn("CVE-2026-49975", hits[0].metadata["cve_ids"])
        self.assertEqual("Hatena Bookmark", hits[0].metadata["source_label"])
        self.assertEqual("https://qiita.com/long-910/items/76779fc1d8602dab73b3", hits[0].metadata["target_url"])
        evidence = classify_hit(
            SearchHit(
                query=hits[0].query,
                title=hits[0].title,
                url=hits[0].url,
                domain="b.hatena.ne.jp",
                metadata=hits[0].metadata,
            )
        )
        self.assertIsNotNone(evidence)
        self.assertEqual("hatena_popular", evidence.evidence_type)
        self.assertEqual("social", evidence.source_type)

    def test_discovery_extracts_cves_from_web_hits(self) -> None:
        with patch(
            "sync.hot_intel.fetch_rss_feed_items",
            return_value=[
                {
                    "feed": "The Hacker News",
                    "query": "https://feeds.feedburner.com/TheHackersNews",
                    "title": "NGINX CVE-2026-42945 exploited in the wild",
                    "summary": "The issue has public PoC coverage.",
                    "url": "https://thehackernews.com/2026/05/nginx-cve-2026-42945-exploited-in-wild.html",
                    "domain": "thehackernews.com",
                    "published_at": "2026-06-04T00:00:00Z",
                    "cve_ids": ["CVE-2026-42945"],
                }
            ],
        ), patch("sync.hot_intel.search_duckduckgo", return_value=[]), patch("sync.hot_intel.search_hatena", return_value=[]):
            result = discover_hot_candidates(results_per_query=1, max_candidates=5)

        self.assertIn("CVE-2026-42945", result["discovered_vuln_ids"])
        self.assertGreaterEqual(result["query_count"], 1)
        self.assertGreaterEqual(result["result_count"], 1)
        self.assertGreaterEqual(len(result["search_hits"]), 1)
        self.assertEqual(["CVE-2026-42945"], result["search_hits"][0]["cve_ids"])

    def test_discovery_accepts_extra_query_terms(self) -> None:
        with patch("sync.hot_intel.fetch_rss_feed_items", return_value=[]), patch(
            "sync.hot_intel.search_duckduckgo",
            return_value=[
                SearchHit(
                    query='"Palo Alto" exploit OR PoC OR "active exploitation"',
                    title="Palo Alto advisory mentions CVE-2026-0257 exploitation",
                    url="https://example.invalid/cve-2026-0257",
                    domain="example.invalid",
                )
            ],
        ), patch("sync.hot_intel.search_hatena", return_value=[]):
            result = discover_hot_candidates(results_per_query=1, max_candidates=5, query_terms=["Palo Alto"])

        self.assertIn("CVE-2026-0257", result["discovered_vuln_ids"])
        self.assertTrue(any("Palo Alto" in query for query in result["search_queries"]))

    def test_discovery_uses_hatena_search_results(self) -> None:
        with patch("sync.hot_intel.fetch_rss_feed_items", return_value=[]), patch(
            "sync.hot_intel.search_duckduckgo",
            return_value=[],
        ), patch(
            "sync.hot_intel.search_hatena",
            return_value=[
                SearchHit(
                    query="https://b.hatena.ne.jp/q/HTTP%2F2%20Bomb?users=50&sort=popular&date_range=m&safe=on&target=title",
                    title="HTTP/2 Bomb をわかりやすく解説——AIが人間より先に気づいた脆弱性 - Qiita",
                    url="https://b.hatena.ne.jp/entry/s/qiita.com/long-910/items/76779fc1d8602dab73b3",
                    domain="b.hatena.ne.jp",
                    metadata={
                        "hatena_users": 27,
                        "cve_ids": ["CVE-2026-49975"],
                        "target_url": "https://qiita.com/long-910/items/76779fc1d8602dab73b3",
                    },
                )
            ],
        ):
            result = discover_hot_candidates(results_per_query=1, max_candidates=5)

        self.assertIn("CVE-2026-49975", result["discovered_vuln_ids"])
        self.assertTrue(any("b.hatena.ne.jp/q/" in query for query in result["search_queries"]))

    def test_discovery_uses_signal_first_baseline_by_default(self) -> None:
        seen_queries: list[str] = []

        def fake_search(query: str, results_per_query: int = 10):
            seen_queries.append(query)
            if "active exploitation" in query or "in the wild" in query or "PoC" in query or "zero-day" in query:
                return [
                    SearchHit(
                        query=query,
                        title="Active exploitation report for CVE-2026-0257",
                        url="https://example.invalid/cve-2026-0257",
                        domain="example.invalid",
                    )
                ]
            return []

        with patch("sync.hot_intel.fetch_rss_feed_items", return_value=[]), patch(
            "sync.hot_intel.search_duckduckgo",
            side_effect=fake_search,
        ), patch("sync.hot_intel.search_hatena", return_value=[]):
            result = discover_hot_candidates(results_per_query=1, max_candidates=5)

        self.assertIn("CVE-2026-0257", result["discovered_vuln_ids"])
        self.assertTrue(any("active exploitation" in query for query in seen_queries))

    def test_discovery_broadens_when_baseline_is_thin(self) -> None:
        seen_queries: list[str] = []

        def fake_search(query: str, results_per_query: int = 10):
            seen_queries.append(query)
            if "CVE-2026" in query:
                return [
                    SearchHit(
                        query=query,
                        title="Year-based query found CVE-2026-42945",
                        url="https://example.invalid/cve-2026-42945",
                        domain="example.invalid",
                    )
                ]
            return []

        with patch("sync.hot_intel.fetch_rss_feed_items", return_value=[]), patch(
            "sync.hot_intel.search_duckduckgo",
            side_effect=fake_search,
        ), patch("sync.hot_intel.search_hatena", return_value=[]):
            result = discover_hot_candidates(results_per_query=1, max_candidates=5)

        self.assertIn("CVE-2026-42945", result["discovered_vuln_ids"])
        self.assertTrue(any("CVE-2026" in query for query in seen_queries))

    def test_discovery_continues_when_one_rss_feed_fails(self) -> None:
        def fake_fetch_rss_feed_items(
            feed_name: str,
            feed_url: str,
            results_per_query: int = 10,
            follow_article_links: bool = True,
        ):
            if feed_name == "The Hacker News":
                raise FetchError("temporary dns failure")
            return [
                {
                    "feed": feed_name,
                    "query": feed_url,
                    "title": "NGINX CVE-2026-42945 exploited in the wild",
                    "summary": "The issue has public PoC coverage.",
                    "url": "https://thehackernews.com/2026/05/nginx-cve-2026-42945-exploited-in-wild.html",
                    "domain": "thehackernews.com",
                    "published_at": "2026-06-04T00:00:00Z",
                    "cve_ids": ["CVE-2026-42945"],
                }
            ]

        with patch("sync.hot_intel.fetch_rss_feed_items", side_effect=fake_fetch_rss_feed_items), patch(
            "sync.hot_intel.search_duckduckgo",
            return_value=[],
        ), patch("sync.hot_intel.search_hatena", return_value=[]):
            result = discover_hot_candidates(results_per_query=1, max_candidates=5)

        self.assertIn("CVE-2026-42945", result["discovered_vuln_ids"])
        self.assertTrue(result["fetch_errors"])

    def test_rss_items_fall_back_to_article_body_for_cves(self) -> None:
        rss_xml = """<?xml version="1.0" encoding="utf-8"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Threat actors exploit critical flaw</title>
              <link>https://example.invalid/article</link>
              <description><![CDATA[Campaign details without a CVE in the feed summary.]]></description>
              <pubDate>Thu, 28 May 2026 20:56:04 +0530</pubDate>
            </item>
          </channel>
        </rss>
        """
        article_html = """
        <html>
          <head><title>Threat actors exploit critical flaw CVE-2026-42945</title></head>
          <body>
            <p>The advisory references CVE-2026-42945 and public PoC coverage.</p>
          </body>
        </html>
        """

        def fake_fetch_text(url: str, headers=None, attempts: int = 3) -> str:
            if url == "https://feeds.feedburner.com/TheHackersNews":
                return rss_xml
            if url == "https://example.invalid/article":
                return article_html
            raise AssertionError(f"unexpected url: {url}")

        with patch("sync.hot_intel.fetch_text", side_effect=fake_fetch_text):
            items = fetch_rss_feed_items(
                "The Hacker News",
                "https://feeds.feedburner.com/TheHackersNews",
                results_per_query=10,
            )

        self.assertEqual(1, len(items))
        self.assertIn("CVE-2026-42945", items[0]["cve_ids"])


class FetchHotTests(TestCase):
    def test_sync_profile_sets_balanced_defaults(self) -> None:
        with patch("sync.fetch_hot.discover_hot_candidates", return_value={"search_queries": [], "query_count": 0, "result_count": 0, "discovered_vuln_ids": [], "search_hits": [], "urls": []}), patch(
            "sync.fetch_hot.collect_hot_evidence_for_vuln",
            return_value=None,
        ):
            result = fetch_hot.sync(cutoff="2026-05-01T00:00:00+00:00", profile="balanced")

        self.assertEqual(0, result.rows_fetched)
        self.assertEqual(0, result.rows_written)

    def test_sync_profile_allows_explicit_override(self) -> None:
        captured: dict[str, int] = {}

        def fake_discovery(results_per_query: int = 10, max_candidates: int = 20, query_terms=None, follow_article_links: bool = True, enable_duckduckgo: bool = True):
            captured["results_per_query"] = results_per_query
            captured["max_candidates"] = max_candidates
            return {"search_queries": [], "query_count": 0, "result_count": 0, "discovered_vuln_ids": [], "search_hits": [], "urls": []}

        with patch("sync.fetch_hot.discover_hot_candidates", side_effect=fake_discovery), patch(
            "sync.fetch_hot.collect_hot_evidence_for_vuln",
            return_value=None,
        ):
            fetch_hot.sync(
                cutoff="2026-05-01T00:00:00+00:00",
                profile="balanced",
                search_cap=12,
                results_per_query=14,
            )

        self.assertEqual(12, captured["max_candidates"])
        self.assertEqual(14, captured["results_per_query"])

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

            def fake_collect(
                vuln_id: str,
                title: str | None = None,
                summary: str | None = None,
                queries_per_vuln: int = 3,
                results_per_query: int = 10,
                hits=None,
            ):
                if vuln_id == "CVE-2026-45185":
                    return {
                        "score": 0.95,
                        "query_count": 3,
                        "search_queries": ["\"Sample Application Remote Code Execution Vulnerability\""],
                        "result_count": 7,
                        "evidence_count": 3,
                        "independent_sources": 2,
                        "evidence_types": ["active_exploitation", "vendor_advisory"],
                        "source_types": ["news", "vendor"],
                        "urls": ["https://example.invalid/a", "https://example.invalid/b"],
                        "search_hits": [
                            {
                                "query": "\"Sample Application Remote Code Execution Vulnerability\"",
                                "title": "Example result",
                                "url": "https://example.invalid/a",
                                "domain": "example.invalid",
                            }
                        ],
                        "evidence_details": [
                            {
                                "evidence_type": "active_exploitation",
                                "source_type": "news",
                                "weight": 0.95,
                                "url": "https://example.invalid/a",
                                "title": "Example result",
                                "domain": "example.invalid",
                                "query": "\"Sample Application Remote Code Execution Vulnerability\"",
                                "matched_terms": ["active exploitation"],
                            }
                        ],
                        "headline": "Palo Alto advisory and coverage mention active exploitation",
                        "discovery_query_count": 5,
                        "discovery_queries": ["\"actively exploited\" CVE"],
                        "discovery_result_count": 2,
                        "discovery_hits": [
                            {
                                "query": "\"actively exploited\" CVE",
                                "title": "Example result",
                                "url": "https://example.invalid/a",
                                "domain": "example.invalid",
                                "cve_ids": ["CVE-2026-45185"],
                            }
                        ],
                        "discovered_vuln_ids": ["CVE-2026-45185"],
                    }
                return None

            with patch("sync.fetch_hot.discover_hot_candidates", return_value={"search_queries": ["https://feeds.feedburner.com/TheHackersNews"], "query_count": 1, "result_count": 1, "discovered_vuln_ids": ["CVE-2026-45185"], "search_hits": [], "urls": []}), patch(
                "sync.fetch_hot.collect_hot_evidence_for_vuln", side_effect=fake_collect
            ):
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
            self.assertIn("search_queries", signal_row["value_json"])
            self.assertIsNotNone(log_row)
            self.assertEqual("hot", log_row["feed"])
            self.assertEqual("ok", log_row["status"])
            self.assertEqual(1, log_row["rows_affected"])

    def test_sync_can_evaluate_direct_vuln_ids_without_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-42945",
                    source="cve_program",
                    title="NGINX ngx_http_rewrite_module vulnerability",
                    severity="HIGH",
                    cvss_score=8.1,
                    published_at="2026-05-13T14:12:43.971Z",
                    first_seen_at="2026-05-13T14:12:43.971Z",
                )
                conn.commit()
            finally:
                conn.close()

            def fake_collect(
                vuln_id: str,
                title: str | None = None,
                summary: str | None = None,
                queries_per_vuln: int = 3,
                results_per_query: int = 10,
                hits=None,
            ):
                if vuln_id != "CVE-2026-42945":
                    return None
                return {
                    "score": 0.88,
                    "query_count": 2,
                    "search_queries": ['"NGINX ngx_http_rewrite_module vulnerability"'],
                    "result_count": 3,
                    "evidence_count": 2,
                    "independent_sources": 2,
                    "evidence_types": ["active_exploitation", "public_poc"],
                    "source_types": ["news"],
                    "urls": ["https://example.invalid/nginx"],
                    "search_hits": [
                        {
                            "query": '"NGINX ngx_http_rewrite_module vulnerability"',
                            "title": "NGINX CVE-2026-42945 actively exploited",
                            "url": "https://example.invalid/nginx",
                            "domain": "example.invalid",
                        }
                    ],
                    "evidence_details": [
                        {
                            "evidence_type": "active_exploitation",
                            "source_type": "news",
                            "weight": 0.95,
                            "url": "https://example.invalid/nginx",
                            "title": "NGINX CVE-2026-42945 actively exploited",
                            "domain": "example.invalid",
                            "query": '"NGINX ngx_http_rewrite_module vulnerability"',
                            "matched_terms": ["active exploitation"],
                        }
                    ],
                    "headline": "NGINX CVE-2026-42945 actively exploited",
                    "discovery_query_count": 0,
                    "discovery_queries": [],
                    "discovery_result_count": 0,
                    "discovery_hits": [],
                    "discovered_vuln_ids": ["CVE-2026-42945"],
                }

            with patch("sync.fetch_hot.discover_hot_candidates") as discover_mock, patch(
                "sync.fetch_hot.collect_hot_evidence_for_vuln", side_effect=fake_collect
            ):
                result = fetch_hot.sync(
                    cutoff="2026-05-01T00:00:00+00:00",
                    vuln_ids=["CVE-2026-42945"],
                    db_path=core_db,
                )

            discover_mock.assert_not_called()
            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(1, result.rows_written)

            conn = connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                signal_row = conn.execute(
                    "SELECT signal_type, provider, score, value_json FROM signals WHERE vuln_id = ?",
                    ("CVE-2026-42945",),
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(signal_row)
            self.assertEqual("hot", signal_row["signal_type"])
            self.assertIn('"vuln_ids": ["CVE-2026-42945"]', signal_row["value_json"])

    def test_sync_can_fall_back_to_trivy_vuln_list_mirror_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            core_db = tmp_path / "core.db"
            source_dir = tmp_path / "vuln-list"
            advisory_dir = source_dir / "ubuntu" / "2026"
            advisory_dir.mkdir(parents=True)
            (advisory_dir / "CVE-2026-49975.json").write_text(
                """
                {
                  "Candidate": "CVE-2026-49975",
                  "Description": "HTTP/2 Bomb denial of service issue",
                  "Priority": "medium",
                  "References": [
                    "https://blog.calif.io/p/codex-discovered-a-hidden-http2-bomb"
                  ],
                  "Patches": {
                    "apache2": {
                      "jammy": {"Status": "released", "Note": "2.4.52-1ubuntu4.21"}
                    }
                  }
                }
                """.strip(),
                encoding="utf-8",
            )
            migrate(core_db)
            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-49975",
                    source="trivy",
                    title="HTTP/2 Bomb denial of service issue",
                    summary="HTTP/2 Bomb denial of service issue",
                    severity="MEDIUM",
                    cvss_score=None,
                    published_at="2026-06-03T00:00:00Z",
                    first_seen_at="2026-06-03T00:00:00Z",
                )
                conn.commit()
            finally:
                conn.close()

            def fake_collect(
                vuln_id: str,
                title: str | None = None,
                summary: str | None = None,
                queries_per_vuln: int = 3,
                results_per_query: int = 10,
                hits=None,
            ):
                if hits is None:
                    return None
                return {
                    "score": 0.76,
                    "query_count": 2,
                    "search_queries": ['"HTTP/2 Bomb" exploit OR PoC OR "active exploitation"'],
                    "result_count": len(hits),
                    "evidence_count": 1,
                    "independent_sources": 1,
                    "evidence_types": ["public_poc"],
                    "source_types": ["search"],
                    "urls": [hit.url for hit in hits],
                    "search_hits": [
                        {
                            "query": hit.query,
                            "title": hit.title,
                            "url": hit.url,
                            "domain": hit.domain,
                        }
                        for hit in hits
                    ],
                    "evidence_details": [
                        {
                            "evidence_type": "public_poc",
                            "source_type": "search",
                            "weight": 0.6,
                            "url": hit.url,
                            "title": hit.title,
                            "domain": hit.domain,
                            "query": hit.query,
                            "matched_terms": ["exploit"],
                        }
                        for hit in hits
                    ],
                    "headline": "Codex Discovered a Hidden HTTP/2 Bomb",
                    "discovery_query_count": 0,
                    "discovery_queries": [],
                    "discovery_result_count": 0,
                    "discovery_hits": [],
                    "discovered_vuln_ids": ["CVE-2026-49975"],
                }

            with patch("sync.fetch_hot.TRIVY_VULN_LIST_DEFAULT_DIR", source_dir), patch(
                "sync.fetch_hot.collect_hot_evidence_for_vuln", side_effect=fake_collect
            ):
                result = fetch_hot.sync(
                    cutoff="2026-05-01T00:00:00+00:00",
                    vuln_ids=["CVE-2026-49975"],
                    db_path=core_db,
                )

            self.assertEqual(1, result.rows_fetched)
            self.assertEqual(1, result.rows_written)

            conn = connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                signal_row = conn.execute(
                    "SELECT signal_type, provider, score, value_json FROM signals WHERE vuln_id = ? AND signal_type = 'hot' ORDER BY id DESC LIMIT 1",
                    ("CVE-2026-49975",),
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(signal_row)
            self.assertEqual("hot", signal_row["signal_type"])
            self.assertIn("codex-discovered-a-hidden-http2-bomb", signal_row["value_json"])

    def test_sync_logs_error_when_some_candidates_fail(self) -> None:
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
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-45186",
                    source="cve_program",
                    title="Second Sample Remote Code Execution Vulnerability",
                    severity="HIGH",
                    cvss_score=7.1,
                    published_at="2026-05-29",
                    first_seen_at="2026-05-13T18:15:10.172Z",
                )
                conn.commit()
            finally:
                conn.close()

            def fake_collect(
                vuln_id: str,
                title: str | None = None,
                summary: str | None = None,
                queries_per_vuln: int = 3,
                results_per_query: int = 10,
                hits=None,
            ):
                if vuln_id == "CVE-2026-45185":
                    return {
                        "score": 0.91,
                        "query_count": 2,
                        "search_queries": ['"Sample Application Remote Code Execution Vulnerability"'],
                        "result_count": 4,
                        "evidence_count": 2,
                        "independent_sources": 2,
                        "evidence_types": ["active_exploitation"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/a"],
                        "search_hits": [],
                        "evidence_details": [],
                        "headline": "working candidate",
                        "discovery_query_count": 1,
                        "discovery_queries": ['"Sample Application Remote Code Execution Vulnerability"'],
                        "discovery_result_count": 1,
                        "discovery_hits": [],
                        "discovered_vuln_ids": ["CVE-2026-45185", "CVE-2026-45186"],
                    }
                raise RuntimeError("transient fetch failure")

            with patch(
                "sync.fetch_hot.discover_hot_candidates",
                return_value={
                    "search_queries": ["https://feeds.feedburner.com/TheHackersNews"],
                    "query_count": 1,
                    "result_count": 2,
                    "discovered_vuln_ids": ["CVE-2026-45185", "CVE-2026-45186"],
                    "search_hits": [],
                    "urls": [],
                    "fetch_errors": [],
                },
            ), patch("sync.fetch_hot.collect_hot_evidence_for_vuln", side_effect=fake_collect):
                result = fetch_hot.sync(cutoff="2026-05-01T00:00:00+00:00", search_cap=5, db_path=core_db)

            self.assertEqual(2, result.rows_fetched)
            self.assertEqual(1, result.rows_written)

            conn = connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                log_row = conn.execute(
                    "SELECT feed, status, rows_affected, error_msg FROM fetch_log ORDER BY id DESC LIMIT 1"
                ).fetchone()
            finally:
                conn.close()

            self.assertIsNotNone(log_row)
            self.assertEqual("hot", log_row["feed"])
            self.assertEqual("error", log_row["status"])
            self.assertEqual(1, log_row["rows_affected"])
            self.assertIn("search failures for 1 candidate(s)", log_row["error_msg"])


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
                        "query_count": 3,
                        "search_queries": ["\"Example Hot Vulnerability\""],
                        "result_count": 2,
                        "evidence_count": 1,
                        "independent_sources": 1,
                        "evidence_types": ["news_mention"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/old"],
                        "search_hits": [],
                        "evidence_details": [],
                        "headline": "older observation",
                        "discovery_query_count": 1,
                        "discovery_queries": ["\"Example Hot Vulnerability\""],
                        "discovery_result_count": 1,
                        "discovery_hits": [],
                        "discovered_vuln_ids": ["CVE-2026-9999"],
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
                        "query_count": 3,
                        "search_queries": ["\"Example Hot Vulnerability\""],
                        "result_count": 6,
                        "evidence_count": 3,
                        "independent_sources": 2,
                        "evidence_types": ["active_exploitation", "vendor_advisory"],
                        "source_types": ["vendor", "news"],
                        "urls": ["https://example.invalid/new"],
                        "search_hits": [],
                        "evidence_details": [],
                        "headline": "newer observation",
                        "discovery_query_count": 1,
                        "discovery_queries": ["\"Example Hot Vulnerability\""],
                        "discovery_result_count": 1,
                        "discovery_hits": [],
                        "discovered_vuln_ids": ["CVE-2026-9999"],
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
                        "query_count": 3,
                        "search_queries": ["\"Another Hot Vulnerability\""],
                        "result_count": 2,
                        "evidence_count": 1,
                        "independent_sources": 1,
                        "evidence_types": ["news_mention"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/other"],
                        "search_hits": [],
                        "evidence_details": [],
                        "headline": "lower hot score but higher CVSS",
                        "discovery_query_count": 1,
                        "discovery_queries": ["\"Another Hot Vulnerability\""],
                        "discovery_result_count": 1,
                        "discovery_hits": [],
                        "discovered_vuln_ids": ["CVE-2026-9998"],
                    },
                    observed_at="2026-05-30T00:00:00+00:00",
                )
                conn.commit()
            finally:
                conn.close()

            rows = skills.top_hot(limit=10, db_path=core_db)

            self.assertEqual(2, len(rows))
            self.assertEqual("CVE-2026-9999", rows[0]["vuln_id"])
            self.assertEqual("newer observation", rows[0]["headline"])
            self.assertEqual("CVE-2026-9998", rows[1]["vuln_id"])
            self.assertEqual("lower hot score but higher CVSS", rows[1]["headline"])
            self.assertAlmostEqual(0.87, rows[0]["hot_score"], places=2)
            self.assertIn("kev_present", rows[0])
            self.assertIn("exploit_present", rows[0])
            self.assertIn("epss_score", rows[0])
            self.assertIn("cvss_score", rows[0])
            self.assertIn("published_at", rows[0])
            self.assertIn("query_count", rows[0])
            self.assertIn("search_queries", rows[0])
            self.assertIn("source_label", rows[0])

    def test_top_hot_prefers_most_recent_signal_over_higher_old_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-9996",
                    source="ghsa",
                    title="Stale Hot Signal Sample",
                    severity="HIGH",
                    cvss_score=8.4,
                    published_at="2026-05-20T00:00:00Z",
                    first_seen_at="2026-05-20T00:00:00Z",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2026-9996",
                    signal_type="hot",
                    provider="Web Hot Intel",
                    score=0.95,
                    value={
                        "search_budget": 5,
                        "query_count": 3,
                        "search_queries": ["\"Stale Hot Signal Sample\""],
                        "result_count": 7,
                        "evidence_count": 3,
                        "independent_sources": 2,
                        "evidence_types": ["active_exploitation"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/older"],
                        "search_hits": [],
                        "evidence_details": [],
                        "headline": "older high score",
                        "discovery_query_count": 1,
                        "discovery_queries": ["\"Stale Hot Signal Sample\""],
                        "discovery_result_count": 1,
                        "discovery_hits": [],
                        "discovered_vuln_ids": ["CVE-2026-9996"],
                    },
                    observed_at="2026-05-30T00:00:00+00:00",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2026-9996",
                    signal_type="hot",
                    provider="Web Hot Intel",
                    score=0.15,
                    value={
                        "search_budget": 5,
                        "query_count": 3,
                        "search_queries": ["\"Stale Hot Signal Sample\""],
                        "result_count": 2,
                        "evidence_count": 1,
                        "independent_sources": 1,
                        "evidence_types": ["news_mention"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/newer"],
                        "search_hits": [],
                        "evidence_details": [],
                        "headline": "newer low score",
                        "discovery_query_count": 1,
                        "discovery_queries": ["\"Stale Hot Signal Sample\""],
                        "discovery_result_count": 1,
                        "discovery_hits": [],
                        "discovered_vuln_ids": ["CVE-2026-9996"],
                    },
                    observed_at="2026-05-31T00:00:00+00:00",
                )
                conn.commit()
            finally:
                conn.close()

            rows = skills.top_hot(limit=5, db_path=core_db)

            self.assertEqual(1, len(rows))
            self.assertEqual("newer low score", rows[0]["headline"])
            self.assertEqual("2026-05-31T00:00:00+00:00", rows[0]["observed_at"])
            self.assertAlmostEqual(0.15, rows[0]["signal_score"], places=2)

    def test_top_hot_exposes_hatena_source_label(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            core_db = Path(tmp) / "core.db"
            migrate(core_db)
            conn = sqlite3.connect(core_db)
            conn.row_factory = sqlite3.Row
            try:
                upsert_vulnerability(
                    conn,
                    vuln_id="CVE-2026-49975",
                    source="cve_program",
                    title="HTTP/2 Bomb denial of service issue",
                    severity="HIGH",
                    cvss_score=7.5,
                    published_at="2026-06-03T00:00:00Z",
                    first_seen_at="2026-06-03T00:00:00Z",
                )
                append_signal(
                    conn,
                    vuln_id="CVE-2026-49975",
                    signal_type="hot",
                    provider="Web Hot Intel",
                    score=0.81,
                    value={
                        "search_budget": 3,
                        "query_count": 3,
                        "search_queries": ['"HTTP/2 Bomb"'],
                        "result_count": 1,
                        "evidence_count": 1,
                        "independent_sources": 1,
                        "evidence_types": ["hatena_popular"],
                        "source_types": ["social"],
                        "urls": ["https://b.hatena.ne.jp/entry/s/qiita.com/long-910/items/76779fc1d8602dab73b3"],
                        "search_hits": [
                            {
                                "query": "https://b.hatena.ne.jp/q/HTTP%2F2%20Bomb?users=20&sort=popular&date_range=m&safe=on&target=text",
                                "title": "CVE-2026-49975「HTTP/2 Bomb」をわかりやすく解説——AIが人間より先に気づいた脆弱性 - Qiita",
                                "url": "https://b.hatena.ne.jp/entry/s/qiita.com/long-910/items/76779fc1d8602dab73b3",
                                "domain": "b.hatena.ne.jp",
                                "source_label": "Hatena Bookmark",
                            }
                        ],
                        "evidence_details": [
                            {
                                "evidence_type": "hatena_popular",
                                "source_type": "social",
                                "source_label": "Hatena Bookmark",
                                "weight": 0.55,
                                "url": "https://b.hatena.ne.jp/entry/s/qiita.com/long-910/items/76779fc1d8602dab73b3",
                                "title": "CVE-2026-49975「HTTP/2 Bomb」をわかりやすく解説——AIが人間より先に気づいた脆弱性 - Qiita",
                                "domain": "b.hatena.ne.jp",
                                "query": "https://b.hatena.ne.jp/q/HTTP%2F2%20Bomb?users=20&sort=popular&date_range=m&safe=on&target=text",
                                "matched_terms": ["CVE-2026-49975"],
                            }
                        ],
                        "headline": "Hatena popular entry for HTTP/2 Bomb",
                        "discovery_query_count": 1,
                        "discovery_queries": ["https://b.hatena.ne.jp/q/HTTP%2F2%20Bomb?users=20&sort=popular&date_range=m&safe=on&target=text"],
                        "discovery_result_count": 1,
                        "discovery_hits": [],
                        "discovered_vuln_ids": ["CVE-2026-49975"],
                    },
                    observed_at="2026-06-10T00:00:00+00:00",
                )
                conn.commit()
            finally:
                conn.close()

            rows = skills.top_hot(limit=5, db_path=core_db)

            self.assertEqual(1, len(rows))
            self.assertEqual("Hatena Bookmark", rows[0]["source_label"])

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
                        "query_count": 3,
                        "search_queries": ["\"CLI Label Sample\""],
                        "result_count": 1,
                        "evidence_count": 1,
                        "independent_sources": 1,
                        "evidence_types": ["news_mention"],
                        "source_types": ["news"],
                        "urls": ["https://example.invalid/cli"],
                        "search_hits": [],
                        "evidence_details": [],
                        "headline": "cli label sample",
                        "discovery_query_count": 1,
                        "discovery_queries": ["\"CLI Label Sample\""],
                        "discovery_result_count": 1,
                        "discovery_hits": [],
                        "discovered_vuln_ids": ["CVE-2026-9997"],
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
            self.assertIn("priority [hot / KEV / exploit / EPSS / CVSS / published_at]", output)
            self.assertIn("hot_score\tkev_present\texploit_present\tepss_score\tcvss_score\tpublished_at\tfirst_seen_at\tvuln_id", output)
            self.assertNotIn("hot_reference [reference-only]", output)

            buf = StringIO()
            with redirect_stdout(buf):
                skills._print_hot_rows(skills.top_hot(limit=5, db_path=core_db), details=True)

            output = buf.getvalue()
            self.assertIn("hot_reference [reference-only]", output)
            self.assertIn("vuln_id\tsignal_score\tobserved_at\tsource\tseverity\ttitle\tsource_label\tquery_count\tsearch_queries\tsearch_budget\tresult_count\tevidence_count\tindependent_sources\tevidence_types\tsource_types\turls\theadline\tdiscovery_query_count\tdiscovery_queries\tdiscovery_result_count\tdiscovery_hits\tdiscovered_vuln_ids", output)
