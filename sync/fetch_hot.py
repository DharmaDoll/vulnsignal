#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from collections import defaultdict

from sync.common import run_measured, FetchResult, append_signal, connect, log_fetch, utc_now
from sync.hot_intel import SearchHit, collect_hot_evidence_for_vuln, discover_hot_candidates


FEED = "hot"
PROVIDER = "Web Hot Intel"
DEFAULT_SEARCH_CAP = 20
DEFAULT_RESULTS_PER_QUERY = 20
DEFAULT_QUERIES_PER_VULN = 3
HOT_PROFILES = {
    "strict": {"search_cap": 10, "results_per_query": 10, "queries_per_vuln": 2},
    "balanced": {"search_cap": 20, "results_per_query": 20, "queries_per_vuln": 3},
    "broad": {"search_cap": 30, "results_per_query": 30, "queries_per_vuln": 4},
}


def _default_cutoff(days: int = 7) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


def _load_candidates(conn, vuln_ids: list[str]) -> list[dict[str, Any]]:
    if not vuln_ids:
        return []
    placeholders = ",".join("?" for _ in vuln_ids)
    rows = list(
        conn.execute(
            f"""
            SELECT vuln_id, source, title, summary, severity, cvss_score, published_at, first_seen_at
            FROM vulnerabilities
            WHERE vuln_id IN ({placeholders})
            """,
            tuple(vuln_ids),
        ).fetchall()
    )
    by_id = {row["vuln_id"]: row for row in rows}
    candidates: list[dict[str, Any]] = []
    for vuln_id in vuln_ids:
        row = by_id.get(vuln_id)
        if row is None:
            continue
        # Historical Trivy imports can fill fields on an existing canonical row.
        if str(row["source"]).lower().startswith("trivy") or conn.execute(
            "SELECT 1 FROM signals WHERE vuln_id=? AND lower(provider) LIKE 'trivy%' LIMIT 1",
            (vuln_id,),
        ).fetchone():
            trusted = conn.execute("""
                SELECT provider,value_json FROM signals WHERE vuln_id=?
                  AND provider IN ('CVE Program','GitHub Advisory Database','CISA KEV')
                ORDER BY observed_at DESC,id DESC
            """, (vuln_id,))
            metadata = {}
            for evidence in trusted:
                value = json.loads(evidence["value_json"] or "{}")
                for key in ("title", "summary", "product", "package_name", "severity", "cvss_score", "published_at"):
                    if value.get(key) is not None:
                        metadata.setdefault(key, value[key])
            if not metadata:
                continue
            row = {**dict.fromkeys(row.keys()), **metadata, "source": "provider evidence", "vuln_id": vuln_id,
                   "title": metadata.get("title") or metadata.get("product") or metadata.get("package_name")}
        candidates.append(
            {
                "vuln_id": row["vuln_id"],
                "source": row["source"],
                "title": row["title"],
                "summary": row["summary"],
                "severity": row["severity"],
                "cvss_score": row["cvss_score"],
                "published_at": row["published_at"],
                "first_seen_at": row["first_seen_at"],
            }
        )
    return candidates


def _candidate_hits(discovery_hits: list[dict[str, Any]]) -> dict[str, list[SearchHit]]:
    hits_by_vuln: dict[str, list[SearchHit]] = defaultdict(list)
    for hit in discovery_hits:
        title = " ".join(part for part in (hit.get("title"), hit.get("summary")) if part)
        search_hit = SearchHit(
            query=str(hit.get("query") or hit.get("feed") or ""),
            title=title or str(hit.get("title") or ""),
            url=str(hit.get("url") or ""),
            domain=str(hit.get("domain") or ""),
            metadata={**(hit.get("metadata") or {}), "published_at": hit.get("published_at")},
        )
        for vuln_id in hit.get("cve_ids", []):
            hits_by_vuln[vuln_id].append(search_hit)
    return hits_by_vuln


def sync(
    cutoff: str | None = None,
    search_cap: int | None = None,
    queries_per_vuln: int | None = None,
    results_per_query: int | None = None,
    query_terms: list[str] | None = None,
    vuln_ids: list[str] | None = None,
    simple: bool = False,
    profile: str | None = None,
    dry_run: bool = False,
    db_path: Path | None = None,
) -> FetchResult:
    cutoff = cutoff or _default_cutoff()
    search_cap = DEFAULT_SEARCH_CAP if search_cap is None else search_cap
    queries_per_vuln = DEFAULT_QUERIES_PER_VULN if queries_per_vuln is None else queries_per_vuln
    results_per_query = DEFAULT_RESULTS_PER_QUERY if results_per_query is None else results_per_query
    if profile:
        selected = HOT_PROFILES.get(profile)
        if selected is None:
            raise ValueError(f"unknown hot profile: {profile}")
        search_cap = selected["search_cap"] if search_cap == DEFAULT_SEARCH_CAP else search_cap
        results_per_query = selected["results_per_query"] if results_per_query == DEFAULT_RESULTS_PER_QUERY else results_per_query
        queries_per_vuln = selected["queries_per_vuln"] if queries_per_vuln == DEFAULT_QUERIES_PER_VULN else queries_per_vuln
    conn = connect(db_path) if db_path is not None else connect()
    written = 0
    errors = 0
    candidates: list[dict[str, Any]] = []
    try:
        discovery: dict[str, Any]
        if vuln_ids:
            candidate_ids = list(dict.fromkeys(vuln_ids))
            candidates = _load_candidates(conn, candidate_ids)
            discovery = {
                "search_queries": [],
                "query_count": 0,
                "result_count": 0,
                "discovered_vuln_ids": [candidate["vuln_id"] for candidate in candidates],
                "search_hits": [],
                "urls": [],
                "fetch_errors": [],
            }
            hits_by_vuln = None
        else:
            discovery = discover_hot_candidates(
                results_per_query=results_per_query,
                max_candidates=search_cap,
                query_terms=query_terms,
                follow_article_links=not simple,
                enable_duckduckgo=not simple,
                enable_hatena=not simple,
            )
            candidates = _load_candidates(conn, discovery["discovered_vuln_ids"])
            hits_by_vuln = _candidate_hits(discovery["search_hits"])
        if dry_run:
            return FetchResult(rows_fetched=len(candidates), rows_written=0, cache_used=False)

        for candidate in candidates:
            try:
                evidence = collect_hot_evidence_for_vuln(
                    candidate["vuln_id"],
                    title=candidate.get("title"),
                    summary=candidate.get("summary"),
                    queries_per_vuln=queries_per_vuln,
                    results_per_query=results_per_query,
                    hits=hits_by_vuln.get(candidate["vuln_id"], []) if hits_by_vuln is not None else None,
                )
            except Exception as exc:
                errors += 1
                continue

            if not evidence:
                continue

            value = {
                "window_cutoff": cutoff,
                "search_budget": len(discovery["discovered_vuln_ids"]),
                "search_cap": search_cap,
                "query_budget": queries_per_vuln,
                "results_per_query": results_per_query,
                "discovery_queries": discovery["search_queries"],
                "discovery_query_count": discovery["query_count"],
                "discovery_result_count": discovery["result_count"],
                "hot_rule_version": 2,
                "discovery_hits": [hit for hit in discovery["search_hits"]
                                   if candidate["vuln_id"] in hit.get("cve_ids", [])][:10],
                "discovered_vuln_ids": discovery["discovered_vuln_ids"],
                "fetch_errors": discovery.get("fetch_errors", []),
                "query_terms": query_terms or [],
                "vuln_ids": vuln_ids or [],
                **evidence,
            }
            if append_signal(
                conn,
                vuln_id=candidate["vuln_id"],
                signal_type="hot",
                provider=PROVIDER,
                score=evidence["score"],
                value=value,
                observed_at=utc_now(),
            ):
                written += 1
                conn.commit()

        if discovery.get("fetch_errors") and not discovery.get("result_count"):
            log_fetch(conn, FEED, "error", written, "discovery returned no results after source failures")
        elif errors:
            log_fetch(conn, FEED, "error", written, f"search failures for {errors} candidate(s)")
        else:
            log_fetch(conn, FEED, "ok", written)
        conn.commit()
        return FetchResult(rows_fetched=len(candidates), rows_written=written, cache_used=False)
    except Exception as exc:
        conn.rollback()
        log_fetch(conn, FEED, "error", written, str(exc))
        conn.commit()
        return FetchResult(rows_fetched=len(candidates), rows_written=written, cache_used=False)
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cutoff", help="Legacy metadata field; kept for backward-compatible logs.")
    parser.add_argument("--search-cap", type=int, default=None, help="Maximum CVEs to search per run.")
    parser.add_argument("--queries-per-vuln", type=int, default=None)
    parser.add_argument("--results-per-query", type=int, default=None)
    parser.add_argument(
        "--profile",
        choices=sorted(HOT_PROFILES),
        help="Shortcut for strict/balanced/broad hot search settings.",
    )
    parser.add_argument(
        "--query-term",
        action="append",
        default=[],
        help="Optional extra discovery term to widen hot coverage on top of the built-in baseline. Can be repeated.",
    )
    parser.add_argument(
        "--vuln-id",
        action="append",
        default=[],
        help="Directly evaluate one or more vuln_ids for hot evidence without discovery. Can be repeated.",
    )
    parser.add_argument(
        "--simple",
        action="store_true",
        help="Run RSS-only discovery without article-body or DuckDuckGo expansion.",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = run_measured(FEED, sync,
        cutoff=args.cutoff,
        search_cap=args.search_cap,
        queries_per_vuln=args.queries_per_vuln,
        results_per_query=args.results_per_query,
        query_terms=args.query_term,
        vuln_ids=args.vuln_id,
        simple=args.simple,
        profile=args.profile,
        dry_run=args.dry_run,
    )
    print(result)


if __name__ == "__main__":
    main()
