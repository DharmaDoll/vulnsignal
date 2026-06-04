#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from collections import defaultdict

from sync.common import FetchResult, append_signal, connect, log_fetch, utc_now
from sync.hot_intel import SearchHit, collect_hot_evidence_for_vuln, discover_hot_candidates


FEED = "hot"
PROVIDER = "Web Hot Intel"
DEFAULT_SEARCH_CAP = 20
DEFAULT_RESULTS_PER_QUERY = 5
DEFAULT_QUERIES_PER_VULN = 3
BOUNDARY_HINTS = ("cisco", "palo alto", "fortinet", "juniper", "f5", "watchguard", "sonicwall", "checkpoint")


def _default_cutoff(days: int = 7) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")


def _is_boundary(title: str | None, source: str | None) -> bool:
    text = f"{title or ''} {source or ''}".lower()
    return any(hint in text for hint in BOUNDARY_HINTS)


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
        if _is_boundary(row["title"], row["source"]):
            continue
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
        )
        for vuln_id in hit.get("cve_ids", []):
            hits_by_vuln[vuln_id].append(search_hit)
    return hits_by_vuln


def sync(
    cutoff: str | None = None,
    search_cap: int = DEFAULT_SEARCH_CAP,
    queries_per_vuln: int = DEFAULT_QUERIES_PER_VULN,
    results_per_query: int = DEFAULT_RESULTS_PER_QUERY,
    dry_run: bool = False,
    db_path: Path | None = None,
) -> FetchResult:
    cutoff = cutoff or _default_cutoff()
    conn = connect(db_path) if db_path is not None else connect()
    written = 0
    errors = 0
    candidates: list[dict[str, Any]] = []
    try:
        discovery = discover_hot_candidates(results_per_query=results_per_query, max_candidates=search_cap)
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
                    hits=hits_by_vuln.get(candidate["vuln_id"], []),
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
                "discovery_hits": discovery["search_hits"],
                "discovered_vuln_ids": discovery["discovered_vuln_ids"],
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

        if errors and written == 0:
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
    parser.add_argument("--search-cap", type=int, default=DEFAULT_SEARCH_CAP, help="Maximum CVEs to search per run.")
    parser.add_argument("--queries-per-vuln", type=int, default=DEFAULT_QUERIES_PER_VULN)
    parser.add_argument("--results-per-query", type=int, default=DEFAULT_RESULTS_PER_QUERY)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = sync(
        cutoff=args.cutoff,
        search_cap=args.search_cap,
        queries_per_vuln=args.queries_per_vuln,
        results_per_query=args.results_per_query,
        dry_run=args.dry_run,
    )
    print(result)


if __name__ == "__main__":
    main()
