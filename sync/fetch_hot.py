#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from sync.common import FetchResult, append_signal, connect, log_fetch, utc_now
from sync.hot_intel import collect_hot_evidence_for_vuln


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


def _candidate_query(cutoff: str) -> str:
    return """
        SELECT vuln_id, source, title, severity, cvss_score, published_at, first_seen_at
        FROM vulnerabilities
        WHERE first_seen_at >= ?
        ORDER BY
          COALESCE(cvss_score, 0) DESC,
          CASE WHEN source = 'kev' THEN 1 ELSE 0 END DESC,
          CASE WHEN source = 'ghsa' THEN 1 ELSE 0 END DESC,
          first_seen_at DESC,
          vuln_id ASC
    """


def _load_candidates(conn, cutoff: str, search_cap: int) -> tuple[list[dict[str, Any]], int]:
    rows = list(conn.execute(_candidate_query(cutoff), (cutoff,)).fetchall())
    total = 0
    candidates: list[dict[str, Any]] = []
    for row in rows:
        if _is_boundary(row["title"], row["source"]):
            continue
        total += 1
        if len(candidates) < search_cap:
            candidates.append(
                {
                    "vuln_id": row["vuln_id"],
                    "source": row["source"],
                    "title": row["title"],
                    "severity": row["severity"],
                    "cvss_score": row["cvss_score"],
                    "published_at": row["published_at"],
                    "first_seen_at": row["first_seen_at"],
                }
            )
    return candidates, total


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
        candidates, total_recent = _load_candidates(conn, cutoff, search_cap)
        if dry_run:
            return FetchResult(rows_fetched=len(candidates), rows_written=0, cache_used=False)

        for candidate in candidates:
            try:
                evidence = collect_hot_evidence_for_vuln(
                    candidate["vuln_id"],
                    title=candidate.get("title"),
                    queries_per_vuln=queries_per_vuln,
                    results_per_query=results_per_query,
                )
            except Exception as exc:
                errors += 1
                continue

            if not evidence:
                continue

            value = {
                "window_cutoff": cutoff,
                "report_window_count": total_recent,
                "search_budget": len(candidates),
                "search_cap": search_cap,
                "query_budget": queries_per_vuln,
                "results_per_query": results_per_query,
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
    parser.add_argument("--cutoff", help="ISO8601 cutoff for the report window. Defaults to seven days ago.")
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
