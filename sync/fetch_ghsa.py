#!/usr/bin/env python3
from __future__ import annotations

import argparse
from typing import Any
from urllib.parse import urlencode

from sync.common import (
    FetchResult,
    append_signal,
    connect,
    fetch_json,
    log_fetch,
    read_cache,
    upsert_vulnerability,
    utc_now,
    write_cache,
)


FEED = "ghsa"
URL = "https://api.github.com/advisories"


def load_payload(limit: int, cache_only: bool, ecosystem: str | None = None) -> tuple[list[dict[str, Any]], bool]:
    if cache_only:
        return read_cache(FEED), True

    rows: list[dict[str, Any]] = []
    page = 1
    try:
        while len(rows) < limit:
            per_page = min(100, limit - len(rows))
            params = {"type": "reviewed", "per_page": str(per_page), "page": str(page)}
            if ecosystem:
                params["ecosystem"] = ecosystem
            payload = fetch_json(
                f"{URL}?{urlencode(params)}",
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "vulnsignal/0.1",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            if not payload:
                break
            rows.extend(payload)
            page += 1
        write_cache(FEED, rows)
        return rows, False
    except Exception:
        return read_cache(FEED), True


def external_ids(item: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    cve_id = item.get("cve_id")
    ghsa_id = item.get("ghsa_id")
    if cve_id:
        ids.append(cve_id)
    if ghsa_id:
        ids.append(ghsa_id)
    return ids


def patched_version(value: Any) -> str | None:
    if isinstance(value, dict):
        return value.get("identifier")
    if isinstance(value, str):
        return value
    return None


def sync(
    limit: int = 100,
    dry_run: bool = False,
    cache_only: bool = False,
    ecosystem: str | None = None,
) -> FetchResult:
    rows, cache_used = load_payload(limit, cache_only, ecosystem)
    rows = rows[:limit]

    if dry_run:
        return FetchResult(rows_fetched=len(rows), rows_written=0, cache_used=cache_used)

    conn = connect()
    written = 0
    try:
        for item in rows:
            ids = external_ids(item)
            if not ids:
                continue

            cvss = item.get("cvss") or {}
            cvss_score = cvss.get("score")
            for vuln_id in ids:
                upsert_vulnerability(
                    conn,
                    vuln_id=vuln_id,
                    source="ghsa",
                    title=item.get("summary"),
                    summary=item.get("description"),
                    severity=item.get("severity"),
                    cvss_score=float(cvss_score) if cvss_score is not None else None,
                    cvss_source="GHSA" if cvss_score is not None else None,
                    published_at=item.get("published_at"),
                    updated_at=item.get("updated_at"),
                )
                append_signal(
                    conn,
                    vuln_id=vuln_id,
                    signal_type="enrichment",
                    provider="GitHub Advisory Database",
                    score=float(cvss_score) if cvss_score is not None else None,
                    value={
                        "ghsa_id": item.get("ghsa_id"),
                        "cve_id": item.get("cve_id"),
                        "severity": item.get("severity"),
                        "cvss": cvss,
                        "cwes": item.get("cwes"),
                        "url": item.get("url") or item.get("html_url"),
                    },
                    observed_at=utc_now(),
                )
                written += 1

            for vulnerability in item.get("vulnerabilities") or []:
                package = vulnerability.get("package") or {}
                for vuln_id in ids:
                    append_signal(
                        conn,
                        vuln_id=vuln_id,
                        signal_type="package_advisory",
                        provider="GitHub Advisory Database",
                        score=None,
                        value={
                            "ghsa_id": item.get("ghsa_id"),
                            "cve_id": item.get("cve_id"),
                            "ecosystem": package.get("ecosystem"),
                            "package_name": package.get("name"),
                            "affected_versions": vulnerability.get("vulnerable_version_range"),
                            "fixed_version": patched_version(vulnerability.get("first_patched_version")),
                            "vulnerable_functions": vulnerability.get("vulnerable_functions"),
                        },
                        observed_at=utc_now(),
                    )
                    written += 1

        log_fetch(conn, FEED, "ok", written)
        conn.commit()
        return FetchResult(rows_fetched=len(rows), rows_written=written, cache_used=cache_used)
    except Exception as exc:
        conn.rollback()
        log_fetch(conn, FEED, "error", written, str(exc))
        conn.commit()
        raise
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--ecosystem")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--cache-only", action="store_true")
    args = parser.parse_args()
    result = sync(
        limit=args.limit,
        dry_run=args.dry_run,
        cache_only=args.cache_only,
        ecosystem=args.ecosystem,
    )
    print(result)


if __name__ == "__main__":
    main()
