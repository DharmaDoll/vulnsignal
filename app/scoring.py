from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sync.hot_intel import attention_score_from_value


SCORING_VERSION = "v1"
MIN_YEAR = 2015
DEFAULT_REPORT_KEY = "alerts"
CRITICALITY_BONUS = {
    "critical": 10,
    "high": 7,
    "medium": 3,
    "low": 0,
}
FRESHNESS_THRESHOLDS_HOURS = {
    "kev": 3,
    "hot": 24,
    "epss": 48,
    "ghsa": 24,
    "trivy": 24,
    "trivy_vuln_list": 24,
    "trivy_db": 24,
    "go-exploitdb": 48,
    "vulnrichment": 48,
    "vex": 48,
    "nvd": 24,
}


@dataclass(frozen=True)
class ScoredFinding:
    asset_id: str
    hostname: str
    vuln_id: str
    risk_score: int
    raw_score: float
    cvss_score: float
    epss_score: float
    kev_present: bool
    exploit_present: bool
    vex_suppressed: bool
    criticality_bonus: int
    exposure_bonus: int
    score_breakdown: dict[str, Any]
    scoring_version: str = SCORING_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "hostname": self.hostname,
            "vuln_id": self.vuln_id,
            "risk_score": self.risk_score,
            "raw_score": self.raw_score,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "kev_present": self.kev_present,
            "exploit_present": self.exploit_present,
            "vex_suppressed": self.vex_suppressed,
            "criticality_bonus": self.criticality_bonus,
            "exposure_bonus": self.exposure_bonus,
            "score_breakdown": self.score_breakdown,
            "scoring_version": self.scoring_version,
        }


def _parse_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _normalize_report_key(report_key: str | None) -> str:
    if report_key is None:
        return DEFAULT_REPORT_KEY
    key = report_key.strip()
    return key or DEFAULT_REPORT_KEY


def _latest_signals(conn: sqlite3.Connection, vuln_id: str) -> dict[str, sqlite3.Row]:
    latest: dict[str, sqlite3.Row] = {}
    rows = conn.execute(
        """
        SELECT id, signal_type, provider, score, value_json, observed_at
        FROM signals
        WHERE vuln_id = ?
        ORDER BY signal_type, observed_at DESC, id DESC
        """,
        (vuln_id,),
    ).fetchall()
    for row in rows:
        signal_type = row["signal_type"]
        if signal_type not in latest:
            latest[signal_type] = row
    return latest


def _signal_value(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    return _parse_json(row["value_json"])


def _signal_score(row: sqlite3.Row | None) -> float:
    if row is None or row["score"] is None:
        return 0.0
    return float(row["score"])


def _criticality_bonus(value: str | None) -> int:
    if not value:
        return 0
    return CRITICALITY_BONUS.get(value.lower(), 0)


def _vex_suppressed(latest: dict[str, sqlite3.Row]) -> bool:
    vex = latest.get("vex")
    if not vex:
        return False
    value = _signal_value(vex)
    return str(value.get("status", "")).lower() == "not_affected"


def _has_any_signal(latest: dict[str, sqlite3.Row], signal_type: str) -> bool:
    return signal_type in latest


def _epss_score(conn: sqlite3.Connection, vuln_id: str) -> float:
    row = conn.execute("SELECT epss FROM epss_current WHERE vuln_id = ?", (vuln_id,)).fetchone()
    return float(row["epss"]) if row and row["epss"] is not None else 0.0


def _score_components(
    cvss_score: float,
    epss_score: float,
    kev_present: bool,
    exploit_present: bool,
    exposure_bonus: int,
    criticality_bonus: int,
    vex_suppressed: bool,
) -> tuple[float, int, dict[str, Any]]:
    cvss_component = cvss_score * 4.0
    epss_component = epss_score * 20.0
    kev_bonus = 15 if kev_present else 0
    exploit_bonus = 10 if exploit_present else 0
    vex_suppression = 40 if vex_suppressed else 0
    raw_score = (
        cvss_component
        + epss_component
        + kev_bonus
        + exploit_bonus
        + exposure_bonus
        + criticality_bonus
        - vex_suppression
    )
    risk_score = min(100, round(raw_score))
    breakdown = {
        "components": {
            "cvss_component": cvss_component,
            "epss_component": epss_component,
            "kev_bonus": kev_bonus,
            "exploit_bonus": exploit_bonus,
            "exposure_bonus": exposure_bonus,
            "criticality_bonus": criticality_bonus,
            "vex_suppression": vex_suppression,
        },
        "raw_score": raw_score,
        "risk_score": risk_score,
    }
    return raw_score, risk_score, breakdown


def score_vulnerability(
    conn: sqlite3.Connection,
    vuln_row: sqlite3.Row,
    asset_row: sqlite3.Row | None = None,
) -> ScoredFinding:
    vuln_id = vuln_row["vuln_id"]
    latest = _latest_signals(conn, vuln_id)
    cvss_score = float(vuln_row["cvss_score"] or 0.0)
    epss_score = _epss_score(conn, vuln_id)
    kev_present = _has_any_signal(latest, "kev")
    exploit_present = _has_any_signal(latest, "exploit")
    vex_suppressed = _vex_suppressed(latest)
    exposure_bonus = 10 if asset_row is not None and int(asset_row["exposed"] or 0) == 1 else 0
    criticality_bonus = _criticality_bonus(asset_row["criticality"] if asset_row is not None else None)
    raw_score, risk_score, breakdown = _score_components(
        cvss_score=cvss_score,
        epss_score=epss_score,
        kev_present=kev_present,
        exploit_present=exploit_present,
        exposure_bonus=exposure_bonus,
        criticality_bonus=criticality_bonus,
        vex_suppressed=vex_suppressed,
    )
    return ScoredFinding(
        asset_id=asset_row["asset_id"] if asset_row is not None else "",
        hostname=asset_row["hostname"] if asset_row is not None else "",
        vuln_id=vuln_id,
        risk_score=risk_score,
        raw_score=raw_score,
        cvss_score=cvss_score,
        epss_score=epss_score,
        kev_present=kev_present,
        exploit_present=exploit_present,
        vex_suppressed=vex_suppressed,
        criticality_bonus=criticality_bonus,
        exposure_bonus=exposure_bonus,
        score_breakdown=breakdown,
    )


def iter_ranked_findings(
    conn: sqlite3.Connection,
    excluded_vuln_ids: set[str] | None = None,
) -> list[ScoredFinding]:
    rows = conn.execute(
        """
        SELECT
          f.asset_id,
          a.hostname,
          a.exposed,
          a.criticality,
          f.vuln_id,
          v.cvss_score
        FROM findings f
        JOIN assets a ON a.asset_id = f.asset_id
        JOIN vulnerabilities v ON v.vuln_id = f.vuln_id
        WHERE COALESCE(f.status, 'open') != 'suppressed'
        """
    ).fetchall()
    scored: list[ScoredFinding] = []
    for row in rows:
        if excluded_vuln_ids and row["vuln_id"] in excluded_vuln_ids:
            continue
        finding = score_vulnerability(conn, row, row)
        if not finding.vex_suppressed:
            scored.append(finding)
    scored.sort(key=lambda item: (-item.risk_score, -int(item.kev_present), item.vuln_id, item.asset_id))
    return scored


def top_risks(conn: sqlite3.Connection, limit: int | None = 20) -> list[dict[str, Any]]:
    ranked = iter_ranked_findings(conn)
    if limit is not None:
        ranked = ranked[:limit]
    return [finding.to_dict() for finding in ranked]


def recommend_patch_queue(conn: sqlite3.Connection, limit: int | None = 20) -> list[dict[str, Any]]:
    ranked = iter_ranked_findings(conn)
    ranked.sort(key=lambda item: (-item.risk_score, -int(item.kev_present), item.asset_id, item.vuln_id))
    if limit is not None:
        ranked = ranked[:limit]
    return [finding.to_dict() for finding in ranked]


def _reported_vuln_ids(conn: sqlite3.Connection, report_key: str) -> set[str]:
    rows = conn.execute(
        """
        SELECT DISTINCT vuln_id
        FROM report_history
        WHERE report_key = ?
        """,
        (_normalize_report_key(report_key),),
    ).fetchall()
    return {row["vuln_id"] for row in rows}


def top_unreported_risks(
    conn: sqlite3.Connection,
    limit: int | None = 100,
    report_key: str | None = DEFAULT_REPORT_KEY,
) -> list[dict[str, Any]]:
    reported_vuln_ids = _reported_vuln_ids(conn, _normalize_report_key(report_key))
    ranked = iter_ranked_findings(conn, excluded_vuln_ids=reported_vuln_ids)
    if limit is not None:
        ranked = ranked[:limit]
    return [finding.to_dict() for finding in ranked]


def top_new_alerts(
    conn: sqlite3.Connection,
    limit: int | None = 100,
    alert_key: str | None = DEFAULT_REPORT_KEY,
) -> list[dict[str, Any]]:
    return top_unreported_risks(conn, limit=limit, report_key=alert_key)


def record_report_history(
    conn: sqlite3.Connection,
    vuln_ids: list[str],
    report_key: str | None = DEFAULT_REPORT_KEY,
    report_run_id: str | None = None,
    payloads_by_vuln_id: dict[str, Any] | None = None,
) -> int:
    normalized_report_key = _normalize_report_key(report_key)
    payloads_by_vuln_id = payloads_by_vuln_id or {}
    reported_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    rows_written = 0
    seen_vuln_ids: set[str] = set()
    for vuln_id in vuln_ids:
        if vuln_id in seen_vuln_ids:
            continue
        seen_vuln_ids.add(vuln_id)
        payload = payloads_by_vuln_id.get(vuln_id)
        if payload is None:
            payload_json = None
        elif isinstance(payload, str):
            payload_json = payload
        else:
            payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        conn.execute(
            """
            INSERT INTO report_history (
              report_key,
              vuln_id,
              report_run_id,
              payload_json,
              reported_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (normalized_report_key, vuln_id, report_run_id, payload_json, reported_at),
        )
        rows_written += 1
    return rows_written


def record_notification_history(
    conn: sqlite3.Connection,
    vuln_ids: list[str],
    alert_key: str | None = DEFAULT_REPORT_KEY,
    notification_run_id: str | None = None,
    payloads_by_vuln_id: dict[str, Any] | None = None,
) -> int:
    return record_report_history(
        conn,
        vuln_ids=vuln_ids,
        report_key=alert_key,
        report_run_id=notification_run_id,
        payloads_by_vuln_id=payloads_by_vuln_id,
    )


def has_exploit(conn: sqlite3.Connection, vuln_id: str) -> bool:
    latest = _latest_signals(conn, vuln_id)
    return "exploit" in latest


def find_vuln(conn: sqlite3.Connection, vuln_id: str) -> dict[str, Any] | None:
    vuln_row = conn.execute(
        """
        SELECT vuln_id, source, title, summary, severity, cvss_score, cvss_source, published_at, first_seen_at, updated_at
        FROM vulnerabilities
        WHERE vuln_id = ?
        """,
        (vuln_id,),
    ).fetchone()
    if vuln_row is None:
        return None

    latest = _latest_signals(conn, vuln_id)
    signals = {
        signal_type: {
            "provider": row["provider"],
            "score": row["score"],
            "value_json": _signal_value(row),
            "observed_at": row["observed_at"],
        }
        for signal_type, row in latest.items()
    }
    asset_rows = conn.execute(
        """
        SELECT f.asset_id, a.hostname, a.exposed, a.criticality, f.status
        FROM findings f
        JOIN assets a ON a.asset_id = f.asset_id
        WHERE f.vuln_id = ? AND COALESCE(f.status, 'open') != 'suppressed'
        """,
        (vuln_id,),
    ).fetchall()
    return {
        "vulnerability": dict(vuln_row),
        "signals": signals,
        "affected_assets": [dict(row) for row in asset_rows],
        "has_exploit": "exploit" in latest,
        "vex_suppressed": _vex_suppressed(latest),
    }


def affected_assets(conn: sqlite3.Connection, vuln_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT
          f.id AS finding_id,
          f.asset_id,
          a.hostname,
          a.os,
          a.version,
          a.owner,
          a.exposed,
          a.criticality,
          f.vuln_id,
          f.risk_score AS stored_risk_score,
          f.scoring_version AS finding_scoring_version,
          f.status AS finding_status,
          f.updated_at AS finding_updated_at,
          v.source,
          v.title,
          v.summary,
          v.severity,
          v.cvss_score,
          v.cvss_source,
          v.published_at,
          v.first_seen_at,
          v.updated_at AS vuln_updated_at
        FROM findings f
        JOIN assets a ON a.asset_id = f.asset_id
        JOIN vulnerabilities v ON v.vuln_id = f.vuln_id
        WHERE f.vuln_id = ? AND COALESCE(f.status, 'open') != 'suppressed'
        ORDER BY COALESCE(f.risk_score, 0) DESC, a.hostname, a.asset_id
        """,
        (vuln_id,),
    ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        finding = score_vulnerability(conn, row, row)
        items.append(
            {
                "finding_id": row["finding_id"],
                "finding_status": row["finding_status"],
                "finding_updated_at": row["finding_updated_at"],
                "stored_risk_score": row["stored_risk_score"],
                "scoring_version": row["finding_scoring_version"] or finding.scoring_version,
                "asset": {
                    "asset_id": row["asset_id"],
                    "hostname": row["hostname"],
                    "os": row["os"],
                    "version": row["version"],
                    "owner": row["owner"],
                    "exposed": row["exposed"],
                    "criticality": row["criticality"],
                },
                "vulnerability": {
                    "vuln_id": row["vuln_id"],
                    "source": row["source"],
                    "title": row["title"],
                    "summary": row["summary"],
                    "severity": row["severity"],
                    "cvss_score": row["cvss_score"],
                    "cvss_source": row["cvss_source"],
                    "published_at": row["published_at"],
                    "first_seen_at": row["first_seen_at"],
                    "updated_at": row["vuln_updated_at"],
                },
                "finding": finding.to_dict(),
            }
        )
    return items


def explain_asset_risk(conn: sqlite3.Connection, hostname: str) -> dict[str, Any] | None:
    asset_row = conn.execute(
        """
        SELECT asset_id, hostname, os, version, owner, exposed, criticality
        FROM assets
        WHERE hostname = ?
        ORDER BY asset_id
        LIMIT 1
        """,
        (hostname,),
    ).fetchone()
    if asset_row is None:
        return None

    rows = conn.execute(
        """
        SELECT
          f.id AS finding_id,
          f.asset_id,
          a.hostname,
          a.os,
          a.version,
          a.owner,
          a.exposed,
          a.criticality,
          f.vuln_id,
          f.risk_score AS stored_risk_score,
          f.scoring_version AS finding_scoring_version,
          f.status AS finding_status,
          f.updated_at AS finding_updated_at,
          v.source,
          v.title,
          v.summary,
          v.severity,
          v.cvss_score,
          v.cvss_source,
          v.published_at,
          v.first_seen_at,
          v.updated_at AS vuln_updated_at
        FROM findings f
        JOIN assets a ON a.asset_id = f.asset_id
        JOIN vulnerabilities v ON v.vuln_id = f.vuln_id
        WHERE a.hostname = ? AND COALESCE(f.status, 'open') != 'suppressed'
        ORDER BY COALESCE(f.risk_score, 0) DESC, v.cvss_score DESC, f.vuln_id
        """,
        (hostname,),
    ).fetchall()

    findings: list[dict[str, Any]] = []
    for row in rows:
        finding = score_vulnerability(conn, row, row)
        findings.append(
            {
                "finding_id": row["finding_id"],
                "finding_status": row["finding_status"],
                "finding_updated_at": row["finding_updated_at"],
                "stored_risk_score": row["stored_risk_score"],
                "scoring_version": row["finding_scoring_version"] or finding.scoring_version,
                "vulnerability": {
                    "vuln_id": row["vuln_id"],
                    "source": row["source"],
                    "title": row["title"],
                    "summary": row["summary"],
                    "severity": row["severity"],
                    "cvss_score": row["cvss_score"],
                    "cvss_source": row["cvss_source"],
                    "published_at": row["published_at"],
                    "first_seen_at": row["first_seen_at"],
                    "updated_at": row["vuln_updated_at"],
                },
                "finding": finding.to_dict(),
            }
        )

    findings.sort(
        key=lambda item: (
            -item["finding"]["risk_score"],
            -int(item["finding"]["kev_present"]),
            -int(item["finding"]["exploit_present"]),
            item["vulnerability"]["vuln_id"],
        )
    )

    return {
        "asset": dict(asset_row),
        "scoring_version": SCORING_VERSION,
        "findings": findings,
    }


def top_hot(
    conn: sqlite3.Connection,
    limit: int | None = 20,
    vuln_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    params: list[Any] = []
    vuln_filter = ""
    if vuln_ids:
        placeholders = ",".join("?" for _ in vuln_ids)
        vuln_filter = f" AND s.vuln_id IN ({placeholders})"
        params.extend(vuln_ids)
    rows = conn.execute(
        """
        SELECT
          s.id,
          s.vuln_id,
          s.provider,
          s.score,
          s.value_json,
          s.observed_at,
          v.source,
          v.title,
          v.summary,
          v.severity,
          v.cvss_score,
          v.published_at,
          v.first_seen_at,
          v.updated_at
        FROM signals s
        JOIN vulnerabilities v ON v.vuln_id = s.vuln_id
        WHERE s.signal_type = 'hot'
        """ + vuln_filter + """
        ORDER BY s.observed_at DESC, s.id DESC
        """,
        tuple(params),
    ).fetchall()

    latest_by_vuln: dict[str, sqlite3.Row] = {}
    for row in rows:
        vuln_id = row["vuln_id"]
        if vuln_id not in latest_by_vuln:
            latest_by_vuln[vuln_id] = row
    ranked = sorted(
        latest_by_vuln.values(),
        key=lambda row: (
            -(attention_score_from_value(_signal_value(row)) or float(row["score"] or 0.0)),
            -int("kev" in _latest_signals(conn, row["vuln_id"])),
            -int("exploit" in _latest_signals(conn, row["vuln_id"])),
            -_epss_score(conn, row["vuln_id"]),
            -(float(row["cvss_score"] or 0.0)),
            row["published_at"] or "",
            row["vuln_id"],
        ),
    )
    if limit is not None:
        ranked = ranked[:limit]

    items: list[dict[str, Any]] = []
    for row in ranked:
        value = _signal_value(row)
        latest = _latest_signals(conn, row["vuln_id"])
        display_score = attention_score_from_value(value)
        source_label = None
        for item in value.get("evidence_details", []) or []:
            if isinstance(item, dict):
                label = item.get("source_label")
                if label:
                    source_label = str(label)
                    break
        if source_label is None:
            for item in value.get("search_hits", []) or []:
                if isinstance(item, dict):
                    label = item.get("source_label")
                    if label:
                        source_label = str(label)
                        break
        items.append(
            {
                "vuln_id": row["vuln_id"],
                "source": row["source"],
                "title": row["title"],
                "severity": row["severity"],
                "cvss_score": row["cvss_score"],
                "epss_score": _epss_score(conn, row["vuln_id"]),
                "kev_present": "kev" in latest,
                "exploit_present": "exploit" in latest,
                "published_at": row["published_at"],
                "first_seen_at": row["first_seen_at"],
                "signal_provider": row["provider"],
                "signal_score": row["score"],
                "hot_score": display_score if display_score is not None else row["score"],
                "observed_at": row["observed_at"],
                "query_count": value.get("query_count"),
                "search_queries": value.get("search_queries", []),
                "search_budget": value.get("search_budget"),
                "result_count": value.get("result_count"),
                "evidence_count": value.get("evidence_count"),
                "independent_sources": value.get("independent_sources"),
                "evidence_types": value.get("evidence_types", []),
                "source_types": value.get("source_types", []),
                "source_label": source_label,
                "urls": value.get("urls", []),
                "search_hits": value.get("search_hits", []),
                "evidence_details": value.get("evidence_details", []),
                "headline": value.get("headline"),
                "discovery_query_count": value.get("discovery_query_count"),
                "discovery_queries": value.get("discovery_queries", []),
                "discovery_result_count": value.get("discovery_result_count"),
                "discovery_hits": value.get("discovery_hits", []),
                "discovered_vuln_ids": value.get("discovered_vuln_ids", []),
            }
        )
    return items


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _staleness_status(last_success_at: str | None, threshold_hours: int | None) -> str:
    if threshold_hours is None:
        return "unknown"
    last = _parse_time(last_success_at)
    if last is None:
        return "missing"
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    age_hours = (datetime.now(timezone.utc) - last.astimezone(timezone.utc)).total_seconds() / 3600
    return "fresh" if age_hours <= threshold_hours else "stale"


def data_freshness(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    feeds = list(FRESHNESS_THRESHOLDS_HOURS.keys())
    summaries: list[dict[str, Any]] = []
    for feed in feeds:
        last_fetch = conn.execute(
            """
            SELECT attempted_at, status, rows_affected
            FROM fetch_log
            WHERE feed = ?
            ORDER BY attempted_at DESC, id DESC
            LIMIT 1
            """,
            (feed,),
        ).fetchone()
        last_success = conn.execute(
            """
            SELECT attempted_at
            FROM fetch_log
            WHERE feed = ? AND status = 'ok'
            ORDER BY attempted_at DESC, id DESC
            LIMIT 1
            """,
            (feed,),
        ).fetchone()
        last_success_at = last_success["attempted_at"] if last_success else None
        summaries.append(
            {
                "feed": feed,
                "last_fetch_status": last_fetch["status"] if last_fetch else "missing",
                "last_success_at": last_success_at,
                "last_rows_affected": last_fetch["rows_affected"] if last_fetch else None,
                "staleness_status": _staleness_status(last_success_at, FRESHNESS_THRESHOLDS_HOURS.get(feed)),
            }
        )
    return summaries
