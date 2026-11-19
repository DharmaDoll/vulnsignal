#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import skills
from db.migrate import migrate
from sync.hot_intel import reviewed_hot_value
from sync.common import DB_PATH, connect, utc_now
from sync.exploit_adapter import DEFAULT_DB_PATH as DEFAULT_EXPLOIT_DB_PATH, get_exploits
DEEP_DIVE_SCHEMA_VERSION = 2


def _sentences(text: str | None) -> list[str]:
    if not text:
        return []
    compact = " ".join(text.split())
    return [item.strip() for item in re.split(r"(?<=[.!?])\s+", compact) if item.strip()]


def _matching_sentences(text: str | None, patterns: tuple[str, ...]) -> list[str]:
    matches: list[str] = []
    for sentence in _sentences(text):
        lowered = sentence.lower()
        if any(pattern in lowered for pattern in patterns):
            matches.append(sentence)
    return matches


def _signal_names(core: dict[str, Any]) -> set[str]:
    signals = core.get("signals") or {}
    return set(signals.keys()) if isinstance(signals, dict) else set()


def _priority(core: dict[str, Any], hot_rows: list[dict[str, Any]], exploits: list[dict[str, Any]]) -> str:
    vuln = core.get("vulnerability") or {}
    signals = _signal_names(core)
    cvss = float(vuln.get("cvss_score") or 0.0)
    if "kev" in signals or exploits or "exploit" in signals:
        return "watch_now"
    if hot_rows or "hot" in signals:
        return "watch_now"
    if cvss >= 9.0:
        return "monitor_only"
    return "review_if_asset_exposed"


def build_impact_template(
    core: dict[str, Any],
    advisories: list[dict[str, Any]],
    exploits: list[dict[str, Any]],
    hot_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    vuln = core.get("vulnerability") or {}
    title = vuln.get("title") or ""
    summary = vuln.get("summary") or ""
    signals = sorted(_signal_names(core))
    references: list[str] = []
    for signal in (core.get("signals") or {}).values():
        value = signal.get("value_json") if isinstance(signal, dict) else {}
        for ref in (value or {}).get("references") or []:
            if isinstance(ref, str) and ref not in references:
                references.append(ref)
    for advisory in advisories:
        for ref in advisory.get("references") or []:
            if isinstance(ref, str) and ref not in references:
                references.append(ref)

    affected = _matching_sentences(summary, ("only impacts", "affects", "affected", "vulnerable"))
    if not affected:
        affected = [
            "Asset or service matches the vulnerable product/component described by the CVE title or package advisory.",
        ]
    not_affected = [
        "No matching asset, package, service, or configuration is present.",
        "A trusted VEX/not_affected assertion exists for the asset.",
    ]
    if fixed_versions := sorted({item.get("fixed_version") for item in advisories if item.get("fixed_version")}):
        not_affected.append(f"Installed version is at or above a fixed version: {', '.join(fixed_versions[:5])}.")

    mitigations = _matching_sentences(summary, ("remediate", "mitigat", "enable", "disable", "upgrade", "update", "patch", "fix"))
    if not mitigations:
        mitigations = [
            "Apply the vendor fix or documented configuration change from the referenced advisory.",
        ]

    detection = [
        "Correlate exposed matching assets with this vuln_id and review application/security logs around first_seen_at.",
    ]
    if exploits or "exploit" in signals:
        detection.append("Search for known exploit or PoC indicators from go-exploitdb context.")
    if hot_rows or "hot" in signals:
        detection.append("Review hot evidence URLs/domains and monitor for matching exploit discussion or scanning patterns.")

    return {
        "affected_conditions": affected,
        "not_affected_conditions": not_affected,
        "verification_steps": [
            "Confirm whether any asset/service uses the affected product, package, or cloud configuration.",
            "Check package fixed versions or vendor configuration state where applicable.",
            "Review core signals and local advisory mirror details before escalating.",
        ],
        "immediate_mitigation": mitigations,
        "permanent_fix": [
            "Apply the vendor-supported fixed version or durable configuration change.",
            "Record asset status after remediation so future triage can suppress already-fixed exposure.",
        ],
        "detection_guidance": detection,
        "priority": _priority(core, hot_rows, exploits),
        "residual_risk": [
            "Asset impact is not inferred unless findings/assets are populated.",
            "Absence of exploit or hot evidence in local sources is not proof of non-exploitation.",
        ],
        "evidence": {
            "title": title,
            "cvss_score": vuln.get("cvss_score"),
            "severity": vuln.get("severity"),
            "signals": signals,
            "package_advisories_rows": len(advisories),
            "go_exploitdb_rows": len(exploits),
            "hot_rows": len(hot_rows),
            "references": references[:10],
        },
    }


def source_context(vuln_id, db_path):
    """Build current details from individually attributed observations."""
    with closing(connect(db_path)) as conn:
        rows = conn.execute("""
            SELECT signal_type, provider, value_json, observed_at, score FROM signals
            WHERE vuln_id=? AND provider IN ('CVE Program','GitHub Advisory Database','CISA KEV',
                  'CISA Vulnrichment','Web Hot Intel','go-exploitdb')
            ORDER BY observed_at DESC,id DESC
        """, (vuln_id,))
        vulnerability = {"vuln_id": vuln_id}
        signals = {}
        packages = {}
        for row in rows:
            value = json.loads(row["value_json"] or "{}")
            provider = row["provider"]
            if provider == "CISA Vulnrichment" and not value.get("source_fields_version"):
                continue
            kind = row["signal_type"]
            if kind == "hot":
                value = reviewed_hot_value(vuln_id, value)
                if not value:
                    continue
            signals.setdefault(kind, {**dict(row), "value_json": value, "score": value["score"] if kind == "hot" else row["score"]})
            for field in ("title", "summary", "published_at"):
                if value.get(field):
                    vulnerability.setdefault(field, value[field])
            if kind == "package_advisory":
                key = (value.get("ghsa_id"), value.get("ecosystem"), value.get("package_name"))
                packages.setdefault(key, value)
            if value.get("cvss_score") is not None:
                trust = {"GitHub Advisory Database": 3, "CISA Vulnrichment": 2, "CVE Program": 1}
                if trust.get(provider, 0) > trust.get(vulnerability.get("cvss_source"), 0):
                    vulnerability.update(cvss_score=value["cvss_score"], cvss_source=provider,
                                         severity=value.get("severity"))
    if not signals:
        raise RuntimeError(f"no eligible evidence in core.db for {vuln_id}")
    return {"vulnerability": vulnerability, "signals": signals, "has_exploit": "exploit" in signals}, list(packages.values())


def build_report(
    vuln_id: str,
    db_path: Path = DB_PATH,
    exploit_db: Path = DEFAULT_EXPLOIT_DB_PATH,
    refresh_hot: bool = False,
) -> dict[str, Any]:
    migrate(db_path)
    hot_refresh_result: Any = None
    if refresh_hot:
        hot_refresh_result = skills.refresh_hot_for_vuln_ids([vuln_id], db_path=db_path, simple=True)

    core, advisories = source_context(vuln_id, db_path)
    exploits = [asdict(record) for record in get_exploits(vuln_id, db_path=exploit_db)] if exploit_db.is_file() else []
    hot_rows = [core["signals"]["hot"]] if "hot" in core["signals"] else []
    impact = build_impact_template(core, advisories, exploits, hot_rows)

    return {
        "schema_version": DEEP_DIVE_SCHEMA_VERSION,
        "kind": "deep_dive",
        "vuln_id": vuln_id,
        "generated_at": utc_now(),
        "sources": {
            "core_db": str(db_path),
            "exploit_db": str(exploit_db),
        },
        "core": core,
        "package_advisories": advisories,
        "go_exploitdb": exploits,
        "hot": hot_rows,
        "hot_refresh": hot_refresh_result,
        "impact": impact,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the bounded deep-dive worker for one vulnerability.")
    parser.add_argument("vuln_id", help="Vulnerability ID to inspect.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a short text summary.")
    parser.add_argument("--refresh-hot", action="store_true", help="Refresh hot intel for the vuln before reading it.")
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    parser.add_argument("--exploit-db", type=Path, default=DEFAULT_EXPLOIT_DB_PATH)
    args = parser.parse_args()

    report = build_report(
        vuln_id=args.vuln_id,
        db_path=args.db_path,
        exploit_db=args.exploit_db,
        refresh_hot=args.refresh_hot,
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        return

    print(f"vuln_id: {report['vuln_id']}")
    print(f"core_title: {report['core']['vulnerability'].get('title')}")
    print(f"signals: {', '.join(sorted(report['core']['signals'].keys())) or '-'}")
    print(f"package_advisories_rows: {len(report['package_advisories'])}")
    print(f"go_exploitdb_rows: {len(report['go_exploitdb'])}")
    print(f"hot_rows: {len(report['hot'])}")
    print(f"priority: {report['impact']['priority']}")


if __name__ == "__main__":
    main()
