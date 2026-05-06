from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class AdvisoryRecord:
    vuln_id: str
    source: str
    ecosystem: str
    package_name: str
    affected_versions: list[str]
    fixed_version: str | None
    severity: str | None
    observed_at: str
    title: str | None = None
    summary: str | None = None


def first_value(item: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in item and item[key] not in (None, "", []):
            return item[key]
    return None


def normalize_list(value: Any) -> list[str]:
    if value in (None, "", []):
        return []
    if isinstance(value, list):
        return [str(part) for part in value if part not in (None, "")]
    return [str(value)]


def normalize_fixed_version(value: Any) -> str | None:
    if value in (None, "", []):
        return None
    if isinstance(value, list):
        return ", ".join(str(part) for part in value if part not in (None, ""))
    if isinstance(value, dict):
        identifier = first_value(value, ("identifier", "version", "fixed_version", "FixedVersion"))
        return str(identifier) if identifier else None
    return str(value)


def normalize_vuln_id(value: Any) -> str | None:
    if not value:
        return None
    if isinstance(value, list):
        for candidate in value:
            normalized = normalize_vuln_id(candidate)
            if normalized:
                return normalized
        return None
    text = str(value).strip()
    if text.startswith(("CVE-", "GHSA-")):
        return text
    return None


def context_from_key(key: str, parent_context: dict[str, Any]) -> dict[str, Any]:
    context = dict(parent_context)
    lower = key.lower()
    known_ecosystems = {
        "alpine",
        "composer",
        "debian",
        "go",
        "maven",
        "npm",
        "nuget",
        "pip",
        "pypi",
        "rubygems",
        "rust",
        "ubuntu",
    }
    if lower in known_ecosystems:
        context.setdefault("ecosystem", lower)
    elif "package_name" not in context and "/" not in key and len(key) <= 120:
        context.setdefault("package_name", key)
    return context


def parse_advisories(payload: Any, observed_at: str, context: dict[str, Any] | None = None) -> list[AdvisoryRecord]:
    context = context or {}
    advisories: list[AdvisoryRecord] = []

    if isinstance(payload, list):
        for item in payload:
            advisories.extend(parse_advisories(item, observed_at, context))
        return advisories

    if not isinstance(payload, dict):
        return advisories

    vuln_id = normalize_vuln_id(
        first_value(
            payload,
            (
                "VulnerabilityID",
                "vulnerability_id",
                "vuln_id",
                "cve_id",
                "cve",
                "ghsa_id",
                "id",
                "ID",
            ),
        )
    )
    package_name = first_value(payload, ("PkgName", "package_name", "package", "pkg_name", "name", "Name"))
    ecosystem = first_value(payload, ("ecosystem", "Ecosystem", "type", "Type", "datasource", "DataSource"))

    if vuln_id and (package_name or context.get("package_name")):
        fixed_version = normalize_fixed_version(
            first_value(payload, ("FixedVersion", "fixed_version", "fixedVersion", "fixed_versions"))
        )
        affected_versions = normalize_list(
            first_value(
                payload,
                (
                    "AffectedVersion",
                    "AffectedVersions",
                    "affected_version",
                    "affected_versions",
                    "affected",
                    "vulnerable_version_range",
                ),
            )
        )
        if not affected_versions and fixed_version:
            affected_versions = [f"< {fixed_version}"]

        advisories.append(
            AdvisoryRecord(
                vuln_id=vuln_id,
                source="trivy-json",
                ecosystem=str(ecosystem or context.get("ecosystem") or "unknown"),
                package_name=str(package_name or context.get("package_name")),
                affected_versions=affected_versions,
                fixed_version=fixed_version,
                severity=first_value(payload, ("Severity", "severity")),
                observed_at=observed_at,
                title=first_value(payload, ("Title", "title")),
                summary=first_value(payload, ("Description", "description", "summary")),
            )
        )

    for key, value in payload.items():
        advisories.extend(parse_advisories(value, observed_at, context_from_key(str(key), context)))

    return advisories


def load_advisories_from_json(path: Path, observed_at: str) -> list[AdvisoryRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return parse_advisories(payload, observed_at)
