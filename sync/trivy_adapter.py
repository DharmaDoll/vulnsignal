from __future__ import annotations

import hashlib
import json
import re
import subprocess
import os
import tempfile
from collections import deque
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from sync.common import FetchError, ROOT, read_text_cache, write_text_cache


TRIVY_DB_SCHEMA_VERSION = 2
TRIVY_DB_DEFAULT_DIR = ROOT / "db" / "trivy_cache.db"
TRIVY_DB_HELPER_DIR = ROOT / "cmd" / "trivydbdump"
TRIVY_DB_CACHE_FEED = "trivy_db_dump"
TRIVY_DB_CACHE_SUFFIX = "jsonl"


class TrivyDBSchemaError(RuntimeError):
    pass


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
    published_at: str | None = None
    source_path: str | None = None
    title: str | None = None
    summary: str | None = None


@dataclass(frozen=True)
class VulnerabilityRecord:
    vuln_id: str
    source: str
    title: str | None
    summary: str | None
    severity: str | None
    cvss_score: float | None
    cvss_vector: str | None
    vendor_severity: dict[str, Any] | None
    references: list[str]
    observed_at: str


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
    if re.match(r"^[A-Z0-9][A-Z0-9._-]*-[A-Za-z0-9._-]+$", text):
        return text
    return None


def context_from_key(key: str, parent_context: dict[str, Any]) -> dict[str, Any]:
    context = dict(parent_context)
    lower = key.lower()
    known_ecosystems = {
        "alpine",
        "amazon",
        "composer",
        "debian",
        "fedora",
        "go",
        "mariner",
        "maven",
        "npm",
        "nuget",
        "oracle",
        "pip",
        "pypi",
        "redhat",
        "rocky",
        "rubygems",
        "rust",
        "suse",
        "ubuntu",
        "wolfi",
    }
    if lower in known_ecosystems:
        context.setdefault("ecosystem", lower)
    return context


def package_from_payload(payload: dict[str, Any], context: dict[str, Any]) -> tuple[str | None, str | None]:
    package = first_value(payload, ("PkgName", "package_name", "package", "pkg_name", "name", "Name"))
    ecosystem = first_value(payload, ("ecosystem", "Ecosystem", "type", "Type", "datasource", "DataSource"))

    package_obj = payload.get("package")
    if isinstance(package_obj, dict):
        package = package or first_value(package_obj, ("name", "Name", "package_name", "pkg_name"))
        ecosystem = ecosystem or first_value(package_obj, ("ecosystem", "Ecosystem"))

    if not package and isinstance(payload.get("package"), str):
        package = payload.get("package")

    ecosystem_hint = context.get("ecosystem")
    if not ecosystem and ecosystem_hint:
        ecosystem = ecosystem_hint

    return (
        str(package or context.get("package_name")) if package or context.get("package_name") else None,
        str(ecosystem or context.get("ecosystem") or "unknown"),
    )


def range_strings(range_item: dict[str, Any]) -> list[str]:
    strings: list[str] = []
    range_type = first_value(range_item, ("type", "Type"))
    events = range_item.get("events") or range_item.get("Events") or []
    if not isinstance(events, list):
        events = [events]
    for event in events:
        if not isinstance(event, dict):
            continue
        for key in ("introduced", "fixed", "last_affected", "limit"):
            value = event.get(key)
            if value not in (None, "", []):
                prefix = f"{range_type}:" if range_type else ""
                strings.append(f"{prefix}{key}:{value}")
    return strings


def affected_versions_from_payload(payload: dict[str, Any], fixed_version: str | None) -> list[str]:
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

    ranges = payload.get("ranges") or payload.get("Ranges")
    if isinstance(ranges, list):
        for item in ranges:
            if isinstance(item, dict):
                affected_versions.extend(range_strings(item))

    if not affected_versions and fixed_version:
        affected_versions = [f"< {fixed_version}"]
    return affected_versions


def normalize_severity(value: Any) -> str | None:
    if value in (None, "", []):
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(first_value(value, ("score", "type", "severity", "level")) or None)
    if isinstance(value, list):
        for item in value:
            normalized = normalize_severity(item)
            if normalized:
                return normalized
    return str(value)


def normalize_cvss(value: Any) -> tuple[float | None, str | None]:
    if value in (None, "", []):
        return None, None
    if isinstance(value, (int, float)):
        return float(value), None
    if isinstance(value, list):
        for item in value:
            score, vector = normalize_cvss(item)
            if score is not None or vector is not None:
                return score, vector
        return None, None
    if isinstance(value, dict):
        score = first_value(value, ("V3Score", "V2Score", "score", "baseScore"))
        vector = first_value(value, ("V3Vector", "V2Vector", "vector"))
        if score is not None:
            try:
                return float(score), str(vector) if vector else None
            except (TypeError, ValueError):
                return None, str(vector) if vector else None
        for item in value.values():
            score, vector = normalize_cvss(item)
            if score is not None or vector is not None:
                return score, vector
    return None, None


def vulnerability_from_payload(
    vuln_id: str,
    payload: dict[str, Any],
    observed_at: str,
    source_hint: str | None = None,
) -> VulnerabilityRecord:
    title = first_value(payload, ("Title", "title"))
    summary = first_value(payload, ("Description", "description", "details"))
    severity = normalize_severity(first_value(payload, ("Severity", "severity")) or payload.get("severity"))
    cvss_score, cvss_vector = normalize_cvss(first_value(payload, ("CVSS", "cvss")))
    vendor_severity = payload.get("VendorSeverity") if isinstance(payload.get("VendorSeverity"), dict) else None
    references = normalize_list(first_value(payload, ("References", "references")))
    return VulnerabilityRecord(
        vuln_id=vuln_id,
        source=source_hint or "trivy-db",
        title=str(title) if title else None,
        summary=str(summary) if summary else None,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        vendor_severity=vendor_severity,
        references=references,
        observed_at=observed_at,
    )


def advisory_from_payload(
    payload: dict[str, Any],
    observed_at: str,
    context: dict[str, Any] | None = None,
    source_hint: str | None = None,
    source_path: str | None = None,
) -> AdvisoryRecord | None:
    context = context or {}
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
        or context.get("vuln_id")
    )
    if not vuln_id:
        aliases = payload.get("aliases") or payload.get("Aliases")
        if isinstance(aliases, list):
            for alias in aliases:
                vuln_id = normalize_vuln_id(alias)
                if vuln_id:
                    break

    if not vuln_id:
        return None

    package_name, ecosystem = package_from_payload(payload, context)
    if not package_name:
        return None

    fixed_version = normalize_fixed_version(
        first_value(payload, ("FixedVersion", "fixed_version", "fixedVersion", "fixed_versions", "first_patched_version"))
    )
    affected_versions = affected_versions_from_payload(payload, fixed_version)

    severity = normalize_severity(first_value(payload, ("Severity", "severity")) or payload.get("severity"))
    published_at = first_value(payload, ("PublishedAt", "published", "published_at", "datePublished"))
    advisory_container = payload.get("Advisory")
    if isinstance(advisory_container, dict):
        published_at = published_at or first_value(advisory_container, ("PublishedAt", "published", "published_at"))

    return AdvisoryRecord(
        vuln_id=vuln_id,
        source=source_hint or "trivy-vuln-list",
        ecosystem=ecosystem,
        package_name=package_name,
        affected_versions=affected_versions,
        fixed_version=fixed_version,
        severity=severity,
        observed_at=observed_at,
        published_at=str(published_at) if published_at else None,
        source_path=source_path,
        title=first_value(payload, ("Title", "title", "summary")),
        summary=first_value(payload, ("Description", "description", "details", "summary")),
    )


def _enrich_record(record: AdvisoryRecord, vuln_meta: dict[str, Any] | None) -> AdvisoryRecord:
    if not vuln_meta:
        return record
    title = record.title or first_value(vuln_meta, ("Title", "title"))
    summary = record.summary or first_value(vuln_meta, ("Description", "description", "details"))
    severity = record.severity or normalize_severity(first_value(vuln_meta, ("Severity", "severity")))
    return replace(record, title=title, summary=summary, severity=severity)


def parse_advisories(
    payload: Any,
    observed_at: str,
    context: dict[str, Any] | None = None,
    source_hint: str | None = None,
    source_path: str | None = None,
) -> list[AdvisoryRecord]:
    context = context or {}
    advisories: list[AdvisoryRecord] = []

    if isinstance(payload, list):
        for item in payload:
            advisories.extend(parse_advisories(item, observed_at, context, source_hint, source_path))
        return advisories

    if not isinstance(payload, dict):
        return advisories

    if "Entries" in payload and isinstance(payload["Entries"], list):
        for entry in payload["Entries"]:
            if isinstance(entry, dict):
                advisories.extend(parse_advisories(entry, observed_at, context, source_hint, source_path))
        return advisories

    if "vulnerabilities" in payload and isinstance(payload["vulnerabilities"], list):
        for vulnerability in payload["vulnerabilities"]:
            if not isinstance(vulnerability, dict):
                continue
            package = vulnerability.get("package") or {}
            if not isinstance(package, dict):
                package = {}
            child = {key: value for key, value in payload.items() if key != "vulnerabilities"}
            child.update(vulnerability)
            child["package"] = package
            advisories.extend(parse_advisories(child, observed_at, context, source_hint, source_path))
        return advisories

    if "affected" in payload and isinstance(payload["affected"], list):
        for affected in payload["affected"]:
            if not isinstance(affected, dict):
                continue
            child = {key: value for key, value in payload.items() if key != "affected"}
            child.update(affected)
            package = affected.get("package")
            if isinstance(package, dict):
                child["package"] = package
            advisories.extend(parse_advisories(child, observed_at, context, source_hint, source_path))
        return advisories

    advisory = advisory_from_payload(payload, observed_at, context, source_hint, source_path)
    if advisory:
        advisories.append(advisory)
        return advisories

    for key, value in payload.items():
        if isinstance(value, (dict, list)):
            advisories.extend(parse_advisories(value, observed_at, context_from_key(str(key), context), source_hint, source_path))

    return advisories


def load_advisories_from_json(path: Path, observed_at: str, source_hint: str | None = None) -> list[AdvisoryRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return parse_advisories(payload, observed_at, source_hint=source_hint, source_path=str(path))


def iter_advisories_from_json(path: Path, observed_at: str, source_hint: str | None = None):
    payload = json.loads(path.read_text(encoding="utf-8"))
    for advisory in parse_advisories(payload, observed_at, source_hint=source_hint, source_path=str(path)):
        yield advisory


def iter_advisories_from_directory(
    source_dir: Path,
    observed_at: str,
    targets: list[str] | None = None,
    source_files: list[Path] | None = None,
):
    if source_files is not None:
        for path in sorted(path for path in source_files if path.is_file()):
            yield from iter_advisories_from_json(path, observed_at, source_hint=path.parent.name)
        return
    selected_targets = targets or []
    for target in selected_targets:
        target_dir = source_dir / target
        if not target_dir.exists():
            continue
        for path in sorted(path for path in target_dir.rglob("*.json") if path.is_file()):
            yield from iter_advisories_from_json(path, observed_at, source_hint=target)


def load_advisories_from_directory(
    source_dir: Path,
    observed_at: str,
    targets: list[str] | None = None,
    source_files: list[Path] | None = None,
) -> list[AdvisoryRecord]:
    return list(iter_advisories_from_directory(source_dir, observed_at, targets=targets, source_files=source_files))


def ecosystem_from_source_path(source_path: list[str]) -> str:
    normalized = " ".join(source_path).lower()
    mappings = (
        ("red hat", "redhat"),
        ("redhat", "redhat"),
        ("oracle", "oracle"),
        ("ubuntu", "ubuntu"),
        ("debian", "debian"),
        ("alpine", "alpine"),
        ("amazon", "amazon"),
        ("amzn", "amazon"),
        ("mariner", "mariner"),
        ("photon", "photon"),
        ("suse", "suse"),
        ("rocky", "rocky"),
        ("alma", "alma"),
        ("wolfi", "wolfi"),
        ("ghsa", "ghsa"),
        ("go", "go"),
        ("osv", "osv"),
        ("pip", "pypi"),
        ("pypi", "pypi"),
        ("npm", "npm"),
        ("composer", "composer"),
        ("maven", "maven"),
        ("nuget", "nuget"),
        ("rubygems", "rubygems"),
        ("rust", "rust"),
    )
    for needle, ecosystem in mappings:
        if needle in normalized:
            return ecosystem
    if source_path:
        token = source_path[0].strip().lower()
        token = re.sub(r"[^a-z0-9]+", "_", token).strip("_")
        return token or "unknown"
    return "unknown"


def _trivy_db_dump_command(db_dir: Path, expected_schema_version: int) -> list[str]:
    helper_binary = TRIVY_DB_HELPER_DIR / "trivydbdump"
    if helper_binary.exists():
        return [
            str(helper_binary),
            "--db-dir",
            str(db_dir),
            "--expected-schema-version",
            str(expected_schema_version),
        ]
    return [
        "go",
        "run",
        ".",
        "--db-dir",
        str(db_dir),
        "--expected-schema-version",
        str(expected_schema_version),
    ]


def _load_trivy_db_dump_from_cache() -> tuple[dict[str, Any], ...]:
    cached = read_text_cache(TRIVY_DB_CACHE_FEED, suffix=TRIVY_DB_CACHE_SUFFIX)
    rows: list[dict[str, Any]] = []
    for line in cached.splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return tuple(rows)


def _cache_payload_hash(payload: Any) -> str:
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload_json.encode("utf-8")).hexdigest()


def load_trivy_vulnerability_fingerprints_from_cache(
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> dict[str, str]:
    try:
        rows = _load_trivy_db_dump_from_cache()
    except FetchError:
        return {}
    cache: dict[str, str] = {}
    for row in rows:
        if row.get("row_type") != "vulnerability":
            continue
        vuln_id = row.get("vuln_id")
        payload = row.get("payload")
        if not isinstance(vuln_id, str) or not isinstance(payload, dict):
            continue
        cache[vuln_id] = row.get("payload_hash") or _cache_payload_hash(payload)
    return cache


def _write_trivy_db_cache(lines: list[str]) -> None:
    if lines:
        write_text_cache(TRIVY_DB_CACHE_FEED, "".join(lines), suffix=TRIVY_DB_CACHE_SUFFIX)


def _trivy_db_schema_version(db_dir: Path) -> int | None:
    metadata_path = db_dir / "metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        return None
    except json.JSONDecodeError as exc:
        return None
    version = metadata.get("Version")
    if not isinstance(version, int):
        return None
    return version


def _validate_trivy_db_schema(db_dir: Path, expected_schema_version: int) -> None:
    version = _trivy_db_schema_version(db_dir)
    if version is not None and version != expected_schema_version:
        raise TrivyDBSchemaError(
            f"trivy db schema version mismatch: got {version} want {expected_schema_version}"
        )


def _load_trivy_db_dump_from_helper(db_dir: Path, expected_schema_version: int) -> tuple[tuple[dict[str, Any], ...], bool]:
    if not TRIVY_DB_HELPER_DIR.exists():
        raise FetchError(f"missing Trivy DB helper: {TRIVY_DB_HELPER_DIR}")

    command = _trivy_db_dump_command(db_dir, expected_schema_version)
    process = subprocess.Popen(
        command,
        cwd=TRIVY_DB_HELPER_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    rows: list[dict[str, Any]] = []
    lines: list[str] = []

    assert process.stdout is not None
    for line in process.stdout:
        lines.append(line)
        stripped = line.strip()
        if not stripped:
            continue
        try:
            rows.append(json.loads(stripped))
        except json.JSONDecodeError as exc:
            process.kill()
            raise FetchError(f"invalid Trivy DB dump output: {exc}") from exc

    returncode = process.wait()
    if returncode != 0:
        try:
            return _load_trivy_db_dump_from_cache(), True
        except FetchError:
            tail = "".join(lines[-10:]).strip()
            raise FetchError(f"Trivy DB helper failed with exit code {returncode}: {tail}") from None

    _write_trivy_db_cache(lines)
    return tuple(rows), False


def iter_vulnerabilities_from_db(
    db_dir: Path,
    observed_at: str,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
):
    _validate_trivy_db_schema(db_dir, expected_schema_version)
    if not TRIVY_DB_HELPER_DIR.exists():
        raise FetchError(f"missing Trivy DB helper: {TRIVY_DB_HELPER_DIR}")

    command = _trivy_db_dump_command(db_dir, expected_schema_version)
    process = subprocess.Popen(
        command,
        cwd=TRIVY_DB_HELPER_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    tail: deque[str] = deque(maxlen=10)
    temp_name: str | None = None
    completed = False

    assert process.stdout is not None
    cache_path = ROOT / "db" / "cache" / f"{TRIVY_DB_CACHE_FEED}.{TRIVY_DB_CACHE_SUFFIX}"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=str(cache_path.parent),
            prefix=f"{cache_path.name}.tmp.",
        ) as tmp:
            temp_name = tmp.name
            for line in process.stdout:
                tail.append(line)
                tmp.write(line)
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    row = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    process.kill()
                    with suppress(Exception):
                        process.wait()
                    raise FetchError(f"invalid Trivy DB dump output: {exc}") from exc
                if row.get("row_type") != "vulnerability":
                    continue
                vuln_id = row.get("vuln_id")
                payload = row.get("payload")
                if not isinstance(vuln_id, str) or not isinstance(payload, dict):
                    continue
                yield vulnerability_from_payload(vuln_id, payload, observed_at, source_hint="trivy-db")

            returncode = process.wait()
            if returncode != 0:
                raise FetchError(
                    f"Trivy DB helper failed with exit code {returncode}: {''.join(tail).strip()}"
                )
            tmp.flush()
            os.fsync(tmp.fileno())
        if temp_name is not None:
            os.replace(temp_name, cache_path)
            completed = True
    except Exception:
        process.kill()
        with suppress(Exception):
            process.wait()
        raise
    finally:
        if process.poll() is None:
            process.kill()
            with suppress(Exception):
                process.wait()
        if not completed and temp_name:
            with suppress(FileNotFoundError):
                os.unlink(temp_name)


def iter_trivy_db_dump_rows(
    db_dir: Path,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
):
    _validate_trivy_db_schema(db_dir, expected_schema_version)
    if not TRIVY_DB_HELPER_DIR.exists():
        raise FetchError(f"missing Trivy DB helper: {TRIVY_DB_HELPER_DIR}")

    command = _trivy_db_dump_command(db_dir, expected_schema_version)
    process = subprocess.Popen(
        command,
        cwd=TRIVY_DB_HELPER_DIR,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    tail: deque[str] = deque(maxlen=10)
    temp_name: str | None = None
    completed = False

    assert process.stdout is not None
    cache_path = ROOT / "db" / "cache" / f"{TRIVY_DB_CACHE_FEED}.{TRIVY_DB_CACHE_SUFFIX}"
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=str(cache_path.parent),
            prefix=f"{cache_path.name}.tmp.",
        ) as tmp:
            temp_name = tmp.name
            for line in process.stdout:
                tail.append(line)
                tmp.write(line)
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    row = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    process.kill()
                    with suppress(Exception):
                        process.wait()
                    raise FetchError(f"invalid Trivy DB dump output: {exc}") from exc
                yield row

            returncode = process.wait()
            if returncode != 0:
                raise FetchError(f"Trivy DB helper failed with exit code {returncode}: {''.join(tail).strip()}")
            tmp.flush()
            os.fsync(tmp.fileno())
        if temp_name is not None:
            os.replace(temp_name, cache_path)
            completed = True
    except Exception:
        process.kill()
        with suppress(Exception):
            process.wait()
        raise
    finally:
        if process.poll() is None:
            process.kill()
            with suppress(Exception):
                process.wait()
        if not completed and temp_name:
            with suppress(FileNotFoundError):
                os.unlink(temp_name)


def load_vulnerabilities_from_db_cache_only(
    db_dir: Path,
    observed_at: str,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> list[VulnerabilityRecord]:
    _validate_trivy_db_schema(db_dir, expected_schema_version)
    rows = _load_trivy_db_dump_from_cache()
    vulnerabilities: list[VulnerabilityRecord] = []
    for row in rows:
        row_type = row.get("row_type")
        vuln_id = row.get("vuln_id")
        payload = row.get("payload")
        if row_type != "vulnerability":
            continue
        if not isinstance(vuln_id, str) or not isinstance(payload, dict):
            continue
        vulnerabilities.append(vulnerability_from_payload(vuln_id, payload, observed_at, source_hint="trivy-db"))
    return vulnerabilities


def load_advisories_from_db_with_cache(
    db_dir: Path,
    observed_at: str,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> tuple[list[AdvisoryRecord], bool]:
    _validate_trivy_db_schema(db_dir, expected_schema_version)
    rows, cache_used = _load_trivy_db_dump_from_helper(db_dir.resolve(), expected_schema_version)
    vuln_meta: dict[str, dict[str, Any]] = {}
    advisory_rows: list[dict[str, Any]] = []

    for row in rows:
        row_type = row.get("row_type")
        vuln_id = row.get("vuln_id")
        payload = row.get("payload")
        if not isinstance(vuln_id, str) or not isinstance(payload, (dict, list)):
            continue
        if row_type == "vulnerability" and isinstance(payload, dict):
            vuln_meta[vuln_id] = payload
        elif row_type == "advisory":
            advisory_rows.append(row)

    advisories: list[AdvisoryRecord] = []
    for row in advisory_rows:
        vuln_id = row.get("vuln_id")
        package_name = row.get("package_name")
        source_path = row.get("source_path") or []
        payload = row.get("payload")
        if not isinstance(vuln_id, str) or not isinstance(package_name, str):
            continue
        if not isinstance(source_path, list):
            source_path = []
        if not isinstance(payload, (dict, list)):
            continue
        context = {
            "vuln_id": vuln_id,
            "package_name": package_name,
            "ecosystem": ecosystem_from_source_path([str(part) for part in source_path]),
            "source_path": source_path,
        }
        for advisory in parse_advisories(payload, observed_at, context=context, source_hint="trivy-db"):
            advisories.append(_enrich_record(advisory, vuln_meta.get(advisory.vuln_id)))

    return advisories, cache_used


def load_vulnerabilities_from_db_with_cache(
    db_dir: Path,
    observed_at: str,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> tuple[list[VulnerabilityRecord], bool]:
    _validate_trivy_db_schema(db_dir, expected_schema_version)
    rows, cache_used = _load_trivy_db_dump_from_helper(db_dir.resolve(), expected_schema_version)

    vulnerabilities: list[VulnerabilityRecord] = []
    for row in rows:
        row_type = row.get("row_type")
        vuln_id = row.get("vuln_id")
        payload = row.get("payload")
        if row_type != "vulnerability":
            continue
        if not isinstance(vuln_id, str) or not isinstance(payload, dict):
            continue
        vulnerabilities.append(vulnerability_from_payload(vuln_id, payload, observed_at, source_hint="trivy-db"))

    return vulnerabilities, cache_used


def load_vulnerabilities_from_db(
    db_dir: Path,
    observed_at: str,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> list[VulnerabilityRecord]:
    vulnerabilities, _ = load_vulnerabilities_from_db_with_cache(db_dir, observed_at, expected_schema_version)
    return vulnerabilities


def load_advisories_from_db(
    db_dir: Path,
    observed_at: str,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> list[AdvisoryRecord]:
    advisories, _ = load_advisories_from_db_with_cache(db_dir, observed_at, expected_schema_version)
    return advisories


def get_advisories(
    vuln_id: str,
    db_dir: Path = TRIVY_DB_DEFAULT_DIR,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> list[AdvisoryRecord]:
    observed_at = "1970-01-01T00:00:00+00:00"
    advisories = load_advisories_from_db(db_dir, observed_at, expected_schema_version)
    return [advisory for advisory in advisories if advisory.vuln_id == vuln_id]


def get_vulnerabilities(
    vuln_id: str,
    db_dir: Path = TRIVY_DB_DEFAULT_DIR,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> list[VulnerabilityRecord]:
    observed_at = "1970-01-01T00:00:00+00:00"
    vulnerabilities = load_vulnerabilities_from_db(db_dir, observed_at, expected_schema_version)
    return [vulnerability for vulnerability in vulnerabilities if vulnerability.vuln_id == vuln_id]


def get_vulnerabilities_from_db(
    db_dir: Path = TRIVY_DB_DEFAULT_DIR,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> list[VulnerabilityRecord]:
    observed_at = "1970-01-01T00:00:00+00:00"
    return load_vulnerabilities_from_db(db_dir, observed_at, expected_schema_version)


def get_advisories_by_package(
    ecosystem: str,
    package: str,
    version: str,
    db_dir: Path = TRIVY_DB_DEFAULT_DIR,
    expected_schema_version: int = TRIVY_DB_SCHEMA_VERSION,
) -> list[AdvisoryRecord]:
    observed_at = "1970-01-01T00:00:00+00:00"
    advisories = load_advisories_from_db(db_dir, observed_at, expected_schema_version)
    return [
        advisory
        for advisory in advisories
        if advisory.ecosystem == ecosystem and advisory.package_name == package
    ]
