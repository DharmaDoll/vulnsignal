#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from sync.common import (
    ROOT,
    FetchResult,
    append_asset_observation,
    connect,
    log_fetch,
    upsert_asset,
)


FEED = "asset_csv"
DEFAULT_CSV = ROOT / "data" / "assets.csv"

OBSERVATION_COLUMNS = {
    "os": ("os", "os_version"),
    "software": ("product", "software_version"),
    "product": ("product", "product_version"),
    "middleware": ("middleware", "middleware_version"),
    "framework": ("framework", "framework_version"),
    "runtime": ("runtime", "runtime_version"),
    "language": ("language", "language_version"),
}


def _clean(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    text = str(value).strip()
    return text or None


def _parse_int_bool(value: Any) -> int | None:
    text = _clean(value)
    if text is None:
        return None
    normalized = text.lower()
    if normalized in {"1", "true", "yes", "y"}:
        return 1
    if normalized in {"0", "false", "no", "n"}:
        return 0
    return None


def _parse_float(value: Any, default: float = 0.5) -> float:
    text = _clean(value)
    if text is None:
        return default
    try:
        return float(text)
    except ValueError:
        return default


def _parse_details(value: Any) -> dict[str, Any] | None:
    text = _clean(value)
    if text is None:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}
    return parsed if isinstance(parsed, dict) else {"raw": parsed}


def _asset_payload(row: dict[str, Any]) -> dict[str, Any]:
    asset_os = _clean(row.get("os"))
    asset_version = _clean(row.get("version")) or _clean(row.get("os_version"))
    return {
        "asset_id": _clean(row.get("asset_id")),
        "hostname": _clean(row.get("hostname")),
        "os": asset_os,
        "version": asset_version,
        "owner": _clean(row.get("owner")),
        "exposed": _parse_int_bool(row.get("exposed")),
        "criticality": _clean(row.get("criticality")),
    }


def _observations_from_row(row: dict[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    confidence = _parse_float(row.get("confidence"))
    source = _clean(row.get("source")) or "csv"
    observed_at = _clean(row.get("observed_at"))
    details = _parse_details(row.get("details_json") or row.get("details"))

    kind = _clean(row.get("kind"))
    name = _clean(row.get("name"))
    version = _clean(row.get("version"))
    if kind and name:
        observations.append(
            {
                "kind": kind,
                "name": name,
                "version": version,
                "confidence": confidence,
                "source": source,
                "details": details,
                "observed_at": observed_at,
            }
        )

    for column, (derived_kind, version_column) in OBSERVATION_COLUMNS.items():
        value = _clean(row.get(column))
        if not value:
            continue
        obs_version = _clean(row.get(version_column))
        observations.append(
            {
                "kind": derived_kind,
                "name": value,
                "version": obs_version,
                "confidence": confidence,
                "source": source,
                "details": details,
                "observed_at": observed_at,
            }
        )

    return observations


def sync(csv_path: Path, dry_run: bool = False, limit: int | None = None) -> FetchResult:
    subprocess.run([sys.executable, str(ROOT / "db" / "migrate.py")], check=True)

    rows_fetched = 0
    rows_written = 0
    conn = None
    try:
        with csv_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            conn = connect()
            for row in reader:
                rows_fetched += 1
                if limit is not None and rows_fetched > limit:
                    break

                payload = _asset_payload(row)
                asset_id = payload["asset_id"]
                hostname = payload["hostname"]
                if not asset_id or not hostname:
                    continue

                observations = _observations_from_row(row)
                if dry_run:
                    rows_written += 1 + len(observations)
                    continue

                if upsert_asset(
                    conn,
                    asset_id=asset_id,
                    hostname=hostname,
                    os=payload["os"],
                    version=payload["version"],
                    owner=payload["owner"],
                    exposed=payload["exposed"],
                    criticality=payload["criticality"],
                ):
                    rows_written += 1

                for observation in observations:
                    if append_asset_observation(
                        conn,
                        asset_id=asset_id,
                        kind=observation["kind"],
                        name=observation["name"],
                        version=observation["version"],
                        confidence=observation["confidence"],
                        source=observation["source"],
                        details=observation["details"],
                        observed_at=observation["observed_at"],
                    ):
                        rows_written += 1

            if not dry_run and conn is not None:
                log_fetch(conn, FEED, "ok", rows_written)
                conn.commit()
        return FetchResult(rows_fetched=rows_fetched, rows_written=rows_written, cache_used=False)
    except Exception as exc:
        if conn is None:
            conn = connect()
        else:
            conn.rollback()
        log_fetch(conn, FEED, "error", rows_written, str(exc))
        conn.commit()
        raise
    finally:
        if conn is not None:
            conn.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=Path, default=DEFAULT_CSV, help="Path to an asset CSV file.")
    parser.add_argument("--limit", type=int, help="Limit rows for local sampling.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    result = sync(csv_path=args.csv, dry_run=args.dry_run, limit=args.limit)
    print(result)


if __name__ == "__main__":
    main()
