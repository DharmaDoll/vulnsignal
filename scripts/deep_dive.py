#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import skills
from db.migrate import migrate
from sync.common import DB_PATH, utc_now
from sync.exploit_adapter import DEFAULT_DB_PATH as DEFAULT_EXPLOIT_DB_PATH, get_exploits
from sync.trivy_adapter import (
    TRIVY_VULN_LIST_DEFAULT_DIR,
    load_advisories_for_vuln_id_from_directory,
)


DEFAULT_TARGETS = ["alpine", "debian", "ubuntu", "ghsa", "glad", "go", "osv", "seal"]


def build_report(
    vuln_id: str,
    db_path: Path = DB_PATH,
    mirror_dir: Path = TRIVY_VULN_LIST_DEFAULT_DIR,
    exploit_db: Path = DEFAULT_EXPLOIT_DB_PATH,
    targets: list[str] | None = None,
    refresh_hot: bool = False,
) -> dict[str, Any]:
    migrate(db_path)
    hot_refresh_result: Any = None
    if refresh_hot:
        hot_refresh_result = skills.refresh_hot_for_vuln_ids([vuln_id], db_path=db_path, simple=True)

    core = skills.find_vuln(vuln_id, db_path=db_path)
    if core is None:
        raise RuntimeError(f"vulnerability not found in core.db: {vuln_id}")

    advisories = [
        asdict(record)
        for record in load_advisories_for_vuln_id_from_directory(
            mirror_dir,
            vuln_id,
            utc_now(),
            targets=targets or DEFAULT_TARGETS,
        )
    ]
    exploits = [asdict(record) for record in get_exploits(vuln_id, db_path=exploit_db)]
    hot_rows = skills.top_hot(limit=5, db_path=db_path, vuln_ids=[vuln_id])

    return {
        "vuln_id": vuln_id,
        "generated_at": utc_now(),
        "sources": {
            "core_db": str(db_path),
            "vuln_list_mirror": str(mirror_dir),
            "exploit_db": str(exploit_db),
        },
        "core": core,
        "trivy_vuln_list": advisories,
        "go_exploitdb": exploits,
        "hot": hot_rows,
        "hot_refresh": hot_refresh_result,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the bounded deep-dive worker for one vulnerability.")
    parser.add_argument("vuln_id", help="Vulnerability ID to inspect.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of a short text summary.")
    parser.add_argument("--refresh-hot", action="store_true", help="Refresh hot intel for the vuln before reading it.")
    parser.add_argument("--db-path", type=Path, default=DB_PATH)
    parser.add_argument("--mirror-dir", type=Path, default=TRIVY_VULN_LIST_DEFAULT_DIR)
    parser.add_argument("--exploit-db", type=Path, default=DEFAULT_EXPLOIT_DB_PATH)
    parser.add_argument(
        "--target",
        action="append",
        dest="targets",
        default=[],
        help="Limit Trivy vuln-list lookup to a specific target family. Can be repeated.",
    )
    args = parser.parse_args()

    report = build_report(
        vuln_id=args.vuln_id,
        db_path=args.db_path,
        mirror_dir=args.mirror_dir,
        exploit_db=args.exploit_db,
        targets=args.targets or None,
        refresh_hot=args.refresh_hot,
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        return

    print(f"vuln_id: {report['vuln_id']}")
    print(f"core_title: {report['core']['vulnerability'].get('title')}")
    print(f"signals: {', '.join(sorted(report['core']['signals'].keys())) or '-'}")
    print(f"trivy_vuln_list_rows: {len(report['trivy_vuln_list'])}")
    print(f"go_exploitdb_rows: {len(report['go_exploitdb'])}")
    print(f"hot_rows: {len(report['hot'])}")


if __name__ == "__main__":
    main()
