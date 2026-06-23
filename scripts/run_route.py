#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.routing import VULN_ID_RE
from sync.common import utc_now


def _run_json_command(command: list[str]) -> Any:
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip() or result.stdout.strip() or f"command failed: {' '.join(command)}"
        raise RuntimeError(stderr)
    return json.loads(result.stdout)


def _route_plan(request: str) -> dict[str, Any]:
    return _run_json_command([sys.executable, "-m", "app.skills", "route", request, "--json"])


def _deep_dive(request: str, refresh_hot: bool) -> dict[str, Any] | None:
    vuln_ids = list(dict.fromkeys(match.group(0).upper() for match in VULN_ID_RE.finditer(request)))
    if len(vuln_ids) != 1:
        return None
    command = [sys.executable, "scripts/deep_dive.py", vuln_ids[0], "--json"]
    if refresh_hot:
        command.append("--refresh-hot")
    return _run_json_command(command)


def _watchlist(limit: int, hot_limit: int, request: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "top_risks": _run_json_command([sys.executable, "-m", "app.skills", "risks", "--limit", str(limit), "--json"]),
    }
    if "hot" in request.lower():
        payload["hot"] = _run_json_command(
            [sys.executable, "-m", "app.skills", "hot", "--limit", str(hot_limit), "--details", "--json"]
        )
    return payload


def _freshness() -> list[dict[str, Any]]:
    return _run_json_command([sys.executable, "-m", "app.skills", "freshness", "--json"])


def _artifact(kind: str, data: Any, summary: str, worker: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "summary": summary,
        "worker": worker,
        "data": data,
    }


def execute(request: str, limit: int = 10, hot_limit: int = 10, refresh_hot: bool = False) -> dict[str, Any]:
    route = _route_plan(request)
    artifact: dict[str, Any] | None
    if route["mode"] == "deep_dive":
        data = _deep_dive(request, refresh_hot=refresh_hot)
        artifact = None if data is None else _artifact("deep_dive", data, "Single-vulnerability evidence bundle", "scripts/deep_dive.py")
    elif route["mode"] == "watchlist":
        data = _watchlist(limit=limit, hot_limit=hot_limit, request=request)
        artifact = _artifact("watchlist", data, "Ranked watchlist bundle", "app.skills")
    elif route["mode"] == "feed_refresh":
        data = _freshness()
        artifact = _artifact("freshness", data, "Feed freshness bundle", "app.skills")
    else:
        artifact = None
    return {
        "request": request,
        "generated_at": utc_now(),
        "route": route,
        "execution": {
            "status": "ok" if artifact is not None else "skipped",
            "worker_count": 0 if artifact is None else 1,
        },
        "artifact": artifact,
        "result": None if artifact is None else artifact["data"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Route a request and execute the bounded CLI workers.")
    parser.add_argument("request", help="Free-form request to route.")
    parser.add_argument("--limit", type=int, default=10, help="Watchlist limit for ranked findings.")
    parser.add_argument("--hot-limit", type=int, default=10, help="Hot list limit when hot is requested.")
    parser.add_argument("--refresh-hot", action="store_true", help="Refresh hot intel before deep-dive lookup.")
    parser.add_argument("--json", action="store_true", help="Emit JSON only.")
    args = parser.parse_args()

    payload = execute(args.request, limit=args.limit, hot_limit=args.hot_limit, refresh_hot=args.refresh_hot)

    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
        return

    route = payload["route"]
    print(f"mode: {route['mode']}")
    print(f"primary_agent: {route['primary_agent']}")
    print(f"summary: {route['summary']}")
    if payload["artifact"] is None:
        print("result: no bounded worker executed")
    elif route["mode"] == "deep_dive":
        result = payload["artifact"]["data"]
        print(f"vuln_id: {result['vuln_id']}")
        print(f"signals: {', '.join(sorted(result['core']['signals'].keys())) or '-'}")
        print(f"trivy_vuln_list_rows: {len(result['trivy_vuln_list'])}")
        print(f"go_exploitdb_rows: {len(result['go_exploitdb'])}")
        print(f"hot_rows: {len(result['hot'])}")
    elif route["mode"] == "watchlist":
        result = payload["artifact"]["data"]
        print(f"top_risks: {len(result['top_risks'])}")
        if "hot" in result:
            print(f"hot: {len(result['hot'])}")
    elif route["mode"] == "feed_refresh":
        freshness = payload["artifact"]["data"]
        print(f"feeds: {len(freshness)}")


if __name__ == "__main__":
    main()
