# DEEP_DIVE.md

## Purpose

This document defines the repeatable workflow for investigating a single
vulnerability when the system flags it as important.

Use it when you want to answer:

- Is this CVE already in `core.db`?
- Which signals support it?
- What package ranges or fixed versions does Trivy provide?
- Is there a concrete exploit or PoC?
- Is it currently getting attention?

The goal is reproducibility. Every lookup should be repeatable from the same
local sources without relying on memory.

## Agent routing

Use a `main` agent for the final answer and a `sub-agent` only for bounded
work that can be checked independently.

- `main` owns the user-facing conclusion.
- `sub-agent` may gather evidence, rank candidates, or inspect one source at a
  time.
- `main` should still decide what the user sees.

Recommended split:

- `main`:
  - "今追うべき10件"
  - "このCVEをどう扱うべきか"
  - final ranking or watchlist synthesis
- `sub-agent`:
  - `core.db` candidate extraction
  - `hot` refresh or inspection for one `vuln_id`
  - `db/exploit.db` lookup
  - `vuln-list` mirror search
  - docs and skill consistency checks

Preview the split before you work:

```bash
uv run python -m app.skills route "Here is the request you want to inspect"
```

CLI-only orchestration pattern:

```bash
REQUEST='CVE-2026-31431 deep dive'

uv run python -m app.skills route "$REQUEST" --json > /tmp/vulnsignal-route.json
cat /tmp/vulnsignal-route.json

# main agent reads the route JSON and then launches bounded workers.
# Example worker action:
uv run python scripts/deep_dive.py CVE-2026-31431 --json

# Thin wrapper that does both:
uv run python scripts/run_route.py "$REQUEST" --json
```

Worker contract for this repo:

- `route` always decides the split, but it does not execute workers.
- `main` owns the final answer and any synthesis.
- each worker should return one bounded artifact:
  - one CVE
  - one watchlist
  - one hot refresh
  - one exploit lookup
- the main agent can combine those artifacts without exposing sub-agent internals.

The wrapper JSON is stable and should contain:

- `request`
- `generated_at`
- `route`
- `execution`
- `artifact`
- `result`

Example shapes:

- `deep_dive`
  - `artifact.kind = "deep_dive"`
  - `artifact.data.core`
  - `artifact.data.trivy_vuln_list`
  - `artifact.data.go_exploitdb`
  - `artifact.data.hot`
- `watchlist`
  - `artifact.kind = "watchlist"`
  - `artifact.data.top_risks`
  - `artifact.data.hot` when the request asked for hot attention
- `feed_refresh`
  - `artifact.kind = "freshness"`
  - `artifact.data` is the feed freshness array from `fetch_log`

Minimal JSON sketches:

```json
{
  "request": "ここ三日間の注目の脆弱性を30件",
  "generated_at": "2026-06-18T08:14:02Z",
  "route": { "mode": "watchlist" },
  "execution": { "status": "ok", "worker_count": 1 },
  "artifact": {
    "kind": "watchlist",
    "summary": "Ranked watchlist bundle",
    "worker": "app.skills",
    "data": {
      "top_risks": [],
      "hot": []
    }
  },
  "result": {
    "top_risks": [],
    "hot": []
  }
}
```

```json
{
  "request": "feed freshness",
  "generated_at": "2026-06-18T08:14:02Z",
  "route": { "mode": "feed_refresh" },
  "execution": { "status": "ok", "worker_count": 1 },
  "artifact": {
    "kind": "freshness",
    "summary": "Feed freshness bundle",
    "worker": "app.skills",
    "data": []
  },
  "result": []
}
```

Do not split:

- policy changes
- score or ranking formula decisions
- deletion or destructive changes
- ambiguous intent resolution

## Default investigation order

1. Check `db/core.db` for the `vulnerabilities` row.
2. Inspect `signals` for `kev`, `exploit`, and `hot`.
3. Resolve package context from the local `aquasecurity/vuln-list` mirror.
4. If exploit detail matters, inspect `db/exploit.db` through
   `sync.exploit_adapter`.
5. If current attention matters, refresh or inspect `hot`.
6. Persist only if the result should become part of the normal feed ingest.

## Local sources

- `db/core.db` - canonical normalized platform state
- `data/aquasecurity-vuln-list-mirror` - package and OSV detail on demand
- `db/exploit.db` - raw go-exploitdb context
- `hot` - current attention signal

## Canonical lookup recipe

Use this as the default single-CVE workflow.

```bash
VULN_ID='CVE-2026-31431'
MIRROR_DIR='data/aquasecurity-vuln-list-mirror'

rg -n --glob '*.json' "$VULN_ID" "$MIRROR_DIR"/{alpine,debian,ubuntu,ghsa,glad,go,osv,seal}

python3 - <<'PY'
from pathlib import Path
from datetime import datetime, timezone
from sync.trivy_adapter import load_advisories_for_vuln_id_from_directory

vuln_id = 'CVE-2026-31431'
source_dir = Path('data/aquasecurity-vuln-list-mirror')
observed_at = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
targets = ['alpine', 'debian', 'ubuntu', 'ghsa', 'glad', 'go', 'osv', 'seal']

for advisory in load_advisories_for_vuln_id_from_directory(source_dir, vuln_id, observed_at, targets=targets):
    print(advisory.vuln_id, advisory.source, advisory.ecosystem, advisory.package_name, advisory.fixed_version)
PY

sqlite3 -header -column db/core.db "
SELECT signal_type, provider, score, observed_at
FROM signals
WHERE vuln_id = '$VULN_ID'
ORDER BY observed_at DESC, id DESC;
"

python3 -m sync.fetch_hot --vuln-id "$VULN_ID" --simple
```

## Interpretation rules

- `core.db` tells you whether the platform already knows about the item.
- `signals` tell you whether the item is escalating.
- `vuln-list` tells you package and fixed-version detail.
- `db/exploit.db` tells you whether the raw exploit corpus has PoC or
  weaponized material.
- `hot` tells you whether the item is currently getting attention.

## Reproducibility checklist

When you finish the lookup, keep these fields in the note:

- `vuln_id`
- `package_name`
- `fixed_version`
- `signal_type`
- the local file path you used

If the item is worth keeping, rerun the bounded ingest after the deep dive so
the platform state stays consistent with the investigation.
