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

## Agent roles

If you split work across agents, keep the final answer in `main` and use a
bounded worker only for one CVE, one lookup, or one freshness check at a time.

## Default investigation order

1. Check `db/core.db` for the `vulnerabilities` row.
2. Inspect `signals` for `kev`, `exploit`, and `hot`.
3. Resolve package context from the local `aquasecurity/vuln-list` mirror.
4. Inspect `db/exploit.db` through `sync.exploit_adapter` if exploit detail matters.
5. Refresh or inspect `hot` if current attention matters.
6. Persist only if the result belongs in normal feed ingest.

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

## Worker contract

`scripts/deep_dive.py <CVE-ID> --json` returns a bounded bundle with `core`,
`trivy_vuln_list`, `go_exploitdb`, and `hot`. Use `--refresh-hot` only when you
need to refresh the local attention signal first.

Keep the note keyed by:

- `vuln_id`
- `package_name`
- `fixed_version`
- `signal_type`
- the local file path you used

## Reproducibility checklist

When you finish the lookup, keep the same fields listed above.

If the item is worth keeping, rerun the bounded ingest after the deep dive so
the platform state stays consistent with the investigation.
