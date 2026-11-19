# DEEP_DIVE.md

## Purpose

This document defines the repeatable workflow for investigating a single
vulnerability when the system flags it as important.

Use it when you want to answer:

- Is this CVE already in `core.db`?
- Which signals support it?
- What package ranges or fixed versions are recorded in GHSA?
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
3. Resolve package context from GHSA package advisory signals.
4. Inspect `db/exploit.db` through `sync.exploit_adapter` if exploit detail matters.
5. Refresh or inspect `hot` if current attention matters.
6. Persist only if the result belongs in normal feed ingest.

## Local sources

- `db/core.db` - canonical normalized platform state
- `db/exploit.db` - raw go-exploitdb context
- `hot` - current attention signal

## Canonical lookup recipe

Use this as the default single-CVE workflow.

```bash
VULN_ID='CVE-2026-31431'
python3 scripts/deep_dive.py "$VULN_ID" --json
```

## Interpretation rules

- `core.db` tells you whether the platform already knows about the item.
- `signals` tell you whether the item is escalating.
- GHSA package advisories provide package and fixed-version detail.
- `db/exploit.db` tells you whether the raw exploit corpus has PoC or
  weaponized material.
- `hot` tells you whether the item is currently getting attention.

## Worker contract

`scripts/deep_dive.py <CVE-ID> --json` emits a versioned JSON object with:

- `schema_version`: `2`
- `kind`: `deep_dive`
- `vuln_id`
- `generated_at`
- `sources`
- `core`
- `package_advisories`
- `go_exploitdb`
- `hot`
- `hot_refresh`

Keep those fields stable. When the lookup is worth keeping, rerun the bounded
ingest so the platform state stays consistent with the investigation.

## Skills CLI envelope

`python3 -m app.skills <command> --json` also returns a versioned envelope with
`schema_version`, `kind`, and `result`. Keep that shape stable across
`hot`, `vuln`, `risks`, `patch-queue`, `has-exploit`, `assets`, `asset-risk`,
and `freshness`.
