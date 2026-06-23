# vulnsignal
Lean AI-Native Vulnerability Intelligence Platform

Current feed priority: CVE Program, KEV, EPSS, GHSA, Trivy vuln-list, Vulnrichment, go-exploitdb. NVD is optional enrichment in the current phase.

GHSA, CVE Program, Trivy vuln-list, and Vulnrichment are all operated from local git mirrors under `data/`.
For core.db ingestion, only keep records published in 2015 or later.
Refresh those mirrors with `./scripts/update_data_mirrors.sh` before any ingest that depends on them.
Use `./scripts/refresh_all_sources.sh` when you also want to refresh `db/exploit.db` from go-exploitdb.
The mirror script uses shallow clones and recreates broken mirrors automatically.

For a reproducible smaller validation run, use `./scripts/ingest_recent_core_db.sh`.
It refreshes the local mirrors, ingests KEV, EPSS, CVE Program, GHSA, Trivy vuln-list, and Vulnrichment for the latest three calendar years by default, optionally ingests `db/exploit.db` when present, and finishes with `python3 -m sync.feed_quality`.

Current implementation plan: `docs/ROADMAP.md`

Python execution:

- If you have `uv` installed, prefer `uv run python -m ...` for repo commands.
- The repository now carries a minimal `pyproject.toml` and `uv.lock` so `uv` can manage the Python runtime and future lockfile.

Quick local refresh:

```bash
uv run python db/migrate.py
./scripts/refresh_all_sources.sh
./scripts/ingest_recent_core_db.sh
```

Recommended end-to-end flow for a local refresh and review:

1. Run `uv run python db/migrate.py`.
2. Refresh mirrors and `db/exploit.db` with `./scripts/refresh_all_sources.sh`.
3. Ingest the latest feed window with `./scripts/ingest_recent_core_db.sh`.
4. Refresh web intel with `uv run python -m sync.fetch_hot` after `core.db` is current.
5. Inspect feed health with `uv run python -m sync.feed_quality`.
6. For a quick answer, use `uv run python -m app.skills hot --limit 10 --details` or a short SQL list.

For one practical scheduling example, see the `Hot web intel` section in [docs/FEEDS.md](docs/FEEDS.md). It shows a model case with daily core refresh, 6-hour hot collection, and a short hot watchlist. Treat it as an example, not a hard requirement.
For `hot` discovery keywords and short-list review examples, see [docs/FEEDS.md](docs/FEEDS.md).
`hot` should be run from a local shell with working outbound HTTP/DNS; restricted-network environments may return zero discoveries even when the code is healthy.
For a bounded single-CVE worker, use `uv run python scripts/deep_dive.py CVE-2026-31431 --json`.
For the bounded single-CVE worker contract, see [docs/DEEP_DIVE.md](docs/DEEP_DIVE.md).

If you only want the live KEV feed, run `uv run python -m sync.fetch_kev` directly. If you only want the live EPSS snapshot, run `uv run python -m sync.fetch_epss` directly. For a bounded validation corpus, prefer the wrapper script. It keeps the mirror refresh, KEV, EPSS, and recent advisory ingest window in one pass.

`./scripts/ingest_recent_core_db.sh` now takes a lock so two refreshes do not run at the same time. It expects the local mirrors for CVE Program, GHSA, Trivy vuln-list, and Vulnrichment to be refreshed by `./scripts/update_data_mirrors.sh` first. If you also want a fresh `db/exploit.db`, run `./scripts/refresh_all_sources.sh` first. The ingest script stores the last successful mirror refs in `db/refresh_recent_core_db.refs`, so subsequent runs diff against the last ingested commit instead of `HEAD@{1}`. If network refresh is unavailable, set `SKIP_MIRROR_REFRESH=1` and the script will continue with the current local mirrors.

`refresh_all_sources.sh` looks for `go-exploitdb` in `EXPLOITDB_BINARY`, `GO_EXPLOITDB_BINARY`, `PATH`, `$(go env GOBIN)`, and `$(go env GOPATH)/bin` in that order.

Git pre-commit secret scanning:

```bash
./scripts/install-git-hooks.sh
```

This enables the repo-managed `.githooks/pre-commit` hook, which runs `gitleaks` on staged changes.
Run this once after cloning the repo to enable the hook in your local Git config.

Install `gitleaks` first. Common options:

- macOS: `brew install gitleaks`
- Linux: use your package manager if available, or download the binary from the `gitleaks` releases page
- Go install: `go install github.com/gitleaks/gitleaks/v8@latest`

go-exploitdb execution path:

1. Install a matching binary, for example `go install github.com/vulsio/go-exploitdb@latest`.
2. Fetch SQLite data with the repo wrapper, which defaults to all source families, for example `python3 -m sync.update_exploitdb --binary ~/go/bin/go-exploitdb`.
3. Validate the generated DB through `sync/exploit_adapter.py`.
4. Import CVE-linked rows with `python3 -m sync.fetch_exploitdb --db db/exploit.db`.

CVE Program execution path:

1. Mirror `CVEProject/cvelistV5` locally with `git clone --depth 1 https://github.com/CVEProject/cvelistV5 data/cvelistv5-mirror`.
2. Refresh that mirror with `git -C data/cvelistv5-mirror pull --ff-only`.
3. Ingest the local JSON tree with `python3 -m sync.fetch_cve_program --source-dir data/cvelistv5-mirror`.
4. Use `--min-year 2024` for a bounded validation ingest.

GHSA execution path:

1. Mirror `github/advisory-database` locally with `git clone --depth 1 https://github.com/github/advisory-database data/github-advisory-database-mirror`.
2. Refresh that mirror with `git -C data/github-advisory-database-mirror pull --ff-only`.
3. Ingest the reviewed advisory tree with `python3 -m sync.fetch_ghsa --source-dir data/github-advisory-database-mirror`.
4. Use `--include-unreviewed` only if you want the extra advisory set.

Trivy vuln-list execution path:

1. Mirror `aquasecurity/vuln-list` locally with `git clone --depth 1 https://github.com/aquasecurity/vuln-list data/aquasecurity-vuln-list-mirror`.
2. Refresh that mirror with `git -C data/aquasecurity-vuln-list-mirror pull --ff-only`.
3. Ingest the local JSON tree with `python3 -m sync.fetch_trivy_vuln_list --source-dir data/aquasecurity-vuln-list-mirror`.
4. Use the mirror as the normal source of truth when you need package ranges, fixed versions, or target-specific advisory detail; do not expect `core.db` alone to retain that full history.
5. For a concrete lookup recipe, see [docs/DEEP_DIVE.md](docs/DEEP_DIVE.md). It points you to `core.db`, `vuln-list`, `db/exploit.db`, and `hot` in a repeatable order.

Vulnrichment execution path:

1. Mirror the CISA Vulnrichment repository locally, for example `git clone --depth 1 https://github.com/cisagov/vulnrichment data/vulnrichment-mirror`.
2. Refresh that mirror with `git -C data/vulnrichment-mirror pull --ff-only`.
3. Ingest the local JSON tree with `python3 -m sync.fetch_vulnrichment --source-dir data/vulnrichment-mirror`.
4. Use `--dry-run` first if you want to verify the local file tree before writing signals.

Observed in this project:

- `exploitdb` produced 60,578 Offensive Security records.
- 30,862 of those rows had CVE IDs and were importable as `exploit` signals.
- The current go-exploitdb build exposes `exploits` plus `fetch_meta`, where `fetch_meta.schema_version` was `3`.


```
project/
├── AGENTS.md
├── app/
│   └── AGENTS.md
├── sync/
│   └── AGENTS.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SCHEMA.md
│   ├── SCORING.md
│   └── FEEDS.md
└── .agents/skills/
    ├── api/SKILL.md
    ├── core-db-analysis/SKILL.md
    ├── core-db-insights/SKILL.md
    ├── feeds/SKILL.md
    ├── hot-intel/SKILL.md
    ├── schema/SKILL.md
    └── scoring/SKILL.md
```


Trivy の主経路は advisory JSON と `aquasecurity/vuln-list` です。compiled DB は任意のバックフィル用途としてのみ残しています。
package-range や fixed-version の確認が必要なときは、`aquasecurity/vuln-list` の local mirror を前提にしてください。`core.db` には full history を持たせません。
取得手順とローカル cache の要件は [docs/FEEDS.md](docs/FEEDS.md) を参照してください。
`core.db` が他の ingest でロックされている場合は、`VULNSIGNAL_DB_PATH=/tmp/vulnsignal-core.db` のように別 DB を指定して再現用 ingest を回せます。

Trivy DB を手動で読む場合の実行例:

```bash
uv run python -m sync.fetch_trivy_db --db-dir db/trivy_cache.db
```

`db/trivy_cache.db` には `trivy.db` と `metadata.json` が必要です。
`sync/fetch_trivy_db.py` は `vulnerability` を正規化して `enrichment` signals に落としますが、通常更新フローでは回しません。

GitHub CLI の認証を平文で残したくない場合は、`scripts/gh_secret.py store` で Secret Service に token を入れてから `scripts/check_dependabot.sh` を使ってください。
移行中だけ `ALLOW_PLAINTEXT_GH=1` を付けると既存の `gh auth` 保存値を読むフォールバックにできます。
Dependency cooldown は lock の更新時にかけています。たとえばローカルで dependency を更新するときは `UV_EXCLUDE_NEWER="$(date -u -d '7 days ago' +%F)"` を付けてから `uv lock` を実行してください。CI の frozen install では lockfile をそのまま使います。

```bash
UV_EXCLUDE_NEWER="$(date -u -d '7 days ago' +%F)"
uv lock --exclude-newer "$UV_EXCLUDE_NEWER"
uv sync --frozen --dev
uv run python -m pytest -q
```
