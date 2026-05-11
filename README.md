# vulnsignal
Lean AI-Native Vulnerability Intelligence Platform

Current feed priority: CVE Program, KEV, EPSS, GHSA, Trivy JSON, Vulnrichment, go-exploitdb. NVD is optional enrichment in the current phase.

GHSA, CVE Program, Trivy vuln-list, and Vulnrichment are all operated from local git mirrors under `data/`.
For core.db ingestion, only keep records published in 2015 or later.
Refresh those mirrors with `./scripts/update_data_mirrors.sh`.
The script uses shallow clones and recreates broken mirrors automatically.

For a reproducible smaller validation run, use `./scripts/ingest_recent_core_db.sh`.
It refreshes the local mirrors, ingests the latest three calendar years by default, and finishes with `python3 -m sync.feed_quality`.

Current implementation plan: `docs/ROADMAP.md`

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

1. Install a matching binary, for example `go install github.com/vulsio/go-exploitdb@v0.7.0`.
2. Fetch SQLite data, for example `go-exploitdb fetch exploitdb --dbtype sqlite3 --dbpath db/exploit.db`.
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
├── AGENTS.md              94行  ← ルート命令書
├── app/
│   └── AGENTS.md          27行  ← API/スコアリング層専用
├── sync/
│   └── AGENTS.md          26行  ← フィード/アダプタ層専用
├── docs/
│   ├── ARCHITECTURE.md         ← 人間向け設計思想
│   ├── SCHEMA.md               ← テーブル定義・マイグレーション
│   ├── SCORING.md              ← スコア計算式
│   └── FEEDS.md                ← フィード仕様・アダプタ契約
└── .agents/skills/
    ├── scoring/SKILL.md        ← スコアリング作業時に自動呼び出し
    ├── feeds/SKILL.md          ← フィード/アダプタ作業時に自動呼び出し
    └── schema/SKILL.md         ← スキーマ/マイグレーション作業時に自動呼び出し
```


Trivy は advisory JSON と compiled DB の両方を扱えます。
JSON は package advisory の入力として使い、compiled DB は vulnerability metadata の enrichment に使います。
取得手順とローカル cache の要件は [docs/FEEDS.md](/home/calvet/git/vulnsignal/docs/FEEDS.md) を参照してください。

直読みの実行例:

```bash
python3 -m sync.fetch_trivy_db --db-dir db/trivy_cache.db
```

`db/trivy_cache.db` には `trivy.db` と `metadata.json` が必要です。
`sync/fetch_trivy_db.py` が `vulnerability` を正規化して `enrichment` signals に落とします。
