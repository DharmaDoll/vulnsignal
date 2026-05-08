# vulnsignal
Lean AI-Native Vulnerability Intelligence Platform

Current feed priority: KEV, EPSS, GHSA, Trivy JSON, Vulnrichment, go-exploitdb. NVD is optional enrichment in the current phase.

Current implementation plan: `docs/ROADMAP.md`

Git pre-commit secret scanning:

```bash
./scripts/install-git-hooks.sh
```

This enables the repo-managed `.githooks/pre-commit` hook, which runs `gitleaks` on staged changes.

Install `gitleaks` first. Common options:

- macOS: `brew install gitleaks`
- Linux: use your package manager if available, or download the binary from the `gitleaks` releases page
- Go install: `go install github.com/gitleaks/gitleaks/v8@latest`

go-exploitdb execution path:

1. Install a matching binary, for example `go install github.com/vulsio/go-exploitdb@v0.7.0`.
2. Fetch SQLite data, for example `go-exploitdb fetch exploitdb --dbtype sqlite3 --dbpath db/exploit.db`.
3. Validate the generated DB through `sync/exploit_adapter.py`.
4. Import CVE-linked rows with `python3 -m sync.fetch_exploitdb --db db/exploit.db`.

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
