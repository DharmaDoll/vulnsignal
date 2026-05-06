# vulnsignal
Lean AI-Native Vulnerability Intelligence Platform

Current feed priority: KEV, EPSS, GHSA, Trivy JSON, Vulnrichment, go-exploitdb. NVD is optional enrichment in the current phase.

Current implementation plan: `docs/ROADMAP.md`

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


Trivy DB をそのまま core.db に混ぜ込むのではなく、構造を理解して必要情報だけ signals / vulnerabilities に正規化して取り込むのが正解です。
Trivy DBはそのまま保存する対象ではない。知識源として抽出・翻訳して使う対象です。

1. Trivy DBとは何か
Trivy は内部で脆弱性DBを持っています。
主な用途：
	•	OS package advisory
	•	Language package advisory
	•	CVEとパッケージの紐付け
	•	fixed version 情報

これは NVDより実運用寄りデータ です。

⸻

2. そのまま統合しない理由
理由は3つ。
① 内部構造がTrivy都合
Trivy用に最適化されているため：

③ 目的は判断基盤
必要なのは全内部構造ではなく：
	•	このCVEは何に効くか
	•	fixed versionは何か
	•	このassetに影響あるか

です。

⸻

3. 現実的な抽出方法（重要）

```
trivy --download-db-only
```

Trivy内部DB形式を直接読むより、Trivyが持つ advisory JSON を利用する方が安全です。
Trivy repo / advisory sources を JSON取得

次にやるべき実装（超重要）
Trivyの実DB形式から直接抽出するコード
ecosystem別 version comparator 実装


```python
import sqlite3
import json

DB = "core.db"

conn = sqlite3.connect(DB)
cur = conn.cursor()

with open("trivy_advisories.json") as f:
    advisories = json.load(f)

for item in advisories:
    vuln_id = item["VulnerabilityID"]
    pkg = item["PkgName"]
    fixed = item.get("FixedVersion")
    severity = item.get("Severity", "UNKNOWN")

    # InstalledVersion をそのまま条件として使わず、
    # advisory由来の affected range があればそちら優先
    affected = "< " + fixed if fixed else None

    cur.execute("""
        INSERT INTO package_impacts (
            vuln_id,
            ecosystem,
            package_name,
            affected_constraint,
            fixed_version,
            severity,
            provider
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        vuln_id,
        "linux",
        pkg,
        affected,
        fixed,
        severity,
        "Trivy"
    ))

conn.commit()
conn.close()

```
