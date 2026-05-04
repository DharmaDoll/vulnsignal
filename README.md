# vulnsignal
Lean AI-Native Vulnerability Intelligence Platform


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

③ あなたの目的は判断基盤
必要なのは全内部構造ではなく：
	•	このCVEは何に効くか
	•	fixed versionは何か
	•	このassetに影響あるか

です。

⸻

3. 統合方針（推奨）
Layer分離


trivy --download-db-only


次にやるべき実装（超重要）
Trivyの実DB形式から直接抽出するコード
または
ecosystem別 version comparator 実装
