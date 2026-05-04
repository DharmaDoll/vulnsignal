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
