---
name: core-db-analysis
description: フィードの重複、更新量、遅延、データマートの網羅率やソース間の重なりをローカル DB から集計する。
---

# データ品質とカバレッジ

`uv run python db/migrate.py` 後、`uv run python -m sync.feed_quality` でフィードごとの取得状況を確認する。期間集計が必要なら `db/core.db` を読み取り専用で開き、[スキーマ](../../../docs/SCHEMA.md) に従う。

- 更新コストを比較する場合は `fetch_log` と `feed_metrics` を取得回ごとに結ぶ。キャッシュ利用、失敗、計測値の欠測を区別する。
- 対象期間と時計を明示する。イベントの発生は `intel_event`、観測の流入は `signals.observed_at` で集計する。観測行数、イベント数、ユニークな脆弱性数はそれぞれ分母を示す。
- 提供元間の重なりは `intel_evidence` から提供元ごとの `DISTINCT vuln_id` を求める。同じ CVE に独自の評価変更や根拠がある可能性も調べてから、ソースを省けるか判断する。
- EPSS の現時点の網羅率は `epss_current` との結合で算出する。CVSS の履歴は `intel_cvss` を使い、欠測とスコア 0 を区別する。

個別の脆弱性例を添える場合は `scripts.intel search` と `evidence` で検算する。結果には再集計できる期間、条件、集計単位を含める。
