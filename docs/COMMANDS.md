# 運用コマンド

VulnSignal のコマンドを、役割と実行タイミングで整理する。すべてリポジトリのルートで実行する。Python コマンドには `uv run python` を使用する。

## 基本の運用

期間内の注目一覧をAgentが選ぶときは、次のコマンドで全体・話題性・登録テーマの候補をまとめて取得する。各検索は既定10件で、CVEごとの hits に検索経路、順位、根拠を保持する。limit_reached が真の場合は候補の偏りを確認し、必要に応じて --limit を増やす。

```bash
uv run python -m scripts.intel candidates --since 2026-11-16T15:28:00+09:00 --until 2026-11-19T15:28:00+09:00
```

```text
refresh_intelligence.py --refresh
              |
              v
       scripts.intel search
              |
              v
      scripts.intel evidence
```

| コマンド | 役割 | 実行するタイミング |
|---|---|---|
| `uv run python scripts/refresh_intelligence.py --refresh` | ミラーと有効な外部フィードを更新し、正規化、hot取得、検索マート反映まで実行する | 定期更新、Agentに最新情報を質問する前 |
| `uv run python scripts/refresh_intelligence.py --refresh --save` | 通常更新に加えてトリアージ結果と再現用データを保存する | 監査記録や日次成果物が必要なとき |
| `uv run python -m scripts.intel search --term nginx` | ローカルの検索マートを任意語で検索する | 製品名や技術名から注目情報を探すとき |
| `uv run python -m scripts.intel search --theme Java --since 2026-11-01` | 登録テーマと期間で検索する | Java、Reactなどの注視対象を期間指定で調べるとき |
| `uv run python -m scripts.intel search --id CVE-2026-123007` | 特定CVEのイベント、CVSS、EPSS、PoC参照を検索する | 個別脆弱性を調べるとき |
| `uv run python -m scripts.intel evidence SIGNAL_ID` | 検索結果から元の観測、提供元、URLを確認する | Agentの回答根拠を検証するとき |

`refresh_intelligence.py --refresh` が通常運用の入口である。マイグレーション、ソース更新、差分取り込み、hot更新、検索マート更新をまとめて行う。Trivyは現行の通常更新経路に含まれない。

## 検索例

| 知りたいこと | コマンド |
|---|---|
| 直近7日間のNGINX関連 | `uv run python -m scripts.intel search --term nginx` |
| 11月に公表されたJava関連 | `uv run python -m scripts.intel search --theme Java --clock source --since 2026-11-01T00:00:00+09:00 --until 2026-12-01T00:00:00+09:00` |
| CVSSが上昇した脆弱性 | `uv run python -m scripts.intel search --kind cvss_increase --since 2026-11-01` |
| EPSSパーセンタイル0.99以上のPoC参照 | `uv run python -m scripts.intel search --kind exploit_reference --min-percentile 0.99 --sort epss` |
| 特定CVEのCVSS下降履歴 | `uv run python -m scripts.intel search --id CVE-2022-30333 --kind cvss_decrease` |

`--clock source` は公表日、`--clock observed` はローカル取得時刻を基準にする。既定の `effective` はイベントの性質に応じた時刻を採用する。

## 部分更新と状態確認

| コマンド | 役割 | 実行するタイミング |
|---|---|---|
| `uv run python -m scripts.intel refresh` | 保存済みの観測を検索マートへ増分反映する | 検索結果の `unindexed` が正のとき、既存DBからマートを構築するとき |
| `uv run python -m sync.feed_quality` | 鮮度、取得状態、キャッシュ利用、件数、重複率を表示する | 更新後の確認、欠測や遅延の調査 |
| `uv run python -m sync.fetch_hot` | 話題性情報を取得する | 報道、公開PoC、悪用情報の話題性だけを更新したいとき |
| `uv run python -m sync.fetch_hot --vuln-id CVE-2026-123007` | 特定CVEの話題性を取得する | 個別案件の追加調査 |
| `uv run python -m sync.fetch_kev` | CISA KEVを更新する | KEV掲載状況を優先して更新したいとき |
| `uv run python -m sync.fetch_epss` | FIRST EPSSの日次スナップショットを更新する | EPSSだけを更新したいとき |

`sync.fetch_hot` の単独実行後は検索マートへ反映する。

```bash
uv run python -m sync.fetch_hot
uv run python -m scripts.intel refresh
```

## 取得と取り込みの内部コマンド

| コマンド | 役割 | 実行するタイミング |
|---|---|---|
| `./scripts/update_data_mirrors.sh` | CVE Program、GHSA、VulnrichmentのGitミラーを更新する | ミラー更新だけを検証するとき |
| `./scripts/refresh_all_sources.sh` | Gitミラーとgo-exploitdbを更新する | PoCデータベースを含む取得処理を分離して調べるとき |
| `./scripts/ingest_recent_core_db.sh` | 各ソースの差分を正規化して `core.db` へ取り込む | 取得済みソースの取り込みを再実行するとき |
| `uv run python db/migrate.py` | SQLiteスキーマを最新版へ移行する | DBを直接扱うスクリプトやテストの前 |

通常更新では `refresh_intelligence.py --refresh` がこれらを適切な順序で呼び出す。個別コマンドは障害の切り分け、フィード開発、再取り込みで使用する。

## 分析と任意出力

| コマンド | 役割 | 実行するタイミング |
|---|---|---|
| `uv run python -m scripts.period_recommendations --period week --date 2026-11-18` | 日・週・月・四半期の推薦を生成する | 会話外で期間集計を確認するとき |
| `uv run python -m scripts.period_recommendations --period month --date 2026-11-01 --save` | 期間推薦と再現用アーカイブを保存する | 後から同じ入力で再評価したいとき |
| `uv run python scripts/report_recent_attention.py --days 7 --as-of 2026-11-19T00:00:00+09:00` | 指定時点を基準に注目情報をファイル出力する | 過去時点の一覧を再生成するとき |
| `uv run python scripts/deep_dive.py CVE-2026-123007 --json` | 特定CVEを複数シグナルから詳細分析する | 個別案件の深掘り |
| `uv run python scripts/triage_new_cves.py --hours 24 --limit 40 --json` | 新規取り込みCVEの候補選定結果を表示する | 推薦ルールの調査やデバッグ |

通常のAgent応答は `scripts.intel search` と `scripts.intel evidence` を使用する。レポート系コマンドはファイル成果物や再現用アーカイブが必要な場合に使用する。

## 開発と互換入口

| コマンド | 役割 | 実行するタイミング |
|---|---|---|
| `uv run python -m pytest -q` | 全テストを実行する | コード、スキーマ、フィード処理を変更した後 |
| `uv run python scripts/refresh_intelligence.py --help` | 更新入口のオプションを確認する | 運用オプションを確認するとき |
| `uv run python -m scripts.intel search --help` | 検索条件を確認する | テーマ、期間、EPSS、イベント種別を組み合わせるとき |

`scripts/run_daily_review.py --daily` は旧名称との互換入口である。新しい手順とジョブでは `scripts/refresh_intelligence.py --refresh` を使用する。

## 関連ドキュメント

- [アーキテクチャ](ARCHITECTURE.md)
- [フィード仕様と鮮度基準](FEEDS.md)
- [検索マートのスキーマ](SCHEMA.md)
- [レポートと保存先](REPORTS.md)
