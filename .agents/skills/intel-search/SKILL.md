---
name: intel-search
description: ローカルの脆弱性データマートを検索し、期間・技術テーマ別の注目項目や特定 CVE の評価変化を根拠付きで回答する。
---

# 脆弱性情報の対話検索

「ここ3日で注視すべきもの」など期間内の注目一覧には、まず次を使う。開始と終了を利用者のタイムゾーンで確定し、同じ境界で根拠確認まで進める。

```sh
uv run python -m scripts.intel candidates --since 2026-11-16T15:28:00+09:00 --until 2026-11-19T15:28:00+09:00
```

全体・話題性・登録テーマを各10件検索し、CVEごとにまとめる。各候補の hits に検索経路、順位、根拠IDがある。全候補を確認してから回答に載せる案件を選ぶ。実悪用、記事の主題、成立条件、期間中の変化を確認し、テーマ一致だけで掲載を決めない。同じ記事の付随的な言及やバックフィルを新規の重要情報と誤認しない。

searches の limit_reached は検索上限に達した可能性を示す。候補が偏る場合や長期間を扱う場合は --limit（最大100）を増やすか期間を分けて補う。候補数と回答件数は別に扱う。回答に使う主張は evidence で確認する。

リポジトリのルートで `uv run python db/migrate.py` を実行する。`uv run python -m scripts.intel search` が通常の入口。期間を指定されたら、利用者のタイムゾーンで開始以上・終了未満の境界を渡す。たとえば日本時間の10月なら次のように検索する。

```sh
uv run python -m scripts.intel search --theme Java --since 2026-10-01T00:00:00+09:00 --until 2026-11-01T00:00:00+09:00
```

- 「期間中に公表」は `--clock source`、「ローカルで観測」は `--clock observed`。通常の注目項目には既定の `effective` を使い、`time_basis` を確認する。バックフィルで見つかった古い情報を新規公表として扱わない。
- 登録テーマは `--theme`、任意の語は `--term`。製品・パッケージへの一致に限定する場合は `--product-only`。テーマは取得後に照合し、`match.basis` が本文での言及にとどまる場合はその旨を示す。
- CVE の経緯は `--id`、CVSS 上昇は `--kind cvss_increase`。変化を説明するときは同じ提供元・アドバイザリ・バージョンの前後値を使う。EPSS はスコア日付を添え、過去期間で取得できない値は欠測として扱う。
- 公開 PoC の参照、KEV 掲載、ウェブでの話題は別の根拠として示す。回答に使うイベントは `uv run python -m scripts.intel evidence SIGNAL_ID` で確認し、脆弱性 ID、注目する理由、提供元、シグナル ID を結び付ける。
- `unindexed` が正なら `uv run python -m scripts.intel refresh` で取得済みの観測を反映して再検索する。`feed_status` が古い場合は結果の鮮度を明示する。ソース自体の更新依頼には `uv run python scripts/refresh_intelligence.py --refresh` を使う。

結果は会話で返す。期間レポートや再現用アーカイブの保存を依頼された場合は [README](../../../README.md) の期間別出力手順を使う。
