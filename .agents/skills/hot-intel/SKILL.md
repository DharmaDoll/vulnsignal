---
name: hot-intel
description: hot フィードの再取得や、特定 CVE が話題性シグナルに採用された理由・欠落した理由を調査する。
---

# 話題性フィードの運用

`uv run python db/migrate.py` 後、`uv run python -m app.skills hot --limit 20 --details` で直近の根拠を確認する。新規取得を依頼されたら `uv run python -m sync.fetch_hot`、特定の CVE だけなら `--vuln-id` を指定する。その結果を対話検索に使う場合は `uv run python -m scripts.intel refresh` で反映する。

採否は検索ヒットと実際に採用された `evidence_details` を区別し、情報源と観測時刻で説明する。プロファイルと調査コマンドは [hot の運用例](references/hot.md) を参照。
