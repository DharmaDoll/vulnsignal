---
name: scoring
description: 既存の app/scoring.py の資産別 risk_score や scoring_version を明示的に保守するときに使う。
---

# 資産別スコアの保守

[スコア仕様](../../../docs/SCORING.md) と `app/scoring.py` を照合し、既存の呼び出し元が使うスコア・抑制理由・バージョンの契約を確認する。計算式の改訂時は過去の判断に記録されたバージョンを保持する。

資産連携は凍結中。対話検索の優先順位や CVSS の変更イベントを扱う実装は `scripts/intel.py` にある。
