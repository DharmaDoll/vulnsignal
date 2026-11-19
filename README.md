# vulnsignal
Lean AI-Native Vulnerability Intelligence Platform

Current feed priority: CVE Program, KEV, EPSS, GHSA, Vulnrichment, go-exploitdb. NVD is optional enrichment in the current phase.

GHSA, CVE Program, and Vulnrichment are all operated from local git mirrors under `data/`.
For core.db ingestion, only keep records published in 2015 or later.
Refresh those mirrors with `./scripts/update_data_mirrors.sh` before any ingest that depends on them.
Use `./scripts/refresh_all_sources.sh` when you also want to refresh `db/exploit.db` from go-exploitdb.
The mirror script uses shallow clones and recreates broken mirrors automatically.

For a reproducible smaller validation run, use `./scripts/ingest_recent_core_db.sh`.
It refreshes the local mirrors, ingests KEV, EPSS, CVE Program, GHSA, and Vulnrichment for the latest three calendar years by default, optionally ingests `db/exploit.db` when present, and finishes with `python3 -m sync.feed_quality`.

Current implementation plan: `docs/ROADMAP.md`
Report types and dependencies: `docs/REPORTS.md`
Command roles and execution timing: [docs/COMMANDS.md](docs/COMMANDS.md)

## ローカル知識をAgentから検索する

期間内の注目一覧には `uv run python -m scripts.intel candidates --since 2026-11-16T15:28:00+09:00 --until 2026-11-19T15:28:00+09:00` を使用します。全体・話題性・登録テーマの検索をまとめ、CVEごとに候補と根拠を返します。Agentは候補全体を確認して回答を選びます。

`uv run python scripts/refresh_intelligence.py --refresh` でフィードを更新し、SQLiteの検索用データマートへ増分反映します。既存データだけで構築するときは `uv run python -m scripts.intel refresh` を実行します。通常更新の成果物は `db/core.db` です。

```bash
uv run python -m scripts.intel search --theme Java --since 2026-11-19T00:00:00+09:00
uv run python -m scripts.intel search --term React --product-only
uv run python -m scripts.intel search --kind kev --clock source --limit 5
uv run python -m scripts.intel search --id CVE-2026-114938
uv run python -m scripts.intel evidence 1102213
```

検索はJSONを標準出力に返します。日付指定なしの一般検索は直近7日間、ID指定はその案件の時系列です。`--since` は開始を含み、`--until` は終了を含みません。全体検索はCVEごとに代表的な出来事を返します。重要度の並びはKEV、報道、公開資料、重大評価、その他です。KEVと報道は証拠の種類が異なります。

`source_date` は公告の公表日・KEV追加日、`observed_at` はローカル観測時刻です。既定の期間検索は出典日付を優先し、日付不明の公告・採点・修正版を除きます。報道や公開資料の初観測は `time_basis` で明示します。`--clock source` は出典日付があるもの、`--clock observed` はローカルの取り込み経過を調べるために使います。技術テーマの一致根拠と推薦根拠は別々の signal_id から確認できます。0件の場合は unindexed と feed_status も確認してください。ミラーの取得状態とDBへの取り込み時刻は異なります。

### EPSSとCVSSの再評価を調べる

```bash
uv run python -m scripts.intel search --kind exploit_reference --min-percentile 0.99 --sort epss
uv run python -m scripts.intel search --kind cvss_increase --since 2026-11-01 --min-epss 0.05
uv run python -m scripts.intel search --id CVE-2022-30333 --kind cvss_decrease
```

EPSSとパーセンタイルの閾値は0～1で指定し、両方を指定するとAND条件になる。欠損はJSONのnullで、閾値を指定した検索からは外れる。score_dateはその値の保存元の日付。現在値が締切後に更新されていれば過去の値を推測しない。

CVSSの現在値は出典の優先順（GHSA、Vulnrichment、CVE Program）に沿って選び、同じ出典では最新の観測を採用する。比較は同じ脆弱性・出典・アドバイザリ・CVSS版の連続観測間で行う。初回観測は変更に数えない。上昇は通常検索で重大評価より優先する。変更には旧値、新値、差分、旧・新のsignal_idがあり、個々の出典による変更と現在の採用値を別々に表示する。上昇・下降の日時はローカルで差を観測した時刻。元の公開日とは異なり得る。数値がなく、有効なベクトルがある場合は基本値を計算する。

## 任意のレポート出力

`uv run python -m scripts.period_recommendations --period week --date 2026-11-18` は保存済み証拠から暦週の要約を表示します。日報・再生用ファイルが必要な場合は、日次CLIまたは期間別CLIに `--save` を付けます。旧版の保存済み入力は `--replay FILE` で再計算できます。

For a reproducible recent-attention report without refreshing mirrors or
ingesting feeds, use:

```bash
uv run python scripts/report_recent_attention.py --days 7 --as-of 2026-07-17T00:00:00+00:00
```

The report includes date columns (`published`, `first_seen`, and hot
`observed`) and saves the exact JSON artifact under `data/reports/attention/`.
Pin `--as-of` to reproduce the same relative window against the same local DB
state.

Python execution:

- If you have `uv` installed, prefer `uv run python -m ...` for repo commands.
- The repository now carries a minimal `pyproject.toml` and `uv.lock` so `uv` can manage the Python runtime and future lockfile.

Branch hygiene:

- Before creating a new branch, rebase the current worktree onto `origin/main` so the branch starts from the latest mainline state.

Quick local refresh:

```bash
uv run python db/migrate.py
./scripts/refresh_all_sources.sh
./scripts/ingest_recent_core_db.sh
```

The intelligence refresh command avoids refreshing git mirrors twice in one run. If
`refresh_all_sources.sh` already refreshed mirrors, the ingest step automatically
uses `SKIP_MIRROR_REFRESH=1`.

通常更新には `uv run python scripts/refresh_intelligence.py --refresh` を使います。更新後は Agent に「先週の Java 関連で注意すべき脆弱性は？」「この CVE の CVSS が上がった根拠は？」と質問できます。

| 用途 | プロジェクトスキル |
|---|---|
| 期間・技術テーマ別の注目項目、CVE ごとの評価履歴と根拠 | [intel-search](.agents/skills/intel-search/SKILL.md) |
| フィードの重複、取得量、遅延、カバレッジの集計 | [core-db-analysis](.agents/skills/core-db-analysis/SKILL.md) |
| 話題性フィードの再取得と採否の調査 | [hot-intel](.agents/skills/hot-intel/SKILL.md) |
| 取得ジョブ、SQLite マイグレーション、既存の資産別スコアの保守 | [feeds](.agents/skills/feeds/SKILL.md)・[schema](.agents/skills/schema/SKILL.md)・[scoring](.agents/skills/scoring/SKILL.md) |

For one practical scheduling example, see the `Hot web intel` section in [docs/FEEDS.md](docs/FEEDS.md). It shows a model case with daily core refresh, 6-hour hot collection, and a short hot watchlist. Treat it as an example, not a hard requirement.
For `hot` discovery keywords and short-list review examples, see [docs/FEEDS.md](docs/FEEDS.md).
`hot` should be run from a local shell with working outbound HTTP/DNS; restricted-network environments may return zero discoveries even when the code is healthy.
For a bounded single-CVE worker, use `uv run python scripts/deep_dive.py CVE-2026-31431 --json`.
For the bounded single-CVE worker contract, see [docs/DEEP_DIVE.md](docs/DEEP_DIVE.md).

If you only want the live KEV feed, run `uv run python -m sync.fetch_kev` directly. If you only want the live EPSS snapshot, run `uv run python -m sync.fetch_epss` directly. For a bounded validation corpus, prefer the wrapper script. It keeps the mirror refresh, KEV, EPSS, and recent advisory ingest window in one pass.

`./scripts/ingest_recent_core_db.sh` now takes a lock so two refreshes do not run at the same time. It expects the local mirrors for CVE Program, GHSA, and Vulnrichment to be refreshed by `./scripts/update_data_mirrors.sh` first. If you also want a fresh `db/exploit.db`, run `./scripts/refresh_all_sources.sh` first. The ingest script stores the last successful mirror refs in `db/refresh_recent_core_db.refs`, so subsequent runs diff against the last ingested commit instead of `HEAD@{1}`. If network refresh is unavailable, set `SKIP_MIRROR_REFRESH=1` and the script will continue with the current local mirrors.

`refresh_all_sources.sh` looks for `go-exploitdb` in `EXPLOITDB_BINARY`, `GO_EXPLOITDB_BINARY`, `PATH`, `$(go env GOBIN)`, and `$(go env GOPATH)/bin` in that order.

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

1. Install a matching binary, for example `go install github.com/vulsio/go-exploitdb@latest`.
2. Fetch SQLite data with the repo wrapper, which defaults to all source families, for example `python3 -m sync.update_exploitdb --binary ~/go/bin/go-exploitdb`.
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
├── AGENTS.md
├── app/
│   └── AGENTS.md
├── sync/
│   └── AGENTS.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SCHEMA.md
│   ├── SCORING.md
│   └── FEEDS.md
└── .agents/skills/
    ├── core-db-analysis/SKILL.md
    ├── feeds/SKILL.md
    ├── hot-intel/SKILL.md
    ├── intel-search/SKILL.md
    ├── schema/SKILL.md
    └── scoring/SKILL.md
```


GitHub CLI の認証を平文で残したくない場合は、`scripts/gh_secret.py store` で Secret Service に token を入れてから `scripts/check_dependabot.sh` を使ってください。
移行中だけ `ALLOW_PLAINTEXT_GH=1` を付けると既存の `gh auth` 保存値を読むフォールバックにできます。
Dependency cooldown は lock の更新時にかけています。たとえばローカルで dependency を更新するときは `UV_EXCLUDE_NEWER="$(date -u -d '7 days ago' +%F)"` を付けてから `uv lock` を実行してください。CI の frozen install では lockfile をそのまま使います。

Dependabot の運用基準は次のとおりです。

1. Dependabot PR は、まず自動生成された更新候補として扱う。
2. 取り込み可否は GitHub Actions の `pytest` が通るかで決める。
3. `uv` の version updates は Dependabot 側の `cooldown` で 7 日寝かせる。
4. `uv sync --frozen --dev` が失敗した PR は、依存が cooldown 外になるまで待つか、更新対象を見直して再実行する。
5. `uv.lock` はコミット対象で、CI では `uv lock` を回さない。
6. 失敗理由の確認には `scripts/check_dependabot.sh` を使う。
7. 古い open PR は不要なら close して整理する。

Dependabot PR が来たときの運用フローは次のとおりです。

1. PR の種類を確認する。
   - security update は脆弱性修正が目的
   - version update は通常追従で、cooldown の対象
2. `scripts/check_dependabot.sh` で滞留 PR と alerts を確認する。
3. PR ごとに GitHub Actions の `pytest` を確認する。
4. version update が `uv sync --frozen --dev` で落ちた場合は、cooldown 外になるまで待つか、PR を close して次回更新を待つ。
5. security update は cooldown を待たず、該当ライブラリだけを安全な版へ最小差分で更新する。
6. security update の PR は `pytest` が通れば優先して取り込む。
7. 失敗が一時的なものなら GitHub Actions を rerun して再確認する。
8. `uv.lock` に問題がなければ squash merge で main に入れる。
9. 不要になった Dependabot PR は close する。

security update を手元で再現するときは、更新対象のパッケージだけを lock に反映してから必ずテストを通します。

```bash
UV_EXCLUDE_NEWER="$(date -u -d '7 days ago' +%F)" uv lock -P <pkg> --exclude-newer "$UV_EXCLUDE_NEWER"
uv sync --frozen --dev
uv run python -m pytest -q
```

```bash
UV_EXCLUDE_NEWER="$(date -u -d '7 days ago' +%F)"
uv lock --exclude-newer "$UV_EXCLUDE_NEWER"
uv sync --frozen --dev
uv run python -m pytest -q
```
