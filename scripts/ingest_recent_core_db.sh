#!/usr/bin/env bash
set -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MIN_YEAR="${MIN_YEAR:-$(( $(date +%Y) - 2 ))}"

exec 9>"$ROOT_DIR/db/refresh_recent_core_db.lock"
if ! flock -n 9; then
  printf '%s\n' "another refresh_recent_core_db run is already active" >&2
  exit 1
fi

python3 db/migrate.py

if [ "${SKIP_MIRROR_REFRESH:-0}" != "1" ]; then
  if ! ./scripts/update_data_mirrors.sh; then
    printf '%s\n' "warn: mirror refresh failed; continuing with existing mirrors" >&2
  fi
fi

python3 -m sync.fetch_cve_program --min-year "$MIN_YEAR" --changed-since-ref "HEAD@{1}"
python3 -m sync.fetch_kev
python3 -m sync.fetch_epss
python3 -m sync.fetch_ghsa --min-year "$MIN_YEAR" --changed-since-ref "HEAD@{1}"
python3 -m sync.fetch_trivy_vuln_list --min-year "$MIN_YEAR" --changed-since-ref "HEAD@{1}"
python3 -m sync.fetch_vulnrichment --min-year "$MIN_YEAR" --changed-since-ref "HEAD@{1}"

if [ "${SKIP_TRIVY_DB:-0}" = "1" ]; then
  printf '%s\n' "skip: trivy db ingest disabled by SKIP_TRIVY_DB=1"
elif [ -d "db/trivy_cache.db" ]; then
  python3 -m sync.fetch_trivy_db --db-dir db/trivy_cache.db --min-year "$MIN_YEAR"
else
  printf '%s\n' "skip: db/trivy_cache.db not found"
fi

if [ -f "db/exploit.db" ]; then
  python3 -m sync.fetch_exploitdb --db db/exploit.db --min-year "$MIN_YEAR"
else
  printf '%s\n' "skip: db/exploit.db not found"
fi

python3 -m sync.feed_quality
