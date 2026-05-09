#!/usr/bin/env bash
set -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MIN_YEAR="${MIN_YEAR:-$(( $(date +%Y) - 2 ))}"

python3 db/migrate.py
./scripts/update_data_mirrors.sh

python3 -m sync.fetch_ghsa --min-year "$MIN_YEAR"
python3 -m sync.fetch_trivy_vuln_list --min-year "$MIN_YEAR"
python3 -m sync.fetch_vulnrichment --min-year "$MIN_YEAR"

if [ -d "db/trivy_cache.db" ]; then
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
