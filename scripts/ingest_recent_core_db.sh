#!/usr/bin/env bash
set -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MIN_YEAR="${MIN_YEAR:-$(( $(date +%Y) - 2 ))}"
STATE_FILE="$ROOT_DIR/db/refresh_recent_core_db.refs"

load_state() {
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    . "$STATE_FILE"
  fi
}

write_state() {
  printf 'CVE_PROGRAM_REF=%s\n' "$1" > "$STATE_FILE.tmp"
  printf 'GHSA_REF=%s\n' "$2" >> "$STATE_FILE.tmp"
  printf 'VULNRICHMENT_REF=%s\n' "$3" >> "$STATE_FILE.tmp"
  mv "$STATE_FILE.tmp" "$STATE_FILE"
}

git_head() {
  git -C "$1" rev-parse HEAD
}

exec 9>"$ROOT_DIR/db/refresh_recent_core_db.lock"
if ! flock -n 9; then
  printf '%s\n' "another refresh_recent_core_db run is already active" >&2
  exit 1
fi

python3 db/migrate.py
load_state

if [ "${SKIP_MIRROR_REFRESH:-0}" != "1" ]; then
  if ! ./scripts/update_data_mirrors.sh; then
    printf '%s\n' "warn: mirror refresh failed; continuing with existing mirrors" >&2
  fi
fi

ingest_mirror() {
  local module="$1" ref="$2"
  if [ -n "$ref" ]; then
    python3 -m "$module" --changed-since-ref "$ref" --min-year "${MIN_CHANGED_YEAR:-2015}"
  else
    python3 -m "$module" --min-year "$MIN_YEAR"
  fi
}

ingest_mirror sync.fetch_cve_program "${CVE_PROGRAM_REF:-}"
python3 -m sync.fetch_kev
python3 -m sync.fetch_epss
ingest_mirror sync.fetch_ghsa "${GHSA_REF:-}"
ingest_mirror sync.fetch_vulnrichment "${VULNRICHMENT_REF:-}"

if [ -f "db/exploit.db" ]; then
  python3 -m sync.fetch_exploitdb --db db/exploit.db --min-year "$MIN_YEAR"
else
  printf '%s\n' "skip: db/exploit.db not found"
fi

if [ "${SKIP_FEED_QUALITY:-0}" != "1" ]; then
  python3 -m sync.feed_quality
fi

write_state \
  "$(git_head data/cvelistv5-mirror)" \
  "$(git_head data/github-advisory-database-mirror)" \
  "$(git_head data/vulnrichment-mirror)"
