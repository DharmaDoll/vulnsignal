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
  printf 'CVE_PROGRAM_REF=%s\n' "$1" > "$STATE_FILE"
  printf 'GHSA_REF=%s\n' "$2" >> "$STATE_FILE"
  printf 'TRIVY_VULN_LIST_REF=%s\n' "$3" >> "$STATE_FILE"
  printf 'VULNRICHMENT_REF=%s\n' "$4" >> "$STATE_FILE"
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

if [ -z "${CVE_PROGRAM_REF:-}" ]; then
  CVE_PROGRAM_REF="$(git -C data/cvelistv5-mirror rev-parse HEAD@{1})"
fi
if [ -z "${GHSA_REF:-}" ]; then
  GHSA_REF="$(git -C data/github-advisory-database-mirror rev-parse HEAD@{1})"
fi
if [ -z "${TRIVY_VULN_LIST_REF:-}" ]; then
  TRIVY_VULN_LIST_REF="$(git -C data/aquasecurity-vuln-list-mirror rev-parse HEAD@{1})"
fi
if [ -z "${VULNRICHMENT_REF:-}" ]; then
  VULNRICHMENT_REF="$(git -C data/vulnrichment-mirror rev-parse HEAD@{1})"
fi

python3 -m sync.fetch_cve_program --min-year "$MIN_YEAR" --changed-since-ref "$CVE_PROGRAM_REF"
python3 -m sync.fetch_kev
python3 -m sync.fetch_epss
python3 -m sync.fetch_ghsa --min-year "$MIN_YEAR" --changed-since-ref "$GHSA_REF"
python3 -m sync.fetch_trivy_vuln_list --min-year "$MIN_YEAR" --changed-since-ref "$TRIVY_VULN_LIST_REF"
python3 -m sync.fetch_vulnrichment --min-year "$MIN_YEAR" --changed-since-ref "$VULNRICHMENT_REF"

if [ -f "db/exploit.db" ]; then
  python3 -m sync.fetch_exploitdb --db db/exploit.db --min-year "$MIN_YEAR"
else
  printf '%s\n' "skip: db/exploit.db not found"
fi

python3 -m sync.feed_quality

write_state \
  "$(git_head data/cvelistv5-mirror)" \
  "$(git_head data/github-advisory-database-mirror)" \
  "$(git_head data/aquasecurity-vuln-list-mirror)" \
  "$(git_head data/vulnrichment-mirror)"
