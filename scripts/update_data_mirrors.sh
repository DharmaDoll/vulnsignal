#!/usr/bin/env bash
set -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

clone_or_pull() {
  repo_url="$1"
  target_dir="$2"

  if [ -d "$target_dir/.git" ]; then
    git -C "$target_dir" pull --ff-only
  elif [ -e "$target_dir" ]; then
    printf '%s\n' "error: $target_dir exists but is not a git repository" >&2
    exit 1
  else
    git clone --depth 1 "$repo_url" "$target_dir"
  fi
}

mkdir -p "$ROOT_DIR/data"
clone_or_pull "https://github.com/github/advisory-database" "$ROOT_DIR/data/github-advisory-database-mirror"
clone_or_pull "https://github.com/aquasecurity/vuln-list" "$ROOT_DIR/data/aquasecurity-vuln-list-mirror"
clone_or_pull "https://github.com/cisagov/vulnrichment" "$ROOT_DIR/data/vulnrichment-mirror"
