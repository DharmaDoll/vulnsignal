#!/usr/bin/env bash
set -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

is_valid_git_repo() {
  git -C "$1" rev-parse --verify HEAD >/dev/null 2>&1
}

clone_fresh() {
  repo_url="$1"
  target_dir="$2"

  parent_dir="$(dirname "$target_dir")"
  temp_dir="$(mktemp -d "$parent_dir/.mirror.XXXXXX")"
  cleanup() {
    rm -rf "$temp_dir"
  }

  trap cleanup RETURN
  git clone --depth 1 "$repo_url" "$temp_dir"
  rm -rf "$target_dir"
  mv "$temp_dir" "$target_dir"
  trap - RETURN
}

clone_or_pull() {
  repo_url="$1"
  target_dir="$2"

  if [ -d "$target_dir/.git" ]; then
    if is_valid_git_repo "$target_dir"; then
      git -C "$target_dir" pull --ff-only
    else
      printf '%s\n' "warn: $target_dir is a broken mirror; recreating it" >&2
      clone_fresh "$repo_url" "$target_dir"
    fi
  elif [ -e "$target_dir" ]; then
    printf '%s\n' "error: $target_dir exists but is not a git repository" >&2
    exit 1
  else
    clone_fresh "$repo_url" "$target_dir"
  fi
}

mkdir -p "$ROOT_DIR/data"
clone_or_pull "https://github.com/github/advisory-database" "$ROOT_DIR/data/github-advisory-database-mirror"
clone_or_pull "https://github.com/CVEProject/cvelistV5" "$ROOT_DIR/data/cvelistv5-mirror"
clone_or_pull "https://github.com/aquasecurity/vuln-list" "$ROOT_DIR/data/aquasecurity-vuln-list-mirror"
clone_or_pull "https://github.com/cisagov/vulnrichment" "$ROOT_DIR/data/vulnrichment-mirror"
