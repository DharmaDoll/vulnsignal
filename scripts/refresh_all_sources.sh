#!/usr/bin/env bash
set -eu

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ "${SKIP_MIRROR_REFRESH:-0}" != "1" ]; then
  ./scripts/update_data_mirrors.sh
fi

if [ "${SKIP_EXPLOITDB_UPDATE:-0}" = "1" ]; then
  printf '%s\n' "skip: go-exploitdb update disabled by SKIP_EXPLOITDB_UPDATE=1"
  exit 0
fi

if [ -z "${EXPLOITDB_BINARY:-}" ]; then
  if [ -n "${GO_EXPLOITDB_BINARY:-}" ]; then
    EXPLOITDB_BINARY="$GO_EXPLOITDB_BINARY"
  elif command -v go-exploitdb >/dev/null 2>&1; then
    EXPLOITDB_BINARY="$(command -v go-exploitdb)"
  else
    GOBIN_DIR="$(go env GOBIN 2>/dev/null || true)"
    if [ -n "$GOBIN_DIR" ] && [ -x "$GOBIN_DIR/go-exploitdb" ]; then
      EXPLOITDB_BINARY="$GOBIN_DIR/go-exploitdb"
    else
      GOPATH_DIR="$(go env GOPATH 2>/dev/null || true)"
      if [ -n "$GOPATH_DIR" ] && [ -x "$GOPATH_DIR/bin/go-exploitdb" ]; then
        EXPLOITDB_BINARY="$GOPATH_DIR/bin/go-exploitdb"
      else
        EXPLOITDB_BINARY=""
      fi
    fi
  fi
fi
if [ -z "$EXPLOITDB_BINARY" ]; then
  printf '%s\n' "error: go-exploitdb binary not found; set EXPLOITDB_BINARY or install go-exploitdb" >&2
  exit 1
fi

python3 -m sync.update_exploitdb --binary "$EXPLOITDB_BINARY"
