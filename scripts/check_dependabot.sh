#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GH_BIN="${GH_BIN:-}"
if [ -z "$GH_BIN" ]; then
  if command -v gh >/dev/null 2>&1; then
    GH_BIN="$(command -v gh)"
  elif [ -x "$HOME/go/bin/gh" ]; then
    GH_BIN="$HOME/go/bin/gh"
  fi
fi

if [ -z "${GH_BIN:-}" ]; then
  printf '%s\n' "error: gh not found; install gh or set GH_BIN" >&2
  exit 1
fi

GH_TOKEN_VALUE="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
if [ -z "$GH_TOKEN_VALUE" ]; then
  GH_TOKEN_VALUE="$(python3 "$ROOT_DIR/scripts/gh_secret.py" --host github.com --user DharmaDoll get 2>/dev/null || true)"
fi
if [ -z "$GH_TOKEN_VALUE" ] && [ "${ALLOW_PLAINTEXT_GH:-0}" = "1" ]; then
  GH_TOKEN_VALUE="$("$GH_BIN" auth token)"
fi
if [ -z "$GH_TOKEN_VALUE" ]; then
  printf '%s\n' "error: GitHub token not available; store it in Secret Service with scripts/gh_secret.py store or set GH_TOKEN" >&2
  exit 1
fi

REPO="${GITHUB_REPOSITORY:-}"
if [ -z "$REPO" ]; then
  REPO="$(GH_TOKEN="$GH_TOKEN_VALUE" GITHUB_TOKEN="$GH_TOKEN_VALUE" "$GH_BIN" repo view --json nameWithOwner -q .nameWithOwner)"
fi

PR_LIMIT="${DEPENDABOT_PR_LIMIT:-20}"
RUN_LIMIT="${DEPENDABOT_RUN_LIMIT:-5}"

printf 'repo: %s\n' "$REPO"

printf '%s\n' "dependabot_prs:"
PR_OUTPUT="$(GH_TOKEN="$GH_TOKEN_VALUE" GITHUB_TOKEN="$GH_TOKEN_VALUE" "$GH_BIN" pr list --repo "$REPO" --search dependabot --state all --limit "$PR_LIMIT" --json number,title,state,headRefName,updatedAt --jq '.[] | "- #\(.number) \(.state) \(.headRefName) \(.title) (\(.updatedAt))"')"
if [ -n "$PR_OUTPUT" ]; then
  printf '%s\n' "$PR_OUTPUT"
else
  printf '%s\n' "  (none)"
fi

printf '%s\n' "dependabot_alerts:"
ALERT_COUNT="$(GH_TOKEN="$GH_TOKEN_VALUE" GITHUB_TOKEN="$GH_TOKEN_VALUE" "$GH_BIN" api "repos/$REPO/dependabot/alerts" --paginate --jq '.[] | .security_vulnerability.package.name' | sed '/^$/d' | wc -l | tr -d ' ')"
if [ "$ALERT_COUNT" = "0" ]; then
  printf '%s\n' "  count: 0"
else
  printf '  count: %s\n' "$ALERT_COUNT"
fi

printf '%s\n' "dependabot_updates:"
RUN_OUTPUT="$(GH_TOKEN="$GH_TOKEN_VALUE" GITHUB_TOKEN="$GH_TOKEN_VALUE" "$GH_BIN" run list --repo "$REPO" --workflow "Dependabot Updates" --limit "$RUN_LIMIT" --json databaseId,workflowName,status,conclusion,createdAt,headBranch --jq '.[] | "- #\(.databaseId) \(.status)/\(.conclusion) \(.createdAt) \(.headBranch) \(.workflowName)"')"
if [ -n "$RUN_OUTPUT" ]; then
  printf '%s\n' "$RUN_OUTPUT"
else
  printf '%s\n' "  (none)"
fi

printf '%s\n' "dependency_graph:"
GRAPH_OUTPUT="$(GH_TOKEN="$GH_TOKEN_VALUE" GITHUB_TOKEN="$GH_TOKEN_VALUE" "$GH_BIN" run list --repo "$REPO" --workflow "Dependency Graph" --limit 1 --json databaseId,workflowName,status,conclusion,createdAt,headBranch --jq '.[] | "- #\(.databaseId) \(.status)/\(.conclusion) \(.createdAt) \(.headBranch) \(.workflowName)"')"
if [ -n "$GRAPH_OUTPUT" ]; then
  printf '%s\n' "$GRAPH_OUTPUT"
else
  printf '%s\n' "  (none)"
fi
