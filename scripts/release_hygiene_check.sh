#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

failed=0

section() {
  printf '\n[%s]\n' "$1"
}

fail() {
  printf 'release hygiene failure: %s\n' "$1" >&2
  failed=1
}

check_no_git_grep_matches() {
  local pattern="$1"
  local description="$2"
  shift 2

  section "${description}"
  if git grep -n -E "${pattern}" -- "$@"; then
    fail "${description}"
  else
    printf 'ok\n'
  fi
}

section "tracked credential-shaped file names"
if git ls-files | grep -En '(^|/)(\.env|.*\.pem$|.*\.key$|.*credential.*|.*credentials.*|.*token.*)' ; then
  fail "tracked credential-shaped file names are not release-safe"
else
  printf 'ok\n'
fi

check_no_git_grep_matches \
  '(\.\./\.\./toolkits|toolkits/mcp-toolkit-rs|path[[:space:]]*=[[:space:]]*"(../|/home/|/Users/))' \
  "local workspace or operator path dependencies" \
  Cargo.toml Cargo.lock kc-admin-gateway/Cargo.toml kc-admin-mcp/Cargo.toml docs .github

check_no_git_grep_matches \
  '(pull_request_target|secrets\.|permissions:[[:space:]]*write|contents:[[:space:]]*write|id-token:[[:space:]]*write)' \
  "privileged workflow patterns" \
  .github/workflows

section "cargo metadata"
cargo metadata --locked --no-deps --format-version 1 >/dev/null
printf 'ok\n'

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi
