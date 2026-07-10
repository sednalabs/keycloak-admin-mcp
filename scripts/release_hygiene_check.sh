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

check_main_only_attestation_permissions() {
  local workflow=".github/workflows/kc-admin-mcp-release-artifacts.yml"
  local privileged_matches
  local match
  local unexpected=""
  local oidc_count=0
  local attestations_count=0
  local attestation_failed=0
  local attestation_job
  local required_line
  local actual_guard
  local expected_guard
  local actual_permissions
  local expected_permissions

  section "main-only attestation permissions"

  privileged_matches="$(
    git grep -n -E '(id-token|attestations):[[:space:]]*write' -- .github/workflows || true
  )"

  while IFS= read -r match; do
    [[ -z "${match}" ]] && continue

    case "${match}" in
      "${workflow}:"*":      id-token: write")
        ((oidc_count += 1))
        ;;
      "${workflow}:"*":      attestations: write")
        ((attestations_count += 1))
        ;;
      *)
        unexpected+="${match}"$'\n'
        ;;
    esac
  done <<< "${privileged_matches}"

  if [[ -n "${unexpected}" || "${oidc_count}" -ne 1 || "${attestations_count}" -ne 1 ]]; then
    [[ -n "${unexpected}" ]] && printf '%s' "${unexpected}"
    fail "attestation write permissions must occur exactly once in the approved workflow job"
    return
  fi

  attestation_job="$(
    awk '
      $0 == "  attest-artifacts:" {
        inside = 1
        print
        next
      }
      inside && /^  [[:alnum:]_-]+:$/ { exit }
      inside { print }
    ' "${workflow}"
  )"

  if [[ -z "${attestation_job}" ]]; then
    fail "attestation job is missing"
    return
  fi

  actual_guard="$(
    awk '
      $0 == "    if: >-" {
        inside = 1
        next
      }
      inside && /^    [^ ]/ { exit }
      inside { print }
    ' <<< "${attestation_job}"
  )"
  expected_guard=$'      github.ref == '\''refs/heads/main'\'' &&\n      (github.event_name == '\''push'\'' || github.event_name == '\''workflow_dispatch'\'')'

  if [[ "${actual_guard}" != "${expected_guard}" ]]; then
    fail "attestation job must use the exact main push or main workflow_dispatch guard"
    attestation_failed=1
  fi

  actual_permissions="$(
    awk '
      $0 == "    permissions:" {
        inside = 1
        next
      }
      inside && /^    [^ ]/ { exit }
      inside { print }
    ' <<< "${attestation_job}"
  )"
  expected_permissions=$'      actions: read\n      contents: read\n      id-token: write\n      attestations: write'

  if [[ "${actual_permissions}" != "${expected_permissions}" ]]; then
    fail "attestation job permissions must match the approved least-privilege set"
    attestation_failed=1
  fi

  local required_lines=(
    "    needs: build-artifacts"
  )

  for required_line in "${required_lines[@]}"; do
    if ! grep -Fqx -- "${required_line}" <<< "${attestation_job}"; then
      fail "attestation job is missing required guard or permission: ${required_line}"
      attestation_failed=1
    fi
  done

  if [[ "${attestation_failed}" -eq 0 ]]; then
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
  '(pull_request_target|secrets\.|permissions:[[:space:]]*write|contents:[[:space:]]*write)' \
  "privileged workflow patterns" \
  .github/workflows

check_main_only_attestation_permissions

section "cargo metadata"
cargo metadata --locked --no-deps --format-version 1 >/dev/null
printf 'ok\n'

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi
