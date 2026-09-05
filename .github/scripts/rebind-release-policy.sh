#!/usr/bin/env bash

# Rebind the checked-out release policy to anonymous live main immediately
# before a credentialed release operation. Historical source remains data only.
set -euo pipefail

# Production accepts only the compiled repository identity and canonical URL.
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  # GitHub runs never accept a caller-selected transport or remote.
  if [[ "$#" -ne 4 \
    || "${GITHUB_REPOSITORY:-}" != "NVIDIA/yaml-sigil-rs" ]]; then
    echo "usage: rebind-release-policy.sh REPOSITORY POLICY_ROOT SOURCE_ROOT SOURCE_SHA" >&2
    exit 2
  fi
  remote_url="https://github.com/NVIDIA/yaml-sigil-rs.git"
else
  # Local tests may provide an isolated file remote without weakening Actions.
  if [[ "$#" -ne 5 ]]; then
    echo "usage: rebind-release-policy.sh REPOSITORY POLICY_ROOT SOURCE_ROOT SOURCE_SHA TEST_REMOTE" >&2
    exit 2
  fi
  remote_url="$5"
fi

repository="$1"
policy_root="$2"
source_root="$3"
source_sha="$4"

# Fail closed on every caller-controlled identity before invoking Git.
if [[ "${repository}" != "NVIDIA/yaml-sigil-rs" \
  || ! "${source_sha}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "release policy rebind received an invalid repository or source SHA" >&2
  exit 1
fi

policy_top="$(git -C "${policy_root}" rev-parse --show-toplevel)"
source_top="$(git -C "${source_root}" rev-parse --show-toplevel)"
policy_physical="$(cd "${policy_root}" && pwd -P)"
source_physical="$(cd "${source_root}" && pwd -P)"
policy_top="$(cd "${policy_top}" && pwd -P)"
source_top="$(cd "${source_top}" && pwd -P)"

# Both checkouts must be distinct, exact roots with no candidate-writable drift.
if [[ "${policy_physical}" != "${policy_top}" \
  || "${source_physical}" != "${source_top}" \
  || "${policy_physical}" == "${source_physical}" \
  || -n "$(git -C "${policy_root}" status --porcelain=v1 --untracked-files=all)" \
  || -n "$(git -C "${source_root}" status --porcelain=v1 --untracked-files=all)" \
  || "$(git -C "${source_root}" rev-parse HEAD)" != "${source_sha}" ]]; then
  echo "release policy or source checkout is not exact and clean" >&2
  exit 1
fi

scratch="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/yaml-sigil-main.XXXXXX")"
cleanup() {
  rm -rf -- "${scratch}"
}
trap cleanup EXIT

git -C "${scratch}" init --quiet
git -C "${scratch}" remote add origin "${remote_url}"
env -u GH_TOKEN -u GITHUB_TOKEN -u GIT_TOKEN \
  GIT_ASKPASS=/bin/false \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_SYSTEM=/dev/null \
  GIT_TERMINAL_PROMPT=0 \
  git -c credential.helper= -C "${scratch}" fetch --quiet --no-tags origin \
  "+refs/heads/main:refs/remotes/origin/main"
live_main="$(git -C "${scratch}" rev-parse refs/remotes/origin/main)"

# The checked-out protected policy must still be the one live main selects.
if [[ "$(git -C "${policy_root}" rev-parse HEAD)" != "${live_main}" ]]; then
  echo "protected release policy is no longer exact live main" >&2
  exit 1
fi

# Historical recovery source may be data only when it remains on main lineage.
if ! git -C "${scratch}" merge-base --is-ancestor "${source_sha}" "${live_main}"; then
  echo "release source is not an ancestor of exact live main" >&2
  exit 1
fi

printf 'Bound protected release policy to live main %s before release authority.\n' \
  "${live_main}"
