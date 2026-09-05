#!/usr/bin/env bash

# Exercise the pre-token current-main binding entirely against local Git data.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixture="$(mktemp -d)"
cleanup() {
  rm -rf -- "${fixture}"
}
trap cleanup EXIT

upstream="${fixture}/upstream"
remote="${fixture}/remote.git"
policy="${fixture}/policy"
source="${fixture}/source"

git init --quiet --initial-branch=main "${upstream}"
git -C "${upstream}" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit --quiet --allow-empty -m initial
initial="$(git -C "${upstream}" rev-parse HEAD)"
git clone --quiet --bare "${upstream}" "${remote}"
git clone --quiet "${remote}" "${policy}"
git clone --quiet "${remote}" "${source}"

# Production mode must reject a caller-selected transport before authentication.
if env GITHUB_ACTIONS=true GITHUB_REPOSITORY=NVIDIA/yaml-sigil-rs \
  "${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${initial}" "${remote}" \
  >/dev/null 2>&1; then
  echo "production release binding accepted a caller-selected transport" >&2
  exit 1
fi

# Local fixture calls deliberately remove hosted identity and use the test remote.
env -u GITHUB_ACTIONS -u GITHUB_REPOSITORY \
  "${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${initial}" "${remote}"

git -C "${upstream}" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit --quiet --allow-empty -m later
git -C "${upstream}" push --quiet "${remote}" main

# A policy checkout that is no longer current main must fail before authentication.
if env -u GITHUB_ACTIONS -u GITHUB_REPOSITORY \
  "${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${initial}" "${remote}" \
  >/dev/null 2>&1; then
  echo "stale protected policy unexpectedly passed live-main binding" >&2
  exit 1
fi

git -C "${policy}" pull --quiet --ff-only
env -u GITHUB_ACTIONS -u GITHUB_REPOSITORY \
  "${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${initial}" "${remote}"

git -C "${source}" switch --quiet -c unrelated
git -C "${source}" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit --quiet --allow-empty -m unrelated
unrelated="$(git -C "${source}" rev-parse HEAD)"

# A clean source outside current main lineage must never become recovery data.
if env -u GITHUB_ACTIONS -u GITHUB_REPOSITORY \
  "${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${unrelated}" "${remote}" \
  >/dev/null 2>&1; then
  echo "unrelated release source unexpectedly passed main-lineage binding" >&2
  exit 1
fi

printf 'release policy live-main binding tests passed\n'
