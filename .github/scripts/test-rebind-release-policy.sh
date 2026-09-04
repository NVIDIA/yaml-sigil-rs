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

"${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${initial}" "${remote}"

git -C "${upstream}" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit --quiet --allow-empty -m later
git -C "${upstream}" push --quiet "${remote}" main

# A policy checkout that is no longer current main must fail before authentication.
if "${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${initial}" "${remote}" \
  >/dev/null 2>&1; then
  echo "stale protected policy unexpectedly passed live-main binding" >&2
  exit 1
fi

git -C "${policy}" pull --quiet --ff-only
"${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${initial}" "${remote}"

git -C "${source}" switch --quiet -c unrelated
git -C "${source}" -c user.name=fixture -c user.email=fixture@example.invalid \
  commit --quiet --allow-empty -m unrelated
unrelated="$(git -C "${source}" rev-parse HEAD)"

# A clean source outside current main lineage must never become recovery data.
if "${script_dir}/rebind-release-policy.sh" \
  NVIDIA/yaml-sigil-rs "${policy}" "${source}" "${unrelated}" "${remote}" \
  >/dev/null 2>&1; then
  echo "unrelated release source unexpectedly passed main-lineage binding" >&2
  exit 1
fi

printf 'release policy live-main binding tests passed\n'
