#!/usr/bin/env bash

# Exercise canonical-branch, deletion, mode, and untracked-path rejection in
# the protected release-PR inventory without invoking release-plz or a network.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

install -d "${test_root}/bin"
printf '%s\n' '#!/bin/sh' 'exit 99' > "${test_root}/bin/cargo"
chmod 0700 "${test_root}/bin/cargo"

initialize_release_range() {
  local repository="$1"
  install -d "${repository}"
  git -C "${repository}" init --quiet
  printf '%s\n' \
    '[workspace]' \
    '[workspace.package]' \
    'version = "0.5.0"' > "${repository}/Cargo.toml"
  install -d "${repository}/crates/yaml-sigil-core"
  printf '%s\n' '# Changelog' > \
    "${repository}/crates/yaml-sigil-core/CHANGELOG.md"
  printf '%s\n' 'fixture' > "${repository}/unexpected.txt"
  git -C "${repository}" add Cargo.toml \
    crates/yaml-sigil-core/CHANGELOG.md unexpected.txt
  git -C "${repository}" \
    -c user.name=fixture \
    -c user.email=fixture@example.invalid \
    -c commit.gpgsign=false \
    commit --quiet --message=base
  git -C "${repository}" rev-parse HEAD

  printf '%s\n' \
    '[workspace]' \
    '[workspace.package]' \
    'version = "0.6.0"' > "${repository}/Cargo.toml"
}

expect_inventory_rejection() {
  local repository="$1"
  local base_sha="$2"
  local head_sha="$3"
  local expected="$4"
  local branch="${5:-release-plz-manual-0.6.0}"
  local output
  output="${test_root}/result-$(basename -- "${repository}").log"
  # Each fixture must fail before the stubbed Cargo validator is relevant.
  if (
    cd -- "${repository}"
    PATH="${test_root}/bin:${PATH}" \
      BASE_SHA="${base_sha}" \
      HEAD_SHA="${head_sha}" \
      YAML_SIGIL_RELEASE_PR_BRANCH="${branch}" \
      "${script_dir}/check-release-pull-request.sh"
  ) > "${output}" 2>&1; then
    echo "release inventory unexpectedly accepted an unsafe path" >&2
    exit 1
  fi
  grep -F "${expected}" "${output}" >/dev/null
}

deletion_repo="${test_root}/deletion"
deletion_base="$(initialize_release_range "${deletion_repo}")"
git -C "${deletion_repo}" rm --quiet unexpected.txt
git -C "${deletion_repo}" add Cargo.toml
git -C "${deletion_repo}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=release
deletion_head="$(git -C "${deletion_repo}" rev-parse HEAD)"
expect_inventory_rejection "${deletion_repo}" "${deletion_base}" \
  "${deletion_head}" 'Release proposal changed unexpected path'

rename_repo="${test_root}/rename-into-allowed"
rename_base="$(initialize_release_range "${rename_repo}")"
install -d "${rename_repo}/crates/yaml-sigil-transcription"
git -C "${rename_repo}" mv unexpected.txt \
  crates/yaml-sigil-transcription/CHANGELOG.md
git -C "${rename_repo}" add Cargo.toml
git -C "${rename_repo}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=release
rename_head="$(git -C "${rename_repo}" rev-parse HEAD)"
expect_inventory_rejection "${rename_repo}" "${rename_base}" \
  "${rename_head}" 'Release proposal changed unexpected path'

allowed_deletion_repo="${test_root}/allowed-deletion"
allowed_deletion_base="$(initialize_release_range "${allowed_deletion_repo}")"
git -C "${allowed_deletion_repo}" rm --quiet \
  crates/yaml-sigil-core/CHANGELOG.md
git -C "${allowed_deletion_repo}" add Cargo.toml
git -C "${allowed_deletion_repo}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=release
allowed_deletion_head="$(git -C "${allowed_deletion_repo}" rev-parse HEAD)"
expect_inventory_rejection "${allowed_deletion_repo}" \
  "${allowed_deletion_base}" "${allowed_deletion_head}" \
  'Release proposal must retain exact regular 100644 path'

executable_repo="${test_root}/executable"
executable_base="$(initialize_release_range "${executable_repo}")"
chmod 0755 "${executable_repo}/crates/yaml-sigil-core/CHANGELOG.md"
git -C "${executable_repo}" add Cargo.toml \
  crates/yaml-sigil-core/CHANGELOG.md
git -C "${executable_repo}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=release
executable_head="$(git -C "${executable_repo}" rev-parse HEAD)"
expect_inventory_rejection "${executable_repo}" "${executable_base}" \
  "${executable_head}" \
  'Release proposal must retain exact regular 100644 path'

untracked_repo="${test_root}/untracked"
untracked_base="$(initialize_release_range "${untracked_repo}")"
git -C "${untracked_repo}" add Cargo.toml
git -C "${untracked_repo}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=release
untracked_head="$(git -C "${untracked_repo}" rev-parse HEAD)"
printf '%s\n' 'unreviewed' > "${untracked_repo}/unexpected-untracked.txt"
expect_inventory_rejection "${untracked_repo}" "${untracked_base}" \
  "${untracked_head}" 'Release proposal changed unexpected path'

canonical_no_version_repo="${test_root}/canonical-no-version"
canonical_no_version_base="$(initialize_release_range "${canonical_no_version_repo}")"
printf '%s\n' 'release notes only' >> \
  "${canonical_no_version_repo}/crates/yaml-sigil-core/CHANGELOG.md"
git -C "${canonical_no_version_repo}" add \
  crates/yaml-sigil-core/CHANGELOG.md
git -C "${canonical_no_version_repo}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=release
canonical_no_version_head="$(git -C "${canonical_no_version_repo}" rev-parse HEAD)"
expect_inventory_rejection "${canonical_no_version_repo}" \
  "${canonical_no_version_base}" "${canonical_no_version_head}" \
  'A canonical release branch must advance to its exact version.' \
  release-plz-manual-0.5.0

static_acceptance_repo="${test_root}/static-acceptance"
static_acceptance_base="$(initialize_release_range "${static_acceptance_repo}")"
git -C "${static_acceptance_repo}" add Cargo.toml
git -C "${static_acceptance_repo}" \
  -c user.name=fixture \
  -c user.email=fixture@example.invalid \
  -c commit.gpgsign=false \
  commit --quiet --message=release
static_acceptance_head="$(git -C "${static_acceptance_repo}" rev-parse HEAD)"
# Static policy must finish without invoking candidate Cargo; terminal source
# validation is intentionally a later workflow boundary.
(
  cd -- "${static_acceptance_repo}"
  PATH="${test_root}/bin:${PATH}" \
    BASE_SHA="${static_acceptance_base}" \
    HEAD_SHA="${static_acceptance_head}" \
    YAML_SIGIL_RELEASE_PR_BRANCH=release-plz-manual-0.6.0 \
    "${script_dir}/check-release-pull-request.sh"
)

promotion_repo="${test_root}/promotion"
promotion_base="$(initialize_release_range "${promotion_repo}")"
printf '%s\n' '[workspace]' '[workspace.package]' \
  'version = "0.6.0-rc.0"' > "${promotion_repo}/Cargo.toml"
git -C "${promotion_repo}" add Cargo.toml
git -C "${promotion_repo}" -c user.name=fixture \
  -c user.email=fixture@example.invalid -c commit.gpgsign=false \
  commit --quiet --message=activation
printf '%s\n' 'product change' >> "${promotion_repo}/unexpected.txt"
git -C "${promotion_repo}" add unexpected.txt
git -C "${promotion_repo}" -c user.name=fixture \
  -c user.email=fixture@example.invalid -c commit.gpgsign=false \
  commit --quiet --message=implementation
promotion_head="$(git -C "${promotion_repo}" rev-parse HEAD)"

check_promotion() {
  (
    cd -- "${promotion_repo}"
    PATH="${test_root}/bin:${PATH}" \
      BASE_SHA="${promotion_base}" HEAD_SHA="${promotion_head}" \
      BASE_REF=refs/heads/main YAML_SIGIL_RELEASE_PR_BRANCH='' \
      YAML_SIGIL_PROMOTION_BRANCH=dev/0.6.0 \
      env "$@" "${script_dir}/check-release-pull-request.sh"
  )
}

reject_promotion() {
  # An invalid binding must reject before candidate Cargo can execute.
  if check_promotion "$@" > "${test_root}/promotion.log" 2>&1; then
    echo "promotion unexpectedly accepted invalid metadata" >&2
    exit 1
  fi
  grep -F '::error::' "${test_root}/promotion.log" >/dev/null
}

# A bound cumulative promotion admits multiple commits and product paths;
# the ordinary release contract still rejects the identical unbound range.
check_promotion
reject_promotion YAML_SIGIL_PROMOTION_BRANCH=
reject_promotion YAML_SIGIL_PROMOTION_BRANCH=dev/0.7.0
reject_promotion YAML_SIGIL_PROMOTION_BRANCH=dev/00.6.0
reject_promotion YAML_SIGIL_PROMOTION_BRANCH=dev/0x6x0
reject_promotion YAML_SIGIL_PROMOTION_BRANCH=dev/0.6.0-rc.0
reject_promotion BASE_REF=
reject_promotion BASE_REF=refs/heads/dev/0.6.0
reject_promotion BASE_REF=refs/heads/support/0.6
reject_promotion YAML_SIGIL_RELEASE_PR_BRANCH=release-plz-manual-0.6.0-rc.0
reject_promotion BASE_SHA="${promotion_head}"

for version in 0.6.0 0.6.0-rc.1 0.6.0-rc.0+build 0.7.0-rc.0; do
  printf '%s\n' '[workspace]' '[workspace.package]' \
    "version = \"${version}\"" > "${promotion_repo}/Cargo.toml"
  git -C "${promotion_repo}" add Cargo.toml
  git -C "${promotion_repo}" -c user.name=fixture \
    -c user.email=fixture@example.invalid -c commit.gpgsign=false \
    commit --quiet --message=invalid-version
  reject_promotion HEAD_SHA="$(git -C "${promotion_repo}" rev-parse HEAD)"
done

git -C "${promotion_repo}" checkout "${promotion_head}" -- Cargo.toml
chmod 0755 "${promotion_repo}/Cargo.toml"
git -C "${promotion_repo}" add Cargo.toml
git -C "${promotion_repo}" -c user.name=fixture \
  -c user.email=fixture@example.invalid -c commit.gpgsign=false \
  commit --quiet --message=invalid-mode
reject_promotion HEAD_SHA="$(git -C "${promotion_repo}" rev-parse HEAD)"

echo "release pull-request and coordination promotion policy tests passed"
