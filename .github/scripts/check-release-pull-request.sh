#!/usr/bin/env bash

# Validate the narrow file and branch contract of a locally prepared release
# pull request. The caller supplies live PR metadata and an exact Git range.
set -euo pipefail

: "${BASE_SHA:?BASE_SHA must identify current pull request base}"
: "${HEAD_SHA:?HEAD_SHA must identify the exact pull request head}"
: "${YAML_SIGIL_RELEASE_PR_BRANCH:=}"

workspace_version() {
  git show "$1:Cargo.toml" | awk '
    /^\[workspace\.package\]$/ { in_package=1; next }
    /^\[/ { in_package=0 }
    in_package && /^version = "/ {
      value=$0
      sub(/^version = "/, "", value)
      sub(/".*$/, "", value)
      print value
      exit
    }
  '
}

base_version="$(workspace_version "${BASE_SHA}")"
head_version="$(workspace_version "${HEAD_SHA}")"
changed=()
while IFS= read -r -d '' path; do
  changed+=("${path}")
done < <(git diff --no-renames --name-only --diff-filter=ACDMRTUXB -z \
  "${BASE_SHA}..${HEAD_SHA}")
while IFS= read -r -d '' path; do
  changed+=("${path}")
done < <(git ls-files --others --exclude-standard -z --)

release_change=false
# A version change is the durable content signal for a release proposal.
if [[ "${base_version}" != "${head_version}" ]]; then
  release_change=true
fi

# Ordinary pull requests remain unrestricted by the release-only contract.
if [[ "${release_change}" != "true" ]]; then
  # A canonical release branch is never an ordinary pull request: its branch
  # version and source version must describe one exact release transaction.
  if [[ -n "${YAML_SIGIL_RELEASE_PR_BRANCH}" ]]; then
    echo "::error::A canonical release branch must advance to its exact version."
    exit 1
  fi
  exit 0
fi

# The protected anonymous binder emits only a same-repository canonical branch.
if [[ "${YAML_SIGIL_RELEASE_PR_BRANCH}" != "release-plz-manual-${head_version}" ]]; then
  echo "::error::A version change must use the canonical release branch."
  exit 1
fi

commit_count="$(git rev-list --count "${BASE_SHA}..${HEAD_SHA}")"
# A release proposal is one locally signed and DCO-compliant review commit.
if [[ "${commit_count}" != "1" ]]; then
  echo "::error::A release proposal must contain exactly one commit."
  exit 1
fi

allowed() {
  # Keep the release-only diff to Cargo and release-plz maintained source files.
  case "$1" in
    Cargo.toml | \
      crates/yaml-sigil-core/Cargo.toml | \
      crates/yaml-sigil-core/CHANGELOG.md | \
      crates/yaml-sigil-transcription/Cargo.toml | \
      crates/yaml-sigil-transcription/CHANGELOG.md | \
      crates/yaml-sigil-signing/Cargo.toml | \
      crates/yaml-sigil-signing/CHANGELOG.md | \
      crates/yaml-sigil-verification/Cargo.toml | \
      crates/yaml-sigil-verification/CHANGELOG.md)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

for path in "${changed[@]}"; do
  # A release-only commit may contain only release-plz and Cargo-managed files.
  if ! allowed "${path}"; then
    echo "::error::Release proposal changed unexpected path ${path}."
    exit 1
  fi

  entry="$(git ls-tree "${HEAD_SHA}" -- "${path}")"
  IFS=$' \t' read -r mode object_type object_sha listed_path extra <<< "${entry}"
  # Release-plz may modify existing source files, but it may not delete them,
  # replace them with links, or change their executable/source-file mode.
  if [[ "${mode}" != "100644" \
    || "${object_type}" != "blob" \
    || ! "${object_sha}" =~ ^[0-9a-f]{40}$ \
    || "${listed_path}" != "${path}" \
    || -n "${extra:-}" ]]; then
    echo "::error::Release proposal must retain exact regular 100644 path ${path}."
    exit 1
  fi
done

# Exact package versions, dependency policy, and traits resolution are checked
# later inside the workflow's terminal candidate-execution boundary.
