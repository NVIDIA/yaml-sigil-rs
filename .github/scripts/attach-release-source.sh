#!/usr/bin/env bash

# Attach an already-qualified detached source to local main refs so pinned
# release-plz can resolve its merged pull request. This never updates a remote.
set -euo pipefail

# Accept exactly one lowercase commit identity selected by protected policy.
if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  echo "usage: attach-release-source.sh SOURCE_SHA" >&2
  exit 2
fi
source_sha="$1"

head_sha="$(git rev-parse --verify HEAD)"
status="$(git status --porcelain=v1 --untracked-files=all)"
# Ref attachment is valid only for the exact clean qualified source tree.
if [[ "${head_sha}" != "${source_sha}" || -n "${status}" ]]; then
  echo "release source checkout differs from the qualified commit" >&2
  exit 1
fi

# These updates are strictly local Git context; no fetch, push, or credential
# operation is permitted at the Cargo publication boundary.
git update-ref refs/heads/main "${source_sha}"
git update-ref refs/remotes/origin/main "${source_sha}"
git symbolic-ref HEAD refs/heads/main

# Read back all three bindings before release-plz receives publication authority.
if [[ "$(git rev-parse HEAD)" != "${source_sha}" \
  || "$(git rev-parse refs/heads/main)" != "${source_sha}" \
  || "$(git rev-parse refs/remotes/origin/main)" != "${source_sha}" \
  || "$(git symbolic-ref --quiet --short HEAD)" != "main" \
  || -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "local release source refs did not retain the exact qualified source" >&2
  exit 1
fi
