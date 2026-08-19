#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
# SPDX-License-Identifier: Apache-2.0

# Create a validation-only Cargo home that patches unpublished implementation
# crates to their reviewed workspace paths. Do not use this helper during
# publication: release-plz must then resolve every dependency through crates.io.

set -euo pipefail

# Require a dedicated Cargo home so validation cannot mutate the runner default.
if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 CARGO_HOME" >&2
  exit 2
fi

cargo_home="$1"
workspace_root="$(git rev-parse --show-toplevel)"

mkdir -p "${cargo_home}"
cat >"${cargo_home}/config.toml" <<EOF
[patch.crates-io]
yaml-sigil-core = { path = "${workspace_root}/crates/yaml-sigil-core" }
yaml-sigil-transcription = { path = "${workspace_root}/crates/yaml-sigil-transcription" }
yaml-sigil-signing = { path = "${workspace_root}/crates/yaml-sigil-signing" }
yaml-sigil-verification = { path = "${workspace_root}/crates/yaml-sigil-verification" }
EOF
