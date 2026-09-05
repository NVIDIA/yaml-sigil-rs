// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Protected-path adapter for the authenticated Buf executable.

use std::path::PathBuf;

/// Return the immutable Buf path staged by the protected runner.
#[must_use]
pub fn buf_bin_path() -> PathBuf {
    PathBuf::from("/trusted-tools/bin/buf")
}
