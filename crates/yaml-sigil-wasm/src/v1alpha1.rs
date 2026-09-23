// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API.
//!
//! These re-exports name the same definitions as the crate's unqualified
//! `v1alpha1` default. Values and trait implementations work through either
//! path without conversion. The specification identifier is independent of
//! the crate's package version.

pub use crate::{
    ArtifactResourceLimits, ComposeResult, DecomposeResult, SignResult, VerifyResult, compose,
    compose_with_limits, decompose, decompose_with_limits, sign, sign_with_limits, verify,
    verify_with_limits,
};
