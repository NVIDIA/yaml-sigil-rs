// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API.
//!
//! These re-exports name the same definitions as the crate's unqualified
//! `v1alpha1` default. Values and trait implementations work through either
//! path without conversion. The specification identifier is independent of
//! the crate's package version.

pub use crate::{
    AbstractArtifact, ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm,
    ArtifactResourceLimits, ArtifactResourceResult, AsyncTranscriber, ComposeOutcome,
    ComposeRequest, ComposeSuccess, DEFAULT_MAX_ARTIFACT_BYTES, DecomposeOutcome, DecomposeRequest,
    DecomposeResponse, DecomposeStructuralResult, DefaultAsyncTranscriber, DefaultTranscriber,
    EncodeError, EncodeErrorKind, OuterConformance, Transcriber, TranscriberCapabilities,
    TranscriberError, TranscriberInvocationError, TranscriptionForm, compose,
    compose_with_resource_limits, decompose, decompose_with_resource_limits,
    transcriber_capabilities,
};
