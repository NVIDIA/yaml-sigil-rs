// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Explicit YamlSigil `v1alpha1` API, identical to the default exports.

#[cfg(feature = "alloc")]
pub use crate::{
    AbstractArtifact, AsyncTranscriber, ComposeError, ComposeOutcome, ComposeRequest,
    ComposeSuccess, DecomposeError, DecomposeOutcome, DecomposeRequest, DecomposeResponse,
    DecomposeStructuralResult, DefaultAsyncTranscriber, DefaultTranscriber, EncodeError,
    EncodeErrorKind, OuterConformance, Transcriber, TranscriberCapabilities, TranscriberError,
    TranscriberInvocationError, TranscriptionForm, compose, decompose, transcriber_capabilities,
};
pub use crate::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
