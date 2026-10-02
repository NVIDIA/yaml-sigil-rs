// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Compose and decompose YamlSigil `v1alpha1` artifact bytes.
//!
//! Select `v1alpha1` explicitly; default paths name the same definitions.
//! `compose` produces owned output and returns a flat `ComposeError` on
//! invocation, resource, encoding, or content failure. `decompose` borrows
//! payload and carrier bytes from the original artifact. Temporary requests
//! and policy values need not outlive those returned slices.
//!
//! Requests carry `resource_limits`. Input admission precedes parsing and
//! output admission precedes component scans and complete-output allocation.
//! Limits are operational policy, independent of conformance. The 16,384-octet
//! YAML carrier constraint applies separately when metadata is parsed.
//!
//! Defaults enable `std`, `yaml`, and `protobuf`. Either format works with
//! `no_std + alloc`. Disabled formats fail with invocation errors and are
//! absent from capabilities. This crate provides no cryptographic verification.
//! See the [portable API guide](https://github.com/NVIDIA/yaml-sigil-rs/blob/main/docs/no-std.md).

#![cfg_attr(not(feature = "std"), no_std)]
#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

#[cfg(feature = "alloc")]
mod operations;
pub mod v1alpha1;
#[cfg(feature = "alloc")]
pub use operations::{
    AbstractArtifact, AsyncTranscriber, ComposeError, ComposeOutcome, ComposeRequest,
    ComposeSuccess, DecomposeError, DecomposeOutcome, DecomposeRequest, DecomposeResponse,
    DecomposeStructuralResult, DefaultAsyncTranscriber, DefaultTranscriber, EncodeError,
    EncodeErrorKind, OuterConformance, Transcriber, TranscriberCapabilities, TranscriberError,
    TranscriberInvocationError, TranscriptionForm, compose, decompose, transcriber_capabilities,
};
pub use yaml_sigil_traits::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
