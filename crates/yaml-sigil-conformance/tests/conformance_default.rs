// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Conformance fixture suites against the workspace's `Default*` impls.
//!
//! Each `#[test]` invokes the corresponding `run_*_suite` function from the
//! library. The crate's library exposes those suites as generic functions so
//! downstream consumers in sibling repositories can re-run them against their
//! own trait implementations.
//!
//! Audit trail: `docs/conformance-validation.md`.

use yaml_sigil_conformance::{
    alg_ecdsa::{run_ecdsa_suite, run_ecdsa_suite_async},
    alg_ed25519::{run_ed25519_suite, run_ed25519_suite_async},
    base64::run_base64_suite,
    decomposition::{run_yaml_decomposition_suite, run_yaml_decomposition_suite_async},
    key_id::{run_keyid_suite, run_keyid_suite_async},
    proto_outer::{run_protobuf_outer_suite, run_protobuf_outer_suite_async},
    schema_alignment::{run_schema_alignment_suite, run_schema_alignment_suite_async},
    yaml_signature::{run_yaml_signature_suite, run_yaml_signature_suite_async},
};
use yaml_sigil_signing::{DefaultAsyncSigner, DefaultSigner};
use yaml_sigil_transcription::{DefaultAsyncTranscriber, DefaultTranscriber};
use yaml_sigil_verification::{DefaultAsyncVerifier, DefaultVerifier};

#[test]
fn yaml_decomposition_default() {
    run_yaml_decomposition_suite(&DefaultTranscriber, &DefaultVerifier);
}

#[test]
fn protobuf_outer_default() {
    run_protobuf_outer_suite(&DefaultTranscriber, &DefaultVerifier);
}

#[test]
fn schema_alignment_default() {
    run_schema_alignment_suite(&DefaultVerifier);
}

#[test]
fn keyid_default() {
    run_keyid_suite(&DefaultVerifier);
}

#[test]
fn base64_default() {
    run_base64_suite();
}

#[test]
fn ed25519_default() {
    run_ed25519_suite(&DefaultVerifier, &DefaultSigner);
}

#[test]
fn ecdsa_default() {
    run_ecdsa_suite(&DefaultVerifier, &DefaultSigner);
}

#[test]
fn yaml_signature_default() {
    run_yaml_signature_suite(&DefaultVerifier);
}

// Parallel async entry points — drive the same fixtures through the
// AsyncSigner / AsyncVerifier / AsyncTranscriber traits and their
// DefaultAsync* implementations. Sync and async paths cover identical
// fixtures; any divergence is a bug, not a divergence-catalog entry.

#[tokio::test]
async fn yaml_decomposition_default_async() {
    run_yaml_decomposition_suite_async(&DefaultAsyncTranscriber, &DefaultAsyncVerifier).await;
}

#[tokio::test]
async fn protobuf_outer_default_async() {
    run_protobuf_outer_suite_async(&DefaultAsyncTranscriber, &DefaultAsyncVerifier).await;
}

#[tokio::test]
async fn schema_alignment_default_async() {
    run_schema_alignment_suite_async(&DefaultAsyncVerifier).await;
}

#[tokio::test]
async fn keyid_default_async() {
    run_keyid_suite_async(&DefaultAsyncVerifier).await;
}

#[tokio::test]
async fn ed25519_default_async() {
    run_ed25519_suite_async(&DefaultAsyncVerifier, &DefaultAsyncSigner).await;
}

#[tokio::test]
async fn ecdsa_default_async() {
    run_ecdsa_suite_async(&DefaultAsyncVerifier, &DefaultAsyncSigner).await;
}

#[tokio::test]
async fn yaml_signature_default_async() {
    run_yaml_signature_suite_async(&DefaultAsyncVerifier).await;
}
