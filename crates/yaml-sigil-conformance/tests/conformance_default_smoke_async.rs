// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Async siblings of `conformance_default_smoke.rs`.

use yaml_sigil_conformance::{
    alg_ecdsa::run_ecdsa_suite_async,
    alg_ed25519::run_ed25519_suite_async,
    decomposition::run_yaml_decomposition_suite_async,
    key_id::{run_keyid_compose_suite_async, run_keyid_suite_async},
    proto_outer::run_protobuf_outer_suite_async,
    schema_alignment::run_schema_alignment_suite_async,
    yaml_signature::run_yaml_signature_suite_async,
};
use yaml_sigil_signing::DefaultAsyncSigner;
use yaml_sigil_transcription::DefaultAsyncTranscriber;
use yaml_sigil_verification::DefaultAsyncVerifier;

#[tokio::test]
async fn conformance_yaml_decomposition_async() {
    run_yaml_decomposition_suite_async(&DefaultAsyncTranscriber, &DefaultAsyncVerifier).await;
}

#[tokio::test]
async fn conformance_protobuf_outer_async() {
    run_protobuf_outer_suite_async(&DefaultAsyncTranscriber, &DefaultAsyncVerifier).await;
}

#[tokio::test]
async fn conformance_schema_alignment_async() {
    run_schema_alignment_suite_async(&DefaultAsyncVerifier).await;
}

#[tokio::test]
async fn conformance_keyid_async() {
    run_keyid_suite_async(&DefaultAsyncVerifier).await;
    run_keyid_compose_suite_async(&DefaultAsyncTranscriber).await;
}

#[tokio::test]
async fn conformance_yaml_signature_async() {
    run_yaml_signature_suite_async(&DefaultAsyncVerifier).await;
}

#[tokio::test]
async fn conformance_ed25519_async() {
    run_ed25519_suite_async(&DefaultAsyncVerifier, &DefaultAsyncSigner).await;
}

#[tokio::test]
async fn conformance_ecdsa_async() {
    run_ecdsa_suite_async(&DefaultAsyncVerifier, &DefaultAsyncSigner).await;
}
