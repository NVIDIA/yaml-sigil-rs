// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Smoke-run the workspace conformance suites against the parent's
//! `Default*` implementations at the harness crate's pinned feature mix.
//!
//! Audit trail: `docs/conformance-validation.md`.

use yaml_sigil_conformance::{
    alg_ecdsa::run_ecdsa_suite, alg_ed25519::run_ed25519_suite, base64::run_base64_suite,
    decomposition::run_yaml_decomposition_suite, key_id::run_keyid_suite,
    proto_outer::run_protobuf_outer_suite, schema_alignment::run_schema_alignment_suite,
    yaml_signature::run_yaml_signature_suite,
};
use yaml_sigil_signing::DefaultSigner;
use yaml_sigil_transcription::DefaultTranscriber;
use yaml_sigil_verification::DefaultVerifier;

#[test]
fn conformance_yaml_decomposition() {
    run_yaml_decomposition_suite(&DefaultTranscriber, &DefaultVerifier);
}

#[test]
fn conformance_protobuf_outer() {
    run_protobuf_outer_suite(&DefaultTranscriber, &DefaultVerifier);
}

#[test]
fn conformance_schema_alignment() {
    run_schema_alignment_suite(&DefaultVerifier);
}

#[test]
fn conformance_keyid() {
    run_keyid_suite(&DefaultVerifier);
}

#[test]
fn conformance_base64() {
    run_base64_suite();
}

#[test]
fn conformance_ed25519() {
    run_ed25519_suite(&DefaultVerifier, &DefaultSigner);
}

#[test]
fn conformance_ecdsa() {
    run_ecdsa_suite(&DefaultVerifier, &DefaultSigner);
}

#[test]
fn conformance_yaml_signature() {
    run_yaml_signature_suite(&DefaultVerifier);
}
