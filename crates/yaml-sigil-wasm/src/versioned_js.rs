// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! JavaScript namespace entry points share the existing typed boundary.
//!
//! Rust re-exports alone do not create JavaScript exports. Keep these
//! forwarding functions free of validation, allocation, and protocol logic.

use js_sys::Uint8Array;
use wasm_bindgen::prelude::*;

use crate::{ArtifactResourceLimits, ComposeResult, DecomposeResult, SignResult, VerifyResult};

/// Compose a YamlSigil `v1alpha1` artifact.
#[wasm_bindgen(js_namespace = v1alpha1)]
pub fn compose(payload: Uint8Array, signature_carrier: Uint8Array, form: &str) -> ComposeResult {
    crate::compose(payload, signature_carrier, form)
}

/// Compose with an explicit complete-output policy.
#[wasm_bindgen(js_namespace = v1alpha1, js_name = composeWithResourceLimits)]
pub fn compose_with_limits(
    payload: Uint8Array,
    signature_carrier: Uint8Array,
    form: &str,
    limits: &ArtifactResourceLimits,
) -> ComposeResult {
    crate::compose_with_limits(payload, signature_carrier, form, limits)
}

/// Decompose a YamlSigil `v1alpha1` artifact.
#[wasm_bindgen(js_namespace = v1alpha1)]
pub fn decompose(artifact: Uint8Array, form: &str, outer: Option<String>) -> DecomposeResult {
    crate::decompose(artifact, form, outer)
}

/// Admit the original input before copying or interpreting it.
#[wasm_bindgen(js_namespace = v1alpha1, js_name = decomposeWithResourceLimits)]
pub fn decompose_with_limits(
    artifact: Uint8Array,
    form: &str,
    outer: Option<String>,
    limits: &ArtifactResourceLimits,
) -> DecomposeResult {
    crate::decompose_with_limits(artifact, form, outer, limits)
}

/// Sign a YamlSigil `v1alpha1` artifact.
#[wasm_bindgen(js_namespace = v1alpha1)]
pub fn sign(
    payload: Uint8Array,
    algorithm_selector: &str,
    signing_key: Uint8Array,
    keyid: Option<String>,
    append_missing_final_newline: bool,
    output_form_selector: &str,
) -> SignResult {
    crate::sign(
        payload,
        algorithm_selector,
        signing_key,
        keyid,
        append_missing_final_newline,
        output_form_selector,
    )
}

/// Sign with explicit complete-output admission and final sizing.
#[wasm_bindgen(js_namespace = v1alpha1, js_name = signWithResourceLimits)]
pub fn sign_with_limits(
    payload: Uint8Array,
    algorithm_selector: &str,
    signing_key: Uint8Array,
    keyid: Option<String>,
    append_missing_final_newline: bool,
    output_form_selector: &str,
    limits: &ArtifactResourceLimits,
) -> SignResult {
    crate::sign_with_limits(
        payload,
        algorithm_selector,
        signing_key,
        keyid,
        append_missing_final_newline,
        output_form_selector,
        limits,
    )
}

/// Verify a YamlSigil `v1alpha1` artifact.
#[wasm_bindgen(js_namespace = v1alpha1)]
pub fn verify(
    artifact: Uint8Array,
    form_selector: &str,
    algorithm_selector: &str,
    verifying_key: Uint8Array,
) -> VerifyResult {
    crate::verify(artifact, form_selector, algorithm_selector, verifying_key)
}

/// Admit the original input before copying, schema checks, or key resolution.
#[wasm_bindgen(js_namespace = v1alpha1, js_name = verifyWithResourceLimits)]
pub fn verify_with_limits(
    artifact: Uint8Array,
    form_selector: &str,
    algorithm_selector: &str,
    verifying_key: Uint8Array,
    limits: &ArtifactResourceLimits,
) -> VerifyResult {
    crate::verify_with_limits(
        artifact,
        form_selector,
        algorithm_selector,
        verifying_key,
        limits,
    )
}
