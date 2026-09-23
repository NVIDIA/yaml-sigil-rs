// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Typed JavaScript boundary for browser and Node.js WebAssembly runtimes.
//!
//! Select [`v1alpha1`] in Rust or the generated JavaScript `v1alpha1` export
//! explicitly. The unqualified API remains the `v1alpha1` default. Both
//! JavaScript paths use the same result classes and resource-policy objects.

pub mod v1alpha1;

mod bytes;
mod resource;
mod versioned_js;

use bytes::ByteInput;
pub use resource::ArtifactResourceLimits;
use resource::{Failure, flatten_encoding};

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use js_sys::Uint8Array;
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use wasm_bindgen::prelude::*;
use yaml_sigil_core::{AlgorithmId, ArtifactResourceForm};
use yaml_sigil_signing::{
    OutputForm, SignError, SignInvocationError, SignOutcome, SignRequest, SigningKey,
    sign as sign_runtime, sign_with_resource_limits,
};
use yaml_sigil_transcription::{
    ComposeOutcome, ComposeRequest, DecomposeOutcome, DecomposeRequest, DecomposeResponse,
    OuterConformance, TranscriberError, TranscriberInvocationError, TranscriptionForm,
    compose as compose_runtime, compose_with_resource_limits, decompose as decompose_runtime,
    decompose_with_resource_limits,
};
use yaml_sigil_verification::{
    ArtifactForm, InvocationError, PublicKeys, VerifierOptions, VerifierState,
    resolve_ed25519_verifying_key, resolve_p256_verifying_key, verify as verify_runtime,
    verify_with_resource_limits,
};

const ED25519_NAME: &str = "ED25519_PUREEDDSA_RAW_RS64_CANONICAL";
const P256_NAME: &str = "ECDSA_SECP256R1_SHA256_RAW_RS64";

fn bytes_or_empty(bytes: Option<&[u8]>) -> Uint8Array {
    Uint8Array::from(bytes.unwrap_or_default())
}

fn transcription_form(value: &str) -> Option<TranscriptionForm> {
    match value {
        "yaml" => Some(TranscriptionForm::Yaml),
        "protobuf" => Some(TranscriptionForm::Protobuf),
        _ => None,
    }
}

fn output_form(value: &str) -> Option<OutputForm> {
    match value {
        "yaml" => Some(OutputForm::Yaml),
        "protobuf" => Some(OutputForm::Protobuf),
        _ => None,
    }
}

fn artifact_form(value: &str) -> Option<ArtifactForm> {
    match value {
        "yaml" => Some(ArtifactForm::Yaml),
        "protobuf" => Some(ArtifactForm::Proto),
        _ => None,
    }
}

fn outer_conformance(value: &str) -> Option<OuterConformance> {
    match value {
        "strict" => Some(OuterConformance::Strict),
        "signature_strict" => Some(OuterConformance::SignatureStrict),
        _ => None,
    }
}

fn algorithm(value: &str) -> Option<AlgorithmId> {
    match value {
        ED25519_NAME => Some(AlgorithmId::Ed25519),
        P256_NAME => Some(AlgorithmId::EcdsaP256Sha256),
        _ => None,
    }
}

fn algorithm_name(value: AlgorithmId) -> &'static str {
    match value {
        AlgorithmId::Ed25519 => ED25519_NAME,
        AlgorithmId::EcdsaP256Sha256 => P256_NAME,
    }
}

fn transcriber_invocation_code(error: TranscriberInvocationError) -> &'static str {
    match error {
        TranscriberInvocationError::InvalidOrUnsupportedForm => "invalid_or_unsupported_form",
        TranscriberInvocationError::InvalidOrUnsupportedOuterConformance => {
            "invalid_or_unsupported_outer_conformance"
        }
    }
}

fn transcriber_error_code(error: TranscriberError) -> &'static str {
    match error {
        TranscriberError::InvalidPayloadBytes => "invalid_payload_bytes",
        TranscriberError::InvalidSignatureCarrier => "invalid_signature_carrier",
    }
}

fn sign_invocation_code(error: SignInvocationError) -> &'static str {
    match error {
        SignInvocationError::InvalidOrUnsupportedAlgorithm => "invalid_or_unsupported_algorithm",
        SignInvocationError::InvalidAlgorithmParameters => "invalid_algorithm_parameters",
        SignInvocationError::InvalidOrUnsupportedOutputForm => "invalid_or_unsupported_output_form",
        SignInvocationError::InvalidKeyid => "invalid_keyid",
    }
}

fn sign_error_code(error: &SignError) -> &'static str {
    match error {
        SignError::InvalidPayloadBytes => "invalid_payload_bytes",
        SignError::PayloadLineTerminatorRefusal => "payload_line_terminator_refusal",
        SignError::InvalidOrUnsupportedAlgorithm => "invalid_or_unsupported_algorithm",
        SignError::InvalidAlgorithmParameters => "invalid_algorithm_parameters",
        SignError::InvalidOrUnsupportedOutputForm => "invalid_or_unsupported_output_form",
        SignError::InvalidKeyid => "invalid_keyid",
        SignError::KeyOperationFailure => "key_operation_failure",
        SignError::YamlValidationFailure => "yaml_validation_failure",
        SignError::YamlSerialize(_) => "yaml_serialize",
    }
}

fn verify_invocation_code(error: InvocationError) -> &'static str {
    match error {
        InvocationError::InvalidAlgorithmParameters => "invalid_algorithm_parameters",
        InvocationError::KeyResolutionFailure => "key_resolution_failure",
        InvocationError::TrustPolicyConfigurationError => "trust_policy_configuration_error",
        InvocationError::InvalidPreVerifyResult => "invalid_pre_verify_result",
        InvocationError::InvalidOrUnsupportedForm => "invalid_or_unsupported_form",
    }
}

#[wasm_bindgen]
pub struct ComposeResult {
    status: &'static str,
    code: Option<&'static str>,
    artifact: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl ComposeResult {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn code(&self) -> Option<String> {
        self.code.map(str::to_string)
    }

    #[wasm_bindgen(getter, js_name = hasArtifact)]
    pub fn has_artifact(&self) -> bool {
        self.artifact.is_some()
    }

    #[wasm_bindgen(getter)]
    pub fn artifact(&self) -> Uint8Array {
        bytes_or_empty(self.artifact.as_deref())
    }
}

#[wasm_bindgen]
pub fn compose(payload: Uint8Array, signature_carrier: Uint8Array, form: &str) -> ComposeResult {
    compose_impl(payload, signature_carrier, form, None)
}

/// Compose with an explicit complete-output policy.
#[wasm_bindgen(js_name = composeWithResourceLimits)]
pub fn compose_with_limits(
    payload: Uint8Array,
    signature_carrier: Uint8Array,
    form: &str,
    limits: &ArtifactResourceLimits,
) -> ComposeResult {
    compose_impl(payload, signature_carrier, form, Some(limits))
}

fn compose_impl(
    payload: Uint8Array,
    signature_carrier: Uint8Array,
    form: &str,
    limits: Option<&ArtifactResourceLimits>,
) -> ComposeResult {
    let Some(form) = transcription_form(form) else {
        return ComposeResult {
            status: "invocation_error",
            code: Some("invalid_or_unsupported_form"),
            artifact: None,
        };
    };
    let payload = match ByteInput::new(&payload) {
        Ok(input) => input,
        Err(error) => return ComposeResult::failure(error),
    };
    let signature_carrier = match ByteInput::new(&signature_carrier) {
        Ok(input) => input,
        Err(error) => return ComposeResult::failure(error),
    };
    if let Some(limits) = limits {
        let resource_form = match form {
            TranscriptionForm::Yaml => ArtifactResourceForm::Yaml,
            TranscriptionForm::Protobuf => ArtifactResourceForm::Protobuf,
        };
        if let Err(error) = limits.with_admitted_output(
            resource_form,
            &[payload.len(), signature_carrier.len()],
            || (),
        ) {
            return ComposeResult::failure(error);
        }
    }
    let payload = match payload.to_vec() {
        Ok(bytes) => bytes,
        Err(error) => return ComposeResult::failure(error),
    };
    let signature_carrier = match signature_carrier.to_vec() {
        Ok(bytes) => bytes,
        Err(error) => return ComposeResult::failure(error),
    };
    let request = ComposeRequest {
        payload: &payload,
        signature_carrier: &signature_carrier,
        form,
    };
    let outcome = if let Some(limits) = limits {
        match flatten_encoding(compose_with_resource_limits(&request, &limits.inner)) {
            Ok(outcome) => outcome,
            Err(error) => return ComposeResult::failure(error),
        }
    } else {
        compose_runtime(&request)
    };
    match outcome {
        ComposeOutcome::Success(success) => ComposeResult {
            status: "success",
            code: None,
            artifact: Some(success.artifact),
        },
        ComposeOutcome::Invocation(error) => ComposeResult {
            status: "invocation_error",
            code: Some(transcriber_invocation_code(error)),
            artifact: None,
        },
        ComposeOutcome::Error(error) => ComposeResult {
            status: "error",
            code: Some(transcriber_error_code(error)),
            artifact: None,
        },
    }
}

impl ComposeResult {
    fn failure(error: Failure) -> Self {
        Self {
            status: error.status(),
            code: Some(error.code()),
            artifact: None,
        }
    }
}

#[wasm_bindgen]
pub struct DecomposeResult {
    status: &'static str,
    code: Option<&'static str>,
    payload: Option<Vec<u8>>,
    signature_carrier: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl DecomposeResult {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn code(&self) -> Option<String> {
        self.code.map(str::to_string)
    }

    #[wasm_bindgen(getter, js_name = hasPayload)]
    pub fn has_payload(&self) -> bool {
        self.payload.is_some()
    }

    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Uint8Array {
        bytes_or_empty(self.payload.as_deref())
    }

    #[wasm_bindgen(getter, js_name = hasSignatureCarrier)]
    pub fn has_signature_carrier(&self) -> bool {
        self.signature_carrier.is_some()
    }

    #[wasm_bindgen(getter, js_name = signatureCarrier)]
    pub fn signature_carrier(&self) -> Uint8Array {
        bytes_or_empty(self.signature_carrier.as_deref())
    }
}

#[wasm_bindgen]
pub fn decompose(artifact: Uint8Array, form: &str, outer: Option<String>) -> DecomposeResult {
    decompose_impl(artifact, form, outer, None)
}

/// Admit the JavaScript input length before copying or interpreting it.
#[wasm_bindgen(js_name = decomposeWithResourceLimits)]
pub fn decompose_with_limits(
    artifact: Uint8Array,
    form: &str,
    outer: Option<String>,
    limits: &ArtifactResourceLimits,
) -> DecomposeResult {
    decompose_impl(artifact, form, outer, Some(limits))
}

fn decompose_impl(
    artifact: Uint8Array,
    form: &str,
    outer: Option<String>,
    limits: Option<&ArtifactResourceLimits>,
) -> DecomposeResult {
    let artifact = match ByteInput::new(&artifact) {
        Ok(input) => input,
        Err(error) => return DecomposeResult::failure(error),
    };
    if let Some(limits) = limits
        && let Err(error) = limits.with_admitted_input(artifact.len(), || ())
    {
        return DecomposeResult::failure(error);
    }
    let Some(form) = transcription_form(form) else {
        return DecomposeResult::invocation("invalid_or_unsupported_form");
    };
    let outer = match outer.as_deref() {
        Some(value) => match outer_conformance(value) {
            Some(value) => Some(value),
            None => {
                return DecomposeResult::invocation("invalid_or_unsupported_outer_conformance");
            }
        },
        None => None,
    };
    let artifact = match artifact.to_vec() {
        Ok(bytes) => bytes,
        Err(error) => return DecomposeResult::failure(error),
    };
    let request = DecomposeRequest {
        artifact: &artifact,
        form,
        outer_conformance: outer,
    };
    let response = if let Some(limits) = limits {
        match decompose_with_resource_limits(&request, &limits.inner) {
            Ok(response) => response,
            Err(error) => return DecomposeResult::failure(error.into()),
        }
    } else {
        decompose_runtime(&request)
    };
    match response {
        DecomposeResponse::Invocation(error) => {
            DecomposeResult::invocation(transcriber_invocation_code(error))
        }
        DecomposeResponse::Structural(result) => match result.outcome {
            DecomposeOutcome::Ok => DecomposeResult {
                status: "ok",
                code: None,
                payload: result.payload,
                signature_carrier: result.signature_carrier,
            },
            DecomposeOutcome::Unsigned => DecomposeResult {
                status: "unsigned",
                code: None,
                payload: None,
                signature_carrier: None,
            },
            DecomposeOutcome::MalformedAttemptedSigned => DecomposeResult {
                status: "malformed_attempted_signed",
                code: None,
                payload: None,
                signature_carrier: None,
            },
        },
    }
}

impl DecomposeResult {
    fn failure(error: Failure) -> Self {
        Self {
            status: error.status(),
            code: Some(error.code()),
            payload: None,
            signature_carrier: None,
        }
    }

    fn invocation(code: &'static str) -> Self {
        Self {
            status: "invocation_error",
            code: Some(code),
            payload: None,
            signature_carrier: None,
        }
    }
}

#[wasm_bindgen]
pub struct SignResult {
    status: &'static str,
    code: Option<&'static str>,
    artifact: Option<Vec<u8>>,
    modified_payload: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl SignResult {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn code(&self) -> Option<String> {
        self.code.map(str::to_string)
    }

    #[wasm_bindgen(getter, js_name = hasArtifact)]
    pub fn has_artifact(&self) -> bool {
        self.artifact.is_some()
    }

    #[wasm_bindgen(getter)]
    pub fn artifact(&self) -> Uint8Array {
        bytes_or_empty(self.artifact.as_deref())
    }

    #[wasm_bindgen(getter, js_name = hasModifiedPayload)]
    pub fn has_modified_payload(&self) -> bool {
        self.modified_payload.is_some()
    }

    #[wasm_bindgen(getter, js_name = modifiedPayload)]
    pub fn modified_payload(&self) -> Uint8Array {
        bytes_or_empty(self.modified_payload.as_deref())
    }
}

#[wasm_bindgen]
pub fn sign(
    payload: Uint8Array,
    algorithm_selector: &str,
    signing_key: Uint8Array,
    keyid: Option<String>,
    append_missing_final_newline: bool,
    output_form_selector: &str,
) -> SignResult {
    sign_impl(
        payload,
        algorithm_selector,
        signing_key,
        keyid,
        append_missing_final_newline,
        output_form_selector,
        None,
    )
}

/// Sign with explicit complete-output admission and final sizing.
#[wasm_bindgen(js_name = signWithResourceLimits)]
pub fn sign_with_limits(
    payload: Uint8Array,
    algorithm_selector: &str,
    signing_key: Uint8Array,
    keyid: Option<String>,
    append_missing_final_newline: bool,
    output_form_selector: &str,
    limits: &ArtifactResourceLimits,
) -> SignResult {
    sign_impl(
        payload,
        algorithm_selector,
        signing_key,
        keyid,
        append_missing_final_newline,
        output_form_selector,
        Some(limits),
    )
}

fn sign_impl(
    payload: Uint8Array,
    algorithm_selector: &str,
    signing_key: Uint8Array,
    keyid: Option<String>,
    append_missing_final_newline: bool,
    output_form_selector: &str,
    limits: Option<&ArtifactResourceLimits>,
) -> SignResult {
    let Some(algorithm) = algorithm(algorithm_selector) else {
        return SignResult::invocation("invalid_or_unsupported_algorithm");
    };
    let Some(output_form) = output_form(output_form_selector) else {
        return SignResult::invocation("invalid_or_unsupported_output_form");
    };

    let signing_key = match ByteInput::new(&signing_key) {
        Ok(input) => input,
        Err(error) => return SignResult::failure(error),
    };
    if signing_key.len() != 32 {
        return SignResult::invocation("invalid_signing_key");
    }
    if limits.is_some()
        && keyid
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 1024)
    {
        return SignResult::invocation("invalid_keyid");
    }
    let payload = match ByteInput::new(&payload) {
        Ok(input) => input,
        Err(error) => return SignResult::failure(error),
    };
    if let Some(limits) = limits {
        let resource_form = match output_form {
            OutputForm::Yaml => ArtifactResourceForm::Yaml,
            OutputForm::Protobuf => ArtifactResourceForm::Protobuf,
        };
        if let Err(error) = limits.with_admitted_output(resource_form, &[payload.len()], || ()) {
            return SignResult::failure(error);
        }
    }
    let payload = match payload.to_vec() {
        Ok(bytes) => bytes,
        Err(error) => return SignResult::failure(error),
    };
    let key_bytes = match signing_key.to_secret_vec() {
        Ok(bytes) => bytes,
        Err(error) => return SignResult::failure(error),
    };
    match algorithm {
        AlgorithmId::Ed25519 => {
            let Ok(seed) = <&[u8; 32]>::try_from(key_bytes.as_slice()) else {
                return SignResult::invocation("invalid_signing_key");
            };
            let key = Ed25519SigningKey::from_bytes(seed);
            sign_with_key(
                &payload,
                algorithm,
                SigningKey::Ed25519(&key),
                keyid.as_deref(),
                append_missing_final_newline,
                output_form,
                limits,
            )
        }
        AlgorithmId::EcdsaP256Sha256 => {
            if key_bytes.len() != 32 {
                return SignResult::invocation("invalid_signing_key");
            }
            let Ok(key) = P256SigningKey::from_slice(&key_bytes) else {
                return SignResult::invocation("invalid_signing_key");
            };
            sign_with_key(
                &payload,
                algorithm,
                SigningKey::EcdsaP256Sha256(&key),
                keyid.as_deref(),
                append_missing_final_newline,
                output_form,
                limits,
            )
        }
    }
}

fn sign_with_key(
    payload: &[u8],
    algorithm: AlgorithmId,
    key: SigningKey<'_>,
    keyid: Option<&str>,
    append_missing_final_newline: bool,
    output_form: OutputForm,
    limits: Option<&ArtifactResourceLimits>,
) -> SignResult {
    let request = SignRequest {
        payload,
        algorithm,
        key,
        keyid,
        append_missing_final_newline,
        output_form,
        algorithm_parameters: &[],
    };
    let outcome = if let Some(limits) = limits {
        match flatten_encoding(sign_with_resource_limits(&request, &limits.inner)) {
            Ok(outcome) => outcome,
            Err(error) => return SignResult::failure(error),
        }
    } else {
        sign_runtime(&request)
    };
    match outcome {
        SignOutcome::Success(success) => SignResult {
            status: "success",
            code: None,
            artifact: Some(success.artifact),
            modified_payload: (!success.modified_payload.is_empty())
                .then_some(success.modified_payload),
        },
        SignOutcome::Invocation(error) => SignResult::invocation(sign_invocation_code(error)),
        SignOutcome::Signer(error) => SignResult {
            status: "signer_error",
            code: Some(sign_error_code(&error)),
            artifact: None,
            modified_payload: None,
        },
    }
}

impl SignResult {
    fn failure(error: Failure) -> Self {
        Self {
            status: error.status(),
            code: Some(error.code()),
            artifact: None,
            modified_payload: None,
        }
    }

    fn invocation(code: &'static str) -> Self {
        Self {
            status: "invocation_error",
            code: Some(code),
            artifact: None,
            modified_payload: None,
        }
    }
}

#[wasm_bindgen]
pub struct VerifyResult {
    status: &'static str,
    code: Option<&'static str>,
    payload: Option<Vec<u8>>,
    algorithm: Option<&'static str>,
}

#[wasm_bindgen]
impl VerifyResult {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> String {
        self.status.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn code(&self) -> Option<String> {
        self.code.map(str::to_string)
    }

    #[wasm_bindgen(getter, js_name = hasPayload)]
    pub fn has_payload(&self) -> bool {
        self.payload.is_some()
    }

    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Uint8Array {
        bytes_or_empty(self.payload.as_deref())
    }

    #[wasm_bindgen(getter, js_name = hasAlgorithm)]
    pub fn has_algorithm(&self) -> bool {
        self.algorithm.is_some()
    }

    #[wasm_bindgen(getter)]
    pub fn algorithm(&self) -> Option<String> {
        self.algorithm.map(str::to_string)
    }
}

enum ResolvedVerifyingKey {
    Ed25519(Ed25519VerifyingKey),
    P256(P256VerifyingKey),
}

#[wasm_bindgen]
pub fn verify(
    artifact: Uint8Array,
    form_selector: &str,
    algorithm_selector: &str,
    verifying_key: Uint8Array,
) -> VerifyResult {
    verify_impl(
        artifact,
        form_selector,
        algorithm_selector,
        verifying_key,
        None,
    )
}

/// Admit the JavaScript input before copying, schema checks, or key resolution.
#[wasm_bindgen(js_name = verifyWithResourceLimits)]
pub fn verify_with_limits(
    artifact: Uint8Array,
    form_selector: &str,
    algorithm_selector: &str,
    verifying_key: Uint8Array,
    limits: &ArtifactResourceLimits,
) -> VerifyResult {
    verify_impl(
        artifact,
        form_selector,
        algorithm_selector,
        verifying_key,
        Some(limits),
    )
}

fn verify_impl(
    artifact: Uint8Array,
    form_selector: &str,
    algorithm_selector: &str,
    verifying_key: Uint8Array,
    limits: Option<&ArtifactResourceLimits>,
) -> VerifyResult {
    let artifact = match ByteInput::new(&artifact) {
        Ok(input) => input,
        Err(error) => return VerifyResult::failure(error),
    };
    if let Some(limits) = limits
        && let Err(error) = limits.with_admitted_input(artifact.len(), || ())
    {
        return VerifyResult::failure(error);
    }
    let Some(form) = artifact_form(form_selector) else {
        return VerifyResult::invocation("invalid_or_unsupported_form");
    };
    let Some(selected_algorithm) = algorithm(algorithm_selector) else {
        return VerifyResult::invocation("invalid_or_unsupported_algorithm");
    };
    let expected_key_length = match selected_algorithm {
        AlgorithmId::Ed25519 => 32,
        AlgorithmId::EcdsaP256Sha256 => 65,
    };
    let verifying_key = match ByteInput::new(&verifying_key) {
        Ok(input) => input,
        Err(error) => return VerifyResult::failure(error),
    };
    if verifying_key.len() != expected_key_length {
        return VerifyResult::invocation("key_resolution_failure");
    }
    let artifact = match artifact.to_vec() {
        Ok(bytes) => bytes,
        Err(error) => return VerifyResult::failure(error),
    };
    let key_bytes = match verifying_key.to_vec() {
        Ok(bytes) => bytes,
        Err(error) => return VerifyResult::failure(error),
    };
    let key = match selected_algorithm {
        AlgorithmId::Ed25519 => match resolve_ed25519_verifying_key(&key_bytes) {
            Ok(key) => ResolvedVerifyingKey::Ed25519(key),
            Err(error) => return VerifyResult::invocation(verify_invocation_code(error)),
        },
        AlgorithmId::EcdsaP256Sha256 => match resolve_p256_verifying_key(&key_bytes) {
            Ok(key) => ResolvedVerifyingKey::P256(key),
            Err(error) => return VerifyResult::invocation(verify_invocation_code(error)),
        },
    };
    let keys = match &key {
        ResolvedVerifyingKey::Ed25519(key) => PublicKeys {
            ed25519: Some(key),
            p256: None,
        },
        ResolvedVerifyingKey::P256(key) => PublicKeys {
            ed25519: None,
            p256: Some(key),
        },
    };
    let options = VerifierOptions {
        verify_ed25519: selected_algorithm == AlgorithmId::Ed25519,
        verify_ecdsa_p256_sha256: selected_algorithm == AlgorithmId::EcdsaP256Sha256,
        ..VerifierOptions::default()
    };
    #[cfg(feature = "json-schema-validate")]
    if schema_validation_rejects(&artifact, form) {
        return VerifyResult::state("malformed_attempted_signed", None);
    }
    let outcome = if let Some(limits) = limits {
        match verify_with_resource_limits(&artifact, form, &keys, options, &limits.inner) {
            Ok(outcome) => outcome,
            Err(error) => return VerifyResult::failure(error.into()),
        }
    } else {
        verify_runtime(&artifact, form, &keys, options)
    };
    match outcome {
        Err(error) => VerifyResult::invocation(verify_invocation_code(error)),
        Ok(VerifierState::Verified { payload, algorithm }) => VerifyResult {
            status: "verified",
            code: None,
            payload: Some(payload),
            algorithm: Some(algorithm_name(algorithm)),
        },
        Ok(VerifierState::Unsigned) => VerifyResult::state("unsigned", None),
        Ok(VerifierState::MalformedAttemptedSigned) => {
            VerifyResult::state("malformed_attempted_signed", None)
        }
        Ok(VerifierState::SignedButAlgorithmUnsupported { algorithm }) => VerifyResult::state(
            "signed_but_algorithm_unsupported",
            Some(algorithm_name(algorithm)),
        ),
        Ok(VerifierState::SignedButFailedVerification) => {
            VerifyResult::state("signed_but_failed_verification", None)
        }
    }
}

#[cfg(feature = "json-schema-validate")]
fn schema_validation_rejects(artifact: &[u8], form: ArtifactForm) -> bool {
    if form != ArtifactForm::Yaml {
        return false;
    }
    let response = decompose_runtime(&DecomposeRequest {
        artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let DecomposeResponse::Structural(result) = response else {
        return false;
    };
    if result.outcome != DecomposeOutcome::Ok {
        return false;
    }
    let Some(carrier) = result.signature_carrier else {
        return false;
    };
    let Ok(document) = yaml_sigil_core::parse_signature_document(&carrier) else {
        return false;
    };
    yaml_sigil_core::signature_document_validates_tier_a_schema(&document).is_err()
}

impl VerifyResult {
    fn failure(error: Failure) -> Self {
        Self {
            status: error.status(),
            code: Some(error.code()),
            payload: None,
            algorithm: None,
        }
    }

    fn invocation(code: &'static str) -> Self {
        Self {
            status: "invocation_error",
            code: Some(code),
            payload: None,
            algorithm: None,
        }
    }

    fn state(status: &'static str, algorithm: Option<&'static str>) -> Self {
        Self {
            status,
            code: None,
            payload: None,
            algorithm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_are_exact_and_case_sensitive() {
        assert_eq!(transcription_form("yaml"), Some(TranscriptionForm::Yaml));
        assert_eq!(output_form("protobuf"), Some(OutputForm::Protobuf));
        assert_eq!(artifact_form("protobuf"), Some(ArtifactForm::Proto));
        assert_eq!(algorithm(ED25519_NAME), Some(AlgorithmId::Ed25519));
        assert_eq!(algorithm(P256_NAME), Some(AlgorithmId::EcdsaP256Sha256));
        assert_eq!(outer_conformance("strict"), Some(OuterConformance::Strict));
        assert_eq!(transcription_form("YAML"), None);
        assert_eq!(algorithm("ed25519"), None);
        assert_eq!(outer_conformance("signature-strict"), None);
    }
}
