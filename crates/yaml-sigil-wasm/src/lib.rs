// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Typed JavaScript boundary for browser and Node.js WebAssembly runtimes.

use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use js_sys::Uint8Array;
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
use wasm_bindgen::prelude::*;
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{
    OutputForm, SignError, SignInvocationError, SignOutcome, SignRequest, SigningKey,
    sign as sign_runtime,
};
use yaml_sigil_transcription::{
    ComposeOutcome, ComposeRequest, DecomposeOutcome, DecomposeRequest, DecomposeResponse,
    OuterConformance, TranscriberError, TranscriberInvocationError, TranscriptionForm,
    compose as compose_runtime, decompose as decompose_runtime,
};
use yaml_sigil_verification::{
    ArtifactForm, InvocationError, PublicKeys, VerifierOptions, VerifierState,
    resolve_ed25519_verifying_key, resolve_p256_verifying_key, verify as verify_runtime,
};
use zeroize::Zeroizing;

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
    let Some(form) = transcription_form(form) else {
        return ComposeResult {
            status: "invocation_error",
            code: Some("invalid_or_unsupported_form"),
            artifact: None,
        };
    };
    let payload = payload.to_vec();
    let signature_carrier = signature_carrier.to_vec();
    match compose_runtime(&ComposeRequest {
        payload: &payload,
        signature_carrier: &signature_carrier,
        form,
    }) {
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
    let artifact = artifact.to_vec();
    match decompose_runtime(&DecomposeRequest {
        artifact: &artifact,
        form,
        outer_conformance: outer,
    }) {
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
    let Some(algorithm) = algorithm(algorithm_selector) else {
        return SignResult::invocation("invalid_or_unsupported_algorithm");
    };
    let Some(output_form) = output_form(output_form_selector) else {
        return SignResult::invocation("invalid_or_unsupported_output_form");
    };

    let payload = payload.to_vec();
    let key_bytes = Zeroizing::new(signing_key.to_vec());
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
) -> SignResult {
    match sign_runtime(&SignRequest {
        payload,
        algorithm,
        key,
        keyid,
        append_missing_final_newline,
        output_form,
        algorithm_parameters: &[],
    }) {
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
    let Some(form) = artifact_form(form_selector) else {
        return VerifyResult::invocation("invalid_or_unsupported_form");
    };
    let Some(selected_algorithm) = algorithm(algorithm_selector) else {
        return VerifyResult::invocation("invalid_or_unsupported_algorithm");
    };
    let artifact = artifact.to_vec();
    let key_bytes = verifying_key.to_vec();
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
    match verify_runtime(&artifact, form, &keys, options) {
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
