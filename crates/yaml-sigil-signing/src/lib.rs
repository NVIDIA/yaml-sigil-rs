// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YamlSigil v1alpha1 signing: YAML + protobuf artifacts, Ed25519 + ECDSA P-256 SHA-256.
//! Signed-artifact transcoding lives in [`transcription`].
//!
//! Request-shape failures are [`SignInvocationError`]; sign-time failures are
//! [`SignError`], plus the YAML serialization extension. Resource-aware
//! protobuf output preserves the core facade's [`yaml_sigil_core::pb::EncodeError`]
//! in a separate inner result layer.
//!
//! Convenience wrappers [`sign_yaml`] and [`sign_proto`] call [`sign`] with a fixed [`OutputForm`].
//!
//! # Resource boundaries
//!
//! Existing signing entry points retain their unbounded complete-output
//! behavior. [`sign_with_resource_limits`], [`sign_yaml_with_resource_limits`],
//! and [`sign_proto_with_resource_limits`] apply an explicitly selected policy
//! before avoidable content processing, cryptography, and complete-output
//! allocation. This policy is operational hardening, not YamlSigil `v1alpha1`
//! conformance.

mod proto_carrier;
pub mod transcription;

pub use transcription::{
    TranscodeError, proto_wire_to_signed_yaml_stream,
    proto_wire_to_signed_yaml_stream_with_resource_limits, signed_yaml_stream_to_proto_wire,
    signed_yaml_stream_to_proto_wire_with_resource_limits,
};

use tracing::instrument;
pub use yaml_sigil_core::pb::{EncodeError, EncodeErrorKind};
pub use yaml_sigil_core::{
    ArtifactResourceError, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    ArtifactResourceResult, DEFAULT_MAX_ARTIFACT_BYTES,
};
use yaml_sigil_core::{SignatureDocument, pb::check_encoded_message_size, validate_payload_stream};
use yaml_sigil_traits::{
    AlgorithmId, ProtobufWireDecodeAdvertisement, YamlSignatureDocumentDuplicateKeyPolicy,
    YamlSignatureDocumentUnknownFieldPolicy,
};

// The portable traits and DTOs live in `yaml-sigil-traits`. This implementation
// binds the generic key-bearing DTOs to its RustCrypto key types while retaining
// the established `yaml_sigil_signing::{SigningKey, SignRequest}` paths.
pub use yaml_sigil_traits::signing::{
    AsyncSigner, OutputForm, SignError, SignInvocationError, SignOutcome, SignSuccess, Signer,
    SignerCapabilities,
};
use yaml_sigil_traits::signing::{
    SignRequest as GenericSignRequest, SigningKey as GenericSigningKey,
};

/// Signing keys supported by this RustCrypto implementation.
pub type SigningKey<'a> = GenericSigningKey<'a, ed25519_dalek::SigningKey, p256::ecdsa::SigningKey>;

/// Unified sign request specialized for this RustCrypto implementation.
pub type SignRequest<'a> =
    GenericSignRequest<'a, ed25519_dalek::SigningKey, p256::ecdsa::SigningKey>;

/// Return the capability set for this crate build.
pub fn signer_capabilities() -> SignerCapabilities {
    SignerCapabilities {
        protobuf_wire_decode: ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder,
        yaml_signature_duplicate_key_policy:
            YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse,
        yaml_signature_unknown_field_policy:
            YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse,
        supported_output_forms: &[OutputForm::Yaml, OutputForm::Protobuf],
        supported_algorithms: &[AlgorithmId::Ed25519, AlgorithmId::EcdsaP256Sha256],
        best_effort_yaml_validation: false,
        implementation_name: env!("CARGO_PKG_NAME"),
        implementation_version: env!("CARGO_PKG_VERSION"),
    }
}

/// Parameters for producing a signed YAML artifact (convenience wrapper).
pub struct SignYamlParams<'a> {
    pub payload: &'a [u8],
    pub algorithm: AlgorithmId,
    pub key: SigningKey<'a>,
    pub keyid: Option<&'a str>,
    /// If true, a missing trailing `\\n` on a non-empty payload is fixed by appending `0x0A`.
    pub append_missing_final_newline: bool,
}

/// Parameters for producing protobuf `SignedYamlArtifact` wire bytes (convenience wrapper).
pub struct SignProtoParams<'a> {
    pub payload: &'a [u8],
    pub algorithm: AlgorithmId,
    pub key: SigningKey<'a>,
    pub keyid: Option<&'a str>,
    /// Ignored for protobuf output; payload bytes are always preserved exactly.
    pub append_missing_final_newline: bool,
}

fn validate_invocation_shape(req: &SignRequest<'_>) -> Result<(), SignInvocationError> {
    let caps = signer_capabilities();
    if !caps.supported_output_forms.contains(&req.output_form) {
        return Err(SignInvocationError::InvalidOrUnsupportedOutputForm);
    }
    if !caps.supported_algorithms.contains(&req.algorithm) {
        return Err(SignInvocationError::InvalidOrUnsupportedAlgorithm);
    }
    if !req.algorithm_parameters.is_empty() {
        return Err(SignInvocationError::InvalidAlgorithmParameters);
    }
    if let Some(keyid) = req.keyid {
        let octets = keyid.len();
        if octets == 0 || octets > 1024 {
            return Err(SignInvocationError::InvalidKeyid);
        }
    }
    match (&req.algorithm, &req.key) {
        (AlgorithmId::Ed25519, SigningKey::Ed25519(_)) => Ok(()),
        (AlgorithmId::EcdsaP256Sha256, SigningKey::EcdsaP256Sha256(_)) => Ok(()),
        _ => Err(SignInvocationError::InvalidOrUnsupportedAlgorithm),
    }
}

fn validate_keyid_content(req: &SignRequest<'_>) -> Result<(), SignInvocationError> {
    if req.keyid.is_some_and(|keyid| keyid.contains(['\r', '\n'])) {
        Err(SignInvocationError::InvalidKeyid)
    } else {
        Ok(())
    }
}

fn validate_invocation(req: &SignRequest<'_>) -> Result<(), SignInvocationError> {
    validate_invocation_shape(req)?;
    validate_keyid_content(req)
}

fn normalize_yaml_payload(
    payload: &[u8],
    append_missing_final_newline: bool,
) -> Result<Vec<u8>, SignError> {
    if std::str::from_utf8(payload).is_err() {
        return Err(SignError::InvalidPayloadBytes);
    }
    if payload.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(SignError::InvalidPayloadBytes);
    }
    if payload.is_empty() {
        return Ok(Vec::new());
    }
    if payload.ends_with(b"\n") {
        return Ok(payload.to_vec());
    }
    if append_missing_final_newline {
        let mut v = payload.to_vec();
        v.push(b'\n');
        return Ok(v);
    }
    Err(SignError::PayloadLineTerminatorRefusal)
}

const FIXED_SIGNATURE_BYTES: u64 = 64;

fn varint_len(mut value: u64) -> u64 {
    let mut length = 1;
    while value >= 0x80 {
        value >>= 7;
        length += 1;
    }
    length
}

fn checked_yaml_signing_lower_bound(
    req: &SignRequest<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<usize> {
    let overflow = || limits.size_computation_overflow(ArtifactResourceForm::Yaml);
    let projected_lf = usize::from(
        !req.payload.is_empty()
            && !req.payload.ends_with(b"\n")
            && req.append_missing_final_newline,
    );
    let minimum_signature_text_len = usize::try_from(FIXED_SIGNATURE_BYTES)
        .ok()
        .and_then(|bytes| bytes.checked_mul(4))
        .and_then(|bits| bits.checked_add(2))
        .map(|rounded| rounded / 3)
        .ok_or_else(overflow)?;
    let mut minimum_carrier_len = "schema: "
        .len()
        .checked_add(yaml_sigil_core::SCHEMA_V1ALPHA1.len())
        .and_then(|size| size.checked_add(1))
        .and_then(|size| size.checked_add("alg: ".len()))
        .and_then(|size| size.checked_add(req.algorithm.as_yaml_str().len()))
        .and_then(|size| size.checked_add(1))
        .ok_or_else(overflow)?;
    if let Some(keyid) = req.keyid {
        minimum_carrier_len = minimum_carrier_len
            .checked_add("keyid: ".len())
            .and_then(|size| size.checked_add(2))
            .and_then(|size| size.checked_add(keyid.len()))
            .and_then(|size| size.checked_add(1))
            .ok_or_else(overflow)?;
    }
    minimum_carrier_len = minimum_carrier_len
        .checked_add("signature: ".len())
        .and_then(|size| size.checked_add(minimum_signature_text_len))
        .and_then(|size| size.checked_add(1))
        .ok_or_else(overflow)?;

    let minimum_artifact_len = req
        .payload
        .len()
        .checked_add(projected_lf)
        .and_then(|size| size.checked_add(4))
        .and_then(|size| size.checked_add(minimum_carrier_len))
        .ok_or_else(overflow)?;
    limits.check_output_size_lower_bound(ArtifactResourceForm::Yaml, minimum_artifact_len)
}

fn checked_len_field_size(value_len: u64) -> Option<u64> {
    1u64.checked_add(varint_len(value_len))
        .and_then(|size| size.checked_add(value_len))
}

fn checked_proto_signing_size(
    req: &SignRequest<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    let overflow = || limits.size_computation_overflow(ArtifactResourceForm::Protobuf);
    let payload_len = u64::try_from(req.payload.len()).map_err(|_| overflow())?;
    let keyid_len = req
        .keyid
        .map(str::len)
        .map(u64::try_from)
        .transpose()
        .map_err(|_| overflow())?;
    checked_proto_signing_size_from_lengths(payload_len, keyid_len, limits)
}

fn checked_proto_signing_size_from_lengths(
    payload_len: u64,
    keyid_len: Option<u64>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    let overflow = || limits.size_computation_overflow(ArtifactResourceForm::Protobuf);
    let mut carrier_len = 2u64;
    if let Some(keyid_len) = keyid_len {
        carrier_len = carrier_len
            .checked_add(checked_len_field_size(keyid_len).ok_or_else(overflow)?)
            .ok_or_else(overflow)?;
    }
    carrier_len = carrier_len
        .checked_add(checked_len_field_size(FIXED_SIGNATURE_BYTES).ok_or_else(overflow)?)
        .ok_or_else(overflow)?;

    let raw_size = checked_len_field_size(payload_len)
        .and_then(|payload_size| {
            checked_len_field_size(carrier_len)
                .and_then(|carrier_size| payload_size.checked_add(carrier_size))
        })
        .ok_or_else(overflow)?;
    let encoded_size = usize::try_from(raw_size).map_err(|_| overflow())?;
    limits.check_output_size(ArtifactResourceForm::Protobuf, encoded_size)?;
    Ok(check_encoded_message_size(encoded_size))
}

fn preflight_signing_output(
    req: &SignRequest<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<usize, EncodeError>> {
    match req.output_form {
        OutputForm::Yaml => Ok(Ok(checked_yaml_signing_lower_bound(req, limits)?)),
        OutputForm::Protobuf => checked_proto_signing_size(req, limits),
    }
}

/// Unified signing entry point corresponding to the IDL `Sign` operation.
///
/// For protobuf output, `append_missing_final_newline` is
/// ignored and the payload bytes are signed and emitted without modification.
///
/// This method does not enforce an implementation-local complete-artifact
/// limit. Use [`sign_with_resource_limits`] to select the shared output policy.
#[instrument(level = "info", skip(req), fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign(req: &SignRequest<'_>) -> SignOutcome {
    sign_inner(req)
}

/// Sign after applying an explicit complete-output resource policy.
///
/// Request-shape validation performs work bounded independently of payload
/// length. Protobuf output is sized exactly before content validation or
/// cryptography. YAML output first applies a conclusive lower bound and then
/// checks the exact serialized result before complete-artifact allocation.
/// The outer result reports resource rejection. The inner result preserves a
/// protobuf format error after resource admission; YAML output always reaches
/// the existing [`SignOutcome`] layer.
#[instrument(level = "info", skip(req, limits), fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign_with_resource_limits(
    req: &SignRequest<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<SignOutcome, EncodeError>> {
    if let Err(error) = validate_invocation_shape(req) {
        return Ok(Ok(SignOutcome::Invocation(error)));
    }
    if let Err(error) = preflight_signing_output(req, limits)? {
        return Ok(Err(error));
    }
    if let Err(error) = validate_keyid_content(req) {
        return Ok(Ok(SignOutcome::Invocation(error)));
    }
    Ok(Ok(sign_after_invocation_validation(req, Some(limits))?))
}

fn sign_inner(req: &SignRequest<'_>) -> SignOutcome {
    if let Err(e) = validate_invocation(req) {
        return SignOutcome::Invocation(e);
    }
    sign_after_invocation_validation(req, None)
        .expect("the unbounded signing path cannot return a resource error")
}

fn sign_after_invocation_validation(
    req: &SignRequest<'_>,
    limits: Option<&ArtifactResourceLimits>,
) -> ArtifactResourceResult<SignOutcome> {
    // Only YAML output applies the YAML envelope rules: valid UTF-8, no BOM,
    // and a final line terminator. Protobuf payloads are opaque bytes and must
    // bypass both normalization and validation.
    let payload = match req.output_form {
        OutputForm::Yaml => {
            let payload =
                match normalize_yaml_payload(req.payload, req.append_missing_final_newline) {
                    Ok(p) => p,
                    Err(e) => return Ok(SignOutcome::Signer(e)),
                };
            if validate_payload_stream(&payload).is_err() {
                return Ok(SignOutcome::Signer(SignError::InvalidPayloadBytes));
            }
            payload
        }
        OutputForm::Protobuf => req.payload.to_vec(),
    };

    let modified_payload = if req.payload == payload.as_slice() {
        Vec::new()
    } else {
        payload.clone()
    };

    let sig_bytes = match sign_digest(&payload, req.algorithm, &req.key) {
        Ok(b) => b,
        Err(e) => return Ok(SignOutcome::Signer(e)),
    };

    let artifact = match req.output_form {
        OutputForm::Yaml => {
            let emitted = if let Some(limits) = limits {
                emit_yaml_artifact_with_resource_limits(&payload, req, &sig_bytes, limits)?
            } else {
                emit_yaml_artifact(&payload, req, &sig_bytes)
            };
            match emitted {
                Ok(artifact) => artifact,
                Err(error) => return Ok(SignOutcome::Signer(error)),
            }
        }
        OutputForm::Protobuf => match emit_proto_artifact(&payload, req, &sig_bytes) {
            Ok(a) => a,
            Err(e) => return Ok(SignOutcome::Signer(e)),
        },
    };

    Ok(SignOutcome::Success(SignSuccess {
        artifact,
        modified_payload,
    }))
}

fn emit_yaml_artifact(
    payload: &[u8],
    req: &SignRequest<'_>,
    sig_bytes: &[u8],
) -> Result<Vec<u8>, SignError> {
    let body = serialize_yaml_signature_carrier(req, sig_bytes)?;

    match yaml_sigil_transcription::compose(&yaml_sigil_transcription::ComposeRequest {
        payload,
        signature_carrier: body.as_bytes(),
        form: yaml_sigil_transcription::TranscriptionForm::Yaml,
    }) {
        yaml_sigil_transcription::ComposeOutcome::Success(s) => Ok(s.artifact),
        yaml_sigil_transcription::ComposeOutcome::Invocation(_)
        | yaml_sigil_transcription::ComposeOutcome::Error(_) => {
            Err(SignError::YamlSerialize("compose failed".into()))
        }
    }
}

fn serialize_yaml_signature_carrier(
    req: &SignRequest<'_>,
    sig_bytes: &[u8],
) -> Result<String, SignError> {
    let doc = SignatureDocument {
        schema: yaml_sigil_core::SCHEMA_V1ALPHA1.to_string(),
        alg: req.algorithm.as_yaml_str().to_string(),
        keyid: req.keyid.map(|s| s.to_string()),
        signature: base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            sig_bytes,
        ),
    };

    let mut body = yaml_sigil_core::serialize_signature_document(&doc)
        .map_err(|e| SignError::YamlSerialize(e.to_string()))?;
    if !body.ends_with('\n') {
        body.push('\n');
    }
    Ok(body)
}

fn emit_yaml_artifact_with_resource_limits(
    payload: &[u8],
    req: &SignRequest<'_>,
    sig_bytes: &[u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, SignError>> {
    let body = match serialize_yaml_signature_carrier(req, sig_bytes) {
        Ok(body) => body,
        Err(error) => return Ok(Err(error)),
    };

    let encoded_size = payload
        .len()
        .checked_add(4)
        .and_then(|size| size.checked_add(body.len()))
        .ok_or_else(|| limits.size_computation_overflow(ArtifactResourceForm::Yaml))?;
    limits.check_output_size(ArtifactResourceForm::Yaml, encoded_size)?;

    let outcome = yaml_sigil_transcription::compose(&yaml_sigil_transcription::ComposeRequest {
        payload,
        signature_carrier: body.as_bytes(),
        form: yaml_sigil_transcription::TranscriptionForm::Yaml,
    });
    match outcome {
        yaml_sigil_transcription::ComposeOutcome::Success(s) => {
            debug_assert_eq!(s.artifact.len(), encoded_size);
            Ok(Ok(s.artifact))
        }
        yaml_sigil_transcription::ComposeOutcome::Invocation(_)
        | yaml_sigil_transcription::ComposeOutcome::Error(_) => {
            Ok(Err(SignError::YamlSerialize("compose failed".into())))
        }
    }
}

fn emit_proto_artifact(
    payload: &[u8],
    req: &SignRequest<'_>,
    sig_bytes: &[u8],
) -> Result<Vec<u8>, SignError> {
    let carrier = proto_carrier::encode_inner_signature_carrier(
        req.algorithm,
        sig_bytes.to_vec(),
        req.keyid.map(|s| s.to_string()),
    );
    Ok(yaml_sigil_core::compose_proto_outer(payload, &carrier))
}

/// Sign with YAML output through [`sign`].
///
/// This wrapper has the resource behavior documented on [`sign`].
#[instrument(level = "info", skip(params), fields(alg = ?params.algorithm))]
pub fn sign_yaml(params: &SignYamlParams<'_>) -> Result<Vec<u8>, SignError> {
    let req = SignRequest {
        payload: params.payload,
        algorithm: params.algorithm,
        key: params.key,
        keyid: params.keyid,
        append_missing_final_newline: params.append_missing_final_newline,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    match sign_inner(&req) {
        SignOutcome::Success(s) => Ok(s.artifact),
        SignOutcome::Invocation(e) => Err(map_invocation_to_sign_error(e)),
        SignOutcome::Signer(e) => Err(e),
    }
}

/// Sign with YAML output after applying an explicit output policy.
pub fn sign_yaml_with_resource_limits(
    params: &SignYamlParams<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, SignError>> {
    let request = SignRequest {
        payload: params.payload,
        algorithm: params.algorithm,
        key: params.key,
        keyid: params.keyid,
        append_missing_final_newline: params.append_missing_final_newline,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };
    if let Err(error) = validate_invocation_shape(&request) {
        return Ok(Err(map_invocation_to_sign_error(error)));
    }
    checked_yaml_signing_lower_bound(&request, limits)?;
    if let Err(error) = validate_keyid_content(&request) {
        return Ok(Err(map_invocation_to_sign_error(error)));
    }
    let outcome = sign_after_invocation_validation(&request, Some(limits))?;
    Ok(match outcome {
        SignOutcome::Success(success) => Ok(success.artifact),
        SignOutcome::Invocation(error) => Err(map_invocation_to_sign_error(error)),
        SignOutcome::Signer(error) => Err(error),
    })
}

/// Sign with protobuf output through [`sign`].
///
/// This wrapper has the resource behavior documented on [`sign`].
#[instrument(level = "info", skip(params), fields(alg = ?params.algorithm))]
pub fn sign_proto(params: &SignProtoParams<'_>) -> Result<Vec<u8>, SignError> {
    let req = SignRequest {
        payload: params.payload,
        algorithm: params.algorithm,
        key: params.key,
        keyid: params.keyid,
        append_missing_final_newline: params.append_missing_final_newline,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &[],
    };
    match sign(&req) {
        SignOutcome::Success(s) => Ok(s.artifact),
        SignOutcome::Invocation(e) => Err(map_invocation_to_sign_error(e)),
        SignOutcome::Signer(e) => Err(e),
    }
}

/// Sign with protobuf output after applying an explicit output policy.
///
/// The outer result reports resource rejection, the next result preserves a
/// protobuf format error, and the innermost result preserves [`SignError`].
pub fn sign_proto_with_resource_limits(
    params: &SignProtoParams<'_>,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Result<Vec<u8>, SignError>, EncodeError>> {
    let request = SignRequest {
        payload: params.payload,
        algorithm: params.algorithm,
        key: params.key,
        keyid: params.keyid,
        append_missing_final_newline: params.append_missing_final_newline,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &[],
    };
    let outcome = match sign_with_resource_limits(&request, limits)? {
        Ok(outcome) => outcome,
        Err(error) => return Ok(Err(error)),
    };
    Ok(Ok(match outcome {
        SignOutcome::Success(success) => Ok(success.artifact),
        SignOutcome::Invocation(error) => Err(map_invocation_to_sign_error(error)),
        SignOutcome::Signer(error) => Err(error),
    }))
}

fn map_invocation_to_sign_error(e: SignInvocationError) -> SignError {
    match e {
        SignInvocationError::InvalidOrUnsupportedAlgorithm => {
            SignError::InvalidOrUnsupportedAlgorithm
        }
        SignInvocationError::InvalidAlgorithmParameters => SignError::InvalidAlgorithmParameters,
        SignInvocationError::InvalidOrUnsupportedOutputForm => {
            SignError::InvalidOrUnsupportedOutputForm
        }
        SignInvocationError::InvalidKeyid => SignError::InvalidKeyid,
    }
}

fn sign_digest(
    payload: &[u8],
    algorithm: AlgorithmId,
    key: &SigningKey<'_>,
) -> Result<Vec<u8>, SignError> {
    match (algorithm, key) {
        (AlgorithmId::Ed25519, SigningKey::Ed25519(sk)) => {
            use ed25519_dalek::Signer;
            Ok(sk.sign(payload).to_bytes().to_vec())
        }
        (AlgorithmId::EcdsaP256Sha256, SigningKey::EcdsaP256Sha256(sk)) => {
            use p256::ecdsa::signature::Signer;
            let sig: p256::ecdsa::Signature = sk
                .try_sign(payload)
                .map_err(|_| SignError::KeyOperationFailure)?;
            // Raw R || S 64 octets.
            Ok(sig.to_bytes().to_vec())
        }
        _ => Err(SignError::InvalidOrUnsupportedAlgorithm),
    }
}

/// In-process default signer that delegates to the crate's free functions.
///
/// This unit type retains the unbounded resource behavior of [`sign`]. Use the
/// resource-aware free functions when you need the shared policy.
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultSigner;

impl Signer for DefaultSigner {
    type Ed25519SigningKey = ed25519_dalek::SigningKey;
    type P256SigningKey = p256::ecdsa::SigningKey;

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }
    fn sign(&self, req: &SignRequest<'_>) -> SignOutcome {
        sign(req)
    }
}

/// In-process default async signer that delegates to the crate's free functions.
///
/// The body is `async { sign(req) }` — no `tokio::spawn_blocking`. The signing
/// path is CPU-bound, deterministic, and short; offloading to a blocking pool
/// would add latency without protecting any meaningful reactor.
///
/// This unit type retains the unconfigured resource behavior of [`sign`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAsyncSigner;

impl AsyncSigner for DefaultAsyncSigner {
    type Ed25519SigningKey = ed25519_dalek::SigningKey;
    type P256SigningKey = p256::ecdsa::SigningKey;

    fn capabilities(&self) -> SignerCapabilities {
        signer_capabilities()
    }
    async fn sign(&self, req: &SignRequest<'_>) -> SignOutcome {
        sign(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey as EdSk;

    fn finite(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(maximum).unwrap())
    }

    #[test]
    fn signer_capabilities_lists_two_algorithms() {
        let c = signer_capabilities();
        assert_eq!(c.supported_algorithms.len(), 2);
        assert_eq!(c.supported_output_forms.len(), 2);
        assert!(!c.best_effort_yaml_validation);
        assert_eq!(
            c.protobuf_wire_decode,
            yaml_sigil_core::ProtobufWireDecodeAdvertisement::UnprofiledStockDecoder
        );
        assert_eq!(
            c.yaml_signature_duplicate_key_policy,
            yaml_sigil_core::YamlSignatureDocumentDuplicateKeyPolicy::RejectedAtParse
        );
        assert_eq!(
            c.yaml_signature_unknown_field_policy,
            yaml_sigil_core::YamlSignatureDocumentUnknownFieldPolicy::RejectedAtParse
        );
    }

    // The concrete RustCrypto bindings must remain expressible on a
    // synchronous trait object.
    #[test]
    fn default_signer_supports_a_trait_object_with_explicit_bindings() {
        let signer: &dyn Signer<
            Ed25519SigningKey = ed25519_dalek::SigningKey,
            P256SigningKey = p256::ecdsa::SigningKey,
        > = &DefaultSigner;
        assert_eq!(signer.capabilities(), signer_capabilities());
    }

    #[test]
    fn signer_rejects_line_break_in_keyid() {
        let sk = EdSk::from_bytes(&[5u8; 32]);
        for keyid in ["kid\nsuffix", "kid\rsuffix"] {
            let req = SignRequest {
                payload: b"a: b\n",
                algorithm: AlgorithmId::Ed25519,
                key: SigningKey::Ed25519(&sk),
                keyid: Some(keyid),
                append_missing_final_newline: false,
                output_form: OutputForm::Yaml,
                algorithm_parameters: &[],
            };
            assert!(matches!(
                sign(&req),
                SignOutcome::Invocation(SignInvocationError::InvalidKeyid)
            ));
        }
    }

    #[test]
    fn bounded_signing_preserves_request_shape_precedence() {
        let sk = EdSk::from_bytes(&[8u8; 32]);
        let request = SignRequest {
            payload: &[0xff; 16],
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[1],
        };
        assert!(matches!(
            sign_with_resource_limits(&request, &finite(1))
                .unwrap()
                .unwrap(),
            SignOutcome::Invocation(SignInvocationError::InvalidAlgorithmParameters)
        ));
    }

    #[test]
    fn bounded_signing_defers_keyid_content_and_payload_validation() {
        let sk = EdSk::from_bytes(&[9u8; 32]);
        for output_form in [OutputForm::Yaml, OutputForm::Protobuf] {
            let request = SignRequest {
                payload: &[0xff; 16],
                algorithm: AlgorithmId::Ed25519,
                key: SigningKey::Ed25519(&sk),
                keyid: Some("line\nbreak"),
                append_missing_final_newline: false,
                output_form,
                algorithm_parameters: &[],
            };
            let error = sign_with_resource_limits(&request, &finite(1)).unwrap_err();
            assert_eq!(
                error.kind(),
                ArtifactResourceErrorKind::OutputArtifactTooLarge
            );
            assert_eq!(
                error.artifact_form(),
                Some(match output_form {
                    OutputForm::Yaml => ArtifactResourceForm::Yaml,
                    OutputForm::Protobuf => ArtifactResourceForm::Protobuf,
                })
            );
            assert_eq!(
                error.observed_or_projected_artifact_bytes(),
                match output_form {
                    OutputForm::Yaml => None,
                    OutputForm::Protobuf => Some(
                        checked_proto_signing_size(&request, &ArtifactResourceLimits::unbounded(),)
                            .unwrap()
                            .unwrap(),
                    ),
                }
            );

            assert!(matches!(
                sign_with_resource_limits(&request, &ArtifactResourceLimits::unbounded())
                    .unwrap()
                    .unwrap(),
                SignOutcome::Invocation(SignInvocationError::InvalidKeyid)
            ));
        }
    }

    #[test]
    fn protobuf_signing_projection_matches_emission_at_varint_boundaries() {
        let sk = EdSk::from_bytes(&[10u8; 32]);
        for payload_len in [0, 1, 127, 128, 16_383, 16_384] {
            let payload = vec![0xa5; payload_len];
            for keyid in [None, Some("key")] {
                let request = SignRequest {
                    payload: &payload,
                    algorithm: AlgorithmId::Ed25519,
                    key: SigningKey::Ed25519(&sk),
                    keyid,
                    append_missing_final_newline: false,
                    output_form: OutputForm::Protobuf,
                    algorithm_parameters: &[],
                };
                let projected =
                    checked_proto_signing_size(&request, &ArtifactResourceLimits::unbounded())
                        .unwrap()
                        .unwrap();
                let outcome = sign_with_resource_limits(&request, &finite(projected))
                    .unwrap()
                    .unwrap();
                let artifact = match outcome {
                    SignOutcome::Success(success) => success.artifact,
                    other => panic!("{other:?}"),
                };
                assert_eq!(artifact.len(), projected);
            }
        }

        let p256_key = p256::ecdsa::SigningKey::from_slice(&[13u8; 32]).unwrap();
        for payload_len in [0, 127, 128] {
            let payload = vec![0x5a; payload_len];
            let request = SignRequest {
                payload: &payload,
                algorithm: AlgorithmId::EcdsaP256Sha256,
                key: SigningKey::EcdsaP256Sha256(&p256_key),
                keyid: Some("p256-key"),
                append_missing_final_newline: false,
                output_form: OutputForm::Protobuf,
                algorithm_parameters: &[],
            };
            let projected =
                checked_proto_signing_size(&request, &ArtifactResourceLimits::unbounded())
                    .unwrap()
                    .unwrap();
            let outcome = sign_with_resource_limits(&request, &finite(projected))
                .unwrap()
                .unwrap();
            let artifact = match outcome {
                SignOutcome::Success(success) => success.artifact,
                other => panic!("{other:?}"),
            };
            assert_eq!(artifact.len(), projected);
        }
    }

    #[test]
    fn protobuf_signing_preserves_resource_then_format_precedence() {
        let payload_len = u64::try_from(i32::MAX).unwrap();
        let resource_error =
            checked_proto_signing_size_from_lengths(payload_len, None, &finite(1)).unwrap_err();
        assert_eq!(
            resource_error.kind(),
            ArtifactResourceErrorKind::OutputArtifactTooLarge
        );

        let format_error = checked_proto_signing_size_from_lengths(
            payload_len,
            None,
            &ArtifactResourceLimits::unbounded(),
        )
        .unwrap()
        .unwrap_err();
        assert_eq!(
            format_error.kind(),
            yaml_sigil_core::pb::EncodeErrorKind::MessageTooLarge
        );
    }

    #[test]
    fn protobuf_signing_reports_exact_output_rejection() {
        let sk = EdSk::from_bytes(&[11u8; 32]);
        let params = SignProtoParams {
            payload: b"opaque payload",
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: Some("key"),
            append_missing_final_newline: false,
        };
        let artifact = sign_proto(&params).unwrap();
        assert!(
            sign_proto_with_resource_limits(&params, &finite(artifact.len()))
                .unwrap()
                .unwrap()
                .is_ok()
        );
        let error =
            sign_proto_with_resource_limits(&params, &finite(artifact.len() - 1)).unwrap_err();
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::OutputArtifactTooLarge
        );
        assert_eq!(
            error.observed_or_projected_artifact_bytes(),
            Some(artifact.len())
        );
    }

    #[test]
    fn yaml_signing_uses_lower_bound_then_final_exact_size() {
        let sk = EdSk::from_bytes(&[12u8; 32]);
        let request = SignRequest {
            payload: b"key: value",
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: Some("quoted\"key"),
            append_missing_final_newline: true,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let minimum =
            checked_yaml_signing_lower_bound(&request, &ArtifactResourceLimits::unbounded())
                .unwrap();
        let artifact = match sign(&request) {
            SignOutcome::Success(success) => success.artifact,
            other => panic!("{other:?}"),
        };
        assert!(minimum < artifact.len());
        assert!(artifact.starts_with(b"key: value\n---\n"));

        let early = sign_with_resource_limits(&request, &finite(minimum - 1)).unwrap_err();
        assert_eq!(early.observed_or_projected_artifact_bytes(), None);

        let exact = sign_with_resource_limits(&request, &finite(artifact.len() - 1)).unwrap_err();
        assert_eq!(
            exact.observed_or_projected_artifact_bytes(),
            Some(artifact.len())
        );
        assert!(matches!(
            sign_with_resource_limits(&request, &finite(artifact.len()))
                .unwrap()
                .unwrap(),
            SignOutcome::Success(_)
        ));

        let params = SignYamlParams {
            payload: request.payload,
            algorithm: request.algorithm,
            key: request.key,
            keyid: request.keyid,
            append_missing_final_newline: request.append_missing_final_newline,
        };
        assert_eq!(
            sign_yaml_with_resource_limits(&params, &finite(artifact.len()))
                .unwrap()
                .unwrap(),
            artifact
        );
    }

    #[test]
    fn default_signer_matches_free_function() {
        let sk = EdSk::from_bytes(&[5u8; 32]);
        let payload = b"a: b\n";
        let req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: Some("kid-d"),
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let direct = match sign(&req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via free fn"),
        };
        let via_trait = match Signer::sign(&DefaultSigner, &req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via trait"),
        };
        assert_eq!(direct, via_trait);
        assert_eq!(
            DefaultSigner.capabilities().supported_algorithms.len(),
            signer_capabilities().supported_algorithms.len()
        );
    }

    #[test]
    fn unified_sign_matches_wrappers() {
        let sk = EdSk::from_bytes(&[3u8; 32]);
        let payload = b"x: y\n";
        let yaml_req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let proto_req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
            output_form: OutputForm::Protobuf,
            algorithm_parameters: &[],
        };
        let y1 = sign_yaml(&SignYamlParams {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
        })
        .unwrap();
        let y2 = match sign(&yaml_req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success"),
        };
        assert_eq!(y1, y2);
        let p1 = sign_proto(&SignProtoParams {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline: false,
        })
        .unwrap();
        let p2 = match sign(&proto_req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success"),
        };
        assert_eq!(p1, p2);
    }

    #[tokio::test]
    async fn default_async_signer_matches_free_function() {
        let sk = EdSk::from_bytes(&[5u8; 32]);
        let payload = b"a: b\n";
        let req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: Some("kid-d"),
            append_missing_final_newline: false,
            output_form: OutputForm::Yaml,
            algorithm_parameters: &[],
        };
        let direct = match sign(&req) {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via free fn"),
        };
        let via_async_trait = match AsyncSigner::sign(&DefaultAsyncSigner, &req).await {
            SignOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via async trait"),
        };
        assert_eq!(direct, via_async_trait);
        assert_eq!(
            AsyncSigner::capabilities(&DefaultAsyncSigner)
                .supported_algorithms
                .len(),
            signer_capabilities().supported_algorithms.len()
        );
    }
}
