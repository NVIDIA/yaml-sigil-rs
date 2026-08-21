// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YamlSigil v1alpha1 signing: YAML + protobuf artifacts, Ed25519 + ECDSA P-256 SHA-256.
//! Signed-artifact transcoding lives in [`transcription`].
//!
//! Request-shape failures are [`SignInvocationError`]; sign-time failures are
//! [`SignError`], plus output-path extensions (`YamlSerialize` only; protobuf
//! encode is infallible here).
//!
//! Convenience wrappers [`sign_yaml`] and [`sign_proto`] call [`sign`] with a fixed [`OutputForm`].

mod proto_carrier;
pub mod transcription;

pub use transcription::{
    TranscodeError, proto_wire_to_signed_yaml_stream, signed_yaml_stream_to_proto_wire,
};

use tracing::instrument;
use yaml_sigil_core::{SignatureDocument, validate_payload_stream};
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

fn validate_invocation(req: &SignRequest<'_>) -> Result<(), SignInvocationError> {
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
        if octets == 0 || octets > 1024 || keyid.contains(['\r', '\n']) {
            return Err(SignInvocationError::InvalidKeyid);
        }
    }
    match (&req.algorithm, &req.key) {
        (AlgorithmId::Ed25519, SigningKey::Ed25519(_)) => Ok(()),
        (AlgorithmId::EcdsaP256Sha256, SigningKey::EcdsaP256Sha256(_)) => Ok(()),
        _ => Err(SignInvocationError::InvalidOrUnsupportedAlgorithm),
    }
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

/// Unified signing entry point corresponding to the IDL `Sign` operation.
///
/// For protobuf output, `append_missing_final_newline` is
/// ignored and the payload bytes are signed and emitted without modification.
#[instrument(level = "info", skip(req), fields(alg = ?req.algorithm, form = ?req.output_form))]
pub fn sign(req: &SignRequest<'_>) -> SignOutcome {
    sign_inner(req)
}

fn sign_inner(req: &SignRequest<'_>) -> SignOutcome {
    if let Err(e) = validate_invocation(req) {
        return SignOutcome::Invocation(e);
    }

    // Only YAML output applies the YAML envelope rules: valid UTF-8, no BOM,
    // and a final line terminator. Protobuf payloads are opaque bytes and must
    // bypass both normalization and validation.
    let payload = match req.output_form {
        OutputForm::Yaml => {
            let payload =
                match normalize_yaml_payload(req.payload, req.append_missing_final_newline) {
                    Ok(p) => p,
                    Err(e) => return SignOutcome::Signer(e),
                };
            if validate_payload_stream(&payload).is_err() {
                return SignOutcome::Signer(SignError::InvalidPayloadBytes);
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
        Err(e) => return SignOutcome::Signer(e),
    };

    let artifact = match req.output_form {
        OutputForm::Yaml => match emit_yaml_artifact(&payload, req, &sig_bytes) {
            Ok(a) => a,
            Err(e) => return SignOutcome::Signer(e),
        },
        OutputForm::Protobuf => match emit_proto_artifact(&payload, req, &sig_bytes) {
            Ok(a) => a,
            Err(e) => return SignOutcome::Signer(e),
        },
    };

    SignOutcome::Success(SignSuccess {
        artifact,
        modified_payload,
    })
}

fn emit_yaml_artifact(
    payload: &[u8],
    req: &SignRequest<'_>,
    sig_bytes: &[u8],
) -> Result<Vec<u8>, SignError> {
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

/// Convenience: sign with YAML output (thin wrapper over [`sign`]).
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

/// Convenience: sign with protobuf output (thin wrapper over [`sign`]).
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
