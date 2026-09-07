// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Signed-artifact transcoding via the Transcription API (Decompose → metadata → Compose).
//!
//! Empty decoded signature octets pass through here: rejection is the
//! verifier's verification-stage responsibility (`MalformedAttemptedSigned`),
//! not metadata extraction.
//!
//! # Resource boundaries
//!
//! The `_with_resource_limits` variants check the complete source before
//! parsing and check the destination independently before complete-output
//! allocation. Existing functions retain their unbounded behavior. Resource
//! policy is operational hardening and does not determine YamlSigil `v1alpha1`
//! conformance.
//!
//! ```no_run
//! use yaml_sigil_signing::{
//!     ArtifactResourceLimits,
//!     signed_yaml_stream_to_proto_wire_with_resource_limits,
//! };
//!
//! # fn transcode(yaml: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//! let limits = ArtifactResourceLimits::default();
//! let protobuf =
//!     signed_yaml_stream_to_proto_wire_with_resource_limits(yaml, &limits)???;
//! // Source and destination are each compared with the ceiling. Their byte
//! // lengths are not added together.
//! Ok(protobuf)
//! # }
//! ```

use base64::Engine;
use thiserror::Error;
use tracing::instrument;
use yaml_sigil_core::{
    ArtifactResourceForm, ArtifactResourceLimits, ArtifactResourceResult, SCHEMA_V1ALPHA1,
    SignatureDocument, compose_proto_outer, compose_proto_outer_with_resource_limits,
    parse_signature_document, pb::EncodeError, serialize_signature_document,
    validate_payload_stream, view_signature_carrier,
};
use yaml_sigil_traits::{AlgorithmId, OuterConformance};
use yaml_sigil_transcription::{
    ComposeOutcome, ComposeRequest, DecomposeOutcome, DecomposeRequest, TranscriptionForm, compose,
    decompose,
};

/// Failure to transcode between signed YAML stream bytes and protobuf wire.
#[derive(Debug, Error)]
pub enum TranscodeError {
    #[error("artifact is not a well-formed signed YAML stream")]
    NotSignedYamlStream,
    #[error("payload invariant violation")]
    PayloadInvariant,
    #[error("invalid base64 in YAML signature field")]
    InvalidSignatureBase64,
    #[error("unknown or unsupported YAML `alg` value")]
    UnknownYamlAlg,
    #[error("unsupported algorithm wire value")]
    UnsupportedWireAlg,
    #[error("YAML signature document schema mismatch")]
    SchemaMismatch,
    #[error(transparent)]
    Core(#[from] yaml_sigil_core::error::CoreError),
    #[error("YAML serialization failed: {0}")]
    YamlSerialize(String),
}

fn yaml_decompose(yaml_artifact: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TranscodeError> {
    let resp = decompose(&DecomposeRequest {
        artifact: yaml_artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let structural = match resp {
        yaml_sigil_transcription::DecomposeResponse::Structural(s) => s,
        yaml_sigil_transcription::DecomposeResponse::Invocation(_) => {
            return Err(TranscodeError::NotSignedYamlStream);
        }
    };
    if structural.outcome != DecomposeOutcome::Ok {
        return Err(TranscodeError::NotSignedYamlStream);
    }
    Ok((
        structural
            .payload
            .ok_or(TranscodeError::NotSignedYamlStream)?,
        structural
            .signature_carrier
            .ok_or(TranscodeError::NotSignedYamlStream)?,
    ))
}

fn proto_decompose(wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TranscodeError> {
    let resp = decompose(&DecomposeRequest {
        artifact: wire,
        form: TranscriptionForm::Protobuf,
        outer_conformance: Some(OuterConformance::SignatureStrict),
    });
    let structural = match resp {
        yaml_sigil_transcription::DecomposeResponse::Structural(s) => s,
        yaml_sigil_transcription::DecomposeResponse::Invocation(_) => {
            return Err(TranscodeError::NotSignedYamlStream);
        }
    };
    if structural.outcome != DecomposeOutcome::Ok {
        return Err(TranscodeError::NotSignedYamlStream);
    }
    Ok((
        structural
            .payload
            .ok_or(TranscodeError::NotSignedYamlStream)?,
        structural
            .signature_carrier
            .ok_or(TranscodeError::NotSignedYamlStream)?,
    ))
}

/// Convert a signed YAML artifact into protobuf `SignedYamlArtifact` wire bytes.
///
/// This function has the resource behavior documented on this module.
#[instrument(level = "debug", skip(yaml_artifact), fields(len = yaml_artifact.len()))]
pub fn signed_yaml_stream_to_proto_wire(yaml_artifact: &[u8]) -> Result<Vec<u8>, TranscodeError> {
    let (payload, inner_carrier) = yaml_to_proto_components(yaml_artifact)?;
    Ok(compose_proto_outer(&payload, &inner_carrier))
}

fn yaml_to_proto_components(yaml_artifact: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TranscodeError> {
    let (payload, carrier) = yaml_decompose(yaml_artifact)?;
    validate_payload_stream(&payload).map_err(|_| TranscodeError::PayloadInvariant)?;

    let doc = parse_signature_document(&carrier)?;
    doc.validate_schema()
        .map_err(|_| TranscodeError::SchemaMismatch)?;

    let sig_octets = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(doc.signature.as_bytes())
        .map_err(|_| TranscodeError::InvalidSignatureBase64)?;

    let alg_id = AlgorithmId::from_yaml_str(&doc.alg).ok_or(TranscodeError::UnknownYamlAlg)?;

    let inner_carrier =
        crate::proto_carrier::encode_inner_signature_carrier(alg_id, sig_octets, doc.keyid);

    Ok((payload, inner_carrier))
}

/// Convert signed YAML to protobuf with independent source and destination checks.
///
/// The outer result reports resource rejection, the next result preserves a
/// protobuf format error, and the innermost result preserves [`TranscodeError`].
#[instrument(level = "debug", skip(yaml_artifact, limits), fields(len = yaml_artifact.len()))]
pub fn signed_yaml_stream_to_proto_wire_with_resource_limits(
    yaml_artifact: &[u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Result<Vec<u8>, TranscodeError>, EncodeError>> {
    limits.check_input_size(ArtifactResourceForm::Yaml, yaml_artifact)?;
    let (payload, inner_carrier) = match yaml_to_proto_components(yaml_artifact) {
        Ok(components) => components,
        Err(error) => return Ok(Ok(Err(error))),
    };
    let artifact = match compose_proto_outer_with_resource_limits(&payload, &inner_carrier, limits)?
    {
        Ok(artifact) => artifact,
        Err(error) => return Ok(Err(error)),
    };
    Ok(Ok(Ok(artifact)))
}

/// Convert protobuf wire bytes into a signed YAML artifact stream.
///
/// # Resource usage
///
/// This function adds no implementation-local complete-artifact limit.
/// Protobuf decomposition copies recognized fields into owned buffers, and
/// conversion constructs an owned YAML stream. Work and allocation are linear
/// in field and output size. Use
/// [`proto_wire_to_signed_yaml_stream_with_resource_limits`] to check both
/// complete artifacts.
#[instrument(level = "debug", skip(wire), fields(len = wire.len()))]
pub fn proto_wire_to_signed_yaml_stream(wire: &[u8]) -> Result<Vec<u8>, TranscodeError> {
    let (payload, body) = proto_to_yaml_components(wire)?;

    match compose(&ComposeRequest {
        payload: &payload,
        signature_carrier: body.as_bytes(),
        form: TranscriptionForm::Yaml,
    }) {
        ComposeOutcome::Success(s) => Ok(s.artifact),
        ComposeOutcome::Invocation(_) | ComposeOutcome::Error(_) => {
            Err(TranscodeError::NotSignedYamlStream)
        }
    }
}

fn proto_to_yaml_components(wire: &[u8]) -> Result<(Vec<u8>, String), TranscodeError> {
    let (payload, carrier) = proto_decompose(wire)?;
    validate_payload_stream(&payload).map_err(|_| TranscodeError::PayloadInvariant)?;

    let view = view_signature_carrier(&carrier)?;

    let alg = AlgorithmId::from_i32(view.alg_wire).ok_or(TranscodeError::UnsupportedWireAlg)?;

    let doc = SignatureDocument {
        schema: SCHEMA_V1ALPHA1.to_string(),
        alg: alg.as_yaml_str().to_string(),
        keyid: view.keyid,
        signature: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&view.signature),
    };

    let mut body = serialize_signature_document(&doc)
        .map_err(|e| TranscodeError::YamlSerialize(e.to_string()))?;
    if !body.ends_with('\n') {
        body.push('\n');
    }

    Ok((payload, body))
}

/// Convert protobuf to signed YAML with independent source and destination checks.
#[instrument(level = "debug", skip(wire, limits), fields(len = wire.len()))]
pub fn proto_wire_to_signed_yaml_stream_with_resource_limits(
    wire: &[u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, TranscodeError>> {
    limits.check_input_size(ArtifactResourceForm::Protobuf, wire)?;
    let (payload, body) = match proto_to_yaml_components(wire) {
        Ok(components) => components,
        Err(error) => return Ok(Err(error)),
    };
    let encoded_size = payload
        .len()
        .checked_add(4)
        .and_then(|size| size.checked_add(body.len()))
        .ok_or_else(|| limits.size_computation_overflow(ArtifactResourceForm::Yaml))?;
    limits.check_output_size(ArtifactResourceForm::Yaml, encoded_size)?;
    let outcome = compose(&ComposeRequest {
        payload: &payload,
        signature_carrier: body.as_bytes(),
        form: TranscriptionForm::Yaml,
    });
    Ok(match outcome {
        ComposeOutcome::Success(success) => {
            debug_assert_eq!(success.artifact.len(), encoded_size);
            Ok(success.artifact)
        }
        ComposeOutcome::Invocation(_) | ComposeOutcome::Error(_) => {
            Err(TranscodeError::NotSignedYamlStream)
        }
    })
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;

    use super::{
        TranscodeError, proto_wire_to_signed_yaml_stream,
        proto_wire_to_signed_yaml_stream_with_resource_limits, signed_yaml_stream_to_proto_wire,
        signed_yaml_stream_to_proto_wire_with_resource_limits,
    };
    use crate::{SignYamlParams, SigningKey, sign_yaml};
    use yaml_sigil_core::{
        AlgorithmId, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
        compose_proto_outer, decode_signed_yaml_artifact, view_signed_yaml_artifact,
    };

    fn finite(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(maximum).unwrap())
    }

    fn add_signature_whitespace(artifact: &[u8]) -> Vec<u8> {
        let text = std::str::from_utf8(artifact).expect("signer emits UTF-8 YAML");
        let marker = "signature: ";
        let value_start = text.rfind(marker).expect("signature field") + marker.len();
        let value_end = value_start
            + text[value_start..]
                .find('\n')
                .expect("signature line terminator");
        let mut mutated = String::with_capacity(text.len() + 4);
        mutated.push_str(&text[..value_start]);
        mutated.push_str("\" ");
        mutated.push_str(&text[value_start..value_end]);
        mutated.push_str(" \"");
        mutated.push_str(&text[value_end..]);
        mutated.into_bytes()
    }

    fn assert_proto_yaml_proto_signature(signature_b64: &str, expected_yaml_line: &str) {
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature_b64)
            .expect("test signature is canonical base64url");
        let carrier = crate::proto_carrier::encode_inner_signature_carrier(
            AlgorithmId::Ed25519,
            signature.clone(),
            None,
        );
        let wire = compose_proto_outer(b"review: scalar\n", &carrier);

        let yaml = proto_wire_to_signed_yaml_stream(&wire).expect("transcode protobuf to YAML");
        let yaml_text = std::str::from_utf8(&yaml).expect("transcoder emits UTF-8 YAML");
        assert!(
            yaml_text.ends_with(expected_yaml_line),
            "unexpected YAML artifact: {yaml_text:?}"
        );

        let round_trip =
            signed_yaml_stream_to_proto_wire(&yaml).expect("transcode YAML back to protobuf");
        let decoded = decode_signed_yaml_artifact(&round_trip).expect("decode protobuf artifact");
        let view = view_signed_yaml_artifact(&decoded).expect("view protobuf artifact");
        assert_eq!(view.payload, b"review: scalar\n");
        assert_eq!(view.signature, signature);
    }

    #[test]
    fn yaml_to_proto_rejects_signature_whitespace() {
        let signing_key = Ed25519SigningKey::from_bytes(&[55_u8; 32]);
        let artifact = sign_yaml(&SignYamlParams {
            payload: b"review: cyber55\n",
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&signing_key),
            keyid: None,
            append_missing_final_newline: false,
        })
        .expect("sign baseline artifact");
        let mutated = add_signature_whitespace(&artifact);

        assert!(matches!(
            signed_yaml_stream_to_proto_wire(&mutated),
            Err(TranscodeError::InvalidSignatureBase64)
        ));
    }

    #[test]
    fn transcoding_checks_source_and_destination_independently() {
        let signing_key = Ed25519SigningKey::from_bytes(&[56_u8; 32]);
        let yaml = sign_yaml(&SignYamlParams {
            payload: b"review: boundaries\n",
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&signing_key),
            keyid: Some("key"),
            append_missing_final_newline: false,
        })
        .unwrap();
        let proto = signed_yaml_stream_to_proto_wire(&yaml).unwrap();
        assert!(proto.len() < yaml.len());

        let input_error =
            signed_yaml_stream_to_proto_wire_with_resource_limits(&yaml, &finite(yaml.len() - 1))
                .unwrap_err();
        assert_eq!(
            input_error.kind(),
            ArtifactResourceErrorKind::InputArtifactTooLarge
        );
        assert_eq!(
            input_error.artifact_form(),
            Some(ArtifactResourceForm::Yaml)
        );

        let yaml_to_proto =
            signed_yaml_stream_to_proto_wire_with_resource_limits(&yaml, &finite(yaml.len()))
                .unwrap()
                .unwrap()
                .unwrap();
        assert_eq!(yaml_to_proto, proto);

        let yaml_again = proto_wire_to_signed_yaml_stream(&proto).unwrap();
        assert!(yaml_again.len() > proto.len());
        let output_error = proto_wire_to_signed_yaml_stream_with_resource_limits(
            &proto,
            &finite(yaml_again.len() - 1),
        )
        .unwrap_err();
        assert_eq!(
            output_error.kind(),
            ArtifactResourceErrorKind::OutputArtifactTooLarge
        );
        assert_eq!(
            output_error.artifact_form(),
            Some(ArtifactResourceForm::Yaml)
        );
        assert_eq!(
            output_error.observed_or_projected_artifact_bytes(),
            Some(yaml_again.len())
        );

        let round_trip = proto_wire_to_signed_yaml_stream_with_resource_limits(
            &proto,
            &finite(yaml_again.len()),
        )
        .unwrap()
        .unwrap();
        assert_eq!(round_trip, yaml_again);
    }

    #[test]
    fn protobuf_transcode_input_rejection_precedes_malformed_wire() {
        let error =
            proto_wire_to_signed_yaml_stream_with_resource_limits(&[0xff, 0xff], &finite(1))
                .unwrap_err();
        assert_eq!(
            error.kind(),
            ArtifactResourceErrorKind::InputArtifactTooLarge
        );
        assert_eq!(error.artifact_form(), Some(ArtifactResourceForm::Protobuf));
    }

    #[test]
    fn proto_yaml_proto_preserves_empty_signature() {
        assert_proto_yaml_proto_signature("", "signature: \"\"\n");
    }

    #[test]
    fn proto_yaml_proto_preserves_yaml_ambiguous_signature() {
        assert_proto_yaml_proto_signature("true", "signature: \"true\"\n");
    }
}
