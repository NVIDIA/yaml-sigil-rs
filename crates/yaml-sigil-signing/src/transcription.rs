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
//! The primary operations take `&ArtifactResourceLimits` and check the source before
//! parsing and check the destination independently before complete-output
//! allocation. Use `unbounded()` to omit the optional byte ceiling. Resource
//! policy is operational hardening and does not determine YamlSigil `v1alpha1`
//! conformance.
//!
//! ```no_run
//! use yaml_sigil_signing::v1alpha1::{
//!     ArtifactResourceLimits,
//!     signed_yaml_stream_to_proto_wire,
//! };
//!
//! # fn transcode(yaml: &[u8]) -> Result<Vec<u8>, Box<dyn core::error::Error>> {
//! let limits = ArtifactResourceLimits::default();
//! let protobuf =
//!     signed_yaml_stream_to_proto_wire(yaml, &limits)?;
//! // Source and destination are each compared with the ceiling. Their byte
//! // lengths are not added together.
//! Ok(protobuf)
//! # }
//! ```

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use base64::Engine;
use thiserror::Error;

use yaml_sigil_core::{
    ArtifactResourceForm, ArtifactResourceLimits, SCHEMA_V1ALPHA1, SignatureDocument,
    compose_proto_outer, parse_signature_document, pb::EncodeError, serialize_signature_document,
    validate_payload_stream, view_signature_carrier,
};
use yaml_sigil_traits::{AlgorithmId, OuterConformance};
use yaml_sigil_transcription::{
    ComposeRequest, DecomposeOutcome, DecomposeRequest, TranscriptionForm, compose, decompose,
};

/// Failure to transcode between signed YAML stream bytes and protobuf wire.
#[derive(Debug, Error)]
pub enum TranscodeError {
    /// The source or projected destination violates the complete-artifact policy.
    #[error(transparent)]
    Resource(#[from] yaml_sigil_core::ArtifactResourceError),
    /// The destination violates protobuf encoding limits.
    #[error(transparent)]
    Encoding(#[from] EncodeError),
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

fn yaml_decompose(yaml_artifact: &[u8]) -> Result<(&[u8], &[u8]), TranscodeError> {
    let resp = decompose(&DecomposeRequest {
        resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded(),
        artifact: yaml_artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let structural = match resp {
        Ok(s) => s,
        Err(_) => {
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

fn proto_decompose(wire: &[u8]) -> Result<(&[u8], &[u8]), TranscodeError> {
    let resp = decompose(&DecomposeRequest {
        resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded(),
        artifact: wire,
        form: TranscriptionForm::Protobuf,
        outer_conformance: Some(OuterConformance::SignatureStrict),
    });
    let structural = match resp {
        Ok(s) => s,
        Err(_) => {
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

/// Convert signed YAML to protobuf after independent source and destination admission.
pub fn signed_yaml_stream_to_proto_wire(
    yaml_artifact: &[u8],
    limits: &ArtifactResourceLimits,
) -> Result<Vec<u8>, TranscodeError> {
    limits.check_input_size(ArtifactResourceForm::Yaml, yaml_artifact)?;
    let (payload, carrier) = yaml_to_proto_components(yaml_artifact)?;
    compose_proto_outer(payload, &carrier, limits).map_err(|error| match error {
        yaml_sigil_core::ArtifactEncodeError::Resource(error) => TranscodeError::Resource(error),
        yaml_sigil_core::ArtifactEncodeError::Encoding(error) => TranscodeError::Encoding(error),
    })
}

/// Convert protobuf to signed YAML after independent source and destination admission.
pub fn proto_wire_to_signed_yaml_stream(
    wire: &[u8],
    limits: &ArtifactResourceLimits,
) -> Result<Vec<u8>, TranscodeError> {
    limits.check_input_size(ArtifactResourceForm::Protobuf, wire)?;
    let (payload, body) = proto_to_yaml_components(wire)?;
    compose(&ComposeRequest {
        payload,
        signature_carrier: body.as_bytes(),
        form: TranscriptionForm::Yaml,
        resource_limits: limits.clone(),
    })
    .map(|success| success.artifact)
    .map_err(|error| match error {
        yaml_sigil_traits::transcription::ComposeError::Resource(error) => {
            TranscodeError::Resource(error)
        }
        yaml_sigil_traits::transcription::ComposeError::Encoding(error) => {
            TranscodeError::Encoding(error)
        }
        _ => TranscodeError::NotSignedYamlStream,
    })
}

fn yaml_to_proto_components(yaml_artifact: &[u8]) -> Result<(&[u8], Vec<u8>), TranscodeError> {
    let (payload, carrier) = yaml_decompose(yaml_artifact)?;
    validate_payload_stream(payload).map_err(|_| TranscodeError::PayloadInvariant)?;

    let doc = parse_signature_document(carrier)?;
    doc.validate_schema()
        .map_err(|_| TranscodeError::SchemaMismatch)?;

    let sig_octets = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(doc.signature.as_bytes())
        .map_err(|_| TranscodeError::InvalidSignatureBase64)?;

    let alg_id = AlgorithmId::from_yaml_str(&doc.alg).ok_or(TranscodeError::UnknownYamlAlg)?;

    let inner_carrier =
        super::proto_carrier::encode_inner_signature_carrier(alg_id, sig_octets, doc.keyid);

    Ok((payload, inner_carrier))
}

fn proto_to_yaml_components(wire: &[u8]) -> Result<(&[u8], String), TranscodeError> {
    let (payload, carrier) = proto_decompose(wire)?;
    validate_payload_stream(payload).map_err(|_| TranscodeError::PayloadInvariant)?;

    let view = view_signature_carrier(carrier)?;

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

#[cfg(test)]
fn signed_yaml_stream_to_proto_wire_with_resource_limits(
    input: &[u8],
    limits: &ArtifactResourceLimits,
) -> yaml_sigil_core::ArtifactResourceResult<Result<Result<Vec<u8>, TranscodeError>, EncodeError>> {
    match signed_yaml_stream_to_proto_wire(input, limits) {
        Err(TranscodeError::Resource(error)) => Err(error),
        Err(TranscodeError::Encoding(error)) => Ok(Err(error)),
        result => Ok(Ok(result)),
    }
}
#[cfg(test)]
fn proto_wire_to_signed_yaml_stream_with_resource_limits(
    input: &[u8],
    limits: &ArtifactResourceLimits,
) -> yaml_sigil_core::ArtifactResourceResult<Result<Vec<u8>, TranscodeError>> {
    match proto_wire_to_signed_yaml_stream(input, limits) {
        Err(TranscodeError::Resource(error)) => Err(error),
        result => Ok(result),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;

    use super::super::{SignYamlParams, SigningKey, sign_yaml};
    use super::{
        TranscodeError, proto_wire_to_signed_yaml_stream,
        proto_wire_to_signed_yaml_stream_with_resource_limits, signed_yaml_stream_to_proto_wire,
        signed_yaml_stream_to_proto_wire_with_resource_limits,
    };
    use yaml_sigil_core::{
        AlgorithmId, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
        compose_proto_outer, decode_signed_yaml_artifact, view_signed_yaml_artifact,
    };

    fn finite(maximum: usize) -> ArtifactResourceLimits {
        ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(core::num::NonZeroUsize::new(maximum).unwrap())
    }

    fn add_signature_whitespace(artifact: &[u8]) -> Vec<u8> {
        let text = core::str::from_utf8(artifact).expect("signer emits UTF-8 YAML");
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
        let carrier = super::super::proto_carrier::encode_inner_signature_carrier(
            AlgorithmId::Ed25519,
            signature.clone(),
            None,
        );
        let wire = compose_proto_outer(
            b"review: scalar\n",
            &carrier,
            &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        )
        .expect("unbounded artifact policy");

        let yaml = proto_wire_to_signed_yaml_stream(&wire, &ArtifactResourceLimits::unbounded())
            .expect("transcode protobuf to YAML");
        let yaml_text = core::str::from_utf8(&yaml).expect("transcoder emits UTF-8 YAML");
        assert!(
            yaml_text.ends_with(expected_yaml_line),
            "unexpected YAML artifact: {yaml_text:?}"
        );

        let round_trip =
            signed_yaml_stream_to_proto_wire(&yaml, &ArtifactResourceLimits::unbounded())
                .expect("transcode YAML back to protobuf");
        let decoded = decode_signed_yaml_artifact(
            &round_trip,
            &yaml_sigil_core::ArtifactResourceLimits::unbounded(),
        )
        .expect("decode protobuf artifact");
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
            signed_yaml_stream_to_proto_wire(&mutated, &ArtifactResourceLimits::unbounded()),
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
        let proto =
            signed_yaml_stream_to_proto_wire(&yaml, &ArtifactResourceLimits::unbounded()).unwrap();
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

        let yaml_again =
            proto_wire_to_signed_yaml_stream(&proto, &ArtifactResourceLimits::unbounded()).unwrap();
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
