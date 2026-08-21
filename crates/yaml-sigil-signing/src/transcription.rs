// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Signed-artifact transcoding via the Transcription API (Decompose → metadata → Compose).
//!
//! Empty decoded signature octets pass through here: rejection is the
//! verifier's verification-stage responsibility (`MalformedAttemptedSigned`),
//! not metadata extraction.

use base64::Engine;
use thiserror::Error;
use tracing::instrument;
use yaml_sigil_core::{
    SCHEMA_V1ALPHA1, SignatureDocument, compose_proto_outer, parse_signature_document,
    serialize_signature_document, validate_payload_stream, view_signature_carrier,
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
#[instrument(level = "debug", skip(yaml_artifact), fields(len = yaml_artifact.len()))]
pub fn signed_yaml_stream_to_proto_wire(yaml_artifact: &[u8]) -> Result<Vec<u8>, TranscodeError> {
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

    Ok(compose_proto_outer(&payload, &inner_carrier))
}

/// Convert protobuf wire bytes into a signed YAML artifact stream.
#[instrument(level = "debug", skip(wire), fields(len = wire.len()))]
pub fn proto_wire_to_signed_yaml_stream(wire: &[u8]) -> Result<Vec<u8>, TranscodeError> {
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

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey as Ed25519SigningKey;

    use super::{
        TranscodeError, proto_wire_to_signed_yaml_stream, signed_yaml_stream_to_proto_wire,
    };
    use crate::{SignYamlParams, SigningKey, sign_yaml};
    use yaml_sigil_core::{
        AlgorithmId, compose_proto_outer, decode_signed_yaml_artifact, view_signed_yaml_artifact,
    };

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
    fn proto_yaml_proto_preserves_empty_signature() {
        assert_proto_yaml_proto_signature("", "signature: \"\"\n");
    }

    #[test]
    fn proto_yaml_proto_preserves_yaml_ambiguous_signature() {
        assert_proto_yaml_proto_signature("true", "signature: \"true\"\n");
    }
}
