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

    let mut doc_bytes = b"---\n".to_vec();
    doc_bytes.extend_from_slice(&carrier);
    let doc = parse_signature_document(&doc_bytes)?;
    doc.validate_schema()
        .map_err(|_| TranscodeError::SchemaMismatch)?;

    let sig_octets = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(doc.signature.trim())
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
