// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use tracing::instrument;
use yaml_sigil_core::{
    has_unknown_signature_document_fields, parse_signature_document, validate_payload_stream,
};
use yaml_sigil_traits::AlgorithmId;
use yaml_sigil_transcription::{DecomposeOutcome, DecomposeRequest, TranscriptionForm, decompose};

use crate::{
    ArtifactForm, InvocationError, PreVerifyOutcome, PreVerifyResponse, PublicKeys,
    UnverifiedSignature, VerifierOptions, VerifierState,
};

fn preverify_outcome_from_decompose(
    outcome: DecomposeOutcome,
    allow_unsigned: bool,
) -> PreVerifyOutcome {
    match outcome {
        DecomposeOutcome::Ok => PreVerifyOutcome::Ok,
        DecomposeOutcome::Unsigned if allow_unsigned => PreVerifyOutcome::Unsigned,
        DecomposeOutcome::Unsigned => PreVerifyOutcome::StructuralFailure,
        DecomposeOutcome::MalformedAttemptedSigned => PreVerifyOutcome::StructuralFailure,
    }
}

fn extract_yaml_metadata(
    payload: Vec<u8>,
    carrier: Vec<u8>,
    options: &VerifierOptions,
) -> Result<UnverifiedSignature, PreVerifyOutcome> {
    let mut doc_bytes = b"---\n".to_vec();
    doc_bytes.extend_from_slice(&carrier);
    if options.reject_unknown_signature_document_fields {
        match has_unknown_signature_document_fields(&doc_bytes) {
            Ok(true) | Err(_) => return Err(PreVerifyOutcome::MetadataParseFailure),
            Ok(false) => {}
        }
    }
    let doc = match parse_signature_document(&doc_bytes) {
        Ok(d) => d,
        Err(_) => return Err(PreVerifyOutcome::MetadataParseFailure),
    };
    if doc.validate_schema().is_err() {
        return Err(PreVerifyOutcome::MetadataParseFailure);
    }
    let alg = match AlgorithmId::from_yaml_str(&doc.alg) {
        Some(a) => a,
        None => return Err(PreVerifyOutcome::MetadataParseFailure),
    };
    if let Some(ref keyid) = doc.keyid
        && !keyid_is_valid(keyid)
    {
        return Err(PreVerifyOutcome::MetadataParseFailure);
    }
    let octets = match decode_sig_b64(&doc.signature) {
        Ok(o) => o,
        Err(()) => return Err(PreVerifyOutcome::MetadataParseFailure),
    };
    let _ = payload;
    Ok(UnverifiedSignature {
        algorithm: alg,
        keyid: doc.keyid,
        signature_octets: octets,
    })
}

/// `keyid` must be 1..=1024 UTF-8 octets without CR or LF.
pub(crate) fn keyid_is_valid(keyid: &str) -> bool {
    let len = keyid.len();
    (1..=1024).contains(&len) && !keyid.contains(['\r', '\n'])
}

pub(crate) fn pre_verify_yaml(
    artifact: &[u8],
    allow_unsigned: bool,
    _include_parser_observations: bool,
    options: &VerifierOptions,
) -> PreVerifyResponse {
    let resp = decompose(&DecomposeRequest {
        artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let structural = match resp {
        yaml_sigil_transcription::DecomposeResponse::Structural(s) => s,
        yaml_sigil_transcription::DecomposeResponse::Invocation(_) => {
            return PreVerifyResponse {
                outcome: PreVerifyOutcome::StructuralFailure,
                form: ArtifactForm::Yaml,
                unverified_payload_bytes: None,
                unverified_signature: None,
                parser_observations: Vec::new(),
            };
        }
    };
    let base_outcome = preverify_outcome_from_decompose(structural.outcome, allow_unsigned);
    if base_outcome != PreVerifyOutcome::Ok {
        return PreVerifyResponse {
            outcome: base_outcome,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        };
    }
    let payload = structural.payload.expect("ok decompose");
    let carrier = structural.signature_carrier.expect("ok decompose");
    if validate_payload_stream(&payload).is_err() {
        return PreVerifyResponse {
            outcome: PreVerifyOutcome::StructuralFailure,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        };
    }
    match extract_yaml_metadata(payload.clone(), carrier, options) {
        Ok(sig) => PreVerifyResponse {
            outcome: PreVerifyOutcome::Ok,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: Some(payload),
            unverified_signature: Some(sig),
            parser_observations: Vec::new(),
        },
        Err(o) => PreVerifyResponse {
            outcome: o,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        },
    }
}

#[instrument(level = "debug", skip_all)]
pub(crate) fn verify_yaml(
    artifact: &[u8],
    keys: &PublicKeys<'_>,
    options: &VerifierOptions,
    include_parser_observations: bool,
) -> Result<(VerifierState, Vec<String>), InvocationError> {
    let pre = pre_verify_yaml(artifact, false, include_parser_observations, options);
    let obs = if include_parser_observations {
        pre.parser_observations.clone()
    } else {
        Vec::new()
    };
    let state = match pre.outcome {
        PreVerifyOutcome::Ok => verify_from_pre_verify(&pre, keys, options)?,
        PreVerifyOutcome::Unsigned => VerifierState::Unsigned,
        PreVerifyOutcome::StructuralFailure | PreVerifyOutcome::MetadataParseFailure => {
            VerifierState::MalformedAttemptedSigned
        }
    };
    Ok((state, obs))
}

pub(crate) fn verify_from_pre_verify(
    pre: &PreVerifyResponse,
    keys: &PublicKeys<'_>,
    options: &VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    if pre.form != ArtifactForm::Yaml || pre.outcome != PreVerifyOutcome::Ok {
        return Err(InvocationError::InvalidPreVerifyResult);
    }
    let payload = pre
        .unverified_payload_bytes
        .as_ref()
        .ok_or(InvocationError::InvalidPreVerifyResult)?;
    let sig = pre
        .unverified_signature
        .as_ref()
        .ok_or(InvocationError::InvalidPreVerifyResult)?;
    let wire = match sig.algorithm {
        AlgorithmId::Ed25519 => 1,
        AlgorithmId::EcdsaP256Sha256 => 2,
    };
    crate::verify_extracted_signature(
        payload,
        wire,
        sig.signature_octets.as_slice(),
        keys,
        options,
    )
}

fn decode_sig_b64(s: &str) -> Result<Vec<u8>, ()> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine.decode(s).map_err(|_| ())
}
