// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;
use base64::Engine;

use yaml_sigil_core::{parse_signature_document, validate_payload_stream};
use yaml_sigil_traits::AlgorithmId;
use yaml_sigil_transcription::{DecomposeOutcome, DecomposeRequest, TranscriptionForm, decompose};

use crate::{ArtifactForm, PreVerifyOutcome, PreVerifyResponse, UnverifiedSignature};

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

fn extract_yaml_metadata(carrier: &[u8]) -> Result<UnverifiedSignature, PreVerifyOutcome> {
    let doc = match parse_signature_document(carrier) {
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
        && !super::keyid_is_valid(keyid)
    {
        return Err(PreVerifyOutcome::MetadataParseFailure);
    }
    let octets = match decode_sig_b64(&doc.signature) {
        Ok(o) => o,
        Err(()) => return Err(PreVerifyOutcome::MetadataParseFailure),
    };
    Ok(UnverifiedSignature {
        algorithm: alg,
        keyid: doc.keyid,
        signature_octets: octets,
    })
}

pub(crate) fn pre_verify_yaml(
    artifact: &[u8],
    allow_unsigned: bool,
    _include_parser_observations: bool,
) -> PreVerifyResponse<'_> {
    let resp = decompose(&DecomposeRequest {
        resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded(),
        artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let structural = match resp {
        Ok(s) => s,
        Err(_) => {
            return PreVerifyResponse {
                source_artifact: artifact,
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
            source_artifact: artifact,
            outcome: base_outcome,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        };
    }
    let payload = structural.payload.expect("ok decompose");
    let carrier = structural.signature_carrier.expect("ok decompose");
    if validate_payload_stream(payload).is_err() {
        return PreVerifyResponse {
            source_artifact: artifact,
            outcome: PreVerifyOutcome::StructuralFailure,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        };
    }
    match extract_yaml_metadata(carrier) {
        Ok(sig) => PreVerifyResponse {
            source_artifact: artifact,
            outcome: PreVerifyOutcome::Ok,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: Some(payload),
            unverified_signature: Some(sig),
            parser_observations: Vec::new(),
        },
        Err(o) => PreVerifyResponse {
            source_artifact: artifact,
            outcome: o,
            form: ArtifactForm::Yaml,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        },
    }
}

fn decode_sig_b64(s: &str) -> Result<Vec<u8>, ()> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    engine.decode(s).map_err(|_| ())
}
