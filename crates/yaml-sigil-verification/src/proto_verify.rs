// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use tracing::instrument;
use yaml_sigil_core::view_signature_carrier;
use yaml_sigil_traits::{AlgorithmId, OuterConformance};
use yaml_sigil_transcription::{DecomposeOutcome, DecomposeRequest, TranscriptionForm, decompose};

use crate::{
    ArtifactForm, InvocationError, PreVerifyOutcome, PreVerifyResponse, PublicKeys,
    UnverifiedSignature, VerifierOptions, VerifierState,
};

pub(crate) fn default_outer_conformance() -> OuterConformance {
    OuterConformance::SignatureStrict
}

fn extract_proto_metadata(carrier: Vec<u8>) -> Result<UnverifiedSignature, PreVerifyOutcome> {
    // Empty carrier bytes correspond to a present-but-empty outer `signature`
    // submessage. These flow through metadata extraction and are rejected at
    // Verification's verification stage (the non-empty `signature` rule).
    // Decoding an empty
    // protobuf body yields `YamlSigilSignature::default()` (alg=UNSPECIFIED,
    // signature=[], keyid=None); the alg=UNSPECIFIED check below catches this
    // at metadata for now, while the empty-octets rule is enforced at
    // verify_extracted_signature.
    let inner = match view_signature_carrier(&carrier) {
        Ok(v) => v,
        Err(_) => return Err(PreVerifyOutcome::MetadataParseFailure),
    };
    if inner.alg_wire <= 0 {
        return Err(PreVerifyOutcome::MetadataParseFailure);
    }
    let algorithm = match AlgorithmId::from_i32(inner.alg_wire) {
        Some(a) => a,
        None => return Err(PreVerifyOutcome::MetadataParseFailure),
    };
    if let Some(ref keyid) = inner.keyid
        && !crate::yaml_verify::keyid_octets_in_bounds(keyid)
    {
        return Err(PreVerifyOutcome::MetadataParseFailure);
    }
    Ok(UnverifiedSignature {
        algorithm,
        keyid: inner.keyid,
        signature_octets: inner.signature,
    })
}

pub(crate) fn pre_verify_proto(
    wire: &[u8],
    _include_parser_observations: bool,
) -> PreVerifyResponse {
    let outer = default_outer_conformance();
    let resp = decompose(&DecomposeRequest {
        artifact: wire,
        form: TranscriptionForm::Protobuf,
        outer_conformance: Some(outer),
    });
    let structural = match resp {
        yaml_sigil_transcription::DecomposeResponse::Structural(s) => s,
        yaml_sigil_transcription::DecomposeResponse::Invocation(_) => {
            return PreVerifyResponse {
                outcome: PreVerifyOutcome::StructuralFailure,
                form: ArtifactForm::Proto,
                unverified_payload_bytes: None,
                unverified_signature: None,
                parser_observations: Vec::new(),
            };
        }
    };
    if structural.outcome != DecomposeOutcome::Ok {
        return PreVerifyResponse {
            outcome: PreVerifyOutcome::StructuralFailure,
            form: ArtifactForm::Proto,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        };
    }
    let payload = structural.payload.expect("ok decompose");
    let carrier = structural.signature_carrier.expect("ok decompose");
    // The protobuf form's `payload` is an arbitrary byte container; no UTF-8 /
    // BOM / line-terminator checks run here.
    // YAML-form payload-envelope rules live in `yaml_verify::pre_verify_yaml`.
    // See docs/conformance-validation.md.
    match extract_proto_metadata(carrier) {
        Ok(sig) => PreVerifyResponse {
            outcome: PreVerifyOutcome::Ok,
            form: ArtifactForm::Proto,
            unverified_payload_bytes: Some(payload),
            unverified_signature: Some(sig),
            parser_observations: Vec::new(),
        },
        Err(o) => PreVerifyResponse {
            outcome: o,
            form: ArtifactForm::Proto,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        },
    }
}

#[instrument(level = "debug", skip_all)]
pub(crate) fn verify_proto(
    wire: &[u8],
    keys: &PublicKeys<'_>,
    options: &VerifierOptions,
    include_parser_observations: bool,
) -> Result<(VerifierState, Vec<String>), InvocationError> {
    let pre = pre_verify_proto(wire, include_parser_observations);
    let obs = if include_parser_observations {
        pre.parser_observations.clone()
    } else {
        Vec::new()
    };
    let state = match pre.outcome {
        PreVerifyOutcome::Ok => verify_from_pre_verify_proto(&pre, keys, options)?,
        PreVerifyOutcome::Unsigned => VerifierState::Unsigned,
        PreVerifyOutcome::StructuralFailure | PreVerifyOutcome::MetadataParseFailure => {
            VerifierState::MalformedAttemptedSigned
        }
    };
    Ok((state, obs))
}

pub(crate) fn verify_from_pre_verify_proto(
    pre: &PreVerifyResponse,
    keys: &PublicKeys<'_>,
    options: &VerifierOptions,
) -> Result<VerifierState, InvocationError> {
    if pre.form != ArtifactForm::Proto || pre.outcome != PreVerifyOutcome::Ok {
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
