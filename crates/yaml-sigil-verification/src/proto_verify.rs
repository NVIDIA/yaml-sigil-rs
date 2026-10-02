// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

use alloc::vec::Vec;

use yaml_sigil_core::view_signature_carrier;
use yaml_sigil_traits::{AlgorithmId, OuterConformance};
use yaml_sigil_transcription::{DecomposeOutcome, DecomposeRequest, TranscriptionForm, decompose};

use crate::{ArtifactForm, PreVerifyOutcome, PreVerifyResponse, UnverifiedSignature};

pub(crate) fn default_outer_conformance() -> OuterConformance {
    OuterConformance::SignatureStrict
}

fn extract_proto_metadata(carrier: &[u8]) -> Result<UnverifiedSignature, PreVerifyOutcome> {
    // Empty carrier bytes correspond to a present-but-empty outer `signature`
    // submessage. These flow through metadata extraction and are rejected at
    // Verification's verification stage (the non-empty `signature` rule).
    // Decoding an empty
    // protobuf body yields `YamlSigilSignature::default()` (alg=UNSPECIFIED,
    // signature=[], keyid=None); the alg=UNSPECIFIED check below catches this
    // at metadata for now, while the empty-octets rule is enforced at
    // verify_extracted_signature.
    let inner = match view_signature_carrier(carrier) {
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
        && !super::keyid_is_valid(keyid)
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
) -> PreVerifyResponse<'_> {
    let outer = default_outer_conformance();
    let resp = decompose(&DecomposeRequest {
        resource_limits: yaml_sigil_traits::ArtifactResourceLimits::unbounded(),
        artifact: wire,
        form: TranscriptionForm::Protobuf,
        outer_conformance: Some(outer),
    });
    let structural = match resp {
        Ok(s) => s,
        Err(_) => {
            return PreVerifyResponse {
                source_artifact: wire,
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
            source_artifact: wire,
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
            source_artifact: wire,
            outcome: PreVerifyOutcome::Ok,
            form: ArtifactForm::Proto,
            unverified_payload_bytes: Some(payload),
            unverified_signature: Some(sig),
            parser_observations: Vec::new(),
        },
        Err(o) => PreVerifyResponse {
            source_artifact: wire,
            outcome: o,
            form: ArtifactForm::Proto,
            unverified_payload_bytes: None,
            unverified_signature: None,
            parser_observations: Vec::new(),
        },
    }
}
