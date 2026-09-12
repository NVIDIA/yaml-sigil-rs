// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bytes-only outer `SignedYamlArtifact` compose/decompose for the Transcription API.
//!
//! Does not parse the `YamlSigilSignature` interior; returns the length-delimited body of
//! field 2 as opaque `signature_carrier` bytes.

use crate::conformance::OuterConformance;
use crate::error::CoreError;
use crate::{ArtifactResourceForm, ArtifactResourceLimits, ArtifactResourceResult};

/// Outcome of outer protobuf envelope decomposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoOuterDecomposeOutcome {
    /// Wire shape or outer-conformance violation.
    Malformed,
    /// Recovered payload and opaque signature-carrier bytes.
    Ok {
        payload: Vec<u8>,
        signature_carrier: Vec<u8>,
    },
}

/// Serialize outer `SignedYamlArtifact` with opaque `signature_carrier` as field 2 body.
pub fn compose_proto_outer(payload: &[u8], signature_carrier: &[u8]) -> Vec<u8> {
    crate::pb::compose_raw_outer(payload, signature_carrier)
}

/// Serialize an outer artifact after applying an explicit complete-output policy.
///
/// Checked wire-size arithmetic and policy admission occur before allocation.
/// The outer result reports resource rejection. After admission, the inner
/// result preserves the protobuf facade's format error.
pub fn compose_proto_outer_with_resource_limits(
    payload: &[u8],
    signature_carrier: &[u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, crate::pb::EncodeError>> {
    crate::pb::compose_raw_outer_with_resource_limits(payload, signature_carrier, limits)
}

/// Decompose outer wire bytes under the selected outer-envelope conformance mode.
///
/// # Resource usage
///
/// YamlSigil `v1alpha1` defines no maximum complete artifact size, and this
/// function adds no implementation-local limit. It copies recognized fields
/// into owned buffers with work and allocation linear in their total size. Use
/// [`decompose_proto_outer_with_resource_limits`] to apply the shared input
/// policy first. A local resource rejection is independent of artifact
/// conformance.
#[tracing::instrument(level = "debug", skip(wire), fields(len = wire.len(), ?mode))]
pub fn decompose_proto_outer(wire: &[u8], mode: OuterConformance) -> ProtoOuterDecomposeOutcome {
    match crate::pb::decompose_raw_outer(wire, mode) {
        crate::pb::RawOuterDecomposeOutcome::Malformed => ProtoOuterDecomposeOutcome::Malformed,
        crate::pb::RawOuterDecomposeOutcome::Ok {
            payload,
            signature_carrier,
        } => ProtoOuterDecomposeOutcome::Ok {
            payload,
            signature_carrier,
        },
    }
}

/// Decompose outer wire bytes after applying an explicit complete-input policy.
///
/// The raw input length is checked before tag or conformance processing.
pub fn decompose_proto_outer_with_resource_limits(
    wire: &[u8],
    mode: OuterConformance,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<ProtoOuterDecomposeOutcome> {
    let wire = limits.check_input_size(ArtifactResourceForm::Protobuf, wire)?;
    Ok(decompose_proto_outer(wire, mode))
}

/// Decode inner `YamlSigilSignature` from opaque carrier bytes (verification metadata stage).
///
/// # Resource usage
///
/// This decoder adds no deployment-specific signature-carrier limit. It
/// copies recognized fields into owned buffers with work and allocation
/// linear in field size. Apply any local input bound before this call.
pub fn decode_signature_carrier(
    carrier: &[u8],
) -> Result<crate::pb::YamlSigilSignature, CoreError> {
    crate::pb::YamlSigilSignature::decode(carrier).map_err(CoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_opaque_carrier() {
        let inner = crate::pb::YamlSigilSignature::new(crate::AlgorithmId::Ed25519, vec![1, 2, 3])
            .encode_to_vec()
            .unwrap();
        let wire = compose_proto_outer(b"k: v\n", &inner);
        match decompose_proto_outer(&wire, OuterConformance::Strict) {
            ProtoOuterDecomposeOutcome::Ok {
                payload,
                signature_carrier,
            } => {
                assert_eq!(payload, b"k: v\n");
                assert_eq!(signature_carrier, inner);
            }
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn duplicate_signature_rejected() {
        let mut wire = compose_proto_outer(b"p\n", b"a");
        let second = compose_proto_outer(&[], b"b");
        wire.extend_from_slice(&second[2..]);
        assert_eq!(
            decompose_proto_outer(&wire, OuterConformance::SignatureStrict),
            ProtoOuterDecomposeOutcome::Malformed
        );
    }

    #[test]
    fn missing_signature_malformed() {
        let only_payload = compose_proto_outer(b"p\n", &[])[..4].to_vec();
        assert_eq!(
            decompose_proto_outer(&only_payload, OuterConformance::Strict),
            ProtoOuterDecomposeOutcome::Malformed
        );
    }

    #[test]
    fn resource_limit_precedes_malformed_wire_and_mode_processing() {
        let limits = ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(1).unwrap());
        let error = decompose_proto_outer_with_resource_limits(
            &[0xff, 0xff],
            OuterConformance::Strict,
            &limits,
        )
        .unwrap_err();
        assert_eq!(
            error.kind(),
            crate::ArtifactResourceErrorKind::InputArtifactTooLarge
        );
        assert_eq!(error.artifact_form(), Some(ArtifactResourceForm::Protobuf));
    }

    #[test]
    fn resource_aware_raw_composition_checks_the_exact_output_boundary() {
        let expected = compose_proto_outer(b"payload", b"carrier");
        let exact = ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(expected.len()).unwrap());
        assert_eq!(
            compose_proto_outer_with_resource_limits(b"payload", b"carrier", &exact)
                .unwrap()
                .unwrap(),
            expected
        );

        let too_small = ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(expected.len() - 1).unwrap());
        let error = compose_proto_outer_with_resource_limits(b"payload", b"carrier", &too_small)
            .unwrap_err();
        assert_eq!(
            error.observed_or_projected_artifact_bytes(),
            Some(expected.len())
        );
    }
}
