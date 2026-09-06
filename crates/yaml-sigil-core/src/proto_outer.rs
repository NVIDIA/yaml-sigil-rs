// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bytes-only outer `SignedYamlArtifact` compose/decompose for the Transcription API.
//!
//! Does not parse the `YamlSigilSignature` interior; returns the length-delimited body of
//! field 2 as opaque `signature_carrier` bytes.

use crate::conformance::OuterConformance;
use crate::error::CoreError;

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

/// Decompose outer wire bytes under the selected outer-envelope conformance mode.
///
/// # Resource usage
///
/// The library imposes no universal artifact, payload, or signature-carrier size limit.
/// Recognized fields are copied into owned buffers. Allocation and copying are linear in the
/// total size of those fields. Callers handling untrusted data must enforce
/// deployment-appropriate size limits before invoking this function.
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

/// Decode inner `YamlSigilSignature` from opaque carrier bytes (verification metadata stage).
///
/// # Resource usage
///
/// This decoder imposes no universal signature-carrier size limit. It copies recognized fields
/// into owned buffers, so allocation and copying are linear in field size. Callers handling
/// untrusted data must enforce deployment-appropriate size limits before invocation.
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
}
