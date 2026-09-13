// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Protobuf wire decode/encode helpers.

use crate::error::CoreError;
use crate::proto_outer::decode_signature_carrier;
use crate::{ArtifactResourceLimits, ArtifactResourceResult};

/// Decode protobuf `SignedYamlArtifact` wire bytes.
///
/// # Resource usage
///
/// YamlSigil `v1alpha1` defines no maximum complete artifact size, and this
/// decoder adds no implementation-local limit. It copies recognized fields
/// into owned buffers with work and allocation linear in field size. Use
/// [`decode_signed_yaml_artifact_with_resource_limits`] to apply the shared
/// input policy first.
pub fn decode_signed_yaml_artifact(
    bytes: &[u8],
) -> Result<crate::pb::SignedYamlArtifact, CoreError> {
    crate::pb::SignedYamlArtifact::decode(bytes).map_err(CoreError::from)
}

/// Decode protobuf wire bytes after applying an explicit complete-input policy.
pub fn decode_signed_yaml_artifact_with_resource_limits(
    bytes: &[u8],
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<crate::pb::SignedYamlArtifact, CoreError>> {
    Ok(
        crate::pb::SignedYamlArtifact::decode_with_resource_limits(bytes, limits)?
            .map_err(CoreError::from),
    )
}

/// Encode an owned protobuf artifact through the stable facade.
pub fn encode_signed_yaml_artifact(
    msg: &crate::pb::SignedYamlArtifact,
) -> Result<Vec<u8>, crate::pb::EncodeError> {
    msg.encode_to_vec()
}

/// Encode an owned protobuf artifact after applying an explicit output policy.
pub fn encode_signed_yaml_artifact_with_resource_limits(
    msg: &crate::pb::SignedYamlArtifact,
    limits: &ArtifactResourceLimits,
) -> ArtifactResourceResult<Result<Vec<u8>, crate::pb::EncodeError>> {
    msg.encode_to_vec_with_resource_limits(limits)
}

/// Payload + algorithm wire number + raw signature octets extracted from protobuf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoArtifactView {
    pub payload: Vec<u8>,
    pub alg_wire: i32,
    pub signature: Vec<u8>,
    /// Optional key identifier from `YamlSigilSignature.keyid` (protobuf field 2).
    pub keyid: Option<String>,
}

/// Copy the payload and signature fields from a decoded `SignedYamlArtifact` into an owned view.
///
/// # Resource usage
///
/// This helper clones recognized fields into owned buffers with work and
/// allocation linear in field size. Apply any local limit before constructing
/// `artifact` from potentially untrusted input.
pub fn view_signed_yaml_artifact(
    artifact: &crate::pb::SignedYamlArtifact,
) -> Result<ProtoArtifactView, CoreError> {
    let sig = artifact
        .signature()
        .ok_or_else(|| CoreError::ProtobufDecode("missing signature submessage".into()))?;
    Ok(ProtoArtifactView {
        payload: artifact.payload().to_vec(),
        alg_wire: sig.algorithm_wire_value(),
        signature: sig.signature().to_vec(),
        keyid: sig.keyid().map(str::to_owned),
    })
}

/// Extract inner signature fields from opaque carrier bytes (verification metadata stage).
///
/// # Resource usage
///
/// Protobuf decoding has the resource behavior documented on [`decode_signature_carrier`].
pub fn view_signature_carrier(carrier: &[u8]) -> Result<ProtoArtifactView, CoreError> {
    let sig = decode_signature_carrier(carrier)?;
    Ok(ProtoArtifactView {
        payload: Vec::new(),
        alg_wire: sig.algorithm_wire_value(),
        signature: sig.signature().to_vec(),
        keyid: sig.keyid().map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        decode_signed_yaml_artifact, decode_signed_yaml_artifact_with_resource_limits,
        encode_signed_yaml_artifact, encode_signed_yaml_artifact_with_resource_limits,
        view_signed_yaml_artifact,
    };
    use crate::pb::{SignedYamlArtifact, YamlSigilSignature};
    use crate::{AlgorithmId, ArtifactResourceLimits};

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_signed_yaml_artifact(b"\xff\x0a\x99").is_err());
    }

    #[test]
    fn view_requires_signature_submessage() {
        let a = SignedYamlArtifact::default();
        let err = view_signed_yaml_artifact(&a).unwrap_err();
        assert!(matches!(err, crate::error::CoreError::ProtobufDecode(_)));
    }

    /// Protobuf facade decode/view round-trip.
    #[test]
    fn encode_signed_yaml_artifact_then_decode_matches() {
        let inner = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
        let outer = SignedYamlArtifact::new(b"ok\n".to_vec(), Some(inner));
        let bytes = encode_signed_yaml_artifact(&outer).unwrap();
        let decoded = decode_signed_yaml_artifact(&bytes).unwrap();
        let v = view_signed_yaml_artifact(&decoded).unwrap();
        assert_eq!(v.payload, b"ok\n");
        assert_eq!(v.alg_wire, 1);
        assert_eq!(v.signature, [1, 2, 3]);
        assert!(v.keyid.is_none());
    }

    #[test]
    fn resource_aware_wire_helpers_preserve_the_nested_error_layer() {
        let inner = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
        let outer = SignedYamlArtifact::new(b"ok\n".to_vec(), Some(inner));
        let bytes = encode_signed_yaml_artifact(&outer).unwrap();
        let limits = ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(bytes.len()).unwrap());

        assert_eq!(
            encode_signed_yaml_artifact_with_resource_limits(&outer, &limits)
                .unwrap()
                .unwrap(),
            bytes
        );
        assert_eq!(
            decode_signed_yaml_artifact_with_resource_limits(&bytes, &limits)
                .unwrap()
                .unwrap(),
            outer
        );

        let too_small = ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(std::num::NonZeroUsize::new(bytes.len() - 1).unwrap());
        assert!(encode_signed_yaml_artifact_with_resource_limits(&outer, &too_small).is_err());
        assert!(decode_signed_yaml_artifact_with_resource_limits(&bytes, &too_small).is_err());
    }
}
