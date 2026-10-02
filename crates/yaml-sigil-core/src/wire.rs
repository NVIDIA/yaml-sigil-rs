// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Protobuf wire decode/encode helpers.

use alloc::{string::String, vec::Vec};

use crate::ArtifactResourceLimits;
use crate::error::CoreError;
use crate::proto_outer::decode_signature_carrier;

/// Decode protobuf wire bytes after applying an explicit complete-input policy.
pub fn decode_signed_yaml_artifact(
    bytes: &[u8],
    limits: &ArtifactResourceLimits,
) -> Result<crate::pb::SignedYamlArtifact, crate::ArtifactDecodeError> {
    crate::pb::SignedYamlArtifact::decode(bytes, limits)
}

/// Encode an owned protobuf artifact after applying an explicit output policy.
pub fn encode_signed_yaml_artifact(
    msg: &crate::pb::SignedYamlArtifact,
    limits: &ArtifactResourceLimits,
) -> Result<Vec<u8>, crate::ArtifactEncodeError> {
    msg.encode_to_vec(limits)
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
        keyid: sig.keyid().map(String::from),
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
        keyid: sig.keyid().map(String::from),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        decode_signed_yaml_artifact, encode_signed_yaml_artifact, view_signed_yaml_artifact,
    };
    use crate::pb::{SignedYamlArtifact, YamlSigilSignature};
    use crate::{AlgorithmId, ArtifactResourceLimits};

    #[test]
    fn decode_rejects_garbage() {
        assert!(
            decode_signed_yaml_artifact(
                b"\xff\x0a\x99",
                &crate::ArtifactResourceLimits::unbounded()
            )
            .is_err()
        );
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
        let bytes =
            encode_signed_yaml_artifact(&outer, &crate::ArtifactResourceLimits::unbounded())
                .unwrap();
        let decoded =
            decode_signed_yaml_artifact(&bytes, &crate::ArtifactResourceLimits::unbounded())
                .unwrap();
        let v = view_signed_yaml_artifact(&decoded).unwrap();
        assert_eq!(v.payload, b"ok\n");
        assert_eq!(v.alg_wire, 1);
        assert_eq!(v.signature, [1, 2, 3]);
        assert!(v.keyid.is_none());
    }

    #[test]
    fn wire_helpers_apply_policy_and_preserve_codec_errors() {
        let inner = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
        let outer = SignedYamlArtifact::new(b"ok\n".to_vec(), Some(inner));
        let bytes =
            encode_signed_yaml_artifact(&outer, &crate::ArtifactResourceLimits::unbounded())
                .unwrap();
        let limits = ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(core::num::NonZeroUsize::new(bytes.len()).unwrap());

        assert_eq!(encode_signed_yaml_artifact(&outer, &limits).unwrap(), bytes);
        assert_eq!(decode_signed_yaml_artifact(&bytes, &limits).unwrap(), outer);

        let too_small = ArtifactResourceLimits::unbounded()
            .with_max_artifact_bytes(core::num::NonZeroUsize::new(bytes.len() - 1).unwrap());
        assert!(encode_signed_yaml_artifact(&outer, &too_small).is_err());
        assert!(decode_signed_yaml_artifact(&bytes, &too_small).is_err());
    }
}
