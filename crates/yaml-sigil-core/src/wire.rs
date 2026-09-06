// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Protobuf wire decode/encode helpers.

use crate::error::CoreError;
use crate::proto_outer::decode_signature_carrier;

/// Decode protobuf `SignedYamlArtifact` wire bytes.
///
/// # Resource usage
///
/// YamlSigil `v1alpha1` defines no maximum complete artifact size, and this
/// decoder adds no deployment-specific limit. It copies recognized fields
/// into owned buffers with work and allocation linear in field size.
/// Applications accepting potentially untrusted input should apply their
/// chosen whole-artifact bound before this call.
pub fn decode_signed_yaml_artifact(
    bytes: &[u8],
) -> Result<crate::pb::SignedYamlArtifact, CoreError> {
    crate::pb::SignedYamlArtifact::decode(bytes).map_err(CoreError::from)
}

/// Encode an owned protobuf artifact through the stable facade.
pub fn encode_signed_yaml_artifact(
    msg: &crate::pb::SignedYamlArtifact,
) -> Result<Vec<u8>, crate::pb::EncodeError> {
    msg.encode_to_vec()
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
        decode_signed_yaml_artifact, encode_signed_yaml_artifact, view_signed_yaml_artifact,
    };
    use crate::AlgorithmId;
    use crate::pb::{SignedYamlArtifact, YamlSigilSignature};

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
}
