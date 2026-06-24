// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Protobuf wire decode/encode helpers.

use crate::error::CoreError;
use crate::proto_outer::decode_signature_carrier;

pub fn decode_signed_yaml_artifact(
    bytes: &[u8],
) -> Result<crate::pb::SignedYamlArtifact, CoreError> {
    use buffa::Message;
    crate::pb::SignedYamlArtifact::decode_from_slice(bytes).map_err(CoreError::from)
}

pub fn encode_signed_yaml_artifact(msg: &crate::pb::SignedYamlArtifact) -> Vec<u8> {
    use buffa::Message;
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

pub fn view_signed_yaml_artifact(
    artifact: &crate::pb::SignedYamlArtifact,
) -> Result<ProtoArtifactView, CoreError> {
    if !artifact.signature.is_set() {
        return Err(CoreError::ProtobufDecode(
            "missing signature submessage".into(),
        ));
    }
    let sig = artifact
        .signature
        .as_option()
        .ok_or_else(|| CoreError::ProtobufDecode("missing signature submessage".into()))?;
    Ok(ProtoArtifactView {
        payload: artifact.payload.clone(),
        alg_wire: sig.alg.to_i32(),
        signature: sig.signature.clone(),
        keyid: sig.keyid.clone(),
    })
}

/// Extract inner signature fields from opaque carrier bytes (verification metadata stage).
pub fn view_signature_carrier(carrier: &[u8]) -> Result<ProtoArtifactView, CoreError> {
    let sig = decode_signature_carrier(carrier)?;
    let alg_wire = sig.alg.to_i32();
    Ok(ProtoArtifactView {
        payload: Vec::new(),
        alg_wire,
        signature: sig.signature,
        keyid: sig.keyid,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        decode_signed_yaml_artifact, encode_signed_yaml_artifact, view_signed_yaml_artifact,
    };
    use crate::pb::{Algorithm, SignedYamlArtifact, YamlSigilSignature};
    use buffa::MessageField;

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

    /// Protobuf `buffa` decode/view round-trip.
    #[test]
    fn encode_signed_yaml_artifact_then_decode_matches() {
        let inner = YamlSigilSignature {
            alg: Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL.into(),
            signature: vec![1, 2, 3],
            ..Default::default()
        };
        let outer = SignedYamlArtifact {
            payload: b"ok\n".to_vec(),
            signature: MessageField::from(inner),
            ..Default::default()
        };
        let bytes = encode_signed_yaml_artifact(&outer);
        let decoded = decode_signed_yaml_artifact(&bytes).unwrap();
        let v = view_signed_yaml_artifact(&decoded).unwrap();
        assert_eq!(v.payload, b"ok\n");
        assert_eq!(v.alg_wire, 1);
        assert_eq!(v.signature, [1, 2, 3]);
        assert!(v.keyid.is_none());
    }
}
