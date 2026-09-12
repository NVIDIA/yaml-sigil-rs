// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Byte-level interoperability fixture generated with Buffa 0.5.2.
//!
//! The independently generated types and the stable facade exchange bytes
//! without sharing generated Rust types or a Buffa version.
//!
//! ```
//! use yaml_sigil_core::{
//!     AlgorithmId,
//!     pb::{SignedYamlArtifact, SignedYamlArtifactRef, YamlSigilSignature},
//! };
//! use yaml_sigil_core_downstream_buffa_0_5::{
//!     decode_independent, encode_independent,
//! };
//!
//! let independent_wire = encode_independent();
//! let borrowed = SignedYamlArtifactRef::decode(&independent_wire).unwrap();
//! assert_eq!(borrowed.payload(), b"message\n");
//!
//! let signature =
//!     YamlSigilSignature::new(AlgorithmId::EcdsaP256Sha256, vec![4, 5, 6]);
//! let facade_wire =
//!     SignedYamlArtifact::new(b"other\n".to_vec(), Some(signature))
//!         .encode_to_vec()
//!         .unwrap();
//! assert_eq!(
//!     decode_independent(&facade_wire).unwrap(),
//!     (b"other\n".to_vec(), 2, vec![4, 5, 6]),
//! );
//! ```

mod generated {
    include!(concat!(env!("OUT_DIR"), "/compat_include.rs"));
}

use buffa::{Message as _, MessageField};
use generated::compat::v1::{CompatAlgorithm, CompatArtifact, CompatSignature};

/// Encode a wire-compatible artifact with independently generated Buffa 0.5.2 types.
pub fn encode_independent() -> Vec<u8> {
    let signature = CompatSignature {
        alg: CompatAlgorithm::COMPAT_ALGORITHM_ED25519.into(),
        keyid: Some("key-1".to_owned()),
        signature: vec![1, 2, 3],
        ..Default::default()
    };
    CompatArtifact {
        payload: b"message\n".to_vec(),
        signature: MessageField::from(signature),
        ..Default::default()
    }
    .encode_to_vec()
}

/// Decode facade-produced bytes with independently generated Buffa 0.5.2 types.
pub fn decode_independent(input: &[u8]) -> Result<(Vec<u8>, i32, Vec<u8>), buffa::DecodeError> {
    let artifact = CompatArtifact::decode_from_slice(input)?;
    let signature = artifact.signature.as_option().cloned().unwrap_or_default();
    Ok((
        artifact.payload,
        signature.alg.to_i32(),
        signature.signature,
    ))
}

#[cfg(test)]
mod tests {
    use yaml_sigil_core::{
        AlgorithmId, ArtifactResourceLimits,
        pb::{SignedYamlArtifact, SignedYamlArtifactRef, YamlSigilSignature},
    };

    #[test]
    fn independently_generated_buffa_messages_exchange_bytes_with_the_facade() {
        let independent_wire = super::encode_independent();
        let borrowed = SignedYamlArtifactRef::decode_with_resource_limits(
            &independent_wire,
            &ArtifactResourceLimits::default(),
        )
        .unwrap()
        .unwrap();
        let signature = borrowed.signature().unwrap();
        assert_eq!(borrowed.payload(), b"message\n");
        assert_eq!(signature.algorithm(), Some(AlgorithmId::Ed25519));
        assert_eq!(signature.keyid(), Some("key-1"));
        assert_eq!(signature.signature(), [1, 2, 3]);

        let facade_signature =
            YamlSigilSignature::new(AlgorithmId::EcdsaP256Sha256, vec![4, 5, 6]);
        let facade = SignedYamlArtifact::new(b"other\n".to_vec(), Some(facade_signature));
        let decoded = super::decode_independent(&facade.encode_to_vec().unwrap()).unwrap();
        assert_eq!(decoded, (b"other\n".to_vec(), 2, vec![4, 5, 6]));
        assert_eq!(
            borrowed
                .encode_to_vec_with_resource_limits(&ArtifactResourceLimits::default())
                .unwrap()
                .unwrap(),
            independent_wire
        );
    }
}
