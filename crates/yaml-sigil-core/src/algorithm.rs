// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Canonical algorithm identifiers and protobuf enum mapping.
//!
//! YAML `alg:` and JSON Schema use the unprefixed canonical names; the protobuf
//! `Algorithm` enum uses Buf-prefixed constants
//! (`ALGORITHM_…_…`). `yaml-sigil-traits` owns the portable identifier; this
//! module keeps core-specific protobuf conversions.

pub use yaml_sigil_traits::AlgorithmId;

/// YAML `schema:` value for v1alpha1 signature documents.
pub const SCHEMA_V1ALPHA1: &str = "YamlSigilSignature.v1alpha1";

pub fn algorithm_id_from_buffa_enum(alg: crate::pb::Algorithm) -> Option<AlgorithmId> {
    use crate::pb::Algorithm;
    match alg {
        Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL => Some(AlgorithmId::Ed25519),
        Algorithm::ALGORITHM_ECDSA_SECP256R1_SHA256_RAW_RS64 => Some(AlgorithmId::EcdsaP256Sha256),
        Algorithm::ALGORITHM_UNSPECIFIED => None,
    }
}

pub fn algorithm_id_to_buffa_enum(algorithm: AlgorithmId) -> crate::pb::Algorithm {
    use crate::pb::Algorithm;
    match algorithm {
        AlgorithmId::Ed25519 => Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL,
        AlgorithmId::EcdsaP256Sha256 => Algorithm::ALGORITHM_ECDSA_SECP256R1_SHA256_RAW_RS64,
    }
}

#[cfg(test)]
mod tests {
    use super::AlgorithmId;

    #[test]
    fn yaml_str_mapping() {
        assert_eq!(
            AlgorithmId::from_yaml_str("ED25519_PUREEDDSA_RAW_RS64_CANONICAL"),
            Some(AlgorithmId::Ed25519)
        );
        assert_eq!(
            AlgorithmId::from_yaml_str("  ECDSA_SECP256R1_SHA256_RAW_RS64  "),
            Some(AlgorithmId::EcdsaP256Sha256)
        );
        assert_eq!(AlgorithmId::from_yaml_str("nope"), None);
        assert_eq!(
            AlgorithmId::from_yaml_str("ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL"),
            None,
            "protobuf-prefixed form is not a valid YAML alg"
        );
        assert_eq!(
            AlgorithmId::Ed25519.as_yaml_str(),
            "ED25519_PUREEDDSA_RAW_RS64_CANONICAL"
        );
    }

    #[test]
    fn wire_i32_mapping() {
        assert_eq!(AlgorithmId::from_i32(1), Some(AlgorithmId::Ed25519));
        assert_eq!(AlgorithmId::from_i32(2), Some(AlgorithmId::EcdsaP256Sha256));
        assert_eq!(AlgorithmId::from_i32(0), None);
        assert_eq!(AlgorithmId::from_i32(99), None);
    }

    #[test]
    fn buffa_algorithm_enum_maps_to_wire_and_back() {
        use crate::algorithm::{algorithm_id_from_buffa_enum, algorithm_id_to_buffa_enum};
        use crate::pb::Algorithm;
        assert_eq!(
            algorithm_id_from_buffa_enum(Algorithm::ALGORITHM_UNSPECIFIED),
            None
        );
        assert_eq!(
            algorithm_id_from_buffa_enum(Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL),
            Some(AlgorithmId::Ed25519)
        );
        let round =
            algorithm_id_from_buffa_enum(algorithm_id_to_buffa_enum(AlgorithmId::EcdsaP256Sha256));
        assert_eq!(round, Some(AlgorithmId::EcdsaP256Sha256));
    }
}
