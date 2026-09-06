// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Canonical algorithm identifiers.
//!
//! YAML `alg:` and JSON Schema use the unprefixed canonical names; the protobuf
//! wire form uses the numeric values exposed by the stable [`crate::pb`]
//! facade. `yaml-sigil-traits` owns the portable identifier.

pub use yaml_sigil_traits::AlgorithmId;

/// YAML `schema:` value for v1alpha1 signature documents.
pub const SCHEMA_V1ALPHA1: &str = "YamlSigilSignature.v1alpha1";

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
            AlgorithmId::from_yaml_str("ECDSA_SECP256R1_SHA256_RAW_RS64"),
            Some(AlgorithmId::EcdsaP256Sha256)
        );
        assert_eq!(
            AlgorithmId::from_yaml_str(" ECDSA_SECP256R1_SHA256_RAW_RS64"),
            None,
            "YAML algorithm identifiers must be exact canonical strings"
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
}
