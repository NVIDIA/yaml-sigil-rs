// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Encode inner `YamlSigilSignature` protobuf bytes for outer [`compose_proto_outer`].

use yaml_sigil_traits::AlgorithmId;

/// Length-delimited body of outer field 2 (`signature` message).
pub(crate) fn encode_inner_signature_carrier(
    algorithm: AlgorithmId,
    signature: Vec<u8>,
    keyid: Option<String>,
) -> Vec<u8> {
    use buffa::Message;
    use yaml_sigil_core::pb::{Algorithm, YamlSigilSignature};
    let alg_pb = match algorithm {
        AlgorithmId::Ed25519 => Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL,
        AlgorithmId::EcdsaP256Sha256 => Algorithm::ALGORITHM_ECDSA_SECP256R1_SHA256_RAW_RS64,
    };
    YamlSigilSignature {
        alg: alg_pb.into(),
        signature,
        keyid,
        ..Default::default()
    }
    .encode_to_vec()
}
