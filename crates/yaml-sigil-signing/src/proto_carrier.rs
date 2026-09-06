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
    let mut message = yaml_sigil_core::pb::YamlSigilSignature::new(algorithm, signature);
    message.set_keyid(keyid);
    message
        .encode_to_vec()
        .expect("validated YamlSigil signature fields fit the protobuf size ceiling")
}
