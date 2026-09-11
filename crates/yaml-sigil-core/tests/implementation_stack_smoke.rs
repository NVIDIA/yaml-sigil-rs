// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Smoke tests for the fixed protobuf and YAML implementation stack.

use yaml_sigil_core::{
    AlgorithmId, SCHEMA_V1ALPHA1, SignatureDocument, parse_signature_document,
    serialize_signature_document,
};

fn sample_doc() -> SignatureDocument {
    SignatureDocument {
        schema: SCHEMA_V1ALPHA1.to_string(),
        alg: AlgorithmId::Ed25519.as_yaml_str().to_string(),
        keyid: None,
        signature: "Zm9v".to_string(),
    }
}

#[test]
fn capability_yaml_roundtrip() {
    let doc = sample_doc();
    let out = serialize_signature_document(&doc).unwrap();
    let parsed = parse_signature_document(out.as_bytes()).unwrap();
    assert_eq!(parsed.alg, doc.alg);
}

#[test]
fn capability_buffa_decode_encode_roundtrip() {
    use buffa::MessageField;
    use yaml_sigil_core::pb::{Algorithm, SignedYamlArtifact, YamlSigilSignature};
    use yaml_sigil_core::{decode_signed_yaml_artifact, encode_signed_yaml_artifact};

    let inner = YamlSigilSignature {
        alg: Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL.into(),
        signature: vec![1, 2, 3],
        ..Default::default()
    };
    let outer = SignedYamlArtifact {
        payload: b"k: v\n".to_vec(),
        signature: MessageField::from(inner),
        ..Default::default()
    };
    let wire = encode_signed_yaml_artifact(&outer);
    let back = decode_signed_yaml_artifact(&wire).unwrap();
    assert_eq!(back.payload, outer.payload);
}
