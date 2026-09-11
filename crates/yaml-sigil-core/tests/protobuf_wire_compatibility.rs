// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Wire-compatibility characterization for the Buffa 0.5 public API.
//!
//! The protobuf facade tests continue to run these exact vectors after the
//! generated implementation becomes private.

use std::panic::{AssertUnwindSafe, catch_unwind};

use buffa::{Message, MessageField};
use yaml_sigil_core::pb::{Algorithm, SignedYamlArtifact, YamlSigilSignature};

fn push_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn push_tag(out: &mut Vec<u8>, field_number: u32, wire_type: u8) {
    push_varint(out, (u64::from(field_number) << 3) | u64::from(wire_type));
}

fn push_varint_field(out: &mut Vec<u8>, field_number: u32, value: u64) {
    push_tag(out, field_number, 0);
    push_varint(out, value);
}

fn push_len_field(out: &mut Vec<u8>, field_number: u32, value: &[u8]) {
    push_tag(out, field_number, 2);
    push_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn signature_wire(algorithm_wire_value: i32, keyid: Option<&str>, signature: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    if algorithm_wire_value != 0 {
        push_varint_field(&mut wire, 1, algorithm_wire_value as u64);
    }
    if let Some(keyid) = keyid {
        push_len_field(&mut wire, 2, keyid.as_bytes());
    }
    if !signature.is_empty() {
        push_len_field(&mut wire, 3, signature);
    }
    wire
}

fn artifact_wire(payload: &[u8], signature: Option<&[u8]>) -> Vec<u8> {
    let mut wire = Vec::new();
    if !payload.is_empty() {
        push_len_field(&mut wire, 1, payload);
    }
    if let Some(signature) = signature {
        push_len_field(&mut wire, 2, signature);
    }
    wire
}

fn decoded_signature(artifact: &SignedYamlArtifact) -> &YamlSigilSignature {
    artifact
        .signature
        .as_option()
        .expect("characterized artifact has a signature message")
}

#[test]
fn buffa_0_5_decodes_known_algorithms_and_optional_keyids() {
    for (wire_value, algorithm) in [
        (1, Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL),
        (2, Algorithm::ALGORITHM_ECDSA_SECP256R1_SHA256_RAW_RS64),
    ] {
        for keyid in [None, Some(""), Some("key-1")] {
            let carrier = signature_wire(wire_value, keyid, &[1, 2, 3]);
            let wire = artifact_wire(b"message\n", Some(&carrier));
            let decoded = SignedYamlArtifact::decode_from_slice(&wire).unwrap();
            let signature = decoded_signature(&decoded);

            assert_eq!(decoded.payload, b"message\n");
            assert_eq!(signature.alg, algorithm);
            assert_eq!(signature.keyid.as_deref(), keyid);
            assert_eq!(signature.signature, [1, 2, 3]);
            assert_eq!(decoded.encode_to_vec(), wire);
        }
    }
}

#[test]
fn buffa_0_5_preserves_unknown_algorithm_numbers() {
    let carrier = signature_wire(99, None, &[0xaa]);
    let wire = artifact_wire(b"payload", Some(&carrier));
    let decoded = SignedYamlArtifact::decode_from_slice(&wire).unwrap();

    assert_eq!(decoded_signature(&decoded).alg.to_i32(), 99);
    assert_eq!(decoded.encode_to_vec(), wire);
}

#[test]
fn buffa_0_5_accepts_arbitrary_payload_and_absent_signature() {
    let payload = [0xff, 0x00, 0x80, b'\n'];
    let with_signature = artifact_wire(&payload, Some(&signature_wire(1, None, &[7])));
    let decoded = SignedYamlArtifact::decode_from_slice(&with_signature).unwrap();
    assert_eq!(decoded.payload, payload);

    let without_signature = artifact_wire(&payload, None);
    let decoded = SignedYamlArtifact::decode_from_slice(&without_signature).unwrap();
    assert_eq!(decoded.payload, payload);
    assert!(!decoded.signature.is_set());
    assert_eq!(decoded.encode_to_vec(), without_signature);
}

#[test]
fn buffa_0_5_merges_duplicate_singular_fields() {
    let mut wire = Vec::new();
    push_len_field(&mut wire, 1, b"first");
    push_len_field(&mut wire, 1, b"second");
    push_len_field(&mut wire, 2, &signature_wire(1, Some("retained"), &[]));
    push_len_field(&mut wire, 2, &signature_wire(2, None, &[9, 8, 7]));

    let decoded = SignedYamlArtifact::decode_from_slice(&wire).unwrap();
    let signature = decoded_signature(&decoded);
    assert_eq!(decoded.payload, b"second");
    assert_eq!(signature.alg.to_i32(), 2);
    assert_eq!(signature.keyid.as_deref(), Some("retained"));
    assert_eq!(signature.signature, [9, 8, 7]);

    let expected = artifact_wire(
        b"second",
        Some(&signature_wire(2, Some("retained"), &[9, 8, 7])),
    );
    assert_eq!(decoded.encode_to_vec(), expected);
}

#[test]
fn buffa_0_5_preserves_every_unknown_wire_type_and_nested_groups() {
    let mut unknown_fields = Vec::new();
    push_varint_field(&mut unknown_fields, 10, 300);

    push_tag(&mut unknown_fields, 11, 1);
    unknown_fields.extend_from_slice(&0x0123_4567_89ab_cdef_u64.to_le_bytes());

    push_len_field(&mut unknown_fields, 12, &[0x00, 0xff, 0x80]);

    push_tag(&mut unknown_fields, 13, 3);
    push_varint_field(&mut unknown_fields, 1, 42);
    push_tag(&mut unknown_fields, 14, 3);
    push_len_field(&mut unknown_fields, 2, b"nested");
    push_tag(&mut unknown_fields, 14, 4);
    push_tag(&mut unknown_fields, 13, 4);

    push_tag(&mut unknown_fields, 15, 5);
    unknown_fields.extend_from_slice(&0xdead_beef_u32.to_le_bytes());

    let mut carrier = signature_wire(1, None, &[1]);
    carrier.extend_from_slice(&unknown_fields);
    let mut wire = artifact_wire(b"payload", Some(&carrier));
    wire.extend_from_slice(&unknown_fields);

    let decoded = SignedYamlArtifact::decode_from_slice(&wire).unwrap();
    assert_eq!(decoded.encode_to_vec(), wire);
}

#[test]
fn buffa_0_5_rejects_malformed_input_without_panicking() {
    let malformed = [
        vec![0x80],
        vec![0x80; 11],
        vec![0x00],
        vec![0x56],
        vec![0x57],
        vec![0x51, 1, 2],
        vec![0x52, 3, 1],
        vec![0x55, 1],
        vec![0x53],
        vec![0x54],
        vec![0x53, 0x5c],
        vec![0x0a, 0x80],
        vec![
            0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
        ],
    ];

    for wire in malformed {
        let decoded = catch_unwind(AssertUnwindSafe(|| {
            SignedYamlArtifact::decode_from_slice(&wire)
        }));
        assert!(decoded.is_ok(), "decoder panicked for {wire:02x?}");
        assert!(
            decoded.unwrap().is_err(),
            "decoder accepted malformed input {wire:02x?}"
        );
    }
}

#[test]
fn buffa_0_5_generated_construction_matches_characterized_wire() {
    let signature = YamlSigilSignature {
        alg: Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL.into(),
        keyid: Some("key-1".to_owned()),
        signature: vec![1, 2, 3],
        ..Default::default()
    };
    let artifact = SignedYamlArtifact {
        payload: b"message\n".to_vec(),
        signature: MessageField::from(signature),
        ..Default::default()
    };

    assert_eq!(
        artifact.encode_to_vec(),
        artifact_wire(
            b"message\n",
            Some(&signature_wire(1, Some("key-1"), &[1, 2, 3])),
        )
    );
}
