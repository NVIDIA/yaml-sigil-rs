// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Protobuf outer-envelope conformance probes (`proto.*` probe IDs).

use yaml_sigil_core::{
    OuterConformance, ProtoOuterDecomposeOutcome, compose_proto_outer, decompose_proto_outer,
};

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn write_len_delimited_field(out: &mut Vec<u8>, field_number: u64, value: &[u8]) {
    let tag = (field_number << 3) | 2;
    write_varint(out, tag);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

#[test]
fn roundtrip_opaque_carrier() {
    let inner = b"inner-carrier-bytes";
    let wire = compose_proto_outer(b"k: v\n", inner);
    match decompose_proto_outer(&wire, OuterConformance::Strict) {
        ProtoOuterDecomposeOutcome::Ok {
            payload,
            signature_carrier,
        } => {
            assert_eq!(payload, b"k: v\n");
            assert_eq!(signature_carrier, inner);
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn duplicate_signature_malformed() {
    let mut wire = Vec::new();
    write_len_delimited_field(&mut wire, 1, b"p\n");
    write_len_delimited_field(&mut wire, 2, b"a");
    write_len_delimited_field(&mut wire, 2, b"b");
    assert_eq!(
        decompose_proto_outer(&wire, OuterConformance::SignatureStrict),
        ProtoOuterDecomposeOutcome::Malformed
    );
}

#[test]
fn missing_signature_malformed() {
    let mut wire = Vec::new();
    write_len_delimited_field(&mut wire, 1, b"p\n");
    assert_eq!(
        decompose_proto_outer(&wire, OuterConformance::Strict),
        ProtoOuterDecomposeOutcome::Malformed
    );
}

#[test]
fn duplicate_payload_strict() {
    let mut wire = Vec::new();
    write_len_delimited_field(&mut wire, 1, b"first\n");
    write_len_delimited_field(&mut wire, 1, b"second\n");
    write_len_delimited_field(&mut wire, 2, b"sig");
    assert_eq!(
        decompose_proto_outer(&wire, OuterConformance::Strict),
        ProtoOuterDecomposeOutcome::Malformed
    );
}

#[test]
fn unknown_outer_field_strict() {
    let mut wire = Vec::new();
    write_len_delimited_field(&mut wire, 1, b"p\n");
    write_len_delimited_field(&mut wire, 2, b"sig");
    write_len_delimited_field(&mut wire, 99, b"unknown");
    assert_eq!(
        decompose_proto_outer(&wire, OuterConformance::Strict),
        ProtoOuterDecomposeOutcome::Malformed
    );
}

#[test]
fn last_payload_wins() {
    let mut wire = Vec::new();
    write_len_delimited_field(&mut wire, 1, b"first\n");
    write_len_delimited_field(&mut wire, 1, b"second\n");
    write_len_delimited_field(&mut wire, 2, b"sig");
    match decompose_proto_outer(&wire, OuterConformance::SignatureStrict) {
        ProtoOuterDecomposeOutcome::Ok {
            payload,
            signature_carrier,
        } => {
            assert_eq!(payload, b"second\n");
            assert_eq!(signature_carrier, b"sig");
        }
        o => panic!("{o:?}"),
    }
}

#[test]
fn invalid_outer_field_numbers_are_malformed() {
    for field_number in [0, (1_u64 << 29) + 1, (1_u64 << 32) + 1] {
        let mut wire = Vec::new();
        write_len_delimited_field(&mut wire, 1, b"signed\n");
        write_len_delimited_field(&mut wire, 2, b"sig");
        write_len_delimited_field(&mut wire, field_number, b"attacker\n");
        assert_eq!(
            decompose_proto_outer(&wire, OuterConformance::SignatureStrict),
            ProtoOuterDecomposeOutcome::Malformed,
            "field number {field_number} must be rejected"
        );
    }
}

#[test]
fn overflowing_tenth_tag_varint_byte_is_malformed() {
    let mut wire = vec![0x8a];
    wire.extend_from_slice(&[0x80; 8]);
    wire.push(0x02);
    wire.extend_from_slice(&[0x01, b'p']);
    write_len_delimited_field(&mut wire, 2, b"sig");

    assert_eq!(
        decompose_proto_outer(&wire, OuterConformance::SignatureStrict),
        ProtoOuterDecomposeOutcome::Malformed
    );
}

#[test]
fn oversized_known_field_length_is_malformed_on_every_pointer_width() {
    let mut wire = Vec::new();
    write_varint(&mut wire, (1 << 3) | 2);
    write_varint(&mut wire, (1_u64 << 32) + 5);
    wire.extend_from_slice(b"short");
    write_len_delimited_field(&mut wire, 2, b"sig");

    assert_eq!(
        decompose_proto_outer(&wire, OuterConformance::SignatureStrict),
        ProtoOuterDecomposeOutcome::Malformed
    );
}

#[test]
fn oversized_unknown_field_length_is_malformed_on_every_pointer_width() {
    let mut wire = Vec::new();
    write_varint(&mut wire, (99 << 3) | 2);
    write_varint(&mut wire, (1_u64 << 32) + 5);
    wire.extend_from_slice(b"short");
    write_len_delimited_field(&mut wire, 1, b"payload\n");
    write_len_delimited_field(&mut wire, 2, b"sig");

    assert_eq!(
        decompose_proto_outer(&wire, OuterConformance::SignatureStrict),
        ProtoOuterDecomposeOutcome::Malformed
    );
}
