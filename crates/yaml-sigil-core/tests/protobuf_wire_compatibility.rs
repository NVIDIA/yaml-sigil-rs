// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Wire-compatibility vectors characterized against the former Buffa 0.5 API.
//!
//! The stable facade must continue to decode and encode these exact vectors.

use std::panic::{AssertUnwindSafe, catch_unwind};

use yaml_sigil_core::{
    AlgorithmId, ArtifactResourceErrorKind, ArtifactResourceForm, ArtifactResourceLimits,
    pb::{
        DecodeErrorKind, SignedYamlArtifact, SignedYamlArtifactRef, YamlSigilSignature,
        YamlSigilSignatureRef,
    },
};

fn finite(maximum: usize) -> ArtifactResourceLimits {
    ArtifactResourceLimits::unbounded()
        .with_max_artifact_bytes(std::num::NonZeroUsize::new(maximum).unwrap())
}

fn assert_points_into(input: &[u8], borrowed: &[u8]) {
    let input_start = input.as_ptr() as usize;
    let input_end = input_start + input.len();
    let borrowed_start = borrowed.as_ptr() as usize;
    let borrowed_end = borrowed_start + borrowed.len();
    assert!(borrowed_start >= input_start);
    assert!(borrowed_end <= input_end);
}

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
        .signature()
        .expect("characterized artifact has a signature message")
}

#[test]
fn facade_decodes_buffa_0_5_known_algorithms_and_optional_keyids() {
    for (wire_value, algorithm) in [(1, AlgorithmId::Ed25519), (2, AlgorithmId::EcdsaP256Sha256)] {
        for keyid in [None, Some(""), Some("key-1")] {
            let carrier = signature_wire(wire_value, keyid, &[1, 2, 3]);
            let wire = artifact_wire(b"message\n", Some(&carrier));
            let decoded = SignedYamlArtifact::decode_from_slice(&wire).unwrap();
            let signature = decoded_signature(&decoded);

            assert_eq!(decoded.payload(), b"message\n");
            assert_eq!(signature.algorithm(), Some(algorithm));
            assert_eq!(signature.keyid(), keyid);
            assert_eq!(signature.signature(), [1, 2, 3]);
            assert_eq!(decoded.encode_to_vec().unwrap(), wire);
        }
    }
}

#[test]
fn facade_preserves_buffa_0_5_unknown_algorithm_numbers() {
    for wire_value in [99, -1] {
        let carrier = signature_wire(wire_value, None, &[0xaa]);
        let wire = artifact_wire(b"payload", Some(&carrier));
        let decoded = SignedYamlArtifact::decode_from_slice(&wire).unwrap();

        assert_eq!(decoded_signature(&decoded).algorithm(), None);
        assert_eq!(
            decoded_signature(&decoded).algorithm_wire_value(),
            wire_value
        );
        assert_eq!(decoded.encode_to_vec().unwrap(), wire);
    }
}

#[test]
fn facade_accepts_buffa_0_5_arbitrary_payload_and_absent_signature() {
    let payload = [0xff, 0x00, 0x80, b'\n'];
    let with_signature = artifact_wire(&payload, Some(&signature_wire(1, None, &[7])));
    let decoded = SignedYamlArtifact::decode_from_slice(&with_signature).unwrap();
    assert_eq!(decoded.payload(), payload);

    let without_signature = artifact_wire(&payload, None);
    let decoded = SignedYamlArtifact::decode_from_slice(&without_signature).unwrap();
    assert_eq!(decoded.payload(), payload);
    assert!(decoded.signature().is_none());
    assert_eq!(decoded.encode_to_vec().unwrap(), without_signature);
}

#[test]
fn facade_matches_buffa_0_5_duplicate_singular_field_merging() {
    let mut wire = Vec::new();
    push_len_field(&mut wire, 1, b"first");
    push_len_field(&mut wire, 1, b"second");
    push_len_field(&mut wire, 2, &signature_wire(1, Some("retained"), &[]));
    push_len_field(&mut wire, 2, &signature_wire(2, None, &[9, 8, 7]));

    let decoded = SignedYamlArtifact::decode_from_slice(&wire).unwrap();
    let signature = decoded_signature(&decoded);
    assert_eq!(decoded.payload(), b"second");
    assert_eq!(signature.algorithm_wire_value(), 2);
    assert_eq!(signature.keyid(), Some("retained"));
    assert_eq!(signature.signature(), [9, 8, 7]);

    let expected = artifact_wire(
        b"second",
        Some(&signature_wire(2, Some("retained"), &[9, 8, 7])),
    );
    assert_eq!(decoded.encode_to_vec().unwrap(), expected);
}

#[test]
fn facade_preserves_buffa_0_5_unknown_wire_types_and_nested_groups() {
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
    assert!(decoded.has_unknown_fields());
    assert_eq!(decoded.encode_to_vec().unwrap(), wire);

    let borrowed = SignedYamlArtifactRef::decode(&wire).unwrap();
    assert!(borrowed.has_unknown_fields());
    assert_eq!(borrowed.encode_to_vec().unwrap(), wire);
    assert_eq!(decoded.encoded_len().unwrap(), wire.len());
    assert_eq!(borrowed.encoded_len().unwrap(), wire.len());

    assert_eq!(
        decoded
            .encode_to_vec_with_resource_limits(&finite(wire.len()))
            .unwrap()
            .unwrap(),
        wire
    );
    assert_eq!(
        borrowed
            .encode_to_vec_with_resource_limits(&finite(wire.len()))
            .unwrap()
            .unwrap(),
        wire
    );

    let mut discarded = borrowed.to_owned().unwrap();
    discarded.discard_unknown_fields();
    assert!(!discarded.has_unknown_fields());
    assert_eq!(
        discarded.encode_to_vec().unwrap(),
        artifact_wire(b"payload", Some(&signature_wire(1, None, &[1])))
    );
}

#[test]
fn facade_resource_decode_rejects_before_every_malformed_wire_shape() {
    let inputs = [
        vec![0x80, 0x00],
        vec![0x80; 11],
        vec![0x00, 0x00],
        vec![0x0f, 0x00],
        vec![0x56, 0x00],
        vec![0x53, 0x5c],
        vec![0x0a, 0x80],
        {
            let mut duplicate = artifact_wire(b"a", None);
            duplicate.extend_from_slice(&artifact_wire(b"b", None));
            duplicate
        },
        {
            let mut unknown_group = Vec::new();
            push_tag(&mut unknown_group, 10, 3);
            push_varint_field(&mut unknown_group, 1, 1);
            push_tag(&mut unknown_group, 10, 4);
            unknown_group
        },
    ];
    let limits = finite(1);
    for input in inputs {
        let owned = SignedYamlArtifact::decode_with_resource_limits(&input, &limits).unwrap_err();
        let borrowed =
            SignedYamlArtifactRef::decode_with_resource_limits(&input, &limits).unwrap_err();
        for error in [owned, borrowed] {
            assert_eq!(
                error.kind(),
                ArtifactResourceErrorKind::InputArtifactTooLarge
            );
            assert_eq!(error.artifact_form(), Some(ArtifactResourceForm::Protobuf));
            assert_eq!(
                error.observed_or_projected_artifact_bytes(),
                Some(input.len())
            );
        }
    }
}

#[test]
fn facade_sizing_matches_owned_and_borrowed_emission_at_varint_boundaries() {
    for payload_len in [0, 1, 127, 128, 16_383, 16_384] {
        let signature = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![7; 64]);
        let artifact = SignedYamlArtifact::new(vec![0xa5; payload_len], Some(signature));
        let owned_wire = artifact.encode_to_vec().unwrap();
        assert_eq!(artifact.encoded_len().unwrap(), owned_wire.len());
        assert_eq!(
            artifact
                .encode_to_vec_with_resource_limits(&finite(owned_wire.len()))
                .unwrap()
                .unwrap(),
            owned_wire
        );

        let borrowed = SignedYamlArtifactRef::decode(&owned_wire).unwrap();
        let borrowed_wire = borrowed.encode_to_vec().unwrap();
        assert_eq!(borrowed.encoded_len().unwrap(), borrowed_wire.len());
        assert_eq!(
            borrowed
                .encode_to_vec_with_resource_limits(&finite(borrowed_wire.len()))
                .unwrap()
                .unwrap(),
            borrowed_wire
        );
    }
}

#[test]
fn owned_and_borrowed_unknown_varint_sizes_follow_their_actual_output() {
    let mut wire = artifact_wire(b"payload", None);
    push_tag(&mut wire, 10, 0);
    wire.extend_from_slice(&[0x81, 0x00]);

    let owned = SignedYamlArtifact::decode(&wire).unwrap();
    let borrowed = SignedYamlArtifactRef::decode(&wire).unwrap();
    let owned_wire = owned.encode_to_vec().unwrap();
    let borrowed_wire = borrowed.encode_to_vec().unwrap();
    assert_eq!(owned_wire.last(), Some(&1));
    assert_eq!(borrowed_wire, wire);
    assert_eq!(owned.encoded_len().unwrap(), owned_wire.len());
    assert_eq!(borrowed.encoded_len().unwrap(), borrowed_wire.len());
    assert_eq!(borrowed_wire.len(), owned_wire.len() + 1);
}

#[test]
fn facade_rejects_buffa_0_5_malformed_corpus_without_panicking() {
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
        for decode in [SignedYamlArtifact::decode as fn(&[u8]) -> _, |input| {
            SignedYamlArtifactRef::decode(input).map(|_| SignedYamlArtifact::default())
        }] {
            let decoded = catch_unwind(AssertUnwindSafe(|| decode(&wire)));
            assert!(decoded.is_ok(), "decoder panicked for {wire:02x?}");
            assert!(
                decoded.unwrap().is_err(),
                "decoder accepted malformed input {wire:02x?}"
            );
        }
    }
}

#[test]
fn facade_reports_stable_error_categories() {
    let cases = [
        (&[0x80][..], DecodeErrorKind::UnexpectedEnd),
        (&[0x80; 11][..], DecodeErrorKind::InvalidVarint),
        (&[0x00][..], DecodeErrorKind::InvalidFieldNumber),
        (&[0x0f][..], DecodeErrorKind::InvalidWireType),
        (&[0x08, 0x00][..], DecodeErrorKind::UnexpectedWireType),
        (&[0x53, 0x5c][..], DecodeErrorKind::InvalidGroup),
    ];

    for (wire, expected) in cases {
        assert_eq!(
            SignedYamlArtifact::decode(wire).unwrap_err().kind(),
            expected
        );
        assert_eq!(
            SignedYamlArtifactRef::decode(wire).unwrap_err().kind(),
            expected
        );
    }

    let invalid_keyid = [0x12, 0x01, 0xff];
    assert_eq!(
        YamlSigilSignature::decode(&invalid_keyid)
            .unwrap_err()
            .kind(),
        DecodeErrorKind::InvalidUtf8
    );
    assert_eq!(
        YamlSigilSignatureRef::decode(&invalid_keyid)
            .unwrap_err()
            .kind(),
        DecodeErrorKind::InvalidUtf8
    );
}

#[test]
fn facade_construction_matches_buffa_0_5_generated_wire() {
    let mut signature = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
    signature.set_keyid(Some("key-1".to_owned()));
    let artifact = SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature));

    assert_eq!(
        artifact.encode_to_vec().unwrap(),
        artifact_wire(
            b"message\n",
            Some(&signature_wire(1, Some("key-1"), &[1, 2, 3])),
        )
    );
}

#[test]
fn borrowed_views_reference_the_input_and_convert_directly_to_owned() {
    let carrier = signature_wire(1, Some("key-1"), &[1, 2, 3]);
    let wire = artifact_wire(b"message\n", Some(&carrier));
    let borrowed = SignedYamlArtifactRef::decode_with_resource_limits(
        &wire,
        &ArtifactResourceLimits::default(),
    )
    .unwrap()
    .unwrap();
    let signature = borrowed.signature().unwrap();

    assert_points_into(&wire, borrowed.payload());
    assert_points_into(&wire, signature.keyid().unwrap().as_bytes());
    assert_points_into(&wire, signature.signature());

    let owned = borrowed.to_owned().unwrap();
    assert_eq!(owned.payload(), borrowed.payload());
    assert_eq!(
        owned.signature().unwrap().signature(),
        signature.signature()
    );
    let input_start = wire.as_ptr() as usize;
    let input_end = input_start + wire.len();
    let owned_payload = owned.payload().as_ptr() as usize;
    assert!(owned_payload < input_start || owned_payload >= input_end);

    let direct = YamlSigilSignatureRef::decode_from_slice(&carrier).unwrap();
    assert_points_into(&carrier, direct.keyid().unwrap().as_bytes());
    assert_points_into(&carrier, direct.signature());
}

#[test]
fn preallocated_encoding_appends_without_reallocation() {
    let mut signature = YamlSigilSignature::new(AlgorithmId::Ed25519, vec![1, 2, 3]);
    signature.set_keyid(Some("key-1".to_owned()));
    let artifact = SignedYamlArtifact::new(b"message\n".to_vec(), Some(signature));
    let wire = artifact.encode_to_vec().unwrap();
    assert_eq!(artifact.encoded_len().unwrap(), wire.len());

    let prefix = [0xaa, 0xbb];
    let mut owned_output = Vec::with_capacity(prefix.len() + wire.len());
    owned_output.extend_from_slice(&prefix);
    let owned_allocation = owned_output.as_ptr();
    artifact.encode_into(&mut owned_output).unwrap();
    assert_eq!(owned_output.as_ptr(), owned_allocation);
    assert_eq!(&owned_output[..prefix.len()], &prefix);
    assert_eq!(&owned_output[prefix.len()..], wire);

    let borrowed = SignedYamlArtifactRef::decode(&wire).unwrap();
    let mut borrowed_output = Vec::with_capacity(prefix.len() + wire.len());
    borrowed_output.extend_from_slice(&prefix);
    let borrowed_allocation = borrowed_output.as_ptr();
    borrowed.encode_into(&mut borrowed_output).unwrap();
    assert_eq!(borrowed_output.as_ptr(), borrowed_allocation);
    assert_eq!(&borrowed_output[..prefix.len()], &prefix);
    assert_eq!(&borrowed_output[prefix.len()..], wire);

    let mut resource_output = Vec::with_capacity(prefix.len() + wire.len());
    resource_output.extend_from_slice(&prefix);
    let allocation = resource_output.as_ptr();
    artifact
        .encode_into_with_resource_limits(&mut resource_output, &finite(wire.len()))
        .unwrap()
        .unwrap();
    assert_eq!(resource_output.as_ptr(), allocation);
    assert_eq!(&resource_output[..prefix.len()], &prefix);
    assert_eq!(&resource_output[prefix.len()..], wire);

    let mut rejected = Vec::with_capacity(prefix.len() + wire.len());
    rejected.extend_from_slice(&prefix);
    let before = rejected.clone();
    let error = borrowed
        .encode_into_with_resource_limits(&mut rejected, &finite(wire.len() - 1))
        .unwrap_err();
    assert_eq!(
        error.kind(),
        ArtifactResourceErrorKind::OutputArtifactTooLarge
    );
    assert_eq!(
        error.observed_or_projected_artifact_bytes(),
        Some(wire.len())
    );
    assert_eq!(rejected, before);
}
