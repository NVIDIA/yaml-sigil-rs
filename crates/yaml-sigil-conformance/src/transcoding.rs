// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YAML ↔ protobuf transcoding suite — `fixtures/transcoding/`.
//!
//! The paired fixtures exercise base64url signature strings that YAML would
//! resolve as non-string scalars if emitted plainly. Assertions compare parsed
//! values and effective protobuf fields rather than emitted YAML bytes because
//! the carrier profile permits multiple string-scalar presentations.

use yaml_sigil_core::{
    DecompositionOutcome, ProtoArtifactView, decode_signed_yaml_artifact, decompose_artifact,
    parse_signature_document, view_signed_yaml_artifact,
};
use yaml_sigil_signing::{proto_wire_to_signed_yaml_stream, signed_yaml_stream_to_proto_wire};

use crate::fixtures::load_bytes;

const CATEGORY: &str = "transcoding";

struct TranscodingCase {
    stem: &'static str,
    signature_text: &'static str,
}

const CASES: &[TranscodingCase] = &[
    TranscodingCase {
        stem: "empty",
        signature_text: "",
    },
    TranscodingCase {
        stem: "boolean-like-true",
        signature_text: "true",
    },
    TranscodingCase {
        stem: "null-like-null",
        signature_text: "null",
    },
    TranscodingCase {
        stem: "numeric-looking-1234",
        signature_text: "1234",
    },
];

fn effective_fields(wire: &[u8]) -> ProtoArtifactView {
    let artifact = decode_signed_yaml_artifact(wire).expect("decode transcoding protobuf fixture");
    view_signed_yaml_artifact(&artifact).expect("view transcoding protobuf fixture")
}

fn assert_yaml_signature_value(yaml: &[u8], expected: &str, context: &str) {
    let DecompositionOutcome::Signed(ranges) = decompose_artifact(yaml) else {
        panic!("{context}: expected a signed YAML artifact");
    };
    let doc = parse_signature_document(&yaml[ranges.signature_carrier])
        .unwrap_or_else(|error| panic!("{context}: parse signature document: {error}"));
    assert_eq!(
        doc.signature, expected,
        "{context}: parsed signature string mismatch"
    );
}

/// Drive all paired transcoding fixtures through both round-trip directions.
pub fn run_transcoding_suite() {
    for case in CASES {
        let yaml_file = format!("{}.yaml", case.stem);
        let proto_file = format!("{}.binpb", case.stem);
        let fixture_yaml = load_bytes(CATEGORY, &yaml_file);
        let fixture_proto = load_bytes(CATEGORY, &proto_file);
        let expected_fields = effective_fields(&fixture_proto);

        assert_yaml_signature_value(&fixture_yaml, case.signature_text, &yaml_file);

        let proto_from_fixture_yaml = signed_yaml_stream_to_proto_wire(&fixture_yaml)
            .unwrap_or_else(|error| panic!("{yaml_file}: transcode to protobuf: {error}"));
        assert_eq!(
            effective_fields(&proto_from_fixture_yaml),
            expected_fields,
            "{yaml_file}: effective protobuf fields mismatch"
        );

        let yaml_from_fixture_proto = proto_wire_to_signed_yaml_stream(&fixture_proto)
            .unwrap_or_else(|error| panic!("{proto_file}: transcode to YAML: {error}"));
        assert_yaml_signature_value(
            &yaml_from_fixture_proto,
            case.signature_text,
            &format!("{proto_file} → YAML"),
        );
        let proto_round_trip = signed_yaml_stream_to_proto_wire(&yaml_from_fixture_proto)
            .unwrap_or_else(|error| panic!("{proto_file}: round-trip through YAML: {error}"));
        assert_eq!(
            effective_fields(&proto_round_trip),
            expected_fields,
            "{proto_file}: protobuf → YAML → protobuf fields mismatch"
        );

        let yaml_round_trip = proto_wire_to_signed_yaml_stream(&proto_from_fixture_yaml)
            .unwrap_or_else(|error| panic!("{yaml_file}: round-trip through protobuf: {error}"));
        assert_yaml_signature_value(
            &yaml_round_trip,
            case.signature_text,
            &format!("{yaml_file} → protobuf → YAML"),
        );
        let second_proto = signed_yaml_stream_to_proto_wire(&yaml_round_trip)
            .unwrap_or_else(|error| panic!("{yaml_file}: decode round-trip YAML: {error}"));
        assert_eq!(
            effective_fields(&second_proto),
            expected_fields,
            "{yaml_file}: YAML → protobuf → YAML fields mismatch"
        );
    }
}
