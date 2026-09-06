// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Bytes-only outer `SignedYamlArtifact` compose/decompose for the Transcription API.
//!
//! Does not parse the `YamlSigilSignature` interior; returns the length-delimited body of
//! field 2 as opaque `signature_carrier` bytes.

use crate::conformance::OuterConformance;
use crate::error::CoreError;

const MAX_PROTOBUF_FIELD_NUMBER: u64 = (1 << 29) - 1;

/// Outcome of outer protobuf envelope decomposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoOuterDecomposeOutcome {
    /// Wire shape or outer-conformance violation.
    Malformed,
    /// Recovered payload and opaque signature-carrier bytes.
    Ok {
        payload: Vec<u8>,
        signature_carrier: Vec<u8>,
    },
}

fn read_varint(bytes: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    while i < bytes.len() {
        let b = bytes[i];
        i += 1;
        if shift == 63 {
            if b > 1 {
                return None;
            }
            result |= u64::from(b) << 63;
            return Some((result, i));
        }
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some((result, i));
        }
        shift += 7;
    }
    None
}

fn read_tag(bytes: &[u8], i: usize) -> Option<(u32, u32, usize)> {
    let (tag, next) = read_varint(bytes, i)?;
    let field = tag >> 3;
    if !(1..=MAX_PROTOBUF_FIELD_NUMBER).contains(&field) {
        return None;
    }
    Some((field as u32, (tag & 7) as u32, next))
}

fn read_length(bytes: &[u8], i: usize) -> Option<(usize, usize)> {
    let (length, next) = read_varint(bytes, i)?;
    Some((usize::try_from(length).ok()?, next))
}

fn write_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn write_len_delimited_field(out: &mut Vec<u8>, field_number: u32, value: &[u8]) {
    let tag = (field_number << 3) | 2;
    write_varint(out, u64::from(tag));
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn skip_field(wire_type: u32, bytes: &[u8], i: usize) -> Option<usize> {
    match wire_type {
        0 => read_varint(bytes, i).map(|(_, j)| j),
        1 => (i + 8 <= bytes.len()).then_some(i + 8),
        2 => {
            let (len, j) = read_length(bytes, i)?;
            let end = j.checked_add(len)?;
            (end <= bytes.len()).then_some(end)
        }
        5 => (i + 4 <= bytes.len()).then_some(i + 4),
        _ => None,
    }
}

/// Serialize outer `SignedYamlArtifact` with opaque `signature_carrier` as field 2 body.
pub fn compose_proto_outer(payload: &[u8], signature_carrier: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_len_delimited_field(&mut out, 1, payload);
    write_len_delimited_field(&mut out, 2, signature_carrier);
    out
}

/// Decompose outer wire bytes under the selected outer-envelope conformance mode.
///
/// # Resource usage
///
/// The library imposes no universal artifact, payload, or signature-carrier size limit.
/// Recognized fields are copied into owned buffers. Allocation and copying are linear in the
/// total size of those fields. Callers handling untrusted data must enforce
/// deployment-appropriate size limits before invoking this function.
#[tracing::instrument(level = "debug", skip(wire), fields(len = wire.len(), ?mode))]
pub fn decompose_proto_outer(wire: &[u8], mode: OuterConformance) -> ProtoOuterDecomposeOutcome {
    let mut payload: Option<Vec<u8>> = None;
    let mut payload_count = 0u32;
    let mut signature_carrier: Option<Vec<u8>> = None;
    let mut signature_count = 0u32;
    let mut i = 0usize;

    while i < wire.len() {
        let (field, wire_type, ni) = match read_tag(wire, i) {
            Some(v) => v,
            None => return ProtoOuterDecomposeOutcome::Malformed,
        };
        i = ni;

        if wire_type != 2 {
            if mode == OuterConformance::Strict {
                return ProtoOuterDecomposeOutcome::Malformed;
            }
            i = match skip_field(wire_type, wire, i) {
                Some(j) => j,
                None => return ProtoOuterDecomposeOutcome::Malformed,
            };
            continue;
        }

        let (len, ni2) = match read_length(wire, i) {
            Some(v) => v,
            None => return ProtoOuterDecomposeOutcome::Malformed,
        };
        i = ni2;
        if i.checked_add(len).is_none_or(|end| end > wire.len()) {
            return ProtoOuterDecomposeOutcome::Malformed;
        }
        let chunk = &wire[i..i + len];
        i += len;

        match field {
            1 => {
                payload_count += 1;
                if mode == OuterConformance::Strict && payload_count > 1 {
                    return ProtoOuterDecomposeOutcome::Malformed;
                }
                payload = Some(chunk.to_vec());
            }
            2 => {
                signature_count += 1;
                if signature_count > 1 {
                    return ProtoOuterDecomposeOutcome::Malformed;
                }
                signature_carrier = Some(chunk.to_vec());
            }
            _ => {
                if mode == OuterConformance::Strict {
                    return ProtoOuterDecomposeOutcome::Malformed;
                }
            }
        }
    }

    let signature_carrier = match signature_carrier {
        Some(c) => c,
        None => return ProtoOuterDecomposeOutcome::Malformed,
    };

    ProtoOuterDecomposeOutcome::Ok {
        payload: payload.unwrap_or_default(),
        signature_carrier,
    }
}

/// Decode inner `YamlSigilSignature` from opaque carrier bytes (verification metadata stage).
///
/// # Resource usage
///
/// This decoder imposes no universal signature-carrier size limit. It copies recognized fields
/// into owned buffers, so allocation and copying are linear in field size. Callers handling
/// untrusted data must enforce deployment-appropriate size limits before invocation.
pub fn decode_signature_carrier(
    carrier: &[u8],
) -> Result<crate::pb::YamlSigilSignature, CoreError> {
    use buffa::Message;
    crate::pb::YamlSigilSignature::decode_from_slice(carrier).map_err(CoreError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_opaque_carrier() {
        let inner = {
            use buffa::Message;
            let sig = crate::pb::YamlSigilSignature {
                alg: crate::pb::Algorithm::ALGORITHM_ED25519_PUREEDDSA_RAW_RS64_CANONICAL.into(),
                signature: vec![1, 2, 3],
                ..Default::default()
            };
            sig.encode_to_vec()
        };
        let wire = compose_proto_outer(b"k: v\n", &inner);
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
    fn duplicate_signature_rejected() {
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
        let only_payload = {
            let mut o = Vec::new();
            write_len_delimited_field(&mut o, 1, b"p\n");
            o
        };
        assert_eq!(
            decompose_proto_outer(&only_payload, OuterConformance::Strict),
            ProtoOuterDecomposeOutcome::Malformed
        );
    }
}
