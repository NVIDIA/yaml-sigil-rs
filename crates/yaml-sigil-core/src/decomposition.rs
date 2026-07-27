// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Artifact decomposition for the signed YAML stream envelope.

use std::ops::Range;

/// Successful split of an artifact into payload and signature-document byte ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRanges {
    pub payload: Range<usize>,
    /// Marker-inclusive YAML signature document `[M, |A|)`.
    pub signature_document: Range<usize>,
    /// Markerless signature carrier `[T, |A|)` for the Transcription API boundary.
    pub signature_carrier: Range<usize>,
}

/// Outcome of the decomposition pass (parser-independent byte scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecompositionOutcome {
    /// No signing attempt (`|A| = 0` or no constrained marker).
    Unsigned,
    /// Structural failure before YAML/crypto (encoding, BOM, marker rules, etc.).
    Malformed,
    /// Payload and signature-document ranges; signature body is non-empty per spec.
    Signed(SignatureRanges),
}

fn utf8_ok(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok()
}

fn bom_at_zero(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF
}

/// Returns true if `idx` is a line-start index in `bytes` (LF or CRLF aware).
fn is_line_start(bytes: &[u8], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    if idx > bytes.len() {
        return false;
    }
    // Line start is offset 0 or the byte immediately following a line terminator.
    // LF: previous is 0x0A
    let prev = bytes[idx - 1];
    if prev == 0x0A {
        return true;
    }
    false
}

/// Constrained marker at `i`: `---` at line start, followed by LF or CRLF.
fn marker_len(bytes: &[u8], i: usize) -> Option<usize> {
    if i + 3 > bytes.len() {
        return None;
    }
    if bytes[i] != b'-' || bytes[i + 1] != b'-' || bytes[i + 2] != b'-' {
        return None;
    }
    if !is_line_start(bytes, i) {
        return None;
    }
    // No trailing octets between third `-` and terminator
    if i + 3 >= bytes.len() {
        return None;
    }
    match bytes[i + 3] {
        b'\n' => Some(4),
        b'\r' if i + 5 <= bytes.len() && bytes[i + 4] == b'\n' => Some(5),
        _ => None,
    }
}

fn collect_markers(bytes: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(len) = marker_len(bytes, i) {
            out.push(i);
            i = i.saturating_add(len);
            continue;
        }
        i += 1;
    }
    out
}

/// Run Artifact Decomposition on UTF-8 artifact bytes (no prior YAML parse).
#[tracing::instrument(level = "debug", skip(artifact), fields(len = artifact.len()))]
pub fn decompose_artifact(artifact: &[u8]) -> DecompositionOutcome {
    if !utf8_ok(artifact) || bom_at_zero(artifact) {
        return DecompositionOutcome::Malformed;
    }
    if artifact.is_empty() {
        return DecompositionOutcome::Unsigned;
    }

    let markers = collect_markers(artifact);
    if markers.is_empty() {
        return DecompositionOutcome::Unsigned;
    }

    let m = *markers.iter().max().expect("non-empty");
    let marker_tail = match marker_len(artifact, m) {
        Some(len) => len,
        None => return DecompositionOutcome::Malformed,
    };
    let t = m + marker_tail;
    if t > artifact.len() {
        return DecompositionOutcome::Malformed;
    }
    if t == artifact.len() {
        return DecompositionOutcome::Malformed;
    }
    DecompositionOutcome::Signed(SignatureRanges {
        payload: 0..m,
        signature_document: m..artifact.len(),
        signature_carrier: t..artifact.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_unsigned() {
        assert_eq!(decompose_artifact(b""), DecompositionOutcome::Unsigned);
    }

    #[test]
    fn no_marker_unsigned() {
        assert_eq!(
            decompose_artifact(b"hello: world\n"),
            DecompositionOutcome::Unsigned
        );
    }

    #[test]
    fn bom_malformed() {
        let mut v = vec![0xEF, 0xBB, 0xBF];
        v.extend_from_slice(b"a: 1\n");
        assert_eq!(decompose_artifact(&v), DecompositionOutcome::Malformed);
    }

    #[test]
    fn signed_split() {
        let a = b"foo: bar\n---\nschema: YamlSigilSignature.v1alpha1\n\
                  alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: eA\n";
        let r = decompose_artifact(a);
        match r {
            DecompositionOutcome::Signed(s) => {
                assert_eq!(&a[s.payload], b"foo: bar\n");
                assert_eq!(
                    &a[s.signature_document],
                    b"---\nschema: YamlSigilSignature.v1alpha1\n\
                      alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: eA\n"
                );
                assert_eq!(
                    &a[s.signature_carrier],
                    b"schema: YamlSigilSignature.v1alpha1\n\
                      alg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: eA\n"
                );
            }
            _ => panic!("{r:?}"),
        }
    }
}
