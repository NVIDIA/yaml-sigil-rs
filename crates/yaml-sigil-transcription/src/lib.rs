// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YamlSigil v1alpha1 Transcription API: bytes-only Compose / Decompose.

use tracing::instrument;
use yaml_sigil_core::{
    DecompositionOutcome, ProtoOuterDecomposeOutcome, compose_proto_outer, decompose_artifact,
    decompose_proto_outer, validate_payload_stream,
};

pub use yaml_sigil_traits::OuterConformance;

// The `Transcriber` / `AsyncTranscriber` trait pair and the Compose / Decompose
// DTOs now live in `yaml-sigil-traits`; re-exported here so existing
// `yaml_sigil_transcription::{Transcriber, ComposeRequest, ...}` paths keep working.
pub use yaml_sigil_traits::transcription::{
    AbstractArtifact, AsyncTranscriber, ComposeOutcome, ComposeRequest, ComposeSuccess,
    DecomposeOutcome, DecomposeRequest, DecomposeResponse, DecomposeStructuralResult, Transcriber,
    TranscriberCapabilities, TranscriberError, TranscriberInvocationError, TranscriptionForm,
};

/// Return the capability set for this build.
pub fn transcriber_capabilities() -> TranscriberCapabilities {
    TranscriberCapabilities {
        supported_forms: &[TranscriptionForm::Yaml, TranscriptionForm::Protobuf],
        supported_outer_conformances: &[
            OuterConformance::Strict,
            OuterConformance::SignatureStrict,
        ],
        emits_canonical_yaml_envelope: true,
        implementation_name: env!("CARGO_PKG_NAME"),
        implementation_version: env!("CARGO_PKG_VERSION"),
    }
}

fn validate_compose_invocation(req: &ComposeRequest<'_>) -> Result<(), TranscriberInvocationError> {
    let caps = transcriber_capabilities();
    if !caps.supported_forms.contains(&req.form) {
        return Err(TranscriberInvocationError::InvalidOrUnsupportedForm);
    }
    Ok(())
}

fn validate_decompose_invocation(
    req: &DecomposeRequest<'_>,
) -> Result<OuterConformance, TranscriberInvocationError> {
    let caps = transcriber_capabilities();
    if !caps.supported_forms.contains(&req.form) {
        return Err(TranscriberInvocationError::InvalidOrUnsupportedForm);
    }
    match req.form {
        TranscriptionForm::Yaml => {
            if req.outer_conformance.is_some() {
                return Err(TranscriberInvocationError::InvalidOrUnsupportedOuterConformance);
            }
            Ok(OuterConformance::Strict) // unused for YAML
        }
        TranscriptionForm::Protobuf => {
            let oc = req
                .outer_conformance
                .ok_or(TranscriberInvocationError::InvalidOrUnsupportedOuterConformance)?;
            if !caps.supported_outer_conformances.contains(&oc) {
                return Err(TranscriberInvocationError::InvalidOrUnsupportedOuterConformance);
            }
            Ok(oc)
        }
    }
}

fn contains_constrained_marker(carrier: &[u8]) -> bool {
    carrier.starts_with(b"---\n")
        || carrier.starts_with(b"---\r\n")
        || carrier.windows(5).any(|window| window == b"\n---\n")
        || carrier.windows(6).any(|window| window == b"\n---\r\n")
}

/// Assemble envelope-form bytes from an abstract Artifact.
#[instrument(level = "info", skip(req), fields(form = ?req.form))]
pub fn compose(req: &ComposeRequest<'_>) -> ComposeOutcome {
    if let Err(e) = validate_compose_invocation(req) {
        return ComposeOutcome::Invocation(e);
    }
    let artifact = match req.form {
        TranscriptionForm::Yaml => {
            if validate_payload_stream(req.payload).is_err() {
                return ComposeOutcome::Error(TranscriberError::InvalidPayloadBytes);
            }
            if contains_constrained_marker(req.signature_carrier) {
                return ComposeOutcome::Error(TranscriberError::InvalidSignatureCarrier);
            }
            let mut out = req.payload.to_vec();
            out.extend_from_slice(b"---\n");
            out.extend_from_slice(req.signature_carrier);
            out
        }
        TranscriptionForm::Protobuf => compose_proto_outer(req.payload, req.signature_carrier),
    };
    ComposeOutcome::Success(ComposeSuccess {
        artifact,
        form: req.form,
    })
}

/// Recover abstract Artifact bytes from an envelope.
///
/// # Resource usage
///
/// For [`TranscriptionForm::Protobuf`], this function has the resource behavior documented on
/// [`yaml_sigil_core::decompose_proto_outer`]. It imposes no universal artifact, payload, or
/// signature-carrier size limit, and it copies recognized fields into owned buffers with
/// allocation and copying linear in field size. Callers handling untrusted data must enforce
/// deployment-appropriate size limits before invocation.
#[instrument(level = "info", skip(req), fields(form = ?req.form))]
pub fn decompose(req: &DecomposeRequest<'_>) -> DecomposeResponse {
    let outer = match validate_decompose_invocation(req) {
        Ok(o) => o,
        Err(e) => return DecomposeResponse::Invocation(e),
    };
    match req.form {
        TranscriptionForm::Yaml => decompose_yaml(req.artifact),
        TranscriptionForm::Protobuf => decompose_proto(req.artifact, outer),
    }
}

/// In-process default transcriber that delegates to the crate's free functions.
///
/// Protobuf decomposition has the resource behavior documented on [`decompose`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultTranscriber;

impl Transcriber for DefaultTranscriber {
    fn capabilities(&self) -> TranscriberCapabilities {
        transcriber_capabilities()
    }
    fn compose(&self, req: &ComposeRequest<'_>) -> ComposeOutcome {
        compose(req)
    }
    fn decompose(&self, req: &DecomposeRequest<'_>) -> DecomposeResponse {
        decompose(req)
    }
}

/// In-process default async transcriber that delegates to the crate's free
/// functions. Bodies are `async { sync_fn(...) }` — the work is structural,
/// CPU-bound, and short.
///
/// Protobuf decomposition has the resource behavior documented on [`decompose`].
#[derive(Debug, Default, Clone, Copy)]
pub struct DefaultAsyncTranscriber;

impl AsyncTranscriber for DefaultAsyncTranscriber {
    fn capabilities(&self) -> TranscriberCapabilities {
        transcriber_capabilities()
    }
    async fn compose(&self, req: &ComposeRequest<'_>) -> ComposeOutcome {
        compose(req)
    }
    async fn decompose(&self, req: &DecomposeRequest<'_>) -> DecomposeResponse {
        decompose(req)
    }
}

#[cfg(test)]
mod trait_smoke_tests {
    use super::*;

    #[test]
    fn default_transcriber_capabilities_match_free_function() {
        let t = DefaultTranscriber;
        assert_eq!(t.capabilities(), transcriber_capabilities());
    }

    #[test]
    fn default_transcriber_compose_yaml_matches_free_function() {
        let payload = b"a: b\n";
        let carrier = b"schema: yaml-sigil/v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: \"\"\n";
        let req = ComposeRequest {
            payload,
            signature_carrier: carrier,
            form: TranscriptionForm::Yaml,
        };
        let direct = match compose(&req) {
            ComposeOutcome::Success(s) => s.artifact,
            _ => panic!("expected success"),
        };
        let via_trait = match DefaultTranscriber.compose(&req) {
            ComposeOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via trait"),
        };
        assert_eq!(direct, via_trait);
    }

    #[tokio::test]
    async fn default_async_transcriber_compose_yaml_matches_free_function() {
        let payload = b"a: b\n";
        let carrier = b"schema: yaml-sigil/v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: \"\"\n";
        let req = ComposeRequest {
            payload,
            signature_carrier: carrier,
            form: TranscriptionForm::Yaml,
        };
        let direct = match compose(&req) {
            ComposeOutcome::Success(s) => s.artifact,
            _ => panic!("expected success"),
        };
        let via_async_trait = match AsyncTranscriber::compose(&DefaultAsyncTranscriber, &req).await
        {
            ComposeOutcome::Success(s) => s.artifact,
            _ => panic!("expected success via async trait"),
        };
        assert_eq!(direct, via_async_trait);

        let composed = direct;
        let dreq = DecomposeRequest {
            artifact: &composed,
            form: TranscriptionForm::Yaml,
            outer_conformance: None,
        };
        let direct_d = match decompose(&dreq) {
            DecomposeResponse::Structural(s) => s,
            _ => panic!("expected structural"),
        };
        let via_async_d = match AsyncTranscriber::decompose(&DefaultAsyncTranscriber, &dreq).await {
            DecomposeResponse::Structural(s) => s,
            _ => panic!("expected structural via async"),
        };
        assert_eq!(direct_d.outcome, via_async_d.outcome);
        assert_eq!(direct_d.payload, via_async_d.payload);
        assert_eq!(
            AsyncTranscriber::capabilities(&DefaultAsyncTranscriber),
            transcriber_capabilities()
        );
    }
}

fn decompose_yaml(artifact: &[u8]) -> DecomposeResponse {
    match decompose_artifact(artifact) {
        DecompositionOutcome::Unsigned => {
            DecomposeResponse::Structural(DecomposeStructuralResult {
                outcome: DecomposeOutcome::Unsigned,
                payload: None,
                signature_carrier: None,
                detail: None,
            })
        }
        DecompositionOutcome::Malformed => {
            DecomposeResponse::Structural(DecomposeStructuralResult {
                outcome: DecomposeOutcome::MalformedAttemptedSigned,
                payload: None,
                signature_carrier: None,
                detail: None,
            })
        }
        DecompositionOutcome::Signed(r) => {
            DecomposeResponse::Structural(DecomposeStructuralResult {
                outcome: DecomposeOutcome::Ok,
                payload: Some(artifact[r.payload].to_vec()),
                signature_carrier: Some(artifact[r.signature_carrier].to_vec()),
                detail: None,
            })
        }
    }
}

fn decompose_proto(wire: &[u8], mode: OuterConformance) -> DecomposeResponse {
    match decompose_proto_outer(wire, mode) {
        ProtoOuterDecomposeOutcome::Malformed => {
            DecomposeResponse::Structural(DecomposeStructuralResult {
                outcome: DecomposeOutcome::MalformedAttemptedSigned,
                payload: None,
                signature_carrier: None,
                detail: None,
            })
        }
        ProtoOuterDecomposeOutcome::Ok {
            payload,
            signature_carrier,
        } => DecomposeResponse::Structural(DecomposeStructuralResult {
            outcome: DecomposeOutcome::Ok,
            payload: Some(payload),
            signature_carrier: Some(signature_carrier),
            detail: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_surface() {
        let c = transcriber_capabilities();
        assert!(c.emits_canonical_yaml_envelope);
        assert_eq!(c.supported_forms.len(), 2);
        assert_eq!(c.supported_outer_conformances.len(), 2);
    }

    #[test]
    fn yaml_compose_decompose_roundtrip() {
        let payload = b"k: v\n";
        let carrier =
            b"schema: YamlSigilSignature.v1alpha1\nalg: ED25519_PUREEDDSA_RAW_RS64_CANONICAL\nsignature: eA\n";
        let composed = match compose(&ComposeRequest {
            payload,
            signature_carrier: carrier,
            form: TranscriptionForm::Yaml,
        }) {
            ComposeOutcome::Success(s) => s.artifact,
            o => panic!("{o:?}"),
        };
        let resp = decompose(&DecomposeRequest {
            artifact: &composed,
            form: TranscriptionForm::Yaml,
            outer_conformance: None,
        });
        match resp {
            DecomposeResponse::Structural(r) => {
                assert_eq!(r.outcome, DecomposeOutcome::Ok);
                assert_eq!(r.payload.as_deref(), Some(payload as &[u8]));
                assert_eq!(r.signature_carrier.as_deref(), Some(carrier as &[u8]));
            }
            DecomposeResponse::Invocation(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn yaml_compose_rejects_marker_in_carrier() {
        let outcome = compose(&ComposeRequest {
            payload: b"k: v\n",
            signature_carrier: b"keyid: 'kid\n---\nschema: injected'\n",
            form: TranscriptionForm::Yaml,
        });
        assert!(matches!(
            outcome,
            ComposeOutcome::Error(TranscriberError::InvalidSignatureCarrier)
        ));
    }

    #[test]
    fn yaml_compose_rejects_invalid_payload_bytes() {
        let invalid_payloads: [&[u8]; 3] = [
            &[0xff, 0x00, 0x80],
            b"\xef\xbb\xbfkey: value\n",
            b"missing final line terminator",
        ];

        for payload in invalid_payloads {
            let outcome = compose(&ComposeRequest {
                payload,
                signature_carrier: b"signature carrier",
                form: TranscriptionForm::Yaml,
            });
            assert!(matches!(
                outcome,
                ComposeOutcome::Error(TranscriberError::InvalidPayloadBytes)
            ));
        }
    }

    #[test]
    fn protobuf_compose_preserves_arbitrary_payload_bytes() {
        let payloads: [&[u8]; 3] = [
            &[0xff, 0x00, 0x80],
            b"\xef\xbb\xbfkey: value\n",
            b"missing final line terminator",
        ];
        let signature_carrier = b"opaque signature carrier";

        for payload in payloads {
            let artifact = match compose(&ComposeRequest {
                payload,
                signature_carrier,
                form: TranscriptionForm::Protobuf,
            }) {
                ComposeOutcome::Success(success) => success.artifact,
                outcome => panic!("{outcome:?}"),
            };
            let response = decompose(&DecomposeRequest {
                artifact: &artifact,
                form: TranscriptionForm::Protobuf,
                outer_conformance: Some(OuterConformance::Strict),
            });

            match response {
                DecomposeResponse::Structural(result) => {
                    assert_eq!(result.outcome, DecomposeOutcome::Ok);
                    assert_eq!(result.payload.as_deref(), Some(payload));
                    assert_eq!(
                        result.signature_carrier.as_deref(),
                        Some(signature_carrier.as_slice())
                    );
                }
                DecomposeResponse::Invocation(error) => panic!("{error:?}"),
            }
        }
    }

    fn write_varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn write_len_delimited(out: &mut Vec<u8>, field_number: u32, value: &[u8]) {
        let tag = (field_number << 3) | 2;
        write_varint(out, u64::from(tag));
        write_varint(out, value.len() as u64);
        out.extend_from_slice(value);
    }

    #[test]
    fn proto_decompose_duplicate_signature_strict() {
        let mut wire = Vec::new();
        write_len_delimited(&mut wire, 1, b"p\n");
        write_len_delimited(&mut wire, 2, b"a");
        write_len_delimited(&mut wire, 2, b"b");
        let resp = decompose(&DecomposeRequest {
            artifact: &wire,
            form: TranscriptionForm::Protobuf,
            outer_conformance: Some(OuterConformance::SignatureStrict),
        });
        match resp {
            DecomposeResponse::Structural(r) => {
                assert_eq!(r.outcome, DecomposeOutcome::MalformedAttemptedSigned);
            }
            DecomposeResponse::Invocation(e) => panic!("{e:?}"),
        }
    }

    #[test]
    fn proto_decompose_unknown_outer_field_strict() {
        let mut wire = Vec::new();
        write_len_delimited(&mut wire, 1, b"p\n");
        write_len_delimited(&mut wire, 2, b"sig");
        write_len_delimited(&mut wire, 99, b"x");
        let resp = decompose(&DecomposeRequest {
            artifact: &wire,
            form: TranscriptionForm::Protobuf,
            outer_conformance: Some(OuterConformance::Strict),
        });
        match resp {
            DecomposeResponse::Structural(r) => {
                assert_eq!(r.outcome, DecomposeOutcome::MalformedAttemptedSigned);
            }
            DecomposeResponse::Invocation(e) => panic!("{e:?}"),
        }
    }
}
