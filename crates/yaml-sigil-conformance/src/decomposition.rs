// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YAML decomposition suite — drives `fixtures/yaml-decomposition/`
//! fixtures through `Transcriber::decompose` (and, where the fixture's expected
//! outcome straddles decompose → verify, through `Verifier::pre_verify` as well).
//!
//! See [`docs/conformance-validation.md`](../../docs/conformance-validation.md) § 2.

use yaml_sigil_transcription::{
    AsyncTranscriber, DecomposeOutcome, DecomposeRequest, DecomposeResponse,
    DecomposeStructuralResult, Transcriber, TranscriptionForm,
};
use yaml_sigil_verification::{ArtifactForm, AsyncVerifier, PreVerifyOutcome, Verifier};

use crate::fixtures::load_bytes;

const CATEGORY: &str = "yaml-decomposition";

/// Per-fixture spec expectation. The verifier pre-verify stage is consulted
/// when the fixture needs coverage beyond the transcription boundary.
#[derive(Debug, Clone, Copy)]
struct YamlFixture {
    file: &'static str,
    decompose: DecomposeOutcome,
    /// `None` means no verifier-stage assertion is required (the decompose
    /// outcome alone is normative).
    pre_verify: Option<PreVerifyOutcome>,
}

const FIXTURES: &[YamlFixture] = &[
    YamlFixture {
        file: "signed-single-lf.yaml",
        decompose: DecomposeOutcome::Ok,
        pre_verify: Some(PreVerifyOutcome::Ok),
    },
    YamlFixture {
        file: "signed-single-crlf.yaml",
        decompose: DecomposeOutcome::Ok,
        pre_verify: Some(PreVerifyOutcome::Ok),
    },
    YamlFixture {
        file: "signed-multi.yaml",
        decompose: DecomposeOutcome::Ok,
        pre_verify: Some(PreVerifyOutcome::Ok),
    },
    YamlFixture {
        file: "empty-payload.yaml",
        decompose: DecomposeOutcome::Ok,
        pre_verify: Some(PreVerifyOutcome::Ok),
    },
    YamlFixture {
        file: "no-marker.yaml",
        decompose: DecomposeOutcome::Unsigned,
        pre_verify: None,
    },
    YamlFixture {
        file: "extra-marker-inside-carrier.yaml",
        decompose: DecomposeOutcome::Ok,
        pre_verify: Some(PreVerifyOutcome::MetadataParseFailure),
    },
    YamlFixture {
        file: "marker-at-eof-empty-body.yaml",
        decompose: DecomposeOutcome::MalformedAttemptedSigned,
        pre_verify: None,
    },
    YamlFixture {
        file: "invalid-utf8-no-marker.yaml",
        decompose: DecomposeOutcome::MalformedAttemptedSigned,
        pre_verify: Some(PreVerifyOutcome::StructuralFailure),
    },
    YamlFixture {
        file: "invalid-utf8-before-marker.yaml",
        decompose: DecomposeOutcome::MalformedAttemptedSigned,
        pre_verify: Some(PreVerifyOutcome::StructuralFailure),
    },
    YamlFixture {
        file: "bom-signed.yaml",
        decompose: DecomposeOutcome::MalformedAttemptedSigned,
        pre_verify: Some(PreVerifyOutcome::StructuralFailure),
    },
    YamlFixture {
        file: "bom-no-marker.yaml",
        decompose: DecomposeOutcome::MalformedAttemptedSigned,
        pre_verify: Some(PreVerifyOutcome::StructuralFailure),
    },
    YamlFixture {
        file: "marker-dense.yaml",
        decompose: DecomposeOutcome::Ok,
        pre_verify: Some(PreVerifyOutcome::Ok),
    },
    YamlFixture {
        file: "document-end-in-payload.yaml",
        decompose: DecomposeOutcome::Ok,
        pre_verify: Some(PreVerifyOutcome::Ok),
    },
];

fn assert_marker_dense_split(artifact: &[u8], structural: &DecomposeStructuralResult) {
    let final_marker = artifact
        .windows(4)
        .rposition(|window| window == b"---\n")
        .expect("marker-dense fixture must contain the final marker");
    let payload = structural
        .payload
        .as_deref()
        .expect("marker-dense decompose must return payload bytes");
    let carrier = structural
        .signature_carrier
        .as_deref()
        .expect("marker-dense decompose must return carrier bytes");

    assert_eq!(
        payload.len(),
        final_marker,
        "marker-dense payload must end at the final marker"
    );
    assert_eq!(
        payload
            .windows(4)
            .filter(|window| *window == b"---\n")
            .count(),
        256,
        "marker-dense payload must retain all 256 earlier marker candidates"
    );
    assert_eq!(
        carrier,
        &artifact[final_marker + 4..],
        "marker-dense carrier must begin immediately after the final marker"
    );
    assert!(
        carrier.starts_with(b"schema: YamlSigilSignature.v1alpha1\n"),
        "marker-dense carrier must begin with the signature mapping"
    );
}

fn assert_document_end_remains_payload(structural: &DecomposeStructuralResult) {
    let payload = structural
        .payload
        .as_deref()
        .expect("document-end-in-payload decompose must return payload bytes");
    assert!(
        payload.ends_with(b"...\n"),
        "YAML document-end marker must remain in the payload"
    );
}

/// Drive every `yaml-decomposition/` fixture through the supplied
/// [`Transcriber`] and (where the spec table extends through verification's
/// metadata stage) the supplied [`Verifier`].
pub fn run_yaml_decomposition_suite<T, V>(t: &T, v: &V)
where
    T: Transcriber,
    V: Verifier,
{
    for fx in FIXTURES {
        let bytes = load_bytes(CATEGORY, fx.file);
        let resp = t.decompose(&DecomposeRequest {
            artifact: &bytes,
            form: TranscriptionForm::Yaml,
            outer_conformance: None,
        });
        let structural = match resp {
            DecomposeResponse::Structural(s) => s,
            DecomposeResponse::Invocation(e) => panic!(
                "{}/{}: unexpected invocation error {e:?}",
                CATEGORY, fx.file
            ),
        };
        assert_eq!(
            structural.outcome, fx.decompose,
            "{}/{}: DecomposeOutcome mismatch",
            CATEGORY, fx.file
        );
        if fx.file == "marker-dense.yaml" {
            assert_marker_dense_split(&bytes, &structural);
        }
        if fx.file == "document-end-in-payload.yaml" {
            assert_document_end_remains_payload(&structural);
        }

        if let Some(expected_pre) = fx.pre_verify {
            let pre = v.pre_verify(&bytes, ArtifactForm::Yaml, true, false);
            assert_eq!(
                pre.outcome, expected_pre,
                "{}/{}: PreVerifyOutcome mismatch (verifier-stage)",
                CATEGORY, fx.file
            );
        }
    }
}

/// Async sibling of [`run_yaml_decomposition_suite`].
pub async fn run_yaml_decomposition_suite_async<T, V>(t: &T, v: &V)
where
    T: AsyncTranscriber,
    V: AsyncVerifier,
{
    for fx in FIXTURES {
        let bytes = load_bytes(CATEGORY, fx.file);
        let resp = t
            .decompose(&DecomposeRequest {
                artifact: &bytes,
                form: TranscriptionForm::Yaml,
                outer_conformance: None,
            })
            .await;
        let structural = match resp {
            DecomposeResponse::Structural(s) => s,
            DecomposeResponse::Invocation(e) => panic!(
                "{}/{} (async): unexpected invocation error {e:?}",
                CATEGORY, fx.file
            ),
        };
        assert_eq!(
            structural.outcome, fx.decompose,
            "{}/{} (async): DecomposeOutcome mismatch",
            CATEGORY, fx.file
        );
        if fx.file == "marker-dense.yaml" {
            assert_marker_dense_split(&bytes, &structural);
        }
        if fx.file == "document-end-in-payload.yaml" {
            assert_document_end_remains_payload(&structural);
        }

        if let Some(expected_pre) = fx.pre_verify {
            let pre = v.pre_verify(&bytes, ArtifactForm::Yaml, true, false).await;
            assert_eq!(
                pre.outcome, expected_pre,
                "{}/{} (async): PreVerifyOutcome mismatch (verifier-stage)",
                CATEGORY, fx.file
            );
        }
    }
}
