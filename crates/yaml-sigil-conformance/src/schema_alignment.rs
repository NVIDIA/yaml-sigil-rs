// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Schema alignment suite — `fixtures/schema-alignment/`.
//! Asserts that `alg:` strings and `Algorithm` enum values our
//! `Verifier::pre_verify` accepts (or rejects with
//! `MalformedAttemptedSigned`) match the spec's mapping.

use yaml_sigil_verification::{ArtifactForm, AsyncVerifier, PreVerifyOutcome, Verifier};

use crate::fixtures::load_bytes;

const CATEGORY: &str = "schema-alignment";

/// `Accepted` means the fixture should reach the verifier's crypto stage
/// (`PreVerifyOutcome::Ok`). `Rejected` means metadata-extraction or
/// structural rejection — either flavor surfaces as
/// `VerifierState::MalformedAttemptedSigned` end-to-end.
#[derive(Debug, Clone, Copy)]
enum Expectation {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy)]
struct SchemaFixture {
    file: &'static str,
    form: ArtifactForm,
    expect: Expectation,
}

const FIXTURES: &[SchemaFixture] = &[
    // fixture: yaml-alg-ed25519.yaml -> Ok
    SchemaFixture {
        file: "yaml-alg-ed25519.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Accepted,
    },
    // fixture: yaml-alg-ecdsa.yaml -> Ok
    SchemaFixture {
        file: "yaml-alg-ecdsa.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Accepted,
    },
    // fixture: yaml-alg-unknown-string.yaml -> MalformedAttemptedSigned
    SchemaFixture {
        file: "yaml-alg-unknown-string.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Rejected,
    },
    // fixture: yaml-alg-prefixed-rejected.yaml -> MalformedAttemptedSigned
    SchemaFixture {
        file: "yaml-alg-prefixed-rejected.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Rejected,
    },
    // fixture: yaml-alg-unspecified-rejected.yaml -> MalformedAttemptedSigned
    SchemaFixture {
        file: "yaml-alg-unspecified-rejected.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Rejected,
    },
    // fixture: proto-alg-ed25519.binpb -> Ok
    SchemaFixture {
        file: "proto-alg-ed25519.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Accepted,
    },
    // fixture: proto-alg-ecdsa.binpb -> Ok
    SchemaFixture {
        file: "proto-alg-ecdsa.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Accepted,
    },
    // fixture: proto-alg-unspecified.binpb -> MalformedAttemptedSigned
    SchemaFixture {
        file: "proto-alg-unspecified.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Rejected,
    },
    // fixture: proto-alg-unknown-integer.binpb -> MalformedAttemptedSigned
    SchemaFixture {
        file: "proto-alg-unknown-integer.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Rejected,
    },
];

pub fn run_schema_alignment_suite<V: Verifier>(v: &V) {
    for fx in FIXTURES {
        let bytes = load_bytes(CATEGORY, fx.file);
        let pre = v.pre_verify(&bytes, fx.form, false, false);
        match fx.expect {
            Expectation::Accepted => assert_eq!(
                pre.outcome,
                PreVerifyOutcome::Ok,
                "{}/{}: expected Ok at pre_verify",
                CATEGORY,
                fx.file
            ),
            Expectation::Rejected => assert!(
                matches!(
                    pre.outcome,
                    PreVerifyOutcome::MetadataParseFailure | PreVerifyOutcome::StructuralFailure
                ),
                "{}/{}: expected metadata/structural rejection, got {:?}",
                CATEGORY,
                fx.file,
                pre.outcome
            ),
        }
    }
}

/// Async sibling of [`run_schema_alignment_suite`].
pub async fn run_schema_alignment_suite_async<V: AsyncVerifier>(v: &V) {
    for fx in FIXTURES {
        let bytes = load_bytes(CATEGORY, fx.file);
        let pre = v.pre_verify(&bytes, fx.form, false, false).await;
        match fx.expect {
            Expectation::Accepted => assert_eq!(
                pre.outcome,
                PreVerifyOutcome::Ok,
                "{}/{} (async): expected Ok at pre_verify",
                CATEGORY,
                fx.file
            ),
            Expectation::Rejected => assert!(
                matches!(
                    pre.outcome,
                    PreVerifyOutcome::MetadataParseFailure | PreVerifyOutcome::StructuralFailure
                ),
                "{}/{} (async): expected metadata/structural rejection, got {:?}",
                CATEGORY,
                fx.file,
                pre.outcome
            ),
        }
    }
}
