// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Key ID suite — `fixtures/key-id/`.
//! Walks 12 YAML+protobuf fixtures covering keyid absence, present-empty,
//! byte-length bounds, and multibyte boundaries.

use yaml_sigil_verification::{ArtifactForm, AsyncVerifier, PreVerifyOutcome, Verifier};

use crate::fixtures::load_bytes;

const CATEGORY: &str = "key-id";

#[derive(Debug, Clone, Copy)]
enum Expectation {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy)]
struct KeyidFixture {
    file: &'static str,
    form: ArtifactForm,
    expect: Expectation,
}

const FIXTURES: &[KeyidFixture] = &[
    KeyidFixture {
        file: "keyid-absent.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Accepted,
    },
    KeyidFixture {
        file: "keyid-absent.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Accepted,
    },
    KeyidFixture {
        file: "keyid-present-empty.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Rejected,
    },
    KeyidFixture {
        file: "keyid-present-empty.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Rejected,
    },
    KeyidFixture {
        file: "keyid-1024-ascii.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Accepted,
    },
    KeyidFixture {
        file: "keyid-1024-ascii.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Accepted,
    },
    KeyidFixture {
        file: "keyid-1025-ascii.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Rejected,
    },
    KeyidFixture {
        file: "keyid-1025-ascii.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Rejected,
    },
    KeyidFixture {
        file: "keyid-multibyte-under.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Accepted,
    },
    KeyidFixture {
        file: "keyid-multibyte-under.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Accepted,
    },
    KeyidFixture {
        file: "keyid-multibyte-over.yaml",
        form: ArtifactForm::Yaml,
        expect: Expectation::Rejected,
    },
    KeyidFixture {
        file: "keyid-multibyte-over.binpb",
        form: ArtifactForm::Proto,
        expect: Expectation::Rejected,
    },
];

pub fn run_keyid_suite<V: Verifier>(v: &V) {
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

/// Async sibling of [`run_keyid_suite`].
pub async fn run_keyid_suite_async<V: AsyncVerifier>(v: &V) {
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
