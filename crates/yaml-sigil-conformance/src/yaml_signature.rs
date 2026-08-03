// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YAML signature-document conformance — `fixtures/yaml-signature-conformance/`.
//!
//! Drives the verifier-side rules in `verification-api.md` "Structural Rules
//! By Form" and "Conformance Profiles" as they manifest on the YAML form. The
//! suite covers the carrier byte limit, document count, mapping root, declared
//! field types, required schema identity, universal duplicate-known-key
//! rejection, and unknown-mapping-key behavior. The protobuf-form symmetric
//! profile cases live in
//! [`proto_outer`](super::proto_outer).
//!
//! The suite is profile-parameterized: the assertions depend on the
//! verifier's advertised
//! [`AdvertisedConformanceProfile`].
//! Duplicate known keys and oversized carriers reject under every profile.
//! The Permissive branch also asserts this implementation's documented
//! stricter behavior for `unknown-key.yaml`.
//! See [`docs/conformance-validation.md`](../../docs/conformance-validation.md)
//! for the per-fixture mapping and implementation-specific parser bounds.

use ed25519_dalek::{SigningKey as EdSk, VerifyingKey as EdVk};
use yaml_sigil_verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, PreVerifyOutcome, PublicKeys,
    Verifier, VerifierOptions, VerifierState,
};

use crate::fixtures::load_bytes;

const CATEGORY: &str = "yaml-signature-conformance";

const UNIVERSAL_METADATA_FAILURES: &[&str] = &[
    "wrong-schema.yaml",
    "missing-schema.yaml",
    "duplicate-schema.yaml",
    "duplicate-alg.yaml",
    "duplicate-keyid.yaml",
    "duplicate-signature.yaml",
    "oversized-carrier.yaml",
    "document-end-with-second-document.yaml",
    "non-mapping-root.yaml",
    "non-string-schema.yaml",
    "non-string-alg.yaml",
    "non-string-keyid.yaml",
    "non-string-signature.yaml",
];

fn placeholder_keys() -> EdVk {
    // Fixtures that reach crypto carry the canonical 86-char placeholder
    // signature (URL-safe-unpadded base64 of 64 zero bytes). Any well-formed
    // Ed25519 public key suffices for the keyring; the placeholder signature
    // lands at `SignedButFailedVerification` because it cannot authenticate
    // against a real key.
    EdSk::from_bytes(&[1u8; 32]).verifying_key()
}

fn verify_with<V: Verifier>(v: &V, file: &str, opts: VerifierOptions) -> VerifierState {
    let bytes = load_bytes(CATEGORY, file);
    let vk = placeholder_keys();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    v.verify(&bytes, ArtifactForm::Yaml, &keys, opts)
        .unwrap_or_else(|e| {
            panic!(
                "{}/{}: unexpected invocation error {e:?} (suite expects only state values)",
                CATEGORY, file
            )
        })
}

/// Drive the sixteen `yaml-signature-conformance/` fixtures through the supplied
/// [`Verifier`]; the assertion table depends on the verifier's advertised
/// [`AdvertisedConformanceProfile`].
pub fn run_yaml_signature_suite<V: Verifier>(v: &V) {
    assert_universal_metadata_failures(v);

    let profile = v.capabilities().conformance_profile;
    match profile {
        AdvertisedConformanceProfile::Strict | AdvertisedConformanceProfile::SignatureStrict => {
            assert_strict_column(v)
        }
        AdvertisedConformanceProfile::Permissive => assert_permissive_column(v),
    }
}

fn assert_universal_metadata_failures<V: Verifier>(v: &V) {
    for file in UNIVERSAL_METADATA_FAILURES {
        let bytes = load_bytes(CATEGORY, file);
        let pre = v.pre_verify(&bytes, ArtifactForm::Yaml, false, false);
        assert_eq!(
            pre.outcome,
            PreVerifyOutcome::MetadataParseFailure,
            "{CATEGORY}/{file}: expected MetadataParseFailure at pre_verify, got {:?}",
            pre.outcome
        );

        let st = verify_with(v, file, VerifierOptions::default());
        assert_eq!(
            st,
            VerifierState::MalformedAttemptedSigned,
            "{CATEGORY}/{file}: expected MalformedAttemptedSigned at verify, got {st:?}"
        );
    }
}

/// Drive the Strict / SignatureStrict column of the fixture table.
///
/// The two profiles share the same expected outcomes for every fixture in
/// this directory. The fixture README's "Strict outcome" and "SignatureStrict
/// outcome" columns are identical for all sixteen entries, so a single assertion
/// routine covers both.
fn assert_strict_column<V: Verifier>(v: &V) {
    let strict_opts = VerifierOptions {
        reject_unknown_signature_document_fields: true,
        ..VerifierOptions::default()
    };

    // Both accepted carriers reach crypto, where the placeholder all-zero
    // signature fails to authenticate.
    for file in ["valid-baseline.yaml", "document-end-at-eof.yaml"] {
        let st = verify_with(v, file, strict_opts.clone());
        assert_eq!(
            st,
            VerifierState::SignedButFailedVerification,
            "{file} (Strict): expected SignedButFailedVerification, got {st:?}"
        );
    }

    // unknown-key: the extra `bogus` mapping key must be rejected.
    let st = verify_with(v, "unknown-key.yaml", strict_opts);
    assert_eq!(
        st,
        VerifierState::MalformedAttemptedSigned,
        "unknown-key.yaml (Strict): expected MalformedAttemptedSigned, got {st:?}"
    );
}

/// Drive the Permissive column of the fixture table.
fn assert_permissive_column<V: Verifier>(v: &V) {
    // Both accepted carriers reach crypto, where the placeholder signature
    // fails to authenticate.
    for file in ["valid-baseline.yaml", "document-end-at-eof.yaml"] {
        let st = verify_with(v, file, VerifierOptions::default());
        assert_eq!(
            st,
            VerifierState::SignedButFailedVerification,
            "{file} (Permissive): expected SignedButFailedVerification, got {st:?}"
        );
    }

    // unknown-key: unknown signature-document fields are rejected at parse
    // time. This remains stricter than the Permissive unknown-field posture.
    let st = verify_with(v, "unknown-key.yaml", VerifierOptions::default());
    assert_eq!(
        st,
        VerifierState::MalformedAttemptedSigned,
        "unknown-key.yaml (Permissive over-delivery): expected MalformedAttemptedSigned, got {st:?}"
    );
}

async fn verify_with_async<V: AsyncVerifier>(
    v: &V,
    file: &str,
    opts: VerifierOptions,
) -> VerifierState {
    let bytes = load_bytes(CATEGORY, file);
    let vk = placeholder_keys();
    let keys = PublicKeys {
        ed25519: Some(&vk),
        p256: None,
    };
    v.verify(&bytes, ArtifactForm::Yaml, &keys, opts)
        .await
        .unwrap_or_else(|e| {
            panic!(
                "{}/{}: unexpected invocation error {e:?} (suite expects only state values)",
                CATEGORY, file
            )
        })
}

/// Async sibling of [`run_yaml_signature_suite`].
pub async fn run_yaml_signature_suite_async<V: AsyncVerifier>(v: &V) {
    assert_universal_metadata_failures_async(v).await;

    let profile = v.capabilities().conformance_profile;
    match profile {
        AdvertisedConformanceProfile::Strict | AdvertisedConformanceProfile::SignatureStrict => {
            assert_strict_column_async(v).await
        }
        AdvertisedConformanceProfile::Permissive => assert_permissive_column_async(v).await,
    }
}

async fn assert_universal_metadata_failures_async<V: AsyncVerifier>(v: &V) {
    for file in UNIVERSAL_METADATA_FAILURES {
        let bytes = load_bytes(CATEGORY, file);
        let pre = v.pre_verify(&bytes, ArtifactForm::Yaml, false, false).await;
        assert_eq!(
            pre.outcome,
            PreVerifyOutcome::MetadataParseFailure,
            "{CATEGORY}/{file} (async): expected MetadataParseFailure at pre_verify, got {:?}",
            pre.outcome
        );

        let st = verify_with_async(v, file, VerifierOptions::default()).await;
        assert_eq!(
            st,
            VerifierState::MalformedAttemptedSigned,
            "{CATEGORY}/{file} (async): expected MalformedAttemptedSigned at verify, got {st:?}"
        );
    }
}

async fn assert_strict_column_async<V: AsyncVerifier>(v: &V) {
    let strict_opts = VerifierOptions {
        reject_unknown_signature_document_fields: true,
        ..VerifierOptions::default()
    };

    for file in ["valid-baseline.yaml", "document-end-at-eof.yaml"] {
        let st = verify_with_async(v, file, strict_opts.clone()).await;
        assert_eq!(
            st,
            VerifierState::SignedButFailedVerification,
            "{file} (Strict, async): expected SignedButFailedVerification, got {st:?}"
        );
    }

    let st = verify_with_async(v, "unknown-key.yaml", strict_opts).await;
    assert_eq!(
        st,
        VerifierState::MalformedAttemptedSigned,
        "unknown-key.yaml (Strict, async): expected MalformedAttemptedSigned, got {st:?}"
    );
}

async fn assert_permissive_column_async<V: AsyncVerifier>(v: &V) {
    for file in ["valid-baseline.yaml", "document-end-at-eof.yaml"] {
        let st = verify_with_async(v, file, VerifierOptions::default()).await;
        assert_eq!(
            st,
            VerifierState::SignedButFailedVerification,
            "{file} (Permissive, async): expected SignedButFailedVerification, got {st:?}"
        );
    }

    let st = verify_with_async(v, "unknown-key.yaml", VerifierOptions::default()).await;
    assert_eq!(
        st,
        VerifierState::MalformedAttemptedSigned,
        "unknown-key.yaml (Permissive over-delivery, async): expected MalformedAttemptedSigned, got {st:?}"
    );
}
