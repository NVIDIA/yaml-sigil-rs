// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! YAML signature-document conformance — `fixtures/yaml-signature-conformance/`.
//!
//! Drives the verifier-side rules in `verification-api.md` "Conformance
//! Profiles" (renamed from "Protobuf Inner Conformance Profiles" in
//! spec commit `ce35681`) as they manifest on the YAML form —
//! specifically, the duplicate-known-singular-field rule and the
//! unknown-mapping-key rule. The protobuf-form symmetric cases live in
//! [`proto_outer`](super::proto_outer).
//!
//! The suite is profile-parameterized: the assertions depend on the
//! verifier's advertised
//! [`AdvertisedConformanceProfile`].
//! Under the spec's clarified `Permissive` behavior (spec commit `692052b`),
//! a YAML decoder may reject duplicate known mapping keys or accept them using
//! documented effective-value semantics. The Permissive branch asserts this
//! implementation's documented behavior: the four `duplicate-*.yaml` fixtures
//! always reject at parse, and `unknown-key.yaml` also rejects at parse.
//! See [`docs/conformance-validation.md`](../../docs/conformance-validation.md)
//! § 2 (per-fixture mapping) and § 5.r § 5d (resolved upstream).

use ed25519_dalek::{SigningKey as EdSk, VerifyingKey as EdVk};
use yaml_sigil_verification::{
    AdvertisedConformanceProfile, ArtifactForm, AsyncVerifier, PublicKeys, Verifier,
    VerifierOptions, VerifierState,
};

use crate::fixtures::load_bytes;

const CATEGORY: &str = "yaml-signature-conformance";

fn placeholder_keys() -> EdVk {
    // The fixtures all carry the canonical 86-char placeholder signature
    // (URL-safe-unpadded base64 of 64 zero bytes); the verifier's task is
    // structural rejection (or acceptance) of the *signature document*, not
    // the cryptographic outcome. Any well-formed Ed25519 public key suffices
    // for the keyring; verification of `valid-baseline.yaml` lands at
    // `SignedButFailedVerification` because the placeholder signature won't
    // authenticate against this (or any other) real key.
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

/// Drive the six `yaml-signature-conformance/` fixtures through the supplied
/// [`Verifier`]; the assertion table depends on the verifier's advertised
/// [`AdvertisedConformanceProfile`].
pub fn run_yaml_signature_suite<V: Verifier>(v: &V) {
    let profile = v.capabilities().conformance_profile;
    match profile {
        AdvertisedConformanceProfile::Strict | AdvertisedConformanceProfile::SignatureStrict => {
            assert_strict_column(v)
        }
        AdvertisedConformanceProfile::Permissive => assert_permissive_column(v),
    }
}

/// Drive the Strict / SignatureStrict column of the fixture table.
///
/// The two profiles share the same expected outcomes for every fixture in
/// this directory (the fixture README's "Strict outcome" and
/// "SignatureStrict outcome" columns are identical for all six entries), so
/// a single assertion routine covers both.
fn assert_strict_column<V: Verifier>(v: &V) {
    let strict_opts = VerifierOptions {
        reject_unknown_signature_document_fields: true,
        ..VerifierOptions::default()
    };

    // valid-baseline: each mapping key appears once → reaches the crypto
    // stage; the placeholder all-zero signature fails to authenticate.
    let st = verify_with(v, "valid-baseline.yaml", strict_opts.clone());
    assert_eq!(
        st,
        VerifierState::SignedButFailedVerification,
        "valid-baseline.yaml (Strict): expected SignedButFailedVerification, got {st:?}"
    );

    // The four duplicate-* fixtures must structurally reject.
    for file in [
        "duplicate-schema.yaml",
        "duplicate-alg.yaml",
        "duplicate-keyid.yaml",
        "duplicate-signature.yaml",
    ] {
        let st = verify_with(v, file, strict_opts.clone());
        assert_eq!(
            st,
            VerifierState::MalformedAttemptedSigned,
            "{}/{} (Strict): expected MalformedAttemptedSigned, got {st:?}",
            CATEGORY,
            file
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
///
/// The specification permits duplicate rejection under this profile. This
/// function records the implementation's documented rejection behavior as a
/// hard contract.
fn assert_permissive_column<V: Verifier>(v: &V) {
    // valid-baseline: reaches the crypto stage; placeholder signature
    // fails to authenticate.
    let st = verify_with(v, "valid-baseline.yaml", VerifierOptions::default());
    assert_eq!(
        st,
        VerifierState::SignedButFailedVerification,
        "valid-baseline.yaml (Permissive): expected SignedButFailedVerification, got {st:?}"
    );

    // The four duplicate-* fixtures reject at parse time. The Permissive
    // profile explicitly permits this implementation's documented behavior.
    for file in [
        "duplicate-schema.yaml",
        "duplicate-alg.yaml",
        "duplicate-keyid.yaml",
        "duplicate-signature.yaml",
    ] {
        let st = verify_with(v, file, VerifierOptions::default());
        assert_eq!(
            st,
            VerifierState::MalformedAttemptedSigned,
            "{}/{} (Permissive duplicate rejection): expected MalformedAttemptedSigned, got {st:?}",
            CATEGORY,
            file
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
    let profile = v.capabilities().conformance_profile;
    match profile {
        AdvertisedConformanceProfile::Strict | AdvertisedConformanceProfile::SignatureStrict => {
            assert_strict_column_async(v).await
        }
        AdvertisedConformanceProfile::Permissive => assert_permissive_column_async(v).await,
    }
}

async fn assert_strict_column_async<V: AsyncVerifier>(v: &V) {
    let strict_opts = VerifierOptions {
        reject_unknown_signature_document_fields: true,
        ..VerifierOptions::default()
    };

    let st = verify_with_async(v, "valid-baseline.yaml", strict_opts.clone()).await;
    assert_eq!(
        st,
        VerifierState::SignedButFailedVerification,
        "valid-baseline.yaml (Strict, async): expected SignedButFailedVerification, got {st:?}"
    );

    for file in [
        "duplicate-schema.yaml",
        "duplicate-alg.yaml",
        "duplicate-keyid.yaml",
        "duplicate-signature.yaml",
    ] {
        let st = verify_with_async(v, file, strict_opts.clone()).await;
        assert_eq!(
            st,
            VerifierState::MalformedAttemptedSigned,
            "{}/{} (Strict, async): expected MalformedAttemptedSigned, got {st:?}",
            CATEGORY,
            file
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
    let st = verify_with_async(v, "valid-baseline.yaml", VerifierOptions::default()).await;
    assert_eq!(
        st,
        VerifierState::SignedButFailedVerification,
        "valid-baseline.yaml (Permissive, async): expected SignedButFailedVerification, got {st:?}"
    );

    for file in [
        "duplicate-schema.yaml",
        "duplicate-alg.yaml",
        "duplicate-keyid.yaml",
        "duplicate-signature.yaml",
    ] {
        let st = verify_with_async(v, file, VerifierOptions::default()).await;
        assert_eq!(
            st,
            VerifierState::MalformedAttemptedSigned,
            "{}/{} (Permissive duplicate rejection, async): expected MalformedAttemptedSigned, got {st:?}",
            CATEGORY,
            file
        );
    }

    let st = verify_with_async(v, "unknown-key.yaml", VerifierOptions::default()).await;
    assert_eq!(
        st,
        VerifierState::MalformedAttemptedSigned,
        "unknown-key.yaml (Permissive over-delivery, async): expected MalformedAttemptedSigned, got {st:?}"
    );
}
