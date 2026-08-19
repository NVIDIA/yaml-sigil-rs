// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Verification runtime suite — `fixtures/verification-runtime/`.
//!
//! Exercises successful ECDSA verification, runtime algorithm-support
//! classification, and cryptographic mismatch for both artifact forms.

use yaml_sigil_core::AlgorithmId;
use yaml_sigil_verification::{
    ArtifactForm, PreVerifyOutcome, PublicKeys, VerifierOptions, VerifierState,
    resolve_p256_verifying_key,
};

use crate::fixtures::{load_bytes, load_string, require_hex_field};
use crate::{ConformanceAsyncVerifier, ConformanceVerifier};

const CATEGORY: &str = "verification-runtime";
const FORMS: &[(&str, ArtifactForm)] =
    &[("yaml", ArtifactForm::Yaml), ("binpb", ArtifactForm::Proto)];

fn runtime_material() -> (Vec<u8>, Vec<u8>) {
    let expected = load_string(CATEGORY, "runtime-classification.expected.txt");
    (
        require_hex_field(&expected, "public key Q, uncompressed (hex)"),
        require_hex_field(&expected, "valid payload (hex)"),
    )
}

fn assert_verified(state: VerifierState, expected_payload: &[u8], context: &str) {
    let VerifierState::Verified { payload, algorithm } = state else {
        panic!("{context}: expected Verified, got {state:?}");
    };
    assert_eq!(
        algorithm,
        AlgorithmId::EcdsaP256Sha256,
        "{context}: verified algorithm mismatch"
    );
    assert_eq!(
        payload, expected_payload,
        "{context}: verified payload mismatch"
    );
}

/// Drive the runtime fixture matrix through a synchronous verifier.
pub fn run_verification_runtime_suite<V: ConformanceVerifier>(verifier: &V) {
    let (public_key_bytes, expected_payload) = runtime_material();
    let public_key = resolve_p256_verifying_key(&public_key_bytes)
        .expect("resolve verification-runtime P-256 public key");
    let keys = PublicKeys {
        ed25519: None,
        p256: Some(&public_key),
    };

    for (extension, form) in FORMS {
        let valid_file = format!("valid.{extension}");
        let valid = load_bytes(CATEGORY, &valid_file);
        let pre = verifier.pre_verify(&valid, *form, false, false);
        assert_eq!(
            pre.outcome,
            PreVerifyOutcome::Ok,
            "{valid_file}: expected successful pre-verification"
        );
        let state = verifier
            .verify(&valid, *form, &keys, VerifierOptions::default())
            .unwrap_or_else(|error| panic!("{valid_file}: verification error: {error}"));
        assert_verified(state, &expected_payload, &valid_file);

        let unsupported = VerifierOptions {
            verify_ecdsa_p256_sha256: false,
            ..VerifierOptions::default()
        };
        let state = verifier
            .verify(&valid, *form, &keys, unsupported)
            .unwrap_or_else(|error| panic!("{valid_file}: unsupported check error: {error}"));
        assert_eq!(
            state,
            VerifierState::SignedButAlgorithmUnsupported {
                algorithm: AlgorithmId::EcdsaP256Sha256,
            },
            "{valid_file}: unsupported algorithm classification mismatch"
        );

        let mismatch_file = format!("cryptographic-mismatch.{extension}");
        let mismatch = load_bytes(CATEGORY, &mismatch_file);
        let pre = verifier.pre_verify(&mismatch, *form, false, false);
        assert_eq!(
            pre.outcome,
            PreVerifyOutcome::Ok,
            "{mismatch_file}: expected successful pre-verification"
        );
        let state = verifier
            .verify(&mismatch, *form, &keys, VerifierOptions::default())
            .unwrap_or_else(|error| panic!("{mismatch_file}: verification error: {error}"));
        assert_eq!(
            state,
            VerifierState::SignedButFailedVerification,
            "{mismatch_file}: cryptographic mismatch classification"
        );
    }
}

/// Async sibling of [`run_verification_runtime_suite`].
pub async fn run_verification_runtime_suite_async<V: ConformanceAsyncVerifier>(verifier: &V) {
    let (public_key_bytes, expected_payload) = runtime_material();
    let public_key = resolve_p256_verifying_key(&public_key_bytes)
        .expect("resolve verification-runtime P-256 public key");
    let keys = PublicKeys {
        ed25519: None,
        p256: Some(&public_key),
    };

    for (extension, form) in FORMS {
        let valid_file = format!("valid.{extension}");
        let valid = load_bytes(CATEGORY, &valid_file);
        let pre = verifier.pre_verify(&valid, *form, false, false).await;
        assert_eq!(
            pre.outcome,
            PreVerifyOutcome::Ok,
            "{valid_file}: expected successful async pre-verification"
        );
        let state = verifier
            .verify(&valid, *form, &keys, VerifierOptions::default())
            .await
            .unwrap_or_else(|error| panic!("{valid_file}: async verification error: {error}"));
        assert_verified(state, &expected_payload, &valid_file);

        let unsupported = VerifierOptions {
            verify_ecdsa_p256_sha256: false,
            ..VerifierOptions::default()
        };
        let state = verifier
            .verify(&valid, *form, &keys, unsupported)
            .await
            .unwrap_or_else(|error| panic!("{valid_file}: async unsupported error: {error}"));
        assert_eq!(
            state,
            VerifierState::SignedButAlgorithmUnsupported {
                algorithm: AlgorithmId::EcdsaP256Sha256,
            },
            "{valid_file}: async unsupported algorithm classification mismatch"
        );

        let mismatch_file = format!("cryptographic-mismatch.{extension}");
        let mismatch = load_bytes(CATEGORY, &mismatch_file);
        let pre = verifier.pre_verify(&mismatch, *form, false, false).await;
        assert_eq!(
            pre.outcome,
            PreVerifyOutcome::Ok,
            "{mismatch_file}: expected successful async pre-verification"
        );
        let state = verifier
            .verify(&mismatch, *form, &keys, VerifierOptions::default())
            .await
            .unwrap_or_else(|error| panic!("{mismatch_file}: async verification error: {error}"));
        assert_eq!(
            state,
            VerifierState::SignedButFailedVerification,
            "{mismatch_file}: async cryptographic mismatch classification"
        );
    }
}
