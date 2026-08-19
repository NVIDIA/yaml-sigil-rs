// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 suite — `fixtures/alg-ed25519/`.
//! Covers RFC 8032 §7.1 Test 1/2, noncanonical encodings, small-order key
//! rejection via the implementation resolver, stable re-sign,
//! and `algorithm_parameters` rejection on both verify and sign.
//!
//! The RFC-derived fixture values and validation rules are third-party
//! standards/test-vector material, not material relicensed under this file's
//! Apache-2.0 declaration. See the crate's `THIRD_PARTY_NOTICES.md`.

use ed25519_dalek::{SigningKey as EdSk, VerifyingKey as EdVk};
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{OutputForm, SignInvocationError, SignOutcome, SignRequest, SigningKey};
use yaml_sigil_verification::{
    ArtifactForm, InvocationError, PublicKeys, VerifierOptions, VerifierState,
    resolve_ed25519_verifying_key,
};

use crate::fixtures::{data_lines, hex_decode, load_bytes, load_string, require_hex_field};
use crate::{
    ConformanceAsyncSigner, ConformanceAsyncVerifier, ConformanceSigner, ConformanceVerifier,
};

const CATEGORY: &str = "alg-ed25519";

fn parse_ed25519_pubkey(expected_txt: &str) -> EdVk {
    let bytes = require_hex_field(expected_txt, "public_key");
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .expect("public_key in expected.txt must be 32 octets");
    EdVk::from_bytes(&arr).expect("RFC pubkey is canonical")
}

fn keys_with_ed25519<'a>(vk: &'a EdVk) -> PublicKeys<'a> {
    PublicKeys {
        ed25519: Some(vk),
        p256: None,
    }
}

pub fn run_ed25519_suite<V: ConformanceVerifier, S: ConformanceSigner>(v: &V, s: &S) {
    happy_path_vectors(v);
    noncanonical_encodings(v);
    small_order_keys();
    stable_resign(s);
    algorithm_parameters_rejection(v, s);
}

fn happy_path_vectors<V: ConformanceVerifier>(v: &V) {
    // fixture: rfc8032-vec1-empty-message.{binpb,yaml} -> Verified
    let vec1_expected = load_string(CATEGORY, "rfc8032-vec1-empty-message.expected.txt");
    let vec1_vk = parse_ed25519_pubkey(&vec1_expected);
    let keys = keys_with_ed25519(&vec1_vk);

    let proto = load_bytes(CATEGORY, "rfc8032-vec1-empty-message.binpb");
    let state = v
        .verify(
            &proto,
            ArtifactForm::Proto,
            &keys,
            VerifierOptions::default(),
        )
        .expect("RFC 8032 Test 1 protobuf verify should not error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "rfc8032-vec1 protobuf: expected Verified, got {state:?}"
    );

    let yaml = load_bytes(CATEGORY, "rfc8032-vec1-empty-message.yaml");
    let state = v
        .verify(&yaml, ArtifactForm::Yaml, &keys, VerifierOptions::default())
        .expect("RFC 8032 Test 1 YAML verify should not error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "rfc8032-vec1 yaml: expected Verified, got {state:?}"
    );

    // fixture: rfc8032-vec2-one-octet.binpb -> Verified. The protobuf-form
    // payload is arbitrary octets per the 2026-05-27 spec rewrite
    // (commit ce35681): the YAML trailing-newline / UTF-8 / no-BOM invariants
    // only apply to YAML-form payloads now. Our verifier honors that carve-out
    // (see docs/conformance-validation.md §3f, §5.r §5b resolved).
    let vec2_expected = load_string(CATEGORY, "rfc8032-vec2-one-octet.expected.txt");
    let vec2_vk = parse_ed25519_pubkey(&vec2_expected);
    let keys2 = keys_with_ed25519(&vec2_vk);
    let proto = load_bytes(CATEGORY, "rfc8032-vec2-one-octet.binpb");
    let state = v
        .verify(
            &proto,
            ArtifactForm::Proto,
            &keys2,
            VerifierOptions::default(),
        )
        .expect("RFC 8032 Test 2 protobuf verify should not return invocation error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "rfc8032-vec2 protobuf: expected Verified, got {state:?}"
    );
}

fn noncanonical_encodings<V: ConformanceVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "noncanonical-encoding.expected.txt");
    let vk = parse_ed25519_pubkey(&expected);
    let keys = keys_with_ed25519(&vk);
    for file in [
        "noncanonical-R.binpb",
        "noncanonical-S-equals-L.binpb",
        "noncanonical-S-equals-L-plus-1.binpb",
    ] {
        // fixture: noncanonical-*.binpb -> MalformedAttemptedSigned. The
        // verifier wraps `ed25519-dalek` with the spec's structural
        // canonical-encoding pre-check (R y-coord < p, S < L) so the
        // distinction between "malformed artifact bytes" and
        // "well-formed signature failed to authenticate" is preserved.
        // See docs/conformance-validation.md §3e (and §5.r for the
        // historical divergence record).
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Proto,
                &keys,
                VerifierOptions::default(),
            )
            .expect("noncanonical fixture should not return invocation error");
        assert_eq!(
            state,
            VerifierState::MalformedAttemptedSigned,
            "{}/{}: expected MalformedAttemptedSigned, got {state:?}",
            CATEGORY,
            file
        );
    }
}

fn small_order_keys() {
    // fixture: configured-key-small-order.txt -> KeyResolutionFailure (8 lines)
    let body = load_string(CATEGORY, "configured-key-small-order.txt");
    let mut count = 0;
    for line in data_lines(&body) {
        let bytes = hex_decode(line);
        assert_eq!(
            bytes.len(),
            32,
            "small-order pubkey line {line} should decode to 32 octets"
        );
        let err =
            resolve_ed25519_verifying_key(&bytes).expect_err("small-order pubkey must be rejected");
        assert!(
            matches!(err, InvocationError::KeyResolutionFailure),
            "small-order pubkey {line}: expected KeyResolutionFailure, got {err:?}"
        );
        count += 1;
    }
    assert_eq!(
        count, 8,
        "configured-key-small-order.txt should hold 8 entries, got {count}"
    );
}

fn stable_resign<S: ConformanceSigner>(s: &S) {
    // fixture: stable-resign.txt -> two Sign invocations on (RFC seed, empty
    // message) MUST produce byte-identical signed artifacts.
    let body = load_string(CATEGORY, "stable-resign.txt");
    let seed = require_hex_field(&body, "seed");
    let expected_sig = require_hex_field(&body, "expected signature");
    let seed_arr: [u8; 32] = seed.as_slice().try_into().expect("32-byte seed");
    let sk = EdSk::from_bytes(&seed_arr);

    let req = SignRequest {
        payload: b"",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &[],
    };
    let out1 = match s.sign(&req) {
        SignOutcome::Success(s) => s,
        other => panic!("first sign should succeed, got {other:?}"),
    };
    let out2 = match s.sign(&req) {
        SignOutcome::Success(s) => s,
        other => panic!("second sign should succeed, got {other:?}"),
    };
    assert_eq!(
        out1.artifact, out2.artifact,
        "two Ed25519 signs over (RFC seed, empty payload) must produce byte-identical artifacts"
    );

    // The pinned signature appears as a contiguous run of 64 octets inside
    // the protobuf artifact. We don't need a full decoder to verify
    // determinism — a substring match against the wire is sufficient and
    // robust against framing changes.
    assert!(
        out1.artifact
            .windows(expected_sig.len())
            .any(|w| w == expected_sig.as_slice()),
        "first artifact must embed the RFC 8032 Test 1 signature octets"
    );
}

fn algorithm_parameters_rejection<V: ConformanceVerifier, S: ConformanceSigner>(v: &V, s: &S) {
    // fixture: algorithm-parameters-present.expected.txt -> InvalidAlgorithmParameters on both
    let vec1_expected = load_string(CATEGORY, "rfc8032-vec1-empty-message.expected.txt");
    let vk = parse_ed25519_pubkey(&vec1_expected);
    let keys = keys_with_ed25519(&vk);
    let proto = load_bytes(CATEGORY, "rfc8032-vec1-empty-message.binpb");
    let opts = VerifierOptions {
        algorithm_parameters: vec![0x00],
        ..VerifierOptions::default()
    };
    let err = v
        .verify(&proto, ArtifactForm::Proto, &keys, opts)
        .expect_err("non-empty algorithm_parameters must yield invocation error");
    assert!(
        matches!(err, InvocationError::InvalidAlgorithmParameters),
        "Verify: expected InvalidAlgorithmParameters, got {err:?}"
    );

    // Use a dummy seed for the signer — the parameter check fires before
    // any key/payload work happens.
    let sk = EdSk::from_bytes(&[0u8; 32]);
    let bad = [0u8];
    let req = SignRequest {
        payload: b"",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &bad,
    };
    match s.sign(&req) {
        SignOutcome::Invocation(SignInvocationError::InvalidAlgorithmParameters) => {}
        other => panic!("Sign: expected InvalidAlgorithmParameters, got {other:?}"),
    }
}

/// Async sibling of [`run_ed25519_suite`]. Drives the same fixtures through
/// the async verifier and signer bindings.
pub async fn run_ed25519_suite_async<V: ConformanceAsyncVerifier, S: ConformanceAsyncSigner>(
    v: &V,
    s: &S,
) {
    happy_path_vectors_async(v).await;
    noncanonical_encodings_async(v).await;
    small_order_keys();
    stable_resign_async(s).await;
    algorithm_parameters_rejection_async(v, s).await;
}

async fn happy_path_vectors_async<V: ConformanceAsyncVerifier>(v: &V) {
    let vec1_expected = load_string(CATEGORY, "rfc8032-vec1-empty-message.expected.txt");
    let vec1_vk = parse_ed25519_pubkey(&vec1_expected);
    let keys = keys_with_ed25519(&vec1_vk);

    let proto = load_bytes(CATEGORY, "rfc8032-vec1-empty-message.binpb");
    let state = v
        .verify(
            &proto,
            ArtifactForm::Proto,
            &keys,
            VerifierOptions::default(),
        )
        .await
        .expect("RFC 8032 Test 1 protobuf verify should not error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "rfc8032-vec1 protobuf (async): expected Verified, got {state:?}"
    );

    let yaml = load_bytes(CATEGORY, "rfc8032-vec1-empty-message.yaml");
    let state = v
        .verify(&yaml, ArtifactForm::Yaml, &keys, VerifierOptions::default())
        .await
        .expect("RFC 8032 Test 1 YAML verify should not error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "rfc8032-vec1 yaml (async): expected Verified, got {state:?}"
    );

    let vec2_expected = load_string(CATEGORY, "rfc8032-vec2-one-octet.expected.txt");
    let vec2_vk = parse_ed25519_pubkey(&vec2_expected);
    let keys2 = keys_with_ed25519(&vec2_vk);
    let proto = load_bytes(CATEGORY, "rfc8032-vec2-one-octet.binpb");
    let state = v
        .verify(
            &proto,
            ArtifactForm::Proto,
            &keys2,
            VerifierOptions::default(),
        )
        .await
        .expect("RFC 8032 Test 2 protobuf verify should not return invocation error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "rfc8032-vec2 protobuf (async): expected Verified, got {state:?}"
    );
}

async fn noncanonical_encodings_async<V: ConformanceAsyncVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "noncanonical-encoding.expected.txt");
    let vk = parse_ed25519_pubkey(&expected);
    let keys = keys_with_ed25519(&vk);
    for file in [
        "noncanonical-R.binpb",
        "noncanonical-S-equals-L.binpb",
        "noncanonical-S-equals-L-plus-1.binpb",
    ] {
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Proto,
                &keys,
                VerifierOptions::default(),
            )
            .await
            .expect("noncanonical fixture should not return invocation error");
        assert_eq!(
            state,
            VerifierState::MalformedAttemptedSigned,
            "{}/{} (async): expected MalformedAttemptedSigned, got {state:?}",
            CATEGORY,
            file
        );
    }
}

async fn stable_resign_async<S: ConformanceAsyncSigner>(s: &S) {
    let body = load_string(CATEGORY, "stable-resign.txt");
    let seed = require_hex_field(&body, "seed");
    let expected_sig = require_hex_field(&body, "expected signature");
    let seed_arr: [u8; 32] = seed.as_slice().try_into().expect("32-byte seed");
    let sk = EdSk::from_bytes(&seed_arr);

    let req = SignRequest {
        payload: b"",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &[],
    };
    let out1 = match s.sign(&req).await {
        SignOutcome::Success(s) => s,
        other => panic!("first sign (async) should succeed, got {other:?}"),
    };
    let out2 = match s.sign(&req).await {
        SignOutcome::Success(s) => s,
        other => panic!("second sign (async) should succeed, got {other:?}"),
    };
    assert_eq!(
        out1.artifact, out2.artifact,
        "two Ed25519 signs (async) over (RFC seed, empty payload) must produce byte-identical artifacts"
    );
    assert!(
        out1.artifact
            .windows(expected_sig.len())
            .any(|w| w == expected_sig.as_slice()),
        "first async artifact must embed the RFC 8032 Test 1 signature octets"
    );
}

async fn algorithm_parameters_rejection_async<
    V: ConformanceAsyncVerifier,
    S: ConformanceAsyncSigner,
>(
    v: &V,
    s: &S,
) {
    let vec1_expected = load_string(CATEGORY, "rfc8032-vec1-empty-message.expected.txt");
    let vk = parse_ed25519_pubkey(&vec1_expected);
    let keys = keys_with_ed25519(&vk);
    let proto = load_bytes(CATEGORY, "rfc8032-vec1-empty-message.binpb");
    let opts = VerifierOptions {
        algorithm_parameters: vec![0x00],
        ..VerifierOptions::default()
    };
    let err = v
        .verify(&proto, ArtifactForm::Proto, &keys, opts)
        .await
        .expect_err("non-empty algorithm_parameters must yield invocation error");
    assert!(
        matches!(err, InvocationError::InvalidAlgorithmParameters),
        "Verify (async): expected InvalidAlgorithmParameters, got {err:?}"
    );

    let sk = EdSk::from_bytes(&[0u8; 32]);
    let bad = [0u8];
    let req = SignRequest {
        payload: b"",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
        output_form: OutputForm::Protobuf,
        algorithm_parameters: &bad,
    };
    match s.sign(&req).await {
        SignOutcome::Invocation(SignInvocationError::InvalidAlgorithmParameters) => {}
        other => panic!("Sign (async): expected InvalidAlgorithmParameters, got {other:?}"),
    }
}
