// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! ECDSA P-256 / SHA-256 suite — `fixtures/alg-ecdsa/`.
//! Happy path + ACVP vector, high-S / low-S acceptance, invalid component
//! ranges, non-fixed-width signatures, bad-key rejection via the
//! implementation resolver, two-nonce instability, and
//! `algorithm_parameters` rejection on both verify and sign.
//!
//! The fixtures exercise encodings and operations from *Standards for
//! Efficient Cryptography 1 (SEC 1)* and secp256r1/P-256 parameters from
//! *Standards for Efficient Cryptography 2 (SEC 2)*. That third-party
//! standards material is not relicensed under this file's Apache-2.0
//! declaration. See the crate's `THIRD_PARTY_NOTICES.md` for source notices
//! and patent/IP caveats.

use p256::ecdsa::{SigningKey as P256Sk, VerifyingKey as P256Vk};
use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{OutputForm, SignInvocationError, SignOutcome, SignRequest, SigningKey};
use yaml_sigil_verification::{
    ArtifactForm, InvocationError, PublicKeys, VerifierOptions, VerifierState,
    resolve_p256_verifying_key,
};

use crate::fixtures::{load_bytes, load_string, require_hex_field};
use crate::{
    ConformanceAsyncSigner, ConformanceAsyncVerifier, ConformanceSigner, ConformanceVerifier,
};

const CATEGORY: &str = "alg-ecdsa";

fn parse_p256_pubkey(expected_txt: &str) -> P256Vk {
    // Try the prose form first (verify-happy-path.expected.txt and
    // two-nonce-instability.expected.txt), then the ACVP form.
    let bytes = [
        "public key Q (uncompressed)",
        "Q (uncompressed, hex)",
        "public key (uncompressed)",
    ]
    .into_iter()
    .find_map(|p| crate::fixtures::read_hex_field(expected_txt, p))
    .expect("no pubkey field in expected.txt");
    P256Vk::from_sec1_bytes(&bytes).expect("happy-path pubkey is on the curve")
}

fn keys_with_p256<'a>(vk: &'a P256Vk) -> PublicKeys<'a> {
    PublicKeys {
        ed25519: None,
        p256: Some(vk),
    }
}

pub fn run_ecdsa_suite<V: ConformanceVerifier, S: ConformanceSigner>(v: &V, s: &S) {
    happy_path_and_acvp(v);
    high_low_s(v);
    invalid_component_ranges(v);
    non_fixed_width(v);
    bad_keys();
    two_nonce_instability(v);
    algorithm_parameters_rejection(v, s);
}

fn happy_path_and_acvp<V: ConformanceVerifier>(v: &V) {
    // fixture: verify-happy-path.{binpb,yaml} -> Verified
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);

    let proto = load_bytes(CATEGORY, "verify-happy-path.binpb");
    let state = v
        .verify(
            &proto,
            ArtifactForm::Proto,
            &keys,
            VerifierOptions::default(),
        )
        .expect("happy-path proto verify should not error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "verify-happy-path.binpb: expected Verified, got {state:?}"
    );

    let yaml = load_bytes(CATEGORY, "verify-happy-path.yaml");
    let state = v
        .verify(&yaml, ArtifactForm::Yaml, &keys, VerifierOptions::default())
        .expect("happy-path yaml verify should not error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "verify-happy-path.yaml: expected Verified, got {state:?}"
    );

    // fixture: acvp-fips186-5-p256-sha256-tc131.binpb -> Verified. The ACVP
    // message is 128 octets of pseudorandom binary (not UTF-8, not
    // newline-terminated), but the protobuf-form payload is arbitrary octets
    // per the 2026-05-27 spec rewrite (spec commit ce35681). See
    // docs/conformance-validation.md §3f, §5.r §5b resolved.
    let acvp_expected = load_string(CATEGORY, "acvp-fips186-5-p256-sha256-tc131.expected.txt");
    let acvp_vk = parse_p256_pubkey(&acvp_expected);
    let acvp_keys = keys_with_p256(&acvp_vk);
    let acvp = load_bytes(CATEGORY, "acvp-fips186-5-p256-sha256-tc131.binpb");
    let state = v
        .verify(
            &acvp,
            ArtifactForm::Proto,
            &acvp_keys,
            VerifierOptions::default(),
        )
        .expect("ACVP tc131 verify should not return invocation error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "acvp-fips186-5-p256-sha256-tc131.binpb: expected Verified, got {state:?}"
    );
}

fn high_low_s<V: ConformanceVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);
    for file in ["high-s.binpb", "low-s.binpb"] {
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Proto,
                &keys,
                VerifierOptions::default(),
            )
            .expect("high/low-s verify should not error");
        assert!(
            matches!(state, VerifierState::Verified { .. }),
            "{}/{}: expected Verified (high-S accepted, no low-S preference), got {state:?}",
            CATEGORY,
            file
        );
    }
    for file in ["high-s.yaml", "low-s.yaml"] {
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Yaml,
                &keys,
                VerifierOptions::default(),
            )
            .expect("high/low-s YAML verify should not error");
        assert!(
            matches!(state, VerifierState::Verified { .. }),
            "{}/{}: expected Verified (high-S accepted, no low-S preference), got {state:?}",
            CATEGORY,
            file
        );
    }
}

fn invalid_component_ranges<V: ConformanceVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);
    for file in [
        "invalid-r-zero.binpb",
        "invalid-s-zero.binpb",
        "invalid-r-equals-n.binpb",
        "invalid-s-equals-n.binpb",
    ] {
        // fixture: invalid-*.binpb -> MalformedAttemptedSigned (per spec).
        // The `p256` crate's `Signature::from_slice` rejects R/S outside
        // `(0, n)`, so this lands at the structural stage rather than the
        // signature-equation stage.
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Proto,
                &keys,
                VerifierOptions::default(),
            )
            .expect("invalid-* fixture should not return invocation error");
        assert_eq!(
            state,
            VerifierState::MalformedAttemptedSigned,
            "{}/{}: expected MalformedAttemptedSigned, got {state:?}",
            CATEGORY,
            file
        );
    }
}

fn non_fixed_width<V: ConformanceVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);
    for file in ["signature-63-bytes.binpb", "signature-65-bytes.binpb"] {
        // fixture: signature-{63,65}-bytes.binpb -> MalformedAttemptedSigned
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Proto,
                &keys,
                VerifierOptions::default(),
            )
            .expect("non-fixed-width fixture should not return invocation error");
        assert_eq!(
            state,
            VerifierState::MalformedAttemptedSigned,
            "{}/{}: expected MalformedAttemptedSigned, got {state:?}",
            CATEGORY,
            file
        );
    }
}

fn bad_keys() {
    // fixture: bad-key-identity.txt -> KeyResolutionFailure
    // Both encodings: SEC 1 single-byte 0x00 and the 65-octet all-zero string.
    let id_body = load_string(CATEGORY, "bad-key-identity.txt");
    let single = require_hex_field(&id_body, "Q-encoded-as-O-single-byte");
    let all_zero = require_hex_field(&id_body, "Q-encoded-all-zero-65");
    assert_eq!(single, vec![0x00]);
    assert_eq!(all_zero.len(), 65);
    for bytes in [single.as_slice(), all_zero.as_slice()] {
        let err = resolve_p256_verifying_key(bytes)
            .expect_err("identity-point encoding must be rejected");
        assert!(
            matches!(err, InvocationError::KeyResolutionFailure),
            "bad-key-identity: expected KeyResolutionFailure, got {err:?}"
        );
    }

    // fixture: bad-key-off-curve.txt -> KeyResolutionFailure
    let off_body = load_string(CATEGORY, "bad-key-off-curve.txt");
    let off_bytes = require_hex_field(&off_body, "public_key (hex)");
    assert_eq!(off_bytes.len(), 65);
    let err = resolve_p256_verifying_key(&off_bytes).expect_err("off-curve key must be rejected");
    assert!(
        matches!(err, InvocationError::KeyResolutionFailure),
        "bad-key-off-curve: expected KeyResolutionFailure, got {err:?}"
    );

    // fixture: bad-key-wrong-curve.txt -> KeyResolutionFailure
    let wrong_body = load_string(CATEGORY, "bad-key-wrong-curve.txt");
    let wrong_bytes = require_hex_field(&wrong_body, "public_key (hex)");
    assert_eq!(wrong_bytes.len(), 65);
    let err = resolve_p256_verifying_key(&wrong_bytes)
        .expect_err("wrong-curve (secp256k1) key must be rejected by P-256 verifier");
    assert!(
        matches!(err, InvocationError::KeyResolutionFailure),
        "bad-key-wrong-curve: expected KeyResolutionFailure, got {err:?}"
    );
}

fn two_nonce_instability<V: ConformanceVerifier>(v: &V) {
    // fixture: two-nonce-instability-k{1,2}.binpb -> both Verified; octets differ
    let body = load_string(CATEGORY, "two-nonce-instability.expected.txt");
    let vk = parse_p256_pubkey(&body);
    let keys = keys_with_p256(&vk);

    let k1 = load_bytes(CATEGORY, "two-nonce-instability-k1.binpb");
    let k2 = load_bytes(CATEGORY, "two-nonce-instability-k2.binpb");

    let st1 = v
        .verify(&k1, ArtifactForm::Proto, &keys, VerifierOptions::default())
        .expect("k1 verify should not error");
    assert!(
        matches!(st1, VerifierState::Verified { .. }),
        "two-nonce-instability-k1.binpb: expected Verified, got {st1:?}"
    );
    let st2 = v
        .verify(&k2, ArtifactForm::Proto, &keys, VerifierOptions::default())
        .expect("k2 verify should not error");
    assert!(
        matches!(st2, VerifierState::Verified { .. }),
        "two-nonce-instability-k2.binpb: expected Verified, got {st2:?}"
    );
    assert_ne!(
        k1, k2,
        "two-nonce-instability k1/k2 artifacts MUST differ at the byte level"
    );

    // The (R, S) octets MUST differ — assert that the R1/S1 and R2/S2
    // pinned values from the expected.txt both appear in their respective
    // artifacts and that no pair coincides.
    let r1 = require_hex_field(&body, "R1");
    let s1 = require_hex_field(&body, "S1");
    let r2 = require_hex_field(&body, "R2");
    let s2 = require_hex_field(&body, "S2");
    assert_ne!(r1, r2, "R1 and R2 must differ");
    assert_ne!(s1, s2, "S1 and S2 must differ");
    assert!(
        k1.windows(r1.len()).any(|w| w == r1.as_slice()),
        "k1 artifact must embed R1"
    );
    assert!(
        k2.windows(r2.len()).any(|w| w == r2.as_slice()),
        "k2 artifact must embed R2"
    );
}

fn algorithm_parameters_rejection<V: ConformanceVerifier, S: ConformanceSigner>(v: &V, s: &S) {
    // fixture: algorithm-parameters-present.expected.txt -> InvalidAlgorithmParameters on both
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);
    let proto = load_bytes(CATEGORY, "verify-happy-path.binpb");
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

    // Use the pinned private key from the happy-path expected.txt for the
    // signer side. (The parameter check fires before any key/payload work,
    // so a real key isn't required — but using it keeps the suite
    // self-consistent.)
    let d_bytes = require_hex_field(&expected, "private key d");
    let sk = P256Sk::from_slice(&d_bytes).expect("happy-path private key parses");
    let bad = [0u8];
    let req = SignRequest {
        payload: b"hello: world\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
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

/// Async sibling of [`run_ecdsa_suite`].
pub async fn run_ecdsa_suite_async<V: ConformanceAsyncVerifier, S: ConformanceAsyncSigner>(
    v: &V,
    s: &S,
) {
    happy_path_and_acvp_async(v).await;
    high_low_s_async(v).await;
    invalid_component_ranges_async(v).await;
    non_fixed_width_async(v).await;
    bad_keys();
    two_nonce_instability_async(v).await;
    algorithm_parameters_rejection_async(v, s).await;
}

async fn happy_path_and_acvp_async<V: ConformanceAsyncVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);

    let proto = load_bytes(CATEGORY, "verify-happy-path.binpb");
    let state = v
        .verify(
            &proto,
            ArtifactForm::Proto,
            &keys,
            VerifierOptions::default(),
        )
        .await
        .expect("happy-path proto verify (async) should not error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "verify-happy-path.binpb (async): expected Verified, got {state:?}"
    );

    let yaml = load_bytes(CATEGORY, "verify-happy-path.yaml");
    let state = v
        .verify(&yaml, ArtifactForm::Yaml, &keys, VerifierOptions::default())
        .await
        .expect("happy-path yaml verify (async) should not error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "verify-happy-path.yaml (async): expected Verified, got {state:?}"
    );

    let acvp_expected = load_string(CATEGORY, "acvp-fips186-5-p256-sha256-tc131.expected.txt");
    let acvp_vk = parse_p256_pubkey(&acvp_expected);
    let acvp_keys = keys_with_p256(&acvp_vk);
    let acvp = load_bytes(CATEGORY, "acvp-fips186-5-p256-sha256-tc131.binpb");
    let state = v
        .verify(
            &acvp,
            ArtifactForm::Proto,
            &acvp_keys,
            VerifierOptions::default(),
        )
        .await
        .expect("ACVP tc131 verify (async) should not return invocation error");
    assert!(
        matches!(state, VerifierState::Verified { .. }),
        "acvp-fips186-5-p256-sha256-tc131.binpb (async): expected Verified, got {state:?}"
    );
}

async fn high_low_s_async<V: ConformanceAsyncVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);
    for file in ["high-s.binpb", "low-s.binpb"] {
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Proto,
                &keys,
                VerifierOptions::default(),
            )
            .await
            .expect("high/low-s verify (async) should not error");
        assert!(
            matches!(state, VerifierState::Verified { .. }),
            "{}/{} (async): expected Verified (high-S accepted), got {state:?}",
            CATEGORY,
            file
        );
    }
    for file in ["high-s.yaml", "low-s.yaml"] {
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Yaml,
                &keys,
                VerifierOptions::default(),
            )
            .await
            .expect("high/low-s YAML verify (async) should not error");
        assert!(
            matches!(state, VerifierState::Verified { .. }),
            "{}/{} (async): expected Verified, got {state:?}",
            CATEGORY,
            file
        );
    }
}

async fn invalid_component_ranges_async<V: ConformanceAsyncVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);
    for file in [
        "invalid-r-zero.binpb",
        "invalid-s-zero.binpb",
        "invalid-r-equals-n.binpb",
        "invalid-s-equals-n.binpb",
    ] {
        // fixture: invalid-*.binpb -> MalformedAttemptedSigned (per spec).
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Proto,
                &keys,
                VerifierOptions::default(),
            )
            .await
            .expect("invalid-* fixture (async) should not return invocation error");
        assert_eq!(
            state,
            VerifierState::MalformedAttemptedSigned,
            "{}/{} (async): expected MalformedAttemptedSigned, got {state:?}",
            CATEGORY,
            file
        );
    }
}

async fn non_fixed_width_async<V: ConformanceAsyncVerifier>(v: &V) {
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);
    for file in ["signature-63-bytes.binpb", "signature-65-bytes.binpb"] {
        let bytes = load_bytes(CATEGORY, file);
        let state = v
            .verify(
                &bytes,
                ArtifactForm::Proto,
                &keys,
                VerifierOptions::default(),
            )
            .await
            .expect("non-fixed-width fixture (async) should not return invocation error");
        assert_eq!(
            state,
            VerifierState::MalformedAttemptedSigned,
            "{}/{} (async): expected MalformedAttemptedSigned, got {state:?}",
            CATEGORY,
            file
        );
    }
}

async fn two_nonce_instability_async<V: ConformanceAsyncVerifier>(v: &V) {
    let body = load_string(CATEGORY, "two-nonce-instability.expected.txt");
    let vk = parse_p256_pubkey(&body);
    let keys = keys_with_p256(&vk);

    let k1 = load_bytes(CATEGORY, "two-nonce-instability-k1.binpb");
    let k2 = load_bytes(CATEGORY, "two-nonce-instability-k2.binpb");

    let st1 = v
        .verify(&k1, ArtifactForm::Proto, &keys, VerifierOptions::default())
        .await
        .expect("k1 verify (async) should not error");
    assert!(
        matches!(st1, VerifierState::Verified { .. }),
        "two-nonce-instability-k1.binpb (async): expected Verified, got {st1:?}"
    );
    let st2 = v
        .verify(&k2, ArtifactForm::Proto, &keys, VerifierOptions::default())
        .await
        .expect("k2 verify (async) should not error");
    assert!(
        matches!(st2, VerifierState::Verified { .. }),
        "two-nonce-instability-k2.binpb (async): expected Verified, got {st2:?}"
    );
    assert_ne!(
        k1, k2,
        "two-nonce-instability k1/k2 artifacts MUST differ at the byte level"
    );

    let r1 = require_hex_field(&body, "R1");
    let s1 = require_hex_field(&body, "S1");
    let r2 = require_hex_field(&body, "R2");
    let s2 = require_hex_field(&body, "S2");
    assert_ne!(r1, r2, "R1 and R2 must differ");
    assert_ne!(s1, s2, "S1 and S2 must differ");
    assert!(
        k1.windows(r1.len()).any(|w| w == r1.as_slice()),
        "k1 artifact must embed R1 (async)"
    );
    assert!(
        k2.windows(r2.len()).any(|w| w == r2.as_slice()),
        "k2 artifact must embed R2 (async)"
    );
}

async fn algorithm_parameters_rejection_async<
    V: ConformanceAsyncVerifier,
    S: ConformanceAsyncSigner,
>(
    v: &V,
    s: &S,
) {
    let expected = load_string(CATEGORY, "verify-happy-path.expected.txt");
    let vk = parse_p256_pubkey(&expected);
    let keys = keys_with_p256(&vk);
    let proto = load_bytes(CATEGORY, "verify-happy-path.binpb");
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

    let d_bytes = require_hex_field(&expected, "private key d");
    let sk = P256Sk::from_slice(&d_bytes).expect("happy-path private key parses");
    let bad = [0u8];
    let req = SignRequest {
        payload: b"hello: world\n",
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
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
