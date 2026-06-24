// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! End-to-end signing → verification using compile-time keys from `yaml-sigil-test-keys`.

use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{
    SignProtoParams, SignYamlParams, SigningKey, proto_wire_to_signed_yaml_stream, sign_proto,
    sign_yaml, signed_yaml_stream_to_proto_wire,
};
use yaml_sigil_test_keys::{
    ed25519_signing_key, ed25519_verifying_key, p256_signing_key, p256_verifying_key,
};
use yaml_sigil_verification::{
    InvocationError, PublicKeys, VerifierOptions, VerifierState, pre_verify_yaml,
    verify_from_pre_verify_yaml, verify_proto, verify_yaml,
};

const PAYLOAD_ED: &[u8] = b"e2e-buildtime-keys: ed25519 payload\n";
const PAYLOAD_P256: &[u8] = b"e2e-buildtime-keys: p256 payload\n";

fn keys_ed25519(vk_idx: u8) -> PublicKeys<'static> {
    let vk = Box::leak(Box::new(ed25519_verifying_key(vk_idx)));
    PublicKeys {
        ed25519: Some(vk),
        p256: None,
    }
}

fn keys_p256(vk_idx: u8) -> PublicKeys<'static> {
    let vk = Box::leak(Box::new(p256_verifying_key(vk_idx)));
    PublicKeys {
        ed25519: None,
        p256: Some(vk),
    }
}

fn keys_both(ed_vk: u8, p_vk: u8) -> PublicKeys<'static> {
    let evk = Box::leak(Box::new(ed25519_verifying_key(ed_vk)));
    let pvk = Box::leak(Box::new(p256_verifying_key(p_vk)));
    PublicKeys {
        ed25519: Some(evk),
        p256: Some(pvk),
    }
}

#[test]
fn e2e_ed25519_yaml_and_proto_pass_and_fail_wrong_peer_key() {
    let sk0 = ed25519_signing_key(0);
    let artifact = sign_yaml(&SignYamlParams {
        payload: PAYLOAD_ED,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk0),
        keyid: Some("kid-e2e"),
        append_missing_final_newline: false,
    })
    .unwrap();

    assert!(matches!(
        verify_yaml(&artifact, &keys_ed25519(0), VerifierOptions::default()).unwrap(),
        VerifierState::Verified { .. }
    ));
    assert_eq!(
        verify_yaml(&artifact, &keys_ed25519(1), VerifierOptions::default()).unwrap(),
        VerifierState::SignedButFailedVerification
    );

    let wire = sign_proto(&SignProtoParams {
        payload: PAYLOAD_ED,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk0),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();

    assert!(matches!(
        verify_proto(&wire, &keys_ed25519(0), VerifierOptions::default()).unwrap(),
        VerifierState::Verified { .. }
    ));
    assert_eq!(
        verify_proto(&wire, &keys_ed25519(1), VerifierOptions::default()).unwrap(),
        VerifierState::SignedButFailedVerification
    );

    let pre = pre_verify_yaml(&artifact, false);
    assert_eq!(pre.outcome, yaml_sigil_verification::PreVerifyOutcome::Ok);
    assert!(matches!(
        verify_from_pre_verify_yaml(&pre, &keys_ed25519(0), VerifierOptions::default()).unwrap(),
        VerifierState::Verified { .. }
    ));
    assert_eq!(
        verify_from_pre_verify_yaml(&pre, &keys_ed25519(1), VerifierOptions::default()).unwrap(),
        VerifierState::SignedButFailedVerification
    );
}

#[test]
fn e2e_p256_yaml_and_proto_pass_and_fail_wrong_peer_key() {
    let sk0 = p256_signing_key(0);
    let artifact = sign_yaml(&SignYamlParams {
        payload: PAYLOAD_P256,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk0),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();

    assert!(matches!(
        verify_yaml(&artifact, &keys_p256(0), VerifierOptions::default()).unwrap(),
        VerifierState::Verified { .. }
    ));
    assert_eq!(
        verify_yaml(&artifact, &keys_p256(1), VerifierOptions::default()).unwrap(),
        VerifierState::SignedButFailedVerification
    );

    let wire = sign_proto(&SignProtoParams {
        payload: PAYLOAD_P256,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk0),
        keyid: Some("p256-e2e"),
        append_missing_final_newline: false,
    })
    .unwrap();

    assert!(matches!(
        verify_proto(&wire, &keys_p256(0), VerifierOptions::default()).unwrap(),
        VerifierState::Verified { .. }
    ));
    assert_eq!(
        verify_proto(&wire, &keys_p256(1), VerifierOptions::default()).unwrap(),
        VerifierState::SignedButFailedVerification
    );

    let pre = pre_verify_yaml(&artifact, false);
    assert!(matches!(
        verify_from_pre_verify_yaml(&pre, &keys_p256(0), VerifierOptions::default()).unwrap(),
        VerifierState::Verified { .. }
    ));
    assert_eq!(
        verify_from_pre_verify_yaml(&pre, &keys_p256(1), VerifierOptions::default()).unwrap(),
        VerifierState::SignedButFailedVerification
    );
}

#[test]
fn e2e_key_resolution_failure_wrong_key_slot() {
    let sk = ed25519_signing_key(0);
    let artifact = sign_yaml(&SignYamlParams {
        payload: PAYLOAD_ED,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();

    let err = verify_yaml(&artifact, &keys_p256(0), VerifierOptions::default()).unwrap_err();
    assert_eq!(err, InvocationError::KeyResolutionFailure);

    let wire = sign_proto(&SignProtoParams {
        payload: PAYLOAD_ED,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let err = verify_proto(&wire, &keys_p256(0), VerifierOptions::default()).unwrap_err();
    assert_eq!(err, InvocationError::KeyResolutionFailure);
}

#[test]
fn e2e_signed_but_algorithm_unsupported_options() {
    let sk = p256_signing_key(0);
    let artifact = sign_yaml(&SignYamlParams {
        payload: PAYLOAD_P256,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();

    let opts = VerifierOptions {
        verify_ed25519: true,
        verify_ecdsa_p256_sha256: false,
        ..VerifierOptions::default()
    };
    assert_eq!(
        verify_yaml(&artifact, &keys_p256(0), opts.clone()).unwrap(),
        VerifierState::SignedButAlgorithmUnsupported {
            algorithm: AlgorithmId::EcdsaP256Sha256
        }
    );

    let wire = sign_proto(&SignProtoParams {
        payload: PAYLOAD_P256,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    assert_eq!(
        verify_proto(&wire, &keys_p256(0), opts).unwrap(),
        VerifierState::SignedButAlgorithmUnsupported {
            algorithm: AlgorithmId::EcdsaP256Sha256
        }
    );
}

#[test]
fn e2e_proto_tamper_fails_verification_or_malformed() {
    let sk = ed25519_signing_key(1);
    let mut wire = sign_proto(&SignProtoParams {
        payload: b"tamper: base\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    assert!(!wire.is_empty());
    let i = wire.len() / 2;
    wire[i] ^= 0x5A;

    let st = verify_proto(&wire, &keys_ed25519(1), VerifierOptions::default()).unwrap();
    assert!(
        matches!(
            st,
            VerifierState::MalformedAttemptedSigned | VerifierState::SignedButFailedVerification
        ),
        "unexpected state: {st:?}"
    );
}

#[test]
fn e2e_second_ed25519_keypair_sign_verify_independent() {
    let sk = ed25519_signing_key(1);
    let artifact = sign_yaml(&SignYamlParams {
        payload: b"pair-1-only: ok\n",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    assert!(matches!(
        verify_yaml(&artifact, &keys_ed25519(1), VerifierOptions::default()).unwrap(),
        VerifierState::Verified { .. }
    ));
    assert_eq!(
        verify_yaml(&artifact, &keys_ed25519(0), VerifierOptions::default()).unwrap(),
        VerifierState::SignedButFailedVerification
    );
}

#[test]
fn e2e_both_keys_supplied_correct_branch_used() {
    let sk_ed = ed25519_signing_key(0);
    let artifact = sign_yaml(&SignYamlParams {
        payload: PAYLOAD_ED,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk_ed),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();

    let keys = keys_both(0, 0);
    assert!(matches!(
        verify_yaml(&artifact, &keys, VerifierOptions::default()).unwrap(),
        VerifierState::Verified { .. }
    ));
}

fn assert_verified_yaml(keys: &PublicKeys<'_>, yaml: &[u8]) {
    assert!(
        matches!(
            verify_yaml(yaml, keys, VerifierOptions::default()).unwrap(),
            VerifierState::Verified { .. }
        ),
        "expected Verified YAML"
    );
}

fn assert_verified_proto(keys: &PublicKeys<'_>, wire: &[u8]) {
    assert!(
        matches!(
            verify_proto(wire, keys, VerifierOptions::default()).unwrap(),
            VerifierState::Verified { .. }
        ),
        "expected Verified proto"
    );
}

#[test]
fn e2e_spec_roundtrip_yaml_proto_yaml_ed25519() {
    let sk = ed25519_signing_key(0);
    let keys = keys_ed25519(0);
    let yaml0 = sign_yaml(&SignYamlParams {
        payload: PAYLOAD_ED,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: Some("kid-rt"),
        append_missing_final_newline: false,
    })
    .unwrap();
    assert_verified_yaml(&keys, &yaml0);

    let wire = signed_yaml_stream_to_proto_wire(&yaml0).unwrap();
    assert_verified_proto(&keys, &wire);

    let yaml1 = proto_wire_to_signed_yaml_stream(&wire).unwrap();
    assert_verified_yaml(&keys, &yaml1);

    let wire2 = signed_yaml_stream_to_proto_wire(&yaml1).unwrap();
    assert_verified_proto(&keys, &wire2);
}

#[test]
fn e2e_spec_roundtrip_proto_yaml_proto_ed25519() {
    let sk = ed25519_signing_key(0);
    let keys = keys_ed25519(0);
    let wire0 = sign_proto(&SignProtoParams {
        payload: PAYLOAD_ED,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: Some("kid-pr"),
        append_missing_final_newline: false,
    })
    .unwrap();
    assert_verified_proto(&keys, &wire0);

    let yaml = proto_wire_to_signed_yaml_stream(&wire0).unwrap();
    assert_verified_yaml(&keys, &yaml);

    let wire1 = signed_yaml_stream_to_proto_wire(&yaml).unwrap();
    assert_verified_proto(&keys, &wire1);
}

#[test]
fn e2e_spec_roundtrip_yaml_proto_yaml_p256() {
    let sk = p256_signing_key(0);
    let keys = keys_p256(0);
    let yaml0 = sign_yaml(&SignYamlParams {
        payload: PAYLOAD_P256,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    assert_verified_yaml(&keys, &yaml0);

    let wire = signed_yaml_stream_to_proto_wire(&yaml0).unwrap();
    assert_verified_proto(&keys, &wire);

    let yaml1 = proto_wire_to_signed_yaml_stream(&wire).unwrap();
    assert_verified_yaml(&keys, &yaml1);
}

#[test]
fn e2e_spec_roundtrip_proto_yaml_proto_p256() {
    let sk = p256_signing_key(0);
    let keys = keys_p256(0);
    let wire0 = sign_proto(&SignProtoParams {
        payload: PAYLOAD_P256,
        algorithm: AlgorithmId::EcdsaP256Sha256,
        key: SigningKey::EcdsaP256Sha256(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    assert_verified_proto(&keys, &wire0);

    let yaml = proto_wire_to_signed_yaml_stream(&wire0).unwrap();
    assert_verified_yaml(&keys, &yaml);

    let wire1 = signed_yaml_stream_to_proto_wire(&yaml).unwrap();
    assert_verified_proto(&keys, &wire1);
}
