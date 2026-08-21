// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Sign -> verify round-trips for YAML and protobuf artifacts.

use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{
    OutputForm, SignOutcome, SignRequest, SignYamlParams, SigningKey, sign, sign_yaml,
};
use yaml_sigil_test_keys::{ed25519_signing_key, ed25519_verifying_key};
use yaml_sigil_verification::{
    PublicKeys, VerifierOptions, VerifierState, verify_proto, verify_yaml,
};

const PAYLOAD: &[u8] = b"sign-verify-roundtrip: ed25519\n";

fn keys() -> PublicKeys<'static> {
    let vk = Box::leak(Box::new(ed25519_verifying_key(0)));
    PublicKeys {
        ed25519: Some(vk),
        p256: None,
    }
}

#[test]
fn yaml_roundtrip() {
    let sk = ed25519_signing_key(0);
    let artifact = sign_yaml(&SignYamlParams {
        payload: PAYLOAD,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .unwrap();
    let st = verify_yaml(&artifact, &keys(), VerifierOptions::default()).unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));
}

#[test]
fn yaml_roundtrip_appends_authorized_newline() {
    let sk = ed25519_signing_key(0);
    let req = SignRequest {
        payload: b"missing: newline",
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: true,
        output_form: OutputForm::Yaml,
        algorithm_parameters: &[],
    };

    let success = match sign(&req) {
        SignOutcome::Success(success) => success,
        other => panic!("expected YAML signing success, got {other:?}"),
    };
    assert_eq!(success.modified_payload, b"missing: newline\n");

    let state = verify_yaml(&success.artifact, &keys(), VerifierOptions::default()).unwrap();
    match state {
        VerifierState::Verified { payload, .. } => {
            assert_eq!(payload, b"missing: newline\n");
        }
        other => panic!("expected verified YAML payload, got {other:?}"),
    }
}

#[test]
fn protobuf_roundtrip_preserves_arbitrary_payload_bytes() {
    let cases: [(&str, &[u8], bool); 3] = [
        ("non-UTF-8", b"\xFFbinary\n", false),
        ("BOM-prefixed", b"\xEF\xBB\xBFbom-prefixed\n", false),
        ("missing final newline", b"missing-final-newline", true),
    ];
    let sk = ed25519_signing_key(0);
    let public_keys = keys();

    for (name, payload, append_missing_final_newline) in cases {
        let req = SignRequest {
            payload,
            algorithm: AlgorithmId::Ed25519,
            key: SigningKey::Ed25519(&sk),
            keyid: None,
            append_missing_final_newline,
            output_form: OutputForm::Protobuf,
            algorithm_parameters: &[],
        };

        let success = match sign(&req) {
            SignOutcome::Success(success) => success,
            other => panic!("expected protobuf signing success for {name}, got {other:?}"),
        };
        assert!(
            success.modified_payload.is_empty(),
            "protobuf signing must not report a modified payload for {name}"
        );

        let state =
            verify_proto(&success.artifact, &public_keys, VerifierOptions::default()).unwrap();
        match state {
            VerifierState::Verified {
                payload: verified_payload,
                ..
            } => assert_eq!(
                verified_payload.as_slice(),
                payload,
                "payload mismatch for {name}"
            ),
            other => panic!("expected verified protobuf payload for {name}, got {other:?}"),
        }
    }
}
