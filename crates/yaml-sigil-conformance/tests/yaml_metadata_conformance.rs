// SPDX-FileCopyrightText: Copyright 2026 NVIDIA CORPORATION & AFFILIATES
// SPDX-License-Identifier: Apache-2.0

//! Verification-stage conformance probes (`yaml.verify_*` probe IDs).

use yaml_sigil_core::AlgorithmId;
use yaml_sigil_signing::{SignYamlParams, SigningKey, sign_yaml};
use yaml_sigil_test_keys::{ed25519_signing_key, ed25519_verifying_key};
use yaml_sigil_transcription::{
    ComposeRequest, DecomposeOutcome, DecomposeRequest, TranscriptionForm, compose, decompose,
};
use yaml_sigil_verification::{
    PreVerifyOutcome, PublicKeys, VerifierOptions, VerifierState, pre_verify_yaml, verify_yaml,
};

const PAYLOAD: &[u8] = b"metadata-conformance: ed25519 payload\n";

fn keys() -> PublicKeys<'static> {
    let vk = Box::leak(Box::new(ed25519_verifying_key(0)));
    PublicKeys {
        ed25519: Some(vk),
        p256: None,
    }
}

fn sign_tier_a() -> Vec<u8> {
    let sk = ed25519_signing_key(0);
    sign_yaml(&SignYamlParams {
        payload: PAYLOAD,
        algorithm: AlgorithmId::Ed25519,
        key: SigningKey::Ed25519(&sk),
        keyid: None,
        append_missing_final_newline: false,
    })
    .expect("sign tier A")
}

fn recompose_with_carrier(carrier: &[u8]) -> Vec<u8> {
    let artifact = sign_tier_a();
    let resp = decompose(&DecomposeRequest {
        artifact: &artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let structural = match resp {
        yaml_sigil_transcription::DecomposeResponse::Structural(s) => s,
        _ => panic!("decompose"),
    };
    assert_eq!(structural.outcome, DecomposeOutcome::Ok);
    let payload = structural.payload.unwrap();
    match compose(&ComposeRequest {
        payload: &payload,
        signature_carrier: carrier,
        form: TranscriptionForm::Yaml,
    }) {
        yaml_sigil_transcription::ComposeOutcome::Success(s) => s.artifact,
        _ => panic!("compose"),
    }
}

#[test]
fn verify_wrong_schema_metadata_failure() {
    let artifact = sign_tier_a();
    let resp = decompose(&DecomposeRequest {
        artifact: &artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let structural = match resp {
        yaml_sigil_transcription::DecomposeResponse::Structural(s) => s,
        _ => panic!("decompose"),
    };
    let carrier = structural.signature_carrier.unwrap();
    let carrier_str = String::from_utf8(carrier).expect("utf8 carrier");
    let bad = carrier_str
        .replace("YamlSigilSignature.v1alpha1", "wrong.schema.id")
        .into_bytes();
    let bad_artifact = recompose_with_carrier(&bad);
    let pre = pre_verify_yaml(&bad_artifact, false);
    assert_eq!(pre.outcome, PreVerifyOutcome::MetadataParseFailure);
}

#[test]
fn verify_unknown_alg_metadata_failure() {
    let carrier = b"schema: YamlSigilSignature.v1alpha1\nalg: NOT_A_REAL_ALG\nsignature: Zm9v\n";
    let artifact = recompose_with_carrier(carrier);
    let pre = pre_verify_yaml(&artifact, false);
    assert_eq!(pre.outcome, PreVerifyOutcome::MetadataParseFailure);
}

#[test]
fn verify_tier_a_ok() {
    let artifact = sign_tier_a();
    let st = verify_yaml(&artifact, &keys(), VerifierOptions::default()).unwrap();
    assert!(matches!(st, VerifierState::Verified { .. }));
}

#[test]
fn verify_unknown_field_default_rejected() {
    let artifact = sign_tier_a();
    let resp = decompose(&DecomposeRequest {
        artifact: &artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let structural = match resp {
        yaml_sigil_transcription::DecomposeResponse::Structural(s) => s,
        _ => panic!("decompose"),
    };
    let mut carrier = structural.signature_carrier.unwrap();
    carrier.extend_from_slice(b"x_yaml_sigil_probe: ignored\n");
    let probe_artifact = recompose_with_carrier(&carrier);
    let st = verify_yaml(&probe_artifact, &keys(), VerifierOptions::default()).unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}

#[test]
fn verify_unknown_field_strict_rejected() {
    let artifact = sign_tier_a();
    let resp = decompose(&DecomposeRequest {
        artifact: &artifact,
        form: TranscriptionForm::Yaml,
        outer_conformance: None,
    });
    let structural = match resp {
        yaml_sigil_transcription::DecomposeResponse::Structural(s) => s,
        _ => panic!("decompose"),
    };
    let mut carrier = structural.signature_carrier.unwrap();
    carrier.extend_from_slice(b"x_yaml_sigil_probe: ignored\n");
    let probe_artifact = recompose_with_carrier(&carrier);
    let opts = VerifierOptions {
        reject_unknown_signature_document_fields: true,
        ..VerifierOptions::default()
    };
    let st = verify_yaml(&probe_artifact, &keys(), opts).unwrap();
    assert_eq!(st, VerifierState::MalformedAttemptedSigned);
}
